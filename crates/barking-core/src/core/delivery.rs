//! Delivery state of sent messages: each packet's delivery
//! (`deliveries.status`) and the state of its message, recomputed from the
//! deliveries to the contact's devices after every delivery state write.
//!
//! A delivery goes `Pending` (sealed, queued) → `OnNetwork` (a node
//! accepted it: `record_deposit`) → `Received` (its ack: `receive_ack`).
//! It fails (`NotDelivered`) in two ways only: expired before any node
//! accepted it (`expire_due`), or deposited then confirmed gone from the
//! network after its expiry (`confirm_expired`, decided by the network
//! client: spec §15.5). A deposited delivery never fails on the local clock
//! alone.

use rusqlite::{OptionalExtension, params};

use super::Core;
use super::route;
use crate::Result;
use crate::identity::Fingerprint;
use crate::mailbox::MailboxId;
use crate::packet::{Packet, PacketId};
use crate::store::{MessageId, MessageStatus, Queries, arr, map_err, to_i64, to_u64};

/// Recomputes the state of the outgoing message `message_id` from its
/// deliveries to the contact's devices (`own = 0`): `Received` if one is
/// received, else `OnNetwork` if one is on the network, else `Pending` if
/// one is pending, else `NotDelivered`. Copies for my own devices never
/// count. A message without any delivery to the contact (sent from another
/// of my devices, imported history) and a received message are left as they
/// are, as is an unknown identifier (a messageless delivery).
pub(crate) fn recompute_message_status(q: &impl Queries, message_id: MessageId) -> Result<()> {
    q.conn()
        .execute(
            "UPDATE messages SET status = (
                SELECT CASE
                    WHEN sum(d.status = 3) > 0 THEN 3
                    WHEN sum(d.status = 1) > 0 THEN 1
                    WHEN sum(d.status = 0) > 0 THEN 0
                    ELSE 5 END
                FROM deliveries d WHERE d.message_id = messages.message_id AND d.own = 0)
            WHERE message_id = ?1 AND direction = 0
              AND EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = ?1 AND d.own = 0)",
            params![message_id.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Bytes of `packet` on the wire (its tier's fixed size): `deliveries.size`.
pub(crate) fn packet_size(packet: &Packet) -> u32 {
    u32::try_from(packet.tier.size()).unwrap_or(u32::MAX)
}

/// A deposited packet awaiting its verdict (`Core::awaiting_verdict_packets`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwaitingVerdict {
    pub packet: PacketId,
    pub mailbox: MailboxId,
    /// Encoded packet.
    pub bytes: Vec<u8>,
    /// Short id of the first node that accepted it (`deliveries.node`).
    pub node: Option<String>,
}

impl Core {
    /// Records that the node `node` (its short identifier) accepted
    /// `packet` at `now`, whatever its kind (message or receipt). The first
    /// acceptance is kept: `outbox.deposited_at` is set once, and a
    /// `Pending` delivery becomes `OnNetwork` with that date and node (its
    /// message's state recomputed). Each node adds one `Deposited` step to
    /// the route of a packet that carries a message. Idempotent; an unknown
    /// packet is ignored. A malformed node identifier is refused.
    pub fn record_deposit(&mut self, packet: PacketId, node: &str, now: u64) -> Result<()> {
        route::check_node(node)?;
        self.store.transaction(|tx| {
            tx.conn()
                .execute(
                    "UPDATE outbox SET deposited_at = ?2 \
                     WHERE packet_id = ?1 AND deposited_at IS NULL",
                    params![packet.0.as_slice(), to_i64(now)],
                )
                .map_err(map_err)?;
            let message: Option<Vec<u8>> = tx
                .conn()
                .query_row(
                    "UPDATE deliveries SET status = ?2, deposited_at = ?3, node = ?4 \
                     WHERE packet_id = ?1 AND status = ?5 RETURNING message_id",
                    params![
                        packet.0.as_slice(),
                        MessageStatus::OnNetwork as i64,
                        to_i64(now),
                        node,
                        MessageStatus::Pending as i64
                    ],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_err)?;
            if let Some(m) = message {
                recompute_message_status(tx, MessageId(arr(m)?))?;
            }
            route::record_deposited(tx, packet, node, now)
        })
    }

    /// Fails the deliveries whose packet expired (`expires_at < now`) before
    /// any node accepted it: `NotDelivered`, `expired_at` = the packet's
    /// expiry, the message recomputed (and noted for `take_failed_notices`
    /// when it fails). Then purges the expired packets of the send queue,
    /// except the deposited ones still awaiting their verdict. A deposited
    /// packet is never failed here: only `confirm_expired` does that.
    pub fn expire_due(&mut self, now: u64) -> Result<()> {
        let failed = self.store.transaction(|tx| {
            let expired: Vec<(Vec<u8>, i64)> = {
                let mut stmt = tx
                    .conn()
                    .prepare(
                        "SELECT o.packet_id, o.expires_at FROM outbox o \
                         JOIN deliveries d ON d.packet_id = o.packet_id \
                         WHERE o.expires_at < ?1 AND o.deposited_at IS NULL \
                         AND d.status = ?2 ORDER BY o.expires_at, o.rowid",
                    )
                    .map_err(map_err)?;
                stmt.query_map(params![to_i64(now), MessageStatus::Pending as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(map_err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(map_err)?
            };
            let mut failed = Vec::new();
            for (id, expires_at) in expired {
                let id = PacketId(arr(id)?);
                failed.extend(fail(tx, id, MessageStatus::Pending, to_u64(expires_at))?);
            }
            tx.outbox_purge_expired(now)?;
            Ok(failed)
        })?;
        self.failed_notices.extend(failed);
        Ok(())
    }

    /// Deposited packets whose delivery still awaits its fate
    /// (`OnNetwork`) although their expiry passed by `started_at`
    /// (`expires_at <= started_at`): the network client checks their
    /// mailbox and calls `confirm_expired` when the network no longer has
    /// them nor their ack. As `(packet, mailbox)`, oldest expiry first;
    /// copies for my devices and messageless packets included.
    pub fn awaiting_verdict(&self, started_at: u64) -> Result<Vec<(PacketId, MailboxId)>> {
        Ok(self
            .awaiting_verdict_packets(started_at)?
            .into_iter()
            .map(|a| (a.packet, a.mailbox))
            .collect())
    }

    /// `awaiting_verdict`, with each packet's bytes and the node that
    /// first accepted it: the network client gives a verdict only on the
    /// answer of a node that held the packet (or of two responsibles).
    pub fn awaiting_verdict_packets(&self, started_at: u64) -> Result<Vec<AwaitingVerdict>> {
        let mut stmt = self
            .store
            .conn()
            .prepare(
                "SELECT o.packet_id, o.bytes, d.node FROM outbox o \
                 JOIN deliveries d ON d.packet_id = o.packet_id \
                 WHERE o.expires_at <= ?1 AND d.status = ?2 \
                 ORDER BY o.expires_at, o.rowid",
            )
            .map_err(map_err)?;
        let rows: Vec<(Vec<u8>, Vec<u8>, Option<String>)> = stmt
            .query_map(
                params![to_i64(started_at), MessageStatus::OnNetwork as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<_>>()
            .map_err(map_err)?;
        let mut out = Vec::new();
        for (id, bytes, node) in rows {
            let Ok(p) = Packet::decode(&bytes) else {
                continue;
            };
            out.push(AwaitingVerdict {
                packet: PacketId(arr(id)?),
                mailbox: p.mailbox,
                bytes,
                node,
            });
        }
        Ok(out)
    }

    /// The failure verdict on a deposited packet (spec §15.5), to be called
    /// only once a responsible of its mailbox answered a fetch, after its
    /// expiry, with neither the packet nor its ack: its `OnNetwork`
    /// delivery becomes `NotDelivered` (`expired_at` = the packet's expiry,
    /// `deposited_at` kept), the packet leaves the send queue (and with it
    /// the awaited ack), the message is recomputed and, when it fails,
    /// noted for `take_failed_notices`. `true` if the delivery failed.
    /// No effect (false) on any other delivery, `Received` included, nor
    /// before the packet's expiry. Idempotent.
    pub fn confirm_expired(&mut self, packet: PacketId, now: u64) -> Result<bool> {
        let outcome = self.store.transaction(|tx| {
            let expires_at: Option<i64> = tx
                .conn()
                .query_row(
                    "SELECT expires_at FROM outbox WHERE packet_id = ?1",
                    params![packet.0.as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_err)?;
            // Out of the queue, the expiry is unknown: the verdict date.
            let expires_at = expires_at.map_or(now, to_u64);
            if expires_at > now || !on_network(tx, packet)? {
                return Ok(None);
            }
            let failed = fail(tx, packet, MessageStatus::OnNetwork, expires_at)?;
            tx.outbox_remove(packet)?;
            Ok(Some(failed))
        })?;
        match outcome {
            Some(failed) => {
                self.failed_notices.extend(failed);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Sent messages that became `NotDelivered` (expiry before deposit,
    /// verdict, undeliverable packet) since the last call, as
    /// `(contact, row id)`: for the failure notification. Empties the list.
    pub fn take_failed_notices(&mut self) -> Vec<(Fingerprint, i64)> {
        std::mem::take(&mut self.failed_notices)
    }
}

/// `true` if the delivery carrying `packet` is `OnNetwork`.
pub(super) fn on_network(q: &impl Queries, packet: PacketId) -> Result<bool> {
    let n: i64 = q
        .conn()
        .query_row(
            "SELECT count(*) FROM deliveries WHERE packet_id = ?1 AND status = ?2",
            params![packet.0.as_slice(), MessageStatus::OnNetwork as i64],
            |r| r.get(0),
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// Fails the delivery carrying `packet` if it is in state `from`:
/// `NotDelivered`, `expired_at` = `expired_at`, its message recomputed.
/// Returns the message's `(contact, row id)` when the message itself just
/// became `NotDelivered` (a notice to give), `None` otherwise. The caller
/// keeps the notice for after its transaction commits.
/// Every delivery state change that fails a message goes through here.
pub(super) fn fail(
    q: &impl Queries,
    packet: PacketId,
    from: MessageStatus,
    expired_at: u64,
) -> Result<Option<(Fingerprint, i64)>> {
    let message: Option<Vec<u8>> = q
        .conn()
        .query_row(
            "UPDATE deliveries SET status = ?2, expired_at = ?3 \
             WHERE packet_id = ?1 AND status = ?4 RETURNING message_id",
            params![
                packet.0.as_slice(),
                MessageStatus::NotDelivered as i64,
                to_i64(expired_at),
                from as i64
            ],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)?;
    let Some(message) = message else {
        return Ok(None);
    };
    let message = MessageId(arr(message)?);
    let before = outgoing_status(q, message)?;
    recompute_message_status(q, message)?;
    let after = outgoing_status(q, message)?;
    Ok(match (before, after) {
        (Some((_, _, b)), Some((contact, row, a)))
            if a == MessageStatus::NotDelivered as i64 && b != a =>
        {
            Some((contact, row))
        }
        _ => None,
    })
}

/// Contact, row id and stored status of the outgoing message `message`.
fn outgoing_status(
    q: &impl Queries,
    message: MessageId,
) -> Result<Option<(Fingerprint, i64, i64)>> {
    let row: Option<(Vec<u8>, i64, i64)> = q
        .conn()
        .query_row(
            "SELECT contact_fp, id, status FROM messages \
             WHERE message_id = ?1 AND direction = 0",
            params![message.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(map_err)?;
    row.map(|(fp, id, status)| Ok((Fingerprint(arr(fp)?), id, status)))
        .transpose()
}
