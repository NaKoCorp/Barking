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
//! alone. One whose verdict never came (no holder could answer) leaves the
//! send queue past `expires_at + ACK_GRACE_SECS`, when no node can hold its
//! ack any more, and stays `OnNetwork`: unconfirmed, never failed by the app
//! alone (spec decision I).

use std::collections::{HashSet, VecDeque};

use rusqlite::{OptionalExtension, params};

use super::Core;
use super::route;
use crate::Result;
use crate::identity::Fingerprint;
use crate::mailbox::MailboxId;
use crate::packet::{Packet, PacketId};
use crate::store::{
    DeliverySummary, Direction, MessageDeliveryDetail, MessageId, MessageRow, MessageStatus,
    PendingPackets, Queries, arr, map_err, to_i64, to_u64,
};
use crate::transparency::TransparencyEvent;

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
        let change = self.store.transaction(|tx| {
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
            let change = match message {
                Some(m) => {
                    let m = MessageId(arr(m)?);
                    recompute_message_status(tx, m)?;
                    change_of(tx, m)?
                }
                None => None,
            };
            route::record_deposited(tx, packet, node, now)?;
            Ok(change)
        })?;
        self.note_changes(change);
        Ok(())
    }

    /// Records that a deposit request for `packet` is about to be sent
    /// (`outbox.deposit_tried_at`, the first try kept). Called by the
    /// network client before each deposit request: a node may store the
    /// packet and its answer be lost, so a tried packet may have left this
    /// device although no deposit is recorded. A deletion counts it as
    /// already left (spec §14.1). An unknown packet is ignored.
    pub fn record_deposit_tried(&mut self, packet: PacketId, now: u64) -> Result<()> {
        self.store
            .conn()
            .execute(
                "UPDATE outbox SET deposit_tried_at = ?2 \
                 WHERE packet_id = ?1 AND deposit_tried_at IS NULL",
                params![packet.0.as_slice(), to_i64(now)],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Fails the deliveries whose packet expired (`expires_at < now`) before
    /// any node accepted it: `NotDelivered`, `expired_at` = the packet's
    /// expiry, the message recomputed (and noted for `take_failed_notices`
    /// when it fails). Then purges the expired packets of the send queue,
    /// except the deposited ones still awaiting their verdict within the
    /// nodes' ack grace. A deposited packet is never failed here: only
    /// `confirm_expired` does that; past the grace it leaves the queue
    /// still `OnNetwork`, without a notice.
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
                failed.push(fail(tx, id, MessageStatus::Pending, to_u64(expires_at))?);
            }
            tx.outbox_purge_expired(now)?;
            Ok(failed)
        })?;
        for f in failed {
            self.settle(f);
        }
        Ok(())
    }

    /// Deposited packets whose delivery still awaits its fate
    /// (`OnNetwork`) although their expiry passed by `started_at`
    /// (`expires_at <= started_at`), within the nodes' ack grace
    /// (`started_at <= expires_at + ACK_GRACE_SECS`; past it, nothing can
    /// confirm them and `expire_due` lets them go): the network client checks their
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

    /// `awaiting_verdict`, with each packet's bytes: the network client
    /// looks up the nodes that accepted it in its deposit ledger (full node
    /// ids), and gives a verdict only on the answer of all of them (or of
    /// two responsibles when the ledger names none).
    pub fn awaiting_verdict_packets(&self, started_at: u64) -> Result<Vec<AwaitingVerdict>> {
        let mut stmt = self
            .store
            .conn()
            .prepare(
                "SELECT o.packet_id, o.bytes FROM outbox o \
                 JOIN deliveries d ON d.packet_id = o.packet_id \
                 WHERE o.expires_at <= ?1 AND o.expires_at >= ?3 AND d.status = ?2 \
                 ORDER BY o.expires_at, o.rowid",
            )
            .map_err(map_err)?;
        let grace_start = started_at.saturating_sub(crate::packet::ACK_GRACE_SECS);
        let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
            .query_map(
                params![
                    to_i64(started_at),
                    MessageStatus::OnNetwork as i64,
                    to_i64(grace_start)
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<_>>()
            .map_err(map_err)?;
        let mut out = Vec::new();
        for (id, bytes) in rows {
            let Ok(p) = Packet::decode(&bytes) else {
                continue;
            };
            out.push(AwaitingVerdict {
                packet: PacketId(arr(id)?),
                mailbox: p.mailbox,
                bytes,
            });
        }
        Ok(out)
    }

    /// The failure verdict on a deposited packet (spec §15.5), to be called
    /// only once every node that accepted it answered a fetch of its
    /// mailbox, after its expiry and the replication slack, with neither the
    /// packet nor its ack: its `OnNetwork`
    /// delivery becomes `NotDelivered` (`expired_at` = the packet's expiry,
    /// `deposited_at` kept), the packet leaves the send queue (and with it
    /// the awaited ack), the message is recomputed and, when it fails,
    /// noted for `take_failed_notices`. `true` if the delivery failed.
    /// No effect (false) on any other delivery, `Received` included, nor
    /// before the packet's expiry, nor once it left the send queue or is
    /// past the nodes' ack grace. Idempotent.
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
            // Out of the queue (let go unconfirmed past the ack grace), or
            // past that grace: nothing can prove it lost any more.
            let Some(expires_at) = expires_at.map(to_u64) else {
                return Ok(None);
            };
            if expires_at > now
                || expires_at.saturating_add(crate::packet::ACK_GRACE_SECS) < now
                || !on_network(tx, packet)?
            {
                return Ok(None);
            }
            let failed = fail(tx, packet, MessageStatus::OnNetwork, expires_at)?;
            tx.outbox_remove(packet)?;
            Ok(Some(failed))
        })?;
        match outcome {
            Some(failed) => {
                self.settle(failed);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Sent messages that became `NotDelivered` (expiry before deposit,
    /// verdict, undeliverable packet) since the last call, as
    /// `(contact, row id)`: for the failure notification. Empties the list.
    pub fn take_failed_notices(&mut self) -> Vec<(Fingerprint, i64)> {
        self.failed_notices.take()
    }

    /// Keeps what a committed `fail` found: its change and its notice.
    pub(super) fn settle(&mut self, failed: Failed) {
        self.note_changes(failed.change);
        if let Some(notice) = failed.notice {
            self.failed_notices.push(notice);
        }
    }

    /// Notes delivery changes of sent messages for `take_delivery_changes`,
    /// each message once until the next take. Called once the transaction
    /// that made them committed.
    pub(super) fn note_changes(&mut self, changes: impl IntoIterator<Item = Change>) {
        for change in changes {
            self.delivery_changes.push(change);
        }
    }
}

/// Most entries kept by each in-memory list of changes
/// (`take_delivery_changes`, `take_failed_notices`). Past it the oldest
/// are dropped: a list taken at this length may be incomplete, and the app
/// then reloads its screens instead of patching them.
pub const MAX_NOTED_CHANGES: usize = 10_000;

/// A list of changes in the order first noted, each once, bounded by
/// `MAX_NOTED_CHANGES` (oldest dropped).
#[derive(Debug, Default)]
pub(super) struct ChangeList {
    order: VecDeque<Change>,
    seen: HashSet<Change>,
}

impl ChangeList {
    pub(super) fn push(&mut self, change: Change) {
        if !self.seen.insert(change) {
            return;
        }
        self.order.push_back(change);
        if self.order.len() > MAX_NOTED_CHANGES
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
    }

    pub(super) fn retain(&mut self, keep: impl Fn(&Change) -> bool) {
        self.order.retain(|c| keep(c));
        self.seen.retain(|c| keep(c));
    }

    pub(super) fn take(&mut self) -> Vec<Change> {
        self.seen.clear();
        self.order.drain(..).collect()
    }
}

/// A sent message whose delivery changed: `(contact, row id)`.
pub(crate) type Change = (Fingerprint, i64);

/// The sent message `message` as a change, if it has a row (copies of a
/// deleted message and messageless packets have none).
pub(super) fn change_of(q: &impl Queries, message: MessageId) -> Result<Option<Change>> {
    Ok(outgoing_status(q, message)?.map(|(contact, row, _)| (contact, row)))
}

/// What `fail` did to a sent message.
#[derive(Debug, Default)]
pub(super) struct Failed {
    /// Its delivery changed (the message has a row).
    pub change: Option<Change>,
    /// It just became `NotDelivered`: a failure notice to give.
    pub notice: Option<Change>,
}

/// Expiry of my sent `packet`: its queue row's, or, once it left the
/// queue, its sealing date plus the packet lifetime. `None` if unknown.
pub(super) fn acked_expiry(q: &impl Queries, packet: PacketId) -> Result<Option<u64>> {
    let row: Option<(Option<i64>, i64)> = q
        .conn()
        .query_row(
            "SELECT (SELECT expires_at FROM outbox WHERE packet_id = ?1), sealed_at \
             FROM deliveries WHERE packet_id = ?1",
            params![packet.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(map_err)?;
    Ok(match row {
        Some((Some(e), _)) => Some(to_u64(e)),
        Some((None, sealed)) if sealed > 0 => {
            Some(to_u64(sealed).saturating_add(crate::packet::DEFAULT_TTL_SECS))
        }
        _ => None,
    })
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
/// Returns the message's change, and its notice when the message itself
/// just became `NotDelivered` and its contact is still known. The caller keeps both for after its
/// transaction commits (`Core::settle`).
/// Every delivery state change that fails a message goes through here.
pub(super) fn fail(
    q: &impl Queries,
    packet: PacketId,
    from: MessageStatus,
    expired_at: u64,
) -> Result<Failed> {
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
        return Ok(Failed::default());
    };
    let message = MessageId(arr(message)?);
    let before = outgoing_status(q, message)?;
    recompute_message_status(q, message)?;
    let after = outgoing_status(q, message)?;
    // No notification for a contact removed since (nothing to name).
    let notice = match (before, after) {
        (Some((_, _, b)), Some((contact, row, a)))
            if a == MessageStatus::NotDelivered as i64
                && b != a
                && q.get_contact(contact)?.is_some() =>
        {
            Some((contact, row))
        }
        _ => None,
    };
    Ok(Failed {
        change: after.map(|(contact, row, _)| (contact, row)),
        notice,
    })
}

/// Fails, at `now`, the contact deliveries of my messages to `fp` that
/// are still `Pending` and that no deposit was tried for: the contact is
/// about to be deleted with their packets, so they will never leave. A
/// tried one may be on a node (spec §14.1): kept, its packet stays queued.
/// The changes go to `Queries::note_change` (this runs deep in a
/// transaction); no failure notice is given for a removed contact.
pub(super) fn fail_stranded(q: &impl Queries, fp: Fingerprint, now: u64) -> Result<()> {
    let packets: Vec<Vec<u8>> = {
        let mut stmt = q
            .conn()
            .prepare(
                "SELECT d.packet_id FROM deliveries d \
                 JOIN messages m ON m.message_id = d.message_id \
                 LEFT JOIN outbox o ON o.packet_id = d.packet_id \
                 WHERE m.contact_fp = ?1 AND m.direction = ?2 AND d.own = 0 \
                 AND d.status = ?3 AND o.deposit_tried_at IS NULL",
            )
            .map_err(map_err)?;
        stmt.query_map(
            params![
                fp.0.as_slice(),
                Direction::Out as i64,
                MessageStatus::Pending as i64
            ],
            |r| r.get(0),
        )
        .map_err(map_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(map_err)?
    };
    for packet in packets {
        let failed = fail(q, PacketId(arr(packet)?), MessageStatus::Pending, now)?;
        if let Some((contact, row)) = failed.change {
            q.note_change(contact, row);
        }
    }
    Ok(())
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

/// Outcome of a deletion (`Core::delete_messages`, spec §5.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteOutcome {
    pub deleted: u32,
    /// Messages nobody will receive: every contact packet was still here.
    pub cancelled: u32,
    /// Messages with some packets cancelled and some already gone.
    pub partly_cancelled: u32,
    /// Messages fully gone before the delete (on the network or received).
    pub already_left: u32,
    /// Contacts who will still receive at least one of them.
    pub still_receiving: Vec<Fingerprint>,
    /// At least one copy for my other devices left or keeps going.
    pub own_copies_kept: bool,
    /// One sent message deleted: its contact devices already left (they
    /// keep it), read in the deletion's transaction. 0 otherwise.
    pub devices_left: u32,
    /// One sent message deleted: its contact devices left or cancelled
    /// (never my own copies). 0 otherwise.
    pub devices_total: u32,
}

impl Core {
    /// Deletes the messages `row_ids` (spec §5.5), in one transaction;
    /// unknown rows (already deleted) are skipped. Each message's state is
    /// read inside the transaction: the outcome tells what really happened,
    /// whatever the confirmation showed.
    ///
    /// Sent message: its contact deliveries still `Pending` are cancelled
    /// (packet out of the queue, delivery and route steps removed), unless
    /// a deposit request was sent for their packet (`record_deposit_tried`:
    /// a node may hold it); those, and those `OnNetwork` or `Received`,
    /// are kept, with their packet if still
    /// queued, so the contact still receives it (a lost packet is
    /// redeposited, the ack clears it, or the verdict settles it); those
    /// `NotDelivered` are removed. The copies for my other devices are
    /// cancelled if nothing left for the contact and they did not leave
    /// either, kept otherwise (spec §5.1). Received message: only the row
    /// goes; `inbound` stays and a pending ack still leaves.
    ///
    /// Each deleted message leaves a tombstone (`insert_message` refuses
    /// its identifier for good) and the batch one `MessagesDeleted`
    /// log entry, without content nor contact.
    pub fn delete_messages(&mut self, row_ids: &[i64], now: u64) -> Result<DeleteOutcome> {
        let (outcome, changes) = self.store.transaction(|tx| delete_rows(tx, row_ids, now))?;
        // A failure notice for a message that no longer exists is moot.
        self.failed_notices
            .retain(|(_, row)| !row_ids.contains(row));
        self.note_changes(changes);
        Ok(outcome)
    }

    /// `delete_messages` for one message.
    pub fn delete_message(&mut self, row_id: i64, now: u64) -> Result<DeleteOutcome> {
        self.delete_messages(&[row_id], now)
    }

    /// Deletes every sent message still `Pending` (none of its packets to
    /// the contact accepted by a node), all contacts: "Cancel all". The
    /// packets that expired undeposited are failed first (`expire_due`):
    /// their messages are `NotDelivered`, not cancelled. The list is read
    /// in the deletion's transaction.
    pub fn cancel_all_pending(&mut self, now: u64) -> Result<DeleteOutcome> {
        self.expire_due(now)?;
        let (outcome, rows) = self.store.transaction(|tx| {
            let rows: Vec<i64> = {
                let mut stmt = tx
                    .conn()
                    .prepare(
                        "SELECT m.id FROM messages m WHERE m.direction = ?1 AND m.status = ?2 \
                         AND EXISTS (SELECT 1 FROM deliveries d \
                         WHERE d.message_id = m.message_id AND d.own = 0) ORDER BY m.id",
                    )
                    .map_err(map_err)?;
                stmt.query_map(
                    params![Direction::Out as i64, MessageStatus::Pending as i64],
                    |r| r.get(0),
                )
                .map_err(map_err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(map_err)?
            };
            Ok((delete_rows(tx, &rows, now)?, rows))
        })?;
        let (outcome, changes) = outcome;
        self.failed_notices.retain(|(_, row)| !rows.contains(row));
        self.note_changes(changes);
        Ok(outcome)
    }
}

/// The deletion of `delete_messages`, inside the caller's transaction,
/// with one change per deleted message.
fn delete_rows(
    q: &impl Queries,
    row_ids: &[i64],
    now: u64,
) -> Result<(DeleteOutcome, Vec<Change>)> {
    let mut out = DeleteOutcome::default();
    let mut changes = Vec::new();
    for &row in row_ids {
        let found: Option<(Vec<u8>, i64, Vec<u8>)> = q
            .conn()
            .query_row(
                "SELECT contact_fp, direction, message_id FROM messages WHERE id = ?1",
                params![row],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(map_err)?;
        let Some((contact, direction, message)) = found else {
            continue;
        };
        let contact = Fingerprint(arr(contact)?);
        let message = MessageId(arr(message)?);
        if direction == Direction::Out as i64 {
            let gone = drop_deliveries(q, message)?;
            match (gone.cancelled > 0, gone.left > 0) {
                (true, false) => out.cancelled += 1,
                (true, true) => out.partly_cancelled += 1,
                (false, true) => out.already_left += 1,
                (false, false) => {}
            }
            if gone.left > 0 && !out.still_receiving.contains(&contact) {
                out.still_receiving.push(contact);
            }
            out.own_copies_kept |= gone.own_kept;
            if row_ids.len() == 1 {
                // "Part of it had already left: Alice will receive it on
                // 1 of their 2 devices" (spec §6.7), from this transaction.
                out.devices_left = gone.left;
                out.devices_total = gone.left + gone.cancelled;
            }
        }
        q.conn()
            .execute("DELETE FROM messages WHERE id = ?1", params![row])
            .map_err(map_err)?;
        q.add_tombstone(message, now)?;
        out.deleted += 1;
        changes.push((contact, row));
    }
    if out.deleted > 0 {
        super::log(
            q,
            now,
            None,
            &TransparencyEvent::MessagesDeleted {
                count: out.deleted,
                cancelled: out.cancelled,
                already_left: out.already_left + out.partly_cancelled,
            },
        )?;
    }
    Ok((out, changes))
}

/// What the deletion of a sent message did to its deliveries.
struct Dropped {
    /// Contact deliveries cancelled (they were still `Pending`).
    cancelled: u32,
    /// Contact deliveries kept: already `OnNetwork` or `Received`.
    left: u32,
    /// A copy for my other devices left or keeps going.
    own_kept: bool,
}

/// Drops the deliveries of the sent message `message` that a deletion
/// cancels or makes moot (spec §5.5 points 1 to 4, §5.1).
fn drop_deliveries(q: &impl Queries, message: MessageId) -> Result<Dropped> {
    let rows: Vec<(Vec<u8>, bool, i64, bool)> = {
        let mut stmt = q
            .conn()
            .prepare(
                "SELECT d.packet_id, d.own, d.status, o.deposit_tried_at IS NOT NULL \
                 FROM deliveries d LEFT JOIN outbox o ON o.packet_id = d.packet_id \
                 WHERE d.message_id = ?1",
            )
            .map_err(map_err)?;
        stmt.query_map(params![message.0.as_slice()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(map_err)?
    };
    let failed = MessageStatus::NotDelivered as i64;
    let left = rows
        .iter()
        .filter(|(_, own, s, tried)| !own && may_have_left(*s, *tried));
    let left = u32::try_from(left.count()).unwrap_or(u32::MAX);
    let mut gone = Dropped {
        cancelled: 0,
        left,
        own_kept: false,
    };
    for (packet, own, status, tried) in rows {
        let packet = PacketId(arr(packet)?);
        let drop = if status == failed {
            true
        } else if may_have_left(status, tried) {
            // Left the phone, or may have: it cannot be recalled.
            gone.own_kept |= own;
            false
        } else if !own {
            gone.cancelled += 1;
            true
        } else {
            // A copy for my devices still here: cancelled with the message
            // only if nobody receives it.
            gone.own_kept |= gone.left > 0;
            gone.left == 0
        };
        if drop {
            remove_delivery(q, packet)?;
        }
    }
    Ok(gone)
}

/// `true` if a delivery in state `status` may have left this device: a node
/// accepted it (`OnNetwork`, `Received`), or it is `Pending` but a deposit
/// request was sent (`tried`: `outbox.deposit_tried_at`), whose answer may
/// have been lost while the node stored it. Never claim it did not leave
/// when a node may have it (spec §14.1).
pub(super) fn may_have_left(status: i64, tried: bool) -> bool {
    status == MessageStatus::OnNetwork as i64
        || status == MessageStatus::Received as i64
        || (status == MessageStatus::Pending as i64 && tried)
}

/// Removes the delivery carrying `packet`, its packet from the send queue
/// and its route steps.
pub(super) fn remove_delivery(q: &impl Queries, packet: PacketId) -> Result<()> {
    q.outbox_remove(packet)?;
    for table in ["deliveries", "route_steps"] {
        q.conn()
            .execute(
                &format!("DELETE FROM {table} WHERE packet_id = ?1"),
                params![packet.0.as_slice()],
            )
            .map_err(map_err)?;
    }
    Ok(())
}

impl Core {
    /// Messages with `contact`, oldest first, each with its delivery
    /// summary (`None`: received, or sent without a delivery to the
    /// contact). Expires the due packets first (`expire_due`), so a message
    /// that expired while the app slept never shows `Pending`.
    pub fn messages_with_delivery(
        &mut self,
        contact: &Fingerprint,
        now: u64,
    ) -> Result<Vec<(MessageRow, Option<DeliverySummary>)>> {
        self.expire_due(now)?;
        self.store.messages_with_delivery(*contact)
    }

    /// Delivery summaries of the messages `ids` that still exist, in the
    /// order given (`None`: a received message, or one without a delivery
    /// to the contact). An unknown or deleted row is left out, so the
    /// caller tells a removed message from one without a summary. Expires
    /// the due packets first.
    pub fn deliveries_of(
        &mut self,
        ids: &[i64],
        now: u64,
    ) -> Result<Vec<(i64, Option<DeliverySummary>)>> {
        self.expire_due(now)?;
        let found: std::collections::HashMap<i64, Option<DeliverySummary>> = self
            .store
            .deliveries_of(ids)?
            .into_iter()
            .map(|(m, s)| (m.id, s))
            .collect();
        Ok(ids
            .iter()
            .filter_map(|id| found.get(id).map(|s| (*id, *s)))
            .collect())
    }

    /// Delivery detail of the sent message `row_id`; `None` if unknown,
    /// received, or without a delivery to the contact. Expires the due
    /// packets first.
    pub fn message_delivery(
        &mut self,
        row_id: i64,
        now: u64,
    ) -> Result<Option<MessageDeliveryDetail>> {
        self.expire_due(now)?;
        self.store.message_delivery(row_id)
    }

    /// Sent messages to `contact` with a delivery to the contact, per
    /// state: `[pending, on_network, received, not_delivered]`. Expires the
    /// due packets first.
    pub fn delivery_counts(&mut self, contact: &Fingerprint, now: u64) -> Result<[u32; 4]> {
        self.expire_due(now)?;
        self.store.delivery_counts(*contact)
    }

    /// One page of the sent messages to `contact` in `state` with a
    /// delivery to the contact, newest first. Expires the due packets first.
    pub fn delivery_page(
        &mut self,
        contact: &Fingerprint,
        state: MessageStatus,
        limit: u32,
        offset: u32,
        now: u64,
    ) -> Result<Vec<(MessageRow, DeliverySummary)>> {
        self.expire_due(now)?;
        self.store.delivery_page(*contact, state, limit, offset)
    }

    /// Packets no node accepted yet that have not expired, classified
    /// (spec §5.7). Expires the due packets first.
    pub fn pending_packets(&mut self, now: u64) -> Result<PendingPackets> {
        self.expire_due(now)?;
        self.store.pending_packets(now)
    }

    /// Number of packets of `pending_packets`: the network screen's count.
    pub fn pending_count(&mut self, now: u64) -> Result<u32> {
        self.expire_due(now)?;
        self.store.pending_count(now)
    }

    /// Sent messages whose delivery changed since the last call, as
    /// `(contact, row id)`, each once, in the order of their first change.
    /// A deleted message is listed too (its row no longer exists).
    /// Empties the list.
    pub fn take_delivery_changes(&mut self) -> Vec<(Fingerprint, i64)> {
        // Changes noted deep in a transaction (a removed contact).
        let noted = self.store.take_noted_changes();
        self.note_changes(noted);
        self.delivery_changes.take()
    }
}
