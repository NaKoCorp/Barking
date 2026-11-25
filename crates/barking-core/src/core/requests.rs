//! Contact requests: storage of the requests received from unknown senders,
//! of the first packets held until a request is accepted, of the refusals
//! and of the invites I sent. This module is SQL only (simple per-table
//! access); the behavior (invite, receive, accept, refuse) builds on it.
//!
//! A request is keyed by the sender's fingerprint. A held first packet
//! (`pending_initials`) is attached to a request (`fp` set) or, while its
//! sender's card is not known yet, to the queue of unknown senders (`fp`
//! NULL, keyed by the initial message's identity key `ik`). When a limit is
//! reached the new item is dropped: nothing is ever evicted.

// The accessors are used by the behavior built on top of this module in the
// following changes; until then nothing calls them.
#![allow(dead_code)]

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::send::{SealTime, Target, seal_for};
use super::{Core, MAX_AGE_SECS, delivery, load_card, log, sync};
use crate::contact::ContactCard;
use crate::content::ExtContent;
use crate::envelope;
use crate::identity::{DeviceId, Fingerprint};
use crate::packet::{Packet, PacketId};
use crate::store::{MessageId, Queries, arr, map_err, to_i64, to_u64};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// Requests kept at most (visible or hidden); a new sender beyond it is dropped.
pub(super) const MAX_PENDING_REQUESTS: u32 = 50;
/// First packets kept at most for one request; a new one beyond it is dropped.
pub(super) const MAX_PACKETS_PER_REQUEST: u32 = 4;
/// First packets kept at most in the queue of unknown senders.
pub(super) const MAX_UNKNOWN_INITIALS: u32 = 16;
/// How long a first packet of an unknown sender is held.
pub(super) const UNKNOWN_RETENTION_SECS: u64 = MAX_AGE_SECS;
/// How long a request is kept without a new invite or message.
pub(super) const REQUEST_RETENTION_SECS: u64 = 30 * 86_400;
/// How long a refusal is remembered.
pub(super) const REFUSAL_RETENTION_SECS: u64 = MAX_AGE_SECS;
/// Minimum delay between two invites to the same person.
pub(super) const INVITE_INTERVAL_SECS: u64 = 86_400;
/// Minimum delay between two notifications for the same request.
pub(super) const NOTIFY_INTERVAL_SECS: u64 = 86_400;

/// A pending contact request, as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRequest {
    pub fingerprint: Fingerprint,
    pub display_name: String,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Invites received from this sender.
    pub invite_count: u32,
    /// First packets held for this sender that are messages (not invites).
    pub pending_messages: u32,
    /// Hidden by the user on this device.
    pub hidden: bool,
    /// Not shown to the user yet.
    pub unseen: bool,
}

/// State of the invite I sent to a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteState {
    /// No invite sent.
    None,
    /// Invite sent at `at`, no answer yet.
    Sent { at: u64 },
    /// Invite sent at `at` that was refused or got no answer.
    Unanswered { at: u64 },
    /// The invite sent at `at` was accepted.
    Accepted { at: u64 },
}

/// A `contact_requests` row, with the card bytes and the device-local
/// `last_notified` that `ContactRequest` does not expose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequestRow {
    pub fp: Fingerprint,
    pub card: Vec<u8>,
    pub display_name: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub invite_count: u32,
    pub hidden: bool,
    pub unseen: bool,
    pub last_notified: Option<u64>,
}

/// A held first packet (`pending_initials` row). `fp` is `None` while it
/// waits in the queue of unknown senders; `invite` marks the packet of an
/// invite rather than a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PendingInitial {
    pub packet_id: PacketId,
    pub ik: [u8; 32],
    pub fp: Option<Fingerprint>,
    pub message_id: Option<MessageId>,
    pub bytes: Vec<u8>,
    pub received_at: u64,
    pub invite: bool,
}

/// An `invites` row: when I last invited, and when it was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InviteRow {
    pub at: u64,
    pub accepted_at: Option<u64>,
}

const REQUEST_COLUMNS: &str =
    "fp, card, display_name, first_seen, last_seen, invite_count, hidden, unseen, last_notified";

fn request_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(RequestRaw, Option<i64>)> {
    Ok((
        (
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
        ),
        r.get(8)?,
    ))
}

type RequestRaw = (Vec<u8>, Vec<u8>, String, i64, i64, i64, bool, bool);

fn into_request((raw, notified): (RequestRaw, Option<i64>)) -> Result<RequestRow> {
    let (fp, card, display_name, first_seen, last_seen, count, hidden, unseen) = raw;
    Ok(RequestRow {
        fp: Fingerprint(arr(fp)?),
        card,
        display_name,
        first_seen: to_u64(first_seen),
        last_seen: to_u64(last_seen),
        invite_count: u32::try_from(count).unwrap_or(u32::MAX),
        hidden,
        unseen,
        last_notified: notified.map(to_u64),
    })
}

/// The request of `fp`, if any.
pub(super) fn get_request(q: &impl Queries, fp: Fingerprint) -> Result<Option<RequestRow>> {
    q.conn()
        .query_row(
            &format!("SELECT {REQUEST_COLUMNS} FROM contact_requests WHERE fp = ?1"),
            params![fp.0.as_slice()],
            request_row,
        )
        .optional()
        .map_err(map_err)?
        .map(into_request)
        .transpose()
}

/// Inserts the request, or replaces every column of the existing one.
pub(super) fn upsert_request(q: &impl Queries, row: &RequestRow) -> Result<()> {
    q.conn()
        .execute(
            &format!(
                "INSERT INTO contact_requests ({REQUEST_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(fp) DO UPDATE SET
                    card = excluded.card, display_name = excluded.display_name,
                    first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                    invite_count = excluded.invite_count, hidden = excluded.hidden,
                    unseen = excluded.unseen, last_notified = excluded.last_notified"
            ),
            params![
                row.fp.0.as_slice(),
                row.card,
                row.display_name,
                to_i64(row.first_seen),
                to_i64(row.last_seen),
                i64::from(row.invite_count),
                row.hidden,
                row.unseen,
                row.last_notified.map(to_i64),
            ],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Deletes the request of `fp` and the first packets held for it, together.
/// Returns whether a request existed.
pub(super) fn delete_request(q: &impl Queries, fp: Fingerprint) -> Result<bool> {
    q.conn()
        .execute(
            "DELETE FROM pending_initials WHERE fp = ?1",
            params![fp.0.as_slice()],
        )
        .map_err(map_err)?;
    let n = q
        .conn()
        .execute(
            "DELETE FROM contact_requests WHERE fp = ?1",
            params![fp.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// Every request (hidden ones too), most recently seen first, with the
/// number of messages held for each.
pub(super) fn list_requests(q: &impl Queries) -> Result<Vec<ContactRequest>> {
    let mut stmt = q
        .conn()
        .prepare(
            "SELECT r.fp, r.display_name, r.first_seen, r.last_seen, r.invite_count,
                    r.hidden, r.unseen,
                    (SELECT count(*) FROM pending_initials p WHERE p.fp = r.fp AND p.invite = 0)
             FROM contact_requests r ORDER BY r.last_seen DESC, r.fp",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })
        .map_err(map_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (fp, display_name, first, last, invites, hidden, unseen, held) =
            row.map_err(map_err)?;
        out.push(ContactRequest {
            fingerprint: Fingerprint(arr(fp)?),
            display_name,
            first_seen: to_u64(first),
            last_seen: to_u64(last),
            invite_count: u32::try_from(invites).unwrap_or(u32::MAX),
            pending_messages: u32::try_from(held).unwrap_or(u32::MAX),
            hidden,
            unseen,
        });
    }
    Ok(out)
}

/// Number of requests, hidden ones included.
pub(super) fn count_requests(q: &impl Queries) -> Result<u32> {
    let n: i64 = q
        .conn()
        .query_row("SELECT count(*) FROM contact_requests", [], |r| r.get(0))
        .map_err(map_err)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

const PENDING_COLUMNS: &str = "packet_id, ik, fp, message_id, bytes, received_at, invite";

type PendingRaw = (
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    bool,
);

fn pending_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingRaw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn into_pending(raw: PendingRaw) -> Result<PendingInitial> {
    let (packet_id, ik, fp, message_id, bytes, received_at, invite) = raw;
    Ok(PendingInitial {
        packet_id: PacketId(arr(packet_id)?),
        ik: arr(ik)?,
        fp: fp.map(|v| arr(v).map(Fingerprint)).transpose()?,
        message_id: message_id.map(|v| arr(v).map(MessageId)).transpose()?,
        bytes,
        received_at: to_u64(received_at),
        invite,
    })
}

fn query_pending(q: &impl Queries, sql: &str, key: &[u8]) -> Result<Vec<PendingInitial>> {
    let mut stmt = q.conn().prepare(sql).map_err(map_err)?;
    let rows = stmt.query_map(params![key], pending_row).map_err(map_err)?;
    rows.map(|r| into_pending(r.map_err(map_err)?)).collect()
}

/// Holds a first packet. Returns `false` (and changes nothing) if a packet
/// with the same id is already held.
pub(super) fn insert_pending_initial(q: &impl Queries, p: &PendingInitial) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            &format!(
                "INSERT OR IGNORE INTO pending_initials ({PENDING_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            ),
            params![
                p.packet_id.0.as_slice(),
                p.ik.as_slice(),
                p.fp.map(|f| f.0.to_vec()),
                p.message_id.map(|m| m.0.to_vec()),
                p.bytes,
                to_i64(p.received_at),
                p.invite,
            ],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// The first packets held for the request of `fp`, oldest first.
pub(super) fn list_pending_by_fp(q: &impl Queries, fp: Fingerprint) -> Result<Vec<PendingInitial>> {
    query_pending(
        q,
        &format!(
            "SELECT {PENDING_COLUMNS} FROM pending_initials WHERE fp = ?1
             ORDER BY received_at, packet_id"
        ),
        &fp.0,
    )
}

/// The first packets held with the initial message identity key `ik`,
/// whether attached to a request or not, oldest first.
pub(super) fn list_pending_by_ik(q: &impl Queries, ik: &[u8; 32]) -> Result<Vec<PendingInitial>> {
    query_pending(
        q,
        &format!(
            "SELECT {PENDING_COLUMNS} FROM pending_initials WHERE ik = ?1
             ORDER BY received_at, packet_id"
        ),
        ik,
    )
}

/// Number of first packets held for the request of `fp`, invites included.
pub(super) fn count_pending_for_fp(q: &impl Queries, fp: Fingerprint) -> Result<u32> {
    let n: i64 = q
        .conn()
        .query_row(
            "SELECT count(*) FROM pending_initials WHERE fp = ?1",
            params![fp.0.as_slice()],
            |r| r.get(0),
        )
        .map_err(map_err)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Number of first packets in the queue of unknown senders (`fp` NULL).
pub(super) fn count_unknown(q: &impl Queries) -> Result<u32> {
    let n: i64 = q
        .conn()
        .query_row(
            "SELECT count(*) FROM pending_initials WHERE fp IS NULL",
            [],
            |r| r.get(0),
        )
        .map_err(map_err)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Deletes one held first packet. Returns whether it existed.
pub(super) fn delete_pending(q: &impl Queries, packet_id: PacketId) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            "DELETE FROM pending_initials WHERE packet_id = ?1",
            params![packet_id.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// Attaches the queued first packets of unknown senders with the identity
/// key `ik` to the request of `fp`. Returns how many were attached.
pub(super) fn attach_unknown_to_fp(
    q: &impl Queries,
    ik: &[u8; 32],
    fp: Fingerprint,
) -> Result<usize> {
    q.conn()
        .execute(
            "UPDATE pending_initials SET fp = ?2 WHERE ik = ?1 AND fp IS NULL",
            params![ik.as_slice(), fp.0.as_slice()],
        )
        .map_err(map_err)
}

/// When `fp` was refused, if it was.
pub(super) fn get_refusal(q: &impl Queries, fp: Fingerprint) -> Result<Option<u64>> {
    Ok(q.conn()
        .query_row(
            "SELECT at FROM refused_requests WHERE fp = ?1",
            params![fp.0.as_slice()],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_err)?
        .map(to_u64))
}

/// Records (or refreshes) the refusal of `fp` at `at`.
pub(super) fn put_refusal(q: &impl Queries, fp: Fingerprint, at: u64) -> Result<()> {
    q.conn()
        .execute(
            "INSERT INTO refused_requests (fp, at) VALUES (?1, ?2)
             ON CONFLICT(fp) DO UPDATE SET at = excluded.at",
            params![fp.0.as_slice(), to_i64(at)],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Forgets the refusal of `fp`. Returns whether there was one.
pub(super) fn delete_refusal(q: &impl Queries, fp: Fingerprint) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            "DELETE FROM refused_requests WHERE fp = ?1",
            params![fp.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// The invite I sent to `fp`, if any.
pub(super) fn get_invite(q: &impl Queries, fp: Fingerprint) -> Result<Option<InviteRow>> {
    Ok(q.conn()
        .query_row(
            "SELECT at, accepted_at FROM invites WHERE fp = ?1",
            params![fp.0.as_slice()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(map_err)?
        .map(|(at, accepted)| InviteRow {
            at: to_u64(at),
            accepted_at: accepted.map(to_u64),
        }))
}

/// Records that I invited `fp` at `at`, keeping an existing acceptance.
pub(super) fn put_invite_at(q: &impl Queries, fp: Fingerprint, at: u64) -> Result<()> {
    q.conn()
        .execute(
            "INSERT INTO invites (fp, at) VALUES (?1, ?2)
             ON CONFLICT(fp) DO UPDATE SET at = excluded.at",
            params![fp.0.as_slice(), to_i64(at)],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Marks the invite to `fp` accepted at `at`. Returns whether an invite
/// existed.
pub(super) fn set_invite_accepted(q: &impl Queries, fp: Fingerprint, at: u64) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            "UPDATE invites SET accepted_at = ?2 WHERE fp = ?1",
            params![fp.0.as_slice(), to_i64(at)],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// Remembers that `packet_id` carried an invite to `fp` (idempotent).
pub(super) fn insert_invite_packet(
    q: &impl Queries,
    packet_id: PacketId,
    fp: Fingerprint,
) -> Result<()> {
    q.conn()
        .execute(
            "INSERT OR IGNORE INTO invite_packets (packet_id, fp) VALUES (?1, ?2)",
            params![packet_id.0.as_slice(), fp.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(())
}

/// The person `packet_id` invited, if it was an invite packet.
pub(super) fn invite_packet_fp(
    q: &impl Queries,
    packet_id: PacketId,
) -> Result<Option<Fingerprint>> {
    q.conn()
        .query_row(
            "SELECT fp FROM invite_packets WHERE packet_id = ?1",
            params![packet_id.0.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_err)?
        .map(|v| arr(v).map(Fingerprint))
        .transpose()
}

/// The devices of contact `fp` an invite goes to: those whose session (the
/// one `seal_for` would use: most recently received, otherwise most recently
/// created) still waits for a first answer (`pending_initial`), and those
/// with no session yet. A device that already answered is left out.
fn waiting_devices(q: &impl Queries, fp: Fingerprint) -> Result<Vec<DeviceId>> {
    let contact = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    let card = load_card(&contact.card)?;
    let mut out = Vec::new();
    for cert in &card.devices.certs {
        let id = cert.device.id();
        let chosen = q
            .sessions_for(fp, id)?
            .into_iter()
            .max_by_key(|s| (s.last_rx, s.created_at));
        if chosen.is_none_or(|s| s.pending_initial.is_some()) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Applies a `SyncInvite { to, at }` from one of my devices: the invite
/// date of `to` becomes the later of the two (last writer wins), so that
/// the 24-hour cap holds for the account. The contact need not exist: the
/// date outlives its removal. Returns whether anything was written.
pub(super) fn apply_sync_invite(q: &impl Queries, to: Fingerprint, at: u64) -> Result<bool> {
    if get_invite(q, to)?.is_some_and(|row| row.at >= at) {
        return Ok(false);
    }
    put_invite_at(q, to, at)?;
    Ok(true)
}

fn random_message_id(rng: &mut impl CryptoRng) -> MessageId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    MessageId(id)
}

impl Core {
    /// Invites `to`, a contact: my current card (`ContactRequest`) sealed
    /// for each of its devices still waiting for a first answer (a first
    /// call after `add_contact` opens a session with each device; a resend
    /// is the next message of the same pending session). Each packet has a
    /// delivery (no message row: nothing in the conversation) so that its
    /// ack is recognised, and is remembered as an invite packet. The invite
    /// date is shared with my other devices (`SyncInvite`), whose packets
    /// come after the contact's. Everything is written in one transaction.
    ///
    /// Refused, writing nothing: `UnknownContact`, `ContactBlocked`,
    /// `TooSoon` while the last invite (sent by any of my devices, even
    /// before the contact was removed and added again) is less than
    /// `INVITE_INTERVAL_SECS` old, `TooLarge` if my card does not fit in a
    /// packet. When every device already answered, `Ok(vec![])` and nothing
    /// is written.
    pub fn invite(
        &mut self,
        to: &Fingerprint,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        let fp = *to;
        if self.store.get_contact(fp)?.is_none() {
            return Err(CoreError::UnknownContact);
        }
        if self.store.block_state(fp)?.blocked {
            return Err(CoreError::ContactBlocked);
        }
        if let Some(last) = get_invite(&self.store, fp)? {
            let retry_at = last.at.saturating_add(INVITE_INTERVAL_SECS);
            if retry_at > now {
                return Err(CoreError::TooSoon { retry_at });
            }
        }
        let card = self.current_card()?;
        let body = ExtContent::ContactRequest {
            card: Box::new(card),
        }
        .to_body();
        if !envelope::fits_in_packet(&body) {
            return Err(CoreError::TooLarge);
        }
        let waiting = waiting_devices(&self.store, fp)?;
        if waiting.is_empty() {
            return Ok(Vec::new());
        }
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let message_id = random_message_id(rng);
            let target = Target::ContactDevices(fp, waiting);
            let sealed = seal_for(
                tx,
                device,
                &target,
                &body,
                message_id,
                SealTime::at(now),
                rng,
            )?;
            // No device reachable: no invite went out, the cap is not spent.
            if sealed.is_empty() {
                return Ok(Vec::new());
            }
            for (packet, peer) in &sealed {
                let size = delivery::packet_size(packet);
                tx.add_delivery(message_id, packet.id, *peer, false, now, size)?;
                insert_invite_packet(tx, packet.id, fp)?;
            }
            put_invite_at(tx, fp, now)?;
            log(
                tx,
                now,
                None,
                &TransparencyEvent::InviteSent { contact: fp },
            )?;
            let copy = ExtContent::SyncInvite { to: fp, at: now }.to_body();
            let mine = sync::seal_to_own(
                tx,
                device,
                &copy,
                SyncKind::Contact,
                random_message_id(rng),
                SealTime::at(now),
                rng,
            )?;
            let mut out: Vec<Packet> = sealed.into_iter().map(|(p, _)| p).collect();
            out.extend(mine);
            Ok(out)
        })
    }

    /// My current card: the stored one (`own_card`, kept by the link and
    /// device list changes), otherwise, on an account never linked, the
    /// card signed now under my display name, as `contact_card` gives it.
    fn current_card(&self) -> Result<ContactCard> {
        match sync::own_card(&self.store)? {
            Some(card) => Ok(card),
            None => self.sign_card(&self.display_name()?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("db"), &[7; 32]).unwrap();
        (d, s)
    }

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    fn request(n: u8, last_seen: u64) -> RequestRow {
        RequestRow {
            fp: fp(n),
            card: vec![n, 1, 2],
            display_name: format!("r{n}"),
            first_seen: 10,
            last_seen,
            invite_count: 1,
            hidden: false,
            unseen: true,
            last_notified: None,
        }
    }

    fn pending(id: u8, ik: u8, owner: Option<u8>, invite: bool) -> PendingInitial {
        PendingInitial {
            packet_id: PacketId([id; 16]),
            ik: [ik; 32],
            fp: owner.map(fp),
            message_id: (!invite).then_some(MessageId([id; 16])),
            bytes: vec![id; 5],
            received_at: u64::from(id),
            invite,
        }
    }

    #[test]
    fn request_upsert_get_list_count() {
        let (_d, s) = store();
        assert_eq!(get_request(&s, fp(1)).unwrap(), None);
        assert_eq!(count_requests(&s).unwrap(), 0);
        upsert_request(&s, &request(1, 100)).unwrap();
        upsert_request(&s, &request(2, 200)).unwrap();
        assert_eq!(count_requests(&s).unwrap(), 2);
        let mut changed = request(1, 300);
        changed.invite_count = 3;
        changed.hidden = true;
        changed.unseen = false;
        changed.last_notified = Some(250);
        upsert_request(&s, &changed).unwrap();
        assert_eq!(count_requests(&s).unwrap(), 2);
        assert_eq!(get_request(&s, fp(1)).unwrap(), Some(changed));
        insert_pending_initial(&s, &pending(1, 9, Some(1), false)).unwrap();
        insert_pending_initial(&s, &pending(2, 9, Some(1), true)).unwrap();
        let list = list_requests(&s).unwrap();
        assert_eq!(list.len(), 2);
        // Most recently seen first.
        assert_eq!(list[0].fingerprint, fp(1));
        assert_eq!(list[0].display_name, "r1");
        assert_eq!((list[0].first_seen, list[0].last_seen), (10, 300));
        assert_eq!(list[0].invite_count, 3);
        // The held invite packet is not a message.
        assert_eq!(list[0].pending_messages, 1);
        assert!(list[0].hidden && !list[0].unseen);
        assert_eq!(list[1].fingerprint, fp(2));
        assert_eq!(list[1].pending_messages, 0);
    }

    #[test]
    fn deleting_a_request_deletes_its_held_packets_only() {
        let (_d, s) = store();
        upsert_request(&s, &request(1, 1)).unwrap();
        upsert_request(&s, &request(2, 1)).unwrap();
        insert_pending_initial(&s, &pending(1, 9, Some(1), false)).unwrap();
        insert_pending_initial(&s, &pending(2, 9, Some(2), false)).unwrap();
        insert_pending_initial(&s, &pending(3, 8, None, false)).unwrap();
        assert!(delete_request(&s, fp(1)).unwrap());
        assert!(!delete_request(&s, fp(1)).unwrap());
        assert_eq!(get_request(&s, fp(1)).unwrap(), None);
        assert!(list_pending_by_fp(&s, fp(1)).unwrap().is_empty());
        assert_eq!(list_pending_by_fp(&s, fp(2)).unwrap().len(), 1);
        assert_eq!(count_unknown(&s).unwrap(), 1);
    }

    #[test]
    fn pending_initials_insert_list_count_delete() {
        let (_d, s) = store();
        let a = pending(1, 9, Some(1), false);
        assert!(insert_pending_initial(&s, &a).unwrap());
        // The same packet is held once.
        assert!(!insert_pending_initial(&s, &a).unwrap());
        insert_pending_initial(&s, &pending(2, 9, None, true)).unwrap();
        insert_pending_initial(&s, &pending(3, 8, None, false)).unwrap();
        assert_eq!(list_pending_by_fp(&s, fp(1)).unwrap(), vec![a.clone()]);
        assert_eq!(count_pending_for_fp(&s, fp(1)).unwrap(), 1);
        assert_eq!(count_unknown(&s).unwrap(), 2);
        let by_ik = list_pending_by_ik(&s, &[9; 32]).unwrap();
        assert_eq!(by_ik.len(), 2);
        assert_eq!(by_ik[0], a);
        assert_eq!(by_ik[1].fp, None);
        assert!(by_ik[1].invite && by_ik[1].message_id.is_none());
        assert!(delete_pending(&s, PacketId([1; 16])).unwrap());
        assert!(!delete_pending(&s, PacketId([1; 16])).unwrap());
        assert_eq!(count_pending_for_fp(&s, fp(1)).unwrap(), 0);
    }

    #[test]
    fn unknown_packets_attach_to_a_request_by_key() {
        let (_d, s) = store();
        insert_pending_initial(&s, &pending(1, 9, None, false)).unwrap();
        insert_pending_initial(&s, &pending(2, 9, None, true)).unwrap();
        insert_pending_initial(&s, &pending(3, 8, None, false)).unwrap();
        insert_pending_initial(&s, &pending(4, 9, Some(5), false)).unwrap();
        assert_eq!(attach_unknown_to_fp(&s, &[9; 32], fp(7)).unwrap(), 2);
        assert_eq!(count_pending_for_fp(&s, fp(7)).unwrap(), 2);
        // The packet already attached to another request is left alone.
        assert_eq!(count_pending_for_fp(&s, fp(5)).unwrap(), 1);
        assert_eq!(count_unknown(&s).unwrap(), 1);
        assert_eq!(attach_unknown_to_fp(&s, &[9; 32], fp(7)).unwrap(), 0);
    }

    #[test]
    fn refusals_are_put_refreshed_and_deleted() {
        let (_d, s) = store();
        assert_eq!(get_refusal(&s, fp(1)).unwrap(), None);
        put_refusal(&s, fp(1), 50).unwrap();
        put_refusal(&s, fp(1), 60).unwrap();
        assert_eq!(get_refusal(&s, fp(1)).unwrap(), Some(60));
        assert!(delete_refusal(&s, fp(1)).unwrap());
        assert!(!delete_refusal(&s, fp(1)).unwrap());
        assert_eq!(get_refusal(&s, fp(1)).unwrap(), None);
    }

    #[test]
    fn invites_keep_their_acceptance_when_resent() {
        let (_d, s) = store();
        assert_eq!(get_invite(&s, fp(1)).unwrap(), None);
        assert!(!set_invite_accepted(&s, fp(1), 5).unwrap());
        put_invite_at(&s, fp(1), 10).unwrap();
        assert_eq!(
            get_invite(&s, fp(1)).unwrap(),
            Some(InviteRow {
                at: 10,
                accepted_at: None
            })
        );
        assert!(set_invite_accepted(&s, fp(1), 20).unwrap());
        put_invite_at(&s, fp(1), 30).unwrap();
        assert_eq!(
            get_invite(&s, fp(1)).unwrap(),
            Some(InviteRow {
                at: 30,
                accepted_at: Some(20)
            })
        );
    }

    #[test]
    fn invite_packets_map_back_to_the_invited() {
        let (_d, s) = store();
        assert_eq!(invite_packet_fp(&s, PacketId([1; 16])).unwrap(), None);
        insert_invite_packet(&s, PacketId([1; 16]), fp(3)).unwrap();
        insert_invite_packet(&s, PacketId([1; 16]), fp(4)).unwrap();
        assert_eq!(
            invite_packet_fp(&s, PacketId([1; 16])).unwrap(),
            Some(fp(3))
        );
    }

    #[test]
    fn a_fresh_store_has_the_v6_tables() {
        let (_d, s) = store();
        for t in [
            "contact_requests",
            "pending_initials",
            "refused_requests",
            "invites",
            "invite_packets",
        ] {
            let n: i64 = s
                .conn()
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0);
        }
    }
}
