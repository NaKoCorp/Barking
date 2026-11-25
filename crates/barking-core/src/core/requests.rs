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

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::log_limit::{LogLimiter, log_limited};
use super::receive::{
    R_BAD_CONTENT, R_PENDING_REQUEST, R_REQUEST_FORGED, R_UNKNOWN_SENDER, R_UNREADABLE,
    REPLAY_TRANSPORT, Rx, RxClock, RxOut, quarantine, rx_packet, trial_open,
};
use super::send::{SealTime, Target, seal_for};
use super::{
    Core, MAX_AGE_SECS, ReceiveOutcome, contacts, delivery, load_card, log, session_id, sync,
};
use crate::contact::ContactCard;
use crate::content::{ExtContent, MAX_REPLAYED};
use crate::envelope::{self, Body, Envelope, Wire, parse_wire};
use crate::handshake::PrekeySecrets;
use crate::handshake::pqxdh::InitialMessage;
use crate::identity::{DeviceId, DeviceKeys, DevicePublic, Fingerprint};
use crate::packet::{DEFAULT_TTL_SECS, Packet, PacketId};
use crate::ratchet::RatchetMessage;
use crate::store::{ContactRow, MessageId, Queries, arr, map_err, to_i64, to_u64};
use crate::transparency::{RequestResolution, SyncKind, TransparencyEvent};
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
    /// The invite was accepted: `at` is when I first learned it (an ack of
    /// an invite, `REQUEST_ACCEPTED` or any message from the contact).
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
/// waits in the queue of unknown senders; `session_id` is that of the
/// session its Initial opens; `invite` marks the packet of an invite rather
/// than a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PendingInitial {
    pub packet_id: PacketId,
    pub ik: [u8; 32],
    pub fp: Option<Fingerprint>,
    pub session_id: [u8; 16],
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

/// Removes the request row of `fp` only: its held packets stay, attached by
/// `fp`, to be replayed. Returns whether a request existed.
pub(super) fn delete_request_row(q: &impl Queries, fp: Fingerprint) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            "DELETE FROM contact_requests WHERE fp = ?1",
            params![fp.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(n > 0)
}

/// Closes the request of `fp`, if there is one (`how`, logged); its held
/// packets stay, to be replayed (`replay_pending`). Returns whether a
/// request existed.
pub(super) fn resolve_request(
    q: &impl Queries,
    fp: Fingerprint,
    how: RequestResolution,
    now: u64,
) -> Result<bool> {
    if !delete_request_row(q, fp)? {
        return Ok(false);
    }
    log(
        q,
        now,
        None,
        &TransparencyEvent::ContactRequestResolved { contact: fp, how },
    )?;
    Ok(true)
}

/// Closes the pending request of `fp` for good (`how`, logged), together
/// with the packets held for it and those of its devices waiting in the
/// queue of unknown senders: nothing of it is replayed. Returns whether a
/// request existed.
pub(super) fn close_request(
    q: &impl Queries,
    fp: Fingerprint,
    how: RequestResolution,
    now: u64,
) -> Result<bool> {
    let Some(row) = get_request(q, fp)? else {
        return Ok(false);
    };
    if let Ok(card) = load_card(&row.card) {
        for c in &card.devices.certs {
            q.conn()
                .execute(
                    "DELETE FROM pending_initials WHERE fp IS NULL AND ik = ?1",
                    params![c.device.dh.as_slice()],
                )
                .map_err(map_err)?;
        }
    }
    delete_request(q, fp)?;
    log(
        q,
        now,
        None,
        &TransparencyEvent::ContactRequestResolved { contact: fp, how },
    )?;
    Ok(true)
}

/// Refuses `fp`: its request and packets are dropped, and the refusal is
/// dated `at` (never moved back), so that an invitation sealed before it is
/// dropped on arrival (spec §7.4).
fn refuse_in(q: &impl Queries, fp: Fingerprint, at: u64, now: u64) -> Result<()> {
    close_request(q, fp, RequestResolution::Refused, now)?;
    let at = get_refusal(q, fp)?.map_or(at, |known| known.max(at));
    put_refusal(q, fp, at)
}

/// Applies a `SyncRefused { fp, at }` from one of my devices, as a refusal
/// here (last writer wins on the date). Returns whether anything changed.
pub(super) fn apply_sync_refused(
    q: &impl Queries,
    fp: Fingerprint,
    at: u64,
    now: u64,
) -> Result<bool> {
    let known = get_refusal(q, fp)?;
    let had_request = get_request(q, fp)?.is_some();
    if !had_request && known.is_some_and(|k| k >= at) {
        return Ok(false);
    }
    refuse_in(q, fp, at, now)?;
    Ok(true)
}

/// Periodic purge: requests with no new packet for `REQUEST_RETENTION_SECS`
/// (logged `Expired`, with their packets), packets of the queue of unknown
/// senders and refusals older than their retention, and packets held for a
/// fingerprint with no request (a contact's, after an acceptance or a new
/// device) older than `UNKNOWN_RETENTION_SECS` by arrival.
pub(super) fn purge_requests(q: &impl Queries, now: u64) -> Result<()> {
    let expired: Vec<Fingerprint> = {
        let mut stmt = q
            .conn()
            .prepare("SELECT fp FROM contact_requests WHERE last_seen + ?1 < ?2")
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![to_i64(REQUEST_RETENTION_SECS), to_i64(now)], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(map_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Fingerprint(arr(row.map_err(map_err)?)?));
        }
        out
    };
    for fp in expired {
        close_request(q, fp, RequestResolution::Expired, now)?;
    }
    q.conn()
        .execute(
            "DELETE FROM pending_initials
             WHERE received_at + ?1 < ?2
               AND (fp IS NULL OR fp NOT IN (SELECT fp FROM contact_requests))",
            params![to_i64(UNKNOWN_RETENTION_SECS), to_i64(now)],
        )
        .map_err(map_err)?;
    q.conn()
        .execute(
            "DELETE FROM refused_requests WHERE at + ?1 < ?2",
            params![to_i64(REFUSAL_RETENTION_SECS), to_i64(now)],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Attaches to `fp`, a contact, the packets of the queue of unknown senders
/// whose initial message names one of the devices its stored card lists
/// (spec §7.3, step 3: "the request and the queue of unknown senders for
/// these keys"), to be replayed with the request's. The replay
/// authenticates each one; one that fails is quarantined and dropped.
/// Returns how many were attached.
pub(super) fn attach_queued_to_contact(q: &impl Queries, fp: Fingerprint) -> Result<usize> {
    let Some(contact) = q.get_contact(fp)? else {
        return Ok(0);
    };
    let card = load_card(&contact.card)?;
    let mut n = 0;
    for c in &card.devices.certs {
        n += q
            .conn()
            .execute(
                "UPDATE pending_initials SET fp = ?1 WHERE fp IS NULL AND ik = ?2",
                params![fp.0.as_slice(), c.device.dh.as_slice()],
            )
            .map_err(map_err)?;
    }
    Ok(n)
}

/// Contacts with first packets still held for them: a request resolved
/// (accepted, added here or on another of my devices) whose replay has not
/// run or was interrupted, or a known contact's new device (spec §7.7).
pub(super) fn held_for_contacts(q: &impl Queries) -> Result<Vec<Fingerprint>> {
    let mut stmt = q
        .conn()
        .prepare(
            "SELECT DISTINCT p.fp FROM pending_initials p
             JOIN contacts c ON c.fp = p.fp",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(map_err)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(Fingerprint(arr(row.map_err(map_err)?)?));
    }
    Ok(out)
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

const PENDING_COLUMNS: &str =
    "packet_id, ik, fp, session_id, message_id, bytes, received_at, invite";

type PendingRaw = (
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
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
        r.get(7)?,
    ))
}

fn into_pending(raw: PendingRaw) -> Result<PendingInitial> {
    let (packet_id, ik, fp, session_id, message_id, bytes, received_at, invite) = raw;
    Ok(PendingInitial {
        packet_id: PacketId(arr(packet_id)?),
        ik: arr(ik)?,
        fp: fp.map(|v| arr(v).map(Fingerprint)).transpose()?,
        session_id: arr(session_id)?,
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
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            ),
            params![
                p.packet_id.0.as_slice(),
                p.ik.as_slice(),
                p.fp.map(|f| f.0.to_vec()),
                p.session_id.as_slice(),
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
             ORDER BY received_at, rowid"
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
             ORDER BY received_at, rowid"
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
/// key `ik` to the request of `fp`, oldest first, while it holds fewer than
/// `MAX_PACKETS_PER_REQUEST`. Each must first pass `authentic`, which gives
/// the message id of its content (then recorded) or `None`. The others
/// (refused, or beyond the cap) are dropped from the queue. Returns how
/// many were attached.
pub(super) fn attach_unknown_to_fp(
    q: &impl Queries,
    ik: &[u8; 32],
    fp: Fingerprint,
    mut authentic: impl FnMut(&PendingInitial) -> Result<Option<MessageId>>,
) -> Result<usize> {
    let queued = query_pending(
        q,
        &format!(
            "SELECT {PENDING_COLUMNS} FROM pending_initials WHERE ik = ?1 AND fp IS NULL
             ORDER BY received_at, rowid"
        ),
        ik,
    )?;
    let mut attached = 0;
    for p in queued {
        let message_id = if count_pending_for_fp(q, fp)? < MAX_PACKETS_PER_REQUEST {
            authentic(&p)?
        } else {
            None
        };
        let Some(message_id) = message_id else {
            delete_pending(q, p.packet_id)?;
            continue;
        };
        q.conn()
            .execute(
                "UPDATE pending_initials SET fp = ?2, message_id = ?3 WHERE packet_id = ?1",
                params![
                    p.packet_id.0.as_slice(),
                    fp.0.as_slice(),
                    message_id.0.as_slice()
                ],
            )
            .map_err(map_err)?;
        attached += 1;
    }
    Ok(attached)
}

/// The held first packet with this id, if any.
pub(super) fn get_pending(q: &impl Queries, packet_id: PacketId) -> Result<Option<PendingInitial>> {
    Ok(query_pending(
        q,
        &format!("SELECT {PENDING_COLUMNS} FROM pending_initials WHERE packet_id = ?1"),
        &packet_id.0,
    )?
    .pop())
}

/// The request whose card lists a device with the X25519 key `ik` (and, when
/// the Initial names it, the signing key `sig`), with that device. Several:
/// none (ambiguous).
fn request_of_device(
    q: &impl Queries,
    ik: &[u8; 32],
    sig: Option<[u8; 32]>,
) -> Result<Option<(Fingerprint, DevicePublic)>> {
    let mut stmt = q
        .conn()
        .prepare("SELECT fp, card FROM contact_requests")
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(map_err)?;
    let mut found = None;
    for row in rows {
        let (fp, card) = row.map_err(map_err)?;
        let card = load_card(&card)?;
        let listed = card
            .devices
            .certs
            .iter()
            .find(|c| c.device.dh == *ik && sig.is_none_or(|s| s == c.device.sig));
        if let Some(cert) = listed {
            if found.is_some() {
                return Ok(None);
            }
            found = Some((Fingerprint(arr(fp)?), cert.device));
        }
    }
    Ok(found)
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

/// Forgets the refusal of `fp`. Returns whether there was one. Only the
/// storage test uses it: refusals leave by purge or are overwritten.
#[allow(dead_code)]
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

/// Marks the invite to `fp` accepted at `at`, keeping an earlier date.
/// Returns whether an invite existed.
pub(super) fn set_invite_accepted(q: &impl Queries, fp: Fingerprint, at: u64) -> Result<bool> {
    let n = q
        .conn()
        .execute(
            "UPDATE invites SET accepted_at = coalesce(accepted_at, ?2) WHERE fp = ?1",
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

/// Fixed reason logged (grouped) when a new sender finds the list of
/// requests full.
const R_REQUESTS_FULL: &str = "too many pending contact requests";

/// A first packet from a device no contact lists, being handled.
struct First<'a> {
    device: &'a DeviceKeys,
    prekeys: &'a PrekeySecrets,
    packet: &'a Packet,
    init: &'a InitialMessage,
    /// The session its Initial opens.
    session: [u8; 16],
    now: u64,
}

impl First<'_> {
    /// The packet as a held row.
    fn held(
        &self,
        fp: Option<Fingerprint>,
        message_id: Option<MessageId>,
        invite: bool,
    ) -> PendingInitial {
        PendingInitial {
            packet_id: self.packet.id,
            ik: self.init.ik,
            fp,
            session_id: self.session,
            message_id,
            bytes: self.packet.encode(),
            received_at: self.now,
            invite,
        }
    }

    /// Trial opening of a held packet as `peer`, a device a request's card
    /// lists (`trial_open`, writing nothing): the message id of its content
    /// if it authenticates, otherwise `None`.
    fn authenticate(
        &self,
        q: &impl Queries,
        held: &PendingInitial,
        peer: &DevicePublic,
    ) -> Result<Option<MessageId>> {
        let Ok(packet) = Packet::decode(&held.bytes) else {
            return Ok(None);
        };
        let Ok(Wire::Initial {
            ek,
            sealed_init,
            msg,
        }) = parse_wire(&packet.payload)
        else {
            return Ok(None);
        };
        let Ok(init) = envelope::open_initial(self.device, &ek, &sealed_init) else {
            return Ok(None);
        };
        if init.ik != peer.dh || init.sig.is_some_and(|sig| sig != peer.sig) {
            return Ok(None);
        }
        let opened = trial_open(
            q,
            self.device,
            self.prekeys,
            &packet,
            &init,
            peer,
            &msg,
            self.now,
        )?;
        Ok(opened.ok().map(|env| MessageId(env.message_id)))
    }
}

/// A `Wire::Initial` to my introduction mailbox from a device no contact
/// lists (`find_sender` gave `R_UNKNOWN_SENDER`), handled without accepting
/// anything: no session written, no ack, nothing marked seen (spec §7.1).
///
/// 1. Trial opening (`trial_open`) as the device the Initial names; refused:
///    quarantine. An Initial without a signing key (written by 0.6.0) is
///    opened as the device of a request's card with its `ik`; with no such
///    card it cannot be read yet, and is queued as it is (4). Nothing joins
///    a request without passing this trial.
/// 2. An invite (`ContactRequest`) creates or updates the request of its
///    card (`on_invitation`).
/// 3. Any other content, from a device a request's card lists, joins that
///    request: `R_PENDING_REQUEST`.
/// 4. Otherwise it goes to the queue of unknown senders: `R_UNKNOWN_SENDER`.
///
/// Beyond a limit the new packet is dropped. A packet already held is a
/// `Duplicate`.
#[allow(clippy::too_many_arguments)]
pub(super) fn on_unknown_initial(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    device: &DeviceKeys,
    prekeys: &PrekeySecrets,
    packet: &Packet,
    init: &InitialMessage,
    msg: &RatchetMessage,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let first = First {
        device,
        prekeys,
        packet,
        init,
        session: session_id(&init.ek),
        now,
    };
    let held = get_pending(q, packet.id)?;
    let peer = match init.initiator() {
        Some(peer) => peer,
        // Written by 0.6.0 (no signing key): its session data still bind
        // `blake3(sig || dh)`, so a card listing the device can authenticate it.
        None => match request_of_device(q, &init.ik, None)? {
            Some((_, listed)) => listed,
            None => {
                if held.is_some() {
                    return duplicate(q, limiter, packet, now);
                }
                return queue_unread(q, limiter, &first);
            }
        },
    };
    // A held packet whose content was read (`message_id` set): its identifier
    // was bound to that content, a repeat is a duplicate (as `is_seen`).
    if held.as_ref().is_some_and(|p| p.message_id.is_some()) {
        return duplicate(q, limiter, packet, now);
    }
    let env = match trial_open(q, device, prekeys, packet, init, &peer, msg, now)? {
        Ok(env) => env,
        Err(reason) => return quarantine(q, limiter, packet, now, reason),
    };
    // A packet held unread under this identifier (an Initial without a
    // signing key) proves nothing: the authenticated one replaces it.
    if held.is_some() {
        delete_pending(q, packet.id)?;
    }
    let card = match &env.body {
        Body::Ext { kind, data, .. } => match ExtContent::decode(*kind, data) {
            Ok(Some(ExtContent::ContactRequest { card })) => Some(card),
            Ok(_) => None,
            Err(_) => return quarantine(q, limiter, packet, now, R_BAD_CONTENT),
        },
        _ => None,
    };
    match card {
        Some(card) => on_invitation(q, limiter, &first, &peer, &env, &card, rng),
        None => hold_message(q, limiter, &first, &peer, MessageId(env.message_id)),
    }
}

/// A packet seen again while it is held: nothing changes.
fn duplicate(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    now: u64,
) -> Result<RxOut> {
    log_limited(
        q,
        limiter,
        now,
        Some(packet.id),
        &TransparencyEvent::DuplicateIgnored {
            packet_id: packet.id,
        },
    )?;
    Ok((ReceiveOutcome::Duplicate, None))
}

/// Steps 3 and 4 of `on_unknown_initial`: a first packet that is not an
/// invite, authenticated as sealed by `peer`, joins the request whose card
/// lists `peer`, otherwise the queue of unknown senders, each within its cap.
fn hold_message(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    first: &First<'_>,
    peer: &DevicePublic,
    message_id: MessageId,
) -> Result<RxOut> {
    let Some((fp, _)) = request_of_device(q, &first.init.ik, Some(peer.sig))? else {
        return queue(q, limiter, first, Some(message_id));
    };
    if count_pending_for_fp(q, fp)? < MAX_PACKETS_PER_REQUEST {
        insert_pending_initial(q, &first.held(Some(fp), Some(message_id), false))?;
        touch_request(q, fp, first.now)?;
    }
    quarantine(q, limiter, first.packet, first.now, R_PENDING_REQUEST)
}

/// Step 4 for an Initial without a signing key whose device no request's
/// card lists: queued unread (`message_id` NULL), within the cap.
fn queue_unread(q: &impl Queries, limiter: &mut LogLimiter, first: &First<'_>) -> Result<RxOut> {
    queue(q, limiter, first, None)
}

/// Step 4: the queue of unknown senders, within its cap.
fn queue(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    first: &First<'_>,
    message_id: Option<MessageId>,
) -> Result<RxOut> {
    if count_unknown(q)? < MAX_UNKNOWN_INITIALS {
        insert_pending_initial(q, &first.held(None, message_id, false))?;
    }
    quarantine(q, limiter, first.packet, first.now, R_UNKNOWN_SENDER)
}

/// A new packet joined the request of `fp`: seen now, and shown again.
fn touch_request(q: &impl Queries, fp: Fingerprint, now: u64) -> Result<()> {
    q.conn()
        .execute(
            "UPDATE contact_requests SET last_seen = ?2, unseen = 1 WHERE fp = ?1",
            params![fp.0.as_slice(), to_i64(now)],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Whether `card` lists `peer` exactly (signing and X25519 keys).
fn lists(card: &ContactCard, peer: &DevicePublic) -> bool {
    card.devices.certs.iter().any(|c| c.device == *peer)
}

/// Step 2 of `on_unknown_initial`: an invite, authenticated as sealed by
/// `peer`. Its card must pass `check_card` (otherwise `R_CARD_REFUSED`) and
/// list `peer` (otherwise `R_REQUEST_FORGED`). A blocked fingerprint, or an
/// invite sealed before the last refusal, is dropped (`Ignored`); so is a
/// new sender while `MAX_PENDING_REQUESTS` requests are kept. The request
/// keeps the newest card, counts the distinct invites (envelope message
/// id) and notifies at most once per `NOTIFY_INTERVAL_SECS`. A card of a
/// known contact goes to `on_contact_device` instead.
#[allow(clippy::too_many_arguments)]
fn on_invitation(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    first: &First<'_>,
    peer: &DevicePublic,
    env: &Envelope,
    card: &ContactCard,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let (packet, now) = (first.packet, first.now);
    let fp = card.fingerprint();
    if let Some(current) = q.get_contact(fp)? {
        return on_contact_device(q, limiter, first, peer, env, &current, card, rng);
    }
    match contacts::check_card(q, card) {
        Ok(_) => {}
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => return Err(e),
        Err(_) => return quarantine(q, limiter, packet, now, contacts::R_CARD_REFUSED),
    }
    if !lists(card, peer) {
        return quarantine(q, limiter, packet, now, R_REQUEST_FORGED);
    }
    if q.block_state(fp)?.drops(env.sent_at)
        || get_refusal(q, fp)?.is_some_and(|at| env.sent_at <= at)
    {
        return Ok((ReceiveOutcome::Ignored, None));
    }
    let existing = get_request(q, fp)?;
    if existing.is_none() && count_requests(q)? >= MAX_PENDING_REQUESTS {
        log_limited(
            q,
            limiter,
            now,
            Some(packet.id),
            &TransparencyEvent::DecryptFailed {
                packet_id: packet.id,
                reason: R_REQUESTS_FULL.to_owned(),
            },
        )?;
        return Ok((ReceiveOutcome::Ignored, None));
    }
    let message_id = MessageId(env.message_id);
    let new_invite = !list_pending_by_fp(q, fp)?
        .iter()
        .any(|p| p.invite && p.message_id == Some(message_id));
    let resent = existing.is_some();
    let mut row = match existing {
        Some(mut row) => {
            let kept = load_card(&row.card)?;
            if card.devices.supersedes(&kept.devices) || card.devices == kept.devices {
                row.card = card.encode();
                row.display_name.clone_from(&card.display_name);
            }
            row.invite_count = row.invite_count.saturating_add(u32::from(new_invite));
            row
        }
        None => RequestRow {
            fp,
            card: card.encode(),
            display_name: card.display_name.clone(),
            first_seen: now,
            last_seen: now,
            invite_count: 1,
            hidden: false,
            unseen: true,
            last_notified: None,
        },
    };
    row.last_seen = now;
    row.unseen = true;
    let notify = row
        .last_notified
        .is_none_or(|at| now.saturating_sub(at) >= NOTIFY_INTERVAL_SECS);
    if notify {
        row.last_notified = Some(now);
    }
    upsert_request(q, &row)?;
    hold_invitation(q, first, fp, peer, message_id)?;
    if !resent || new_invite {
        log(
            q,
            now,
            Some(packet.id),
            &TransparencyEvent::ContactRequestReceived { contact: fp },
        )?;
    }
    Ok((
        ReceiveOutcome::ContactRequest {
            contact: fp,
            resent,
            notify,
        },
        None,
    ))
}

/// An invite from a device of a known contact that its card, as I know it,
/// does not list: a device linked since, whose card never reached me (spec
/// §13). No request: the newer card it carries is a card update, verified
/// as one (`verify_card_update`; older or identical: `R_CARD_REFUSED`). It
/// must list `peer` (otherwise `R_REQUEST_FORGED`), and is then applied as
/// `accept_card_update` does. The packet is held with the contact's
/// fingerprint, to be replayed: `R_PENDING_REQUEST`. A blocked contact's
/// card is applied too (as its card updates are), its invite dropped.
#[allow(clippy::too_many_arguments)]
fn on_contact_device(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    first: &First<'_>,
    peer: &DevicePublic,
    env: &Envelope,
    current: &ContactRow,
    card: &ContactCard,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let (packet, now, fp, device) = (first.packet, first.now, current.fp, first.device);
    let verified = match contacts::verify_card_update(q, current, card)? {
        Ok(contacts::CardUpdate::Newer(verified)) => verified,
        Ok(contacts::CardUpdate::Superseded) => {
            return quarantine(q, limiter, packet, now, contacts::R_CARD_REFUSED);
        }
        Err(reason) => return quarantine(q, limiter, packet, now, reason),
    };
    if !lists(card, peer) {
        return quarantine(q, limiter, packet, now, R_REQUEST_FORGED);
    }
    let (added, removed) =
        contacts::apply_card_update(q, device, current, card, verified, now, rng)?;
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::ContactCardUpdated {
            contact: fp,
            alias: current.alias.clone(),
            added: u32::try_from(added.len()).unwrap_or(u32::MAX),
            removed,
        },
    )?;
    sync::send_own_card(q, device, fp, &added, now, rng)?;
    if q.block_state(fp)?.drops(env.sent_at) {
        return Ok((ReceiveOutcome::Ignored, None));
    }
    hold_invitation(q, first, fp, peer, MessageId(env.message_id))?;
    quarantine(q, limiter, packet, now, R_PENDING_REQUEST)
}

/// Holds an invite packet for `fp`. An invite from another session of the
/// same device replaces that device's packets; the newest invite replaces
/// the one held (one per request). The queued packets of the same device
/// then join it, within the cap, each once it authenticates as `peer`
/// (the device the invite's card lists); the others are dropped.
///
/// A replaced packet whose content was read is marked seen: never acked,
/// it may be delivered again, and must not come back (nor count as a new
/// invite). One held unread is only dropped.
fn hold_invitation(
    q: &impl Queries,
    first: &First<'_>,
    fp: Fingerprint,
    peer: &DevicePublic,
    message_id: MessageId,
) -> Result<()> {
    let other_session = list_pending_by_ik(q, &first.init.ik)?
        .into_iter()
        .filter(|p| p.session_id != first.session && p.fp.is_none_or(|f| f == fp));
    let older_invite = list_pending_by_fp(q, fp)?.into_iter().filter(|p| p.invite);
    for p in other_session.chain(older_invite) {
        if p.message_id.is_some() {
            q.mark_seen(p.packet_id, first.now)?;
        }
        delete_pending(q, p.packet_id)?;
    }
    insert_pending_initial(q, &first.held(Some(fp), Some(message_id), true))?;
    attach_unknown_to_fp(q, &first.init.ik, fp, |held| {
        first.authenticate(q, held, peer)
    })?;
    Ok(())
}

/// Replays one held first packet (spec §7.3, step 3), in one transaction
/// that also drops its row: an interrupted replay resumes with the next
/// packet, never twice the same. The packet goes through the normal receive
/// path past the mailbox match, its checks dated at its reception, its
/// writes and ack at `now` (`RxClock`).
pub(super) fn replay_held(
    core: &mut Core,
    held: &PendingInitial,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<ReceiveOutcome> {
    let my_fp = core.fingerprint();
    let Core {
        store,
        device,
        prekeys,
        root,
        log_limiter,
        ..
    } = core;
    let clock = RxClock {
        check: held.received_at,
        write: now,
    };
    let (outcome, new_prekeys) = store.transaction(|tx| -> Result<RxOut> {
        delete_pending(tx, held.packet_id)?;
        let Ok(packet) = Packet::decode(&held.bytes) else {
            let reason = R_UNREADABLE.to_owned();
            return Ok((ReceiveOutcome::Quarantined { reason }, None));
        };
        let rx = Rx {
            limiter: log_limiter,
            device,
            prekeys,
            root: root.as_ref(),
            my_fp: &my_fp,
        };
        rx_packet(
            tx,
            rx,
            &packet,
            true,
            Vec::new(),
            true,
            REPLAY_TRANSPORT,
            clock,
            rng,
        )
    })?;
    if let Some(p) = new_prekeys {
        *prekeys = p;
    }
    Ok(outcome)
}

/// Replays the first packets held for `fp`, oldest first (`replay_held`),
/// each with the envelope message id it was held under.
fn replay_all(
    core: &mut Core,
    fp: Fingerprint,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<(Option<MessageId>, ReceiveOutcome)>> {
    let mut out = Vec::new();
    for held in list_pending_by_fp(&core.store, fp)? {
        let outcome = replay_held(core, &held, now, rng)?;
        out.push((held.message_id, outcome));
    }
    Ok(out)
}

/// Replays the first packets held for `fp`, now a contact, oldest first:
/// their outcomes, in that order.
pub(super) fn replay_pending(
    core: &mut Core,
    fp: Fingerprint,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<ReceiveOutcome>> {
    Ok(replay_all(core, fp, now, rng)?
        .into_iter()
        .map(|(_, o)| o)
        .collect())
}

/// Replays what is held for every contact (`held_for_contacts`): after an
/// add here or synchronized from another of my devices, after a known
/// contact's card was updated by an invite, or a replay interrupted.
pub(super) fn replay_for_contacts(
    core: &mut Core,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    for fp in held_for_contacts(&core.store)? {
        replay_pending(core, fp, now, rng)?;
    }
    Ok(())
}

/// What `Core::accept_request` did.
#[derive(Debug)]
pub struct Accepted {
    /// The new contact.
    pub contact: Fingerprint,
    /// The outcomes of its held packets, replayed oldest first. The ack of
    /// a packet its sender no longer waits for is not queued: the `ack` of
    /// such a `Message` must not be sent either.
    pub replayed: Vec<ReceiveOutcome>,
    /// `REQUEST_ACCEPTED`, sealed for each of the contact's devices (also
    /// in the send queue).
    pub packets: Vec<Packet>,
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

    /// State of the invite I sent to `contact` (spec §6.2): `None` without
    /// one; `Accepted` once answered; otherwise `Unanswered` once the last
    /// invite's packet has expired (`at + DEFAULT_TTL_SECS <= now`), `Sent`
    /// before. The row outlives the contact (the 24-hour cap does too).
    pub fn invite_state(&self, contact: &Fingerprint, now: u64) -> Result<InviteState> {
        Ok(match get_invite(&self.store, *contact)? {
            None => InviteState::None,
            Some(InviteRow {
                accepted_at: Some(at),
                ..
            }) => InviteState::Accepted { at },
            Some(InviteRow { at, .. }) if at.saturating_add(DEFAULT_TTL_SECS) <= now => {
                InviteState::Unanswered { at }
            }
            Some(InviteRow { at, .. }) => InviteState::Sent { at },
        })
    }

    /// Accepts the pending request of `fp` (spec §7.3):
    ///
    /// 1. in one transaction, adds its card as a contact without an alias
    ///    (never the declared name: an alias taken would replace another
    ///    contact), then sets `alias` if given, queues the contact for my
    ///    other devices (`SyncContact`) and closes the request; its devices'
    ///    packets in the queue of unknown senders join the held ones;
    /// 2. replays its held packets, oldest first, one transaction each
    ///    (`replay_held`);
    /// 3. tells the contact (`REQUEST_ACCEPTED`, with the ids of at most
    ///    `MAX_REPLAYED` messages shown), by the normal send path.
    ///
    /// No request: `UnknownContact`. An `alias` already used by another
    /// contact: `Malformed`, and nothing is written.
    pub fn accept_request(
        &mut self,
        fp: &Fingerprint,
        alias: Option<&str>,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Accepted> {
        self.ensure_active()?;
        let fp = *fp;
        let row = get_request(&self.store, fp)?.ok_or(CoreError::UnknownContact)?;
        if self.store.block_state(fp)?.blocked {
            return Err(CoreError::ContactBlocked);
        }
        let card = load_card(&row.card)?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            contacts::add_in(tx, device, &card, None, now, rng)?;
            if let Some(alias) = alias {
                contacts::set_alias_in(tx, fp, alias)?;
            }
            let time = sync::touch(tx, fp, now, false, device.public().id())?;
            sync::send_state(tx, device, fp, time, rng)?;
            resolve_request(tx, fp, RequestResolution::Accepted, now)?;
            attach_queued_to_contact(tx, fp)?;
            Ok(())
        })?;
        let replayed = replay_all(self, fp, now, rng)?;
        let shown: Vec<MessageId> = replayed
            .iter()
            .filter(|(_, o)| {
                matches!(
                    o,
                    ReceiveOutcome::Message { .. } | ReceiveOutcome::NeedsUpdate { .. }
                )
            })
            .filter_map(|(id, _)| *id)
            .take(MAX_REPLAYED)
            .collect();
        let body = ExtContent::RequestAccepted { replayed: shown }.to_body();
        let Core { store, device, .. } = self;
        let packets = store.transaction(|tx| {
            let message_id = random_message_id(rng);
            let target = Target::Contact(fp);
            let sealed = seal_for(
                tx,
                device,
                &target,
                &body,
                message_id,
                SealTime::at(now),
                rng,
            )?;
            // A delivery without a message row, as an invite: its ack is
            // recognised and clears the send queue.
            for (packet, peer) in &sealed {
                let size = delivery::packet_size(packet);
                tx.add_delivery(message_id, packet.id, *peer, false, now, size)?;
            }
            Ok(sealed.into_iter().map(|(p, _)| p).collect())
        })?;
        Ok(Accepted {
            contact: fp,
            replayed: replayed.into_iter().map(|(_, o)| o).collect(),
            packets,
        })
    }

    /// The pending requests, hidden ones included, most recently seen first.
    pub fn requests(&self) -> Result<Vec<ContactRequest>> {
        list_requests(&self.store)
    }

    /// Refuses the request of `fp` (spec §7.4): the request and its packets
    /// are dropped and nothing goes to the requester (no ack: for it a
    /// refusal looks like no answer). Only the date is kept, to drop the
    /// invitations sealed before it, and shared with my other devices
    /// (`SyncRefused`): the returned packets are for them. No request:
    /// `UnknownContact`.
    pub fn refuse_request(
        &mut self,
        fp: &Fingerprint,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        let fp = *fp;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            if get_request(tx, fp)?.is_none() {
                return Err(CoreError::UnknownContact);
            }
            refuse_in(tx, fp, now, now)?;
            let copy = ExtContent::SyncRefused { fp, at: now }.to_body();
            sync::seal_to_own(
                tx,
                device,
                &copy,
                SyncKind::Contact,
                random_message_id(rng),
                SealTime::at(now),
                rng,
            )
        })
    }

    /// Blocks the requester `fp` (spec §7.5): `block_contact`'s block, which
    /// needs no contact and is shared with my other devices (`SyncOp::Block`,
    /// whose packets are returned), then the request and its packets are
    /// dropped. Later invitations are dropped silently. No request:
    /// `UnknownContact`.
    pub fn block_request(
        &mut self,
        fp: &Fingerprint,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        let fp = *fp;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            if get_request(tx, fp)?.is_none() {
                return Err(CoreError::UnknownContact);
            }
            let out = contacts::set_block_sealed(tx, device, fp, true, now, rng)?;
            close_request(tx, fp, RequestResolution::Blocked, now)?;
            Ok(out)
        })
    }

    /// Hides or shows the request of `fp` in the main list. Local to this
    /// device: not synchronized, `unseen` untouched. No request:
    /// `UnknownContact`.
    pub fn set_request_hidden(&mut self, fp: &Fingerprint, hidden: bool) -> Result<()> {
        self.ensure_active()?;
        let n = self
            .store
            .conn()
            .execute(
                "UPDATE contact_requests SET hidden = ?2 WHERE fp = ?1",
                params![fp.0.as_slice(), hidden],
            )
            .map_err(map_err)?;
        if n == 0 {
            return Err(CoreError::UnknownContact);
        }
        Ok(())
    }

    /// The user opened the list of requests: none is `unseen` any more
    /// (the indicator goes out until a new packet arrives).
    pub fn mark_requests_seen(&mut self) -> Result<()> {
        self.ensure_active()?;
        self.store
            .conn()
            .execute(
                "UPDATE contact_requests SET unseen = 0 WHERE unseen = 1",
                [],
            )
            .map_err(map_err)?;
        Ok(())
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
            session_id: [ik; 16],
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
        assert_eq!(attach_unknown_to_fp(&s, &[9; 32], fp(7), read).unwrap(), 2);
        assert_eq!(count_pending_for_fp(&s, fp(7)).unwrap(), 2);
        // The packet already attached to another request is left alone.
        assert_eq!(count_pending_for_fp(&s, fp(5)).unwrap(), 1);
        assert_eq!(count_unknown(&s).unwrap(), 1);
        assert_eq!(attach_unknown_to_fp(&s, &[9; 32], fp(7), read).unwrap(), 0);
    }

    /// Every packet authenticates, with a message id from its packet id.
    fn read(p: &PendingInitial) -> Result<Option<MessageId>> {
        Ok(Some(MessageId(p.packet_id.0)))
    }

    #[test]
    fn unauthenticated_packets_are_dropped_not_attached() {
        let (_d, s) = store();
        insert_pending_initial(&s, &pending(1, 9, Some(7), true)).unwrap();
        for id in 2..5 {
            insert_pending_initial(&s, &pending(id, 9, None, false)).unwrap();
        }
        // Packet 3 does not authenticate: dropped, and takes no slot.
        let n = attach_unknown_to_fp(&s, &[9; 32], fp(7), |p| {
            Ok((p.packet_id.0[0] != 3).then_some(MessageId([0xaa; 16])))
        })
        .unwrap();
        assert_eq!(n, 2);
        let held = list_pending_by_fp(&s, fp(7)).unwrap();
        let ids: Vec<u8> = held.iter().map(|p| p.packet_id.0[0]).collect();
        assert_eq!(ids, vec![1, 2, 4]);
        // The message id of the authenticated content is recorded.
        assert_eq!(held[1].message_id, Some(MessageId([0xaa; 16])));
        assert_eq!(count_unknown(&s).unwrap(), 0);
    }

    #[test]
    fn attaching_beyond_the_cap_drops_the_rest() {
        let (_d, s) = store();
        insert_pending_initial(&s, &pending(1, 9, Some(7), true)).unwrap();
        for id in 2..8 {
            insert_pending_initial(&s, &pending(id, 9, None, false)).unwrap();
        }
        assert_eq!(attach_unknown_to_fp(&s, &[9; 32], fp(7), read).unwrap(), 3);
        let held: Vec<u8> = list_pending_by_fp(&s, fp(7))
            .unwrap()
            .iter()
            .map(|p| p.packet_id.0[0])
            .collect();
        // The oldest join the request; the others leave the queue.
        assert_eq!(held, vec![1, 2, 3, 4]);
        assert_eq!(count_unknown(&s).unwrap(), 0);
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
        // The first acceptance date stays.
        assert!(set_invite_accepted(&s, fp(1), 25).unwrap());
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
