//! Ephemeral messages (spec §5.3): seen on a device, `SyncSeen` to my
//! other devices, expiry and erasure.
//!
//! A message is ephemeral when `messages.ttl_secs` is set. Its `expire_at`
//! starts at the "never shown" ceiling (`UNSEEN_CEILING_SECS` after its
//! insertion) or, sent from this device, at `now + ttl`. Once shown,
//! `seen_at` is set and `expire_at = min(expire_at, seen_at + ttl)`; the
//! earliest "seen" of all my devices wins (`SyncSeen`), so every device
//! erases it at the same time.
//!
//! Expiry (`expire_ephemeral`) erases the row and its reactions and leaves
//! a tombstone. It never touches packets, deliveries or the send queue: a
//! send still on its way goes on and settles without its row, as for a
//! deleted message whose packets left. It never sends a `SyncDelete`: each
//! device expires on its own. Every read hides a row whose `expire_at` is
//! due (`expire_at <= now`) before the sweep runs.

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::{Core, sync};
use crate::Result;
use crate::content::{ExtContent, MAX_SYNC_SEEN, SeenEntry};
use crate::identity::{DeviceKeys, Fingerprint};
use crate::packet::Packet;
use crate::store::{MessageId, Queries, arr, map_err, to_i64, to_u64};
use crate::transparency::SyncKind;

/// A `pending_seen` row (a "seen" for a message not arrived yet) is
/// dropped this long after it arrived: past it, the message can no longer
/// come (packet lifetime and the receive window, with a margin).
pub const PENDING_SEEN_RETENTION_SECS: u64 = 8 * 86_400;

/// A row with this `expire_at` is still shown at `now`: not ephemeral, or
/// not due yet.
pub(crate) fn is_live(expire_at: Option<u64>, now: u64) -> bool {
    expire_at.is_none_or(|e| e > now)
}

impl Core {
    /// Marks the ephemeral messages of rows `row_ids` as seen at `now`
    /// (their bubble is on screen): `seen_at = now` and
    /// `expire_at = min(expire_at, now + ttl)`, in one transaction. A row
    /// that is unknown, not ephemeral, already seen or already due is
    /// ignored. The entries go to my other devices in the same transaction
    /// (`SyncSeen`, at most `MAX_SYNC_SEEN` per packet): those packets are
    /// returned. None on a device awaiting its link or removed from my
    /// account: the change stays local.
    pub fn mark_seen(
        &mut self,
        row_ids: &[i64],
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        let sync = self.syncs_deletions()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let mut seen = Vec::new();
            for &row in row_ids {
                if let Some(entry) = mark_row(tx, row, now)? {
                    seen.push(entry);
                }
            }
            if sync && !seen.is_empty() {
                seal_seen(tx, device, &seen, now, rng)
            } else {
                Ok(Vec::new())
            }
        })
    }

    /// Erases every ephemeral message due at `now` (`expire_at <= now`):
    /// its row and its reactions, leaving a tombstone (a copy arriving
    /// later is refused). Packets, deliveries and the send queue are left
    /// alone. Also drops the `pending_seen` rows older than
    /// `PENDING_SEEN_RETENTION_SECS`. Returns the erased row ids. Sends
    /// nothing. Does nothing on a core opened for reading (the reads hide
    /// due rows anyway).
    pub fn expire_ephemeral(&mut self, now: u64) -> Result<Vec<i64>> {
        if self.store.is_read_only() {
            return Ok(Vec::new());
        }
        let erased = self.store.transaction(|tx| sweep(tx, now))?;
        // A failure notice for a message that no longer exists is moot.
        self.failed_notices.retain(|(_, row)| !erased.contains(row));
        Ok(erased)
    }

    /// The earliest `expire_at` of the stored ephemeral messages (possibly
    /// already due): when the app's timer should call `expire_ephemeral`.
    /// `None` without any.
    pub fn next_expiry(&self) -> Result<Option<u64>> {
        let next: Option<i64> = self
            .store
            .conn()
            .query_row(
                "SELECT min(expire_at) FROM messages WHERE expire_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(next.map(to_u64))
    }
}

/// Marks the row `row` seen at `now` if it is a live ephemeral not seen
/// yet; its `SyncSeen` entry then.
fn mark_row(q: &impl Queries, row: i64, now: u64) -> Result<Option<SeenEntry>> {
    /// `message_id, contact_fp, ttl_secs, seen_at, expire_at`.
    type Cols = (Vec<u8>, Vec<u8>, Option<u32>, Option<i64>, Option<i64>);
    let found: Option<Cols> = q
        .conn()
        .query_row(
            "SELECT message_id, contact_fp, ttl_secs, seen_at, expire_at \
             FROM messages WHERE id = ?1",
            params![row],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(map_err)?;
    let Some((id, contact, Some(ttl), None, expire_at)) = found else {
        return Ok(None);
    };
    if !is_live(expire_at.map(to_u64), now) {
        return Ok(None);
    }
    q.conn()
        .execute(
            "UPDATE messages SET seen_at = ?2, \
             expire_at = min(coalesce(expire_at, ?3), ?3) WHERE id = ?1",
            params![row, to_i64(now), to_i64(now.saturating_add(u64::from(ttl)))],
        )
        .map_err(map_err)?;
    Ok(Some(SeenEntry {
        id: MessageId(arr(id)?),
        contact: Fingerprint(arr(contact)?),
        at: now,
    }))
}

/// Seals `seen` for my other devices (`SyncSeen`, at most `MAX_SYNC_SEEN`
/// entries per packet). Nothing without another device.
pub(super) fn seal_seen(
    q: &impl Queries,
    device: &DeviceKeys,
    seen: &[SeenEntry],
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Packet>> {
    sync::seal_sync_chunks(
        q,
        device,
        seen,
        MAX_SYNC_SEEN,
        |seen| ExtContent::SyncSeen { seen },
        SyncKind::Seen,
        now,
        rng,
    )
}

/// Applies a `SyncSeen` from another of my devices, received at `now`.
/// Each date is first clamped to `now` (`T' = min(T, now)`: a device whose
/// clock runs ahead cannot delay the erasure; one in the past is honoured,
/// an entry already over is due at once). Then, per entry:
/// - a tombstoned identifier (deleted or expired here) is ignored;
/// - a stored ephemeral of that conversation gets
///   `seen_at = min(seen_at, T')` and `expire_at = min(expire_at, T' + ttl)`;
///   a plain message, or one of another conversation, is left alone; a
///   row this lowers is noted (`Queries::note_change`) for the app;
/// - an unknown one is kept in `pending_seen` (the smallest date wins),
///   applied when the message is inserted (`insert_message_row`), unless
///   its contact is blocked or was removed here.
pub(super) fn apply_seen(q: &impl Queries, seen: &[SeenEntry], now: u64) -> Result<()> {
    for e in seen {
        let at = e.at.min(now);
        let id = e.id.0.as_slice();
        let tombstoned: bool = q
            .conn()
            .query_row(
                "SELECT count(*) > 0 FROM deleted_messages WHERE message_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if tombstoned {
            continue;
        }
        let row: Option<(Vec<u8>, Option<u32>)> = q
            .conn()
            .query_row(
                "SELECT contact_fp, ttl_secs FROM messages WHERE message_id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_err)?;
        match row {
            Some((contact, Some(ttl))) if contact == e.contact.0 => {
                // Only a row this lowers: its countdown changes, so the
                // conversation showing it reloads (`take_delivery_changes`).
                let changed: Option<i64> = q
                    .conn()
                    .query_row(
                        "UPDATE messages SET seen_at = min(coalesce(seen_at, ?2), ?2), \
                         expire_at = min(coalesce(expire_at, ?3), ?3) WHERE message_id = ?1 \
                         AND (seen_at IS NULL OR seen_at > ?2 \
                              OR expire_at IS NULL OR expire_at > ?3) RETURNING id",
                        params![id, to_i64(at), to_i64(at.saturating_add(u64::from(ttl)))],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(map_err)?;
                if let Some(row) = changed {
                    q.note_change(e.contact, row);
                }
            }
            Some(_) => {}
            None => {
                let removed = q.get_contact(e.contact)?.is_none()
                    && q.contact_clock(e.contact)?.is_some_and(|c| c.removed);
                if removed || q.block_state(e.contact)?.blocked {
                    continue;
                }
                q.conn()
                    .execute(
                        "INSERT INTO pending_seen(message_id, contact_fp, seen_at, received_at) \
                         VALUES (?1, ?2, ?3, ?4) ON CONFLICT(message_id) DO UPDATE \
                         SET seen_at = min(seen_at, excluded.seen_at)",
                        params![id, e.contact.0.as_slice(), to_i64(at), to_i64(now)],
                    )
                    .map_err(map_err)?;
            }
        }
    }
    Ok(())
}

/// The expiry of `expire_ephemeral`, inside the caller's transaction:
/// erases every row due at `now` (`erase_row`), then purges the old
/// `pending_seen` rows. Reads identifiers only, never a text. Returns the
/// erased row ids.
pub(crate) fn sweep(q: &impl Queries, now: u64) -> Result<Vec<i64>> {
    let due: Vec<i64> = {
        let mut stmt = q
            .conn()
            .prepare("SELECT id FROM messages WHERE expire_at <= ?1 ORDER BY id")
            .map_err(map_err)?;
        stmt.query_map(params![to_i64(now)], |r| r.get(0))
            .map_err(map_err)?
            .collect::<rusqlite::Result<_>>()
            .map_err(map_err)?
    };
    let mut erased = Vec::with_capacity(due.len());
    for row in due {
        if erase_row(q, row, now)?.is_some() {
            erased.push(row);
        }
    }
    q.conn()
        .execute(
            "DELETE FROM pending_seen WHERE received_at < ?1",
            params![to_i64(now.saturating_sub(PENDING_SEEN_RETENTION_SECS))],
        )
        .map_err(map_err)?;
    Ok(erased)
}

/// Erases the stored message `message_id` if it is already due at `now`
/// (`erase_row`): an ephemeral born due. True when it was erased.
pub(super) fn erase_if_due(q: &impl Queries, message_id: MessageId, now: u64) -> Result<bool> {
    let row: Option<(i64, Option<i64>)> = q
        .conn()
        .query_row(
            "SELECT id, expire_at FROM messages WHERE message_id = ?1",
            params![message_id.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(map_err)?;
    match row {
        Some((row_id, expire_at)) if !is_live(expire_at.map(to_u64), now) => {
            Ok(erase_row(q, row_id, now)?.is_some())
        }
        _ => Ok(false),
    }
}

/// Erases the message of row `row_id`: the row (its freed cells zeroed by
/// `secure_delete`), its reactions, and a tombstone dated `now` so that no
/// copy of it comes back. Never touches its deliveries, packets or send
/// queue, nor the reaction packets about it. Returns its identifier, or
/// `None` for an unknown row.
pub(super) fn erase_row(q: &impl Queries, row_id: i64, now: u64) -> Result<Option<MessageId>> {
    let id: Option<Vec<u8>> = q
        .conn()
        .query_row(
            "DELETE FROM messages WHERE id = ?1 RETURNING message_id",
            params![row_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)?;
    let Some(id) = id else {
        return Ok(None);
    };
    let message = MessageId(arr(id)?);
    q.add_tombstone(message, now)?;
    q.conn()
        .execute(
            "DELETE FROM reactions WHERE message_id = ?1",
            params![message.0.as_slice()],
        )
        .map_err(map_err)?;
    Ok(Some(message))
}
