//! Emoji reactions (spec §5.3, §5.4).
//!
//! Each `(target message, reactor)` holds a last-writer-wins register of
//! the reactor's whole set of emoji, keyed `(clock, tie)`: `clock` is the
//! envelope's `sent_at`, `tie` its `message_id` (the greatest wins). A
//! reaction packet carries the whole set, so a lost or late packet is
//! corrected by the next one, whatever the arrival order.
//!
//! Sending (`set_reactions`): one `Reaction` per device of the contact and
//! one `SyncReaction` per other device of mine, all with the same `sent_at`
//! and `message_id`. Each packet is tracked by a delivery keyed on that
//! `message_id` (the reaction packet's own identifier), never on the target:
//! no message row, so nothing of it reaches the message status, its expiry
//! or its Retry.
//!
//! Each packet is also tracked in `reaction_sends` (packet, target,
//! conversation, audience). The tracking of the current send toward the
//! contact (`current_contact_tie`) stays after its packets leave the send
//! queue, so a late ack still marks it received; a new send that seals for
//! the contact (`set_reactions`) replaces it, while the older packets still
//! queued leave anyway, untracked (their rows stay, flagged `superseded`,
//! only so that the Pending screen counts them as reactions, until the full
//! sync after they left the queue). `expire_due` flags the packets that
//! expired undeposited: a flagged contact send stays `NotDelivered` until
//! the user resends it by hand, and `resend_reactions` (full sync) reseals
//! my current set, with a fresh clock, only for my other devices.

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::delivery;
use super::send::{SealTime, Target, quote_ref, seal_for};
use super::{Core, MAX_AGE_SECS, sync};
use crate::content::{ExtContent, MessageRef};
use crate::emoji;
use crate::identity::{DeviceKeys, Fingerprint};
use crate::packet::Packet;
use crate::store::{
    MessageId, Queries, ReactionRow, arr, drop_reaction_packets, forget_reaction_tracking, map_err,
    to_i64,
};
use crate::transparency::SyncKind;
use crate::{CoreError, Result};

/// What `Core::resend_reactions` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReactionResend {
    /// Audiences resent.
    pub resent: u32,
    /// Groups whose resend failed (rolled back, retried at the next full
    /// sync): the caller logs them.
    pub failed: u32,
}

/// `reactions.reactor` of my own rows (this device and my other devices).
pub const ME_REACTOR: [u8; 32] = [0u8; 32];

/// One emoji shown under a message, with the number of people who chose it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionChip {
    pub emoji: String,
    pub count: u32,
    /// I am among them (from any of my devices).
    pub mine: bool,
}

impl Core {
    /// Replaces my set of emoji on the message of row `row_id` with
    /// `emojis` (an empty set removes my reaction).
    ///
    /// The emoji are taken in their canonical spelling (`emoji::canonical`).
    /// Checks, before any write: the set (`TooManyEmoji`, `InvalidEmoji`),
    /// the row (`MessageNotFound`; a received row without a wire identifier
    /// cannot be referred to either), the contact (`ContactBlocked`,
    /// `UnknownContact` for a removed contact whose history remains).
    ///
    /// The same set as stored (in any order; no row reads as empty) sends
    /// nothing. Otherwise, in one transaction: my row is written with
    /// `clock = max(now, last clock + 1)` (two changes in the same second
    /// stay ordered) and a fresh tie; the emoji I keep stay in their order
    /// and the new ones go to the end. Then a `Reaction` is sealed for each
    /// device of the contact and a `SyncReaction` for each other device of
    /// mine, dated `clock`, under the tie as message identifier, one
    /// delivery per packet without a message row. A contact device without
    /// a session is skipped: the local write stays, without error.
    ///
    /// The tracking of my earlier sends on this target to this contact is
    /// forgotten first (their queued packets still leave): only this send
    /// has a state, and a send that seals for no device of the contact
    /// leaves none.
    pub fn set_reactions(
        &mut self,
        row_id: i64,
        emojis: &[String],
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        // One spelling per emoji ("❤" is "❤\u{FE0F}"), before any comparison.
        let emojis = &emoji::canonical_set(emojis)?;
        let row = self
            .store
            .message_by_row(row_id)?
            .ok_or(CoreError::MessageNotFound)?;
        let to = row.contact_fp;
        if self.store.block_state(to)?.blocked {
            return Err(CoreError::ContactBlocked);
        }
        self.store
            .get_contact(to)?
            .ok_or(CoreError::UnknownContact)?;
        let target = quote_ref(&self.store, &to, row_id)?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let mine = tx.reaction(row.message_id, ME_REACTOR)?;
            let old = mine.as_ref().map(|m| m.emojis.clone()).unwrap_or_default();
            if same_set(&old, emojis) {
                return Ok(Vec::new());
            }
            let stored = merge_order(&old, emojis);
            let clock = mine
                .as_ref()
                .map_or(now, |m| now.max(m.clock.saturating_add(1)));
            let mut tie = [0u8; 16];
            rng.fill_bytes(&mut tie);
            tx.put_reaction_if_newer(&ReactionRow {
                message_id: row.message_id,
                reactor: ME_REACTOR,
                contact_fp: to,
                emojis: stored.clone(),
                clock,
                tie,
                first_seen: mine.as_ref().map_or(clock, |m| m.first_seen),
                first_tie: mine.as_ref().map_or(tie, |m| m.first_tie),
            })?;
            let time = SealTime {
                now,
                sent_at: clock,
            };
            let seal = Seal {
                to,
                message: row.message_id,
                target,
                emojis: &stored,
                tie,
                time,
            };
            forget_reaction_tracking(
                tx,
                "message_id = ?1 AND contact_fp = ?2",
                params![row.message_id.0.as_slice(), to.0.as_slice()],
            )?;
            let (mut out, own) = seal_set(tx, device, &seal, (true, true), rng)?;
            out.extend(own);
            Ok(out)
        })
    }

    /// Resends to my other devices, after their expiry, the reaction copies
    /// that left no node.
    ///
    /// Runs `expire_due(now)` first, which flags each reaction packet that
    /// expired undeposited (or lost after its deposit: `confirm_expired`).
    /// Then, for each `(target, contact)` with a flagged copy for my other
    /// devices, reseals my *current* set on that target to them: the copies
    /// of older sets that expired are not replayed. My row is re-stamped
    /// first (`clock = max(now, clock + 1)`, fresh tie), because the old
    /// clock would be stale at the receiver (`MAX_AGE_SECS`). This creates
    /// copies for my devices only, so the current send toward the contact
    /// (`current_contact_tie`) stays.
    ///
    /// A flagged send toward the contact is never resent here: it stays,
    /// `NotDelivered`, until the user resends it by hand.
    ///
    /// Only a set that exists is resent, an empty one (a removal) included:
    /// with no row of mine on the target (message deleted here, contact
    /// erased) there is nothing to say, and the copies are dropped. A
    /// contact that is unknown or blocked is skipped and dropped too. The
    /// flagged rows of my copies are removed, with their deliveries.
    /// Returns the number of audiences resent and of groups that failed.
    /// The quick sync never calls it.
    ///
    /// It also purges the orphan reactions (`purge_orphans`).
    pub fn resend_reactions(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReactionResend> {
        self.ensure_active()?;
        self.expire_due(now)?;
        if self.store.is_read_only() {
            return Ok(ReactionResend::default());
        }
        let Core { store, device, .. } = self;
        purge_orphans(&*store, now)?;
        drop_left_superseded(&*store)?;
        let groups = flagged_audiences(&*store)?;
        let mut out = ReactionResend::default();
        for (to, message) in groups {
            // A group that fails (its transaction rolled back, its rows
            // still flagged) is retried at the next full sync and does not
            // hold the others back.
            let Ok(sent) = store.transaction(|tx| {
                let usable = tx.get_contact(to)?.is_some() && !tx.block_state(to)?.blocked;
                let mine = tx.reaction(message, ME_REACTOR)?;
                let target =
                    row_id_of(tx, to, message)?.and_then(|row_id| quote_ref(tx, &to, row_id).ok());
                let sent = match (usable, mine, target) {
                    (true, Some(mine), Some(target)) => {
                        let clock = now.max(mine.clock.saturating_add(1));
                        let mut tie = [0u8; 16];
                        rng.fill_bytes(&mut tie);
                        let seal = Seal {
                            to,
                            message,
                            target,
                            emojis: &mine.emojis,
                            tie,
                            time: SealTime {
                                now,
                                sent_at: clock,
                            },
                        };
                        let (_, own) = seal_set(tx, device, &seal, (false, true), rng)?;
                        if !own.is_empty() {
                            tx.put_reaction_if_newer(&ReactionRow { clock, tie, ..mine })?;
                        }
                        u32::from(!own.is_empty())
                    }
                    _ => 0,
                };
                drop_reaction_packets(
                    tx,
                    "expired = 1 AND own = 1 AND message_id = ?1 AND contact_fp = ?2",
                    params![message.0.as_slice(), to.0.as_slice()],
                )?;
                Ok(sent)
            }) else {
                out.failed += 1;
                continue;
            };
            out.resent += sent;
        }
        Ok(out)
    }

    /// The chips under `message` of the conversation with `contact`: rows in
    /// first-seen order, `(first_seen, first_tie)` (a replaced row keeps its
    /// place, the same on both sides), each row's emoji in
    /// its stored order, each emoji at its first appearance.
    pub fn reaction_chips(
        &self,
        contact: &Fingerprint,
        message: MessageId,
    ) -> Result<Vec<ReactionChip>> {
        let mut chips: Vec<ReactionChip> = Vec::new();
        for row in self.store.reactions_on(*contact, message)? {
            let mine = row.reactor == ME_REACTOR;
            for e in row.emojis {
                match chips.iter_mut().find(|c| c.emoji == e) {
                    Some(chip) => {
                        chip.count = chip.count.saturating_add(1);
                        chip.mine |= mine;
                    }
                    None => chips.push(ReactionChip {
                        emoji: e,
                        count: 1,
                        mine,
                    }),
                }
            }
        }
        Ok(chips)
    }
}

/// Erases the orphan reactions: a row whose target is not stored here and
/// was first seen more than `MAX_AGE_SECS` ago. Past that age the target
/// would be refused as too old if it came at all, so the row would never
/// show. Keyed on `first_seen`: later updates of an orphan set do not keep
/// it alive.
fn purge_orphans(q: &impl Queries, now: u64) -> Result<()> {
    q.conn()
        .execute(
            "DELETE FROM reactions WHERE first_seen < ?1 AND NOT EXISTS \
             (SELECT 1 FROM messages m WHERE m.message_id = reactions.message_id)",
            params![to_i64(now.saturating_sub(MAX_AGE_SECS))],
        )
        .map_err(map_err)?;
    Ok(())
}

/// Erases the superseded rows (`forget_reaction_tracking`) whose packet
/// left the send queue: deposited, acknowledged or expired, it is no
/// longer pending.
fn drop_left_superseded(q: &impl Queries) -> Result<()> {
    q.conn()
        .execute(
            "DELETE FROM reaction_sends WHERE superseded = 1 \
             AND packet_id NOT IN (SELECT packet_id FROM outbox)",
            [],
        )
        .map_err(map_err)?;
    Ok(())
}

/// What `seal_set` seals: my set on a target, dated and identified.
struct Seal<'a> {
    /// The conversation.
    to: Fingerprint,
    /// The target (`reactions.message_id`).
    message: MessageId,
    target: MessageRef,
    emojis: &'a [String],
    /// The packets' message identifier: the reaction's own.
    tie: [u8; 16],
    time: SealTime,
}

/// Seals `s` for the contact's devices (`audience.0`) and for my other
/// devices (`audience.1`): one delivery per packet, keyed on the tie, and
/// one `reaction_sends` row per packet. Returns the contact's packets, then
/// my devices'.
fn seal_set(
    q: &impl Queries,
    device: &DeviceKeys,
    s: &Seal<'_>,
    audience: (bool, bool),
    rng: &mut impl CryptoRng,
) -> Result<(Vec<Packet>, Vec<Packet>)> {
    let id = MessageId(s.tie);
    let (mut contact, mut own) = (Vec::new(), Vec::new());
    if audience.0 {
        let body = ExtContent::Reaction {
            target: s.target,
            emojis: s.emojis.to_vec(),
        }
        .to_body();
        let sealed = seal_for(q, device, &Target::Contact(s.to), &body, id, s.time, rng)?;
        for (packet, peer) in &sealed {
            let size = delivery::packet_size(packet);
            q.add_delivery(id, packet.id, *peer, false, s.time.now, size)?;
            track(q, packet, s, false)?;
        }
        contact = sealed.into_iter().map(|(p, _)| p).collect();
    }
    if audience.1 {
        let body = ExtContent::SyncReaction {
            to: s.to,
            target: s.target,
            emojis: s.emojis.to_vec(),
        }
        .to_body();
        own = sync::seal_to_own(q, device, &body, SyncKind::Reaction, id, s.time, rng)?;
        for packet in &own {
            track(q, packet, s, true)?;
        }
    }
    Ok((contact, own))
}

/// Records that `packet` carries a reaction on `s.message`.
fn track(q: &impl Queries, packet: &Packet, s: &Seal<'_>, own: bool) -> Result<()> {
    q.conn()
        .execute(
            "INSERT OR REPLACE INTO reaction_sends (packet_id, message_id, contact_fp, own) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                packet.id.0.as_slice(),
                s.message.0.as_slice(),
                s.to.0.as_slice(),
                own
            ],
        )
        .map_err(map_err)?;
    Ok(())
}

/// `(contact, target)`: see `flagged_audiences`.
type Flagged = (Fingerprint, MessageId);

/// The `(contact, target)` with a copy for my other devices that expired
/// undeposited, oldest first. A flagged send toward the contact is left to
/// the manual resend.
fn flagged_audiences(q: &impl Queries) -> Result<Vec<Flagged>> {
    let mut stmt = q
        .conn()
        .prepare(
            "SELECT contact_fp, message_id FROM reaction_sends \
             WHERE expired = 1 AND own = 1 AND superseded = 0 \
             GROUP BY contact_fp, message_id ORDER BY min(rowid)",
        )
        .map_err(map_err)?;
    let raw = stmt
        .query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;
    raw.into_iter()
        .map(|(c, m)| Ok((Fingerprint(arr(c)?), MessageId(arr(m)?))))
        .collect()
}

/// The tie of my current send toward `contact` on `target`: the
/// `deliveries.message_id` of its `own = 0` packets. `None` without local
/// tracking (synced from another of my devices, imported, or sent while no
/// device of the contact had a session). An own-only resend never changes
/// it: it creates `own = 1` deliveries only.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the reaction delivery state")
)]
pub(super) fn current_contact_tie(
    q: &impl Queries,
    contact: Fingerprint,
    target: MessageId,
) -> Result<Option<MessageId>> {
    let tie: Option<Vec<u8>> = q
        .conn()
        .query_row(
            "SELECT d.message_id FROM reaction_sends rs \
             JOIN deliveries d ON d.packet_id = rs.packet_id \
             WHERE rs.message_id = ?1 AND rs.contact_fp = ?2 AND rs.own = 0 \
             AND rs.superseded = 0 \
             ORDER BY rs.rowid DESC LIMIT 1",
            params![target.0.as_slice(), contact.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)?;
    tie.map(|t| Ok(MessageId(arr(t)?))).transpose()
}

/// The row of the message `message` in the conversation with `contact`.
pub(super) fn row_id_of(
    q: &impl Queries,
    contact: Fingerprint,
    message: MessageId,
) -> Result<Option<i64>> {
    q.conn()
        .query_row(
            "SELECT id FROM messages WHERE message_id = ?1 AND contact_fp = ?2 LIMIT 1",
            params![message.0.as_slice(), contact.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)
}

/// Same emoji, whatever the order (a set has no duplicate).
fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|e| b.contains(e))
}

/// The emoji of `new` kept from `old` in `old`'s order, then the others in
/// `new`'s order.
fn merge_order(old: &[String], new: &[String]) -> Vec<String> {
    old.iter()
        .filter(|e| new.contains(e))
        .chain(new.iter().filter(|e| !old.contains(e)))
        .cloned()
        .collect()
}

/// Applies a received set of `reactor` on `target`, in the conversation with
/// `contact`, dated `(clock, tie)`. `None`: ignored, nothing written (a
/// target deleted here, or one of another conversation). `Some(added)`: the
/// emoji the set adds to the one it replaced, empty if it is not newer.
pub(super) fn apply(
    q: &impl Queries,
    contact: Fingerprint,
    reactor: [u8; 32],
    target: MessageId,
    emojis: Vec<String>,
    clock: u64,
    tie: [u8; 16],
) -> Result<Option<Vec<String>>> {
    if deleted_here(q, target)? || owner(q, target)?.is_some_and(|c| c != contact) {
        return Ok(None);
    }
    let old = q.reaction(target, reactor)?;
    let row = ReactionRow {
        message_id: target,
        reactor,
        contact_fp: contact,
        emojis,
        clock,
        tie,
        first_seen: old.as_ref().map_or(clock, |o| o.first_seen),
        first_tie: old.as_ref().map_or(tie, |o| o.first_tie),
    };
    if !q.put_reaction_if_newer(&row)? {
        return Ok(Some(Vec::new()));
    }
    let before = old.map(|o| o.emojis).unwrap_or_default();
    Ok(Some(
        row.emojis
            .into_iter()
            .filter(|e| !before.contains(e))
            .collect(),
    ))
}

/// The message `id` was deleted from this device (tombstone).
fn deleted_here(q: &impl Queries, id: MessageId) -> Result<bool> {
    q.conn()
        .query_row(
            "SELECT count(*) > 0 FROM deleted_messages WHERE message_id = ?1",
            params![id.0.as_slice()],
            |r| r.get(0),
        )
        .map_err(map_err)
}

/// The conversation of the stored message `id`, whatever it is.
fn owner(q: &impl Queries, id: MessageId) -> Result<Option<Fingerprint>> {
    let fp: Option<Vec<u8>> = q
        .conn()
        .query_row(
            "SELECT contact_fp FROM messages WHERE message_id = ?1",
            params![id.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)?;
    fp.map(|b| Ok(Fingerprint(arr(b)?))).transpose()
}
