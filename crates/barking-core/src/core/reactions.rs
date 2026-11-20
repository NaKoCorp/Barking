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
//! conversation, audience). `expire_due` flags the ones that expired
//! undeposited, and `resend_reactions` (full sync) reseals my current set
//! for each such audience with a fresh clock.

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::delivery;
use super::send::{SealTime, Target, quote_ref, seal_for};
use super::{Core, sync};
use crate::content::{ExtContent, MessageRef};
use crate::emoji;
use crate::identity::{DeviceKeys, Fingerprint};
use crate::packet::Packet;
use crate::store::{MessageId, Queries, ReactionRow, arr, map_err};
use crate::transparency::SyncKind;
use crate::{CoreError, Result};

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
    pub fn set_reactions(
        &mut self,
        row_id: i64,
        emojis: &[String],
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        emoji::check_set(emojis)?;
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
            let (mut out, own) = seal_set(tx, device, &seal, (true, true), rng)?;
            out.extend(own);
            Ok(out)
        })
    }

    /// Resends, after their expiry, the reaction packets that left no node.
    ///
    /// Runs `expire_due(now)` first, which flags each reaction packet that
    /// expired undeposited. Then, for each `(target, contact)` with a
    /// flagged audience (the contact's devices, my other devices), reseals
    /// my *current* set on that target to the flagged audiences: the packets
    /// of older sets that expired are not replayed. My row is re-stamped
    /// first (`clock = max(now, clock + 1)`, fresh tie), because the old
    /// clock would be stale at the receiver (`MAX_AGE_SECS`); the audiences
    /// of a target share the new clock and tie.
    ///
    /// Only a set that exists is resent, an empty one (a removal) included:
    /// with no row of mine on the target (message deleted here, contact
    /// erased) there is nothing to say, and the audience is dropped. A
    /// contact that is unknown or blocked is skipped and dropped too. The
    /// flagged rows are removed. Returns the number of audiences resent.
    /// The quick sync never calls it.
    pub fn resend_reactions(&mut self, now: u64, rng: &mut impl CryptoRng) -> Result<u32> {
        self.ensure_active()?;
        self.expire_due(now)?;
        if self.store.is_read_only() {
            return Ok(0);
        }
        let Core { store, device, .. } = self;
        let groups = flagged_audiences(&*store)?;
        let mut resent = 0u32;
        for (to, message, audience) in groups {
            resent += store.transaction(|tx| {
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
                        let (contact, own) = seal_set(tx, device, &seal, audience, rng)?;
                        if !contact.is_empty() || !own.is_empty() {
                            tx.put_reaction_if_newer(&ReactionRow { clock, tie, ..mine })?;
                        }
                        u32::from(!contact.is_empty()) + u32::from(!own.is_empty())
                    }
                    _ => 0,
                };
                tx.conn()
                    .execute(
                        "DELETE FROM reaction_sends \
                         WHERE expired = 1 AND message_id = ?1 AND contact_fp = ?2",
                        params![message.0.as_slice(), to.0.as_slice()],
                    )
                    .map_err(map_err)?;
                Ok(sent)
            })?;
        }
        Ok(resent)
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

/// `(contact, target, (contact devices, my devices))`: see `flagged_audiences`.
type Flagged = (Fingerprint, MessageId, (bool, bool));

/// The audiences with a packet
/// that expired undeposited, oldest first.
fn flagged_audiences(q: &impl Queries) -> Result<Vec<Flagged>> {
    let mut stmt = q
        .conn()
        .prepare(
            "SELECT contact_fp, message_id, max(own = 0), max(own = 1) \
             FROM reaction_sends WHERE expired = 1 \
             GROUP BY contact_fp, message_id ORDER BY min(rowid)",
        )
        .map_err(map_err)?;
    let raw = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;
    raw.into_iter()
        .map(|(c, m, contact, own)| Ok((Fingerprint(arr(c)?), MessageId(arr(m)?), (contact, own))))
        .collect()
}

/// The row of the message `message` in the conversation with `contact`.
fn row_id_of(q: &impl Queries, contact: Fingerprint, message: MessageId) -> Result<Option<i64>> {
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
