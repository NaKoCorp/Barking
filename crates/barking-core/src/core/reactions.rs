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

use rand_core::CryptoRng;
use rusqlite::{OptionalExtension, params};

use super::delivery;
use super::send::{SealTime, Target, quote_ref, seal_for};
use super::{Core, sync};
use crate::content::ExtContent;
use crate::emoji;
use crate::identity::Fingerprint;
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
            let id = MessageId(tie);
            let time = SealTime {
                now,
                sent_at: clock,
            };
            let body = ExtContent::Reaction {
                target,
                emojis: stored.clone(),
            }
            .to_body();
            let sealed = seal_for(tx, device, &Target::Contact(to), &body, id, time, rng)?;
            for (packet, peer) in &sealed {
                let size = delivery::packet_size(packet);
                tx.add_delivery(id, packet.id, *peer, false, now, size)?;
            }
            let copy = ExtContent::SyncReaction {
                to,
                target,
                emojis: stored,
            }
            .to_body();
            let own = sync::seal_to_own(tx, device, &copy, SyncKind::Reaction, id, time, rng)?;
            let mut out: Vec<Packet> = sealed.into_iter().map(|(p, _)| p).collect();
            out.extend(own);
            Ok(out)
        })
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
