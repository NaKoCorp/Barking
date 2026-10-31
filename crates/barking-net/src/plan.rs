//! Deposit bookkeeping: which responsible nodes accepted each outgoing
//! packet, when a node may be tried again, which nodes lost a message, and
//! the resulting deposit plan for a synchronization.
//!
//! The ledger holds packet hashes (`pow::content_hash`), node ids and dates
//! only, never packet bytes. Acceptance dates are rounded to the hour.

use std::collections::{BTreeMap, HashSet};

use barking_packet::{Kind, MailboxId, Packet};
use barking_proto::pow::content_hash;
use barking_proto::{ErrorReason, NodeId};
use serde::{Deserialize, Serialize};

use crate::score::ScoreEvent;
use crate::view::hour;

/// Copies of a message the client deposits itself, on distinct responsibles.
pub const CLIENT_COPIES: usize = 3;
/// A message accepted this long ago without receipt gets more copies.
pub const RESEND_AFTER_SECS: u64 = 6 * 3600;
/// Delay before trying a node again after it accepted or refused for good.
pub const REDEPOSIT_AFTER_SECS: u64 = 86_400;
/// Delay after a `NodeFull` or `MailboxFull` refusal (room may come back).
pub const FULL_RETRY_SECS: u64 = 600;
/// Delay after a receipt that arrived before its packet (`UnknownAckTarget`).
pub const DEFERRED_ACK_RETRY_SECS: u64 = 3_600;
/// A message this close to expiry is not checked for losses: a node whose
/// clock runs ahead may already have purged it.
pub const LOSS_GRACE_SECS: u64 = 3_600;

/// Deposit state of the outgoing packets, keyed by packet hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    packets: BTreeMap<[u8; 32], PacketState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PacketState {
    /// First acceptance by any node (hour).
    first_accepted: Option<u64>,
    /// Nodes holding the packet, with the acceptance date (hour).
    accepted: Vec<(NodeId, u64)>,
    /// No new deposit on this node before this date.
    retry: Vec<(NodeId, u64)>,
    /// Nodes where the message went missing: never tried again.
    lost: Vec<NodeId>,
    /// A loss not yet made up by a new acceptance.
    resend_now: bool,
}

impl PacketState {
    /// A node the packet may be deposited on now.
    fn eligible(&self, node: &NodeId, now: u64) -> bool {
        !self.accepted.iter().any(|(n, _)| n == node)
            && !self.lost.contains(node)
            && !self.retry.iter().any(|(n, t)| n == node && now < *t)
    }

    fn accept(&mut self, node: NodeId, now: u64) {
        let at = hour(now);
        self.first_accepted.get_or_insert(at);
        self.accepted.retain(|(n, _)| *n != node);
        self.accepted.push((node, at));
        self.resend_now = false;
    }

    fn set_retry(&mut self, node: NodeId, until: u64) {
        self.retry.retain(|(n, _)| *n != node);
        self.retry.push((node, until));
    }
}

/// One deposit to make, in plan order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedDeposit {
    pub bytes: Vec<u8>,
    pub node: NodeId,
    pub is_ack: bool,
    /// First deposit of a packet never accepted anywhere.
    pub first_copy: bool,
}

impl Ledger {
    /// Rebuilds a ledger from `bytes` written by `Serialize`. Dates from the
    /// future are brought back: acceptances to the present, retry delays to
    /// at most `REDEPOSIT_AFTER_SECS` ahead. Unreadable `bytes` give an
    /// error: the caller starts from an empty ledger.
    pub fn restore(bytes: &[u8], now: u64) -> Result<Ledger, postcard::Error> {
        let mut ledger: Ledger = postcard::from_bytes(bytes)?;
        let now_hour = hour(now);
        let max_retry = now.saturating_add(REDEPOSIT_AFTER_SECS);
        for s in ledger.packets.values_mut() {
            s.first_accepted = s.first_accepted.map(|t| hour(t).min(now_hour));
            for (_, t) in &mut s.accepted {
                *t = hour(*t).min(now_hour);
            }
            for (_, t) in &mut s.retry {
                *t = (*t).min(max_retry);
            }
        }
        Ok(ledger)
    }

    /// True if the packet is known to the ledger.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.packets.contains_key(hash)
    }

    /// Nodes currently holding the packet.
    pub fn holders(&self, hash: &[u8; 32]) -> Vec<NodeId> {
        self.packets
            .get(hash)
            .map(|s| s.accepted.iter().map(|(n, _)| *n).collect())
            .unwrap_or_default()
    }
}

/// Deposit plan for `outbox`. `responsibles` gives the responsible nodes of
/// a mailbox, best score first; nodes whose retry delay has not elapsed,
/// that already hold the packet or lost it are skipped. Order: receipts,
/// first copies of messages never accepted, resends (after a loss, or
/// `RESEND_AFTER_SECS` without receipt), then extra copies up to
/// `CLIENT_COPIES`. Expired and undecodable packets are left out.
pub fn plan_deposits(
    outbox: &[Vec<u8>],
    ledger: &Ledger,
    responsibles: impl Fn(&MailboxId) -> Vec<NodeId>,
    now: u64,
) -> Vec<PlannedDeposit> {
    let empty = PacketState::default();
    let mut seen = HashSet::new();
    let (mut acks, mut first, mut resends, mut extra) = (vec![], vec![], vec![], vec![]);
    for bytes in outbox {
        let Ok(p) = Packet::decode(bytes) else {
            continue;
        };
        let hash = content_hash(bytes);
        if u64::from(p.expires_at) <= now || !seen.insert(hash) {
            continue;
        }
        let state = ledger.packets.get(&hash).unwrap_or(&empty);
        let is_ack = p.kind == Kind::Ack;
        let deposit = |node, first_copy| PlannedDeposit {
            bytes: bytes.clone(),
            node,
            is_ack,
            first_copy,
        };
        let mut nodes = responsibles(&p.mailbox)
            .into_iter()
            .filter(|n| state.eligible(n, now));
        let needed = CLIENT_COPIES.saturating_sub(state.accepted.len());
        match state.first_accepted {
            None => {
                let Some(n) = nodes.next() else { continue };
                if is_ack {
                    acks.push(deposit(n, true));
                } else {
                    first.push(deposit(n, true));
                    extra.extend(
                        nodes
                            .take(needed.saturating_sub(1))
                            .map(|n| deposit(n, false)),
                    );
                }
            }
            // A receipt accepted once is done.
            Some(_) if is_ack => {}
            Some(at) if state.resend_now || now >= at.saturating_add(RESEND_AFTER_SECS) => {
                resends.extend(nodes.take(needed).map(|n| deposit(n, false)));
            }
            Some(_) => extra.extend(nodes.take(needed).map(|n| deposit(n, false))),
        }
    }
    acks.append(&mut first);
    acks.append(&mut resends);
    acks.append(&mut extra);
    acks
}

/// Records the outcome of depositing packet `hash` on `node` and returns the
/// score event for that node. Accepted or refused for good: no new deposit
/// there for 24 h; `NodeFull`/`MailboxFull`: 10 min; `UnknownAckTarget`:
/// 1 h; `RateLimited` sets no delay.
pub fn record_outcome(
    ledger: &mut Ledger,
    hash: [u8; 32],
    node: NodeId,
    result: &Result<(), ErrorReason>,
    now: u64,
) -> ScoreEvent {
    let (delay, event) = match result {
        Ok(()) => (REDEPOSIT_AFTER_SECS, ScoreEvent::Success),
        Err(ErrorReason::RateLimited) => return ScoreEvent::Neutral,
        Err(ErrorReason::NodeFull | ErrorReason::MailboxFull) => {
            (FULL_RETRY_SECS, ScoreEvent::Neutral)
        }
        Err(ErrorReason::UnknownAckTarget) => (DEFERRED_ACK_RETRY_SECS, ScoreEvent::Neutral),
        Err(_) => (REDEPOSIT_AFTER_SECS, ScoreEvent::Neutral),
    };
    let state = ledger.packets.entry(hash).or_default();
    if result.is_ok() {
        state.accept(node, now);
    }
    state.set_retry(node, now.saturating_add(delay));
    event
}

/// Loss check after fetching from `node`. A message of `outbox` is lost
/// there when `node` had accepted it, its mailbox is among
/// `fetched_mailboxes` (mailboxes fetched in full), it is missing from
/// `fetched_items` and it is not within `LOSS_GRACE_SECS` of expiry. A
/// receipt for it among `fetched_items` proves delivery. The node is recorded as having
/// lost it (and no longer holds it), so a second call for the same fetch
/// returns nothing. Returns the hashes of the lost messages.
pub fn detect_losses(
    ledger: &mut Ledger,
    node: &NodeId,
    fetched_mailboxes: &[MailboxId],
    fetched_items: &[Vec<u8>],
    outbox: &[Vec<u8>],
    now: u64,
) -> Vec<[u8; 32]> {
    let present: HashSet<[u8; 32]> = fetched_items.iter().map(|b| content_hash(b)).collect();
    // A receipt in the mailbox replaced its message on the node: the
    // message was delivered, not lost.
    let acked: HashSet<[u8; 16]> = fetched_items
        .iter()
        .filter_map(|b| Packet::decode(b).ok())
        .filter(|p| p.kind == Kind::Ack)
        .filter_map(|p| {
            p.payload
                .get(..16)
                .and_then(|t| <[u8; 16]>::try_from(t).ok())
        })
        .collect();
    let mut lost = Vec::new();
    for bytes in outbox {
        let Ok(p) = Packet::decode(bytes) else {
            continue;
        };
        if p.kind != Kind::Message
            || u64::from(p.expires_at) <= now.saturating_add(LOSS_GRACE_SECS)
            || !fetched_mailboxes.contains(&p.mailbox)
            || acked.contains(&p.id.0)
        {
            continue;
        }
        let hash = content_hash(bytes);
        if present.contains(&hash) {
            continue;
        }
        let Some(state) = ledger.packets.get_mut(&hash) else {
            continue;
        };
        let held = state.accepted.len();
        state.accepted.retain(|(n, _)| n != node);
        if state.accepted.len() == held {
            continue;
        }
        if !state.lost.contains(node) {
            state.lost.push(*node);
        }
        state.resend_now = true;
        lost.push(hash);
    }
    lost
}

/// Hashes of the packets `node` had accepted that are among
/// `fetched_items` (the `Found` score event).
pub fn found_messages(ledger: &Ledger, node: &NodeId, fetched_items: &[Vec<u8>]) -> Vec<[u8; 32]> {
    let mut found = Vec::new();
    for bytes in fetched_items {
        let hash = content_hash(bytes);
        if !found.contains(&hash)
            && ledger
                .packets
                .get(&hash)
                .is_some_and(|s| s.accepted.iter().any(|(n, _)| n == node))
        {
            found.push(hash);
        }
    }
    found
}

/// Forgets the packets that left `outbox` and the retry delays elapsed.
pub fn prune(ledger: &mut Ledger, outbox: &[Vec<u8>], now: u64) {
    let live: HashSet<[u8; 32]> = outbox.iter().map(|b| content_hash(b)).collect();
    ledger.packets.retain(|hash, s| {
        s.retry.retain(|(_, t)| now < *t);
        live.contains(hash)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use barking_packet::{PacketId, Tier};

    const NOW: u64 = 1_800_000_000; // On the hour.
    const MB: MailboxId = MailboxId([7; 16]);

    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn packet(n: u8, kind: Kind, expires_at: u64) -> Vec<u8> {
        Packet {
            kind,
            hops: 8,
            tier: Tier::S,
            id: PacketId([n; 16]),
            expires_at: expires_at as u32,
            mailbox: MB,
            payload: vec![n],
        }
        .encode()
    }

    fn msg(n: u8) -> Vec<u8> {
        packet(n, Kind::Message, NOW + 7 * 86_400)
    }

    fn ack(n: u8) -> Vec<u8> {
        packet(n, Kind::Ack, NOW + 7 * 86_400)
    }

    /// Responsibles 1..=5, best score first.
    fn five(_: &MailboxId) -> Vec<NodeId> {
        (1..=5).map(node).collect()
    }

    fn accept(ledger: &mut Ledger, bytes: &[u8], n: u8, now: u64) {
        let ev = record_outcome(ledger, content_hash(bytes), node(n), &Ok(()), now);
        assert_eq!(ev, ScoreEvent::Success);
    }

    fn summary(plan: &[PlannedDeposit]) -> Vec<(u8, u8, bool, bool)> {
        plan.iter()
            .map(|d| {
                let p = Packet::decode(&d.bytes).unwrap();
                (p.id.0[0], d.node.0[0], d.is_ack, d.first_copy)
            })
            .collect()
    }

    #[test]
    fn acks_first_then_first_copies_then_resends_then_extra() {
        let mut ledger = Ledger::default();
        // Message 1: accepted on node 1 seven hours ago, no receipt: resend.
        // Message 2: accepted on node 2 just now: extra copies.
        // Message 3: never deposited: first copy, then extra copies.
        accept(&mut ledger, &msg(1), 1, NOW - 7 * 3600);
        accept(&mut ledger, &msg(2), 2, NOW);
        let outbox = vec![msg(1), msg(2), msg(3), ack(4)];
        let plan = plan_deposits(&outbox, &ledger, five, NOW);
        assert_eq!(
            summary(&plan),
            vec![
                (4, 1, true, true),
                (3, 1, false, true),
                (1, 2, false, false),
                (1, 3, false, false),
                (2, 1, false, false),
                (2, 3, false, false),
                (3, 2, false, false),
                (3, 3, false, false),
            ]
        );
        // Duplicates in the outbox are planned once.
        let plan = plan_deposits(&[ack(4), ack(4)], &Ledger::default(), five, NOW);
        assert_eq!(plan.len(), 1);
        // An accepted receipt is done; undecodable bytes are skipped.
        accept(&mut ledger, &ack(4), 1, NOW);
        let plan = plan_deposits(&[ack(4), vec![1, 2, 3]], &ledger, five, NOW);
        assert!(plan.is_empty());
    }

    #[test]
    fn first_copy_goes_to_best_scored_responsible() {
        let best_first = |_: &MailboxId| vec![node(9), node(1), node(2)];
        let plan = plan_deposits(&[msg(1)], &Ledger::default(), best_first, NOW);
        assert_eq!(plan[0].node, node(9));
        assert!(plan[0].first_copy);
        assert_eq!(plan.len(), CLIENT_COPIES);
        // No responsible known: nothing to plan.
        let none = |_: &MailboxId| Vec::new();
        assert!(plan_deposits(&[msg(1)], &Ledger::default(), none, NOW).is_empty());
    }

    #[test]
    fn retry_delays_by_outcome() {
        let cases = [
            (Ok(()), REDEPOSIT_AFTER_SECS, ScoreEvent::Success),
            (Err(ErrorReason::PowTooWeak), 86_400, ScoreEvent::Neutral),
            (Err(ErrorReason::NodeFull), 600, ScoreEvent::Neutral),
            (Err(ErrorReason::MailboxFull), 600, ScoreEvent::Neutral),
            (
                Err(ErrorReason::UnknownAckTarget),
                3_600,
                ScoreEvent::Neutral,
            ),
        ];
        for (result, delay, event) in cases {
            let mut ledger = Ledger::default();
            let a = ack(1);
            let only_one = |_: &MailboxId| vec![node(1)];
            assert_eq!(
                record_outcome(&mut ledger, content_hash(&a), node(1), &result, NOW),
                event
            );
            if result.is_ok() {
                continue;
            }
            assert!(
                plan_deposits(std::slice::from_ref(&a), &ledger, only_one, NOW + delay - 1)
                    .is_empty()
            );
            assert_eq!(plan_deposits(&[a], &ledger, only_one, NOW + delay).len(), 1);
        }
        // An accepted node is never planned again for that packet.
        let mut ledger = Ledger::default();
        accept(&mut ledger, &msg(1), 1, NOW);
        let only_one = |_: &MailboxId| vec![node(1)];
        assert!(plan_deposits(&[msg(1)], &ledger, only_one, NOW + 2 * 86_400).is_empty());
        // RateLimited sets no delay.
        let mut ledger = Ledger::default();
        let r = Err(ErrorReason::RateLimited);
        assert_eq!(
            record_outcome(&mut ledger, content_hash(&ack(1)), node(1), &r, NOW),
            ScoreEvent::Neutral
        );
        assert_eq!(plan_deposits(&[ack(1)], &ledger, only_one, NOW).len(), 1);
    }

    #[test]
    fn lost_message_redeposited_elsewhere_immediately() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW);
        accept(&mut ledger, &m, 2, NOW);
        accept(&mut ledger, &m, 3, NOW);
        assert!(plan_deposits(std::slice::from_ref(&m), &ledger, five, NOW).is_empty());
        // Node 2 is fetched in full and the message is missing.
        let lost = detect_losses(
            &mut ledger,
            &node(2),
            &[MB],
            &[],
            std::slice::from_ref(&m),
            NOW + 60,
        );
        assert_eq!(lost, vec![content_hash(&m)]);
        // Idempotent: the same fetch reported again finds no new loss.
        let again = detect_losses(
            &mut ledger,
            &node(2),
            &[MB],
            &[],
            std::slice::from_ref(&m),
            NOW + 60,
        );
        assert!(again.is_empty());
        assert_eq!(ledger.holders(&content_hash(&m)), vec![node(1), node(3)]);
        // Resent right away, not to node 2.
        let plan = plan_deposits(std::slice::from_ref(&m), &ledger, five, NOW + 60);
        assert_eq!(summary(&plan), vec![(1, 4, false, false)]);
        // Once accepted elsewhere, the loss is made up.
        accept(&mut ledger, &m, 4, NOW + 60);
        assert!(plan_deposits(std::slice::from_ref(&m), &ledger, five, NOW + 120).is_empty());
        // The message still found on node 1 counts as found.
        let found = found_messages(&ledger, &node(1), std::slice::from_ref(&m));
        assert_eq!(found, vec![content_hash(&m)]);
        assert!(found_messages(&ledger, &node(2), std::slice::from_ref(&m)).is_empty());
    }

    #[test]
    fn no_ack_after_six_hours_adds_copies_up_to_three() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW);
        // Node 2 refused (full); its delay is over by the next plans.
        let full = Err(ErrorReason::NodeFull);
        record_outcome(&mut ledger, content_hash(&m), node(2), &full, NOW);
        // Before six hours: extra copies only.
        let plan = plan_deposits(
            std::slice::from_ref(&m),
            &ledger,
            five,
            NOW + RESEND_AFTER_SECS - 1,
        );
        assert_eq!(
            summary(&plan),
            vec![(1, 2, false, false), (1, 3, false, false)]
        );
        // After six hours: resends, ahead of the first copy of a new message.
        let outbox = vec![m.clone(), msg(2)];
        let plan = plan_deposits(&outbox, &ledger, five, NOW + RESEND_AFTER_SECS);
        assert_eq!(
            summary(&plan)[..3],
            [
                (2, 1, false, true),
                (1, 2, false, false),
                (1, 3, false, false)
            ]
        );
        // Three holders: no more copies, even later.
        accept(&mut ledger, &m, 2, NOW + RESEND_AFTER_SECS);
        accept(&mut ledger, &m, 3, NOW + RESEND_AFTER_SECS);
        assert!(plan_deposits(&[m], &ledger, five, NOW + 2 * RESEND_AFTER_SECS).is_empty());
    }

    #[test]
    fn acked_message_is_not_counted_lost() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW);
        // The receipt arrived: the message left the outbox.
        let lost = detect_losses(&mut ledger, &node(1), &[MB], &[], &[], NOW + 60);
        assert!(lost.is_empty());
        assert_eq!(ledger.holders(&content_hash(&m)), vec![node(1)]);
        // Present on the node: not lost either.
        let lost = detect_losses(
            &mut ledger,
            &node(1),
            &[MB],
            std::slice::from_ref(&m),
            std::slice::from_ref(&m),
            NOW,
        );
        assert!(lost.is_empty());
        // A node that never accepted it loses nothing.
        let lost = detect_losses(
            &mut ledger,
            &node(2),
            &[MB],
            &[],
            std::slice::from_ref(&m),
            NOW,
        );
        assert!(lost.is_empty());
        // The copy relayed with fewer hops left is the same message.
        let mut relayed = m.clone();
        relayed[2] = 3;
        let lost = detect_losses(&mut ledger, &node(1), &[MB], &[relayed], &[m], NOW);
        assert!(lost.is_empty());
    }

    #[test]
    fn ack_in_fetch_proves_message_not_lost() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW);
        // The recipient's receipt replaced the message on the node, and the
        // outbox has not been refreshed yet.
        let receipt = Packet {
            kind: Kind::Ack,
            hops: 8,
            tier: Tier::S,
            id: PacketId([42; 16]),
            expires_at: (NOW + 86_400) as u32,
            mailbox: MB,
            payload: [[1u8; 16], [9u8; 16]].concat(),
        }
        .encode();
        let ob = std::slice::from_ref(&m);
        let lost = detect_losses(&mut ledger, &node(1), &[MB], &[receipt], ob, NOW + 60);
        assert!(lost.is_empty());
        assert_eq!(ledger.holders(&content_hash(&m)), vec![node(1)]);
        // A receipt for another message proves nothing.
        let other = packet(5, Kind::Ack, NOW + 86_400);
        let lost = detect_losses(&mut ledger, &node(1), &[MB], &[other], ob, NOW + 60);
        assert_eq!(lost, vec![content_hash(&m)]);
    }

    #[test]
    fn truncated_fetch_detects_no_loss() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW);
        // The mailbox was not fetched in full (truncated or not asked).
        let other = MailboxId([8; 16]);
        let lost = detect_losses(
            &mut ledger,
            &node(1),
            &[other],
            &[],
            std::slice::from_ref(&m),
            NOW,
        );
        assert!(lost.is_empty());
        assert_eq!(ledger.holders(&content_hash(&m)), vec![node(1)]);
    }

    #[test]
    fn expired_message_is_not_lost() {
        let mut ledger = Ledger::default();
        let m = packet(1, Kind::Message, NOW + 100);
        accept(&mut ledger, &m, 1, NOW);
        let lost = detect_losses(
            &mut ledger,
            &node(1),
            &[MB],
            &[],
            std::slice::from_ref(&m),
            NOW + 100,
        );
        assert!(lost.is_empty());
        // Nor planned.
        assert!(plan_deposits(&[m], &Ledger::default(), five, NOW + 100).is_empty());
        // Within the grace before expiry a node with a fast clock may have
        // purged it already: not checkable.
        let m = packet(3, Kind::Message, NOW + LOSS_GRACE_SECS);
        accept(&mut ledger, &m, 1, NOW);
        let ob = std::slice::from_ref(&m);
        assert!(detect_losses(&mut ledger, &node(1), &[MB], &[], ob, NOW).is_empty());
        // Just beyond the grace it is checked.
        let lost = detect_losses(&mut ledger, &node(1), &[MB], &[], ob, NOW - 1);
        assert_eq!(lost, vec![content_hash(&m)]);
        // Receipts are never checked for losses.
        let a = ack(2);
        accept(&mut ledger, &a, 1, NOW);
        assert!(detect_losses(&mut ledger, &node(1), &[MB], &[], &[a], NOW).is_empty());
    }

    #[test]
    fn prune_forgets_left_packets() {
        let mut ledger = Ledger::default();
        let (m1, m2) = (msg(1), msg(2));
        accept(&mut ledger, &m1, 1, NOW);
        accept(&mut ledger, &m2, 1, NOW);
        let full = Err(ErrorReason::NodeFull);
        record_outcome(&mut ledger, content_hash(&m2), node(2), &full, NOW);
        prune(
            &mut ledger,
            std::slice::from_ref(&m2),
            NOW + FULL_RETRY_SECS,
        );
        assert!(!ledger.contains(&content_hash(&m1)));
        assert!(ledger.contains(&content_hash(&m2)));
        let state = &ledger.packets[&content_hash(&m2)];
        assert_eq!(state.retry.len(), 1, "elapsed delay forgotten");
        assert_eq!(state.retry[0].0, node(1));
    }

    #[test]
    fn ledger_dates_hour_rounded_and_restore_clamps() {
        let mut ledger = Ledger::default();
        let m = msg(1);
        accept(&mut ledger, &m, 1, NOW + 1234);
        let state = &ledger.packets[&content_hash(&m)];
        assert_eq!(state.first_accepted, Some(NOW));
        assert_eq!(state.accepted[0].1, NOW);
        let bytes = postcard::to_allocvec(&ledger).unwrap();
        assert_eq!(Ledger::restore(&bytes, NOW + 1234).unwrap(), ledger);
        // Clock gone back a week: dates brought back to the present.
        let restored = Ledger::restore(&bytes, NOW - 7 * 86_400).unwrap();
        let state = &restored.packets[&content_hash(&m)];
        assert_eq!(state.first_accepted, Some(NOW - 7 * 86_400));
        assert!(state.retry[0].1 <= NOW - 7 * 86_400 + REDEPOSIT_AFTER_SECS);
        // Garbage gives an error, never a panic.
        assert!(Ledger::restore(&[0xff; 7], NOW).is_err());
    }
}
