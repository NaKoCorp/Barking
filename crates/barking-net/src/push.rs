//! Wake subscriptions of this device: which nodes hold a subscription for
//! which of my mailboxes, planned over a seven-day horizon (spec §5), and
//! for which mailboxes where a message I sent awaits its ack (`Acks`).
//!
//! Everything here is pure: [`plan_push`] compares the persisted
//! [`PushState`] with the mailboxes wanted and the nodes responsible for each
//! (given by the caller), and says what to subscribe, unsubscribe and forget.
//! Sending the requests and recording their outcome is the caller's job.
//! The state lives in the core's encrypted database
//! (`Core::transport_state("push")`), never in the clear.

use std::collections::BTreeMap;

use barking_core::mailbox::day_of;
use barking_core::{Core, CoreError};
use barking_packet::MailboxId;
use barking_proto::NodeId;
use barking_proto::push::{
    ApnsEnv, RelayRef, SubKind, Subscription, WakeReason, WakeToken, cancel_hash, seal,
};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

/// Days ahead of today whose mailboxes are subscribed.
pub const HORIZON_DAYS: u32 = 7;
/// Nodes subscribed per mailbox: with `CLIENT_COPIES` (3) first copies on the
/// five responsibles, 3 + 3 > 5 guarantees that a sender and a recipient who
/// agree on the responsibles share a node, so the first wake-up does not wait
/// for replication between nodes (spec §1, §5.2).
pub const WAKE_NODES: usize = 3;
/// Key of the state in the core's database.
pub const PUSH_STATE_KEY: &str = "push";
/// How long a node that did not wake is left out of the plan.
pub const NO_WAKE_SECS: u64 = 86_400;

/// Version of the encoding. Format 1 (no kind: every subscription was a
/// `Messages` one) still reads, as `Messages`; it is written back as the
/// current format on the next save. Any other value reads as an unreadable
/// state. Frozen: any change to `Stored` must bump `FORMAT` and migrate the
/// older formats (`push_state_golden_bytes` holds the bytes of format 2,
/// `push_state_format_1_reads_as_messages` those of format 1).
const FORMAT: u8 = 2;
const FORMAT_1: u8 = 1;

/// What the relay and the sealing key are, and the device token to wake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushConfig {
    pub relay: RelayRef,
    pub seal_public: [u8; 32],
    pub seal_key_id: u8,
    pub apns_token: Vec<u8>,
    pub env: ApnsEnv,
}

/// Subscriptions held for one mailbox and one kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxSubs {
    /// Day of the mailbox.
    pub day: u32,
    /// Collapse label, the same on every node of the mailbox.
    pub collapse: [u8; 16],
    /// Nodes holding a subscription, with the secret that cancels it.
    pub nodes: Vec<(NodeId, [u8; 32])>,
}

/// Subscriptions kept between runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushState {
    /// BLAKE3 of the encoded `PushConfig` the subscriptions were made with;
    /// `None` when push is off.
    pub config_hash: Option<[u8; 32]>,
    /// By mailbox and kind: the two kinds of a mailbox are distinct
    /// subscriptions on the node, with their own secrets and labels.
    pub subs: BTreeMap<(MailboxId, SubKind), BoxSubs>,
    /// End of the time a node is left out, by node.
    pub no_wake: BTreeMap<NodeId, u64>,
}

/// Mailbox, kind, day, collapse label, nodes with their cancel secret.
type StoredBox = (MailboxId, SubKind, u32, [u8; 16], Vec<(NodeId, [u8; 32])>);

#[derive(Serialize, Deserialize)]
struct Stored {
    format: u8,
    config_hash: Option<[u8; 32]>,
    subs: Vec<StoredBox>,
    no_wake: Vec<(NodeId, u64)>,
}

/// Format 1: mailbox, day, collapse label, nodes (all `Messages`).
type StoredBox1 = (MailboxId, u32, [u8; 16], Vec<(NodeId, [u8; 32])>);

#[derive(Deserialize)]
struct Stored1 {
    format: u8,
    config_hash: Option<[u8; 32]>,
    subs: Vec<StoredBox1>,
    no_wake: Vec<(NodeId, u64)>,
}

/// What a run has to do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushPlan {
    pub subscribe: Vec<(MailboxId, SubKind, NodeId)>,
    pub unsubscribe: Vec<(MailboxId, SubKind, NodeId, [u8; 32])>,
    /// Entries to drop from the state without unsubscribing (their
    /// subscriptions expire by themselves), or once their unsubscribes
    /// are sent.
    pub forget: Vec<(MailboxId, SubKind)>,
}

impl PushState {
    /// Reads the state. A missing or undecodable one gives an empty state; a
    /// storage read error is returned, so that the caller never plans from an
    /// empty state over real subscriptions (it would lose their cancel
    /// secrets).
    pub fn load(core: &Core) -> Result<PushState, CoreError> {
        Ok(match core.transport_state(PUSH_STATE_KEY)? {
            Some(bytes) => PushState::decode(&bytes).unwrap_or_else(|| {
                tracing::warn!("unreadable push state: starting from an empty one");
                PushState::default()
            }),
            None => PushState::default(),
        })
    }

    /// Writes the state to the core's encrypted database.
    pub fn save(&self, core: &mut Core) -> Result<(), CoreError> {
        core.set_transport_state(PUSH_STATE_KEY, &self.encode())
    }

    /// Postcard encoding of the state.
    pub fn encode(&self) -> Vec<u8> {
        let stored = Stored {
            format: FORMAT,
            config_hash: self.config_hash,
            subs: self
                .subs
                .iter()
                .map(|((m, k), b)| (*m, *k, b.day, b.collapse, b.nodes.clone()))
                .collect(),
            no_wake: self.no_wake.iter().map(|(n, t)| (*n, *t)).collect(),
        };
        postcard::to_allocvec(&stored).expect("a push state always encodes")
    }

    /// Rebuilds a state from `encode` output; `None` if unreadable.
    /// Format 1 reads with every entry as `Messages`.
    pub fn decode(bytes: &[u8]) -> Option<PushState> {
        // `format` comes first, and postcard writes a `u8` as one byte.
        let (config_hash, subs, no_wake): (_, Vec<StoredBox>, _) = match *bytes.first()? {
            FORMAT => {
                let s: Stored = postcard::from_bytes(bytes).ok()?;
                (s.config_hash, s.subs, s.no_wake)
            }
            FORMAT_1 => {
                let s: Stored1 = postcard::from_bytes(bytes).ok()?;
                debug_assert_eq!(s.format, FORMAT_1);
                let subs = s
                    .subs
                    .into_iter()
                    .map(|(m, day, collapse, nodes)| (m, SubKind::Messages, day, collapse, nodes))
                    .collect();
                (s.config_hash, subs, s.no_wake)
            }
            _ => return None,
        };
        Some(PushState {
            config_hash,
            subs: subs
                .into_iter()
                .map(|(m, kind, day, collapse, nodes)| {
                    (
                        (m, kind),
                        BoxSubs {
                            day,
                            collapse,
                            nodes,
                        },
                    )
                })
                .collect(),
            no_wake: no_wake.into_iter().collect(),
        })
    }

    /// Hash identifying a configuration (see `config_hash`).
    pub fn config_hash_of(cfg: &PushConfig) -> [u8; 32] {
        let bytes = postcard::to_allocvec(cfg).expect("a push config always encodes");
        *blake3::hash(&bytes).as_bytes()
    }

    /// Switches to `cfg` (`None`: push off): stores its hash and clears
    /// `subs`. Call it after sending the unsubscribes `plan_push` asked for on
    /// a configuration change, before recording the new subscriptions.
    pub fn apply_config(&mut self, cfg: Option<&PushConfig>) {
        self.config_hash = cfg.map(PushState::config_hash_of);
        self.subs.clear();
    }

    /// Collapse label of `mailbox` for `kind`, created (with an entry that
    /// holds no node yet) the first time, so that the label sealed into the
    /// first subscription is the one `note_subscribed` keeps.
    pub fn collapse_for(
        &mut self,
        mailbox: MailboxId,
        kind: SubKind,
        day: u32,
        rng: &mut impl CryptoRng,
    ) -> [u8; 16] {
        self.subs
            .entry((mailbox, kind))
            .or_insert_with(|| {
                let mut collapse = [0u8; 16];
                rng.fill_bytes(&mut collapse);
                BoxSubs {
                    day,
                    collapse,
                    nodes: Vec::new(),
                }
            })
            .collapse
    }

    /// `node` accepted the subscription of `mailbox` for `kind`; `secret`
    /// cancels it. The collapse label is created with the first node of the
    /// entry.
    pub fn note_subscribed(
        &mut self,
        mailbox: MailboxId,
        kind: SubKind,
        day: u32,
        node: NodeId,
        secret: [u8; 32],
        rng: &mut impl CryptoRng,
    ) {
        self.collapse_for(mailbox, kind, day, rng);
        let b = self
            .subs
            .get_mut(&(mailbox, kind))
            .expect("entry just ensured");
        match b.nodes.iter_mut().find(|(n, _)| *n == node) {
            Some(entry) => entry.1 = secret,
            None => b.nodes.push((node, secret)),
        }
    }

    /// The subscription of `mailbox` for `kind` on `node` is cancelled (or
    /// gone).
    pub fn note_unsubscribed(&mut self, mailbox: &MailboxId, kind: SubKind, node: &NodeId) {
        let key = (*mailbox, kind);
        if let Some(b) = self.subs.get_mut(&key) {
            b.nodes.retain(|(n, _)| n != node);
            if b.nodes.is_empty() {
                self.subs.remove(&key);
            }
        }
    }

    /// `node` refused or did not take a subscription: left out for
    /// `NO_WAKE_SECS`. Ended exclusions are pruned.
    pub fn note_no_wake(&mut self, node: NodeId, now: u64) {
        self.no_wake.retain(|_, until| *until > now);
        self.no_wake.insert(node, now.saturating_add(NO_WAKE_SECS));
    }

    fn left_out(&self, node: &NodeId, now: u64) -> bool {
        self.no_wake.get(node).is_some_and(|until| *until > now)
    }
}

/// First day whose mailboxes a subscription of `kind` is planned for: today
/// for messages; yesterday too for acks, since a message sealed yesterday
/// (in yesterday's mailbox) may still be acked or expire today, and the
/// subscription runs until the end of the day after its mailbox's day.
fn first_day(kind: SubKind, today: u32) -> u32 {
    match kind {
        SubKind::Messages => today,
        SubKind::Acks => today.saturating_sub(1),
    }
}

/// What to subscribe and unsubscribe so that each wanted mailbox of the
/// horizon has `WAKE_NODES` subscriptions of its kind on its best-ranked
/// nodes.
///
/// `wanted` (mailbox, day, kind) is walked in order; the two kinds of a
/// mailbox are planned apart, as distinct subscriptions. `ranked(mailbox)`
/// lists the nodes responsible for it, best first. Within an entry the
/// nodes already subscribed stay, in their stored order, and the
/// best-ranked missing ones complete them. Without `cfg`, everything is
/// cancelled and forgotten. When the configuration changed, every stored
/// subscription is cancelled and every wanted entry subscribed afresh (the
/// caller then calls `apply_config`). An entry of a past day (before
/// `first_day` of its kind) is forgotten without unsubscribing. A wanted
/// entry whose `ranked` list is empty keeps its stored nodes untouched (no
/// cancel, no new subscription).
pub fn plan_push(
    state: &PushState,
    cfg: Option<&PushConfig>,
    wanted: &[(MailboxId, u32, SubKind)],
    ranked: impl Fn(&MailboxId) -> Vec<NodeId>,
    now: u64,
) -> PushPlan {
    type Key = (MailboxId, SubKind);
    let mut plan = PushPlan::default();
    let unsubscribe_all = |plan: &mut PushPlan, only: Option<&Key>| {
        for ((m, k), b) in &state.subs {
            if only.is_some_and(|o| *o != (*m, *k)) {
                continue;
            }
            for (n, secret) in &b.nodes {
                plan.unsubscribe.push((*m, *k, *n, *secret));
            }
        }
    };
    let Some(cfg) = cfg else {
        unsubscribe_all(&mut plan, None);
        plan.forget = state.subs.keys().copied().collect();
        return plan;
    };
    let changed = state.config_hash != Some(PushState::config_hash_of(cfg));
    if changed {
        unsubscribe_all(&mut plan, None);
    }
    let today = day_of(now);
    let last = today.saturating_add(HORIZON_DAYS);
    let mut seen: Vec<Key> = Vec::new();
    for &(mailbox, day, kind) in wanted {
        let key = (mailbox, kind);
        if day < first_day(kind, today) || day > last || seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let stored: &[(NodeId, [u8; 32])] = match state.subs.get(&key) {
            Some(b) if !changed => &b.nodes,
            _ => &[],
        };
        let ranked = ranked(&mailbox);
        // No responsible known (a view without records): the ranking says
        // nothing, the stored nodes stay as they are.
        if ranked.is_empty() {
            continue;
        }
        let mut kept: Vec<NodeId> = Vec::new();
        for (node, secret) in stored {
            if kept.len() < WAKE_NODES && ranked.contains(node) && !state.left_out(node, now) {
                kept.push(*node);
            } else {
                plan.unsubscribe.push((mailbox, kind, *node, *secret));
            }
        }
        for node in &ranked {
            if kept.len() >= WAKE_NODES {
                break;
            }
            if !kept.contains(node) && !state.left_out(node, now) {
                kept.push(*node);
                plan.subscribe.push((mailbox, kind, *node));
            }
        }
    }
    if !changed {
        for (key, b) in &state.subs {
            if seen.contains(key) {
                continue;
            }
            // Past days expire by themselves; an entry that is no longer
            // wanted is cancelled.
            if b.day >= first_day(key.1, today) {
                unsubscribe_all(&mut plan, Some(key));
            }
            plan.forget.push(*key);
        }
    }
    plan
}

/// Builds the subscription of `mailbox` (of `day`) for `kind` to send to a
/// node, and the secret that cancels it. The sealed token carries the wake
/// reason of the kind (`Messages` → `Message`, `Acks` → `Receipt`), so that
/// the relay sends a receipt wake as a background push. `collapse` comes
/// from `PushState::collapse_for`, called first. It expires the day after
/// the mailbox's day, so that a node a day ahead still takes it.
pub fn build_subscription(
    cfg: &PushConfig,
    mailbox: MailboxId,
    day: u32,
    kind: SubKind,
    collapse: [u8; 16],
    rng: &mut impl CryptoRng,
) -> (Subscription, [u8; 32]) {
    let expires_day = day.saturating_add(1);
    let token = WakeToken {
        apns_token: cfg.apns_token.clone(),
        env: cfg.env,
        collapse,
        expires_day,
        reason: match kind {
            SubKind::Messages => WakeReason::Message,
            SubKind::Acks => WakeReason::Receipt,
        },
    };
    let sealed = seal(&cfg.seal_public, cfg.seal_key_id, &token, rng);
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let sub = Subscription {
        mailbox,
        relay: cfg.relay.clone(),
        sealed,
        cancel_hash: cancel_hash(&secret),
        expires_day,
        kind,
    };
    (sub, secret)
}

#[cfg(test)]
mod tests;
