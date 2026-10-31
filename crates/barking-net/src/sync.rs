//! Full synchronization (spec §6), in this order, the state being saved
//! after each response so that a cut connection redoes nothing:
//!
//! 1. **View.** Expiry and score recovery; bootstrap when fewer than 3 nodes
//!    are reachable.
//! 2. **Session fetch.** Session mailboxes grouped by best responsible (the
//!    session splits each group into `Fetch` requests of 64 mailboxes at
//!    most), resumed from the positions per (node, mailbox). On a failure
//!    or a truncated fetch, the mailboxes concerned go to their next
//!    responsible. Loss audit (spec §5.1) on the way.
//! 3. **Deposits**, following `plan_deposits`: receipts (no proof of work),
//!    first copies, resends, extra copies. Proof budget exhausted: messages
//!    wait, receipts go. `NotResponsible` from 2 responsibles of a mailbox:
//!    fallback lookup, then the plan is redone.
//! 4. **Introduction fetch**, within `INTRO_FETCH_BYTES` and
//!    `INTRO_FETCH_SLICE`; a partial one blocks nothing.
//! 5. **Maintenance**, with the time left: random lookups, candidate
//!    confirmation, fallback lookups while the view is small, then the node
//!    hints of my contact card.
//! 6. `mark_polled` only if every session mailbox was fetched in full.
//!
//! **Score.** Successful requests +0.02, a failure −0.1 only once some node
//! answered during this sync (until then failures wait; if none answers, the
//! client's own connection is at fault). `Found` at most once per node per
//! sync, at most one failure per node per sync. A node whose session
//! fetches are all cut by a lost connection for `UNAUDITED_SYNCS` syncs in a
//! row cannot be audited: one failure per sync from then on. Loss audits of
//! positioned mailboxes re-read them from their start every
//! `AUDIT_EVERY_SECS`, each in a call of its own once all regular session
//! fetches are over, within `REREAD_BYTES` and `REREAD_TIME`.
//!
//! Nothing here logs an address or a mailbox: the transparency log gets the
//! short node id only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::transparency::{AvoidReason, TransparencyEvent};
use barking_core::{Core, CoreError, ReceiveOutcome};
use barking_dht::{BootstrapEntry, builtin_bootstrap};
use barking_packet::{MailboxId, Packet};
use barking_proto::pow::content_hash;
use barking_proto::{ErrorReason, NodeId, NodeRecord};
use tokio::time::Instant;

use crate::discover::{self, DialError, Dialer};
use crate::plan::{self, plan_deposits, record_outcome};
use crate::score::ScoreEvent;
use crate::state::NetState;
use crate::{BOOTSTRAP_VIEW, CandidateBudget};

mod fetch;
mod io;

pub use barking_proto::client::FetchStop;
pub use io::{Connector, DepositOutcome, DepositReply, Depositor, FetchReply, Fetcher};
use io::{Observation, Observed};

/// Longest synchronization.
pub const SYNC_DEADLINE: Duration = Duration::from_secs(180);
/// Proof-of-work allowed per sync (expected attempts): about 1,000
/// deposits at 18 bits, 16 at 24 bits.
pub const SYNC_POW_BUDGET: u64 = 1 << 28;
/// Longest session fetch (all responsibles together).
pub const SESSION_FETCH_SLICE: Duration = Duration::from_secs(90);
/// Longest introduction fetch: beyond it, the fetch is partial, without
/// failing any node.
pub const INTRO_FETCH_SLICE: Duration = Duration::from_secs(45);
/// Maximum bytes fetched per sync from the introduction mailboxes: they are
/// computed from a public key, so anyone can fill them with junk.
pub const INTRO_FETCH_BYTES: usize = 8 << 20;
/// Random lookups per sync, with time left.
pub const LOOKUPS_PER_SYNC: usize = 2;
/// Random lookups per sync while the view has fewer than `BOOTSTRAP_VIEW` nodes.
pub const BOOTSTRAP_LOOKUPS_PER_SYNC: usize = 8;
/// Candidates pinged per sync to confirm them.
pub const CONFIRMS_PER_SYNC: usize = 8;
/// Longest ping of a candidate.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);
/// Reachable nodes below which the sync bootstraps first.
pub const MIN_REACHABLE: usize = 3;
/// Syncs in a row in which a node answered but none of its session fetches
/// completed, the connection being cut (never a rate limit, a client cap or
/// the client's own deadline or slice), after which it gets one failure per
/// sync: it cannot be audited for losses.
pub const UNAUDITED_SYNCS: u32 = 3;
/// A positioned mailbox holding a message the node accepted is read again
/// from its start, for a loss audit, at most this often: in a call of its
/// own, once all regular session fetches are over.
pub const AUDIT_EVERY_SECS: u64 = 6 * 3600;
/// Bytes all audit re-reads of a sync may fetch together.
pub const REREAD_BYTES: usize = 8 << 20;
/// Time all audit re-reads of a sync may take together (within the
/// session fetch slice).
pub const REREAD_TIME: Duration = Duration::from_secs(20);
/// `NotResponsible` answers from distinct responsibles of one mailbox that
/// trigger a fallback lookup.
pub const NOT_RESPONSIBLE_FALLBACK: usize = 2;
/// Time given to closing the connections at the end of a sync.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Transport name given to `Core::receive` (noted in the core's log).
pub const TRANSPORT: &str = "nœud";

/// Introduction fetch slice; adjustable in test builds only.
pub fn intro_slice() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("BARKING_TEST_INTRO_SLICE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return Duration::from_millis(ms);
    }
    INTRO_FETCH_SLICE
}

/// Proof-of-work budget per sync; adjustable in test builds only.
pub fn pow_budget() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(b) = std::env::var("BARKING_TEST_POW_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return b;
    }
    SYNC_POW_BUDGET
}

/// Passes each fetched item to `Core::receive` and hands every result to
/// `on`. False if an item could not be processed (local error): it must
/// not leave the fetch window. A receipt may arrive in a mailbox other than
/// the one fetched for it: everything goes through `receive`, which decides.
pub fn receive_all(
    core: &mut Core,
    items: &[Vec<u8>],
    now: u64,
    mut on: impl FnMut(Result<ReceiveOutcome, CoreError>),
) -> bool {
    let mut rng = rand::rng();
    let mut all = true;
    for item in items {
        let r = core.receive(item, TRANSPORT, now, &mut rng);
        all &= r.is_ok();
        on(r);
    }
    all
}

/// Settings of a sync.
#[derive(Clone, Debug)]
pub struct SyncOptions {
    /// Longest sync (`SYNC_DEADLINE`).
    pub deadline: Duration,
    /// Proof-of-work budget (`pow_budget()`).
    pub pow_budget: u64,
    /// Nodes added by hand, with their address: they enter the view as such.
    pub manual_nodes: Vec<(NodeId, SocketAddr)>,
    /// Built-in bootstrap list (`builtin_bootstrap()`).
    pub builtin: Vec<BootstrapEntry>,
    /// Accept non-routable addresses (tests, private networks).
    pub allow_private: bool,
    /// Date of the sync (tests); `None`: the system clock.
    pub now: Option<u64>,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            deadline: SYNC_DEADLINE,
            pow_budget: pow_budget(),
            manual_nodes: Vec::new(),
            builtin: builtin_bootstrap(),
            allow_private: false,
            now: None,
        }
    }
}

/// What a sync did.
#[derive(Debug, Default)]
pub struct SyncReport {
    /// Mailboxes fetched in full (sessions and introductions).
    pub mailboxes_polled: usize,
    /// Items fetched.
    pub items_received: usize,
    /// What `Core::receive` made of them, in order (errors excepted).
    pub received: Vec<ReceiveOutcome>,
    /// Items that could not be processed (fetched again next time).
    pub receive_errors: usize,
    /// Receipts accepted by a node.
    pub acks_deposited: usize,
    /// First copies of messages accepted.
    pub first_copies: usize,
    /// Extra copies and resends accepted.
    pub extra_copies: usize,
    /// Deposits refused by a node.
    pub refused: usize,
    /// Short ids of the nodes set aside during this sync.
    pub avoided: Vec<String>,
    /// Entries in the view at the end.
    pub view_size: usize,
    /// Some node answered during this sync.
    pub network_up: bool,
    /// Every session mailbox was fetched in full and processed.
    pub polled_all_sessions: bool,
    /// The introductions were not fetched in full (no effect on polling).
    pub intro_partial: bool,
    /// Proof-of-work budget exhausted: messages wait for the next sync.
    pub pow_exhausted: bool,
    /// Maintenance of the view ran.
    pub maintenance_done: bool,
    /// Local error that stopped the sync (the state could not be read).
    pub error: Option<String>,
}

/// Synchronizes with the network (see the module documentation).
pub async fn sync<D>(core: &mut Core, dialer: &D, opts: SyncOptions) -> SyncReport
where
    D: Dialer + Depositor + Fetcher + Sync,
{
    let now = opts.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    let deadline = Instant::now() + opts.deadline;
    let state = match NetState::load(core, now, opts.allow_private) {
        Ok(s) => s,
        Err(e) => {
            return SyncReport {
                error: Some(e.to_string()),
                ..SyncReport::default()
            };
        }
    };
    let mut run = Run {
        core,
        dialer,
        state,
        conns: HashMap::new(),
        failed: HashSet::new(),
        limited: HashSet::new(),
        pending_failures: Vec::new(),
        penalized: HashSet::new(),
        found: HashSet::new(),
        reread_queue: Vec::new(),
        budget: CandidateBudget::default(),
        now,
        deadline,
        pow_left: opts.pow_budget,
        stats: BTreeMap::new(),
        report: SyncReport::default(),
    };
    run.run(&opts).await;
    run.finish().await
}

/// Per-node counts for the transparency log.
#[derive(Default)]
struct NodeStats {
    mailboxes: u32,
    received: u32,
    deposited: u32,
    refused: u32,
    fetched: bool,
}

struct Run<'a, D: Connector> {
    core: &'a mut Core,
    dialer: &'a D,
    state: NetState,
    conns: HashMap<NodeId, D::Conn>,
    /// Nodes that failed (connection, timeout, protocol) during this sync.
    failed: HashSet<NodeId>,
    /// Nodes that answered `RateLimited`: nothing more asked this sync.
    limited: HashSet<NodeId>,
    /// Failures waiting for some node to answer (network up).
    pending_failures: Vec<NodeId>,
    /// Nodes that already took (or wait for) their failure this sync.
    penalized: HashSet<NodeId>,
    /// Nodes that already got `Found` this sync.
    found: HashSet<NodeId>,
    /// Groups served by a node this sync, for the audit re-reads.
    reread_queue: Vec<(NodeId, Vec<MailboxId>)>,
    budget: CandidateBudget,
    now: u64,
    deadline: Instant,
    pow_left: u64,
    stats: BTreeMap<[u8; 32], (NodeId, NodeStats)>,
    report: SyncReport,
}

impl<D> Run<'_, D>
where
    D: Dialer + Depositor + Fetcher + Sync,
{
    async fn run(&mut self, opts: &SyncOptions) {
        let now = self.now;
        for &(id, addr) in &opts.manual_nodes {
            self.state.view.add_manual(id, addr, now);
        }
        self.state.view.expire(now);
        self.state.view.decay_scores(now);
        self.state.fallbacks.prune(now);
        self.save();

        if self.reachable() < MIN_REACHABLE && !self.over() {
            let hints = self.core.contact_node_hints().unwrap_or_default();
            let observed = Observed::new(self.dialer);
            let mut rng = rand::rng();
            let boot = discover::bootstrap(
                &mut self.state.view,
                hints,
                &opts.builtin,
                &observed,
                &mut rng,
                &mut self.budget,
                now,
            );
            let _ = tokio::time::timeout_at(self.deadline, boot).await;
            self.apply_observed(observed);
            self.save();
        }

        let groups = self.core.watched_mailbox_groups(now);
        let mut sessions = groups.sessions;
        sessions.sort_unstable_by_key(|m| m.0);
        sessions.dedup();
        let mut intro = groups.intro;
        intro.sort_unstable_by_key(|m| m.0);
        intro.dedup();
        let watched: HashSet<MailboxId> = sessions.iter().chain(&intro).copied().collect();
        self.state.retain_positions(&watched);

        let polled_sessions = self.fetch_stage(&sessions, false).await;
        self.report.polled_all_sessions = polled_sessions;

        self.deposit_stage().await;

        if !intro.is_empty() {
            let polled_intro = self.fetch_stage(&intro, true).await;
            self.report.intro_partial = !polled_intro;
        }

        if !self.over() {
            self.maintenance(&sessions, &intro).await;
        }

        // With no session mailbox, "all polled" also needs a node that
        // answered: otherwise the window would move past unread days.
        self.report.polled_all_sessions &= self.network_up();
        if self.report.polled_all_sessions
            && let Err(e) = self.core.mark_polled(now)
        {
            tracing::warn!("poll date not recorded: {e}");
            self.report.polled_all_sessions = false;
        }
    }

    /// Closes the connections, saves, logs, and returns the report.
    async fn finish(mut self) -> SyncReport {
        // Two seconds for all the closings together; a connection still
        // open then is dropped.
        let close_end = Instant::now() + CLOSE_TIMEOUT;
        for (_, conn) in std::mem::take(&mut self.conns) {
            let close = self.dialer.close(conn);
            let _ = tokio::time::timeout_at(close_end, close).await;
        }
        self.save();
        for (_, (id, s)) in std::mem::take(&mut self.stats) {
            let node = short_id(&id);
            if s.fetched {
                let _ = self.core.log_transport_event(
                    TransparencyEvent::NodeFetch {
                        node: node.clone(),
                        mailboxes: s.mailboxes,
                        received: s.received,
                    },
                    self.now,
                );
            }
            if s.deposited + s.refused > 0 {
                let _ = self.core.log_transport_event(
                    TransparencyEvent::NodeDeposit {
                        node,
                        count: s.deposited,
                        refused: s.refused,
                    },
                    self.now,
                );
            }
        }
        self.report.network_up = self.network_up();
        self.report.view_size = self.state.view.len();
        self.report
    }

    fn over(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn network_up(&self) -> bool {
        self.report.network_up
    }

    /// Confirmed nodes, not avoided, with an address.
    fn reachable(&self) -> usize {
        self.state
            .view
            .entries()
            .filter(|(_, e)| e.confirmed && !e.avoided(self.now) && !e.addrs().is_empty())
            .count()
    }

    fn save(&mut self) {
        if let Err(e) = self.state.save(self.core) {
            tracing::warn!("network state not saved: {e}");
        }
    }

    fn stats(&mut self, id: NodeId) -> &mut NodeStats {
        &mut self
            .stats
            .entry(id.0)
            .or_insert_with(|| (id, NodeStats::default()))
            .1
    }

    /// Some node answered: the failures seen so far count now.
    fn answered(&mut self) {
        if !self.report.network_up {
            self.report.network_up = true;
            for id in std::mem::take(&mut self.pending_failures) {
                self.apply(id, ScoreEvent::Failure);
            }
        }
    }

    /// Applies a score event. A node takes at most one failure per sync,
    /// whatever failed (fetch, deposit, lookup, ping, audit); a failure
    /// waits until some node answered.
    fn score(&mut self, id: NodeId, event: ScoreEvent) {
        if event == ScoreEvent::Failure {
            if !self.penalized.insert(id) {
                return;
            }
            if !self.report.network_up {
                self.pending_failures.push(id);
                return;
            }
        }
        self.apply(id, event);
    }

    fn apply(&mut self, id: NodeId, event: ScoreEvent) {
        if let Some(reason) =
            self.state
                .view
                .apply_score(&id, event, self.now, self.report.network_up)
        {
            self.log_avoided(id, reason);
        }
    }

    fn log_avoided(&mut self, id: NodeId, reason: AvoidReason) {
        let node = short_id(&id);
        let _ = self.core.log_transport_event(
            TransparencyEvent::NodeAvoided {
                node: node.clone(),
                reason,
            },
            self.now,
        );
        self.report.avoided.push(node);
    }

    /// A node failed (connection, timeout, invalid answer).
    fn fail(&mut self, id: NodeId) {
        self.failed.insert(id);
        self.conns.remove(&id);
        self.score(id, ScoreEvent::Failure);
    }

    /// Outcomes of the lookups and pings made through `observed`.
    fn apply_observed(&mut self, observed: Observed<'_, D>) {
        let outcomes = observed.outcomes.into_inner().unwrap_or_default();
        if outcomes.iter().any(|(_, o)| *o != Observation::Failed) {
            self.answered();
        }
        for (id, o) in outcomes {
            match o {
                Observation::Answered => self.score(id, ScoreEvent::Success),
                Observation::Refused => {}
                Observation::Failed => self.score(id, ScoreEvent::Failure),
            }
        }
    }

    /// The kept connection to `id`, or a new one. `None` if the node cannot
    /// be reached (it is then marked failed) or the deadline is over.
    async fn take_conn(&mut self, id: NodeId) -> Option<D::Conn> {
        if let Some(c) = self.conns.remove(&id) {
            return Some(c);
        }
        if self.failed.contains(&id) || self.limited.contains(&id) {
            return None;
        }
        let addrs = self
            .state
            .view
            .get(&id)
            .map(|e| e.addrs())
            .unwrap_or_default();
        match tokio::time::timeout_at(self.deadline, self.dialer.connect(id, &addrs)).await {
            Err(_) => None,
            Ok(Ok(conn)) => {
                self.answered();
                // A pinned handshake proves the node.
                self.state.view.confirm(&id, self.now);
                Some(conn)
            }
            Ok(Err(DialError::Refused(_) | DialError::NoAddress)) => {
                self.failed.insert(id);
                None
            }
            Ok(Err(_)) => {
                self.fail(id);
                None
            }
        }
    }

    /// Deposits the send queue following `plan_deposits`, redoing the plan
    /// when a node drops out (failure, rate limit) or a fallback lookup
    /// enriched the view.
    async fn deposit_stage(&mut self) {
        let now = self.now;
        let Ok(outbox) = self.core.pending_outbox(now) else {
            return;
        };
        plan::prune(&mut self.state.ledger, &outbox, now);
        let mut pow_exhausted = false;
        let mut not_responsible: HashMap<MailboxId, HashSet<NodeId>> = HashMap::new();
        let mut fallback_tried: HashSet<MailboxId> = HashSet::new();
        'plan: loop {
            let excluded: HashSet<NodeId> = self.failed.union(&self.limited).copied().collect();
            let view = &self.state.view;
            let deposits = plan_deposits(
                &outbox,
                &self.state.ledger,
                |m| {
                    view.responsibles_by_score(m, now)
                        .into_iter()
                        .filter(|n| !excluded.contains(n))
                        .collect()
                },
                now,
            );
            for d in deposits {
                if self.over() {
                    break 'plan;
                }
                if !d.is_ack && pow_exhausted {
                    continue;
                }
                let Some(mut conn) = self.take_conn(d.node).await else {
                    if self.over() {
                        break 'plan;
                    }
                    continue 'plan;
                };
                let deposit = self.dialer.deposit(&mut conn, &d.bytes, self.pow_left);
                let Ok(reply) = tokio::time::timeout_at(self.deadline, deposit).await else {
                    break 'plan;
                };
                self.pow_left = self.pow_left.saturating_sub(reply.pow_spent);
                let result = match reply.outcome {
                    Ok(DepositOutcome::Answered(result)) => result,
                    Ok(DepositOutcome::PowBudget) => {
                        self.conns.insert(d.node, conn);
                        pow_exhausted = true;
                        self.report.pow_exhausted = true;
                        continue;
                    }
                    Err(_) => {
                        self.fail(d.node);
                        self.save();
                        continue 'plan;
                    }
                };
                self.answered();
                self.conns.insert(d.node, conn);
                let event = record_outcome(
                    &mut self.state.ledger,
                    content_hash(&d.bytes),
                    d.node,
                    &result,
                    now,
                );
                self.score(d.node, event);
                self.tally(&d, &result);
                self.save();
                match result {
                    Err(ErrorReason::RateLimited) => {
                        self.limited.insert(d.node);
                        continue 'plan;
                    }
                    Err(ErrorReason::NotResponsible) => {
                        let Ok(p) = Packet::decode(&d.bytes) else {
                            continue;
                        };
                        let nodes = not_responsible.entry(p.mailbox).or_default();
                        nodes.insert(d.node);
                        if nodes.len() >= NOT_RESPONSIBLE_FALLBACK
                            && fallback_tried.insert(p.mailbox)
                            && self.fallback(&p.mailbox).await
                        {
                            continue 'plan;
                        }
                    }
                    _ => {}
                }
            }
            break;
        }
    }

    fn tally(&mut self, d: &plan::PlannedDeposit, result: &Result<(), ErrorReason>) {
        let s = self.stats(d.node);
        match result {
            Ok(()) => {
                s.deposited = s.deposited.saturating_add(1);
                if d.is_ack {
                    self.report.acks_deposited += 1;
                } else if d.first_copy {
                    self.report.first_copies += 1;
                } else {
                    self.report.extra_copies += 1;
                }
            }
            // A receipt ahead of its packet is neither: it is redeposited.
            Err(ErrorReason::UnknownAckTarget) if d.is_ack => {}
            Err(ErrorReason::RateLimited) => {}
            Err(_) => {
                s.refused = s.refused.saturating_add(1);
                self.report.refused += 1;
            }
        }
    }

    /// Fallback lookup on `mailbox` if due and time is left. True if it ran.
    async fn fallback(&mut self, mailbox: &MailboxId) -> bool {
        if self.over() || !self.state.fallbacks.due(mailbox, self.now) {
            return false;
        }
        let observed = Observed::new(self.dialer);
        let lookup = discover::fallback_lookup(
            &mut self.state.view,
            &observed,
            mailbox,
            &mut self.state.fallbacks,
            &mut self.budget,
            self.now,
        );
        let _ = tokio::time::timeout_at(self.deadline, lookup).await;
        self.apply_observed(observed);
        self.save();
        true
    }

    /// Random lookups, candidate confirmation, fallback lookups while the
    /// view is small, then the node hints of my contact card.
    async fn maintenance(&mut self, sessions: &[MailboxId], intro: &[MailboxId]) {
        let now = self.now;
        self.report.maintenance_done = true;
        let count = if self.state.view.len() < BOOTSTRAP_VIEW {
            BOOTSTRAP_LOOKUPS_PER_SYNC
        } else {
            LOOKUPS_PER_SYNC
        };
        let mut rng = rand::rng();
        let observed = Observed::new(self.dialer);
        let lookups = discover::random_lookups(
            &mut self.state.view,
            &observed,
            count,
            &mut rng,
            &mut self.budget,
            now,
        );
        let _ = tokio::time::timeout_at(self.deadline, lookups).await;
        self.apply_observed(observed);
        self.save();

        self.confirm_candidates().await;

        if self.state.view.needs_fallback() {
            let mut mine: Vec<MailboxId> = sessions.iter().chain(intro).copied().collect();
            if let Ok(outbox) = self.core.pending_outbox(now) {
                mine.extend(
                    outbox
                        .iter()
                        .filter_map(|b| Some(Packet::decode(b).ok()?.mailbox)),
                );
            }
            mine.sort_unstable_by_key(|m| m.0);
            mine.dedup();
            for m in &mine {
                if self.over() {
                    break;
                }
                self.fallback(m).await;
            }
        }

        let all: Vec<MailboxId> = sessions.iter().chain(intro).copied().collect();
        let hints = discover::choose_card_nodes(&self.state.view, &all, &mut rng, now);
        if !hints.is_empty()
            && let Err(e) = self.core.set_card_nodes(hints)
        {
            tracing::warn!("contact card node hints not updated: {e}");
        }
    }

    /// Pings up to `CONFIRMS_PER_SYNC` candidates, most recently seen first:
    /// those that answer as themselves become confirmed.
    async fn confirm_candidates(&mut self) {
        let now = self.now;
        let mut candidates: Vec<(NodeId, u64, Vec<SocketAddr>)> = self
            .state
            .view
            .entries()
            .filter(|(_, e)| !e.confirmed && e.record.is_some() && !e.avoided(now))
            .map(|(id, e)| (*id, e.last_seen, e.addrs()))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.0.cmp(&b.0.0)));
        candidates.truncate(CONFIRMS_PER_SYNC);
        let observed = Observed::new(self.dialer);
        for (id, _, addrs) in candidates {
            if self.over() {
                break;
            }
            let end = (Instant::now() + CONFIRM_TIMEOUT).min(self.deadline);
            if let Ok(Ok(record)) = tokio::time::timeout_at(end, observed.ping(id, &addrs)).await {
                confirm(&mut self.state.view, id, record, now);
            }
        }
        self.apply_observed(observed);
        self.save();
    }
}

/// `id` answered a ping pinned on it with `record`: the record is kept if
/// it is valid and belongs to `id`, and the node is confirmed.
fn confirm(view: &mut crate::View, id: NodeId, record: NodeRecord, now: u64) {
    if record.verify(now, &view.policy()).ok() == Some(id) {
        view.set_record(&id, record, now);
        view.confirm(&id, now);
    }
}

/// The first 8 characters of the base32 identifier: what the log shows.
pub fn short_id(id: &NodeId) -> String {
    id.to_string().chars().take(8).collect()
}

#[cfg(test)]
mod tests;
