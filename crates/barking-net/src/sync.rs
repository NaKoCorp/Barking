//! Full synchronization (spec §6), in this order, the state being saved
//! after each response so that a cut connection redoes nothing:
//!
//! 1. **View.** Expiry and score recovery; bootstrap when fewer than 3 nodes
//!    are reachable.
//! 2. **Session fetch.** Session mailboxes grouped by best responsible (the
//!    session splits each group into `Fetch` requests of 64 mailboxes at
//!    most), resumed from the positions per (node, mailbox). On a failure
//!    or a truncated fetch, the mailboxes concerned go to their next
//!    responsible. Loss audit (spec §5.1) on the way. Then cross-checks:
//!    each session mailbox served in full is read from the best other
//!    responsible every `CROSSCHECK_EVERY_SECS` per (node, mailbox).
//! 3. **Deposits**, following `plan_deposits`: receipts (no proof of work),
//!    first copies, resends, extra copies. Proof budget exhausted: messages
//!    wait, receipts go. `NotResponsible` from 2 responsibles of a mailbox:
//!    fallback lookup, then the plan is redone.
//! 4. **Introduction fetch**, within `INTRO_FETCH_BYTES` and
//!    `INTRO_FETCH_SLICE`; a partial one blocks nothing. Then a second
//!    deposit pass for receipts only (no proof of work), so that the
//!    receipts of first contacts leave in the same sync.
//! 5. **Maintenance**, with the time left: random lookups, candidate
//!    confirmation, fallback lookups while the view is small, then the node
//!    hints of my contact card. Skipped when nodes were tried and none
//!    answered (the client's own connection is down). Lookups never ask a
//!    node that failed, rate-limited or was cut short during this sync.
//! 6. **Wake subscriptions** (spec §5.2), with the time left: my mailboxes
//!    from today to `HORIZON_DAYS` ahead, planned by `plan_push` on the
//!    responsibles by score; unsubscribes first, then subscriptions, nearest
//!    day first, on the connections of the sync. A node that does not take
//!    wake-ups is left out (`PushState::note_no_wake`) and not replaced
//!    before the next sync; a rate limit or the end of the proof budget ends
//!    the stage. With push on, skipped while no view entry has a record (a
//!    cold start: no ranking to go by); with push off, the subscriptions are
//!    cancelled all the same, and those whose node could not be reached are
//!    kept, to be cancelled by a later sync. Skipped, like maintenance, when
//!    nodes were tried and none answered. The push state is saved after
//!    each response. Neither scores nor the transparency log are touched,
//!    and nothing about it is logged but local errors.
//! 7. `mark_polled` only if every session mailbox was fetched in full.
//!
//! **Score.** Successful requests +0.02, a failure −0.1 only once a node
//! other than the failed one answered during this sync (until then failures
//! wait; if none answers, the client's own connection is at fault). Only full dial timeouts count: a
//! lookup request or a candidate ping cut by the client's shorter caps is
//! neither a failure nor a success. A request that fails on a session kept
//! from an earlier one dials again once before the node fails (the session
//! may have died: idle timeout, cut connection); a fetch ended by a cut
//! connection leaves no session behind. `Found` at most once per node per
//! sync, at most one failure per node per sync. A fetch the node ended
//! badly (cut connection, paced pages: see `FetchStop::Paced`) or with a
//! rate limit is no successful request, and a page beyond `MAX_PAGE_ITEMS`
//! items fails the node. A node whose session fetches are all ended badly
//! for `UNAUDITED_SYNCS` syncs in a row cannot be audited: one failure per
//! sync from then on. Loss audits of
//! positioned mailboxes re-read them from their start every
//! `AUDIT_EVERY_SECS`, each in a call of its own once all regular session
//! fetches are over, within `REREAD_BYTES` and `REREAD_TIME`.
//!
//! **Network down.** While no node has answered, `DOWN_AFTER_FAILURES`
//! failed dials in a row, then one node added by hand or built-in not tried
//! yet failing too (or none left), end the sync: nothing lost, no score
//! lowered, no `mark_polled`. The nodes that failed then rank last for
//! `DOWN_FAILED_SECS`, so the next sync dials other nodes first.
//!
//! Nothing here logs an address or a mailbox: the transparency log gets the
//! short node id only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::mailbox::day_of;
use barking_core::transparency::{AvoidReason, TransparencyEvent};
use barking_core::{Core, CoreError, ReceiveOutcome};
use barking_dht::{BootstrapEntry, builtin_bootstrap};
use barking_packet::{MailboxId, Packet};
use barking_proto::pow::content_hash;
use barking_proto::{ErrorReason, NodeId, NodeRecord};
use tokio::time::Instant;

use crate::discover::{self, DialError, Dialer};
use crate::plan::{self, plan_deposits, record_outcome};
use crate::push::{HORIZON_DAYS, PushConfig, PushState, build_subscription, plan_push};
use crate::score::ScoreEvent;
use crate::state::NetState;
use crate::{BOOTSTRAP_VIEW, CandidateBudget};

mod fetch;
mod io;

pub use barking_proto::client::FetchStop;
pub use io::{
    Connector, DepositOutcome, DepositReply, Depositor, FetchReply, Fetcher, LinkPage,
    SubscribeReply, Subscriber,
};
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
/// Longest ping of a candidate: running out of it is neither a failure nor
/// a success for the node.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);
/// Reachable nodes below which the sync bootstraps first.
pub const MIN_REACHABLE: usize = 3;
/// Syncs in a row in which a node answered but none of its session fetches
/// completed, the connection being cut or the pages paced (never a rate
/// limit, a client cap or the client's own deadline or slice), after which
/// it gets one failure per
/// sync: it cannot be audited for losses.
pub const UNAUDITED_SYNCS: u32 = 3;
/// A positioned mailbox holding a message the node accepted is read again
/// from its start, for a loss audit, at most this often: in a call of its
/// own, once all regular session fetches are over.
pub const AUDIT_EVERY_SECS: u64 = 6 * 3600;
/// A session mailbox fetched in full from one responsible is also read, at
/// most this often per (node, mailbox), from the best other responsible:
/// a responsible that answers but keeps nothing is never left otherwise.
pub const CROSSCHECK_EVERY_SECS: u64 = 6 * 3600;
/// Dials failed or timed out in a row, no node having answered yet in the
/// sync, after which the network is taken as down and the sync ends.
pub const DOWN_AFTER_FAILURES: u32 = 3;
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
pub const TRANSPORT: &str = "node";

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
    /// Wake-up settings; `None`: push off (subscriptions held are cancelled).
    pub push: Option<PushConfig>,
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
            push: None,
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
    /// Local error that stopped the sync (the network state or the watch
    /// list could not be read).
    pub error: Option<String>,
    /// The stored network state was unreadable and replaced by an empty one
    /// (nodes added by hand included): worth telling the user.
    pub state_reset: bool,
    /// The network state could not be saved at least once during the sync.
    pub state_unsaved: bool,
    /// Wake subscriptions accepted by a node.
    pub subscribed: usize,
    /// Wake subscriptions cancelled.
    pub unsubscribed: usize,
}

/// Synchronizes with the network (see the module documentation).
pub async fn sync<D>(core: &mut Core, dialer: &D, opts: SyncOptions) -> SyncReport
where
    D: Dialer + Depositor + Fetcher + Subscriber + Sync,
{
    let now = opts.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    let deadline = Instant::now() + opts.deadline;
    let (state, state_reset) = match NetState::load_checked(core, now, opts.allow_private) {
        Ok(s) => s,
        Err(e) => {
            return SyncReport {
                error: Some(e.to_string()),
                ..SyncReport::default()
            };
        }
    };
    let mut run = Run::new(core, dialer, state, now, deadline, opts.pow_budget);
    run.report.state_reset = state_reset;
    run.run(&opts).await;
    run.finish().await
}

impl<'a, D: Connector> Run<'a, D> {
    fn new(
        core: &'a mut Core,
        dialer: &'a D,
        state: NetState,
        now: u64,
        deadline: Instant,
        pow_budget: u64,
    ) -> Self {
        Run {
            core,
            dialer,
            state,
            conns: HashMap::new(),
            failed: HashSet::new(),
            limited: HashSet::new(),
            cut: HashSet::new(),
            unused: HashSet::new(),
            answerers: HashSet::new(),
            dial_failed: HashSet::new(),
            pending_failures: Vec::new(),
            penalized: HashSet::new(),
            found: HashSet::new(),
            tried: false,
            dial_failures: 0,
            down: false,
            seeds: Vec::new(),
            dialed: HashSet::new(),
            probed: false,
            reread_queue: Vec::new(),
            page_confirmed: HashSet::new(),
            budget: CandidateBudget::default(),
            now,
            deadline,
            pow_left: pow_budget,
            stats: BTreeMap::new(),
            report: SyncReport::default(),
        }
    }
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
    /// Kept connections on which no request was made yet (the seed probe's).
    unused: HashSet<NodeId>,
    /// Nodes that answered during this sync (refusals included).
    answerers: HashSet<NodeId>,
    /// Nodes whose dial failed or timed out this sync: those a network-down
    /// sync remembers (`NetState::down_failed`).
    dial_failed: HashSet<NodeId>,
    /// Nodes that failed (connection, timeout, protocol) during this sync.
    failed: HashSet<NodeId>,
    /// Nodes that answered `RateLimited`: nothing more asked this sync.
    limited: HashSet<NodeId>,
    /// Nodes whose lookup request or candidate ping was cut by a client cap
    /// shorter than the dial timeout: not asked again by lookups this sync,
    /// but neither failed nor scored (a slow link is not a dead node).
    cut: HashSet<NodeId>,
    /// Failures waiting for a node other than theirs to answer.
    pending_failures: Vec<NodeId>,
    /// Nodes that already took (or wait for) their failure this sync.
    penalized: HashSet<NodeId>,
    /// Nodes that already got `Found` this sync.
    found: HashSet<NodeId>,
    /// Some node was dialled during this sync.
    tried: bool,
    /// Failures in a row while no node has answered yet.
    dial_failures: u32,
    /// `DOWN_AFTER_FAILURES` reached and the seed probe failed: the network
    /// is down, the sync ends.
    down: bool,
    /// Nodes added by hand and built-in entries: one not tried yet is dialled
    /// before the network is taken as down.
    seeds: Vec<(NodeId, Vec<SocketAddr>)>,
    /// Nodes dialled during this sync.
    dialed: HashSet<NodeId>,
    /// The seed probe ran.
    probed: bool,
    /// Groups served by a node this sync, for the audit re-reads.
    reread_queue: Vec<(NodeId, Vec<MailboxId>)>,
    /// Nodes whose carried page size a page timeout confirmed this sync:
    /// the others' grows back (`NetState::recover_page_bytes`).
    page_confirmed: HashSet<NodeId>,
    budget: CandidateBudget,
    now: u64,
    deadline: Instant,
    pow_left: u64,
    stats: BTreeMap<[u8; 32], (NodeId, NodeStats)>,
    report: SyncReport,
}

impl<D> Run<'_, D>
where
    D: Dialer + Depositor + Fetcher + Subscriber + Sync,
{
    async fn run(&mut self, opts: &SyncOptions) {
        let now = self.now;
        for &(id, addr) in &opts.manual_nodes {
            self.state.view.add_manual(id, addr, now);
        }
        self.state.view.expire(now);
        self.state.view.decay_scores(now);
        self.state.fallbacks.prune(now);
        self.state.prune_down_failed(now);
        self.save();
        let mut seeds: Vec<(NodeId, Vec<SocketAddr>)> = self
            .state
            .view
            .entries()
            .filter(|(_, e)| e.manual)
            .map(|(id, e)| (*id, e.addrs()))
            .collect();
        seeds.sort_unstable_by_key(|(id, _)| id.0);
        for b in &opts.builtin {
            if !seeds.iter().any(|(id, _)| *id == b.id) {
                seeds.push((b.id, vec![b.addr]));
            }
        }
        self.seeds = seeds;

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

        // A store read error aborts the sync: polling a partial list, then
        // `mark_polled`, would skip unread session mailboxes for good.
        let groups = match self.core.watched_mailbox_groups(now) {
            Ok(g) => g,
            Err(e) => {
                self.report.error = Some(e.to_string());
                return;
            }
        };
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

        self.deposit_stage(false).await;

        if !intro.is_empty() {
            let polled_intro = self.fetch_stage(&intro, true).await;
            self.report.intro_partial = !polled_intro;
            // Receipts of what the introductions brought.
            if !self.over() {
                self.deposit_stage(true).await;
            }
        }

        // Nodes tried and none answered: lookups would only dial dead ends.
        if !self.over() && (self.network_up() || !self.tried) {
            self.maintenance(&sessions, &intro).await;
        }

        if !self.over() && (self.network_up() || !self.tried) {
            self.push_stage(opts.push.as_ref()).await;
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
        if self.down {
            let failed: Vec<NodeId> = self.dial_failed.iter().copied().collect();
            self.state.note_down_failures(failed, self.now);
        }
        self.state.recover_page_bytes(&self.page_confirmed);
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

    /// The deadline passed, or the network is down.
    fn over(&self) -> bool {
        self.down || Instant::now() >= self.deadline
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
            self.report.state_unsaved = true;
        }
    }

    fn stats(&mut self, id: NodeId) -> &mut NodeStats {
        &mut self
            .stats
            .entry(id.0)
            .or_insert_with(|| (id, NodeStats::default()))
            .1
    }

    /// `id` answered (a refusal included): the network is up, and the
    /// failures waiting for a node other than theirs to answer count now.
    fn answered(&mut self, id: NodeId) {
        self.report.network_up = true;
        if !self.answerers.insert(id) || self.pending_failures.is_empty() {
            return;
        }
        for f in std::mem::take(&mut self.pending_failures) {
            if self.other_answered(f) {
                self.apply(f, ScoreEvent::Failure);
            } else {
                self.pending_failures.push(f);
            }
        }
    }

    /// A node other than `id` answered during this sync (spec §5.1: a
    /// failure counts only then; the only node that answers is not blamed
    /// for its own later timeout).
    fn other_answered(&self, id: NodeId) -> bool {
        self.answerers.iter().any(|a| *a != id)
    }

    /// Applies a score event. A node takes at most one failure per sync,
    /// whatever failed (fetch, deposit, lookup, ping, audit); a failure
    /// waits until another node answered.
    fn score(&mut self, id: NodeId, event: ScoreEvent) {
        if matches!(event, ScoreEvent::Success | ScoreEvent::Found) {
            self.state.down_failed.remove(&id);
        }
        if event == ScoreEvent::Failure {
            if !self.penalized.insert(id) {
                return;
            }
            if !self.other_answered(id) {
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

    /// A dial to `id` failed or timed out: `fail`, and remembered for
    /// `note_down_failures` should the network turn out to be down.
    fn fail_dial(&mut self, id: NodeId) {
        self.dial_failed.insert(id);
        self.fail(id);
    }

    /// A node failed (connection, timeout, invalid answer); while no node
    /// has answered, failures are counted for `confirm_down`.
    fn fail(&mut self, id: NodeId) {
        self.failed.insert(id);
        self.conns.remove(&id);
        self.unused.remove(&id);
        self.score(id, ScoreEvent::Failure);
        if !self.report.network_up {
            self.dial_failures = self.dial_failures.saturating_add(1);
        }
    }

    /// While no node has answered and `DOWN_AFTER_FAILURES` dials failed:
    /// one node added by hand or built-in, not tried yet, is dialled. If it
    /// answers the sync goes on; otherwise (or with none left) the network
    /// is down and the sync ends.
    async fn confirm_down(&mut self) {
        if self.down || self.report.network_up || self.dial_failures < DOWN_AFTER_FAILURES {
            return;
        }
        if self.probed {
            self.down = true;
            return;
        }
        self.probed = true;
        let candidate = self
            .seeds
            .iter()
            .find(|(id, _)| !self.dialed.contains(id) && !self.failed.contains(id))
            .cloned();
        let Some((id, addrs)) = candidate else {
            self.down = true;
            return;
        };
        self.dialed.insert(id);
        self.tried = true;
        match tokio::time::timeout_at(self.deadline, self.dialer.connect(id, &addrs)).await {
            Ok(Ok(conn)) => {
                self.answered(id);
                self.state.view.confirm(&id, self.now);
                self.conns.insert(id, conn);
                self.unused.insert(id);
            }
            Ok(Err(DialError::Refused(_))) => {
                self.answered(id);
                self.failed.insert(id);
            }
            Ok(Err(DialError::NoAddress)) => {
                self.failed.insert(id);
                self.down = true;
            }
            Ok(Err(_)) => {
                self.failed.insert(id);
                self.dial_failed.insert(id);
                self.down = true;
            }
            // The sync's own deadline cut the probe: nothing proven, the
            // sync ends without taking the network as down.
            Err(_) => {}
        }
    }

    /// Outcomes of the lookups and pings made through `observed`. A node
    /// that failed (timeouts included) is not dialled again this sync.
    fn apply_observed(&mut self, observed: Observed<'_, D>) {
        let outcomes = observed.outcomes.into_inner().unwrap_or_default();
        if !outcomes.is_empty() {
            self.tried = true;
        }
        for (id, o) in &outcomes {
            if matches!(o, Observation::Answered | Observation::Refused) {
                self.answered(*id);
            }
        }
        for (id, o) in outcomes {
            match o {
                Observation::Answered => self.score(id, ScoreEvent::Success),
                Observation::Refused => {}
                Observation::Failed => self.fail_dial(id),
                Observation::Cut => {
                    self.cut.insert(id);
                }
            }
        }
    }

    /// Nodes not to ask again this sync: failed or rate-limited.
    fn excluded(&self) -> HashSet<NodeId> {
        self.failed.union(&self.limited).copied().collect()
    }

    /// Nodes lookups and candidate pings leave out: `excluded`, plus those
    /// cut short by a lookup or ping cap this sync.
    fn lookup_excluded(&self) -> HashSet<NodeId> {
        let mut out = self.excluded();
        out.extend(self.cut.iter().copied());
        out
    }

    /// The kept connection to `id`, or a new one, and whether it was just
    /// opened (no request made on it yet). `None` if the node cannot be
    /// reached (it is then marked failed) or the deadline is over.
    async fn take_conn(&mut self, id: NodeId) -> Option<(D::Conn, bool)> {
        if let Some(c) = self.conns.remove(&id) {
            return Some((c, self.unused.remove(&id)));
        }
        self.confirm_down().await;
        if self.down || self.failed.contains(&id) || self.limited.contains(&id) {
            return None;
        }
        // The seed probe may have opened it.
        if let Some(c) = self.conns.remove(&id) {
            return Some((c, self.unused.remove(&id)));
        }
        let addrs = self
            .state
            .view
            .get(&id)
            .map(|e| e.addrs())
            .unwrap_or_default();
        // Nothing to dial: not a try, and nothing the node can be blamed for.
        if addrs.is_empty() {
            self.failed.insert(id);
            return None;
        }
        self.dialed.insert(id);
        let dial = tokio::time::timeout_at(self.deadline, self.dialer.connect(id, &addrs)).await;
        if !matches!(dial, Ok(Err(DialError::NoAddress))) {
            self.tried = true;
        }
        match dial {
            Err(_) => None,
            Ok(Ok(conn)) => {
                self.answered(id);
                // A pinned handshake proves the node.
                self.state.view.confirm(&id, self.now);
                Some((conn, true))
            }
            // A refusal proves the network is up; the node is neutral.
            Ok(Err(DialError::Refused(_))) => {
                self.answered(id);
                self.failed.insert(id);
                None
            }
            Ok(Err(DialError::NoAddress)) => {
                self.failed.insert(id);
                None
            }
            Ok(Err(_)) => {
                self.fail_dial(id);
                self.confirm_down().await;
                None
            }
        }
    }

    /// Deposits the send queue following `plan_deposits`, redoing the plan
    /// when a node drops out (failure, rate limit) or a fallback lookup
    /// enriched the view. `acks_only`: receipts only (the pass after the
    /// introduction fetch).
    async fn deposit_stage(&mut self, acks_only: bool) {
        let now = self.now;
        let Ok(outbox) = self.core.pending_outbox(now) else {
            return;
        };
        plan::prune(&mut self.state.ledger, &outbox, now);
        let mut pow_exhausted = false;
        let mut not_responsible: HashMap<MailboxId, HashSet<NodeId>> = HashMap::new();
        let mut fallback_tried: HashSet<MailboxId> = HashSet::new();
        'plan: loop {
            let excluded = self.excluded();
            let st = &self.state;
            let deposits = plan_deposits(
                &outbox,
                &self.state.ledger,
                |m| {
                    st.order_responsibles(st.view.responsibles_by_score(m, now))
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
                if !d.is_ack && (pow_exhausted || acks_only) {
                    continue;
                }
                // A kept session may have died since its last request (cut
                // connection, idle timeout): one new dial before the node
                // is failed.
                let mut redialled = false;
                let (conn, reply) = loop {
                    let Some((mut conn, fresh)) = self.take_conn(d.node).await else {
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
                    match &reply.outcome {
                        Err(e) if !fresh && !redialled && dead_session(e) => redialled = true,
                        _ => break (conn, reply),
                    }
                };
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
                self.answered(d.node);
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
        let exclude = self.lookup_excluded();
        let observed = Observed::new(self.dialer);
        let lookup = discover::fallback_lookup(
            &mut self.state.view,
            &observed,
            &exclude,
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
        // One lookup at a time: a node that failed in one is not asked by
        // the next.
        for _ in 0..count {
            if self.over() {
                break;
            }
            let exclude = self.lookup_excluded();
            let observed = Observed::new(self.dialer);
            let lookups = discover::random_lookups(
                &mut self.state.view,
                &observed,
                &exclude,
                1,
                &mut rng,
                &mut self.budget,
                now,
            );
            let _ = tokio::time::timeout_at(self.deadline, lookups).await;
            self.apply_observed(observed);
        }
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
        let exclude = self.lookup_excluded();
        let mut candidates: Vec<(NodeId, u64, Vec<SocketAddr>)> = self
            .state
            .view
            .entries()
            .filter(|(id, e)| {
                !e.confirmed && e.record.is_some() && !e.avoided(now) && !exclude.contains(id)
            })
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
            match tokio::time::timeout_at(end, observed.ping(id, &addrs)).await {
                Ok(Ok(record)) => {
                    // A record that is not its own (or not valid): no
                    // successful request.
                    if !confirm(&mut self.state.view, id, record, now) {
                        observed.retract(id);
                    }
                }
                Ok(Err(_)) => {}
                // A cap of the client's, shorter than the dial timeout.
                Err(_) => observed.cut_short(id),
            }
        }
        self.apply_observed(observed);
        self.save();
    }
}

impl<D> Run<'_, D>
where
    D: Dialer + Depositor + Fetcher + Subscriber + Sync,
{
    /// Wake subscriptions (stage 6 of the module documentation).
    async fn push_stage(&mut self, cfg: Option<&PushConfig>) {
        let now = self.now;
        // Cold start: without a single record there is no responsible to
        // rank, and a new configuration would cancel everything for nothing.
        if cfg.is_some() && !self.state.view.entries().any(|(_, e)| e.record.is_some()) {
            return;
        }
        let mut push = match PushState::load(self.core) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("push state not read, wake subscriptions left as they are: {e}");
                return;
            }
        };
        let loaded = push.clone();
        let wanted = match cfg {
            Some(_) => {
                let today = day_of(now);
                let days: Vec<u32> = (today..=today.saturating_add(HORIZON_DAYS)).collect();
                match self.core.own_mailboxes(&days) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!("own mailboxes not read, wake subscriptions skipped: {e}");
                        return;
                    }
                }
            }
            None => Vec::new(),
        };
        let view = &self.state.view;
        let plan = plan_push(
            &push,
            cfg,
            &wanted,
            |m| view.responsibles_by_score(m, now),
            now,
        );
        // Push off or a new configuration: every stored subscription is
        // cancelled, then the state starts afresh.
        let reset = push.config_hash != cfg.map(PushState::config_hash_of);
        let mut skipped: HashSet<NodeId> = HashSet::new();
        let Some(all_sent) = self
            .push_unsubscribes(&mut push, &plan.unsubscribe, &mut skipped)
            .await
        else {
            return;
        };
        // Stopped half-way: the next sync plans the rest from what is left.
        if all_sent {
            if cfg.is_none() {
                // Push off: what is left could not be cancelled (node not
                // reached); kept for a later sync unless already expired.
                let today = day_of(now);
                push.config_hash = None;
                push.subs
                    .retain(|_, b| !b.nodes.is_empty() && b.day.saturating_add(1) >= today);
            } else if reset {
                push.apply_config(cfg);
            } else {
                for m in &plan.forget {
                    push.subs.remove(m);
                }
            }
        }
        if push != loaded && !self.save_push(&push) {
            return;
        }
        let (Some(cfg), true) = (cfg, all_sent) else {
            return;
        };
        let days: HashMap<MailboxId, u32> = wanted.iter().copied().collect();
        'stage: for (mailbox, node) in plan.subscribe {
            if self.over() {
                break;
            }
            let left_out = push.no_wake.get(&node).is_some_and(|until| *until > now);
            let Some(&day) = days.get(&mailbox) else {
                continue;
            };
            if left_out || skipped.contains(&node) {
                continue;
            }
            let mut redialled = false;
            let outcome = loop {
                let Some((mut conn, fresh)) = self.push_conn(node, &skipped).await else {
                    if !self.over() {
                        skipped.insert(node);
                    }
                    continue 'stage;
                };
                if !self.dialer.wake_supported(&conn) {
                    self.conns.insert(node, conn);
                    break None;
                }
                let collapse = push.collapse_for(mailbox, day, &mut rand::rng());
                let (sub, secret) =
                    build_subscription(cfg, mailbox, day, collapse, &mut rand::rng());
                let request = self.dialer.subscribe(&mut conn, &sub, self.pow_left);
                let Ok(reply) = tokio::time::timeout_at(self.deadline, request).await else {
                    break 'stage;
                };
                self.pow_left = self.pow_left.saturating_sub(reply.pow_spent);
                match reply.outcome {
                    Err(e) if !fresh && !redialled && dead_session(&e) => redialled = true,
                    Err(_) => {
                        skipped.insert(node);
                        continue 'stage;
                    }
                    Ok(outcome) => {
                        self.conns.insert(node, conn);
                        break Some((outcome, secret));
                    }
                }
            };
            let mut stop = false;
            match outcome {
                // No wake support announced.
                None => push.note_no_wake(node, now),
                Some((DepositOutcome::Answered(Ok(())), secret)) => {
                    push.note_subscribed(mailbox, day, node, secret, &mut rand::rng());
                    self.report.subscribed += 1;
                }
                Some((DepositOutcome::Answered(Err(ErrorReason::Unsupported)), _)) => {
                    push.note_no_wake(node, now);
                }
                Some((DepositOutcome::Answered(Err(ErrorReason::RateLimited)), _))
                | Some((DepositOutcome::PowBudget, _)) => stop = true,
                // Any other refusal: this mailbox on this node waits for the
                // next sync.
                Some((DepositOutcome::Answered(Err(_)), _)) => {}
            }
            if !self.save_push(&push) || stop {
                break;
            }
        }
    }

    /// Sends the unsubscribes of the plan, saving the push state after each
    /// response. `Some(true)`: every one was sent (or its node could not be
    /// reached); `Some(false)`: stopped by a rate limit or the deadline;
    /// `None`: the state could not be saved.
    async fn push_unsubscribes(
        &mut self,
        push: &mut PushState,
        list: &[(MailboxId, NodeId, [u8; 32])],
        skipped: &mut HashSet<NodeId>,
    ) -> Option<bool> {
        'list: for &(mailbox, node, secret) in list {
            if self.over() {
                return Some(false);
            }
            if skipped.contains(&node) {
                continue;
            }
            let mut redialled = false;
            let result = loop {
                let Some((mut conn, fresh)) = self.push_conn(node, skipped).await else {
                    if self.over() {
                        return Some(false);
                    }
                    skipped.insert(node);
                    continue 'list;
                };
                let request = self.dialer.unsubscribe(&mut conn, mailbox, secret);
                let Ok(result) = tokio::time::timeout_at(self.deadline, request).await else {
                    return Some(false);
                };
                match result {
                    Err(e) if !fresh && !redialled && dead_session(&e) => redialled = true,
                    Ok(()) | Err(DialError::Refused(_)) => {
                        self.conns.insert(node, conn);
                        break result;
                    }
                    Err(_) => {
                        skipped.insert(node);
                        continue 'list;
                    }
                }
            };
            match result {
                Err(DialError::Refused(ErrorReason::RateLimited)) => {
                    return Some(false);
                }
                Ok(()) => {
                    push.note_unsubscribed(&mailbox, &node);
                    self.report.unsubscribed += 1;
                }
                // Any other refusal: nothing left to cancel there.
                Err(_) => push.note_unsubscribed(&mailbox, &node),
            }
            if !self.save_push(push) {
                return None;
            }
        }
        Some(true)
    }

    /// The kept connection to `id`, or a new one, and whether it was just
    /// opened. Unlike `take_conn`, nothing here touches the scores: `None`
    /// when the node failed or was rate-limited this sync, is in `skipped`,
    /// cannot be dialled, or the deadline is over.
    async fn push_conn(
        &mut self,
        id: NodeId,
        skipped: &HashSet<NodeId>,
    ) -> Option<(D::Conn, bool)> {
        if self.over()
            || skipped.contains(&id)
            || self.failed.contains(&id)
            || self.limited.contains(&id)
        {
            return None;
        }
        if let Some(c) = self.conns.remove(&id) {
            return Some((c, self.unused.remove(&id)));
        }
        let addrs = self
            .state
            .view
            .get(&id)
            .map(|e| e.addrs())
            .unwrap_or_default();
        if addrs.is_empty() {
            return None;
        }
        match tokio::time::timeout_at(self.deadline, self.dialer.connect(id, &addrs)).await {
            Ok(Ok(conn)) => Some((conn, true)),
            _ => None,
        }
    }

    /// Saves the push state; false (and a warning) on failure: the stage
    /// must then stop, a subscription whose secret is not kept could never
    /// be cancelled.
    fn save_push(&mut self, push: &PushState) -> bool {
        match push.save(self.core) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("push state not saved, wake subscriptions stopped: {e}");
                false
            }
        }
    }
}

/// A failure that a session kept from an earlier request may owe to its own
/// death rather than to the node: worth one new dial.
fn dead_session(e: &DialError) -> bool {
    matches!(e, DialError::Unreachable | DialError::Timeout)
}

/// `id` answered a ping pinned on it with `record`: the record is kept if
/// it is valid and belongs to `id`, and the node is confirmed. False if
/// the record was refused.
fn confirm(view: &mut crate::View, id: NodeId, record: NodeRecord, now: u64) -> bool {
    if record.verify(now, &view.policy()).ok() != Some(id) {
        return false;
    }
    view.set_record(&id, record, now);
    view.confirm(&id, now);
    true
}

/// The first 8 characters of the base32 identifier: what the log shows.
pub fn short_id(id: &NodeId) -> String {
    id.to_string().chars().take(8).collect()
}

#[cfg(test)]
mod tests;
