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
//! sync. A node whose session fetch never completes for `UNAUDITED_SYNCS`
//! syncs in a row cannot be audited: one failure per sync from then on.
//!
//! Nothing here logs an address or a mailbox: the transparency log gets the
//! short node id only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::transparency::{AvoidReason, TransparencyEvent};
use barking_core::{Core, CoreError, ReceiveOutcome};
use barking_dht::{BootstrapEntry, builtin_bootstrap};
use barking_packet::{MailboxId, Packet};
use barking_proto::client::{Client, ClientError, FetchResume, MAX_FETCH_BYTES, Session};
use barking_proto::pow::content_hash;
use barking_proto::{ErrorReason, NodeId, NodeRecord};
use tokio::time::Instant;

use crate::discover::{self, DIAL_TIMEOUT, DialError, Dialer, QuicDialer, dial_error};
use crate::plan::{self, detect_losses, found_messages, plan_deposits, record_outcome};
use crate::score::ScoreEvent;
use crate::state::NetState;
use crate::{BOOTSTRAP_VIEW, CandidateBudget};

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
/// Syncs in a row without a complete session fetch after which a node gets
/// one failure per sync (it cannot be audited for losses).
pub const UNAUDITED_SYNCS: u32 = 3;
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

/// Answer to a fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchReply {
    /// Items, and whether the fetch ran to the end.
    Items { items: Vec<Vec<u8>>, complete: bool },
    /// Rate limit exhausted before the first page.
    RateLimited,
}

/// What happened to a deposit that reached the node or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositOutcome {
    /// The node answered: accepted or refused.
    Answered(Result<(), ErrorReason>),
    /// Proof-of-work budget exhausted: nothing sent.
    PowBudget,
}

/// Answer to a deposit, with the proof work it spent (even on failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositReply {
    pub outcome: Result<DepositOutcome, DialError>,
    pub pow_spent: u64,
}

/// A connection to a node kept for the whole sync.
pub trait Connector {
    type Conn: Send;

    /// Connects pinned on `id` and says `Hello`: a success proves the node.
    fn connect(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<Self::Conn, DialError>> + Send;

    fn close(&self, conn: Self::Conn) -> impl Future<Output = ()> + Send;
}

/// Fetches on a kept connection (see `Session::fetch_resumable`).
pub trait Fetcher: Connector {
    /// Fetches `mailboxes` from `resume`, at most `max_bytes` bytes and
    /// `slice` long; `resume` gives where to resume afterwards.
    fn fetch(
        &self,
        conn: &mut Self::Conn,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
        slice: Duration,
    ) -> impl Future<Output = Result<FetchReply, DialError>> + Send;
}

/// Deposits on a kept connection (see `Session::deposit`).
pub trait Depositor: Connector {
    /// Deposits `packet`, spending at most `pow_left` proof work.
    fn deposit(
        &self,
        conn: &mut Self::Conn,
        packet: &[u8],
        pow_left: u64,
    ) -> impl Future<Output = DepositReply> + Send;
}

impl Connector for QuicDialer {
    type Conn = Session;

    async fn connect(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Session, DialError> {
        let mut last = DialError::NoAddress;
        for &addr in addrs {
            match tokio::time::timeout(DIAL_TIMEOUT, Client::connect(addr, id)).await {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(e)) => last = dial_error(e),
                Err(_) => last = DialError::Timeout,
            }
        }
        Err(last)
    }

    async fn close(&self, conn: Session) {
        conn.close().await;
    }
}

impl Fetcher for QuicDialer {
    async fn fetch(
        &self,
        conn: &mut Session,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
        slice: Duration,
    ) -> Result<FetchReply, DialError> {
        if mailboxes.is_empty() {
            return Ok(FetchReply::Items {
                items: Vec::new(),
                complete: true,
            });
        }
        conn.set_fetch_deadline(slice);
        match conn.fetch_resumable(mailboxes, resume, max_bytes).await {
            Ok(items) => Ok(FetchReply::Items {
                items,
                complete: !conn.last_fetch_truncated(),
            }),
            Err(ClientError::Refused(ErrorReason::RateLimited)) => Ok(FetchReply::RateLimited),
            Err(e) => Err(dial_error(e)),
        }
    }
}

impl Depositor for QuicDialer {
    async fn deposit(&self, conn: &mut Session, packet: &[u8], pow_left: u64) -> DepositReply {
        let before = conn.pow_spent();
        conn.set_pow_budget(Some(before.saturating_add(pow_left)));
        let outcome = match conn.deposit(packet).await {
            Ok(result) => Ok(DepositOutcome::Answered(result)),
            Err(ClientError::PowBudget) => Ok(DepositOutcome::PowBudget),
            Err(e) => Err(dial_error(e)),
        };
        DepositReply {
            outcome,
            pow_spent: conn.pow_spent().saturating_sub(before),
        }
    }
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
        found: HashSet::new(),
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

/// How one group fetch ended.
enum GroupEnd {
    /// Fetched in full.
    Complete,
    /// Failed, refused, rate limited or truncated: try the next responsible.
    Incomplete { truncated: bool },
    /// Deadline or slice over: stop the stage.
    Stop,
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
    /// Nodes that already got `Found` this sync.
    found: HashSet<NodeId>,
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
                self.score(id, ScoreEvent::Failure);
            }
        }
    }

    /// Applies a score event; a failure waits until some node answered.
    fn score(&mut self, id: NodeId, event: ScoreEvent) {
        if event == ScoreEvent::Failure && !self.report.network_up {
            self.pending_failures.push(id);
            return;
        }
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

    /// Fetches `mailboxes`, grouped by best responsible, moving the
    /// mailboxes of a failed or truncated group to their next responsible
    /// (introductions: on failure only). Returns true if every mailbox was
    /// fetched in full and processed.
    async fn fetch_stage(&mut self, mailboxes: &[MailboxId], intro: bool) -> bool {
        let now = self.now;
        let slice = if intro {
            intro_slice()
        } else {
            SESSION_FETCH_SLICE
        };
        let slice_end = (Instant::now() + slice).min(self.deadline);
        let ranked: HashMap<MailboxId, Vec<NodeId>> = mailboxes
            .iter()
            .map(|m| (*m, self.state.view.responsibles_by_score(m, now)))
            .collect();
        // Next responsible to try, by mailbox; `None`: given up.
        let mut next: HashMap<MailboxId, Option<usize>> =
            mailboxes.iter().map(|m| (*m, Some(0))).collect();
        let mut done: HashSet<MailboxId> = HashSet::new();
        let mut all_processed = true;
        let mut bytes_left = if intro {
            INTRO_FETCH_BYTES
        } else {
            MAX_FETCH_BYTES
        };
        // Per node: did all its session fetches of this sync complete?
        let mut complete_by_node: HashMap<NodeId, bool> = HashMap::new();
        'rounds: loop {
            let mut groups: BTreeMap<[u8; 32], (NodeId, Vec<MailboxId>)> = BTreeMap::new();
            for m in mailboxes {
                if done.contains(m) {
                    continue;
                }
                let Some(Some(from)) = next.get(m).copied() else {
                    continue;
                };
                let list = &ranked[m];
                let pick = (from..list.len())
                    .find(|&i| !self.failed.contains(&list[i]) && !self.limited.contains(&list[i]));
                next.insert(*m, pick);
                if let Some(i) = pick {
                    groups
                        .entry(list[i].0)
                        .or_insert_with(|| (list[i], Vec::new()))
                        .1
                        .push(*m);
                }
            }
            if groups.is_empty() {
                break;
            }
            for (_, (node, group)) in groups {
                if Instant::now() >= slice_end || (intro && bytes_left == 0) {
                    break 'rounds;
                }
                let max_bytes = if intro { bytes_left } else { MAX_FETCH_BYTES };
                let (end, bytes, processed) = self
                    .fetch_group(node, &group, intro, max_bytes, slice_end)
                    .await;
                bytes_left = bytes_left.saturating_sub(bytes);
                all_processed &= processed;
                match end {
                    GroupEnd::Complete => {
                        complete_by_node.entry(node).or_insert(true);
                        done.extend(group.iter().copied());
                        self.report.mailboxes_polled += group.len();
                    }
                    GroupEnd::Incomplete { truncated } => {
                        // Only a node that answered without completing
                        // escapes the audit; a dead one already failed.
                        if truncated {
                            complete_by_node.insert(node, false);
                        }
                        for m in &group {
                            let step = if intro && truncated {
                                // A flooded introduction mailbox is not
                                // worth fetching twice.
                                None
                            } else {
                                next[m].map(|i| i + 1)
                            };
                            next.insert(*m, step);
                        }
                    }
                    GroupEnd::Stop => {
                        break 'rounds;
                    }
                }
            }
        }
        if !intro {
            self.note_audits(complete_by_node);
        }
        all_processed && mailboxes.iter().all(|m| done.contains(m))
    }

    /// Counts the syncs in which a node's session fetch never completed;
    /// from `UNAUDITED_SYNCS` on, one failure per sync.
    fn note_audits(&mut self, complete_by_node: HashMap<NodeId, bool>) {
        for (node, complete) in complete_by_node {
            if complete {
                self.state.unaudited.remove(&node);
                continue;
            }
            let count = self.state.unaudited.entry(node).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= UNAUDITED_SYNCS {
                self.score(node, ScoreEvent::Failure);
            }
        }
        self.save();
    }

    /// One fetch of `group` from `node`. Returns how it ended, the bytes
    /// received and whether every item was processed.
    async fn fetch_group(
        &mut self,
        node: NodeId,
        group: &[MailboxId],
        intro: bool,
        max_bytes: usize,
        slice_end: Instant,
    ) -> (GroupEnd, usize, bool) {
        let Some(mut conn) = self.take_conn(node).await else {
            let end = if self.over() {
                GroupEnd::Stop
            } else {
                GroupEnd::Incomplete { truncated: false }
            };
            return (end, 0, true);
        };
        let mut resume = self.state.resume(&node, group);
        // Mailboxes read from their very start: the only ones a loss audit
        // may rely on (a resumed fetch skips the items already seen).
        let from_start: Vec<MailboxId> = group
            .iter()
            .filter(|m| resume.seen.get(&m.0).copied().unwrap_or(0) == 0)
            .copied()
            .collect();
        let slice = slice_end.saturating_duration_since(Instant::now());
        let fetch = self
            .dialer
            .fetch(&mut conn, group, &mut resume, max_bytes, slice);
        let reply = match tokio::time::timeout_at(self.deadline, fetch).await {
            Err(_) => return (GroupEnd::Stop, 0, true),
            Ok(r) => r,
        };
        let (items, complete) = match reply {
            Ok(FetchReply::Items { items, complete }) => (items, complete),
            Ok(FetchReply::RateLimited) | Err(DialError::Refused(ErrorReason::RateLimited)) => {
                self.answered();
                self.limited.insert(node);
                self.conns.insert(node, conn);
                return (GroupEnd::Incomplete { truncated: true }, 0, true);
            }
            Err(DialError::Refused(_)) => {
                self.answered();
                self.conns.insert(node, conn);
                return (GroupEnd::Incomplete { truncated: false }, 0, true);
            }
            Err(_) => {
                self.fail(node);
                return (GroupEnd::Incomplete { truncated: false }, 0, true);
            }
        };
        self.answered();
        self.score(node, ScoreEvent::Success);
        self.conns.insert(node, conn);
        let bytes = items
            .iter()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add);
        let mut received = Vec::new();
        let mut errors = 0;
        let processed = receive_all(self.core, &items, self.now, |r| match r {
            Ok(o) => received.push(o),
            Err(_) => errors += 1,
        });
        self.report.received.append(&mut received);
        self.report.receive_errors += errors;
        self.report.items_received += items.len();
        if processed {
            self.state.set_positions(&node, group, &resume);
        }
        if !intro {
            self.audit(node, &items, if complete { &from_start } else { &[] });
        }
        let s = self.stats(node);
        s.fetched = true;
        s.mailboxes = s
            .mailboxes
            .saturating_add(u32::try_from(group.len()).unwrap_or(u32::MAX));
        s.received = s
            .received
            .saturating_add(u32::try_from(items.len()).unwrap_or(u32::MAX));
        self.save();
        let end = if complete {
            GroupEnd::Complete
        } else {
            GroupEnd::Incomplete { truncated: true }
        };
        (end, bytes, processed)
    }

    /// Loss audit of a session fetch from `node`: `audited` are the
    /// mailboxes read in full from their start. The send queue is read after
    /// the items were processed, so that receipts just fetched took their
    /// messages out of it.
    fn audit(&mut self, node: NodeId, items: &[Vec<u8>], audited: &[MailboxId]) {
        if !audited.is_empty()
            && let Ok(outbox) = self.core.pending_outbox(self.now)
        {
            let lost = detect_losses(
                &mut self.state.ledger,
                &node,
                audited,
                items,
                &outbox,
                self.now,
            );
            for _ in lost {
                self.score(node, ScoreEvent::Lost);
            }
        }
        if !self.found.contains(&node)
            && !found_messages(&self.state.ledger, &node, items).is_empty()
        {
            self.found.insert(node);
            self.score(node, ScoreEvent::Found);
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

/// What became of one exchange made by discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Answered,
    Refused,
    Failed,
}

/// A dialer that notes the outcome of every exchange, so that lookups and
/// pings feed the score like other requests.
struct Observed<'a, D> {
    inner: &'a D,
    outcomes: Mutex<Vec<(NodeId, Observation)>>,
}

impl<'a, D> Observed<'a, D> {
    fn new(inner: &'a D) -> Self {
        Observed {
            inner,
            outcomes: Mutex::new(Vec::new()),
        }
    }

    fn note<T>(&self, id: NodeId, r: &Result<T, DialError>) {
        let o = match r {
            Ok(_) => Observation::Answered,
            Err(DialError::Refused(_)) => Observation::Refused,
            // No address: nothing the node can be blamed for.
            Err(DialError::NoAddress) => return,
            Err(_) => Observation::Failed,
        };
        if let Ok(mut v) = self.outcomes.lock() {
            v.push((id, o));
        }
    }
}

impl<D: Dialer + Sync> Dialer for Observed<'_, D> {
    fn ping(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<NodeRecord, DialError>> + Send {
        let fut = self.inner.ping(id, addrs);
        async move {
            let r = fut.await;
            self.note(id, &r);
            r
        }
    }

    fn find_node(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send {
        let fut = self.inner.find_node(id, addrs, target);
        async move {
            let r = fut.await;
            self.note(id, &r);
            r
        }
    }
}

#[cfg(test)]
mod tests;
