use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;

use barking_packet::Kind;
use barking_proto::client::FetchResume;

use barking_core::Core;
use tempfile::TempDir;

use super::*;
use crate::score::Score;
use crate::test_support::{id_of, record, subject};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const NODES: usize = 11;

#[derive(Clone, Debug, PartialEq)]
enum Call {
    Ping(NodeId),
    Find(NodeId, [u8; 32]),
    Connect(NodeId),
    /// Node, mailboxes, and those of them that had a position at the call.
    Fetch(NodeId, Vec<MailboxId>, Vec<MailboxId>),
    Deposit(NodeId, [u8; 32]),
    Close(NodeId),
}

/// In-memory network of the test nodes; every call is logged.
#[derive(Default)]
struct Net {
    records: HashMap<NodeId, NodeRecord>,
    /// Unreachable nodes.
    down: HashSet<NodeId>,
    /// Nodes whose `Ping` and `FindNode` never get an answer (the caller's
    /// deadline drops them).
    hang: HashSet<NodeId>,
    /// Items served by any node to a fetch that asks for this mailbox.
    mailbox_items: HashMap<MailboxId, Vec<Vec<u8>>>,
    /// Nodes whose fetch always stops early, for this reason.
    truncate: HashMap<NodeId, FetchStop>,
    /// A fetch asking for one of these mailboxes stops early.
    truncate_mailbox: HashMap<MailboxId, FetchStop>,
    /// A re-read of this mailbox alone, from its start, stops early.
    cut_reread: HashMap<MailboxId, FetchStop>,
    /// Time a re-read of this mailbox (alone, from its start) takes.
    reread_delay: HashMap<MailboxId, Duration>,
    /// Nodes whose fetch answers `RateLimited`.
    rate_limit_fetch: HashSet<NodeId>,
    /// Items every fetch from that node returns.
    items: HashMap<NodeId, Vec<Vec<u8>>>,
    /// Time each fetch takes.
    fetch_delay: Duration,
    /// Time a `Ping` to that node takes (a slow link).
    ping_delay: HashMap<NodeId, Duration>,
    /// Time every `FindNode` takes (a slow link).
    find_delay: Duration,
    /// `FindNode` answered with a refusal (neutral for the score).
    refuse_finds: bool,
    /// Position given to every fetched mailbox (0: none).
    position: u64,
    /// Time each deposit takes.
    deposit_delay: Duration,
    /// Deposits from this one on (0-based) never get an answer.
    stall_deposit_from: Option<usize>,
    /// Message deposits on that node are refused with this reason.
    refuse_deposit: HashMap<NodeId, ErrorReason>,
    /// Proof work of a message deposit; beyond the budget: `PowBudget`.
    pow_cost: u64,
    /// The session to that node dies right after any fetch (the node cut
    /// it, or it went idle): later requests on it fail as unreachable.
    die_after_fetch: HashSet<NodeId>,
    /// Sessions that died, by connection number.
    dead: Mutex<HashSet<usize>>,
    calls: Mutex<Vec<Call>>,
}

/// A session of the test network: the node, and the connection's number.
struct Conn {
    id: NodeId,
    n: usize,
}

impl Net {
    fn log(&self, c: Call) {
        self.calls.lock().unwrap().push(c);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn up(&self, id: &NodeId) -> bool {
        self.records.contains_key(id) && !self.down.contains(id)
    }
}

impl Dialer for Net {
    fn ping(
        &self,
        id: NodeId,
        _addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<NodeRecord, DialError>> + Send {
        self.log(Call::Ping(id));
        let r = match self.records.get(&id) {
            Some(r) if self.up(&id) => Ok(r.clone()),
            _ => Err(DialError::Unreachable),
        };
        let hang = self.hang.contains(&id);
        let delay = self.ping_delay.get(&id).copied().unwrap_or_default();
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(delay).await;
            r
        }
    }

    fn find_node(
        &self,
        id: NodeId,
        _addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send {
        self.log(Call::Find(id, target));
        let r = if !self.up(&id) {
            Err(DialError::Unreachable)
        } else if self.refuse_finds {
            Err(DialError::Refused(ErrorReason::RateLimited))
        } else {
            Ok(Vec::new())
        };
        let hang = self.hang.contains(&id);
        let delay = self.find_delay;
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(delay).await;
            r
        }
    }
}

impl Connector for Net {
    type Conn = Conn;

    async fn connect(&self, id: NodeId, _addrs: &[SocketAddr]) -> Result<Conn, DialError> {
        let n = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(Call::Connect(id));
            calls.len()
        };
        if self.up(&id) {
            Ok(Conn { id, n })
        } else {
            Err(DialError::Unreachable)
        }
    }

    async fn close(&self, conn: Conn) {
        self.log(Call::Close(conn.id));
    }
}

impl Net {
    fn dead(&self, conn: &Conn) -> bool {
        self.dead.lock().unwrap().contains(&conn.n)
    }
}

impl Fetcher for Net {
    async fn fetch(
        &self,
        session: &mut Conn,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        _max_bytes: usize,
        _slice: Duration,
    ) -> Result<FetchReply, DialError> {
        let positioned: Vec<MailboxId> = mailboxes
            .iter()
            .filter(|m| resume.seen.get(&m.0).is_some_and(|s| *s > 0))
            .copied()
            .collect();
        let conn = &session.id;
        self.log(Call::Fetch(*conn, mailboxes.to_vec(), positioned.clone()));
        if self.dead(session) {
            return Err(DialError::Unreachable);
        }
        if self.die_after_fetch.contains(conn) {
            self.dead.lock().unwrap().insert(session.n);
        }
        let reread_delay = match mailboxes {
            [m] if positioned.is_empty() => self.reread_delay.get(m).copied(),
            _ => None,
        };
        tokio::time::sleep(reread_delay.unwrap_or(self.fetch_delay)).await;
        if self.rate_limit_fetch.contains(conn) {
            return Ok(FetchReply::RateLimited);
        }
        if self.position > 0 {
            for m in mailboxes {
                resume.seen.insert(m.0, self.position);
            }
        }
        let reread = match mailboxes {
            [m] if !positioned.contains(m) => self.cut_reread.get(m).copied(),
            _ => None,
        };
        let stop = self
            .truncate
            .get(conn)
            .copied()
            .or_else(|| {
                mailboxes
                    .iter()
                    .find_map(|m| self.truncate_mailbox.get(m).copied())
            })
            .or(reread)
            .unwrap_or(FetchStop::Complete);
        let mut items = self.items.get(conn).cloned().unwrap_or_default();
        for m in mailboxes {
            items.extend(self.mailbox_items.get(m).cloned().unwrap_or_default());
        }
        Ok(FetchReply::Items { items, stop })
    }
}

impl Depositor for Net {
    async fn deposit(&self, session: &mut Conn, packet: &[u8], pow_left: u64) -> DepositReply {
        let conn = &session.id;
        let n = {
            let mut calls = self.calls.lock().unwrap();
            let n = calls
                .iter()
                .filter(|c| matches!(c, Call::Deposit(..)))
                .count();
            calls.push(Call::Deposit(*conn, content_hash(packet)));
            n
        };
        if self.dead(session) {
            return DepositReply {
                outcome: Err(DialError::Unreachable),
                pow_spent: 0,
            };
        }
        if self.stall_deposit_from.is_some_and(|from| n >= from) {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.deposit_delay).await;
        let message = Packet::decode(packet).is_ok_and(|p| p.kind == Kind::Message);
        if message && self.pow_cost > pow_left {
            return DepositReply {
                outcome: Ok(DepositOutcome::PowBudget),
                pow_spent: 0,
            };
        }
        let result = match self.refuse_deposit.get(conn) {
            Some(reason) if message => Err(*reason),
            _ => Ok(()),
        };
        DepositReply {
            outcome: Ok(DepositOutcome::Answered(result)),
            pow_spent: if message { self.pow_cost } else { 0 },
        }
    }
}

/// Bob's core, whose saved view holds the 11 test nodes, all confirmed,
/// and the network that serves them.
fn setup() -> (TempDir, Core, Net) {
    let (dir, mut core) = subject(NOW);
    let net = setup_with(&mut core);
    (dir, core, net)
}

/// Saves the 11 test nodes, all confirmed, as `core`'s view, and returns
/// the network that serves them.
fn setup_with(core: &mut Core) -> Net {
    let mut state = NetState::new(true);
    let mut net = Net::default();
    for n in 0..NODES {
        let r = record(n, NOW);
        state.view.insert(r.clone(), NOW);
        state.view.confirm(&id_of(n), NOW);
        net.records.insert(id_of(n), r);
    }
    state.save(core).unwrap();
    net
}

fn all_nodes(net: &Net, stop: FetchStop) -> HashMap<NodeId, FetchStop> {
    net.records.keys().map(|k| (*k, stop)).collect()
}

fn opts() -> SyncOptions {
    SyncOptions {
        deadline: SYNC_DEADLINE,
        pow_budget: SYNC_POW_BUDGET,
        manual_nodes: Vec::new(),
        builtin: Vec::new(),
        allow_private: true,
        now: Some(NOW),
    }
}

fn load(core: &mut Core) -> NetState {
    NetState::load(core, NOW, true).unwrap()
}

fn fetches_of(calls: &[Call], group: &[MailboxId]) -> Vec<(usize, NodeId, Vec<MailboxId>)> {
    calls
        .iter()
        .enumerate()
        .filter_map(|(i, c)| match c {
            Call::Fetch(n, mbs, _) if mbs.iter().all(|m| group.contains(m)) => {
                Some((i, *n, mbs.clone()))
            }
            _ => None,
        })
        .collect()
}

fn positions_of(calls: &[Call], pred: impl Fn(&Call) -> bool) -> Vec<usize> {
    calls
        .iter()
        .enumerate()
        .filter(|(_, c)| pred(c))
        .map(|(i, _)| i)
        .collect()
}

#[tokio::test(start_paused = true)]
async fn sync_order_sessions_then_deposits_then_intro_then_maintenance() {
    let (_dir, mut core, net) = setup();
    let groups = core.watched_mailbox_groups(NOW);
    assert!(!groups.sessions.is_empty() && !groups.intro.is_empty());
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();

    let sessions = fetches_of(&calls, &groups.sessions);
    let intro = fetches_of(&calls, &groups.intro);
    let deposits = positions_of(&calls, |c| matches!(c, Call::Deposit(..)));
    let finds = positions_of(&calls, |c| matches!(c, Call::Find(..)));
    assert!(!sessions.is_empty() && !intro.is_empty());
    assert!(!deposits.is_empty() && !finds.is_empty());
    assert!(sessions.last().unwrap().0 < deposits[0]);
    assert!(deposits.last().unwrap() < &intro[0].0);
    assert!(intro.last().unwrap().0 < finds[0]);

    // The receipt, one first copy, then two more copies.
    assert_eq!(report.acks_deposited, 1);
    assert_eq!(report.first_copies, 1);
    assert_eq!(report.extra_copies, 2);
    assert!(report.network_up && report.polled_all_sessions && report.maintenance_done);
    assert_eq!(report.view_size, NODES);
    // Connections are closed at the end.
    assert!(matches!(calls.last(), Some(Call::Close(_))));
}

#[tokio::test(start_paused = true)]
async fn first_copy_before_any_maintenance_under_tight_deadline() {
    let (_dir, mut core, mut net) = setup();
    net.deposit_delay = Duration::from_secs(1);
    let groups = core.watched_mailbox_groups(NOW);
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            deadline: Duration::from_millis(2500),
            ..opts()
        },
    )
    .await;
    let calls = net.calls();
    assert_eq!(report.acks_deposited, 1);
    assert_eq!(report.first_copies, 1);
    assert_eq!(report.extra_copies, 0);
    assert!(!report.maintenance_done);
    assert!(!calls.iter().any(|c| matches!(c, Call::Find(..))));
    assert!(fetches_of(&calls, &groups.intro).is_empty());
}

/// Cross-checks already done for `mailboxes` on every node: the sync only
/// makes its primary rounds.
fn no_crosschecks(core: &mut Core, mailboxes: &[MailboxId]) {
    let mut state = load(core);
    for n in 0..NODES {
        for m in mailboxes {
            state.note_crosscheck(&id_of(n), m, NOW);
        }
    }
    state.save(core).unwrap();
}

#[tokio::test(start_paused = true)]
async fn fetch_groups_mailboxes_by_best_responsible() {
    let (_dir, mut core, net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    // The second closest node of the first mailbox scores higher than the
    // closest: it becomes the best responsible.
    let mut state = load(&mut core);
    let r = state.view.responsibles_by_score(&sessions[0], NOW);
    state.view.entries.get_mut(&r[1]).unwrap().score = Score::new(0.9);
    state.save(&mut core).unwrap();
    let mut expected: BTreeMap<[u8; 32], BTreeSet<[u8; 16]>> = BTreeMap::new();
    for m in &sessions {
        let best = state.view.responsibles_by_score(m, NOW)[0];
        expected.entry(best.0).or_default().insert(m.0);
    }
    assert!(expected[&r[1].0].contains(&sessions[0].0));
    no_crosschecks(&mut core, &sessions);

    sync(&mut core, &net, opts()).await;
    let mut actual: BTreeMap<[u8; 32], BTreeSet<[u8; 16]>> = BTreeMap::new();
    for (_, node, mbs) in fetches_of(&net.calls(), &sessions) {
        let set = actual.entry(node.0).or_default();
        for m in mbs {
            assert!(set.insert(m.0), "mailbox fetched twice from one node");
        }
    }
    assert_eq!(actual, expected);
}

#[tokio::test(start_paused = true)]
async fn second_responsible_on_failure_or_truncation() {
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let m = sessions[0];
    let r = load(&mut core).view.responsibles_by_score(&m, NOW);
    // Best responsible unreachable, the second truncates: the third serves.
    net.down.insert(r[0]);
    net.truncate.insert(r[1], FetchStop::Connection);
    no_crosschecks(&mut core, &sessions);
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let served: Vec<NodeId> = fetches_of(&calls, &sessions)
        .into_iter()
        .filter(|(_, _, mbs)| mbs.contains(&m))
        .map(|(_, n, _)| n)
        .collect();
    assert_eq!(served, vec![r[1], r[2]]);
    assert!(calls.contains(&Call::Connect(r[0])));
    assert!(report.polled_all_sessions);
    // The unreachable node lost score (another node answered).
    let state = load(&mut core);
    assert!(state.view.get(&r[0]).unwrap().score.value() < 0.5);
}

#[tokio::test(start_paused = true)]
async fn crosscheck_reads_another_responsible_every_six_hours() {
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let m = sessions[0];
    let mut state = load(&mut core);
    let r = state.view.responsibles_by_score(&m, NOW);
    // The best responsible stays best through the three syncs.
    state.view.entries.get_mut(&r[0]).unwrap().score = Score::new(0.9);
    state.save(&mut core).unwrap();
    // Only the second responsible holds the item: the best one answers
    // empty, as a node that keeps nothing would.
    let (item, _) = message(&mut core);
    net.items.insert(r[1], vec![item]);
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    assert_eq!(fetches_for(&calls, r[0], m).len(), 1);
    assert_eq!(fetches_for(&calls, r[1], m).len(), 1);
    // After every primary fetch, items processed as usual.
    let last_primary = fetches_of(&calls, &sessions)
        .iter()
        .filter(|(_, n, mbs)| *n != r[1] || !mbs.contains(&m))
        .map(|(i, _, _)| *i)
        .filter(|i| !matches!(&calls[*i], Call::Fetch(n, mbs, _) if *n != r[0] && mbs.contains(&m)))
        .max()
        .unwrap();
    let crosscheck = fetches_of(&calls, &sessions)
        .into_iter()
        .find(|(_, n, mbs)| *n == r[1] && mbs.contains(&m))
        .unwrap()
        .0;
    assert!(crosscheck > last_primary);
    assert!(report.items_received >= 1);
    assert!(report.polled_all_sessions);

    // Not again within six hours.
    let seen = net.calls().len();
    let at = |t: u64| SyncOptions {
        now: Some(t),
        ..opts()
    };
    sync(&mut core, &net, at(NOW + 3600)).await;
    assert_eq!(fetches_for(&net.calls()[seen..], r[0], m).len(), 1);
    assert!(fetches_for(&net.calls()[seen..], r[1], m).is_empty());
    let seen = net.calls().len();
    sync(&mut core, &net, at(NOW + CROSSCHECK_EVERY_SECS + 3600)).await;
    assert_eq!(fetches_for(&net.calls()[seen..], r[1], m).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn three_failed_dials_end_the_sync_as_network_down() {
    let (_dir, mut core, mut net) = setup();
    net.down = net.records.keys().copied().collect();
    let before = load(&mut core);
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.network_up && !report.maintenance_done);
    let dials = net
        .calls()
        .iter()
        .filter(|c| matches!(c, Call::Connect(_) | Call::Ping(_) | Call::Find(..)))
        .count();
    assert_eq!(dials, DOWN_AFTER_FAILURES as usize, "{:?}", net.calls());
    let after = load(&mut core);
    for (id, e) in after.view.entries() {
        assert_eq!(e.score, before.view.get(id).unwrap().score);
    }
}

/// Nodes dialled by `calls`, in order.
fn connects(calls: &[Call]) -> Vec<NodeId> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Connect(n) => Some(*n),
            _ => None,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn first_three_dead_then_live_manual_node_keeps_the_sync_going() {
    let (_dir, mut core, mut net) = setup();
    // The three nodes this sync dials first, found by a dry run on the
    // same state.
    let saved = core
        .transport_state(crate::state::STATE_KEY)
        .unwrap()
        .unwrap();
    sync(&mut core, &net, opts()).await;
    let first: Vec<NodeId> = connects(&net.calls()).into_iter().take(3).collect();
    assert_eq!(first.len(), 3);
    core.set_transport_state(crate::state::STATE_KEY, &saved)
        .unwrap();
    net.calls.lock().unwrap().clear();
    net.down = first.iter().copied().collect();
    // A live node added by hand, not among the first dialled.
    let manual = (0..NODES)
        .map(id_of)
        .find(|id| !first.contains(id))
        .unwrap();
    let addr = net.records[&manual].addrs()[0];
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            manual_nodes: vec![(manual, addr)],
            ..opts()
        },
    )
    .await;
    assert_eq!(
        connects(&net.calls())[..4],
        [first[0], first[1], first[2], manual]
    );
    assert!(report.network_up, "{report:?}");
    assert!(
        report.acks_deposited + report.first_copies > 0,
        "{report:?}"
    );
    // The dead nodes were demoted.
    for id in &first {
        assert!(score_of(&mut core, id) < 0.5);
    }
}

#[tokio::test(start_paused = true)]
async fn after_a_down_sync_other_nodes_are_dialled_first() {
    let (_dir, mut core, mut net) = setup();
    net.down = net.records.keys().copied().collect();
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.network_up);
    let dead: Vec<NodeId> = connects(&net.calls());
    assert_eq!(dead.len(), DOWN_AFTER_FAILURES as usize);
    let state = load(&mut core);
    for id in &dead {
        assert!(state.down_failed.contains_key(id));
    }
    // Remembered 24 hours at most.
    let later =
        NetState::load(&mut core, NOW + crate::state::DOWN_FAILED_SECS + 3600, true).unwrap();
    assert!(later.down_failed.is_empty());
    // Back up: the next sync starts with other nodes.
    net.down.clear();
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up);
    let next: Vec<NodeId> = connects(&net.calls()).into_iter().take(3).collect();
    assert!(
        next.iter().all(|id| !dead.contains(id)),
        "{next:?} {dead:?}"
    );
    // Remembered 24 hours at most.
    let later =
        NetState::load(&mut core, NOW + crate::state::DOWN_FAILED_SECS + 3600, true).unwrap();
    assert!(later.down_failed.is_empty());
}

#[tokio::test(start_paused = true)]
async fn state_saved_after_each_response() {
    let (_dir, mut core, mut net) = setup();
    net.position = 7;
    net.stall_deposit_from = Some(1);
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let cut = tokio::time::timeout(Duration::from_secs(60), sync(&mut core, &net, opts())).await;
    assert!(
        cut.is_err(),
        "the sync is cut in the middle of the deposits"
    );
    let calls = net.calls();
    let state = load(&mut core);
    let fetched = fetches_of(&calls, &sessions);
    assert!(!fetched.is_empty());
    for (_, node, mbs) in fetched {
        for m in mbs {
            assert_eq!(state.positions.get(&(node, m)), Some(&7));
        }
    }
    let deposits: Vec<(NodeId, [u8; 32])> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Deposit(n, h) => Some((*n, *h)),
            _ => None,
        })
        .collect();
    assert_eq!(deposits.len(), 2);
    assert_eq!(state.ledger.holders(&deposits[0].1), vec![deposits[0].0]);
    assert!(state.ledger.holders(&deposits[1].1).is_empty());
}

#[tokio::test(start_paused = true)]
async fn mark_polled_only_when_all_sessions_polled() {
    let (_dir, mut core, mut net) = setup();
    core.mark_polled(NOW - 5 * DAY).unwrap();
    let wide = core.watched_mailbox_groups(NOW).intro.len();
    // Every node truncates: no session mailbox is fetched in full.
    net.truncate = all_nodes(&net, FetchStop::Connection);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up && !report.polled_all_sessions);
    assert_eq!(core.watched_mailbox_groups(NOW).intro.len(), wide);

    net.truncate.clear();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.polled_all_sessions);
    assert!(core.watched_mailbox_groups(NOW).intro.len() < wide);
}

#[tokio::test(start_paused = true)]
async fn no_node_answers_reports_network_down_and_keeps_outbox() {
    let (_dir, mut core, mut net) = setup();
    net.down = net.records.keys().copied().collect();
    let outbox = core.pending_outbox(NOW).unwrap();
    let before = load(&mut core);
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.network_up);
    assert!(!report.polled_all_sessions);
    assert_eq!(report.first_copies + report.acks_deposited, 0);
    assert!(report.avoided.is_empty());
    assert_eq!(core.pending_outbox(NOW).unwrap(), outbox);
    // Nobody answered: the client's connection is at fault, no score drops.
    let after = load(&mut core);
    for (id, e) in after.view.entries() {
        assert_eq!(e.score, before.view.get(id).unwrap().score);
    }
    assert!(after.unaudited.is_empty());
    assert_eq!(after.ledger, before.ledger);
}

#[tokio::test(start_paused = true)]
async fn never_completing_node_fails_after_three_syncs() {
    let (_dir, mut core, mut net) = setup();
    net.refuse_finds = true;
    net.truncate = all_nodes(&net, FetchStop::Connection);
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let node = load(&mut core)
        .view
        .responsibles_by_score(&sessions[0], NOW)[0];
    let mut scores = vec![load(&mut core).view.get(&node).unwrap().score.value()];
    for _ in 0..3 {
        sync(&mut core, &net, opts()).await;
        scores.push(load(&mut core).view.get(&node).unwrap().score.value());
    }
    assert_eq!(load(&mut core).unaudited.get(&node), Some(&UNAUDITED_SYNCS));
    let deltas: Vec<f32> = scores.windows(2).map(|w| w[1] - w[0]).collect();
    // Same successes each sync; the third one adds a failure.
    assert!((deltas[0] - deltas[1]).abs() < 1e-4, "{deltas:?}");
    assert!(deltas[2] < deltas[1] - 0.05, "{deltas:?}");
}

// --- Audit, score and deposit wiring ---------------------------------------

/// Bob's queued message and its mailbox.
fn message(core: &mut Core) -> (Vec<u8>, MailboxId) {
    let bytes = core
        .pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .find(|b| Packet::decode(b).unwrap().kind == Kind::Message)
        .unwrap();
    let mailbox = Packet::decode(&bytes).unwrap().mailbox;
    (bytes, mailbox)
}

/// `node` accepted the message earlier.
fn accepted_by(core: &mut Core, node: NodeId, bytes: &[u8]) {
    let mut state = load(core);
    plan::record_outcome(
        &mut state.ledger,
        content_hash(bytes),
        node,
        &Ok(()),
        NOW - 7 * 3600,
    );
    state.save(core).unwrap();
}

fn score_of(core: &mut Core, id: &NodeId) -> f32 {
    load(core).view.get(id).unwrap().score.value()
}

fn holders(core: &mut Core, bytes: &[u8]) -> Vec<NodeId> {
    load(core).ledger.holders(&content_hash(bytes))
}

/// Fetch calls to `node` asking for `m`, with whether `m` was positioned.
fn fetches_for(calls: &[Call], node: NodeId, m: MailboxId) -> Vec<bool> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(n, mbs, positioned) if *n == node && mbs.contains(&m) => {
                Some(positioned.contains(&m))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn complete_from_start_fetch_missing_accepted_message_is_lost() {
    let (_dir, mut core, mut net) = setup();
    // Lookup answers would add successes on top of the loss.
    net.refuse_finds = true;
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    sync(&mut core, &net, opts()).await;
    assert_eq!(fetches_for(&net.calls(), x, m), vec![false]);
    assert!(!holders(&mut core, &bytes).contains(&x));
    assert!(score_of(&mut core, &x) < 0.3);
    assert!(load(&mut core).audited_at.contains_key(&(x, m)));
}

#[tokio::test(start_paused = true)]
async fn positioned_mailbox_is_read_again_for_a_due_audit() {
    let (_dir, mut core, net) = setup();
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    let mut state = load(&mut core);
    state.positions.insert((x, m), 5);
    state.save(&mut core).unwrap();
    sync(&mut core, &net, opts()).await;
    // The regular fetch resumes, then a re-read from the start (no position
    // sent) sees the loss.
    assert_eq!(fetches_for(&net.calls(), x, m), vec![true, false]);
    assert!(!holders(&mut core, &bytes).contains(&x));
}

#[tokio::test(start_paused = true)]
async fn positioned_mailbox_without_due_audit_reports_no_loss() {
    let (_dir, mut core, net) = setup();
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    let mut state = load(&mut core);
    state.positions.insert((x, m), 5);
    state.note_audit(&x, &m, NOW - 3600);
    state.save(&mut core).unwrap();
    sync(&mut core, &net, opts()).await;
    // Resumed from its position: the message is not expected there.
    assert_eq!(fetches_for(&net.calls(), x, m), vec![true]);
    assert!(holders(&mut core, &bytes).contains(&x));
    assert!(score_of(&mut core, &x) >= 0.5);
}

#[tokio::test(start_paused = true)]
async fn truncated_reread_audits_nothing_and_keeps_the_position() {
    let (_dir, mut core, mut net) = setup();
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    let mut state = load(&mut core);
    state.positions.insert((x, m), 5);
    state.save(&mut core).unwrap();
    net.cut_reread.insert(m, FetchStop::ClientLimit);
    sync(&mut core, &net, opts()).await;
    assert_eq!(fetches_for(&net.calls(), x, m), vec![true, false]);
    let state = load(&mut core);
    assert!(state.ledger.holders(&content_hash(&bytes)).contains(&x));
    assert_eq!(state.positions.get(&(x, m)), Some(&5));
    assert!(!state.audited_at.contains_key(&(x, m)));
}

#[tokio::test(start_paused = true)]
async fn receipt_in_the_fetch_prevents_a_loss() {
    let (_dir, mut core, ack) = crate::test_support::subject_with_ack(NOW);
    let mut net = setup_with(&mut core);
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    net.items.insert(x, vec![ack]);
    let report = sync(&mut core, &net, opts()).await;
    assert!(
        report
            .received
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::AckReceived { .. }))
    );
    // Delivered: out of the queue, and the node is not blamed.
    let h = content_hash(&bytes);
    assert!(
        !core
            .pending_outbox(NOW)
            .unwrap()
            .iter()
            .any(|b| content_hash(b) == h)
    );
    assert!(score_of(&mut core, &x) >= 0.5);
}

/// A node `x`, best responsible of the message mailbox `m` once scored 0.8,
/// and second (after `y`, scored 0.9) for another session mailbox `m2`.
fn two_groups(core: &mut Core) -> (NodeId, NodeId, MailboxId) {
    let (_, m) = message(core);
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let mut state = load(core);
    let rm = state.view.responsibles(&m, NOW);
    for m2 in sessions.iter().filter(|s| **s != m) {
        let r2 = state.view.responsibles(m2, NOW);
        let x = r2.iter().find(|n| rm.contains(n));
        let y = r2.iter().find(|n| !rm.contains(n));
        if let (Some(&x), Some(&y)) = (x, y) {
            state.view.entries.get_mut(&x).unwrap().score = Score::new(0.8);
            state.view.entries.get_mut(&y).unwrap().score = Score::new(0.9);
            state.save(core).unwrap();
            return (x, y, *m2);
        }
    }
    panic!("no pair of overlapping responsible sets");
}

#[tokio::test(start_paused = true)]
async fn found_applies_once_per_node_across_two_groups() {
    let (_dir, mut core, mut net) = setup();
    let (bytes, _) = message(&mut core);
    let (x, y, _) = two_groups(&mut core);
    accepted_by(&mut core, x, &bytes);
    net.down.insert(y);
    net.refuse_finds = true;
    net.items.insert(x, vec![bytes.clone()]);
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let fetches = calls
        .iter()
        .filter(|c| matches!(c, Call::Fetch(n, ..) if *n == x))
        .count();
    let deposits = calls
        .iter()
        .filter(|c| matches!(c, Call::Deposit(n, _) if *n == x))
        .count();
    assert!(fetches >= 2, "x serves two groups");
    let expected = 0.8 + 0.02 * (fetches + deposits) as f32 + 0.05;
    assert!(
        (score_of(&mut core, &x) - expected).abs() < 2e-3,
        "{} vs {expected}",
        score_of(&mut core, &x)
    );
}

#[tokio::test(start_paused = true)]
async fn complete_then_truncated_fetch_does_not_count_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    let (x, y, m2) = two_groups(&mut core);
    net.down.insert(y);
    net.truncate_mailbox.insert(m2, FetchStop::Connection);
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let to_x: Vec<bool> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(n, mbs, _) if *n == x => Some(mbs.contains(&m2)),
            _ => None,
        })
        .collect();
    assert!(to_x.contains(&true) && to_x.contains(&false));
    assert!(!load(&mut core).unaudited.contains_key(&x));
}

#[tokio::test(start_paused = true)]
async fn rate_limited_fetch_does_not_count_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    net.rate_limit_fetch = net.records.keys().copied().collect();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up && !report.polled_all_sessions);
    assert!(load(&mut core).unaudited.is_empty());
}

#[tokio::test(start_paused = true)]
async fn truncation_when_the_slice_ran_out_does_not_count() {
    let (_dir, mut core, mut net) = setup();
    net.truncate = all_nodes(&net, FetchStop::Connection);
    net.fetch_delay = SESSION_FETCH_SLICE + Duration::from_secs(10);
    sync(&mut core, &net, opts()).await;
    assert!(load(&mut core).unaudited.is_empty());
}

#[tokio::test(start_paused = true)]
async fn one_failure_per_node_per_sync() {
    let (_dir, mut core, mut net) = setup();
    let x = id_of(0);
    net.down.insert(x);
    // The connection fails: lookups, fallbacks and pings never ask it again.
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.maintenance_done);
    let calls = net.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| matches!(c, Call::Connect(n) | Call::Find(n, _) | Call::Ping(n) if *n == x))
            .count(),
        1
    );
    assert!((score_of(&mut core, &x) - 0.4).abs() < 1e-4);
}

/// Bob's core whose view holds only the nodes `ns`, confirmed.
fn view_of(core: &mut Core, ns: &[usize]) -> Net {
    let mut state = NetState::new(true);
    let mut net = Net::default();
    for &n in ns {
        let r = record(n, NOW);
        state.view.insert(r.clone(), NOW);
        state.view.confirm(&id_of(n), NOW);
        net.records.insert(id_of(n), r);
    }
    state.save(core).unwrap();
    net
}

#[tokio::test(start_paused = true)]
async fn only_node_down_ends_fast_without_maintenance() {
    let (_dir, mut core) = subject(NOW);
    let mut net = view_of(&mut core, &[0]);
    let x = id_of(0);
    net.hang.insert(x);
    let start = Instant::now();
    let report = sync(&mut core, &net, opts()).await;
    let took = start.elapsed();
    // The bootstrap ping gets the full dial timeout (a slow link is not a
    // dead node), nothing more.
    assert!(
        took <= crate::discover::DIAL_TIMEOUT + Duration::from_secs(1),
        "took {took:?}"
    );
    assert!(!report.network_up && !report.maintenance_done);
    // The bootstrap ping timed out: never dialled again this sync.
    assert_eq!(net.calls(), vec![Call::Ping(x)]);
    // Nobody answered: no score drop.
    assert!((score_of(&mut core, &x) - 0.5).abs() < 1e-4);
}

#[tokio::test(start_paused = true)]
async fn bootstrap_ping_timeout_counts_as_one_failure() {
    let (_dir, mut core) = subject(NOW);
    let mut net = view_of(&mut core, &[0, 1]);
    let x = id_of(0);
    net.hang.insert(x);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up);
    let calls = net.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| matches!(c, Call::Connect(n) | Call::Find(n, _) | Call::Ping(n) if *n == x))
            .count(),
        1
    );
    assert!((score_of(&mut core, &x) - 0.4).abs() < 1e-4);
}

#[tokio::test(start_paused = true)]
async fn first_contact_receipt_leaves_in_the_same_sync() {
    use rand::SeedableRng;
    let (dir, mut core, mut net) = setup();
    // Carol writes to Bob for the first time: her message waits in Bob's
    // introduction mailbox.
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    let (mut carol, _) = Core::create(
        &dir.path().join("carol.db"),
        &[3; 32],
        "carol",
        NOW,
        &mut rng,
    )
    .unwrap();
    let card_c = carol.contact_card("Carol").unwrap();
    let card_b = core.contact_card("Bob").unwrap();
    core.add_contact(&card_c, Some("carol"), NOW, &mut rng)
        .unwrap();
    let fb = carol
        .add_contact(&card_b, Some("bob"), NOW, &mut rng)
        .unwrap();
    let intro = core.watched_mailbox_groups(NOW).intro;
    for p in carol.send_text(&fb, "first", NOW, &mut rng).unwrap() {
        assert!(intro.contains(&p.mailbox));
        net.mailbox_items
            .entry(p.mailbox)
            .or_default()
            .push(p.encode());
    }
    let report = sync(&mut core, &net, opts()).await;
    assert!(
        report
            .received
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Message { .. }))
    );
    // Bob's earlier receipt in the first pass, Carol's after the
    // introductions, in the same sync.
    assert_eq!(report.acks_deposited, 2);
    let calls = net.calls();
    let intro_fetch = fetches_of(&calls, &intro)[0].0;
    let deposits = positions_of(&calls, |c| matches!(c, Call::Deposit(..)));
    assert!(deposits.iter().any(|&d| d > intro_fetch));
}

#[tokio::test(start_paused = true)]
async fn not_responsible_twice_runs_fallback_then_replans() {
    let (_dir, mut core, mut net) = setup();
    let (bytes, m) = message(&mut core);
    let r = load(&mut core).view.responsibles_by_score(&m, NOW);
    net.refuse_deposit.insert(r[0], ErrorReason::NotResponsible);
    net.refuse_deposit.insert(r[1], ErrorReason::NotResponsible);
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let h = content_hash(&bytes);
    let at = |c: Call| calls.iter().position(|x| *x == c).unwrap();
    let key = barking_dht::mailbox_key(&m);
    let find = calls
        .iter()
        .position(|c| matches!(c, Call::Find(_, t) if *t == key))
        .unwrap();
    assert!(at(Call::Deposit(r[1], h)) < find);
    assert!(find < at(Call::Deposit(r[2], h)));
    // After the new plan, r[2] takes the first copy.
    assert_eq!(report.first_copies, 1);
    assert!(holders(&mut core, &bytes).contains(&r[2]));
}

#[tokio::test(start_paused = true)]
async fn pow_budget_exhausted_messages_wait_receipts_go() {
    let (_dir, mut core, mut net) = setup();
    net.pow_cost = 1;
    let (bytes, _) = message(&mut core);
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            pow_budget: 0,
            ..opts()
        },
    )
    .await;
    assert_eq!(report.acks_deposited, 1);
    assert_eq!(report.first_copies + report.extra_copies, 0);
    assert!(report.pow_exhausted);
    assert!(holders(&mut core, &bytes).is_empty());
}

#[tokio::test(start_paused = true)]
async fn rate_limited_deposit_replans_on_the_next_responsible() {
    let (_dir, mut core, mut net) = setup();
    let (bytes, m) = message(&mut core);
    let r = load(&mut core).view.responsibles_by_score(&m, NOW);
    net.refuse_deposit.insert(r[0], ErrorReason::RateLimited);
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let h = content_hash(&bytes);
    let limited = calls
        .iter()
        .position(|c| *c == Call::Deposit(r[0], h))
        .unwrap();
    assert!(
        !calls[limited + 1..]
            .iter()
            .any(|c| matches!(c, Call::Deposit(n, _) if *n == r[0]))
    );
    assert_eq!(report.first_copies, 1);
    assert!(holders(&mut core, &bytes).contains(&r[1]));
}

// --- Stop reasons and audit re-reads (R20) ----------------------------------

#[tokio::test(start_paused = true)]
async fn rate_limit_after_some_pages_does_not_count_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    net.truncate = all_nodes(&net, FetchStop::RateLimited);
    for _ in 0..UNAUDITED_SYNCS {
        let report = sync(&mut core, &net, opts()).await;
        assert!(report.network_up && !report.polled_all_sessions);
    }
    assert!(load(&mut core).unaudited.is_empty());
}

#[tokio::test(start_paused = true)]
async fn client_cap_truncation_does_not_count_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    net.truncate = all_nodes(&net, FetchStop::ClientLimit);
    for _ in 0..UNAUDITED_SYNCS {
        sync(&mut core, &net, opts()).await;
    }
    assert!(load(&mut core).unaudited.is_empty());
    // A cut connection, on the other hand, does count.
    net.truncate = all_nodes(&net, FetchStop::Connection);
    sync(&mut core, &net, opts()).await;
    assert!(!load(&mut core).unaudited.is_empty());
}

#[tokio::test(start_paused = true)]
async fn large_reread_neither_starves_group_mates_nor_counts() {
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let (bytes, m) = message(&mut core);
    let x = load(&mut core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(&mut core, x, &bytes);
    let mut state = load(&mut core);
    for s in &sessions {
        state.positions.insert((x, *s), 5);
    }
    state.save(&mut core).unwrap();
    // The re-read of `m` never fits the client's caps.
    net.cut_reread.insert(m, FetchStop::ClientLimit);
    for _ in 0..UNAUDITED_SYNCS {
        let report = sync(&mut core, &net, opts()).await;
        assert!(report.polled_all_sessions);
    }
    let calls = net.calls();
    // Every sync: the regular, positioned fetch first, then the re-read.
    let to_x: Vec<(Vec<MailboxId>, Vec<MailboxId>)> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(n, mbs, positioned) if *n == x && mbs.contains(&m) => {
                Some((mbs.clone(), positioned.clone()))
            }
            _ => None,
        })
        .collect();
    // Regular fetch every sync; the cut re-read only once (it backs off).
    let rereads = to_x.iter().filter(|c| c.1.is_empty()).count();
    assert_eq!(rereads, 1);
    assert_eq!(to_x.len(), UNAUDITED_SYNCS as usize + 1);
    assert!(to_x[0].1.contains(&m), "regular fetch resumes");
    assert_eq!(to_x[1], (vec![m], vec![]), "re-read alone, from the start");
    let state = load(&mut core);
    assert!(!state.unaudited.contains_key(&x));
    assert!(!state.audited_at.contains_key(&(x, m)));
    assert!(state.ledger.holders(&content_hash(&bytes)).contains(&x));
}

#[tokio::test(start_paused = true)]
async fn finished_reread_is_audited_even_if_another_is_cut() {
    let (_dir, mut core) = crate::test_support::subject_two_messages(NOW);
    let mut net = setup_with(&mut core);
    let messages: Vec<(Vec<u8>, MailboxId)> = core
        .pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .filter_map(|b| {
            let p = Packet::decode(&b).unwrap();
            (p.kind == Kind::Message).then_some((b, p.mailbox))
        })
        .collect();
    assert_eq!(messages.len(), 2);
    let (m1, m2) = (messages[0].1, messages[1].1);
    assert_ne!(m1, m2);
    // One node responsible for both mailboxes, made the best for both.
    let mut state = load(&mut core);
    let r1 = state.view.responsibles(&m1, NOW);
    let x = *state
        .view
        .responsibles(&m2, NOW)
        .iter()
        .find(|n| r1.contains(n))
        .expect("overlapping responsibles");
    state.view.entries.get_mut(&x).unwrap().score = Score::new(0.9);
    for (b, m) in &messages {
        plan::record_outcome(
            &mut state.ledger,
            content_hash(b),
            x,
            &Ok(()),
            NOW - 7 * 3600,
        );
        state.positions.insert((x, *m), 5);
    }
    state.save(&mut core).unwrap();
    net.cut_reread.insert(m2, FetchStop::ClientLimit);
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    // Both mailboxes come in one regular fetch from `x`.
    assert!(calls.iter().any(
        |c| matches!(c, Call::Fetch(n, mbs, _) if *n == x && mbs.contains(&m1) && mbs.contains(&m2))
    ));
    let state = load(&mut core);
    assert!(state.audited_at.contains_key(&(x, m1)));
    assert!(!state.audited_at.contains_key(&(x, m2)));
}

// --- Re-reads after every regular fetch, capped and backed off (R21) -------

/// Lone, positionless fetches of `m` from `node`: audit re-reads.
fn rereads_of(calls: &[Call], node: NodeId, m: MailboxId) -> Vec<usize> {
    positions_of(
        calls,
        |c| matches!(c, Call::Fetch(n, mbs, p) if *n == node && *mbs == [m] && p.is_empty()),
    )
}

/// Bob's core with the message accepted by its best responsible `x`, and
/// every session mailbox positioned on `x`.
fn due_reread(core: &mut Core) -> (NodeId, MailboxId, Vec<u8>) {
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let (bytes, m) = message(core);
    let x = load(core).view.responsibles_by_score(&m, NOW)[0];
    accepted_by(core, x, &bytes);
    let mut state = load(core);
    for s in &sessions {
        state.positions.insert((x, *s), 5);
    }
    // At the top score, `x` stays the best responsible of `m` (ties go by
    // distance, and it is the closest) however the others' scores grow.
    state.view.entries.get_mut(&x).unwrap().score = Score::new(1.0);
    state.save(core).unwrap();
    (x, m, bytes)
}

#[tokio::test(start_paused = true)]
async fn slow_reread_waits_for_every_regular_fetch_and_mark_polled() {
    let (_dir, mut core, mut net) = setup();
    core.mark_polled(NOW - 5 * DAY).unwrap();
    let wide = core.watched_mailbox_groups(NOW).intro.len();
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let (x, m, _) = due_reread(&mut core);
    // The re-read would take longer than the whole session slice.
    net.reread_delay.insert(m, Duration::from_secs(200));
    let start = Instant::now();
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    let reread = rereads_of(&calls, x, m);
    assert_eq!(reread.len(), 1);
    let regular: Vec<(usize, NodeId)> = fetches_of(&calls, &sessions)
        .into_iter()
        .filter(|(i, _, _)| *i != reread[0])
        .map(|(i, n, _)| (i, n))
        .collect();
    assert!(
        regular.iter().any(|(_, n)| *n != x),
        "another node serves a group"
    );
    assert!(regular.iter().all(|(i, _)| *i < reread[0]));
    assert!(report.polled_all_sessions);
    assert!(core.watched_mailbox_groups(NOW).intro.len() < wide);
    // The re-read was cut by its own cap, and dated.
    let state = load(&mut core);
    assert!(state.reread_at.contains_key(&(x, m)));
    assert!(!state.audited_at.contains_key(&(x, m)));
    assert!(Instant::now() - start < SYNC_DEADLINE);
}

#[tokio::test(start_paused = true)]
async fn cut_reread_backs_off_six_hours() {
    let (_dir, mut core, mut net) = setup();
    let (x, m, _) = due_reread(&mut core);
    net.reread_delay.insert(m, Duration::from_secs(200));
    sync(&mut core, &net, opts()).await;
    sync(&mut core, &net, opts()).await;
    assert_eq!(rereads_of(&net.calls(), x, m).len(), 1);
    // Once the try is 6 h old, the re-read is due again.
    let mut state = load(&mut core);
    state.note_reread(&x, &m, NOW - AUDIT_EVERY_SECS);
    state.save(&mut core).unwrap();
    sync(&mut core, &net, opts()).await;
    assert_eq!(rereads_of(&net.calls(), x, m).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn no_reread_after_a_cut_connection() {
    let (_dir, mut core, mut net) = setup();
    let (x, m, _) = due_reread(&mut core);
    net.truncate.insert(x, FetchStop::Connection);
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, Call::Fetch(n, ..) if *n == x))
    );
    assert!(rereads_of(&calls, x, m).is_empty());
}

#[tokio::test(start_paused = true)]
async fn deadline_stop_does_not_count_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    net.truncate = all_nodes(&net, FetchStop::Deadline);
    for _ in 0..UNAUDITED_SYNCS {
        sync(&mut core, &net, opts()).await;
    }
    assert!(load(&mut core).unaudited.is_empty());
}

// --- Slow links (client caps shorter than the dial timeout) ----------------

#[tokio::test(start_paused = true)]
async fn slow_lookups_lower_no_score() {
    let (_dir, mut core, mut net) = setup();
    // Every lookup request outlasts its 3 s cap: a slow link, not dead nodes.
    net.find_delay = Duration::from_secs(4);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up && report.maintenance_done, "{report:?}");
    let calls = net.calls();
    // Nodes only asked by lookups: neither failed nor scored.
    let connected: HashSet<NodeId> = connects(&calls).into_iter().collect();
    let idle: Vec<NodeId> = (0..NODES)
        .map(id_of)
        .filter(|id| !connected.contains(id))
        .collect();
    assert!(!idle.is_empty());
    for id in &idle {
        assert!(
            calls
                .iter()
                .any(|c| matches!(c, Call::Find(n, _) if n == id)),
            "{id:?} never asked"
        );
        assert!((score_of(&mut core, id) - 0.5).abs() < 1e-4, "{id:?}");
    }
}

/// A run on `core`'s saved state, as `sync` starts one.
fn run_on<'a>(core: &'a mut Core, net: &'a Net) -> Run<'a, Net> {
    let state = load(core);
    let deadline = Instant::now() + SYNC_DEADLINE;
    Run::new(core, net, state, NOW, deadline, SYNC_POW_BUDGET)
}

#[tokio::test(start_paused = true)]
async fn slow_candidate_ping_lowers_no_score() {
    let (_dir, mut core, mut net) = setup();
    let candidate = id_of(3);
    let mut state = load(&mut core);
    state.view.entries.get_mut(&candidate).unwrap().confirmed = false;
    state.save(&mut core).unwrap();
    net.ping_delay
        .insert(candidate, CONFIRM_TIMEOUT + Duration::from_secs(1));
    let mut run = run_on(&mut core, &net);
    // Another node answered: a failure would count.
    run.answered();
    run.confirm_candidates().await;
    assert!(run.failed.is_empty());
    run.save();
    drop(run);
    assert_eq!(net.calls(), vec![Call::Ping(candidate)]);
    let state = load(&mut core);
    let e = state.view.get(&candidate).unwrap();
    assert!(!e.confirmed);
    assert!((e.score.value() - 0.5).abs() < 1e-4, "{e:?}");
}

#[tokio::test(start_paused = true)]
async fn slow_builtin_seed_joins_on_a_slow_link() {
    let (_dir, mut core) = subject(NOW);
    let mut net = Net::default();
    for n in 0..NODES {
        net.records.insert(id_of(n), record(n, NOW));
    }
    let seed = id_of(0);
    // Its answer takes longer than a bootstrap source's turn.
    net.ping_delay.insert(seed, Duration::from_secs(5));
    let builtin = vec![BootstrapEntry {
        id: seed,
        addr: net.records[&seed].addrs()[0],
    }];
    let report = sync(&mut core, &net, SyncOptions { builtin, ..opts() }).await;
    assert!(report.network_up, "{report:?}");
    let state = load(&mut core);
    let e = state.view.get(&seed).expect("seed in the view");
    assert!(e.confirmed && e.record.is_some(), "{e:?}");
    assert!(e.score.value() >= 0.5, "{e:?}");
}

// --- Dead sessions -----------------------------------------------------------

/// The best responsible of the message's mailbox, raised so that it is also
/// the best responsible of a session mailbox: fetched from, then deposited
/// on, in the same sync.
fn fetched_then_deposited(core: &mut Core) -> (NodeId, Vec<u8>) {
    let (bytes, m) = message(core);
    let sessions = core.watched_mailbox_groups(NOW).sessions;
    let mut state = load(core);
    let x = state
        .view
        .responsibles_by_score(&m, NOW)
        .into_iter()
        .find(|id| {
            sessions
                .iter()
                .any(|s| state.view.responsibles_by_score(s, NOW).contains(id))
        })
        .expect("a responsible of both");
    state.view.entries.get_mut(&x).unwrap().score = Score::new(0.9);
    state.save(core).unwrap();
    (x, bytes)
}

fn connects_to(calls: &[Call], id: NodeId) -> usize {
    connects(calls).into_iter().filter(|n| *n == id).count()
}

#[tokio::test(start_paused = true)]
async fn connection_stop_drops_the_session() {
    let (_dir, mut core, mut net) = setup();
    let (x, bytes) = fetched_then_deposited(&mut core);
    // The node cuts the connection in the middle of the fetch.
    net.truncate.insert(x, FetchStop::Connection);
    net.die_after_fetch.insert(x);
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    // The deposit went out on a new connection, and was accepted there.
    assert!(connects_to(&calls, x) >= 2, "{calls:?}");
    assert!(holders(&mut core, &bytes).contains(&x));
}

#[tokio::test(start_paused = true)]
async fn request_on_a_dead_kept_session_redials_once() {
    let (_dir, mut core, mut net) = setup();
    let (x, bytes) = fetched_then_deposited(&mut core);
    // A complete fetch, then the session dies unnoticed (idle timeout).
    net.die_after_fetch.insert(x);
    let before = score_of(&mut core, &x);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.polled_all_sessions, "{report:?}");
    let calls = net.calls();
    assert!(connects_to(&calls, x) >= 2, "{calls:?}");
    assert!(holders(&mut core, &bytes).contains(&x));
    // Never failed for its dead session.
    assert!(score_of(&mut core, &x) > before, "{before}");
}
