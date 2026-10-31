use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;

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
    Find(NodeId),
    Connect(NodeId),
    Fetch(NodeId, Vec<MailboxId>),
    Deposit(NodeId, [u8; 32]),
    Close(NodeId),
}

/// In-memory network of the test nodes; every call is logged.
#[derive(Default)]
struct Net {
    records: HashMap<NodeId, NodeRecord>,
    /// Unreachable nodes.
    down: HashSet<NodeId>,
    /// Nodes whose fetch is always truncated.
    truncate: HashSet<NodeId>,
    /// `FindNode` answered with a refusal (neutral for the score).
    refuse_finds: bool,
    /// Position given to every fetched mailbox (0: none).
    position: u64,
    /// Time each deposit takes.
    deposit_delay: Duration,
    /// Deposits from this one on (0-based) never get an answer.
    stall_deposit_from: Option<usize>,
    calls: Mutex<Vec<Call>>,
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
        async move { r }
    }

    fn find_node(
        &self,
        id: NodeId,
        _addrs: &[SocketAddr],
        _target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send {
        self.log(Call::Find(id));
        let r = if !self.up(&id) {
            Err(DialError::Unreachable)
        } else if self.refuse_finds {
            Err(DialError::Refused(ErrorReason::RateLimited))
        } else {
            Ok(Vec::new())
        };
        async move { r }
    }
}

impl Connector for Net {
    type Conn = NodeId;

    async fn connect(&self, id: NodeId, _addrs: &[SocketAddr]) -> Result<NodeId, DialError> {
        self.log(Call::Connect(id));
        if self.up(&id) {
            Ok(id)
        } else {
            Err(DialError::Unreachable)
        }
    }

    async fn close(&self, conn: NodeId) {
        self.log(Call::Close(conn));
    }
}

impl Fetcher for Net {
    async fn fetch(
        &self,
        conn: &mut NodeId,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        _max_bytes: usize,
        _slice: Duration,
    ) -> Result<FetchReply, DialError> {
        self.log(Call::Fetch(*conn, mailboxes.to_vec()));
        if self.position > 0 {
            for m in mailboxes {
                resume.seen.insert(m.0, self.position);
            }
        }
        Ok(FetchReply::Items {
            items: Vec::new(),
            complete: !self.truncate.contains(conn),
        })
    }
}

impl Depositor for Net {
    async fn deposit(&self, conn: &mut NodeId, packet: &[u8], _pow_left: u64) -> DepositReply {
        let n = {
            let mut calls = self.calls.lock().unwrap();
            let n = calls
                .iter()
                .filter(|c| matches!(c, Call::Deposit(..)))
                .count();
            calls.push(Call::Deposit(*conn, content_hash(packet)));
            n
        };
        if self.stall_deposit_from.is_some_and(|from| n >= from) {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.deposit_delay).await;
        DepositReply {
            outcome: Ok(DepositOutcome::Answered(Ok(()))),
            pow_spent: 0,
        }
    }
}

/// Bob's core, whose saved view holds the 11 test nodes, all confirmed,
/// and the network that serves them.
fn setup() -> (TempDir, Core, Net) {
    let (dir, mut core) = subject(NOW);
    let mut state = NetState::new(true);
    let mut net = Net::default();
    for n in 0..NODES {
        let r = record(n, NOW);
        state.view.insert(r.clone(), NOW);
        state.view.confirm(&id_of(n), NOW);
        net.records.insert(id_of(n), r);
    }
    state.save(&mut core).unwrap();
    (dir, core, net)
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
            Call::Fetch(n, mbs) if mbs.iter().all(|m| group.contains(m)) => {
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
    assert!(!calls.iter().any(|c| matches!(c, Call::Find(_))));
    assert!(fetches_of(&calls, &groups.intro).is_empty());
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
    net.truncate.insert(r[1]);
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
    net.truncate = net.records.keys().copied().collect();
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
    net.truncate = net.records.keys().copied().collect();
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
