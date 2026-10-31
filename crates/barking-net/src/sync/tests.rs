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
    /// Nodes whose fetch is always truncated.
    truncate: HashSet<NodeId>,
    /// A fetch asking for one of these mailboxes is truncated.
    truncate_mailbox: HashSet<MailboxId>,
    /// Nodes whose fetch answers `RateLimited`.
    rate_limit_fetch: HashSet<NodeId>,
    /// Items every fetch from that node returns.
    items: HashMap<NodeId, Vec<Vec<u8>>>,
    /// Time each fetch takes.
    fetch_delay: Duration,
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
        let positioned = mailboxes
            .iter()
            .filter(|m| resume.seen.get(&m.0).is_some_and(|s| *s > 0))
            .copied()
            .collect();
        self.log(Call::Fetch(*conn, mailboxes.to_vec(), positioned));
        tokio::time::sleep(self.fetch_delay).await;
        if self.rate_limit_fetch.contains(conn) {
            return Ok(FetchReply::RateLimited);
        }
        if self.position > 0 {
            for m in mailboxes {
                resume.seen.insert(m.0, self.position);
            }
        }
        let truncated = self.truncate.contains(conn)
            || mailboxes.iter().any(|m| self.truncate_mailbox.contains(m));
        Ok(FetchReply::Items {
            items: self.items.get(conn).cloned().unwrap_or_default(),
            complete: !truncated,
        })
    }
}

impl Depositor for Net {
    async fn deposit(&self, conn: &mut NodeId, packet: &[u8], pow_left: u64) -> DepositReply {
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
    // Read from the start (no position sent), and the loss is seen.
    assert_eq!(fetches_for(&net.calls(), x, m), vec![false]);
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
    net.truncate_mailbox.insert(m);
    sync(&mut core, &net, opts()).await;
    assert!(!fetches_for(&net.calls(), x, m)[0]);
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
    net.truncate_mailbox.insert(m2);
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
    net.truncate = net.records.keys().copied().collect();
    net.fetch_delay = SESSION_FETCH_SLICE + Duration::from_secs(10);
    sync(&mut core, &net, opts()).await;
    assert!(load(&mut core).unaudited.is_empty());
}

#[tokio::test(start_paused = true)]
async fn one_failure_per_node_per_sync() {
    let (_dir, mut core, mut net) = setup();
    let x = id_of(0);
    net.down.insert(x);
    // The connection fails, then every lookup and fallback to it fails too.
    sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    assert!(
        calls
            .iter()
            .filter(|c| matches!(c, Call::Connect(n) | Call::Find(n, _) if *n == x))
            .count()
            >= 2
    );
    assert!((score_of(&mut core, &x) - 0.4).abs() < 1e-4);
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
