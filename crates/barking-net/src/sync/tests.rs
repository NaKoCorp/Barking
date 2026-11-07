use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;

use barking_packet::Kind;
use barking_proto::client::FetchResume;
use barking_proto::push::{ApnsEnv, RelayRef, SubKind, Subscription};

use barking_core::Core;
use tempfile::TempDir;

use super::*;
use crate::push::{PushConfig, PushState};
use crate::score::Score;
use crate::test_support::{id_of, record, subject, subject_with_ack, subject_with_ack_at};

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
    Subscribe(NodeId, MailboxId, SubKind),
    Unsubscribe(NodeId, MailboxId),
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
    /// Items served only to a re-read of this mailbox (alone, from its
    /// start).
    reread_items: HashMap<MailboxId, Vec<Vec<u8>>>,
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
    /// `refuse_deposit` refuses receipts too.
    refuse_acks: bool,
    /// Message deposits expiring after this date are refused with
    /// `TooFarInFuture`.
    max_expiry: Option<u64>,
    /// Fetches from these nodes time out (on any session).
    fail_fetch: HashSet<NodeId>,
    /// Connections to these nodes are refused (the node answers).
    refuse_connect: HashSet<NodeId>,
    /// The dialer finds no address for these nodes.
    no_address: HashSet<NodeId>,
    /// Connections to these nodes never complete.
    hang_connect: HashSet<NodeId>,
    /// A `Ping` to that node returns this record (someone else's).
    ping_record: HashMap<NodeId, NodeRecord>,
    /// Proof work of a message deposit; beyond the budget: `PowBudget`.
    pow_cost: u64,
    /// The session to that node dies right after any fetch (the node cut
    /// it, or it went idle): later requests on it fail as unreachable.
    die_after_fetch: HashSet<NodeId>,
    /// Sessions that died, by connection number.
    dead: Mutex<HashSet<usize>>,
    /// Page size a fetch from that node ends with (the link's).
    page_after: HashMap<NodeId, u32>,
    /// Nodes whose fetches end with that page size confirmed by a page
    /// timeout at a low throughput.
    page_confirmed: HashSet<NodeId>,
    /// Page size each fetch started from.
    pages: Mutex<Vec<(NodeId, u32)>>,
    /// Nodes that do not announce wake support in their `Hello`.
    no_wake: HashSet<NodeId>,
    /// Subscriptions on that node are refused with this reason.
    refuse_subscribe: HashMap<NodeId, ErrorReason>,
    /// Fetches honour `max_bytes`: the items beyond it are left out and the
    /// fetch stops with `FetchStop::ClientLimit`.
    honor_max_bytes: bool,
    /// Every fetch: node, `max_bytes` asked, bytes returned.
    fetch_bytes: Mutex<Vec<(NodeId, usize, usize)>>,
    /// Time each closing takes.
    close_delay: Duration,
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
            Some(r) if self.up(&id) => Ok(self.ping_record.get(&id).unwrap_or(r).clone()),
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
        if self.hang_connect.contains(&id) {
            std::future::pending::<()>().await;
        }
        if self.no_address.contains(&id) {
            Err(DialError::NoAddress)
        } else if self.refuse_connect.contains(&id) {
            Err(DialError::Refused(ErrorReason::NodeFull))
        } else if self.up(&id) {
            Ok(Conn { id, n })
        } else {
            Err(DialError::Unreachable)
        }
    }

    async fn close(&self, conn: Conn) {
        tokio::time::sleep(self.close_delay).await;
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
        page: &mut LinkPage,
    ) -> Result<FetchReply, DialError> {
        self.pages.lock().unwrap().push((session.id, page.bytes));
        if let Some(&p) = self.page_after.get(&session.id) {
            page.bytes = p;
        }
        page.confirmed = self.page_confirmed.contains(&session.id);
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
        if self.fail_fetch.contains(conn) {
            return Err(DialError::Timeout);
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
        if let [m] = mailboxes
            && positioned.is_empty()
        {
            items.extend(self.reread_items.get(m).cloned().unwrap_or_default());
        }
        let mut stop = stop;
        if self.honor_max_bytes {
            let mut total = 0usize;
            let all = items.len();
            items.retain(|i| {
                total += i.len();
                total <= _max_bytes
            });
            if items.len() < all && stop == FetchStop::Complete {
                stop = FetchStop::ClientLimit;
            }
        }
        let bytes = items.iter().map(Vec::len).sum();
        self.fetch_bytes
            .lock()
            .unwrap()
            .push((*conn, _max_bytes, bytes));
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
        let too_far = message
            && self.max_expiry.is_some_and(|max| {
                Packet::decode(packet).is_ok_and(|p| u64::from(p.expires_at) > max)
            });
        let result = match self.refuse_deposit.get(conn) {
            _ if too_far => Err(ErrorReason::TooFarInFuture),
            Some(reason) if message || self.refuse_acks => Err(*reason),
            _ => Ok(()),
        };
        DepositReply {
            outcome: Ok(DepositOutcome::Answered(result)),
            pow_spent: if message { self.pow_cost } else { 0 },
        }
    }
}

impl Subscriber for Net {
    fn wake_supported(&self, conn: &Conn) -> bool {
        !self.no_wake.contains(&conn.id)
    }

    async fn subscribe(
        &self,
        conn: &mut Conn,
        sub: &Subscription,
        pow_left: u64,
    ) -> SubscribeReply {
        self.log(Call::Subscribe(conn.id, sub.mailbox, sub.kind));
        if self.dead(conn) {
            return SubscribeReply {
                outcome: Err(DialError::Unreachable),
                pow_spent: 0,
            };
        }
        if self.pow_cost > pow_left {
            return SubscribeReply {
                outcome: Ok(DepositOutcome::PowBudget),
                pow_spent: 0,
            };
        }
        let result = match self.refuse_subscribe.get(&conn.id) {
            Some(reason) => Err(*reason),
            None => Ok(()),
        };
        SubscribeReply {
            outcome: Ok(DepositOutcome::Answered(result)),
            pow_spent: self.pow_cost,
        }
    }

    async fn unsubscribe(
        &self,
        conn: &mut Conn,
        mailbox: MailboxId,
        _cancel_secret: [u8; 32],
    ) -> Result<(), DialError> {
        self.log(Call::Unsubscribe(conn.id, mailbox));
        if self.dead(conn) {
            return Err(DialError::Unreachable);
        }
        Ok(())
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
        push: None,
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
    let groups = core.watched_mailbox_groups(NOW).unwrap();
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
    let groups = core.watched_mailbox_groups(NOW).unwrap();
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
}

#[tokio::test(start_paused = true)]
async fn state_saved_after_each_response() {
    let (_dir, mut core, mut net) = setup();
    net.position = 7;
    net.stall_deposit_from = Some(1);
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let wide = core.watched_mailbox_groups(NOW).unwrap().intro.len();
    // Every node truncates: no session mailbox is fetched in full.
    net.truncate = all_nodes(&net, FetchStop::Connection);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up && !report.polled_all_sessions);
    assert_eq!(core.watched_mailbox_groups(NOW).unwrap().intro.len(), wide);

    net.truncate.clear();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.polled_all_sessions);
    assert!(core.watched_mailbox_groups(NOW).unwrap().intro.len() < wide);
}

#[tokio::test(start_paused = true)]
async fn unreadable_watch_list_aborts_without_mark_polled() {
    use barking_core::store::{Queries, Store};
    let (dir, mut core, net) = setup();
    core.mark_polled(NOW - 5 * DAY).unwrap();
    let wide = core.watched_mailbox_groups(NOW).unwrap().intro.len();
    let raw = Store::open(&dir.path().join("bob.db"), &[2; 32]).unwrap();
    raw.conn()
        .execute_batch("ALTER TABLE sessions RENAME TO sessions_gone;")
        .unwrap();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.error.is_some());
    assert!(!report.polled_all_sessions);
    assert!(!net.calls().iter().any(|c| matches!(c, Call::Fetch(..))));
    // The poll date did not move: restored, the window is as wide as before.
    raw.conn()
        .execute_batch("ALTER TABLE sessions_gone RENAME TO sessions;")
        .unwrap();
    assert_eq!(core.watched_mailbox_groups(NOW).unwrap().intro.len(), wide);
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let intro = core.watched_mailbox_groups(NOW).unwrap().intro;
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

/// Bob's message sealed at `at` (an outbox packet), found by its expiry.
fn sealed_at(core: &mut Core, at: u64) -> Vec<u8> {
    use rand::SeedableRng;
    let to = core.contacts().unwrap()[0].fingerprint;
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);
    let sent = core.send_text(&to, "sealed", at, &mut rng).unwrap();
    let expires = u64::from(sent[0].expires_at);
    core.pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .find(|b| u64::from(Packet::decode(b).unwrap().expires_at) == expires)
        .unwrap()
}

fn deposits_of(net: &Net, bytes: &[u8]) -> usize {
    let h = content_hash(bytes);
    net.calls()
        .iter()
        .filter(|c| matches!(c, Call::Deposit(_, x) if *x == h))
        .count()
}

#[tokio::test(start_paused = true)]
async fn too_far_in_future_is_refused_not_retried_forever() {
    let (_dir, mut core, mut net) = setup();
    // The legacy case: a packet sealed with a 7-day expiry. Nodes refuse
    // any expiry beyond 25 h from their clock.
    net.max_expiry = Some(NOW + 25 * 3_600);
    let legacy = sealed_at(&mut core, NOW + 6 * DAY);
    let first = sync(&mut core, &net, opts()).await;
    assert!(first.refused >= 1);
    // It will never be accepted: out of the queue, not offered again.
    assert!(!core.pending_outbox(NOW).unwrap().contains(&legacy));
    let before = deposits_of(&net, &legacy);
    let second = sync(&mut core, &net, opts()).await;
    assert_eq!(deposits_of(&net, &legacy), before);
    assert_eq!(second.refused, 0);
}

#[tokio::test(start_paused = true)]
async fn one_skewed_node_refusal_keeps_the_packet() {
    let (_dir, mut core, mut net) = setup();
    let (bytes, m) = message(&mut core);
    let r = load(&mut core).view.responsibles_by_score(&m, NOW);
    // The best node's clock is behind: it refuses a normal 24 h packet.
    net.refuse_deposit.insert(r[0], ErrorReason::TooFarInFuture);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.refused >= 1);
    // Another node took it, and it stays queued until its receipt.
    assert_eq!(report.first_copies, 1);
    assert!(core.pending_outbox(NOW).unwrap().contains(&bytes));
    assert!(!holders(&mut core, &bytes).contains(&r[0]));
    assert!(!holders(&mut core, &bytes).is_empty());
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    let wide = core.watched_mailbox_groups(NOW).unwrap().intro.len();
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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
    assert!(core.watched_mailbox_groups(NOW).unwrap().intro.len() < wide);
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
async fn reread_items_are_recorded_in_the_route() {
    use barking_core::store::Direction;
    let (_dir, mut core, hello) = crate::test_support::subject_with_hello(NOW);
    let mut net = setup_with(&mut core);
    let (x, m, mine) = due_reread(&mut core);
    // The re-read serves Alice's message, and Bob's own reply (an audit of
    // what he deposited: not a step of its route).
    let mut items = hello;
    items.push(mine);
    net.reread_items.insert(m, items);
    sync(&mut core, &net, opts()).await;
    assert_eq!(rereads_of(&net.calls(), x, m).len(), 1);
    let alice = core.contacts().unwrap()[0].fingerprint;
    let rows = core.messages_with(&alice).unwrap();
    let row = |d| rows.iter().find(|r| r.direction == d).unwrap().id;
    let fetched = |row| -> Vec<Option<String>> {
        core.message_route(row)
            .unwrap()
            .into_iter()
            .filter(|e| e.step == RouteStep::Fetched)
            .map(|e| e.node)
            .collect()
    };
    assert_eq!(fetched(row(Direction::In)), [Some(short_id(&x))]);
    assert!(fetched(row(Direction::Out)).is_empty());
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
    run.answered(id_of(0));
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
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
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

#[tokio::test(start_paused = true)]
async fn page_size_reached_is_carried_to_the_next_sync() {
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
    let x = load(&mut core)
        .view
        .responsibles_by_score(&sessions[0], NOW)[0];
    // A slow link to x: its pages ended at 64 KiB, page timeouts
    // confirming it.
    net.page_after.insert(x, 64 << 10);
    net.page_confirmed.insert(x);
    sync(&mut core, &net, opts()).await;
    let first: Vec<u32> = net
        .pages
        .lock()
        .unwrap()
        .iter()
        .filter(|(n, _)| *n == x)
        .map(|(_, p)| *p)
        .collect();
    assert_eq!(first[0], barking_proto::client::FETCH_PAGE_SIZES[0]);
    assert_eq!(load(&mut core).page_bytes(&x), 64 << 10);
    net.pages.lock().unwrap().clear();
    net.page_after.clear();
    sync(&mut core, &net, opts()).await;
    let pages = net.pages.lock().unwrap().clone();
    let to_x: Vec<u32> = pages
        .iter()
        .filter(|(n, _)| *n == x)
        .map(|(_, p)| *p)
        .collect();
    assert_eq!(to_x.first(), Some(&(64 << 10)), "{pages:?}");
}

/// First page size each sync's fetches from `x` started from.
fn first_pages_to(net: &Net, x: NodeId) -> Option<u32> {
    let pages = std::mem::take(&mut *net.pages.lock().unwrap());
    pages.iter().find(|(n, _)| *n == x).map(|(_, p)| *p)
}

#[tokio::test(start_paused = true)]
async fn forced_page_shrink_recovers_across_syncs() {
    use barking_proto::client::FETCH_PAGE_SIZES;
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
    let x = load(&mut core)
        .view
        .responsibles_by_score(&sessions[0], NOW)[0];
    // One sync where x forced its pages down to 16 KiB, no page timeout
    // confirming it.
    net.page_after.insert(x, 16 << 10);
    sync(&mut core, &net, opts()).await;
    net.page_after.clear();
    assert_eq!(first_pages_to(&net, x), Some(FETCH_PAGE_SIZES[0]));
    // It doubles back at each sync, up to the default.
    let mut seen = Vec::new();
    for _ in 0..6 {
        seen.push(load(&mut core).page_bytes(&x));
        sync(&mut core, &net, opts()).await;
        assert_eq!(first_pages_to(&net, x), seen.last().copied());
    }
    assert_eq!(
        seen,
        [32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20]
    );
    assert_eq!(load(&mut core).page_bytes(&x), FETCH_PAGE_SIZES[0]);
}

#[tokio::test(start_paused = true)]
async fn page_size_confirmed_by_timeouts_stays() {
    let (_dir, mut core, mut net) = setup();
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
    let x = load(&mut core)
        .view
        .responsibles_by_score(&sessions[0], NOW)[0];
    // A slow link: each sync, page timeouts at a low throughput confirm
    // 16 KiB.
    net.page_after.insert(x, 16 << 10);
    net.page_confirmed.insert(x);
    for _ in 0..3 {
        sync(&mut core, &net, opts()).await;
        assert_eq!(load(&mut core).page_bytes(&x), 16 << 10);
    }
}

#[test]
fn slices_hold_twice_a_first_page() {
    use barking_proto::client::{FETCH_PAGE_SIZES, page_timeout};
    // The smallest page fits twice in every slice; the session slice takes
    // 256 KiB pages from the start.
    assert!(INTRO_FETCH_SLICE >= page_timeout(barking_proto::MIN_PAGE_BYTES) * 2);
    assert!(SESSION_FETCH_SLICE >= page_timeout(FETCH_PAGE_SIZES[1]) * 2);
}

// --- Nodes escaping the audit -----------------------------------------------

#[tokio::test(start_paused = true)]
async fn paced_fetch_counts_as_never_completing() {
    let (_dir, mut core, mut net) = setup();
    net.refuse_finds = true;
    net.truncate = all_nodes(&net, FetchStop::Paced);
    for _ in 0..UNAUDITED_SYNCS {
        sync(&mut core, &net, opts()).await;
    }
    let sessions = core.watched_mailbox_groups(NOW).unwrap().sessions;
    let node = load(&mut core)
        .view
        .responsibles_by_score(&sessions[0], NOW)[0];
    assert_eq!(load(&mut core).unaudited.get(&node), Some(&UNAUDITED_SYNCS));
}

#[tokio::test(start_paused = true)]
async fn paced_or_rate_limited_fetch_is_no_success() {
    let (_dir, mut core, mut net) = setup();
    // Lookups answered with a rate limit, deposits refused (both neutral):
    // the fetches alone could move the score.
    net.refuse_finds = true;
    for n in 0..NODES {
        net.refuse_deposit.insert(id_of(n), ErrorReason::NodeFull);
    }
    net.refuse_acks = true;
    net.truncate = all_nodes(&net, FetchStop::Paced);
    let before: Vec<f32> = (0..NODES).map(|n| score_of(&mut core, &id_of(n))).collect();
    sync(&mut core, &net, opts()).await;
    net.truncate = all_nodes(&net, FetchStop::RateLimited);
    sync(&mut core, &net, opts()).await;
    assert!(net.calls().iter().any(|c| matches!(c, Call::Fetch(..))));
    for (n, was) in before.iter().enumerate() {
        let after = score_of(&mut core, &id_of(n));
        assert!((after - was).abs() < 1e-4, "node {n}: {was} -> {after}");
    }
}

// --- Who answered, what counts as tried, what a down sync remembers ---------

/// The node a sync on `core`'s state dials first, found by a dry run; the
/// state is put back and the calls forgotten.
async fn first_dialled(core: &mut Core, net: &Net) -> NodeId {
    let saved = core
        .transport_state(crate::state::STATE_KEY)
        .unwrap()
        .unwrap();
    sync(core, net, opts()).await;
    let first = connects(&net.calls())[0];
    core.set_transport_state(crate::state::STATE_KEY, &saved)
        .unwrap();
    net.calls.lock().unwrap().clear();
    first
}

#[tokio::test(start_paused = true)]
async fn only_answering_node_is_not_failed_for_its_own_timeout() {
    let (_dir, mut core) = subject(NOW);
    let mut net = view_of(&mut core, &[0]);
    let x = id_of(0);
    // Its handshake answers, its fetch times out: no other node answered.
    net.fail_fetch.insert(x);
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.network_up);
    assert!(
        net.calls()
            .iter()
            .any(|c| matches!(c, Call::Fetch(n, ..) if *n == x))
    );
    assert!(
        score_of(&mut core, &x) >= 0.5,
        "{}",
        score_of(&mut core, &x)
    );
}

#[tokio::test(start_paused = true)]
async fn refused_connection_proves_the_network_up() {
    let (_dir, mut core, mut net) = setup();
    let first = first_dialled(&mut core, &net).await;
    // The first node dialled refuses, every other one is down.
    net.down = net
        .records
        .keys()
        .copied()
        .filter(|n| *n != first)
        .collect();
    net.refuse_connect.insert(first);
    let report = sync(&mut core, &net, opts()).await;
    assert_eq!(connects(&net.calls())[0], first);
    assert!(report.network_up, "{report:?}");
    // The others failed while a node answered.
    let dead = connects(&net.calls())[1];
    assert!(score_of(&mut core, &dead) < 0.5);
    assert!((score_of(&mut core, &first) - 0.5).abs() < 1e-4);
}

#[tokio::test(start_paused = true)]
async fn no_address_is_not_a_try() {
    let (_dir, mut core, mut net) = setup();
    // No session can be opened (no address), lookups still answer.
    net.no_address = net.records.keys().copied().collect();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.maintenance_done, "{report:?}");
}

#[tokio::test(start_paused = true)]
async fn down_sync_remembers_only_dial_failures() {
    let (_dir, mut core, mut net) = setup();
    let first = first_dialled(&mut core, &net).await;
    net.down = net.records.keys().copied().collect();
    net.no_address.insert(first);
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.network_up && !report.maintenance_done, "{report:?}");
    assert_eq!(connects(&net.calls())[0], first);
    let state = load(&mut core);
    assert_eq!(state.down_failed.len(), DOWN_AFTER_FAILURES as usize);
    assert!(!state.down_failed.contains_key(&first));
}

#[tokio::test(start_paused = true)]
async fn deadline_during_the_probe_is_not_network_down() {
    let (_dir, mut core, mut net) = setup();
    net.down = net.records.keys().copied().collect();
    // The probe's node, added by hand, never completes its handshake: the
    // sync's deadline cuts it.
    let (manual, addr) = (id_of(10), net.records[&id_of(10)].addrs()[0]);
    net.hang_connect.insert(manual);
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            manual_nodes: vec![(manual, addr)],
            deadline: Duration::from_secs(60),
            ..opts()
        },
    )
    .await;
    assert!(!report.network_up);
    assert!(net.calls().contains(&Call::Connect(manual)));
    assert!(load(&mut core).down_failed.is_empty());
}

#[tokio::test(start_paused = true)]
async fn candidate_answering_with_another_record_gains_nothing() {
    let (_dir, mut core, mut net) = setup();
    let candidate = id_of(3);
    let mut state = load(&mut core);
    state.view.entries.get_mut(&candidate).unwrap().confirmed = false;
    state.save(&mut core).unwrap();
    net.ping_record.insert(candidate, record(4, NOW));
    let mut run = run_on(&mut core, &net);
    run.confirm_candidates().await;
    run.save();
    drop(run);
    assert_eq!(net.calls(), vec![Call::Ping(candidate)]);
    let state = load(&mut core);
    let e = state.view.get(&candidate).unwrap();
    assert!(!e.confirmed);
    assert!((e.score.value() - 0.5).abs() < 1e-4, "{e:?}");
}

#[tokio::test(start_paused = true)]
async fn unreadable_state_is_reported() {
    let (_dir, mut core, net) = setup();
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.state_reset && !report.state_unsaved);
    core.set_transport_state(crate::state::STATE_KEY, b"not a state")
        .unwrap();
    let report = sync(&mut core, &net, opts()).await;
    assert!(report.state_reset, "{report:?}");
    // Read again, the empty state saved since is fine.
    let report = sync(&mut core, &net, opts()).await;
    assert!(!report.state_reset);
}

// --- Wake subscriptions (push stage) -----------------------------------------

fn push_config() -> PushConfig {
    PushConfig {
        relay: RelayRef {
            host: "relay.example".to_string(),
            port: 4433,
            id: id_of(10),
        },
        seal_public: [9; 32],
        seal_key_id: 1,
        apns_token: vec![0xAB; 32],
        env: ApnsEnv::Sandbox,
    }
}

fn push_opts() -> SyncOptions {
    SyncOptions {
        push: Some(push_config()),
        ..opts()
    }
}

fn push_state(core: &Core) -> PushState {
    PushState::load(core).unwrap()
}

fn subscribes(calls: &[Call]) -> Vec<(NodeId, MailboxId)> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Subscribe(n, m, _) => Some((*n, *m)),
            _ => None,
        })
        .collect()
}

/// The subscriptions of `kind` sent, in call order.
fn subscribes_of(calls: &[Call], kind: SubKind) -> Vec<(NodeId, MailboxId)> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Subscribe(n, m, k) if *k == kind => Some((*n, *m)),
            _ => None,
        })
        .collect()
}

fn unsubscribes(calls: &[Call]) -> Vec<(NodeId, MailboxId)> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Unsubscribe(n, m) => Some((*n, *m)),
            _ => None,
        })
        .collect()
}

/// My mailboxes over the push horizon, nearest day first.
fn horizon(core: &Core) -> Vec<(MailboxId, u32)> {
    let today = barking_core::mailbox::day_of(NOW);
    let days: Vec<u32> = (today..=today + crate::push::HORIZON_DAYS).collect();
    core.own_mailboxes(&days).unwrap()
}

#[tokio::test(start_paused = true)]
async fn push_stage_runs_after_maintenance_and_saves_state() {
    let (_dir, mut core, net) = setup();
    let report = sync(&mut core, &net, push_opts()).await;
    let calls = net.calls();
    let subs = subscribes_of(&calls, SubKind::Messages);
    let wanted = horizon(&core);
    assert!(!wanted.is_empty());
    assert_eq!(
        subs.len(),
        wanted.len() * crate::push::WAKE_NODES,
        "{subs:?}"
    );
    // Plus the mailbox where Bob's reply awaits its ack.
    let awaited = core.awaited_ack_mailboxes(NOW).unwrap();
    let acks = subscribes_of(&calls, SubKind::Acks);
    assert_eq!(acks.len(), awaited.len() * crate::push::WAKE_NODES);
    assert_eq!(report.subscribed, subs.len() + acks.len());
    assert_eq!(report.unsubscribed, 0);
    // After the lookups of the maintenance, before the closings.
    let finds = positions_of(&calls, |c| matches!(c, Call::Find(..)));
    let firsts = positions_of(&calls, |c| matches!(c, Call::Subscribe(..)));
    let closes = positions_of(&calls, |c| matches!(c, Call::Close(..)));
    assert!(report.maintenance_done);
    assert!(finds.last().unwrap() < &firsts[0]);
    assert!(firsts.last().unwrap() < &closes[0]);
    // Nearest day first: the first subscriptions are for today's mailboxes.
    assert_eq!(subs[0].1, wanted[0].0);
    // Each one went to a responsible of its mailbox, and is kept.
    let st = push_state(&core);
    assert_eq!(
        st.config_hash,
        Some(PushState::config_hash_of(&push_config()))
    );
    let view = load(&mut core).view;
    for (mailbox, day) in &wanted {
        let b = &st.subs[&(*mailbox, SubKind::Messages)];
        assert_eq!(b.day, *day);
        assert_eq!(b.nodes.len(), crate::push::WAKE_NODES);
        let responsibles = view.responsibles(mailbox, NOW);
        assert!(b.nodes.iter().all(|(n, _)| responsibles.contains(n)));
    }
    // A second sync has nothing left to do.
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, push_opts()).await;
    assert!(subscribes(&net.calls()).is_empty());
    assert_eq!((report.subscribed, report.unsubscribed), (0, 0));
}

#[tokio::test(start_paused = true)]
async fn push_stage_subscribes_awaited_ack_mailboxes() {
    let (_dir, mut core, ack) = subject_with_ack(NOW);
    let mut net = setup_with(&mut core);
    // Bob's reply awaits Alice's receipt in its mailbox.
    let awaited = core.awaited_ack_mailboxes(NOW).unwrap();
    assert_eq!(awaited.len(), 1);
    let (reply, day) = awaited[0];
    sync(&mut core, &net, push_opts()).await;
    let calls = net.calls();
    let acks = subscribes_of(&calls, SubKind::Acks);
    assert_eq!(acks.len(), crate::push::WAKE_NODES, "{acks:?}");
    assert!(acks.iter().all(|(_, m)| *m == reply));
    // Not one of Bob's mailboxes: never subscribed for messages.
    assert!(
        !subscribes_of(&calls, SubKind::Messages)
            .iter()
            .any(|(_, m)| *m == reply)
    );
    let st = push_state(&core);
    let b = &st.subs[&(reply, SubKind::Acks)];
    assert_eq!(b.day, day);
    let holders: BTreeSet<NodeId> = b.nodes.iter().map(|(n, _)| *n).collect();
    assert_eq!(holders.len(), crate::push::WAKE_NODES);
    // The receipt arrives: the next sync fetches it, then cancels the acks
    // subscriptions of the mailbox, and only those.
    net.mailbox_items.entry(reply).or_default().push(ack);
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, push_opts()).await;
    assert!(
        report
            .received
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::AckReceived { .. }))
    );
    assert!(core.awaited_ack_mailboxes(NOW).unwrap().is_empty());
    let calls = net.calls();
    let cancelled: BTreeSet<NodeId> = unsubscribes(&calls)
        .iter()
        .filter(|(_, m)| *m == reply)
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(cancelled, holders);
    assert_eq!(report.unsubscribed, holders.len());
    assert!(subscribes(&calls).is_empty());
    let st = push_state(&core);
    assert!(!st.subs.contains_key(&(reply, SubKind::Acks)));
    assert!(st.subs.keys().all(|(_, k)| *k == SubKind::Messages));
}

#[tokio::test(start_paused = true)]
async fn no_push_config_sends_nothing_when_state_empty() {
    let (_dir, mut core, net) = setup();
    let report = sync(&mut core, &net, opts()).await;
    let calls = net.calls();
    assert!(subscribes(&calls).is_empty() && unsubscribes(&calls).is_empty());
    assert_eq!((report.subscribed, report.unsubscribed), (0, 0));
    assert_eq!(
        core.transport_state(crate::push::PUSH_STATE_KEY).unwrap(),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn push_off_unsubscribes_everything() {
    let (_dir, mut core, net) = setup();
    let first = sync(&mut core, &net, push_opts()).await;
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, opts()).await;
    assert_eq!(unsubscribes(&net.calls()).len(), first.subscribed);
    assert_eq!(report.unsubscribed, first.subscribed);
    assert!(subscribes(&net.calls()).is_empty());
    let st = push_state(&core);
    assert!(st.subs.is_empty() && st.config_hash.is_none());
}

#[tokio::test(start_paused = true)]
async fn unsupported_node_is_noted_and_skipped() {
    // No node announces wake support: nothing is sent, every node the plan
    // picked is left out.
    let (_dir, mut core, mut net) = setup();
    net.no_wake = net.records.keys().copied().collect();
    let report = sync(&mut core, &net, push_opts()).await;
    assert!(subscribes(&net.calls()).is_empty());
    assert_eq!(report.subscribed, 0);
    let st = push_state(&core);
    assert!(!st.no_wake.is_empty());
    assert!(st.subs.values().all(|b| b.nodes.is_empty()));

    // Every node refuses with `Unsupported`: each is asked once, then left
    // out for the rest of the stage.
    let (_dir, mut core, mut net) = setup();
    for n in 0..NODES {
        net.refuse_subscribe
            .insert(id_of(n), ErrorReason::Unsupported);
    }
    let report = sync(&mut core, &net, push_opts()).await;
    let subs = subscribes(&net.calls());
    let asked: HashSet<NodeId> = subs.iter().map(|(n, _)| *n).collect();
    assert!(!asked.is_empty());
    assert_eq!(subs.len(), asked.len(), "{subs:?}");
    assert_eq!(report.subscribed, 0);
    let st = push_state(&core);
    assert!(asked.iter().all(|n| st.no_wake.contains_key(n)));

    // The next sync leaves them out of the plan altogether.
    net.calls.lock().unwrap().clear();
    sync(&mut core, &net, push_opts()).await;
    assert!(
        subscribes(&net.calls())
            .iter()
            .all(|(n, _)| !asked.contains(n))
    );
}

#[tokio::test(start_paused = true)]
async fn rate_limited_stops_the_stage() {
    let (_dir, mut core, mut net) = setup();
    for n in 0..NODES {
        net.refuse_subscribe
            .insert(id_of(n), ErrorReason::RateLimited);
    }
    let report = sync(&mut core, &net, push_opts()).await;
    assert_eq!(subscribes(&net.calls()).len(), 1);
    assert_eq!(report.subscribed, 0);
    // No node is left out for a rate limit.
    assert!(push_state(&core).no_wake.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pow_budget_exhausted_stops_the_stage() {
    let (_dir, mut core, mut net) = setup();
    // Enough for the first copy and two subscriptions, not more.
    net.pow_cost = 10;
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            pow_budget: 50,
            ..push_opts()
        },
    )
    .await;
    let spent_on_deposits = 10 * (report.first_copies + report.extra_copies) as u64;
    let expected = ((50 - spent_on_deposits) / 10) as usize;
    assert_eq!(report.subscribed, expected);
    assert_eq!(subscribes(&net.calls()).len(), expected + 1);
    assert_eq!(
        push_state(&core)
            .subs
            .values()
            .map(|b| b.nodes.len())
            .sum::<usize>(),
        expected
    );
}

#[tokio::test(start_paused = true)]
async fn over_deadline_skips_the_stage() {
    let (_dir, mut core, mut net) = setup();
    net.deposit_delay = Duration::from_secs(1);
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            deadline: Duration::from_millis(2500),
            ..push_opts()
        },
    )
    .await;
    assert!(subscribes(&net.calls()).is_empty());
    assert_eq!(report.subscribed, 0);
    assert_eq!(
        core.transport_state(crate::push::PUSH_STATE_KEY).unwrap(),
        None
    );
}

/// Replaces `core`'s view by entries without any record: the 11 test
/// nodes known by hand at their address, plus `extra` more, all confirmed.
fn recordless_view(core: &mut Core, net: &Net, extra: u8) {
    let mut state = NetState::new(true);
    for (id, r) in &net.records {
        state.view.add_manual(*id, r.addrs()[0], NOW);
        state.view.confirm(id, NOW);
    }
    for i in 0..extra {
        let id = NodeId([0xF0 ^ i; 32]);
        state
            .view
            .add_manual(id, crate::test_support::addr(9, 9, i).into(), NOW);
        state.view.confirm(&id, NOW);
    }
    state.save(core).unwrap();
}

#[tokio::test(start_paused = true)]
async fn cold_start_view_without_records_skips_the_stage_but_push_off_cancels() {
    let (_dir, mut core, net) = setup();
    let first = sync(&mut core, &net, push_opts()).await;
    assert!(first.subscribed > 0);
    let before = push_state(&core);
    // Cold start: 23 entries, none with a record (more than `SMALL_VIEW`:
    // the size of the view is no proof of a ranking).
    recordless_view(&mut core, &net, 12);
    assert!(load(&mut core).view.len() > crate::SMALL_VIEW);
    // Push on, same configuration or a new token: nothing is sent, the
    // state stays.
    let new_token = SyncOptions {
        push: Some(PushConfig {
            apns_token: vec![0xCD; 32],
            ..push_config()
        }),
        ..opts()
    };
    for o in [push_opts(), new_token] {
        net.calls.lock().unwrap().clear();
        let report = sync(&mut core, &net, o).await;
        let calls = net.calls();
        assert!(subscribes(&calls).is_empty() && unsubscribes(&calls).is_empty());
        assert_eq!((report.subscribed, report.unsubscribed), (0, 0));
        assert_eq!(push_state(&core), before);
        assert!(
            !load(&mut core)
                .view
                .entries()
                .any(|(_, e)| e.record.is_some())
        );
    }
    // Push off on the same view: the subscriptions are cancelled all the same.
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, opts()).await;
    assert_eq!(unsubscribes(&net.calls()).len(), first.subscribed);
    assert_eq!(report.unsubscribed, first.subscribed);
    let st = push_state(&core);
    assert!(st.subs.is_empty() && st.config_hash.is_none());
}

#[tokio::test(start_paused = true)]
async fn token_change_unsubscribes_then_resubscribes_in_one_sync() {
    let (_dir, mut core, net) = setup();
    let first = sync(&mut core, &net, push_opts()).await;
    let old = push_state(&core);
    let cfg = PushConfig {
        apns_token: vec![0xCD; 32],
        ..push_config()
    };
    net.calls.lock().unwrap().clear();
    let report = sync(
        &mut core,
        &net,
        SyncOptions {
            push: Some(cfg.clone()),
            ..opts()
        },
    )
    .await;
    let calls = net.calls();
    let unsubs = positions_of(&calls, |c| matches!(c, Call::Unsubscribe(..)));
    let subs = positions_of(&calls, |c| matches!(c, Call::Subscribe(..)));
    assert_eq!(unsubs.len(), first.subscribed);
    assert_eq!(subs.len(), first.subscribed);
    assert!(unsubs.last().unwrap() < &subs[0]);
    assert_eq!(
        (report.unsubscribed, report.subscribed),
        (first.subscribed, first.subscribed)
    );
    // `apply_config` ran: the new hash, fresh collapse labels and secrets.
    let st = push_state(&core);
    assert_eq!(st.config_hash, Some(PushState::config_hash_of(&cfg)));
    assert_eq!(st.subs.len(), old.subs.len());
    for (m, b) in &st.subs {
        assert_eq!(b.nodes.len(), crate::push::WAKE_NODES);
        assert_ne!(b.collapse, old.subs[m].collapse);
        assert!(b.nodes.iter().all(|n| !old.subs[m].nodes.contains(n)));
    }
}

#[tokio::test(start_paused = true)]
async fn unreached_unsubscribe_is_kept_and_retried() {
    let (_dir, mut core, mut net) = setup();
    let first = sync(&mut core, &net, push_opts()).await;
    let before = push_state(&core);
    let holder = before.subs.values().next().unwrap().nodes[0].0;
    let held = |st: &PushState| -> usize {
        st.subs
            .values()
            .filter(|b| b.nodes.iter().any(|(n, _)| *n == holder))
            .count()
    };
    let holder_subs = held(&before);
    assert!(holder_subs > 0);
    // An expired subscription on the same node: never worth keeping.
    let mut st = before.clone();
    let today = barking_core::mailbox::day_of(NOW);
    st.subs.insert(
        (MailboxId([0xEE; 16]), SubKind::Messages),
        crate::push::BoxSubs {
            day: today - 2,
            collapse: [1; 16],
            nodes: vec![(holder, [3; 32])],
        },
    );
    st.save(&mut core).unwrap();
    // Push off while the node is unreachable: everything else is
    // cancelled, its subscriptions are kept, the configuration is cleared.
    net.down.insert(holder);
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, opts()).await;
    assert_eq!(report.unsubscribed, first.subscribed - holder_subs);
    let st = push_state(&core);
    assert_eq!(st.config_hash, None);
    assert_eq!(held(&st), holder_subs);
    assert!(
        st.subs
            .values()
            .all(|b| b.nodes == vec![(holder, b.nodes[0].1)])
    );
    assert!(
        !st.subs
            .contains_key(&(MailboxId([0xEE; 16]), SubKind::Messages))
    );
    let kept = core
        .transport_state(crate::push::PUSH_STATE_KEY)
        .unwrap()
        .unwrap();

    // The node is back, push still off: the next sync cancels them.
    net.down.clear();
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, opts()).await;
    assert_eq!(report.unsubscribed, holder_subs);
    assert!(unsubscribes(&net.calls()).iter().all(|(n, _)| *n == holder));
    assert!(push_state(&core).subs.is_empty());

    // Or push comes back on: they are cancelled first, then the mailboxes
    // subscribed afresh.
    core.set_transport_state(crate::push::PUSH_STATE_KEY, &kept)
        .unwrap();
    net.calls.lock().unwrap().clear();
    let report = sync(&mut core, &net, push_opts()).await;
    let calls = net.calls();
    let unsubs = positions_of(&calls, |c| matches!(c, Call::Unsubscribe(..)));
    let subs = positions_of(&calls, |c| matches!(c, Call::Subscribe(..)));
    assert_eq!(
        (unsubs.len(), report.unsubscribed),
        (holder_subs, holder_subs)
    );
    assert!(unsubs.last().unwrap() < &subs[0]);
    assert_eq!(report.subscribed, first.subscribed);
}

#[tokio::test(start_paused = true)]
async fn push_stage_leaves_scores_and_log_alone() {
    let (_dir, mut core, mut net) = setup();
    // Some nodes unreachable, others refusing: nothing of it is scored.
    net.down.insert(id_of(0));
    net.refuse_connect.insert(id_of(1));
    net.refuse_subscribe
        .insert(id_of(2), ErrorReason::MailboxFull);
    net.refuse_subscribe
        .insert(id_of(3), ErrorReason::Unsupported);
    let scores =
        |core: &mut Core| -> Vec<f32> { (0..NODES).map(|n| score_of(core, &id_of(n))).collect() };
    let before = scores(&mut core);
    let log_before = core.transparency_log(10_000).unwrap().len();
    let cfg = push_config();
    let mut run = run_on(&mut core, &net);
    run.push_stage(Some(&cfg)).await;
    assert!(run.report.subscribed > 0);
    run.push_stage(None).await;
    assert!(run.report.unsubscribed > 0);
    run.save();
    drop(run);
    assert!(subscribes(&net.calls()).iter().any(|(n, _)| *n == id_of(2)));
    assert_eq!(scores(&mut core), before);
    assert_eq!(core.transparency_log(10_000).unwrap().len(), log_before);
}

#[tokio::test(start_paused = true)]
async fn failed_node_is_skipped_for_the_rest_of_the_stage() {
    let (_dir, mut core, mut net) = setup();
    let wanted = horizon(&core);
    let view = load(&mut core).view;
    let x = view.responsibles_by_score(&wanted[0].0, NOW)[0];
    // Its connections are refused: dialled at most once in the whole sync.
    net.refuse_connect.insert(x);
    let report = sync(&mut core, &net, push_opts()).await;
    let calls = net.calls();
    assert!(!subscribes(&calls).iter().any(|(n, _)| *n == x));
    assert!(calls.iter().filter(|c| **c == Call::Connect(x)).count() <= 1);
    assert!(report.subscribed > 0);
    // Not left out: a node that cannot be reached is tried again next sync.
    assert!(!push_state(&core).no_wake.contains_key(&x));
}

#[tokio::test(start_paused = true)]
async fn full_refusals_fall_through_to_the_next_responsible() {
    let (_dir, mut core, mut net) = setup();
    let wanted = horizon(&core);
    let ranked = load(&mut core)
        .view
        .responsibles_by_score(&wanted[0].0, NOW);
    let (node_full, mailbox_full) = (ranked[0], ranked[1]);
    net.refuse_subscribe
        .insert(node_full, ErrorReason::NodeFull);
    net.refuse_subscribe
        .insert(mailbox_full, ErrorReason::MailboxFull);
    sync(&mut core, &net, push_opts()).await;
    let st = push_state(&core);
    // Each mailbox is completed, in the same run, by the next responsibles.
    let view = load(&mut core).view;
    for (mailbox, _) in &wanted {
        let expected: BTreeSet<NodeId> = view
            .responsibles_by_score(mailbox, NOW)
            .into_iter()
            .filter(|n| *n != node_full && *n != mailbox_full)
            .take(crate::push::WAKE_NODES)
            .collect();
        let got: BTreeSet<NodeId> = st.subs[&(*mailbox, SubKind::Messages)]
            .nodes
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(got, expected, "{mailbox:?}");
    }
    // A full node is left out as a whole; a full mailbox only for that
    // mailbox, in that run.
    assert!(st.no_wake.contains_key(&node_full));
    assert!(!st.no_wake.contains_key(&mailbox_full));
    let calls = net.calls();
    let to = |node: NodeId| {
        subscribes(&calls)
            .iter()
            .filter(|(n, _)| *n == node)
            .count()
    };
    assert_eq!(to(node_full), 1, "left out after its first NodeFull");
    assert!(to(mailbox_full) > 1, "tried again for the other mailboxes");
}

// ---- Quick sync (notification extension) ----

fn quick_opts() -> QuickOptions {
    QuickOptions {
        deadline: QUICK_DEADLINE,
        builtin: Vec::new(),
        allow_private: true,
        now: Some(NOW),
    }
}

/// My own mailboxes of yesterday and today, sorted.
fn quick_mailboxes(core: &Core) -> Vec<MailboxId> {
    let today = barking_core::mailbox::day_of(NOW);
    let mut out: Vec<MailboxId> = core
        .own_mailboxes(&[today - 1, today])
        .unwrap()
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    out.sort_unstable_by_key(|m| m.0);
    out
}

/// Every (node, mailbox) pair fetched, in call order.
fn fetched_pairs(calls: &[Call]) -> Vec<(NodeId, MailboxId)> {
    calls
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(n, mbs, _) => Some(mbs.iter().map(|m| (*n, *m)).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn best_responsible(state: &NetState, m: &MailboxId) -> NodeId {
    state.order_responsibles(state.view.responsibles_by_score(m, NOW))[0]
}

#[tokio::test(start_paused = true)]
async fn quick_sync_fetches_today_and_yesterday_only() {
    let (_dir, mut core, mut net) = setup();
    let wanted = quick_mailboxes(&core);
    assert!(!wanted.is_empty());
    let groups = core.watched_mailbox_groups(NOW).unwrap();
    let watched: HashSet<MailboxId> = groups
        .sessions
        .iter()
        .chain(&groups.intro)
        .copied()
        .collect();
    assert!(watched.len() > wanted.len(), "the full sync watches more");
    let state = load(&mut core);
    // The best responsible of the first mailbox truncates: no second
    // responsible for it. The best one of another mailbox is down: its
    // mailboxes move to the next responsible.
    let truncating = best_responsible(&state, &wanted[0]);
    net.truncate.insert(truncating, FetchStop::Connection);
    let down = wanted
        .iter()
        .map(|m| best_responsible(&state, m))
        .find(|n| *n != truncating)
        .expect("two distinct best responsibles");
    net.down.insert(down);

    let report = quick_sync(&mut core, &net, quick_opts()).await;
    let calls = net.calls();
    let pairs = fetched_pairs(&calls);
    let fetched: BTreeSet<[u8; 16]> = pairs.iter().map(|(_, m)| m.0).collect();
    // Plus the mailbox where Bob's reply awaits its ack.
    let awaited = core.awaited_ack_mailboxes(NOW).unwrap();
    let expected: BTreeSet<[u8; 16]> = wanted
        .iter()
        .chain(awaited.iter().map(|(m, _)| m))
        .map(|m| m.0)
        .collect();
    assert_eq!(fetched, expected);
    for m in &wanted {
        let ranked = state.order_responsibles(state.view.responsibles_by_score(m, NOW));
        let from: Vec<NodeId> = pairs
            .iter()
            .filter(|(_, x)| x == m)
            .map(|(n, _)| *n)
            .collect();
        if ranked[0] == down {
            // Failure of the best: the next one only.
            assert!(calls.contains(&Call::Connect(down)));
            assert_eq!(from, vec![ranked[1]], "{m:?}");
        } else {
            // Served (truncated or not) by the best: nobody else.
            assert_eq!(from, vec![ranked[0]], "{m:?}");
        }
    }
    assert!(report.network_up);
    assert!(report.error.is_none());
}

#[tokio::test(start_paused = true)]
async fn quick_sync_fetches_awaited_ack_mailboxes() {
    let (_dir, mut core, ack) = subject_with_ack(NOW);
    let mut net = setup_with(&mut core);
    let awaited = core.awaited_ack_mailboxes(NOW).unwrap();
    assert_eq!(awaited.len(), 1);
    let reply = awaited[0].0;
    assert!(!quick_mailboxes(&core).contains(&reply));
    // A receipt wake-up: Alice's receipt waits in the reply's mailbox.
    net.mailbox_items.entry(reply).or_default().push(ack);
    let report = quick_sync(&mut core, &net, quick_opts()).await;
    assert!(fetched_pairs(&net.calls()).iter().any(|(_, m)| *m == reply));
    assert!(
        report
            .received
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::AckReceived { .. }))
    );
    assert!(core.awaited_ack_mailboxes(NOW).unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn quick_sync_deposits_receipts_but_no_messages() {
    let (_dir, mut core, mut net) = setup();
    net.pow_cost = 0;
    let messages: Vec<[u8; 32]> = core
        .pending_outbox(NOW)
        .unwrap()
        .iter()
        .filter(|b| Packet::decode(b).is_ok_and(|p| p.kind == Kind::Message))
        .map(|b| content_hash(b))
        .collect();
    assert!(!messages.is_empty());
    let report = quick_sync(&mut core, &net, quick_opts()).await;
    let calls = net.calls();
    let deposited: Vec<[u8; 32]> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Deposit(_, h) => Some(*h),
            _ => None,
        })
        .collect();
    assert_eq!(report.acks_deposited, 1);
    assert_eq!((report.first_copies, report.extra_copies), (0, 0));
    assert!(!deposited.is_empty());
    assert!(deposited.iter().all(|h| !messages.contains(h)));
    // After the fetches.
    let last_fetch = positions_of(&calls, |c| matches!(c, Call::Fetch(..)));
    let deposits = positions_of(&calls, |c| matches!(c, Call::Deposit(..)));
    assert!(last_fetch.last().unwrap() < &deposits[0]);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_skips_audit_maintenance_and_push() {
    let (_dir, mut core, mut net) = setup();
    let wanted = quick_mailboxes(&core);
    let mut state = load(&mut core);
    // A node one sync away from its unaudited failure, and best responsible
    // of a mailbox; it cuts every fetch.
    let node = best_responsible(&state, &wanted[0]);
    state.unaudited.insert(node, UNAUDITED_SYNCS - 1);
    state.save(&mut core).unwrap();
    net.truncate.insert(node, FetchStop::Connection);

    let report = quick_sync(&mut core, &net, quick_opts()).await;
    let calls = net.calls();
    // No lookup, no ping, no subscription.
    assert!(!calls.iter().any(|c| matches!(
        c,
        Call::Find(..) | Call::Ping(..) | Call::Subscribe(..) | Call::Unsubscribe(..)
    )));
    assert!(!report.maintenance_done);
    assert_eq!((report.subscribed, report.unsubscribed), (0, 0));
    assert_eq!(
        core.transport_state(crate::push::PUSH_STATE_KEY).unwrap(),
        None
    );
    // No cross-check nor audit re-read: each mailbox fetched once.
    let pairs = fetched_pairs(&calls);
    let mut seen = HashSet::new();
    assert!(pairs.iter().all(|(_, m)| seen.insert(m.0)), "{pairs:?}");
    // No loss audit: neither the unaudited count nor the audit dates move.
    let after = load(&mut core);
    assert_eq!(after.unaudited.get(&node), Some(&(UNAUDITED_SYNCS - 1)));
    for (n, m) in &pairs {
        assert!(after.audit_due(n, m, NOW, AUDIT_EVERY_SECS));
        assert!(after.crosscheck_due(n, m, NOW, CROSSCHECK_EVERY_SECS));
    }
    assert!(report.network_up);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_never_marks_polled() {
    let (_dir, mut core, net) = setup();
    core.mark_polled(NOW - 5 * DAY).unwrap();
    let wide = core.watched_mailbox_groups(NOW).unwrap().intro.len();
    let report = quick_sync(&mut core, &net, quick_opts()).await;
    assert!(report.network_up && report.mailboxes_polled > 0);
    assert!(!report.polled_all_sessions);
    assert_eq!(core.watched_mailbox_groups(NOW).unwrap().intro.len(), wide);
    // A full sync afterwards does mark it.
    sync(&mut core, &net, opts()).await;
    assert!(core.watched_mailbox_groups(NOW).unwrap().intro.len() < wide);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_respects_its_deadline() {
    let (_dir, mut core, mut net) = setup();
    let wanted = quick_mailboxes(&core);
    net.fetch_delay = Duration::from_secs(10);
    net.deposit_delay = Duration::from_secs(10);
    // The closing comes out of the 25 s too.
    net.close_delay = CLOSE_TIMEOUT;
    net.position = 7;
    let start = Instant::now();
    let report = quick_sync(&mut core, &net, quick_opts()).await;
    assert!(start.elapsed() <= QUICK_DEADLINE, "{:?}", start.elapsed());
    // Some fetches went through, not all of them, and their positions are
    // saved.
    assert!(report.mailboxes_polled > 0, "{report:?}");
    assert!(report.mailboxes_polled < wanted.len(), "{report:?}");
    let state = load(&mut core);
    let saved = fetched_pairs(&net.calls())
        .iter()
        .any(|(n, m)| state.resume(n, &[*m]).seen.get(&m.0) == Some(&7));
    assert!(saved);
}

#[test]
fn quick_options_default() {
    let o = QuickOptions::default();
    assert_eq!(o.deadline, QUICK_DEADLINE);
    assert_eq!(QUICK_DEADLINE, Duration::from_secs(25));
    assert_eq!(o.builtin, builtin_bootstrap());
    assert!(!o.allow_private);
    assert_eq!(o.now, None);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_leaves_page_sizes_to_grow_back_in_full_syncs() {
    let (_dir, mut core, net) = setup();
    let mut state = load(&mut core);
    let slow = id_of(0);
    state.set_page_bytes(&slow, 64 << 10);
    state.save(&mut core).unwrap();
    quick_sync(&mut core, &net, quick_opts()).await;
    let after = load(&mut core).page_bytes(&slow);
    assert_eq!(after, 64 << 10);
    sync(&mut core, &net, opts()).await;
    assert!(load(&mut core).page_bytes(&slow) > 64 << 10);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_caps_the_bytes_of_a_flooded_intro() {
    let (_dir, mut core, mut net) = setup();
    net.honor_max_bytes = true;
    let today = barking_core::mailbox::day_of(NOW);
    let days = [today - 1, today];
    let intro = core.own_intro_mailboxes(&days);
    assert_eq!(intro.len(), 2);
    let sessions: Vec<MailboxId> = quick_mailboxes(&core)
        .into_iter()
        .filter(|m| !intro.contains(m))
        .collect();
    assert!(!sessions.is_empty());
    // 16 MiB of junk in each introduction mailbox, served by every node.
    for m in &intro {
        net.mailbox_items
            .insert(*m, vec![vec![0xEE; 64 << 10]; 256]);
    }
    let report = quick_sync(&mut core, &net, quick_opts()).await;
    let fetches = net.fetch_bytes.lock().unwrap().clone();
    let calls = net.calls();
    let total: usize = fetches.iter().map(|(_, _, b)| b).sum();
    assert!(total <= QUICK_FETCH_BYTES, "{total}");
    assert!(fetches.iter().all(|(_, max, _)| *max <= QUICK_FETCH_BYTES));
    // Every fetch of an introduction mailbox asked for its small budget at
    // most, and they got no more than it together.
    let mut intro_bytes = 0;
    let mut n = 0;
    for c in &calls {
        if let Call::Fetch(_, mbs, _) = c {
            let (_, max, bytes) = fetches[n];
            n += 1;
            if mbs.iter().any(|m| intro.contains(m)) {
                assert!(mbs.iter().all(|m| intro.contains(m)), "intro apart");
                assert!(max <= QUICK_INTRO_BYTES);
                intro_bytes += bytes;
            }
        }
    }
    assert!(intro_bytes > 0 && intro_bytes <= QUICK_INTRO_BYTES);
    assert!(report.intro_partial);
    // The session mailboxes were fetched first, and in full.
    let pairs = fetched_pairs(&calls);
    let first_intro = pairs.iter().position(|(_, m)| intro.contains(m)).unwrap();
    for m in &sessions {
        let at = pairs
            .iter()
            .position(|(_, x)| x == m)
            .expect("session fetched");
        assert!(at < first_intro);
    }
    assert!(report.mailboxes_polled >= sessions.len());
    // A truncated introduction mailbox is not fetched again elsewhere (and
    // once the budget is spent, not at all).
    for m in &intro {
        assert!(pairs.iter().filter(|(_, x)| x == m).count() <= 1);
    }
}

#[tokio::test(start_paused = true)]
async fn quick_sync_caps_the_bytes_of_a_flooded_session() {
    let (_dir, mut core, mut net) = setup();
    net.honor_max_bytes = true;
    let today = barking_core::mailbox::day_of(NOW);
    let intro = core.own_intro_mailboxes(&[today - 1, today]);
    for m in quick_mailboxes(&core) {
        if !intro.contains(&m) {
            net.mailbox_items.insert(m, vec![vec![0xEE; 64 << 10]; 64]);
        }
    }
    quick_sync(&mut core, &net, quick_opts()).await;
    let fetches = net.fetch_bytes.lock().unwrap().clone();
    let total: usize = fetches.iter().map(|(_, _, b)| b).sum();
    assert!(total > 0 && total <= QUICK_FETCH_BYTES, "{total}");
    // Spent: nothing left for the introductions.
    assert!(fetches.iter().all(|(_, max, _)| *max <= QUICK_FETCH_BYTES));
}

#[tokio::test(start_paused = true)]
async fn quick_sync_bootstraps_only_from_an_empty_view() {
    // Not empty, but no node confirmed (below MIN_REACHABLE): no bootstrap.
    let (_dir, mut core) = subject(NOW);
    let mut state = NetState::new(true);
    let mut net = Net::default();
    for n in 0..NODES {
        let r = record(n, NOW);
        state.view.insert(r.clone(), NOW);
        net.records.insert(id_of(n), r);
    }
    state.save(&mut core).unwrap();
    let seed = id_of(0);
    let builtin = vec![BootstrapEntry {
        id: seed,
        addr: net.records[&seed].addrs()[0],
    }];
    quick_sync(
        &mut core,
        &net,
        QuickOptions {
            builtin: builtin.clone(),
            ..quick_opts()
        },
    )
    .await;
    assert!(
        !net.calls()
            .iter()
            .any(|c| matches!(c, Call::Ping(..) | Call::Find(..))),
        "{:?}",
        net.calls()
    );

    // Empty: bootstrap from the built-in list.
    let (_dir2, mut core) = subject(NOW);
    let mut net = Net::default();
    for n in 0..NODES {
        net.records.insert(id_of(n), record(n, NOW));
    }
    let report = quick_sync(
        &mut core,
        &net,
        QuickOptions {
            builtin,
            ..quick_opts()
        },
    )
    .await;
    assert!(
        net.calls()
            .iter()
            .any(|c| matches!(c, Call::Ping(id) | Call::Find(id, _) if *id == seed))
    );
    assert!(report.view_size > 0);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_moves_on_from_a_rate_limited_best_responsible() {
    let (_dir, mut core, mut net) = setup();
    let wanted = quick_mailboxes(&core);
    let state = load(&mut core);
    let ranked = state.order_responsibles(state.view.responsibles_by_score(&wanted[0], NOW));
    net.rate_limit_fetch.insert(ranked[0]);
    quick_sync(&mut core, &net, quick_opts()).await;
    let from: Vec<NodeId> = fetched_pairs(&net.calls())
        .into_iter()
        .filter(|(_, m)| *m == wanted[0])
        .map(|(n, _)| n)
        .collect();
    assert_eq!(from, vec![ranked[0], ranked[1]]);
}

#[tokio::test(start_paused = true)]
async fn quick_sync_makes_no_fallback_lookup_after_not_responsible() {
    use rand::SeedableRng;
    let (dir, mut core, mut net) = setup();
    // A second receipt, for Carol.
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
    // The next day: another receipt mailbox.
    for p in carol.send_text(&fb, "first", NOW + DAY, &mut rng).unwrap() {
        core.receive(&p.encode(), "test", NOW + DAY, &mut rng)
            .unwrap();
    }
    let acks: Vec<(MailboxId, [u8; 32])> = core
        .pending_outbox(NOW)
        .unwrap()
        .iter()
        .filter_map(|b| Some((Packet::decode(b).ok()?, content_hash(b))))
        .filter(|(p, _)| p.kind == Kind::Ack)
        .map(|(p, h)| (p.mailbox, h))
        .collect();
    assert_eq!(acks.len(), 2);
    assert_ne!(acks[0].0, acks[1].0);
    // Receipts are planned in the order of the send queue, once per plan.
    // The first one's two best responsibles answer `NotResponsible`; the
    // second one's best rate-limits in between, so that the plan is redone
    // and the first receipt tries its second responsible.
    // A responsible of the second mailbox only, raised to be its best.
    let mut state = load(&mut core);
    let (ma, mc) = (acks[0].0, acks[1].0);
    let only_c = state
        .view
        .responsibles(&mc, NOW)
        .into_iter()
        .find(|n| !state.view.responsibles(&ma, NOW).contains(n))
        .expect("a responsible of the second mailbox only");
    state.view.entries.get_mut(&only_c).unwrap().score = Score::new(0.9);
    state.save(&mut core).unwrap();
    let ranked = |m: &MailboxId| state.order_responsibles(state.view.responsibles_by_score(m, NOW));
    let ha = acks[0].1;
    let refusing = [ranked(&acks[0].0)[0], ranked(&acks[0].0)[1]];
    let limiting = ranked(&acks[1].0)[0];
    assert!(!refusing.contains(&limiting));
    net.refuse_acks = true;
    for n in refusing {
        net.refuse_deposit.insert(n, ErrorReason::NotResponsible);
    }
    net.refuse_deposit
        .insert(limiting, ErrorReason::RateLimited);
    quick_sync(&mut core, &net, quick_opts()).await;
    let calls = net.calls();
    // Refused by both: a full sync would look the mailbox up here.
    for n in refusing {
        assert!(calls.contains(&Call::Deposit(n, ha)), "{calls:?}");
    }
    assert!(!calls.iter().any(|c| matches!(c, Call::Find(..))));
}

// ---- Deposits noted at once, and the failure verdict (spec §15.5) ----

/// Short id of the node that took the expired reply.
const DEPOSIT_NODE: &str = "K7QX2M4A";

/// Bob's reply, sealed a day and 20 minutes ago, deposited, and expired
/// 20 minutes ago without its ack; and Alice's ack for it (encoded),
/// sealed 5 minutes before that expiry: still on the network.
struct Expired {
    _dir: TempDir,
    core: Core,
    net: Net,
    alice: barking_core::identity::Fingerprint,
    reply: Vec<u8>,
    id: PacketId,
    mailbox: MailboxId,
    ack: Vec<u8>,
}

fn expired_reply() -> Expired {
    expired_reply_with(NOW - DAY - 1_200, NOW - 1_500, None, None)
}

/// Bob's reply sealed at `sealed` (expired by `NOW`), Alice's ack sealed at
/// `ack_at`. The delivery records as its first node the short id of the
/// responsible of rank `noted_on` (`None`: a node outside the test
/// network); the deposit ledger says the responsible of rank `ledger_on`
/// accepted it (`None`: nobody).
fn expired_reply_with(
    sealed: u64,
    ack_at: u64,
    noted_on: Option<usize>,
    ledger_on: Option<usize>,
) -> Expired {
    let (dir, mut core, ack) = subject_with_ack_at(sealed, ack_at);
    let reply = core
        .pending_outbox(sealed)
        .unwrap()
        .into_iter()
        .find(|b| Packet::decode(b).unwrap().kind == Kind::Message)
        .unwrap();
    let packet = Packet::decode(&reply).unwrap();
    assert!(u64::from(packet.expires_at) < NOW);
    let net = setup_with(&mut core);
    let r = load(&mut core)
        .view
        .responsibles_by_score(&packet.mailbox, NOW);
    let node = noted_on.map_or_else(|| DEPOSIT_NODE.to_string(), |rank| short_id(&r[rank]));
    if let Some(rank) = ledger_on {
        accepted_by(&mut core, r[rank], &reply);
    }
    core.record_deposit(packet.id, &node, sealed).unwrap();
    let alice = core.contacts().unwrap()[0].fingerprint;
    assert_eq!(
        core.awaiting_verdict(NOW).unwrap(),
        vec![(packet.id, packet.mailbox)]
    );
    assert!(core.awaited_ack_mailboxes(NOW).unwrap().is_empty());
    Expired {
        _dir: dir,
        core,
        net,
        alice,
        reply,
        id: packet.id,
        mailbox: packet.mailbox,
        ack,
    }
}

fn reply_status(e: &Expired) -> barking_core::store::MessageStatus {
    e.core
        .messages_with(&e.alice)
        .unwrap()
        .into_iter()
        .find(|m| m.body == "hi")
        .unwrap()
        .status
}

fn reply_row(e: &Expired) -> i64 {
    e.core
        .messages_with(&e.alice)
        .unwrap()
        .into_iter()
        .find(|m| m.body == "hi")
        .unwrap()
        .id
}

#[tokio::test(start_paused = true)]
async fn verdict_when_a_responsible_answers_without_packet_or_ack() {
    use barking_core::store::MessageStatus;
    let mut e = expired_reply();
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert!(
        fetched_pairs(&e.net.calls())
            .iter()
            .any(|(_, m)| *m == e.mailbox)
    );
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed, vec![(e.alice, reply_row(&e))]);
    assert!(e.core.awaiting_verdict(NOW).unwrap().is_empty());
    // The verdict mailbox does not hold back the poll record.
    assert!(report.polled_all_sessions);
}

#[tokio::test(start_paused = true)]
async fn no_verdict_without_an_answering_responsible() {
    use barking_core::store::MessageStatus;
    let mut e = expired_reply();
    let state = load(&mut e.core);
    let responsibles = state.view.responsibles_by_score(&e.mailbox, NOW);
    // Every responsible answers but cuts its pages short.
    for n in &responsibles {
        e.net.truncate.insert(*n, FetchStop::Paced);
    }
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert!(report.network_up);
    assert!(
        fetched_pairs(&e.net.calls())
            .iter()
            .any(|(_, m)| *m == e.mailbox)
    );
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    // Every responsible fails.
    e.net.truncate.clear();
    for n in &responsibles {
        e.net.fail_fetch.insert(*n);
    }
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    // Every responsible is down: the quick sync gives no verdict either.
    e.net.fail_fetch.clear();
    for n in &responsibles {
        e.net.down.insert(*n);
    }
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    assert_eq!(
        e.core.awaiting_verdict(NOW).unwrap(),
        vec![(e.id, e.mailbox)]
    );
}

#[tokio::test(start_paused = true)]
async fn no_verdict_while_a_node_still_returns_the_packet() {
    use barking_core::store::MessageStatus;
    let mut e = expired_reply();
    // A node whose clock is behind still serves my own packet.
    e.net.mailbox_items.insert(e.mailbox, vec![e.reply.clone()]);
    // Positions saved past the packet must not hide it: the verdict
    // mailbox is read from its start.
    let mut state = load(&mut e.core);
    let mut resume = FetchResume::default();
    resume.seen.insert(e.mailbox.0, 99);
    for n in state.view.responsibles_by_score(&e.mailbox, NOW) {
        state.set_positions(&n, &[e.mailbox], &resume);
    }
    state.save(&mut e.core).unwrap();
    // The node's expiry wake-up: a quick sync, then a full one.
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    let calls = e.net.calls();
    let verdict_fetches: Vec<&Call> = calls
        .iter()
        .filter(|c| matches!(c, Call::Fetch(_, mbs, _) if mbs.contains(&e.mailbox)))
        .collect();
    assert!(verdict_fetches.len() >= 2);
    for c in verdict_fetches {
        let Call::Fetch(_, _, positioned) = c else {
            unreachable!()
        };
        assert!(!positioned.contains(&e.mailbox), "{c:?}");
    }
    // Once the network lets it go, the verdict comes.
    e.net.mailbox_items.clear();
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn late_ack_found_after_expiry_makes_received() {
    use barking_core::store::MessageStatus;
    let mut e = expired_reply();
    e.net.mailbox_items.insert(e.mailbox, vec![e.ack.clone()]);
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::Received);
    assert!(report.failed.is_empty());
    assert!(e.core.awaiting_verdict(NOW).unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn quick_sync_fetches_awaiting_verdict_mailboxes() {
    use barking_core::store::MessageStatus;
    let mut e = expired_reply();
    // The node's expiry wake-up: a quick sync gives the verdict.
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert!(
        fetched_pairs(&e.net.calls())
            .iter()
            .any(|(_, m)| *m == e.mailbox)
    );
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed, vec![(e.alice, reply_row(&e))]);
}

#[tokio::test(start_paused = true)]
async fn deposit_recorded_before_finish() {
    use barking_core::store::MessageStatus;
    let (_dir, mut core, mut net) = setup();
    let alice = core.contacts().unwrap()[0].fingerprint;
    let status = |core: &Core| {
        core.messages_with(&alice)
            .unwrap()
            .into_iter()
            .find(|m| m.body == "hi")
            .unwrap()
            .status
    };
    assert_eq!(status(&core), MessageStatus::Pending);
    // The receipt, then the reply's first copy, are accepted; the next
    // deposit never gets an answer and the app is killed mid-sync.
    net.stall_deposit_from = Some(2);
    let cut = tokio::time::timeout(Duration::from_secs(60), sync(&mut core, &net, opts())).await;
    assert!(
        cut.is_err(),
        "the sync is cut in the middle of the deposits"
    );
    assert_eq!(status(&core), MessageStatus::OnNetwork);
    // `finish` never ran: no deposit was logged.
    let logged = core.transparency_log(100).unwrap();
    assert!(
        !logged
            .iter()
            .any(|(_, ev)| matches!(ev, TransparencyEvent::NodeDeposit { .. })),
        "{logged:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn too_far_in_future_packet_is_not_delivered() {
    use barking_core::store::MessageStatus;
    let (_dir, mut core, mut net) = setup();
    net.max_expiry = Some(NOW + 25 * 3_600);
    sealed_at(&mut core, NOW + 6 * DAY);
    let alice = core.contacts().unwrap()[0].fingerprint;
    let report = sync(&mut core, &net, opts()).await;
    let sealed = core
        .messages_with(&alice)
        .unwrap()
        .into_iter()
        .find(|m| m.body == "sealed")
        .unwrap();
    assert_eq!(sealed.status, MessageStatus::NotDelivered);
    assert_eq!(report.failed, vec![(alice, sealed.id)]);
}

#[tokio::test(start_paused = true)]
async fn verdict_needs_the_accepting_node_or_two_responsibles() {
    use barking_core::store::MessageStatus;
    // Deposited on the second responsible: the best one never held it.
    let mut e = expired_reply_with(NOW - DAY - 1_200, NOW - 1_500, Some(1), Some(1));
    let r = load(&mut e.core)
        .view
        .responsibles_by_score(&e.mailbox, NOW);
    assert!(r.len() >= 3);
    let accepting = r[1];
    // Only the best responsible answers, empty: no verdict.
    for n in &r[1..] {
        e.net.fail_fetch.insert(*n);
    }
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert!(fetched_pairs(&e.net.calls()).contains(&(r[0], e.mailbox)));
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    // The accepting node answers: verdict, asked first.
    e.net.fail_fetch.remove(&accepting);
    let before = e.net.calls().len();
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed.len(), 1);
    let first = e.net.calls()[before..]
        .iter()
        .find_map(|c| match c {
            Call::Fetch(n, mbs, _) if mbs.contains(&e.mailbox) => Some(*n),
            _ => None,
        })
        .unwrap();
    assert_eq!(first, accepting);

    // Deposited on a node gone from the view: two responsibles that answer
    // in full give the verdict.
    let mut e = expired_reply();
    let r = load(&mut e.core)
        .view
        .responsibles_by_score(&e.mailbox, NOW);
    for n in &r[2..] {
        e.net.fail_fetch.insert(*n);
    }
    e.net.fail_fetch.insert(r[1]);
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    e.net.fail_fetch.remove(&r[1]);
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn ack_found_a_day_after_expiry_makes_received() {
    use barking_core::store::MessageStatus;
    // Alice acked right away; Bob missed the wake-up and syncs a day after
    // both expired. The node keeps the ack a day more (`ACK_GRACE_SECS`).
    let sealed = NOW - 2 * DAY + 1_200;
    let mut e = expired_reply_with(sealed, sealed + 60, None, None);
    assert!(u64::from(Packet::decode(&e.ack).unwrap().expires_at) < NOW - DAY + 1_800);
    e.net.mailbox_items.insert(e.mailbox, vec![e.ack.clone()]);
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::Received);
    assert!(report.failed.is_empty());
}

/// A verdict mailbox flooded with junk.
fn flood_verdict_mailbox(e: &mut Expired) {
    e.net.honor_max_bytes = true;
    e.net
        .mailbox_items
        .insert(e.mailbox, vec![vec![0u8; 64 << 10]; 200]);
}

/// Bytes served to the fetches asking for `m`.
fn bytes_for(net: &Net, m: MailboxId) -> usize {
    let calls = net.calls();
    let fetches = calls.iter().filter_map(|c| match c {
        Call::Fetch(_, mbs, _) => Some(mbs),
        _ => None,
    });
    net.fetch_bytes
        .lock()
        .unwrap()
        .iter()
        .zip(fetches)
        .filter(|(_, mbs)| mbs.contains(&m))
        .map(|((_, _, b), _)| *b)
        .sum()
}

#[tokio::test(start_paused = true)]
async fn verdict_fetch_comes_after_sessions_within_its_own_budget() {
    let mut e = expired_reply();
    flood_verdict_mailbox(&mut e);
    let sessions = e.core.watched_mailbox_groups(NOW).unwrap().sessions;
    assert!(!sessions.contains(&e.mailbox));
    let report = sync(&mut e.core, &e.net, opts()).await;
    // The session fetches got their whole budget.
    assert!(report.polled_all_sessions, "{report:?}");
    let calls = e.net.calls();
    let fetches: Vec<&Vec<MailboxId>> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(_, mbs, _) => Some(mbs),
            _ => None,
        })
        .collect();
    let first_verdict = fetches
        .iter()
        .position(|mbs| mbs.contains(&e.mailbox))
        .unwrap();
    for (i, mbs) in fetches.iter().enumerate() {
        if mbs.contains(&e.mailbox) {
            assert_eq!(mbs.len(), 1, "never grouped: {mbs:?}");
        } else if mbs.iter().any(|m| sessions.contains(m)) {
            assert!(i < first_verdict, "sessions first");
        }
    }
    let verdict_bytes = bytes_for(&e.net, e.mailbox);
    assert!(
        verdict_bytes > 0 && verdict_bytes <= INTRO_FETCH_BYTES,
        "{verdict_bytes}"
    );

    // Quick sync: after my own mailboxes, within the introductions' budget.
    let mut e = expired_reply();
    flood_verdict_mailbox(&mut e);
    let own = quick_mailboxes(&e.core);
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert!(report.error.is_none());
    let pairs = fetched_pairs(&e.net.calls());
    let first_verdict = pairs.iter().position(|(_, m)| *m == e.mailbox).unwrap();
    let last_own = pairs.iter().rposition(|(_, m)| own.contains(m)).unwrap();
    assert!(last_own < first_verdict, "{pairs:?}");
    let verdict_bytes = bytes_for(&e.net, e.mailbox);
    assert!(
        verdict_bytes > 0 && verdict_bytes <= QUICK_INTRO_BYTES,
        "{verdict_bytes}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_shared_short_id_is_not_the_accepting_node() {
    use barking_core::store::MessageStatus;
    // The ledger says the second responsible accepted the reply; the
    // delivery's short id is the best one's (a node sharing the prefix).
    let mut e = expired_reply_with(NOW - DAY - 1_200, NOW - 1_500, Some(0), Some(1));
    let r = load(&mut e.core)
        .view
        .responsibles_by_score(&e.mailbox, NOW);
    for n in &r[1..] {
        e.net.fail_fetch.insert(*n);
    }
    // Only the best one answers, empty: it is not the accepting node.
    let report = sync(&mut e.core, &e.net, opts()).await;
    assert!(fetched_pairs(&e.net.calls()).contains(&(r[0], e.mailbox)));
    assert_eq!(reply_status(&e), MessageStatus::OnNetwork);
    assert!(report.failed.is_empty());
    // The node the ledger names answers: verdict. Its ledger entry
    // survived the deposit stages of the first sync.
    e.net.fail_fetch.remove(&r[1]);
    let report = quick_sync(&mut e.core, &e.net, quick_opts()).await;
    assert_eq!(reply_status(&e), MessageStatus::NotDelivered);
    assert_eq!(report.failed.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn session_stage_resumes_a_mailbox_awaiting_a_verdict() {
    // Bob's reply expired awaiting its verdict; a later message in the same
    // session mailbox (sealed the same day) still awaits its ack.
    let mut e = expired_reply();
    let day_start = barking_core::mailbox::day_of(NOW - DAY - 1_200) as u64 * DAY;
    let later = day_start + DAY - 1;
    let mut rng = rand::rng();
    let sent = e
        .core
        .send_text(&e.alice, "same box", later, &mut rng)
        .unwrap();
    assert_eq!(sent[0].mailbox, e.mailbox);
    assert!(u64::from(sent[0].expires_at) > NOW);
    let sessions = e.core.watched_mailbox_groups(NOW).unwrap().sessions;
    assert!(sessions.contains(&e.mailbox));
    let mut state = load(&mut e.core);
    let mut resume = FetchResume::default();
    resume.seen.insert(e.mailbox.0, 99);
    for n in state.view.responsibles_by_score(&e.mailbox, NOW) {
        state.set_positions(&n, &[e.mailbox], &resume);
    }
    state.save(&mut e.core).unwrap();
    sync(&mut e.core, &e.net, opts()).await;
    let fetches: Vec<(Vec<MailboxId>, bool)> = e
        .net
        .calls()
        .iter()
        .filter_map(|c| match c {
            Call::Fetch(_, mbs, positioned) if mbs.contains(&e.mailbox) => {
                Some((mbs.clone(), positioned.contains(&e.mailbox)))
            }
            _ => None,
        })
        .collect();
    // The session stage resumes it, within its group.
    assert!(fetches[0].1, "{fetches:?}");
    // The verdict stage reads it alone, from its start.
    assert!(
        fetches
            .iter()
            .any(|(mbs, positioned)| mbs == &vec![e.mailbox] && !positioned),
        "{fetches:?}"
    );
}
