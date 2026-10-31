use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::Rng;

use super::*;
use crate::ScoreEvent;
use crate::test_support;

const NOW: u64 = 1_800_000_000;

/// In-memory network: every node knows every other one and answers a
/// `FindNode` with its 20 closest to the target.
struct MemNet {
    nodes: Vec<(NodeId, NodeRecord)>,
    down: HashSet<NodeId>,
    /// Nodes whose answer never comes.
    stall: HashSet<NodeId>,
    pings: Mutex<Vec<NodeId>>,
    finds: Mutex<Vec<NodeId>>,
}

impl MemNet {
    fn new(nodes: Vec<(NodeId, NodeRecord)>) -> MemNet {
        MemNet {
            nodes,
            down: HashSet::new(),
            stall: HashSet::new(),
            pings: Mutex::new(Vec::new()),
            finds: Mutex::new(Vec::new()),
        }
    }

    /// `n` nodes with keys drawn at runtime (no puzzle), each in its own /24.
    fn random(n: usize, seed: u64) -> MemNet {
        let mut rng = StdRng::seed_from_u64(seed);
        let nodes = (0..n)
            .map(|i| {
                let mut key = [0; 32];
                rng.fill_bytes(&mut key);
                let addr = format!("11.{}.{}.1:4433", i / 256, i % 256);
                let record = NodeRecord::sign(
                    &SigningKey::from_bytes(&key),
                    Some(addr.parse().unwrap()),
                    None,
                    NOW,
                );
                let id = NodeId::from_public_key(
                    &ed25519_dalek::VerifyingKey::from_bytes(&record.public_key).unwrap(),
                );
                (id, record)
            })
            .collect();
        MemNet::new(nodes)
    }

    fn record(&self, id: &NodeId) -> Option<NodeRecord> {
        self.nodes
            .iter()
            .find(|(n, _)| n == id)
            .map(|(_, r)| r.clone())
    }

    fn pings(&self) -> Vec<NodeId> {
        self.pings.lock().unwrap().clone()
    }

    fn finds(&self) -> Vec<NodeId> {
        self.finds.lock().unwrap().clone()
    }

    fn closest(&self, target: &[u8; 32], n: usize) -> Vec<NodeId> {
        let mut ids: Vec<NodeId> = self.nodes.iter().map(|(id, _)| *id).collect();
        ids.sort_by_key(|id| distance(&id.0, target));
        ids.truncate(n);
        ids
    }
}

impl Dialer for MemNet {
    fn ping(
        &self,
        id: NodeId,
        _addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<NodeRecord, DialError>> + Send {
        self.pings.lock().unwrap().push(id);
        let answer = match self.record(&id) {
            Some(r) if !self.down.contains(&id) => Ok(r),
            _ => Err(DialError::Unreachable),
        };
        stalling(self.stall.contains(&id), answer)
    }

    fn find_node(
        &self,
        id: NodeId,
        _addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send {
        self.finds.lock().unwrap().push(id);
        let answer = if self.record(&id).is_none() || self.down.contains(&id) {
            Err(DialError::Unreachable)
        } else {
            let mut others: Vec<&(NodeId, NodeRecord)> =
                self.nodes.iter().filter(|(n, _)| *n != id).collect();
            others.sort_by_key(|(n, _)| distance(&n.0, &target));
            Ok(others
                .into_iter()
                .take(20)
                .map(|(_, r)| r.clone())
                .collect())
        };
        stalling(self.stall.contains(&id), answer)
    }
}

/// `answer` at once, or never when `stall`.
async fn stalling<T>(stall: bool, answer: T) -> T {
    if stall {
        std::future::pending::<()>().await;
    }
    answer
}

/// Runs a future on a runtime whose clock is paused: it jumps ahead whenever
/// every task waits, so timeouts cost no real time.
fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(future)
}

/// Runs `future` and returns its output with the (virtual) time it took.
fn timed<F: Future>(future: F) -> (F::Output, Duration) {
    block_on(async {
        let start = tokio::time::Instant::now();
        let out = future.await;
        (out, start.elapsed())
    })
}

/// View that accepts runtime keys (no puzzle) and private addresses.
fn test_view() -> View {
    let mut view = View::new(true);
    view.no_puzzle = true;
    view
}

fn encode(record: &NodeRecord) -> Vec<u8> {
    postcard::to_allocvec(record).unwrap()
}

fn entry_of(net: &MemNet, i: usize) -> BootstrapEntry {
    let (id, record) = &net.nodes[i];
    BootstrapEntry {
        id: *id,
        addr: record.addrs()[0],
    }
}

#[test]
fn bootstrap_order_cache_cards_manual_builtin() {
    let mut rng = StdRng::seed_from_u64(1);

    // Three live nodes in the cache: nothing else is tried.
    let net = MemNet::random(100, 7);
    let mut view = test_view();
    for (_, r) in &net.nodes[0..3] {
        view.insert(r.clone(), NOW);
    }
    let hints = vec![encode(&net.nodes[10].1)];
    view.add_manual(net.nodes[20].0, net.nodes[20].1.addrs()[0], NOW);
    let builtin = [entry_of(&net, 30)];
    let report = block_on(bootstrap(
        &mut view,
        hints.clone(),
        &builtin,
        &net,
        &mut rng,
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert!(report.bootstrapped());
    assert_eq!(report.sources, vec![BootstrapSource::Cache]);
    let pinged: HashSet<NodeId> = net.pings().into_iter().collect();
    let cache: HashSet<NodeId> = net.nodes[0..3].iter().map(|(id, _)| *id).collect();
    assert_eq!(pinged, cache);
    assert!(net.finds().is_empty());
    for id in &cache {
        assert!(view.get(id).unwrap().confirmed);
    }
    // The valid hint still entered the view, as a candidate.
    assert!(!view.get(&net.nodes[10].0).unwrap().confirmed);

    // Two live cache nodes and a dead one: the cards complete, the hand-added
    // nodes and the built-in list are not tried.
    let mut net = MemNet::random(100, 7);
    net.down.insert(net.nodes[2].0);
    let mut view = test_view();
    for (_, r) in &net.nodes[0..3] {
        view.insert(r.clone(), NOW);
    }
    view.add_manual(net.nodes[20].0, net.nodes[20].1.addrs()[0], NOW);
    let report = block_on(bootstrap(
        &mut view,
        vec![encode(&net.nodes[10].1), encode(&net.nodes[11].1)],
        &builtin,
        &net,
        &mut rng,
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert_eq!(
        report.sources,
        vec![BootstrapSource::Cache, BootstrapSource::Cards]
    );
    assert_eq!(report.reachable.len(), 3);
    let pings = net.pings();
    assert_eq!(pings.len(), 4, "3 cache nodes then 1 card node");
    assert_eq!(
        pings[..3].iter().collect::<HashSet<_>>(),
        net.nodes[0..3].iter().map(|(id, _)| id).collect()
    );
    assert_eq!(pings[3], net.nodes[10].0);
    assert!(!pings.contains(&net.nodes[20].0));
    assert!(!pings.contains(&net.nodes[30].0));
    assert!(view.get(&net.nodes[10].0).unwrap().confirmed);
    assert!(!view.get(&net.nodes[11].0).unwrap().confirmed);

    // Nothing cached, no card: a hand-added node (record-less), then the
    // built-in list, then one random lookup for real records.
    let net = MemNet::random(100, 7);
    let mut view = test_view();
    let (manual_id, manual_rec) = net.nodes[20].clone();
    view.add_manual(manual_id, manual_rec.addrs()[0], NOW);
    let builtin = [entry_of(&net, 30), entry_of(&net, 31), entry_of(&net, 32)];
    let report = block_on(bootstrap(
        &mut view,
        Vec::new(),
        &builtin,
        &net,
        &mut rng,
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert_eq!(
        report.sources,
        vec![
            BootstrapSource::Cache,
            BootstrapSource::Cards,
            BootstrapSource::Manual,
            BootstrapSource::Builtin
        ]
    );
    assert_eq!(
        net.pings(),
        vec![manual_id, net.nodes[30].0, net.nodes[31].0],
        "stops at 3 reachable: the third built-in entry is not tried"
    );
    let manual = view.get(&manual_id).unwrap();
    assert!(manual.confirmed && manual.manual);
    assert_eq!(manual.record.as_ref(), Some(&manual_rec));
    assert!(view.get(&net.nodes[30].0).unwrap().confirmed);
    assert!(!net.finds().is_empty(), "a random lookup followed");
    assert!(view.len() > 20, "view filled by the lookup: {}", view.len());
    assert_eq!(report.added, view.len() - 1);
}

#[test]
fn bootstrap_stops_empty_handed_when_nothing_answers() {
    let mut net = MemNet::random(10, 3);
    for (id, _) in &net.nodes.clone() {
        net.down.insert(*id);
    }
    let mut view = test_view();
    let builtin: Vec<BootstrapEntry> = (0..10).map(|i| entry_of(&net, i)).collect();
    let report = block_on(bootstrap(
        &mut view,
        Vec::new(),
        &builtin,
        &net,
        &mut StdRng::seed_from_u64(1),
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert!(!report.bootstrapped());
    assert!(report.reachable.is_empty());
    assert_eq!(net.pings().len(), 10);
    assert!(net.finds().is_empty());
    assert!(view.is_empty());
}

#[test]
fn invalid_node_hint_is_ignored() {
    // Puzzle enforced: keys from the precomputed seeds.
    let good = test_support::record(0, NOW);
    let good_id = test_support::id_of(0);
    let net = MemNet::new(vec![(good_id, good.clone())]);
    let mut tampered = test_support::record(1, NOW);
    tampered.issued_at -= 3600;
    let no_puzzle = MemNet::random(1, 9).nodes[0].1.clone();
    let mut trailing = encode(&test_support::record(2, NOW));
    trailing.push(0);
    let mut view = View::new(true);
    let hints = vec![
        vec![0xff; 40],
        encode(&tampered),
        encode(&no_puzzle),
        trailing,
        vec![0; MAX_NODE_HINT_BYTES + 1],
        encode(&good),
        encode(&good),
    ];
    let report = block_on(bootstrap(
        &mut view,
        hints,
        &[],
        &net,
        &mut StdRng::seed_from_u64(1),
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert_eq!(report.invalid_hints, 5);
    assert_eq!(view.len(), 1, "only the valid hint entered the view");
    assert_eq!(net.pings(), vec![good_id], "tried once, duplicates dropped");
    assert_eq!(report.reachable, vec![good_id]);
    assert!(view.get(&good_id).unwrap().confirmed);
}

#[test]
fn random_lookups_fill_view_and_confirm_responders() {
    let mut net = MemNet::random(100, 11);
    let dead: Vec<NodeId> = net.nodes[50..60].iter().map(|(id, _)| *id).collect();
    net.down.extend(dead.iter().copied());
    let mut view = test_view();
    for (_, r) in &net.nodes[0..3] {
        view.insert(r.clone(), NOW);
    }
    let mut budget = CandidateBudget::default();
    let added = block_on(random_lookups(
        &mut view,
        &net,
        2,
        &mut StdRng::seed_from_u64(5),
        &mut budget,
        NOW,
    ));
    assert!(view.len() > 40, "view filled: {}", view.len());
    assert_eq!(added, view.len() - 3);
    let queried: HashSet<NodeId> = net.finds().into_iter().collect();
    let mut candidates = 0;
    for (id, e) in view.entries() {
        let answered = queried.contains(id) && !net.down.contains(id);
        assert_eq!(e.confirmed, answered, "confirmed iff it answered");
        if !e.confirmed {
            candidates += 1;
        }
    }
    assert!(candidates > 0, "relayed records stay candidates");
    assert!(
        dead.iter()
            .all(|id| view.get(id).is_none_or(|e| !e.confirmed))
    );
    assert_eq!(
        budget.remaining(),
        MAX_NEW_CANDIDATES - (view.len() - 3),
        "every new relayed record spent the budget"
    );
}

#[test]
fn random_lookups_respect_candidate_budget() {
    let net = MemNet::random(100, 12);
    let mut view = test_view();
    view.insert(net.nodes[0].1.clone(), NOW);
    let mut budget = CandidateBudget { remaining: 5 };
    block_on(random_lookups(
        &mut view,
        &net,
        2,
        &mut StdRng::seed_from_u64(6),
        &mut budget,
        NOW,
    ));
    assert_eq!(budget.remaining(), 0);
    let candidates = view.entries().filter(|(_, e)| !e.confirmed).count();
    assert!(candidates <= 5, "{candidates} candidates");
}

#[test]
fn fallback_respects_cooldown() {
    let net = MemNet::random(100, 13);
    let mailbox = MailboxId([4; 16]);
    let other = MailboxId([5; 16]);
    let mut log = FallbackLog::default();
    let mut budget = CandidateBudget::default();

    // Empty view: nothing to start from, and the cooldown does not start.
    let mut empty = test_view();
    let found = block_on(fallback_lookup(
        &mut empty,
        &net,
        &mailbox,
        &mut log,
        &mut budget,
        NOW,
    ));
    assert!(found.is_empty());
    assert!(log.due(&mailbox, NOW));

    let mut view = test_view();
    for (_, r) in &net.nodes[0..5] {
        view.insert(r.clone(), NOW);
    }
    let found = block_on(fallback_lookup(
        &mut view,
        &net,
        &mailbox,
        &mut log,
        &mut budget,
        NOW,
    ));
    let truth = net.closest(&mailbox_key(&mailbox), 5);
    assert_eq!(&found[..5], &truth[..], "finds the true closest nodes");
    for id in &truth {
        assert!(view.get(id).unwrap().confirmed, "result enriches the view");
    }
    let finds = net.finds().len();
    assert!(finds > 0);

    let again = block_on(fallback_lookup(
        &mut view,
        &net,
        &mailbox,
        &mut log,
        &mut budget,
        NOW + FALLBACK_COOLDOWN_SECS - 1,
    ));
    assert!(again.is_empty());
    assert_eq!(net.finds().len(), finds, "no request during the cooldown");

    // Another mailbox is not held back.
    assert!(log.due(&other, NOW + 1));

    let later = block_on(fallback_lookup(
        &mut view,
        &net,
        &mailbox,
        &mut log,
        &mut budget,
        NOW + FALLBACK_COOLDOWN_SECS,
    ));
    assert!(!later.is_empty());
    assert!(net.finds().len() > finds);
}

#[test]
fn fallback_log_prunes_and_survives_clock_jumps() {
    let mailbox = MailboxId([4; 16]);
    let mut log = FallbackLog::default();
    log.note(&mailbox, NOW + 10 * 86_400);
    // A date from the future counts as now: due again a day later.
    assert!(!log.due(&mailbox, NOW));
    log.prune(NOW);
    assert!(!log.due(&mailbox, NOW + FALLBACK_COOLDOWN_SECS - 1));
    assert!(log.due(&mailbox, NOW + FALLBACK_COOLDOWN_SECS));
    log.prune(NOW + FALLBACK_COOLDOWN_SECS);
    assert_eq!(log, FallbackLog::default());
}

/// View of `n` confirmed nodes of the network.
fn confirmed_view(net: &MemNet, n: usize) -> View {
    let mut view = test_view();
    for (id, r) in &net.nodes[..n] {
        view.insert(r.clone(), NOW);
        view.confirm(id, NOW);
    }
    view
}

fn decode(hint: &[u8]) -> NodeId {
    let record: NodeRecord = postcard::from_bytes(hint).unwrap();
    record.verify(NOW, &test_view().policy()).unwrap()
}

#[test]
fn card_nodes_never_my_responsibles() {
    let net = MemNet::random(30, 17);
    let view = confirmed_view(&net, 30);
    let mine = [MailboxId([1; 16]), MailboxId([2; 16]), MailboxId([3; 16])];
    let responsibles: HashSet<NodeId> = mine
        .iter()
        .flat_map(|m| view.responsibles(m, NOW))
        .collect();
    assert!(responsibles.len() >= 5);
    let mut rng = StdRng::seed_from_u64(2);
    let mut drawn = HashSet::new();
    for _ in 0..200 {
        let hints = choose_card_nodes(&view, &mine, &mut rng, NOW);
        assert_eq!(hints.len(), MAX_CARD_NODES);
        let ids: HashSet<NodeId> = hints.iter().map(|h| decode(h)).collect();
        assert_eq!(ids.len(), MAX_CARD_NODES, "distinct nodes");
        assert!(hints.iter().all(|h| h.len() <= MAX_NODE_HINT_BYTES));
        assert!(ids.is_disjoint(&responsibles));
        drawn.extend(ids);
    }
    assert_eq!(
        drawn.len(),
        30 - responsibles.len(),
        "drawn at random among all eligible nodes"
    );
}

#[test]
fn card_nodes_only_confirmed_and_well_scored() {
    let net = MemNet::random(10, 19);
    let mut view = test_view();
    for (_, r) in &net.nodes {
        view.insert(r.clone(), NOW);
    }
    let id = |i: usize| net.nodes[i].0;
    // 0, 1: confirmed, score 0.5 and 0.52. 2: confirmed, score 0.2.
    // 3: confirmed but avoided. 4..10: candidates.
    for i in 0..4 {
        view.confirm(&id(i), NOW);
    }
    view.apply_score(&id(1), ScoreEvent::Success, NOW, true);
    view.apply_score(&id(2), ScoreEvent::Lost, NOW, true);
    view.avoid(&id(3), NOW + 86_400, NOW);
    let mut rng = StdRng::seed_from_u64(3);
    for _ in 0..50 {
        let ids: HashSet<NodeId> = choose_card_nodes(&view, &[], &mut rng, NOW)
            .iter()
            .map(|h| decode(h))
            .collect();
        assert_eq!(ids, HashSet::from([id(0), id(1)]));
    }
    assert!(choose_card_nodes(&test_view(), &[], &mut rng, NOW).is_empty());
}

#[test]
fn quic_dialer_without_address_fails_fast() {
    let id = test_support::id_of(0);
    assert_eq!(
        block_on(QuicDialer.ping(id, &[])),
        Err(DialError::NoAddress)
    );
    assert_eq!(
        block_on(QuicDialer.find_node(id, &[], [0; 32])),
        Err(DialError::NoAddress)
    );
}

#[test]
fn lookup_converges_despite_stalling_nodes() {
    let mut net = MemNet::random(100, 21);
    let mailbox = MailboxId([6; 16]);
    let truth = net.closest(&mailbox_key(&mailbox), 5);
    // Every fourth node never answers (none of the true closest).
    let stalled: Vec<NodeId> = net
        .nodes
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !truth.contains(id))
        .step_by(4)
        .collect();
    net.stall.extend(stalled.iter().copied());
    let mut view = test_view();
    // Seeds: stalling nodes first, so the very first requests hang.
    for id in stalled.iter().take(5) {
        view.insert(net.record(id).unwrap(), NOW);
    }
    for (id, r) in &net.nodes {
        if !stalled.contains(id) && !truth.contains(id) && view.len() < 8 {
            view.insert(r.clone(), NOW);
        }
    }
    let (found, took) = timed(fallback_lookup(
        &mut view,
        &net,
        &mailbox,
        &mut FallbackLog::default(),
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert_eq!(&found[..5], &truth[..], "true closest despite stalls");
    assert!(
        took <= Duration::from_millis(LOOKUP_TIMEOUT_MS),
        "took {took:?}"
    );
    assert!(
        stalled
            .iter()
            .all(|id| !view.get(id).is_some_and(|e| e.confirmed))
    );
}

#[test]
fn bootstrap_reaches_later_sources_despite_stalling_cache() {
    let mut net = MemNet::random(100, 23);
    let mut view = test_view();
    // 30 cached nodes, all stalling: only the first 24 are tried.
    for (id, r) in &net.nodes[0..30] {
        view.insert(r.clone(), NOW);
        net.stall.insert(*id);
    }
    // 24 card hints pointing at stalling nodes too.
    let hints: Vec<Vec<u8>> = net.nodes[30..54]
        .iter()
        .map(|(id, r)| {
            net.stall.insert(*id);
            encode(r)
        })
        .collect();
    let (manual_id, manual_rec) = net.nodes[60].clone();
    view.add_manual(manual_id, manual_rec.addrs()[0], NOW);
    let builtin = [entry_of(&net, 70), entry_of(&net, 71)];
    let (report, took) = timed(bootstrap(
        &mut view,
        hints,
        &builtin,
        &net,
        &mut StdRng::seed_from_u64(4),
        &mut CandidateBudget::default(),
        NOW,
    ));
    assert!(report.bootstrapped());
    assert_eq!(
        report.reachable,
        vec![manual_id, net.nodes[70].0, net.nodes[71].0]
    );
    assert_eq!(report.sources.last(), Some(&BootstrapSource::Builtin));
    let pinged: HashSet<NodeId> = net.pings().into_iter().collect();
    assert_eq!(
        net.nodes[0..30]
            .iter()
            .filter(|(id, _)| pinged.contains(id))
            .count(),
        BOOTSTRAP_TRIES_PER_SOURCE
    );
    assert!(took <= Duration::from_secs(45), "took {took:?}");
    assert!(
        took < 2 * BOOTSTRAP_SOURCE_TIMEOUT
            + Duration::from_millis(LOOKUP_TIMEOUT_MS + REQUEST_TIMEOUT_MS),
        "each stalling source costs one timeout, not one per round: {took:?}"
    );
}
