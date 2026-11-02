//! Deterministic simulation of 500 nodes (spec §1, criteria 1 to 4; §9).
//!
//! No network: each node is just a `RoutingTable`, and the harness
//! answers a lookup's `FindNode`s synchronously from the table
//! of the queried node. A dead or mute node never answers: its request
//! stays in flight and holds its slot until the 3 s timeout expires, and
//! the whole lookup remains bounded to 10 s. A fixed seed and a simulated
//! clock make every run identical.

use std::collections::{BTreeSet, HashMap};

use barking_dht::{
    Insert, K, Lookup, Prefix, REPLICAS, RoutingTable, distance, lookup::LOOKUP_TIMEOUT_MS,
    prefixes,
};
use barking_proto::{NodeId, NodeRecord, RecordPolicy};
use ed25519_dalek::SigningKey;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng, seq::SliceRandom};

/// Records without puzzle, private addresses allowed: only the simulation may do so.
const POLICY: RecordPolicy = RecordPolicy {
    allow_private: true,
    puzzle_bits: 0,
};
/// Nodes of the network.
const NODES: usize = 500;
/// Lookups measured per scenario.
const LOOKUPS: usize = 1_000;
/// Start of the simulated clock, in seconds.
const T0: u64 = 1_700_000_000;
/// Simulated round trip of one round of requests, in milliseconds.
const ROUND_MS: u64 = 50;
/// /24 block shared by all Sybil identities.
const SYBIL_BLOCK: [u8; 3] = [10, 9, 8];
/// Common bootstrap node.
const BOOT: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    Honest,
    /// Returns only the 20 accomplices closest to the target.
    OnlyColluders,
    /// Returns invalid records.
    Garbage,
    /// Answers nothing, not even `Ping`s.
    Silent,
}

struct Node {
    id: NodeId,
    record: NodeRecord,
    table: RoutingTable,
    behaviour: Behaviour,
    alive: bool,
}

/// Outcome of a lookup: the harness then applies what each node
/// learns from it (`learn`).
struct Search {
    lookup: Lookup,
    /// Queried nodes that responded.
    answered: Vec<usize>,
    /// Queried nodes that did not respond.
    failed: Vec<usize>,
    /// Simulated duration of the lookup.
    elapsed_ms: u64,
}

struct Net {
    nodes: Vec<Node>,
    index: HashMap<NodeId, usize>,
    /// `OnlyColluders` accomplices, in order of arrival.
    colluders: Vec<usize>,
    /// Next free /24 for a node with its own block.
    next_block: usize,
    rng: StdRng,
    now_ms: u64,
}

impl Net {
    fn new(seed: u64) -> Net {
        Net {
            nodes: Vec::new(),
            index: HashMap::new(),
            colluders: Vec::new(),
            next_block: 0,
            rng: StdRng::seed_from_u64(seed),
            now_ms: T0 * 1000,
        }
    }

    fn now_secs(&self) -> u64 {
        self.now_ms / 1000
    }

    /// Network bootstrapped from `BOOT`: `honest` honest nodes and the
    /// given adversaries, arrived in random order, each on its own
    /// /24.
    fn build(seed: u64, honest: usize, adversaries: &[(Behaviour, usize)]) -> Net {
        let mut net = Net::new(seed);
        let boot = net.add(Behaviour::Honest, None);
        assert_eq!(boot, BOOT);
        let mut arrivals = vec![Behaviour::Honest; honest - 1];
        for &(behaviour, count) in adversaries {
            arrivals.extend(std::iter::repeat_n(behaviour, count));
        }
        arrivals.shuffle(&mut net.rng);
        for behaviour in arrivals {
            let i = net.add(behaviour, None);
            net.join(i);
        }
        net
    }

    /// Creates a node, on its own /24 if `addr` is `None`.
    fn add(&mut self, behaviour: Behaviour, addr: Option<String>) -> usize {
        let addr = addr.unwrap_or_else(|| {
            let b = self.next_block;
            self.next_block += 1;
            format!("11.{}.{}.1:4433", b / 256, b % 256)
        });
        let mut seed = [0; 32];
        self.rng.fill_bytes(&mut seed);
        let record = NodeRecord::sign(
            &SigningKey::from_bytes(&seed),
            Some(addr.parse().unwrap()),
            None,
            self.now_secs(),
        );
        let id = record.verify(self.now_secs(), &POLICY).unwrap();
        let i = self.nodes.len();
        self.nodes.push(Node {
            id,
            record,
            table: RoutingTable::new(id),
            behaviour,
            alive: true,
        });
        self.index.insert(id, i);
        if behaviour == Behaviour::OnlyColluders {
            self.colluders.push(i);
        }
        i
    }

    /// The node answers a `Ping` (connection and `Pong`).
    fn answers_ping(&self, i: usize) -> bool {
        self.nodes[i].alive && self.nodes[i].behaviour != Behaviour::Silent
    }

    /// `at` contacts `peer` directly (connection then valid `Pong`).
    fn contact(&mut self, at: usize, peer: usize) {
        if !self.answers_ping(peer) {
            self.fail(at, peer);
            return;
        }
        let (id, record) = (self.nodes[peer].id, self.nodes[peer].record.clone());
        let now = self.now_secs();
        if let Insert::Pending { ping } = self.nodes[at].table.on_contact(id, record, now) {
            self.ping(at, self.index[&ping]);
        }
    }

    /// `at` pings an already known node: it stays if it answers, otherwise the failure
    /// is counted.
    fn ping(&mut self, at: usize, peer: usize) {
        if self.answers_ping(peer) {
            let (id, record) = (self.nodes[peer].id, self.nodes[peer].record.clone());
            let now = self.now_secs();
            self.nodes[at].table.on_contact(id, record, now);
        } else {
            self.fail(at, peer);
        }
    }

    /// Contact failure from `at` to `peer`; when `peer` is removed, the
    /// reserve candidate is contacted to be promoted.
    fn fail(&mut self, at: usize, peer: usize) {
        let id = self.nodes[peer].id;
        let Some(candidate) = self.nodes[at].table.on_failure(&id) else {
            return;
        };
        let c = self.index[&candidate];
        if self.answers_ping(c) {
            let record = self.nodes[c].record.clone();
            let now = self.now_secs();
            self.nodes[at].table.on_contact(candidate, record, now);
        } else {
            self.nodes[at].table.on_failure(&candidate);
        }
    }

    /// Response of `to` to a `FindNode` for `target`; `None` if nothing comes.
    fn answer(&self, to: usize, target: &[u8; 32]) -> Option<Vec<NodeRecord>> {
        let node = &self.nodes[to];
        if !node.alive {
            return None;
        }
        match node.behaviour {
            Behaviour::Honest => Some(node.table.closest_diverse(target, K)),
            Behaviour::OnlyColluders => {
                let mut accomplices = self.colluders.clone();
                accomplices.sort_by_cached_key(|&c| distance(&self.nodes[c].id.0, target));
                Some(
                    accomplices
                        .into_iter()
                        .take(K)
                        .map(|c| self.nodes[c].record.clone())
                        .collect(),
                )
            }
            Behaviour::Garbage => Some(
                node.table
                    .closest_diverse(target, K)
                    .into_iter()
                    .map(|mut r| {
                        // The signature no longer covers the date.
                        r.issued_at -= 3600;
                        r
                    })
                    .collect(),
            ),
            Behaviour::Silent => None,
        }
    }

    /// Synchronous lookup of `target` by `from`, modifying nothing.
    fn search(&self, from: usize, target: &[u8; 32]) -> Search {
        let me = &self.nodes[from];
        let seeds = me
            .table
            .closest(target, K)
            .into_iter()
            .map(|p| (p.id, p.record))
            .collect();
        let mut now_ms = self.now_ms;
        let now_secs = self.now_secs();
        let mut lookup = Lookup::new(*target, seeds, POLICY, now_ms).excluding(me.id);
        let (mut answered, mut failed) = (Vec::new(), Vec::new());
        while !lookup.is_done(now_ms) {
            // A response arrives within the round of its request. Without a response, the
            // request stays in flight: `next_requests` declares it failed after
            // `REQUEST_TIMEOUT_MS`, and `is_done` stops the lookup after
            // `LOOKUP_TIMEOUT_MS`.
            for (id, _) in lookup.next_requests(now_ms) {
                let to = self.index[&id];
                match self.answer(to, target) {
                    Some(records) => {
                        lookup.on_response(&id, records, now_secs);
                        answered.push(to);
                    }
                    None => failed.push(to),
                }
            }
            now_ms += ROUND_MS;
        }
        Search {
            lookup,
            answered,
            failed,
            elapsed_ms: now_ms - self.now_ms,
        }
    }

    /// Lookup run by a live node: the queried nodes learn about
    /// the caller, the caller counts failures and contacts the responders.
    fn run_lookup(&mut self, from: usize, target: &[u8; 32]) {
        let search = self.search(from, target);
        self.learn(from, search);
    }

    /// Applies to the tables what the lookup of `from` learned.
    fn learn(&mut self, from: usize, search: Search) {
        for &to in &search.answered {
            self.contact(to, from);
        }
        for &to in &search.failed {
            self.fail(from, to);
        }
        for (id, _) in search.lookup.responders() {
            self.contact(from, self.index[&id]);
        }
    }

    /// Measurement lookup: identifiers found and simulated duration, without
    /// effect on the tables.
    fn probe(&self, from: usize, target: &[u8; 32]) -> (Vec<NodeId>, u64) {
        let search = self.search(from, target);
        let found = search
            .lookup
            .result()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        (found, search.elapsed_ms)
    }

    /// Bootstrap from `BOOT` then lookup of its own identifier.
    fn join(&mut self, i: usize) {
        self.contact(i, BOOT);
        self.contact(BOOT, i);
        let own = self.nodes[i].id.0;
        self.run_lookup(i, &own);
    }

    /// Switches `count` random honest nodes (excluding bootstrap) to the
    /// given behaviour, once the network is formed.
    fn turn(&mut self, behaviour: Behaviour, count: usize) {
        let mut candidates: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| i != BOOT && self.nodes[i].behaviour == Behaviour::Honest)
            .collect();
        candidates.shuffle(&mut self.rng);
        for &i in &candidates[..count] {
            self.nodes[i].behaviour = behaviour;
        }
    }

    /// Kills `count` random nodes (excluding bootstrap).
    fn kill(&mut self, count: usize) {
        let mut candidates: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| i != BOOT && self.nodes[i].alive)
            .collect();
        candidates.shuffle(&mut self.rng);
        for &i in &candidates[..count] {
            self.nodes[i].alive = false;
        }
    }

    /// The `n` live honest nodes closest to `key`, computed over
    /// the whole network.
    fn truth(&self, key: &[u8; 32], n: usize) -> Vec<usize> {
        let mut honest: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].alive && self.nodes[i].behaviour == Behaviour::Honest)
            .collect();
        honest.sort_by_cached_key(|&i| distance(&self.nodes[i].id.0, key));
        honest.truncate(n);
        honest
    }

    fn random_honest(&mut self) -> usize {
        loop {
            let i = self.rng.random_range(0..self.nodes.len());
            if self.nodes[i].alive && self.nodes[i].behaviour == Behaviour::Honest {
                return i;
            }
        }
    }

    fn key(&mut self) -> [u8; 32] {
        let mut key = [0; 32];
        self.rng.fill_bytes(&mut key);
        key
    }

    /// Maintenance cycle of each live node, one hour later: pings
    /// of stale heads until dead ones are evicted (with promotion from
    /// the reserve), then refresh of each bucket by a
    /// lookup.
    ///
    /// The refresh lookups of all nodes start together,
    /// on the tables resulting from the pings, as in a network where everyone
    /// maintains their table at the same time; what they learn is
    /// applied afterwards, in node order.
    fn maintenance_cycle(&mut self) {
        self.now_ms += 3_600_000;
        let now = self.now_secs();
        let live: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| self.answers_ping(i))
            .collect();
        for &i in &live {
            loop {
                let heads = self.nodes[i].table.stale_heads(now);
                if heads.is_empty() {
                    break;
                }
                for head in heads {
                    self.ping(i, self.index[&head]);
                }
            }
        }
        let mut refresh = Vec::new();
        for &i in &live {
            for bucket in self.nodes[i].table.buckets_to_refresh(now) {
                let target = self.nodes[i]
                    .table
                    .random_id_in_bucket(bucket, &mut self.rng);
                refresh.push((i, bucket, target));
            }
        }
        let searches = par_map(&refresh, |(i, _, target)| self.search(*i, target));
        for ((i, bucket, _), search) in refresh.into_iter().zip(searches) {
            self.learn(i, search);
            self.nodes[i].table.mark_refreshed(bucket, now);
        }
    }

    /// Replication pass: each live keeper replicates to the responsible nodes
    /// given by its table; a responsible node accepts if the caller and
    /// itself are within its responsibility window (spec §5.2, point 4).
    fn replication_pass(&self, boxes: &mut [Mailbox]) {
        for mailbox in boxes {
            let holders: Vec<usize> = mailbox
                .holders
                .iter()
                .copied()
                .filter(|&h| self.nodes[h].alive)
                .collect();
            for h in holders {
                let Some(targets) = self.nodes[h].table.replica_targets(&mailbox.key) else {
                    continue;
                };
                for target in targets {
                    let t = self.index[&target];
                    if !self.answers_ping(t) {
                        continue;
                    }
                    let table = &self.nodes[t].table;
                    if table.may_hold(&mailbox.key, &self.nodes[h].id)
                        && table.may_hold(&mailbox.key, &target)
                    {
                        mailbox.holders.insert(t);
                    }
                }
            }
        }
    }
}

/// Mailbox: its key and the nodes that keep a copy of it.
struct Mailbox {
    key: [u8; 32],
    holders: BTreeSet<usize>,
}

impl Mailbox {
    fn live_holders(&self, net: &Net) -> BTreeSet<usize> {
        self.holders
            .iter()
            .copied()
            .filter(|&h| net.nodes[h].alive)
            .collect()
    }
}

/// Share of lookups that find at least `need` of the 5 true
/// honest responsible nodes, launched from random honest nodes;
/// also prints their simulated duration and the stricter rate where those
/// nodes are among the `REPLICAS` closest of the result, returned second.
fn success_rate(net: &mut Net, need: usize) -> (f64, f64) {
    let jobs: Vec<([u8; 32], usize)> = (0..LOOKUPS)
        .map(|_| (net.key(), net.random_honest()))
        .collect();
    let net = &*net;
    let outcomes = par_map(&jobs, |(key, from)| {
        let truth = net.truth(key, REPLICAS);
        let (mut found, elapsed_ms) = net.probe(*from, key);
        // The searching node knows itself.
        found.push(net.nodes[*from].id);
        let hits_in = |ids: &[NodeId]| {
            truth
                .iter()
                .filter(|&&t| ids.contains(&net.nodes[t].id))
                .count()
                >= need
        };
        let hit = hits_in(&found);
        found.sort_by_key(|id| distance(&id.0, key));
        found.truncate(REPLICAS);
        (hit, hits_in(&found), elapsed_ms)
    });
    let hits = outcomes.iter().filter(|(hit, _, _)| *hit).count();
    let top_hits = outcomes.iter().filter(|(_, top, _)| *top).count();
    let top_rate = top_hits as f64 / LOOKUPS as f64;
    eprintln!(
        "{need} of 5 among the top {REPLICAS} of the result: {:.1} %",
        top_rate * 100.0
    );
    let mut durations: Vec<u64> = outcomes.iter().map(|&(_, _, ms)| ms).collect();
    durations.sort_unstable();
    let timed_out = durations
        .iter()
        .filter(|&&ms| ms >= LOOKUP_TIMEOUT_MS)
        .count();
    eprintln!(
        "simulated duration: median {} ms, max {} ms, {timed_out} lookups stopped at {LOOKUP_TIMEOUT_MS} ms",
        durations[durations.len() / 2],
        durations[durations.len() - 1],
    );
    (hits as f64 / LOOKUPS as f64, top_rate)
}

/// `f` applied to each element on all cores, results in the order
/// of the elements: signature verification dominates the compute time.
fn par_map<I: Sync, T: Send>(items: &[I], f: impl Fn(&I) -> T + Sync) -> Vec<T> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|part| s.spawn(|| part.iter().map(&f).collect::<Vec<T>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    })
}

#[test]
fn honest_lookup_finds_all_five() {
    let mut net = Net::build(1, NODES, &[]);
    let (rate, top_rate) = success_rate(&mut net, REPLICAS);
    eprintln!("honest network: {:.1} % find all 5", rate * 100.0);
    assert!(rate > 0.99, "rate {rate}");
    // Stricter: the 5 are also the 5 closest of the result.
    assert!(top_rate > 0.99, "top-5 rate {top_rate}");
}

#[test]
fn twenty_percent_liars_still_find_three() {
    let liars = NODES / 5;
    let mut net = Net::build(2, NODES - liars, &[(Behaviour::OnlyColluders, liars)]);
    let (rate, _) = success_rate(&mut net, 3);
    eprintln!("20 % liars: {:.1} % find 3 of 5", rate * 100.0);
    assert!(rate > 0.95, "rate {rate}");
}

#[test]
fn liars_garbage_and_silent_do_not_break_lookups() {
    // Nodes enter the tables honest, then turn: otherwise a mute
    // node would never get in.
    let mut net = Net::build(5, NODES, &[]);
    net.turn(Behaviour::Garbage, NODES / 10);
    net.turn(Behaviour::Silent, NODES / 10);
    let (rate, _) = success_rate(&mut net, 3);
    eprintln!(
        "10 % invalid records, 10 % mute: {:.1} % find 3 of 5",
        rate * 100.0
    );
    assert!(rate > 0.95, "rate {rate}");
}

#[test]
fn sybil_slash24_is_capped() {
    let mut net = Net::build(3, NODES, &[]);
    let honest = net.nodes.len();
    let block = Prefix::V4(SYBIL_BLOCK);
    for s in 0..200 {
        let [a, b, c] = SYBIL_BLOCK;
        let addr = format!("{a}.{b}.{c}.{}:4433", s + 1);
        let i = net.add(Behaviour::Honest, Some(addr));
        net.join(i);
        // The attacker is contacted by each honest node.
        for h in 0..honest {
            net.contact(h, i);
        }
    }
    let mut worst = 0.0f64;
    for h in 0..honest {
        let table = &net.nodes[h].table;
        let active = table.closest(&[0; 32], usize::MAX);
        let sybils = active
            .iter()
            .filter(|p| prefixes(&p.record).contains(&block))
            .count();
        let limit = 2usize.max(active.len() / 10);
        assert!(
            sybils <= limit,
            "node {h}: {sybils} Sybil out of {} active",
            active.len()
        );
        worst = worst.max(sybils as f64 / active.len() as f64);
    }
    eprintln!("Sybil: maximum share {:.1} % of a table", worst * 100.0);
}

#[test]
fn churn_restores_five_copies_in_two_passes() {
    let mut net = Net::build(4, NODES, &[]);
    // 1. Deposit of each mailbox on 3 of its responsible nodes.
    let mut boxes: Vec<Mailbox> = (0..100)
        .map(|_| {
            let key = net.key();
            let holders = net.truth(&key, 3).into_iter().collect();
            Mailbox { key, holders }
        })
        .collect();
    // 2. Replication up to 5 copies, on the 5 true responsible nodes.
    for _ in 0..3 {
        net.replication_pass(&mut boxes);
    }
    for mailbox in &boxes {
        let truth: BTreeSet<usize> = net.truth(&mailbox.key, REPLICAS).into_iter().collect();
        assert!(
            mailbox.holders.is_superset(&truth),
            "initial replication incomplete"
        );
    }
    // 3. Departure of 30 % of the nodes.
    net.kill(NODES * 3 / 10);
    for mailbox in &boxes {
        assert!(
            !mailbox.live_holders(&net).is_empty(),
            "mailbox lost with all its copies"
        );
    }
    // The departures did deprive mailboxes of copies: it is the repair
    // that makes the test pass.
    let damaged = short_of_five(&net, &boxes);
    assert!(damaged > 0, "no mailbox hit by the departures");
    // 4. One maintenance cycle of the tables.
    net.maintenance_cycle();
    // 5. Two replication passes.
    net.replication_pass(&mut boxes);
    net.replication_pass(&mut boxes);
    let short = short_of_five(&net, &boxes);
    eprintln!(
        "departures: {damaged} mailboxes out of 100 hit, {short} still without their 5 copies"
    );
    assert_eq!(short, 0);
}

/// Mailboxes that do not have a live copy on each of their 5 true
/// responsible nodes that are alive.
fn short_of_five(net: &Net, boxes: &[Mailbox]) -> usize {
    boxes
        .iter()
        .filter(|mailbox| {
            let live = mailbox.live_holders(net);
            let truth: BTreeSet<usize> = net.truth(&mailbox.key, REPLICAS).into_iter().collect();
            live.len() < REPLICAS || !live.is_superset(&truth)
        })
        .count()
}
