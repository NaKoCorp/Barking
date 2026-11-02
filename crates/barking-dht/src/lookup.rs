//! Iterative S/Kademlia lookup over `PATHS` disjoint paths (spec §6.3).
//! Pure state machine: the caller sends the `FindNode`s given by
//! `next_requests`, then hands back the responses (`on_response`) and failures
//! (`on_failure`). Timeouts are measured with the clock supplied by
//! the caller, in milliseconds.

use std::collections::{HashMap, HashSet};

use barking_proto::{
    MAX_NODES_PER_RESPONSE, NodeId, NodeRecord, RecordPolicy, record::MAX_RECORD_SKEW_SECS,
};
use ed25519_dalek::Signature;

use crate::{ALPHA, K, MAX_PER_PREFIX, PATHS, Prefix, distance, prefixes};

/// Timeout of a `FindNode` request, in milliseconds.
pub const REQUEST_TIMEOUT_MS: u64 = 3_000;
/// Maximum duration of a lookup, in milliseconds.
pub const LOOKUP_TIMEOUT_MS: u64 = 10_000;

/// `Nodes` response whose author becomes suspect: at least one invalid
/// record, or more than `MAX_NODES_PER_RESPONSE` records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suspect;

/// Filters a `Nodes` response: checks each record and drops duplicates.
/// A single invalid record, or a response that is too long, makes the author
/// suspect and causes the whole response to be ignored.
pub fn filter_nodes(
    records: Vec<NodeRecord>,
    now_secs: u64,
    policy: &RecordPolicy,
) -> Result<Vec<(NodeId, NodeRecord)>, Suspect> {
    filter_known(records, now_secs, policy, &mut HashMap::new())
}

/// Valid records already verified, by signature.
type Verified = HashMap<Signature, (NodeRecord, NodeId)>;

/// Like `filter_nodes`, without rechecking the signature of a record identical
/// to one in `verified`, which receives the valid records. A valid record
/// stays valid as the clock advances; only its date is rechecked, in case
/// the clock went backwards.
fn filter_known(
    records: Vec<NodeRecord>,
    now_secs: u64,
    policy: &RecordPolicy,
    verified: &mut Verified,
) -> Result<Vec<(NodeId, NodeRecord)>, Suspect> {
    if records.len() > MAX_NODES_PER_RESPONSE {
        return Err(Suspect);
    }
    let mut seen = HashSet::with_capacity(records.len());
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let known = verified.get(&record.signature).and_then(|(r, id)| {
            (*r == record && record.issued_at <= now_secs.saturating_add(MAX_RECORD_SKEW_SECS))
                .then_some(*id)
        });
        let id = match known {
            Some(id) => id,
            None => {
                let id = record.verify(now_secs, policy).map_err(|_| Suspect)?;
                verified.insert(record.signature, (record.clone(), id));
                id
            }
        };
        if seen.insert(id) {
            out.push((id, record));
        }
    }
    Ok(out)
}

/// State of a node in a path's list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Waiting,
    InFlight { sent_ms: u64 },
    Responded,
    Failed,
}

#[derive(Clone, Debug)]
struct Entry {
    id: NodeId,
    record: NodeRecord,
    dist: [u8; 32],
    state: State,
}

/// Lookup in progress for a target.
#[derive(Debug)]
pub struct Lookup {
    target: [u8; 32],
    policy: RecordPolicy,
    started_ms: u64,
    /// List of each path, sorted by distance.
    paths: Vec<Vec<Entry>>,
    /// Path owning each taken node: present in that path's list,
    /// or already queried by it. A node belongs to a single path;
    /// a node dropped from its list without having been queried is released.
    owner: HashMap<NodeId, usize>,
    /// Nodes never taken (the node doing the lookup).
    excluded: HashSet<NodeId>,
    suspects: HashSet<NodeId>,
    /// Nodes that responded correctly, in the order of the responses.
    responded: Vec<(NodeId, NodeRecord)>,
    /// Records already verified during the lookup: responses
    /// overlap heavily (twelve times on average in the
    /// 500-node simulation), and signature verification dominated the cost.
    verified: Verified,
}

impl Lookup {
    /// Starts a lookup; the seeds are sorted by distance then
    /// distributed in turn among the paths.
    pub fn new(
        target: [u8; 32],
        mut seeds: Vec<(NodeId, NodeRecord)>,
        policy: RecordPolicy,
        now_ms: u64,
    ) -> Lookup {
        seeds.sort_by_cached_key(|(id, _)| distance(&id.0, &target));
        let mut lookup = Lookup {
            target,
            policy,
            started_ms: now_ms,
            paths: vec![Vec::new(); PATHS],
            owner: HashMap::new(),
            excluded: HashSet::new(),
            suspects: HashSet::new(),
            responded: Vec::new(),
            verified: HashMap::new(),
        };
        let mut next = 0;
        for (id, record) in seeds {
            if lookup.owner.contains_key(&id) {
                continue;
            }
            lookup.add(next, id, record);
            next = (next + 1) % PATHS;
        }
        for path in 0..PATHS {
            lookup.trim(path);
        }
        lookup
    }

    /// Drops an identifier from the lookup (the node doing the lookup): it is
    /// never queried nor retained.
    pub fn excluding(mut self, id: NodeId) -> Lookup {
        if let Some(path) = self.owner.remove(&id) {
            self.paths[path].retain(|e| e.id != id);
        }
        self.responded.retain(|(r, _)| *r != id);
        self.excluded.insert(id);
        self
    }

    /// Adds a node to a path's list, without sorting.
    fn add(&mut self, path: usize, id: NodeId, record: NodeRecord) {
        self.owner.insert(id, path);
        self.paths[path].push(Entry {
            id,
            record,
            dist: distance(&id.0, &self.target),
            state: State::Waiting,
        });
    }

    /// Sorts a path's list and truncates it to `K`; in-flight nodes
    /// beyond that stay, so that their response is still awaited.
    fn trim(&mut self, path: usize) {
        let list = &mut self.paths[path];
        let owner = &mut self.owner;
        list.sort_by_key(|e| e.dist);
        let mut rank = 0;
        list.retain(|e| {
            rank += 1;
            let keep = rank <= K || matches!(e.state, State::InFlight { .. });
            // A node dropped without having been queried is released: another
            // path may take it. A queried node stays taken.
            if !keep && e.state == State::Waiting {
                owner.remove(&e.id);
            }
            keep
        });
    }

    fn entry_mut(&mut self, id: &NodeId) -> Option<(usize, &mut Entry)> {
        let path = *self.owner.get(id)?;
        let entry = self.paths[path].iter_mut().find(|e| e.id == *id)?;
        Some((path, entry))
    }

    fn timed_out(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_ms) >= LOOKUP_TIMEOUT_MS
    }

    /// `FindNode`s to send now, at most `ALPHA` in flight per path.
    /// A request in flight for `REQUEST_TIMEOUT_MS` counts as a failure.
    pub fn next_requests(&mut self, now_ms: u64) -> Vec<(NodeId, NodeRecord)> {
        if self.timed_out(now_ms) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for list in &mut self.paths {
            let mut in_flight = 0;
            for e in list.iter_mut() {
                if let State::InFlight { sent_ms } = e.state {
                    if now_ms.saturating_sub(sent_ms) >= REQUEST_TIMEOUT_MS {
                        e.state = State::Failed;
                    } else {
                        in_flight += 1;
                    }
                }
            }
            // The list is sorted: the first pending ones are the
            // closest.
            for e in list.iter_mut().filter(|e| e.state == State::Waiting) {
                if in_flight >= ALPHA {
                    break;
                }
                e.state = State::InFlight { sent_ms: now_ms };
                in_flight += 1;
                out.push((e.id, e.record.clone()));
            }
        }
        out
    }

    /// `Nodes` response from `from`; ignored if no request is in flight
    /// to it.
    pub fn on_response(&mut self, from: &NodeId, records: Vec<NodeRecord>, now_secs: u64) {
        let policy = self.policy;
        let Some(path) = self.owner.get(from).copied() else {
            return;
        };
        let Some(entry) = self.paths[path].iter_mut().find(|e| e.id == *from) else {
            return;
        };
        if !matches!(entry.state, State::InFlight { .. }) {
            return;
        }
        let Ok(nodes) = filter_known(records, now_secs, &policy, &mut self.verified) else {
            entry.state = State::Failed;
            self.suspects.insert(*from);
            return;
        };
        entry.state = State::Responded;
        let record = entry.record.clone();
        self.responded.push((*from, record));
        for (id, record) in nodes {
            if self.excluded.contains(&id) || self.suspects.contains(&id) {
                continue;
            }
            match self.owner.get(&id) {
                // Already in another path: never retaken (disjoint paths).
                Some(&other) if other != path => {}
                // Already in this path: a more recent record replaces
                // the old one as long as the node has not been queried.
                Some(_) => {
                    if let Some((_, e)) = self.entry_mut(&id)
                        && e.state == State::Waiting
                        && record.issued_at > e.record.issued_at
                    {
                        e.record = record;
                    }
                }
                None => self.add(path, id, record),
            }
        }
        self.trim(path);
    }

    /// Failure of the request to `from` (connection, error, timeout).
    pub fn on_failure(&mut self, from: &NodeId) {
        if let Some((_, entry)) = self.entry_mut(from)
            && matches!(entry.state, State::InFlight { .. })
        {
            entry.state = State::Failed;
        }
    }

    /// True when all paths are exhausted, or after `LOOKUP_TIMEOUT_MS`.
    pub fn is_done(&self, now_ms: u64) -> bool {
        if self.timed_out(now_ms) {
            return true;
        }
        self.paths.iter().flatten().all(|e| match e.state {
            State::Waiting => false,
            State::InFlight { sent_ms } => now_ms.saturating_sub(sent_ms) >= REQUEST_TIMEOUT_MS,
            State::Responded | State::Failed => true,
        })
    }

    /// Nodes that responded, sorted by distance to the target, at most `K` and
    /// `MAX_PER_PREFIX` per block.
    pub fn result(&self) -> Vec<(NodeId, NodeRecord)> {
        let mut sorted: Vec<&(NodeId, NodeRecord)> = self.responded.iter().collect();
        sorted.sort_by_cached_key(|(id, _)| distance(&id.0, &self.target));
        let mut counts: HashMap<Prefix, usize> = HashMap::new();
        let mut out = Vec::new();
        for (id, record) in sorted {
            if out.len() >= K {
                break;
            }
            let blocks = prefixes(record);
            if blocks
                .iter()
                .any(|b| counts.get(b).copied().unwrap_or(0) >= MAX_PER_PREFIX)
            {
                continue;
            }
            for block in blocks {
                *counts.entry(block).or_default() += 1;
            }
            out.push((*id, record.clone()));
        }
        out
    }

    /// Nodes that responded correctly: candidates for the table.
    pub fn responders(&self) -> Vec<(NodeId, NodeRecord)> {
        self.responded.clone()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::{SeedableRng, rngs::StdRng};
    use rand_core::Rng;

    use super::*;
    use crate::{Insert, RoutingTable};

    const NOW_SECS: u64 = 1_000_000;
    const POLICY: RecordPolicy = RecordPolicy {
        allow_private: true,
        puzzle_bits: 0,
    };

    fn bytes(rng: &mut StdRng) -> [u8; 32] {
        let mut out = [0; 32];
        rng.fill_bytes(&mut out);
        out
    }

    /// Node in the /24 specific to `i`.
    fn node(rng: &mut StdRng, i: usize) -> (NodeId, NodeRecord) {
        let seed = bytes(rng);
        let addr = format!("11.{}.{}.1:4433", i / 256, i % 256);
        let rec = NodeRecord::sign(
            &SigningKey::from_bytes(&seed),
            Some(addr.parse().unwrap()),
            None,
            NOW_SECS,
        );
        (rec.verify(NOW_SECS, &POLICY).unwrap(), rec)
    }

    fn nodes(rng: &mut StdRng, n: usize) -> Vec<(NodeId, NodeRecord)> {
        (0..n).map(|i| node(rng, i)).collect()
    }

    /// Fake network: each node knows all the others (within the limit
    /// of its table) and answers with `closest_diverse`.
    fn network(all: &[(NodeId, NodeRecord)]) -> HashMap<NodeId, RoutingTable> {
        all.iter()
            .map(|(id, _)| {
                let mut table = RoutingTable::new(*id);
                for (other, rec) in all {
                    if other != id {
                        let r = table.on_contact(*other, rec.clone(), NOW_SECS);
                        assert!(matches!(r, Insert::Added | Insert::Pending { .. }));
                    }
                }
                (*id, table)
            })
            .collect()
    }

    fn seeds_from(table: &RoutingTable, target: &[u8; 32]) -> Vec<(NodeId, NodeRecord)> {
        table
            .closest(target, K)
            .into_iter()
            .map(|p| (p.id, p.record))
            .collect()
    }

    /// Runs the lookup on the fake network; returns the log
    /// of requests issued.
    fn run(
        lookup: &mut Lookup,
        net: &HashMap<NodeId, RoutingTable>,
        target: &[u8; 32],
    ) -> Vec<NodeId> {
        let mut log = Vec::new();
        let now_ms = 0;
        while !lookup.is_done(now_ms) {
            let reqs = lookup.next_requests(now_ms);
            assert!(!reqs.is_empty(), "lookup stuck");
            for (id, _) in reqs {
                log.push(id);
                let records = net[&id].closest_diverse(target, K);
                lookup.on_response(&id, records, NOW_SECS);
            }
        }
        log
    }

    fn ids(v: &[(NodeId, NodeRecord)]) -> Vec<NodeId> {
        v.iter().map(|(id, _)| *id).collect()
    }

    #[test]
    fn lookup_finds_true_closest_on_honest_net() {
        let mut rng = StdRng::seed_from_u64(1);
        let all = nodes(&mut rng, 100);
        let net = network(&all);
        for round in 0..5 {
            let target = bytes(&mut rng);
            let me = all[round].0;
            let mut lookup =
                Lookup::new(target, seeds_from(&net[&me], &target), POLICY, 0).excluding(me);
            run(&mut lookup, &net, &target);
            let mut truth: Vec<NodeId> = ids(&all).into_iter().filter(|id| *id != me).collect();
            truth.sort_by_key(|id| distance(&id.0, &target));
            let found = ids(&lookup.result());
            assert!(found.len() <= K);
            for id in &truth[..5] {
                assert!(found.contains(id), "round {round}: {id:?} missing");
            }
            assert!(!found.contains(&me));
            // Sorted by distance.
            let mut sorted = found.clone();
            sorted.sort_by_key(|id| distance(&id.0, &target));
            assert_eq!(found, sorted);
        }
    }

    #[test]
    fn paths_are_disjoint() {
        let mut rng = StdRng::seed_from_u64(2);
        let all = nodes(&mut rng, 100);
        let net = network(&all);
        let target = bytes(&mut rng);
        let me = all[0].0;
        let mut lookup =
            Lookup::new(target, seeds_from(&net[&me], &target), POLICY, 0).excluding(me);
        let log = run(&mut lookup, &net, &target);
        let unique: HashSet<NodeId> = log.iter().copied().collect();
        assert_eq!(unique.len(), log.len(), "a node was queried twice");
        // Each queried node appears in a single path only.
        for id in &log {
            let n = lookup
                .paths
                .iter()
                .filter(|p| p.iter().any(|e| e.id == *id))
                .count();
            assert!(n <= 1, "{id:?} in {n} paths");
        }
        assert!(log.len() > PATHS * ALPHA, "the lookup made no progress");
    }

    /// Seeds `seeds`, a first round of requests, and the response of
    /// `from` made of `records`.
    fn lookup_with(seeds: &[(NodeId, NodeRecord)]) -> (Lookup, Vec<NodeId>) {
        let mut lookup = Lookup::new([0; 32], seeds.to_vec(), POLICY, 0);
        let sent = ids(&lookup.next_requests(0));
        (lookup, sent)
    }

    #[test]
    fn invalid_record_makes_responder_suspect() {
        let mut rng = StdRng::seed_from_u64(3);
        let seeds = nodes(&mut rng, 3);
        let fresh = nodes(&mut rng, 4);
        let (mut lookup, sent) = lookup_with(&seeds);
        assert_eq!(sent.len(), 3);
        let liar = sent[0];
        let mut records: Vec<NodeRecord> = fresh.iter().map(|(_, r)| r.clone()).collect();
        // Bad signature: the signed date no longer matches.
        records[3].issued_at -= 3600;
        lookup.on_response(&liar, records, NOW_SECS);
        // The other seeds answer without teaching anything.
        for id in &sent[1..] {
            lookup.on_response(id, vec![], NOW_SECS);
        }
        // No record from the suspect response is queried.
        assert!(lookup.next_requests(0).is_empty());
        assert!(lookup.is_done(0));
        assert!(!ids(&lookup.result()).contains(&liar));
        assert!(!ids(&lookup.responders()).contains(&liar));
        assert_eq!(lookup.result().len(), 2);
        // A second response from the suspect remains ignored.
        let valid: Vec<NodeRecord> = fresh.iter().map(|(_, r)| r.clone()).collect();
        lookup.on_response(&liar, valid, NOW_SECS);
        assert!(lookup.next_requests(0).is_empty());
        assert!(!ids(&lookup.result()).contains(&liar));
    }

    #[test]
    fn oversized_response_is_suspect() {
        let mut rng = StdRng::seed_from_u64(4);
        let seeds = nodes(&mut rng, 1);
        let fresh = nodes(&mut rng, MAX_NODES_PER_RESPONSE + 1);
        let records: Vec<NodeRecord> = fresh.iter().map(|(_, r)| r.clone()).collect();
        assert_eq!(
            filter_nodes(records.clone(), NOW_SECS, &POLICY),
            Err(Suspect)
        );
        assert_eq!(
            filter_nodes(records[..20].to_vec(), NOW_SECS, &POLICY).map(|v| v.len()),
            Ok(20)
        );
        let (mut lookup, sent) = lookup_with(&seeds);
        lookup.on_response(&sent[0], records, NOW_SECS);
        assert!(lookup.next_requests(0).is_empty());
        assert!(lookup.is_done(0));
        assert!(lookup.result().is_empty());
        assert!(lookup.responders().is_empty());
    }

    #[test]
    fn filter_drops_duplicates_silently() {
        let mut rng = StdRng::seed_from_u64(5);
        let (id, rec) = node(&mut rng, 0);
        let out = filter_nodes(vec![rec.clone(), rec.clone()], NOW_SECS, &POLICY).unwrap();
        assert_eq!(out, vec![(id, rec)]);
    }

    #[test]
    fn unresponsive_nodes_time_out() {
        let mut rng = StdRng::seed_from_u64(6);
        let seeds = nodes(&mut rng, K);
        let mut lookup = Lookup::new([0; 32], seeds, POLICY, 0);
        let first = ids(&lookup.next_requests(0));
        assert_eq!(first.len(), PATHS * ALPHA);
        assert!(lookup.next_requests(REQUEST_TIMEOUT_MS - 1).is_empty());
        let second = ids(&lookup.next_requests(REQUEST_TIMEOUT_MS));
        assert_eq!(second.len(), PATHS * ALPHA);
        assert!(second.iter().all(|id| !first.contains(id)));
        // A late response from an expired node is ignored.
        lookup.on_response(&first[0], vec![], NOW_SECS);
        assert!(lookup.responders().is_empty());
        assert!(!lookup.is_done(LOOKUP_TIMEOUT_MS - 1));
        assert!(lookup.is_done(LOOKUP_TIMEOUT_MS));
        assert!(lookup.next_requests(LOOKUP_TIMEOUT_MS).is_empty());
    }

    #[test]
    fn failures_free_a_slot() {
        let mut rng = StdRng::seed_from_u64(7);
        let seeds = nodes(&mut rng, K);
        let mut lookup = Lookup::new([0; 32], seeds, POLICY, 0);
        let first = ids(&lookup.next_requests(0));
        lookup.on_failure(&first[0]);
        assert_eq!(lookup.next_requests(1).len(), 1);
    }

    #[test]
    fn result_excludes_unconfirmed() {
        let mut rng = StdRng::seed_from_u64(8);
        let seeds = nodes(&mut rng, 1);
        let (heard, rec) = node(&mut rng, 1);
        let (mut lookup, sent) = lookup_with(&seeds);
        lookup.on_response(&sent[0], vec![rec], NOW_SECS);
        assert_eq!(ids(&lookup.next_requests(0)), vec![heard]);
        lookup.on_failure(&heard);
        assert!(lookup.is_done(0));
        assert_eq!(ids(&lookup.result()), vec![sent[0]]);
        assert_eq!(ids(&lookup.responders()), vec![sent[0]]);
    }

    #[test]
    fn known_signature_with_other_content_is_suspect() {
        let mut rng = StdRng::seed_from_u64(10);
        let seeds = nodes(&mut rng, 2);
        let (_, rec) = node(&mut rng, 2);
        let (mut lookup, sent) = lookup_with(&seeds);
        lookup.on_response(&sent[0], vec![rec.clone()], NOW_SECS);
        // Same signature, other address: the already verified record does not
        // cover it.
        let mut forged = rec;
        forged.v4 = Some("11.200.0.1:4433".parse().unwrap());
        lookup.on_response(&sent[1], vec![forged], NOW_SECS);
        assert_eq!(ids(&lookup.responders()), vec![sent[0]]);
    }

    #[test]
    fn known_record_still_checks_date() {
        let mut rng = StdRng::seed_from_u64(11);
        let seeds = nodes(&mut rng, 2);
        let (_, rec) = node(&mut rng, 2);
        let (mut lookup, sent) = lookup_with(&seeds);
        lookup.on_response(&sent[0], vec![rec.clone()], NOW_SECS);
        // The clock went backwards: the same record now comes from the future.
        let past = rec.issued_at - MAX_RECORD_SKEW_SECS - 1;
        lookup.on_response(&sent[1], vec![rec], past);
        assert_eq!(ids(&lookup.responders()), vec![sent[0]]);
    }

    #[test]
    fn suspect_offered_by_another_path_is_never_queried() {
        let mut rng = StdRng::seed_from_u64(12);
        let seeds = nodes(&mut rng, 3);
        let (mut lookup, sent) = lookup_with(&seeds);
        let liar = sent[0];
        let liar_rec = seeds.iter().find(|(id, _)| *id == liar).unwrap().1.clone();
        let (_, mut bad) = node(&mut rng, 3);
        bad.issued_at -= 3600;
        lookup.on_response(&liar, vec![bad], NOW_SECS);
        // The other paths learn the suspect's valid record.
        for id in &sent[1..] {
            lookup.on_response(id, vec![liar_rec.clone()], NOW_SECS);
        }
        assert!(lookup.next_requests(0).is_empty());
        assert!(lookup.is_done(0));
        assert!(!ids(&lookup.result()).contains(&liar));
        assert!(lookup.paths[1..].iter().flatten().all(|e| e.id != liar));
    }

    #[test]
    fn flooded_path_lets_other_paths_finish() {
        let mut rng = StdRng::seed_from_u64(13);
        let seeds = nodes(&mut rng, 3);
        let fakes = nodes(&mut rng, MAX_NODES_PER_RESPONSE);
        let honest: Vec<_> = (0..6).map(|i| node(&mut rng, 100 + i)).collect();
        let fake_ids: HashSet<NodeId> = fakes.iter().map(|(id, _)| *id).collect();
        let (mut lookup, sent) = lookup_with(&seeds);
        // Path 0 is flooded with nodes that never answer.
        lookup.on_response(
            &sent[0],
            fakes.into_iter().map(|(_, r)| r).collect(),
            NOW_SECS,
        );
        lookup.on_response(
            &sent[1],
            honest[..3].iter().map(|(_, r)| r.clone()).collect(),
            NOW_SECS,
        );
        lookup.on_response(
            &sent[2],
            honest[3..].iter().map(|(_, r)| r.clone()).collect(),
            NOW_SECS,
        );
        loop {
            let reqs = lookup.next_requests(0);
            if reqs.is_empty() {
                break;
            }
            for (id, _) in reqs {
                if !fake_ids.contains(&id) {
                    lookup.on_response(&id, vec![], NOW_SECS);
                }
            }
        }
        let responders = ids(&lookup.responders());
        for (id, _) in &honest {
            assert!(responders.contains(id));
        }
        assert!(responders.iter().all(|id| !fake_ids.contains(id)));
        // The three seeds (the flooding one did answer) and the honest nodes.
        assert_eq!(lookup.result().len(), sent.len() + honest.len());
        // The flooded path keeps the lookup open until its overall timeout.
        assert!(lookup.is_done(LOOKUP_TIMEOUT_MS));
    }

    #[test]
    fn node_owned_by_one_path_is_refused_by_another() {
        let mut rng = StdRng::seed_from_u64(14);
        let seeds = nodes(&mut rng, 3);
        let (x, x_rec) = node(&mut rng, 3);
        let (mut lookup, sent) = lookup_with(&seeds);
        lookup.on_response(&sent[0], vec![x_rec.clone()], NOW_SECS);
        lookup.on_response(&sent[1], vec![x_rec], NOW_SECS);
        assert_eq!(lookup.owner.get(&x), Some(&0));
        assert!(lookup.paths[0].iter().any(|e| e.id == x));
        assert!(lookup.paths[1].iter().all(|e| e.id != x));
        assert_eq!(ids(&lookup.next_requests(0)), vec![x]);
    }

    #[test]
    fn trimmed_unqueried_node_is_released() {
        let mut rng = StdRng::seed_from_u64(9);
        let target = [0; 32];
        let mut all = nodes(&mut rng, 30);
        all.sort_by_key(|(id, _)| distance(&id.0, &target));
        // The two closest: one seed per path (0 then 1).
        let mut lookup = Lookup::new(target, all[..2].to_vec(), POLICY, 0);
        let sent = ids(&lookup.next_requests(0));
        assert_eq!(sent, ids(&all[..2]));
        let (x, x_rec) = all[29].clone();
        // Path 0 learns X with 19 closer nodes: its list
        // (seed included) exceeds K, X is dropped from it without being queried.
        let mut records: Vec<NodeRecord> = all[2..21].iter().map(|(_, r)| r.clone()).collect();
        records.push(x_rec.clone());
        lookup.on_response(&sent[0], records, NOW_SECS);
        assert!(lookup.paths[0].iter().all(|e| e.id != x));
        // Path 1 receives X from an honest node and must retake it.
        lookup.on_response(&sent[1], vec![x_rec], NOW_SECS);
        assert!(lookup.paths[1].iter().any(|e| e.id == x));
        let log = ids(&lookup.next_requests(0));
        assert!(log.contains(&x));
        let unique: HashSet<NodeId> = log.iter().copied().collect();
        assert_eq!(unique.len(), log.len());
    }
}
