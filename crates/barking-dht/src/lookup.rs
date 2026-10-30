//! Recherche itérative S/Kademlia sur `PATHS` chemins disjoints (spec §6.3).
//! Machine à états pure : l'appelant envoie les `FindNode` que donne
//! `next_requests`, puis lui rend les réponses (`on_response`) et les échecs
//! (`on_failure`). Les délais se mesurent avec l'horloge fournie par
//! l'appelant, en millisecondes.

use std::collections::{HashMap, HashSet};

use barking_proto::{MAX_NODES_PER_RESPONSE, NodeId, NodeRecord, RecordPolicy};

use crate::{ALPHA, K, MAX_PER_PREFIX, PATHS, Prefix, distance, prefixes};

/// Délai d'une requête `FindNode`, en millisecondes.
pub const REQUEST_TIMEOUT_MS: u64 = 3_000;
/// Durée maximale d'une recherche, en millisecondes.
pub const LOOKUP_TIMEOUT_MS: u64 = 10_000;

/// Réponse `Nodes` dont l'auteur devient suspect : au moins une fiche
/// invalide, ou plus de `MAX_NODES_PER_RESPONSE` fiches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suspect;

/// Filtre une réponse `Nodes` : vérifie chaque fiche et écarte les doublons.
/// Une seule fiche invalide, ou une réponse trop longue, rend l'auteur
/// suspect et fait ignorer la réponse entière.
pub fn filter_nodes(
    records: Vec<NodeRecord>,
    now_secs: u64,
    policy: &RecordPolicy,
) -> Result<Vec<(NodeId, NodeRecord)>, Suspect> {
    if records.len() > MAX_NODES_PER_RESPONSE {
        return Err(Suspect);
    }
    let mut seen = HashSet::with_capacity(records.len());
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let id = record.verify(now_secs, policy).map_err(|_| Suspect)?;
        if seen.insert(id) {
            out.push((id, record));
        }
    }
    Ok(out)
}

/// État d'un nœud dans la liste d'un chemin.
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

/// Recherche en cours d'une cible.
#[derive(Debug)]
pub struct Lookup {
    target: [u8; 32],
    policy: RecordPolicy,
    started_ms: u64,
    /// Liste de chaque chemin, triée par distance.
    paths: Vec<Vec<Entry>>,
    /// Chemin propriétaire de chaque nœud déjà vu : un nœud n'appartient
    /// qu'à un chemin.
    owner: HashMap<NodeId, usize>,
    /// Nœuds jamais repris (le nœud qui cherche).
    excluded: HashSet<NodeId>,
    suspects: HashSet<NodeId>,
    /// Nœuds qui ont répondu correctement, dans l'ordre des réponses.
    responded: Vec<(NodeId, NodeRecord)>,
}

impl Lookup {
    /// Démarre une recherche ; les graines sont triées par distance puis
    /// réparties à tour de rôle entre les chemins.
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

    /// Écarte un identifiant de la recherche (le nœud qui cherche) : il n'est
    /// jamais interrogé ni retenu.
    pub fn excluding(mut self, id: NodeId) -> Lookup {
        if let Some(path) = self.owner.remove(&id) {
            self.paths[path].retain(|e| e.id != id);
        }
        self.responded.retain(|(r, _)| *r != id);
        self.excluded.insert(id);
        self
    }

    /// Ajoute un nœud à la liste d'un chemin, sans trier.
    fn add(&mut self, path: usize, id: NodeId, record: NodeRecord) {
        self.owner.insert(id, path);
        self.paths[path].push(Entry {
            id,
            record,
            dist: distance(&id.0, &self.target),
            state: State::Waiting,
        });
    }

    /// Trie la liste d'un chemin et la tronque à `K` ; les nœuds en vol
    /// au-delà restent, pour que leur réponse soit encore attendue.
    fn trim(&mut self, path: usize) {
        let list = &mut self.paths[path];
        list.sort_by_key(|e| e.dist);
        let mut rank = 0;
        list.retain(|e| {
            rank += 1;
            rank <= K || matches!(e.state, State::InFlight { .. })
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

    /// `FindNode` à envoyer maintenant, `ALPHA` en vol au plus par chemin.
    /// Une requête en vol depuis `REQUEST_TIMEOUT_MS` compte comme un échec.
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
            // La liste est triée : les premiers en attente sont les plus
            // proches.
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

    /// Réponse `Nodes` de `from` ; ignorée si aucune requête n'est en vol
    /// vers lui.
    pub fn on_response(&mut self, from: &NodeId, records: Vec<NodeRecord>, now_secs: u64) {
        let policy = self.policy;
        let Some((path, entry)) = self.entry_mut(from) else {
            return;
        };
        if !matches!(entry.state, State::InFlight { .. }) {
            return;
        }
        let Ok(nodes) = filter_nodes(records, now_secs, &policy) else {
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
                // Déjà dans un autre chemin : jamais repris (chemins disjoints).
                Some(&other) if other != path => {}
                // Déjà dans ce chemin : une fiche plus récente remplace
                // l'ancienne tant que le nœud n'a pas été interrogé.
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

    /// Échec de la requête vers `from` (connexion, erreur, délai).
    pub fn on_failure(&mut self, from: &NodeId) {
        if let Some((_, entry)) = self.entry_mut(from)
            && matches!(entry.state, State::InFlight { .. })
        {
            entry.state = State::Failed;
        }
    }

    /// Vrai quand tous les chemins sont épuisés, ou après `LOOKUP_TIMEOUT_MS`.
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

    /// Nœuds qui ont répondu, triés par distance à la cible, `K` au plus et
    /// `MAX_PER_PREFIX` par bloc.
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

    /// Nœuds qui ont répondu correctement : candidats pour la table.
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

    /// Nœud au /24 propre à `i`.
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

    /// Réseau factice : chaque nœud connaît tous les autres (dans la limite
    /// de sa table) et répond par `closest_diverse`.
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

    /// Fait tourner la recherche sur le réseau factice ; renvoie le journal
    /// des requêtes émises.
    fn run(
        lookup: &mut Lookup,
        net: &HashMap<NodeId, RoutingTable>,
        target: &[u8; 32],
    ) -> Vec<NodeId> {
        let mut log = Vec::new();
        let now_ms = 0;
        while !lookup.is_done(now_ms) {
            let reqs = lookup.next_requests(now_ms);
            assert!(!reqs.is_empty(), "recherche bloquée");
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
                assert!(found.contains(id), "tour {round} : {id:?} manquant");
            }
            assert!(!found.contains(&me));
            // Trié par distance.
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
        assert_eq!(unique.len(), log.len(), "un nœud interrogé deux fois");
        // Chaque nœud interrogé n'apparaît que dans un seul chemin.
        for id in &log {
            let n = lookup
                .paths
                .iter()
                .filter(|p| p.iter().any(|e| e.id == *id))
                .count();
            assert!(n <= 1, "{id:?} dans {n} chemins");
        }
        assert!(log.len() > PATHS * ALPHA, "la recherche n'a pas progressé");
    }

    /// Graines `seeds`, un premier tour de requêtes, et la réponse de
    /// `from` faite de `records`.
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
        // Mauvaise signature : la date signée ne correspond plus.
        records[3].issued_at -= 3600;
        lookup.on_response(&liar, records, NOW_SECS);
        // Les autres graines répondent sans rien apprendre.
        for id in &sent[1..] {
            lookup.on_response(id, vec![], NOW_SECS);
        }
        // Aucune fiche de la réponse suspecte n'est interrogée.
        assert!(lookup.next_requests(0).is_empty());
        assert!(lookup.is_done(0));
        assert!(!ids(&lookup.result()).contains(&liar));
        assert!(!ids(&lookup.responders()).contains(&liar));
        assert_eq!(lookup.result().len(), 2);
        // Une seconde réponse du suspect reste ignorée.
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
        // Une réponse tardive d'un nœud expiré est ignorée.
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
}
