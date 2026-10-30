//! Simulation déterministe de 500 nœuds (spec §1, critères 1 à 4 ; §9).
//!
//! Aucun réseau : chaque nœud n'est qu'une `RoutingTable`, et le harnais
//! répond de manière synchrone aux `FindNode` d'une recherche depuis la table
//! du nœud interrogé. Un nœud mort ou muet ne répond jamais : sa requête
//! reste en vol et occupe sa place jusqu'à l'expiration du délai de 3 s, et
//! la recherche entière reste bornée à 10 s. Une graine fixe et une horloge
//! simulée rendent chaque exécution identique.

use std::collections::{BTreeSet, HashMap};

use barking_dht::{
    Insert, K, Lookup, Prefix, REPLICAS, RoutingTable, distance, lookup::LOOKUP_TIMEOUT_MS,
    prefixes,
};
use barking_proto::{NodeId, NodeRecord, RecordPolicy};
use ed25519_dalek::SigningKey;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng, seq::SliceRandom};

/// Fiches sans puzzle, adresses privées admises : seule la simulation le peut.
const POLICY: RecordPolicy = RecordPolicy {
    allow_private: true,
    puzzle_bits: 0,
};
/// Nœuds du réseau.
const NODES: usize = 500;
/// Recherches mesurées par scénario.
const LOOKUPS: usize = 1_000;
/// Début de l'horloge simulée, en secondes.
const T0: u64 = 1_700_000_000;
/// Aller-retour simulé d'un tour de requêtes, en millisecondes.
const ROUND_MS: u64 = 50;
/// Bloc /24 commun à toutes les identités Sybil.
const SYBIL_BLOCK: [u8; 3] = [10, 9, 8];
/// Nœud d'amorçage commun.
const BOOT: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    Honest,
    /// Ne renvoie que les 20 complices les plus proches de la cible.
    OnlyColluders,
    /// Renvoie des fiches invalides.
    Garbage,
    /// Ne répond rien, pas même aux `Ping`.
    Silent,
}

struct Node {
    id: NodeId,
    record: NodeRecord,
    table: RoutingTable,
    behaviour: Behaviour,
    alive: bool,
}

/// Issue d'une recherche : le harnais applique ensuite ce que chaque nœud
/// en apprend (`learn`).
struct Search {
    lookup: Lookup,
    /// Nœuds interrogés qui ont répondu.
    answered: Vec<usize>,
    /// Nœuds interrogés qui n'ont pas répondu.
    failed: Vec<usize>,
    /// Durée simulée de la recherche.
    elapsed_ms: u64,
}

struct Net {
    nodes: Vec<Node>,
    index: HashMap<NodeId, usize>,
    /// Complices `OnlyColluders`, dans l'ordre d'arrivée.
    colluders: Vec<usize>,
    /// Prochain /24 libre pour un nœud à bloc propre.
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

    /// Réseau amorcé depuis `BOOT` : `honest` nœuds honnêtes et les
    /// adversaires donnés, arrivés dans un ordre aléatoire, chacun sur un /24
    /// propre.
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

    /// Crée un nœud, sur un /24 propre si `addr` est `None`.
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

    /// Le nœud répond à un `Ping` (connexion et `Pong`).
    fn answers_ping(&self, i: usize) -> bool {
        self.nodes[i].alive && self.nodes[i].behaviour != Behaviour::Silent
    }

    /// `at` contacte directement `peer` (connexion puis `Pong` valide).
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

    /// `at` pinge un nœud déjà connu : il reste s'il répond, sinon l'échec
    /// est compté.
    fn ping(&mut self, at: usize, peer: usize) {
        if self.answers_ping(peer) {
            let (id, record) = (self.nodes[peer].id, self.nodes[peer].record.clone());
            let now = self.now_secs();
            self.nodes[at].table.on_contact(id, record, now);
        } else {
            self.fail(at, peer);
        }
    }

    /// Échec de contact de `at` vers `peer` ; au retrait de `peer`, la
    /// candidate de la réserve est contactée pour être promue.
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

    /// Réponse de `to` à un `FindNode` de `target` ; `None` si rien ne vient.
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
                        // La signature ne couvre plus la date.
                        r.issued_at -= 3600;
                        r
                    })
                    .collect(),
            ),
            Behaviour::Silent => None,
        }
    }

    /// Recherche synchrone de `target` par `from`, sans rien modifier.
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
            // Une réponse arrive dans le tour de sa requête. Sans réponse, la
            // requête reste en vol : `next_requests` la déclare échouée après
            // `REQUEST_TIMEOUT_MS`, et `is_done` arrête la recherche après
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

    /// Recherche menée par un nœud vivant : les nœuds interrogés apprennent
    /// l'appelant, l'appelant compte les échecs et contacte les répondeurs.
    fn run_lookup(&mut self, from: usize, target: &[u8; 32]) {
        let search = self.search(from, target);
        self.learn(from, search);
    }

    /// Applique aux tables ce que la recherche de `from` a appris.
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

    /// Recherche de mesure : identifiants trouvés et durée simulée, sans
    /// effet sur les tables.
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

    /// Amorçage depuis `BOOT` puis recherche de son propre identifiant.
    fn join(&mut self, i: usize) {
        self.contact(i, BOOT);
        self.contact(BOOT, i);
        let own = self.nodes[i].id.0;
        self.run_lookup(i, &own);
    }

    /// Fait passer `count` nœuds honnêtes au hasard (hors amorçage) au
    /// comportement donné, une fois le réseau formé.
    fn turn(&mut self, behaviour: Behaviour, count: usize) {
        let mut candidates: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| i != BOOT && self.nodes[i].behaviour == Behaviour::Honest)
            .collect();
        candidates.shuffle(&mut self.rng);
        for &i in &candidates[..count] {
            self.nodes[i].behaviour = behaviour;
        }
    }

    /// Tue `count` nœuds au hasard (hors amorçage).
    fn kill(&mut self, count: usize) {
        let mut candidates: Vec<usize> = (0..self.nodes.len())
            .filter(|&i| i != BOOT && self.nodes[i].alive)
            .collect();
        candidates.shuffle(&mut self.rng);
        for &i in &candidates[..count] {
            self.nodes[i].alive = false;
        }
    }

    /// Les `n` nœuds honnêtes vivants les plus proches de `key`, calculés sur
    /// l'ensemble du réseau.
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

    /// Cycle d'entretien de chaque nœud vivant, une heure plus tard : pings
    /// des têtes périmées jusqu'à l'éviction des morts (avec promotion depuis
    /// la réserve), puis rafraîchissement de chaque compartiment par une
    /// recherche.
    ///
    /// Les recherches de rafraîchissement de tous les nœuds partent ensemble,
    /// sur les tables issues des pings, comme dans un réseau où chacun
    /// entretient sa table en même temps ; ce qu'elles apprennent est
    /// appliqué ensuite, dans l'ordre des nœuds.
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

    /// Passe de recopie : chaque gardien vivant recopie vers les responsables
    /// que lui donne sa table ; un responsable accepte si l'appelant et
    /// lui-même sont dans sa fenêtre de responsabilité (spec §5.2, point 4).
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

/// Boîte aux lettres : sa clé et les nœuds qui en gardent une copie.
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

/// Part des recherches qui trouvent au moins `need` des 5 vrais
/// responsables honnêtes, lancées depuis des nœuds honnêtes au hasard ;
/// affiche aussi leur durée simulée.
fn success_rate(net: &mut Net, need: usize) -> f64 {
    let jobs: Vec<([u8; 32], usize)> = (0..LOOKUPS)
        .map(|_| (net.key(), net.random_honest()))
        .collect();
    let net = &*net;
    let outcomes = par_map(&jobs, |(key, from)| {
        let truth = net.truth(key, REPLICAS);
        let (mut found, elapsed_ms) = net.probe(*from, key);
        // Le nœud qui cherche se connaît lui-même.
        found.push(net.nodes[*from].id);
        let hit = truth
            .iter()
            .filter(|&&t| found.contains(&net.nodes[t].id))
            .count()
            >= need;
        (hit, elapsed_ms)
    });
    let hits = outcomes.iter().filter(|(hit, _)| *hit).count();
    let mut durations: Vec<u64> = outcomes.iter().map(|&(_, ms)| ms).collect();
    durations.sort_unstable();
    let timed_out = durations
        .iter()
        .filter(|&&ms| ms >= LOOKUP_TIMEOUT_MS)
        .count();
    eprintln!(
        "durée simulée : médiane {} ms, max {} ms, {timed_out} recherches arrêtées à {LOOKUP_TIMEOUT_MS} ms",
        durations[durations.len() / 2],
        durations[durations.len() - 1],
    );
    hits as f64 / LOOKUPS as f64
}

/// `f` appliquée à chaque élément sur tous les cœurs, résultats dans l'ordre
/// des éléments : la vérification des signatures domine le temps de calcul.
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
    let rate = success_rate(&mut net, REPLICAS);
    eprintln!("réseau honnête : {:.1} % trouvent les 5", rate * 100.0);
    assert!(rate > 0.99, "taux {rate}");
}

#[test]
fn twenty_percent_liars_still_find_three() {
    let liars = NODES / 5;
    let mut net = Net::build(2, NODES - liars, &[(Behaviour::OnlyColluders, liars)]);
    let rate = success_rate(&mut net, 3);
    eprintln!("20 % de menteurs : {:.1} % trouvent 3 des 5", rate * 100.0);
    assert!(rate > 0.95, "taux {rate}");
}

#[test]
fn liars_garbage_and_silent_do_not_break_lookups() {
    // Les nœuds entrent honnêtes dans les tables, puis tournent : sinon un
    // nœud muet n'y entrerait jamais.
    let mut net = Net::build(5, NODES, &[]);
    net.turn(Behaviour::Garbage, NODES / 10);
    net.turn(Behaviour::Silent, NODES / 10);
    let rate = success_rate(&mut net, 3);
    eprintln!(
        "10 % de fiches invalides, 10 % de muets : {:.1} % trouvent 3 des 5",
        rate * 100.0
    );
    assert!(rate > 0.95, "taux {rate}");
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
        // L'attaquant se fait contacter par chaque nœud honnête.
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
            "nœud {h} : {sybils} Sybil sur {} actifs",
            active.len()
        );
        worst = worst.max(sybils as f64 / active.len() as f64);
    }
    eprintln!("Sybil : part maximale {:.1} % d'une table", worst * 100.0);
}

#[test]
fn churn_restores_five_copies_in_two_passes() {
    let mut net = Net::build(4, NODES, &[]);
    // 1. Dépôt de chaque boîte sur 3 de ses responsables.
    let mut boxes: Vec<Mailbox> = (0..100)
        .map(|_| {
            let key = net.key();
            let holders = net.truth(&key, 3).into_iter().collect();
            Mailbox { key, holders }
        })
        .collect();
    // 2. Recopie jusqu'à 5 copies, sur les 5 vrais responsables.
    for _ in 0..3 {
        net.replication_pass(&mut boxes);
    }
    for mailbox in &boxes {
        let truth: BTreeSet<usize> = net.truth(&mailbox.key, REPLICAS).into_iter().collect();
        assert!(
            mailbox.holders.is_superset(&truth),
            "recopie initiale incomplète"
        );
    }
    // 3. Départ de 30 % des nœuds.
    net.kill(NODES * 3 / 10);
    for mailbox in &boxes {
        assert!(
            !mailbox.live_holders(&net).is_empty(),
            "boîte perdue avec toutes ses copies"
        );
    }
    // Les départs ont bien privé des boîtes de copies : c'est la réparation
    // qui fait passer le test.
    let damaged = short_of_five(&net, &boxes);
    assert!(damaged > 0, "aucune boîte touchée par les départs");
    // 4. Un cycle d'entretien des tables.
    net.maintenance_cycle();
    // 5. Deux passes de recopie.
    net.replication_pass(&mut boxes);
    net.replication_pass(&mut boxes);
    let short = short_of_five(&net, &boxes);
    eprintln!("départs : {damaged} boîtes sur 100 touchées, {short} encore sans leurs 5 copies");
    assert_eq!(short, 0);
}

/// Boîtes qui n'ont pas une copie vivante sur chacun de leurs 5 vrais
/// responsables vivants.
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
