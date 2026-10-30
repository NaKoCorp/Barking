//! Table de routage S/Kademlia : 256 compartiments ordonnés par dernier
//! contact, les anciens d'abord, réserve par compartiment et règles de
//! diversité des adresses contre l'éclipse. La table ne vérifie aucune
//! fiche : l'appelant n'y fait entrer un nœud qu'après un contact direct
//! dont la fiche est valide.

use std::{collections::HashMap, iter};

use barking_proto::{NodeId, NodeRecord};
use rand_core::Rng;

use crate::{
    FAILS_BEFORE_EVICT, K, MAX_PER_PREFIX, MAX_PREFIX_SHARE_PERCENT, MIN_PREFIX_ALLOWED, Prefix,
    REFRESH_AFTER_SECS, REPLACEMENTS, REPLICAS, RESPONSIBLE_WINDOW, STALE_AFTER_SECS, bucket_index,
    distance, prefixes,
};

/// Limites de diversité des adresses d'une table. `SPEC` (valeurs de la
/// spec) partout ; d'autres valeurs ne servent qu'aux tests réseau du nœud,
/// où tous les nœuds partagent le /24 de 127.0.0.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversityLimits {
    /// Nœuds d'un même bloc par compartiment (réserve comprise) et par
    /// résultat.
    pub per_prefix: usize,
    /// Part maximale des nœuds actifs de la table pour un même bloc.
    pub share_percent: usize,
    /// Nœuds toujours autorisés par bloc.
    pub min_allowed: usize,
}

impl DiversityLimits {
    /// Valeurs de la spec.
    pub const SPEC: DiversityLimits = DiversityLimits {
        per_prefix: MAX_PER_PREFIX,
        share_percent: MAX_PREFIX_SHARE_PERCENT,
        min_allowed: MIN_PREFIX_ALLOWED,
    };

    /// Aucune limite (tests réseau en local seulement).
    pub const NONE: DiversityLimits = DiversityLimits {
        per_prefix: usize::MAX,
        share_percent: 100,
        min_allowed: usize::MAX,
    };
}

impl Default for DiversityLimits {
    fn default() -> Self {
        DiversityLimits::SPEC
    }
}

/// Nombre de compartiments (un par longueur de préfixe commun).
const BUCKETS: usize = 256;

/// Nœud connu de la table, actif ou en réserve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: NodeId,
    pub record: NodeRecord,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Échecs consécutifs, remis à zéro à chaque contact.
    pub fails: u8,
}

/// Issue d'un contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    /// Nœud déjà actif, rafraîchi.
    Updated,
    /// Nœud devenu actif.
    Added,
    /// Compartiment plein : la candidate est en réserve, et l'appelant doit
    /// pinger `ping`, le nœud actif vu le moins récemment.
    Pending {
        ping: NodeId,
    },
    Rejected(Reject),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Notre propre identifiant.
    Own,
    /// Le nœud ferait dépasser une limite de diversité des adresses.
    Diversity,
    /// Fiche plus ancienne que celle déjà connue.
    Older,
}

#[derive(Clone, Debug, Default)]
struct Bucket {
    /// Nœuds actifs, du moins récemment vu au plus récemment vu.
    active: Vec<Peer>,
    /// Réserve, dans le même ordre.
    reserve: Vec<Peer>,
    /// Date de la dernière recherche dans ce compartiment.
    refreshed_at: u64,
}

pub struct RoutingTable {
    own: NodeId,
    buckets: Vec<Bucket>,
    limits: DiversityLimits,
}

fn position(peers: &[Peer], id: &NodeId) -> Option<usize> {
    peers.iter().position(|p| p.id == *id)
}

/// Compte un échec de `peers[i]` et le retire au `FAILS_BEFORE_EVICT`ᵉ ;
/// vrai s'il a été retiré.
fn count_failure(peers: &mut Vec<Peer>, i: usize) -> bool {
    peers[i].fails = peers[i].fails.saturating_add(1);
    if peers[i].fails < FAILS_BEFORE_EVICT {
        return false;
    }
    peers.remove(i);
    true
}

fn in_block(peer: &Peer, block: &Prefix) -> bool {
    prefixes(&peer.record).contains(block)
}

impl RoutingTable {
    /// Table aux limites de diversité de la spec.
    pub fn new(own: NodeId) -> RoutingTable {
        RoutingTable::with_limits(own, DiversityLimits::SPEC)
    }

    /// Table aux limites de diversité `limits` (tests réseau du nœud).
    pub fn with_limits(own: NodeId, limits: DiversityLimits) -> RoutingTable {
        RoutingTable {
            own,
            buckets: vec![Bucket::default(); BUCKETS],
            limits,
        }
    }

    pub fn own_id(&self) -> NodeId {
        self.own
    }

    /// Enregistre un contact direct réussi avec `id`, dont la fiche a été
    /// vérifiée par l'appelant.
    pub fn on_contact(&mut self, id: NodeId, record: NodeRecord, now: u64) -> Insert {
        let Some(b) = bucket_index(&self.own, &id) else {
            return Insert::Rejected(Reject::Own);
        };
        let bucket = &self.buckets[b];
        let found = position(&bucket.active, &id)
            .map(|i| (true, i))
            .or_else(|| position(&bucket.reserve, &id).map(|i| (false, i)));
        let Some((was_active, i)) = found else {
            return self.insert_new(b, id, record, now);
        };
        let old = if was_active {
            &bucket.active[i]
        } else {
            &bucket.reserve[i]
        };
        if record.issued_at < old.record.issued_at {
            return Insert::Rejected(Reject::Older);
        }
        // Une fiche de même date garde l'ancienne ; une plus récente la
        // remplace si ses blocs respectent encore la diversité.
        let replace = record.issued_at > old.record.issued_at;
        let blocks = prefixes(if replace { &record } else { &old.record });
        if replace
            && blocks != prefixes(&old.record)
            && !self.diversity_ok(b, &id, &blocks, was_active)
        {
            return Insert::Rejected(Reject::Diversity);
        }
        let room = bucket.active.len() < K;
        let promote = !was_active && room && self.diversity_ok(b, &id, &blocks, true);

        let bucket = &mut self.buckets[b];
        let mut peer = if was_active {
            bucket.active.remove(i)
        } else {
            bucket.reserve.remove(i)
        };
        if replace {
            peer.record = record;
        }
        peer.last_seen = now;
        peer.fails = 0;
        if was_active {
            bucket.active.push(peer);
            return Insert::Updated;
        }
        if promote {
            bucket.active.push(peer);
            return Insert::Added;
        }
        // Candidate de la réserve recontactée sans pouvoir être promue.
        bucket.reserve.push(peer);
        match bucket.active.first() {
            Some(head) if !room => Insert::Pending { ping: head.id },
            _ => Insert::Rejected(Reject::Diversity),
        }
    }

    /// Réponse lisible d'un nœud connu, hors contact vérifié : ses échecs
    /// sont remis à zéro et il est vu à `now` (fin de l'ordre de son
    /// compartiment, comme après un contact), sa fiche est inchangée. Vrai
    /// s'il est connu.
    pub fn mark_alive(&mut self, id: &NodeId, now: u64) -> bool {
        let Some(b) = bucket_index(&self.own, id) else {
            return false;
        };
        let bucket = &mut self.buckets[b];
        for peers in [&mut bucket.active, &mut bucket.reserve] {
            if let Some(i) = position(peers, id) {
                let mut peer = peers.remove(i);
                peer.fails = 0;
                peer.last_seen = peer.last_seen.max(now);
                peers.push(peer);
                return true;
            }
        }
        false
    }

    fn insert_new(&mut self, b: usize, id: NodeId, record: NodeRecord, now: u64) -> Insert {
        let full = self.buckets[b].active.len() >= K;
        if !self.diversity_ok(b, &id, &prefixes(&record), !full) {
            return Insert::Rejected(Reject::Diversity);
        }
        let peer = Peer {
            id,
            record,
            first_seen: now,
            last_seen: now,
            fails: 0,
        };
        let bucket = &mut self.buckets[b];
        if !full {
            bucket.active.push(peer);
            return Insert::Added;
        }
        if bucket.reserve.len() >= REPLACEMENTS {
            bucket.reserve.remove(0);
        }
        bucket.reserve.push(peer);
        Insert::Pending {
            ping: bucket.active[0].id,
        }
    }

    /// Vrai si `id`, avec les blocs `blocks`, respecte la limite par
    /// compartiment (réserve comprise) et, s'il devient actif, la part
    /// maximale de la table. `id` lui-même n'est pas compté.
    fn diversity_ok(&self, b: usize, id: &NodeId, blocks: &[Prefix], to_active: bool) -> bool {
        let bucket = &self.buckets[b];
        let neighbours = || {
            bucket
                .active
                .iter()
                .chain(&bucket.reserve)
                .filter(|p| p.id != *id)
        };
        if blocks.iter().any(|block| {
            neighbours().filter(|p| in_block(p, block)).count() >= self.limits.per_prefix
        }) {
            return false;
        }
        if !to_active {
            return true;
        }
        let others = || self.active().filter(|p| p.id != *id);
        let total = others().count() + 1;
        let limit = (self.limits.min_allowed).max(total * self.limits.share_percent / 100);
        blocks
            .iter()
            .all(|block| others().filter(|p| in_block(p, block)).count() < limit)
    }

    /// Compte un échec de contact avec `id`. Au `FAILS_BEFORE_EVICT`ᵉ échec
    /// consécutif, un nœud actif est retiré et la candidate de la réserve
    /// vue le plus récemment est renvoyée : l'appelant la contacte, et
    /// `on_contact` la promeut.
    pub fn on_failure(&mut self, id: &NodeId) -> Option<NodeId> {
        let bucket = &mut self.buckets[bucket_index(&self.own, id)?];
        if let Some(i) = position(&bucket.active, id) {
            if !count_failure(&mut bucket.active, i) {
                return None;
            }
            return bucket.reserve.last().map(|p| p.id);
        }
        let i = position(&bucket.reserve, id)?;
        count_failure(&mut bucket.reserve, i);
        None
    }

    fn active(&self) -> impl Iterator<Item = &Peer> + Clone {
        self.buckets.iter().flat_map(|b| &b.active)
    }

    /// Les `n` nœuds actifs les plus proches de `target`.
    pub fn closest(&self, target: &[u8; 32], n: usize) -> Vec<Peer> {
        let mut peers: Vec<&Peer> = self.active().collect();
        peers.sort_by_cached_key(|p| distance(&p.id.0, target));
        peers.into_iter().take(n).cloned().collect()
    }

    /// Comme `closest`, avec au plus `per_prefix` nœuds par bloc.
    pub fn closest_diverse(&self, target: &[u8; 32], n: usize) -> Vec<NodeRecord> {
        let mut peers: Vec<&Peer> = self.active().collect();
        peers.sort_by_cached_key(|p| distance(&p.id.0, target));
        let mut counts: HashMap<Prefix, usize> = HashMap::new();
        let mut out = Vec::new();
        for peer in peers {
            if out.len() >= n {
                break;
            }
            let blocks = prefixes(&peer.record);
            if blocks
                .iter()
                .any(|b| counts.get(b).copied().unwrap_or(0) >= self.limits.per_prefix)
            {
                continue;
            }
            for block in blocks {
                *counts.entry(block).or_default() += 1;
            }
            out.push(peer.record.clone());
        }
        out
    }

    /// Distance à `key` du `RESPONSIBLE_WINDOW`ᵉ nœud le plus proche, nous
    /// compris ; `None` (borne infinie) si la table compte moins de
    /// `RESPONSIBLE_WINDOW` nœuds actifs (spec §5.2, point 4).
    pub fn proximity_bound(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        if self.len() < RESPONSIBLE_WINDOW {
            return None;
        }
        let mut dists: Vec<[u8; 32]> = self
            .active()
            .map(|p| distance(&p.id.0, key))
            .chain(iter::once(distance(&self.own.0, key)))
            .collect();
        let (_, nth, _) = dists.select_nth_unstable(RESPONSIBLE_WINDOW - 1);
        Some(*nth)
    }

    /// Vrai si `id` est dans la fenêtre de responsabilité de `key`.
    pub fn may_hold(&self, key: &[u8; 32], id: &NodeId) -> bool {
        self.proximity_bound(key)
            .is_none_or(|bound| distance(&id.0, key) <= bound)
    }

    /// Responsables de `key` vers qui recopier : les `REPLICAS` plus
    /// proches, nous compris, moins nous. `None` si nous sommes hors de la
    /// fenêtre de responsabilité.
    pub fn replica_targets(&self, key: &[u8; 32]) -> Option<Vec<NodeId>> {
        if !self.may_hold(key, &self.own) {
            return None;
        }
        let mut ids: Vec<NodeId> = self
            .active()
            .map(|p| p.id)
            .chain(iter::once(self.own))
            .collect();
        ids.sort_by_cached_key(|id| distance(&id.0, key));
        Some(
            ids.into_iter()
                .take(REPLICAS)
                .filter(|id| *id != self.own)
                .collect(),
        )
    }

    /// Tête (nœud actif vu le moins récemment) de chaque compartiment, si
    /// elle n'a pas été vue depuis `STALE_AFTER_SECS`.
    pub fn stale_heads(&self, now: u64) -> Vec<NodeId> {
        self.buckets
            .iter()
            .filter_map(|b| b.active.first())
            .filter(|p| now.saturating_sub(p.last_seen) >= STALE_AFTER_SECS)
            .map(|p| p.id)
            .collect()
    }

    /// Compartiments sans recherche depuis `REFRESH_AFTER_SECS`, jusqu'au
    /// plus profond compartiment non vide.
    pub fn buckets_to_refresh(&self, now: u64) -> Vec<usize> {
        let Some(deepest) = self.buckets.iter().rposition(|b| !b.active.is_empty()) else {
            return Vec::new();
        };
        (0..=deepest)
            .filter(|&i| now.saturating_sub(self.buckets[i].refreshed_at) >= REFRESH_AFTER_SECS)
            .collect()
    }

    pub fn mark_refreshed(&mut self, bucket: usize, now: u64) {
        if let Some(b) = self.buckets.get_mut(bucket) {
            b.refreshed_at = now;
        }
    }

    /// Identifiant aléatoire dont le préfixe commun avec le nôtre mesure
    /// exactement `bucket` bits.
    pub fn random_id_in_bucket(&self, bucket: usize, rng: &mut impl Rng) -> [u8; 32] {
        let bucket = bucket.min(BUCKETS - 1);
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        let (byte, bit) = (bucket / 8, bucket % 8);
        let own = &self.own.0;
        id[..byte].copy_from_slice(&own[..byte]);
        // Bits gardés de notre identifiant, puis le bit inversé.
        let keep = !(0xffu8 >> bit);
        let flip = 0x80u8 >> bit;
        id[byte] = (own[byte] & keep) | (!own[byte] & flip) | (id[byte] & !keep & !flip);
        id
    }

    pub fn get(&self, id: &NodeId) -> Option<&Peer> {
        let bucket = &self.buckets[bucket_index(&self.own, id)?];
        bucket
            .active
            .iter()
            .chain(&bucket.reserve)
            .find(|p| p.id == *id)
    }

    /// Tous les nœuds connus, les actifs d'abord puis la réserve.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.active()
            .chain(self.buckets.iter().flat_map(|b| &b.reserve))
    }

    /// Nombre de nœuds actifs.
    pub fn len(&self) -> usize {
        self.active().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Nombre de compartiments ayant au moins un nœud actif.
    pub fn non_empty_buckets(&self) -> usize {
        self.buckets.iter().filter(|b| !b.active.is_empty()).count()
    }
}

#[cfg(test)]
mod tests {
    use barking_proto::RecordPolicy;
    use ed25519_dalek::SigningKey;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    const OWN: NodeId = NodeId([0; 32]);
    const NOW: u64 = 1_000_000;
    const POLICY: RecordPolicy = RecordPolicy {
        allow_private: true,
        puzzle_bits: 0,
    };

    fn node_at(rng: &mut StdRng, addr: &str, now: u64) -> (NodeId, NodeRecord) {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let rec = NodeRecord::sign(
            &SigningKey::from_bytes(&seed),
            Some(addr.parse().unwrap()),
            None,
            now,
        );
        (rec.verify(now, &POLICY).unwrap(), rec)
    }

    fn node(rng: &mut StdRng, addr: &str) -> (NodeId, NodeRecord) {
        node_at(rng, addr, NOW)
    }

    /// Nœud tiré jusqu'à tomber dans le compartiment `b`.
    fn node_in(rng: &mut StdRng, b: usize, addr: &str) -> (NodeId, NodeRecord) {
        loop {
            let (id, rec) = node(rng, addr);
            if bucket_index(&OWN, &id) == Some(b) {
                return (id, rec);
            }
        }
    }

    /// Adresse dans un /24 propre à `i`.
    fn distinct(i: usize) -> String {
        format!("11.{}.{}.1:4433", i / 256, i % 256)
    }

    /// Adresse dans un /24 commun.
    fn shared(i: usize) -> String {
        format!("10.9.8.{}:4433", i % 250 + 1)
    }

    /// Remplit le compartiment 0 de `K` nœuds (le premier est le plus
    /// ancien), puis présente un 21ᵉ nœud.
    fn full_bucket(rng: &mut StdRng) -> (RoutingTable, Vec<NodeId>, NodeId) {
        let mut table = RoutingTable::new(OWN);
        let mut ids = Vec::new();
        for i in 0..K {
            let (id, rec) = node_in(rng, 0, &distinct(i));
            assert_eq!(table.on_contact(id, rec, NOW + i as u64), Insert::Added);
            ids.push(id);
        }
        let (extra, rec) = node_in(rng, 0, &distinct(K));
        assert_eq!(
            table.on_contact(extra, rec, NOW + 100),
            Insert::Pending { ping: ids[0] }
        );
        (table, ids, extra)
    }

    /// Table de `n` nœuds aux /24 distincts, tous actifs.
    fn table_of(rng: &mut StdRng, n: usize) -> RoutingTable {
        let mut table = RoutingTable::new(OWN);
        for i in 0..n {
            let (id, rec) = node(rng, &distinct(i));
            assert_eq!(table.on_contact(id, rec, NOW), Insert::Added);
        }
        table
    }

    fn active_ids(table: &RoutingTable) -> Vec<NodeId> {
        table
            .closest(&[0; 32], usize::MAX)
            .iter()
            .map(|p| p.id)
            .collect()
    }

    #[test]
    fn own_id_is_rejected() {
        let mut rng = StdRng::seed_from_u64(1);
        let (_, rec) = node(&mut rng, &distinct(0));
        let mut table = RoutingTable::new(OWN);
        assert_eq!(
            table.on_contact(OWN, rec, NOW),
            Insert::Rejected(Reject::Own)
        );
    }

    #[test]
    fn full_bucket_keeps_oldest_alive() {
        let mut rng = StdRng::seed_from_u64(2);
        let (mut table, ids, extra) = full_bucket(&mut rng);
        assert_eq!(table.len(), K);
        assert!(table.get(&extra).is_some());
        assert!(!active_ids(&table).contains(&extra));
        // Le plus ancien répond : il reste, et passe en queue.
        let rec = table.get(&ids[0]).unwrap().record.clone();
        assert_eq!(table.on_contact(ids[0], rec, NOW + 200), Insert::Updated);
        assert!(active_ids(&table).contains(&ids[0]));
        let (other, rec) = node_in(&mut rng, 0, &distinct(K + 1));
        assert_eq!(
            table.on_contact(other, rec, NOW + 300),
            Insert::Pending { ping: ids[1] }
        );
        // Actifs d'abord, puis la réserve.
        let order: Vec<NodeId> = table.peers().map(|p| p.id).collect();
        assert_eq!(&order[K..], &[extra, other]);
    }

    #[test]
    fn three_failures_evict_and_offer_replacement() {
        let mut rng = StdRng::seed_from_u64(3);
        let (mut table, ids, extra) = full_bucket(&mut rng);
        assert_eq!(table.on_failure(&ids[0]), None);
        assert_eq!(table.on_failure(&ids[0]), None);
        assert_eq!(table.get(&ids[0]).unwrap().fails, 2);
        assert_eq!(table.on_failure(&ids[0]), Some(extra));
        assert!(table.get(&ids[0]).is_none());
        assert_eq!(table.len(), K - 1);
        let rec = table.get(&extra).unwrap().record.clone();
        assert_eq!(table.on_contact(extra, rec, NOW + 400), Insert::Added);
        assert_eq!(table.len(), K);
        assert!(active_ids(&table).contains(&extra));
    }

    #[test]
    fn contact_resets_failures() {
        let mut rng = StdRng::seed_from_u64(4);
        let (mut table, ids, _) = full_bucket(&mut rng);
        table.on_failure(&ids[0]);
        table.on_failure(&ids[0]);
        let rec = table.get(&ids[0]).unwrap().record.clone();
        table.on_contact(ids[0], rec, NOW + 200);
        assert_eq!(table.on_failure(&ids[0]), None);
        assert!(table.get(&ids[0]).is_some());
    }

    #[test]
    fn bucket_diversity_caps_two_per_prefix() {
        let mut rng = StdRng::seed_from_u64(5);
        // 30 nœuds hors des compartiments 0 et 1 : la part de table
        // autorise alors 3 nœuds par bloc.
        let mut table = RoutingTable::new(OWN);
        let mut i = 0;
        while table.len() < 30 {
            let (id, rec) = node(&mut rng, &distinct(i));
            i += 1;
            if bucket_index(&OWN, &id).unwrap() >= 2 {
                assert_eq!(table.on_contact(id, rec, NOW), Insert::Added);
            }
        }
        for j in 0..2 {
            let (id, rec) = node_in(&mut rng, 0, &shared(j));
            assert_eq!(table.on_contact(id, rec, NOW), Insert::Added);
        }
        let (id, rec) = node_in(&mut rng, 0, &shared(2));
        assert_eq!(
            table.on_contact(id, rec, NOW),
            Insert::Rejected(Reject::Diversity)
        );
        // La limite vaut par compartiment.
        let (id, rec) = node_in(&mut rng, 1, &shared(3));
        assert_eq!(table.on_contact(id, rec, NOW), Insert::Added);
    }

    #[test]
    fn reserve_obeys_bucket_diversity() {
        let mut rng = StdRng::seed_from_u64(6);
        let (mut table, _, _) = full_bucket(&mut rng);
        // Le 21ᵉ est en réserve sur son propre /24 ; deux candidates d'un
        // même bloc passent, la troisième est ignorée.
        for j in 0..2 {
            let (id, rec) = node_in(&mut rng, 0, &shared(j));
            assert!(matches!(
                table.on_contact(id, rec, NOW + 500),
                Insert::Pending { .. }
            ));
        }
        let (id, rec) = node_in(&mut rng, 0, &shared(2));
        assert_eq!(
            table.on_contact(id, rec, NOW + 500),
            Insert::Rejected(Reject::Diversity)
        );
        assert!(table.get(&id).is_none());
    }

    #[test]
    fn table_share_caps_ten_percent() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut table = RoutingTable::new(OWN);
        for i in 0..100 {
            let (id, rec) = node(&mut rng, &distinct(i));
            table.on_contact(id, rec, NOW);
        }
        for i in 0..200 {
            let (id, rec) = node(&mut rng, &shared(i));
            table.on_contact(id, rec, NOW);
        }
        let block = Prefix::V4([10, 9, 8]);
        let actives = table.closest(&[0; 32], usize::MAX);
        let in_shared = actives.iter().filter(|p| in_block(p, &block)).count();
        let limit = MIN_PREFIX_ALLOWED.max(actives.len() * MAX_PREFIX_SHARE_PERCENT / 100);
        assert!(in_shared >= MIN_PREFIX_ALLOWED);
        assert!(in_shared <= limit, "{in_shared} > {limit}");
    }

    #[test]
    fn closest_diverse_caps_per_prefix() {
        let mut rng = StdRng::seed_from_u64(8);
        let mut table = table_of(&mut rng, 30);
        let mut shared_ids = Vec::new();
        for b in 0..3 {
            let (id, rec) = node_in(&mut rng, b, &shared(b));
            assert_eq!(table.on_contact(id, rec, NOW), Insert::Added);
            shared_ids.push(id);
        }
        let all = table.closest(&[0; 32], usize::MAX);
        let diverse = table.closest_diverse(&[0; 32], usize::MAX);
        assert_eq!(diverse.len(), all.len() - 1);
        let block = Prefix::V4([10, 9, 8]);
        let kept = diverse
            .iter()
            .filter(|r| prefixes(r).contains(&block))
            .count();
        assert_eq!(kept, MAX_PER_PREFIX);
        assert_eq!(table.closest_diverse(&[0; 32], 5).len(), 5);
    }

    #[test]
    fn mark_alive_resets_failures_and_refreshes() {
        let mut rng = StdRng::seed_from_u64(13);
        let mut table = RoutingTable::new(OWN);
        let (a, ra) = node_in(&mut rng, 0, &distinct(0));
        let (b, rb) = node_in(&mut rng, 0, &distinct(1));
        table.on_contact(a, ra.clone(), NOW);
        table.on_contact(b, rb, NOW);
        table.on_failure(&a);
        table.on_failure(&a);
        assert_eq!(table.get(&a).unwrap().fails, 2);
        assert!(table.mark_alive(&a, NOW + 50));
        let p = table.get(&a).unwrap();
        assert_eq!((p.fails, p.last_seen, &p.record), (0, NOW + 50, &ra));
        // Vu le plus récemment : `b` devient la tête du compartiment.
        assert_eq!(table.stale_heads(NOW + STALE_AFTER_SECS), vec![b]);
        // Deux nouveaux échecs ne le retirent pas : la série a recommencé.
        table.on_failure(&a);
        table.on_failure(&a);
        assert!(table.get(&a).is_some());
        assert!(!table.mark_alive(&NodeId([9; 32]), NOW));
        assert!(!table.mark_alive(&OWN, NOW));
    }

    #[test]
    fn relaxed_limits_admit_a_shared_block() {
        let mut rng = StdRng::seed_from_u64(12);
        let nodes: Vec<_> = (0..8).map(|i| node(&mut rng, &shared(i))).collect();
        // Limites de la spec : 2 nœuds du /24 au plus dans toute la table.
        let mut spec = RoutingTable::new(OWN);
        let mut relaxed = RoutingTable::with_limits(OWN, DiversityLimits::NONE);
        for (id, rec) in &nodes {
            spec.on_contact(*id, rec.clone(), NOW);
            assert_eq!(relaxed.on_contact(*id, rec.clone(), NOW), Insert::Added);
        }
        assert_eq!(spec.len(), MIN_PREFIX_ALLOWED);
        assert_eq!(relaxed.len(), nodes.len());
        assert_eq!(relaxed.closest_diverse(&[0; 32], K).len(), nodes.len());
        assert_eq!(DiversityLimits::default(), DiversityLimits::SPEC);
    }

    #[test]
    fn newer_record_replaces_older_and_old_is_ignored() {
        let mut rng = StdRng::seed_from_u64(9);
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let old = NodeRecord::sign(&key, Some("11.0.0.1:4433".parse().unwrap()), None, NOW);
        let new = NodeRecord::sign(
            &key,
            Some("11.0.1.1:4433".parse().unwrap()),
            None,
            NOW + 3600,
        );
        let id = old.verify(NOW, &POLICY).unwrap();
        let mut table = RoutingTable::new(OWN);
        assert_eq!(table.on_contact(id, old.clone(), NOW), Insert::Added);
        assert_eq!(
            table.on_contact(id, new.clone(), NOW + 3600),
            Insert::Updated
        );
        assert_eq!(table.get(&id).unwrap().record, new);
        assert_eq!(
            table.on_contact(id, old, NOW + 3700),
            Insert::Rejected(Reject::Older)
        );
        assert_eq!(table.get(&id).unwrap().record, new);
        assert_eq!(table.get(&id).unwrap().first_seen, NOW);
    }

    #[test]
    fn proximity_bound_needs_ten() {
        let mut rng = StdRng::seed_from_u64(10);
        let key = [0x5a; 32];
        assert_eq!(table_of(&mut rng, 9).proximity_bound(&key), None);
        assert!(table_of(&mut rng, 9).may_hold(&key, &NodeId([0xff; 32])));

        let table = table_of(&mut rng, 30);
        let mut dists: Vec<[u8; 32]> = active_ids(&table)
            .iter()
            .chain([OWN].iter())
            .map(|id| distance(&id.0, &key))
            .collect();
        assert_eq!(dists.len(), 31);
        dists.sort();
        assert_eq!(table.proximity_bound(&key), Some(dists[9]));
        let near = table.closest(&key, 1)[0].id;
        let far = *table.closest(&key, 30).last().map(|p| &p.id).unwrap();
        assert!(table.may_hold(&key, &near));
        assert!(!table.may_hold(&key, &far));
    }

    /// Rang de notre identifiant parmi les nœuds actifs, pour `key`.
    fn own_rank(table: &RoutingTable, key: &[u8; 32]) -> usize {
        let own = distance(&OWN.0, key);
        active_ids(table)
            .iter()
            .filter(|id| distance(&id.0, key) < own)
            .count()
    }

    #[test]
    fn replica_targets_none_when_far() {
        let mut rng = StdRng::seed_from_u64(11);
        let table = table_of(&mut rng, 30);
        let ids_of = |peers: Vec<Peer>| peers.into_iter().map(|p| p.id).collect::<Vec<_>>();

        let mut key = [0; 32];
        let (mut seen_mid, mut seen_far) = (false, false);
        while !(seen_mid && seen_far) {
            rng.fill_bytes(&mut key);
            match own_rank(&table, &key) {
                0..=4 => {
                    let targets = table.replica_targets(&key).unwrap();
                    assert_eq!(targets.len(), REPLICAS - 1);
                    assert_eq!(targets, ids_of(table.closest(&key, REPLICAS - 1)));
                }
                5..=9 => {
                    let targets = table.replica_targets(&key).unwrap();
                    assert_eq!(targets, ids_of(table.closest(&key, REPLICAS)));
                    seen_mid = true;
                }
                _ => {
                    assert_eq!(table.replica_targets(&key), None);
                    seen_far = true;
                }
            }
        }
        // Notre propre identifiant comme clé : nous sommes le plus proche.
        assert_eq!(table.replica_targets(&OWN.0).unwrap().len(), REPLICAS - 1);
    }

    #[test]
    fn random_id_lands_in_bucket() {
        let mut rng = StdRng::seed_from_u64(12);
        let table = RoutingTable::new(NodeId([0xa5; 32]));
        for b in [0, 1, 7, 8, 9, 100, 254, 255] {
            for _ in 0..8 {
                let id = NodeId(table.random_id_in_bucket(b, &mut rng));
                assert_eq!(bucket_index(&table.own_id(), &id), Some(b));
            }
        }
    }

    #[test]
    fn stale_heads_and_refresh() {
        let mut rng = StdRng::seed_from_u64(13);
        let mut table = RoutingTable::new(OWN);
        assert!(table.buckets_to_refresh(NOW).is_empty());
        let (a, rec) = node_in(&mut rng, 0, &distinct(0));
        table.on_contact(a, rec, NOW);
        let (b, rec) = node_in(&mut rng, 2, &distinct(1));
        table.on_contact(b, rec, NOW + 600);
        assert!(!table.is_empty());
        assert_eq!(table.non_empty_buckets(), 2);

        assert!(table.stale_heads(NOW + STALE_AFTER_SECS - 1).is_empty());
        assert_eq!(table.stale_heads(NOW + STALE_AFTER_SECS), vec![a]);

        assert_eq!(table.buckets_to_refresh(NOW), vec![0, 1, 2]);
        table.mark_refreshed(1, NOW);
        assert_eq!(table.buckets_to_refresh(NOW), vec![0, 2]);
        assert_eq!(
            table.buckets_to_refresh(NOW + REFRESH_AFTER_SECS),
            vec![0, 1, 2]
        );
    }
}
