//! Table de hachage dans le nœud (spec §3.3, §4, §5.2, §6) : requêtes
//! `Ping`, `FindNode`, `Store` et `FindValue`, contacts directs, recherche
//! sur le réseau et entretien (`maintain`).
//!
//! **Contact direct** (spec §6.1, et règle R5) : un nœud n'entre dans la
//! table (`on_contact`) qu'avec une fiche qui
//! - est valide (`NodeRecord::verify`) ;
//! - donne l'identifiant épinglé par TLS sur la connexion qui l'a apportée ;
//! - a été renvoyée à l'identique par un `Pong` à **chacune** de ses
//!   adresses que ce nœud peut joindre (au moins une), chaque `Ping` partant
//!   vers cette adresse précise. Une famille est joignable si nous publions
//!   une adresse de cette famille et avons un endpoint pour elle ; une
//!   adresse d'une autre famille n'est ni appelée, ni vérifiée, ni comptée
//!   comme un échec (spec §10).
//!
//! Sans la dernière condition, une fiche à double pile pourrait revendiquer
//! une adresse dans le /24 ou le /48 d'une victime et en prendre les places.
//! Une fiche reçue en `Nodes`, jointe en `from`, ou un nœud qui a répondu
//! pendant une recherche ne sont que des candidats, vérifiés ainsi.
//!
//! Les journaux ne donnent que des identifiants de nœud (base32), jamais
//! d'adresse ni de boîte.

pub mod maintain;
pub mod pool;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use barking_dht::lookup::REQUEST_TIMEOUT_MS;
use barking_dht::{Insert, K, Lookup, RoutingTable, STALE_AFTER_SECS, mailbox_key};
use barking_proto::{
    ErrorReason, MAX_NODES_PER_RESPONSE, NodeId, NodeRecord, RecordPolicy, Request, Response,
};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::DhtConfig;
use crate::limits::{ConnectionSlot, PeerLimiter};
use crate::rules::{self, Policy};
use crate::server::{Shared, Stored, unix_now};
use crate::store::{MAX_PEER_ROWS, PeerRow};
use pool::PeerPool;

/// Délai d'un appel à un pair, connexion comprise (spec §6.3 : 3 s).
pub const CALL_TIMEOUT: Duration = Duration::from_millis(REQUEST_TIMEOUT_MS);
/// Un `Ping` de rappel au plus par identifiant sur cette durée (spec §6.2).
pub const RECALL_INTERVAL: Duration = Duration::from_secs(600);
/// Rappels en cours au plus, tous identifiants confondus : un afflux de
/// fiches jointes ne fait pas du nœud un amplificateur.
const MAX_RECALLS_IN_FLIGHT: usize = 16;
/// Identifiants rappelés gardés au-delà desquels les anciens sont oubliés.
const RECALLS_SWEEP_AT: usize = 1024;
/// Octets comptés au seau d'un pair pour une requête sans paquet.
const SMALL_REQUEST_BYTES: usize = 256;
/// Promotions enchaînées au plus après un contact (anciens d'abord).
const MAX_CONTACT_STEPS: usize = 4;

/// État de la table de hachage d'un nœud.
pub struct Dht {
    key: SigningKey,
    id: NodeId,
    cfg: DhtConfig,
    policy: RecordPolicy,
    /// Notre fiche, republiée par l'entretien.
    record: Mutex<NodeRecord>,
    table: Mutex<RoutingTable>,
    pool: PeerPool,
    limiter: PeerLimiter,
    /// Dernier rappel par identifiant (spec §6.2).
    recalls: Mutex<HashMap<NodeId, Instant>>,
    recall_slots: Arc<Semaphore>,
    /// Nœuds de la table en cours de contrôle (`check_alive`) : un second
    /// contrôle simultané n'ajoute pas d'échec.
    checking: Mutex<HashSet<NodeId>>,
    /// Part de la file de base d'un identifiant appelant.
    db_jobs_per_peer: u32,
    /// Tests : période qui remplace toutes les cadences d'entretien.
    tick: Option<Duration>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Heure arrondie à l'heure inférieure (lignes de `peers`).
fn hour(t: u64) -> u64 {
    t - t % 3600
}

impl Dht {
    pub fn new(
        key: SigningKey,
        cfg: DhtConfig,
        endpoints: Vec<Endpoint>,
        db_jobs_per_peer: u32,
        tick: Option<Duration>,
    ) -> Dht {
        let id = NodeId::from_public_key(&key.verifying_key());
        let record = NodeRecord::sign(&key, cfg.public_v4, cfg.public_v6, unix_now());
        Dht {
            policy: RecordPolicy::network(cfg.allow_private_addrs),
            pool: PeerPool::new(
                key.clone(),
                endpoints,
                cfg.public_v4.is_some(),
                cfg.public_v6.is_some(),
            ),
            key,
            id,
            cfg,
            record: Mutex::new(record),
            table: Mutex::new(RoutingTable::new(id)),
            limiter: PeerLimiter::new(),
            recalls: Mutex::new(HashMap::new()),
            recall_slots: Arc::new(Semaphore::new(MAX_RECALLS_IN_FLIGHT)),
            checking: Mutex::new(HashSet::new()),
            db_jobs_per_peer: db_jobs_per_peer.max(1),
            tick,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn config(&self) -> &DhtConfig {
        &self.cfg
    }

    pub fn tick(&self) -> Option<Duration> {
        self.tick
    }

    /// Notre fiche courante, transmise par `Pong` et `from`.
    pub fn own_record(&self) -> NodeRecord {
        lock(&self.record).clone()
    }

    /// Signe une nouvelle fiche datée de l'heure `now` (spec §6.1).
    pub fn republish(&self, now: u64) {
        *lock(&self.record) =
            NodeRecord::sign(&self.key, self.cfg.public_v4, self.cfg.public_v6, now);
    }

    /// Accès à la table (jamais tenu pendant une attente).
    pub fn table(&self) -> MutexGuard<'_, RoutingTable> {
        lock(&self.table)
    }

    /// Lignes de `peers` : les actifs d'abord, `MAX_PEER_ROWS` au plus,
    /// dates arrondies à l'heure.
    pub fn peer_rows(&self) -> Vec<PeerRow> {
        self.table()
            .peers()
            .filter_map(|p| {
                Some(PeerRow {
                    node_id: p.id.0,
                    record: postcard::to_allocvec(&p.record).ok()?,
                    first_seen: hour(p.first_seen),
                    last_seen: hour(p.last_seen),
                })
            })
            .take(MAX_PEER_ROWS)
            .collect()
    }

    /// Traite une requête de la table. `peer` : nœud appelant authentifié
    /// par son certificat ; `remote` : adresse source de la connexion ;
    /// `group` : sa place dans le limiteur d'adresses, dont le seau a déjà
    /// admis la requête.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        req: Request,
        peer: Option<NodeId>,
        remote: SocketAddr,
        shared: &Arc<Shared>,
        group: &ConnectionSlot,
    ) -> Stored<Response> {
        let err = |r| Stored::Done(Response::Error(r));
        match req {
            Request::Ping { from } => {
                if let Err(r) = self.admit(peer, SMALL_REQUEST_BYTES) {
                    return err(r);
                }
                if let Err(r) = self.check_from(from, peer, remote) {
                    return err(r);
                }
                Stored::Done(Response::Pong {
                    record: self.own_record(),
                })
            }
            Request::FindNode { target, from } => {
                if let Err(r) = self.admit(peer, SMALL_REQUEST_BYTES) {
                    return err(r);
                }
                if let Err(r) = self.check_from(from, peer, remote) {
                    return err(r);
                }
                Stored::Done(Response::Nodes {
                    records: self
                        .table()
                        .closest_diverse(&target, MAX_NODES_PER_RESPONSE),
                })
            }
            Request::Store { packet, pow } => {
                // §5.2 : 1. appelant authentifié ; 2. débit.
                let Some(id) = peer else {
                    return err(ErrorReason::Unsupported);
                };
                if let Err(r) = self.admit(peer, packet.len()) {
                    return err(r);
                }
                // 3. à 5. paquet, proximité, preuve.
                if let Err(r) = self.check_store(&shared.policy, &id, &packet, pow, unix_now()) {
                    return err(r);
                }
                // 6. et 7. accusé et stockage, avec la part de file de
                // l'identifiant, tenue par la tâche bloquante.
                let Some(job) = self.limiter.try_db_job(&id, self.db_jobs_per_peer) else {
                    return Stored::Busy;
                };
                match shared
                    .with_store(false, Some(group), move |s, p| {
                        let _job = job;
                        rules::store_copy(s, p, &packet, pow, unix_now())
                    })
                    .await
                {
                    Stored::Done(Ok(())) => Stored::Done(Response::Ok),
                    Stored::Done(Err(r)) => err(r),
                    Stored::Busy => Stored::Busy,
                    Stored::Failed => Stored::Failed,
                }
            }
            Request::FindValue { mailbox, cursor } => {
                let Some(id) = peer else {
                    return err(ErrorReason::Unsupported);
                };
                if let Err(r) = self.admit(peer, SMALL_REQUEST_BYTES) {
                    return err(r);
                }
                let Some(job) = self.limiter.try_db_job(&id, self.db_jobs_per_peer) else {
                    return Stored::Busy;
                };
                match shared
                    .with_store(false, Some(group), move |s, _| {
                        let _job = job;
                        rules::holdings(s, &mailbox, cursor)
                    })
                    .await
                {
                    Stored::Done(Ok((hashes, next))) => {
                        Stored::Done(Response::Holdings { hashes, next })
                    }
                    Stored::Done(Err(r)) => err(r),
                    Stored::Busy => Stored::Busy,
                    Stored::Failed => Stored::Failed,
                }
            }
            Request::Hello { .. } | Request::Deposit { .. } | Request::Fetch { .. } => {
                err(ErrorReason::Malformed)
            }
        }
    }

    /// Seau de l'identifiant appelant, s'il est authentifié (spec §5.2,
    /// point 2) ; celui du groupe d'adresses est déjà passé.
    fn admit(&self, peer: Option<NodeId>, bytes: usize) -> Result<(), ErrorReason> {
        match peer {
            Some(id) if !self.limiter.admit(&id, bytes, Instant::now()) => {
                Err(ErrorReason::RateLimited)
            }
            _ => Ok(()),
        }
    }

    /// Fiche jointe `from` (spec §4, §6.2) : réservée à un appelant
    /// authentifié, valide et à son identifiant, sinon `Malformed`. Elle est
    /// ensuite rappelée, au plus une fois par identifiant et par
    /// `RECALL_INTERVAL`, et seulement si elle annonce l'IP source de la
    /// connexion (`remote`).
    fn check_from(
        self: &Arc<Self>,
        from: Option<NodeRecord>,
        peer: Option<NodeId>,
        remote: SocketAddr,
    ) -> Result<(), ErrorReason> {
        let Some(record) = from else {
            return Ok(());
        };
        let Some(peer) = peer else {
            return Err(ErrorReason::Malformed);
        };
        match record.verify(unix_now(), &self.policy) {
            Ok(id) if id == peer => {
                self.recall(peer, record, remote);
                Ok(())
            }
            _ => Err(ErrorReason::Malformed),
        }
    }

    /// Rappelle une candidate jointe en `from` : `Ping` d'abord vers son
    /// adresse qui porte l'IP source `remote`, puis vers les autres, et
    /// contact si tout concorde. Rien si aucune de ses adresses n'a cette IP :
    /// sinon n'importe quel identifiant ferait pinger par chaque nœud des
    /// adresses de son choix (réflexion vers une victime). Rien non plus si
    /// elle est déjà dans la table avec cette fiche et vue récemment.
    fn recall(self: &Arc<Self>, id: NodeId, record: NodeRecord, remote: SocketAddr) {
        if id == self.id {
            return;
        }
        let Some(start) = recall_start(&record, remote) else {
            return;
        };
        let fresh = self.table().get(&id).is_some_and(|p| {
            p.record == record && unix_now().saturating_sub(p.last_seen) < STALE_AFTER_SECS
        });
        if fresh {
            return;
        }
        let now = Instant::now();
        let mut recalls = lock(&self.recalls);
        if recalls.len() >= RECALLS_SWEEP_AT {
            recalls.retain(|_, t| now.saturating_duration_since(*t) < RECALL_INTERVAL);
        }
        if recalls
            .get(&id)
            .is_some_and(|t| now.saturating_duration_since(*t) < RECALL_INTERVAL)
        {
            return;
        }
        let Ok(permit) = Arc::clone(&self.recall_slots).try_acquire_owned() else {
            return;
        };
        recalls.insert(id, now);
        drop(recalls);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(r) = me.verify(id, &[start]).await {
                me.admit_contact(id, r).await;
            }
        });
    }

    /// Préconditions d'un `Store` sans base de données (spec §5.2, points 3
    /// à 5), dans l'ordre : paquet, proximité de l'appelant et de nous,
    /// preuve de base.
    pub fn check_store(
        &self,
        policy: &Policy,
        caller: &NodeId,
        packet: &[u8],
        pow: u64,
        now: u64,
    ) -> Result<(), ErrorReason> {
        let (mailbox, _) = rules::copy_target(packet, now)?;
        let key = mailbox_key(&mailbox);
        {
            let table = self.table();
            if !table.may_hold(&key, caller) || !table.may_hold(&key, &self.id) {
                return Err(ErrorReason::NotResponsible);
            }
        }
        rules::copy_pow_ok(policy, packet, pow)
    }

    /// `Ping` du nœud `id` à l'adresse `addr` ; sa fiche si elle est valide
    /// et donne `id` (la connexion est épinglée sur `id` par TLS).
    async fn ping_at(&self, id: NodeId, addr: SocketAddr) -> Option<NodeRecord> {
        let req = Request::Ping {
            from: Some(self.own_record()),
        };
        let resp = timeout(CALL_TIMEOUT, self.pool.request(id, &[addr], &req))
            .await
            .ok()?
            .ok()?;
        let Response::Pong { record } = resp else {
            return None;
        };
        (record.verify(unix_now(), &self.policy).ok()? == id).then_some(record)
    }

    /// Contact direct avec `id`, joint d'abord à l'une de `start` : sa fiche
    /// si elle est valide, donne `id`, et revient à l'identique d'un `Ping`
    /// à chacune de ses adresses joignables d'ici, dont au moins une. Une
    /// adresse d'une famille injoignable d'ici (non publiée, ou sans endpoint)
    /// est sautée.
    pub async fn verify(&self, id: NodeId, start: &[SocketAddr]) -> Option<NodeRecord> {
        if id == self.id {
            return None;
        }
        let mut first = None;
        for a in start.iter().filter(|a| self.pool.can_reach(a)) {
            if let Some(r) = self.ping_at(id, *a).await {
                first = Some((*a, r));
                break;
            }
        }
        let (at, record) = first?;
        let mut verified = false;
        for a in record.addrs() {
            if a == at {
                verified = true;
                continue;
            }
            if !self.pool.can_reach(&a) {
                continue;
            }
            if self.ping_at(id, a).await.as_ref() != Some(&record) {
                return None;
            }
            verified = true;
        }
        verified.then_some(record)
    }

    /// Fait entrer dans la table un nœud dont la fiche vient d'être vérifiée
    /// par `verify`. Compartiment plein : le plus ancien est pingé ; il
    /// reste s'il répond, sinon son échec est compté et, s'il est retiré,
    /// la candidate de la réserve est contactée puis promue.
    pub async fn admit_contact(&self, id: NodeId, record: NodeRecord) {
        let mut next = Some((id, record));
        for _ in 0..MAX_CONTACT_STEPS {
            let Some((id, record)) = next.take() else {
                return;
            };
            let head = match self.table().on_contact(id, record, unix_now()) {
                Insert::Added => {
                    tracing::debug!("pair ajouté à la table : {id}");
                    return;
                }
                Insert::Pending { ping } => ping,
                Insert::Updated | Insert::Rejected(_) => return,
            };
            next = self.check_alive(head).await;
        }
    }

    /// Pinge un nœud de la table. S'il répond, le contact est noté ; sinon
    /// l'échec est compté, et la candidate de réserve qui le remplace, s'il
    /// est retiré, est renvoyée une fois vérifiée. Un contrôle déjà en cours
    /// pour `id` fait sauter celui-ci : un même délai dépassé n'est compté
    /// qu'une fois. Une fiche sans adresse joignable d'ici n'est pas jugée.
    async fn check_alive(&self, id: NodeId) -> Option<(NodeId, NodeRecord)> {
        let _check = self.begin_check(id)?;
        let known = self.table().get(&id).map(|p| p.record.clone())?;
        if !known.addrs().iter().any(|a| self.pool.can_reach(a)) {
            return None;
        }
        if let Some(r) = self.verify(id, &known.addrs()).await {
            // Toujours actif : il reste (rafraîchi), rien à promouvoir.
            self.table().on_contact(id, r, unix_now());
            return None;
        }
        let candidate = self.table().on_failure(&id)?;
        tracing::debug!("pair retiré de la table : {id}");
        let rec = self.table().get(&candidate).map(|p| p.record.clone())?;
        match self.verify(candidate, &rec.addrs()).await {
            Some(r) => Some((candidate, r)),
            None => {
                self.table().on_failure(&candidate);
                None
            }
        }
    }

    /// Marque `id` en cours de contrôle ; `None` s'il l'est déjà.
    fn begin_check(&self, id: NodeId) -> Option<CheckGuard<'_>> {
        // `then` et non `then_some` : une garde construite pour rien serait
        // détruite sous le verrou, et retirerait le contrôle en cours.
        let fresh = lock(&self.checking).insert(id);
        fresh.then(|| CheckGuard { dht: self, id })
    }

    /// Entretien d'un nœud de la table : contrôle, puis promotion éventuelle
    /// de sa remplaçante.
    pub async fn refresh_peer(&self, id: NodeId) {
        if let Some((c, r)) = self.check_alive(id).await {
            self.admit_contact(c, r).await;
        }
    }

    /// Contacte chaque nœud de `targets` (identifiant, adresses de départ),
    /// `parallel` à la fois ; renvoie le nombre de nœuds joints.
    pub async fn contact_all(
        self: &Arc<Self>,
        targets: Vec<(NodeId, Vec<SocketAddr>)>,
        parallel: usize,
    ) -> usize {
        let slots = Arc::new(Semaphore::new(parallel.max(1)));
        let mut set = JoinSet::new();
        for (id, addrs) in targets {
            if id == self.id {
                continue;
            }
            let me = Arc::clone(self);
            let slots = Arc::clone(&slots);
            set.spawn(async move {
                let _slot = slots.acquire_owned().await.ok()?;
                let r = me.verify(id, &addrs).await?;
                me.admit_contact(id, r).await;
                Some(())
            });
        }
        let mut reached = 0;
        while let Some(r) = set.join_next().await {
            if matches!(r, Ok(Some(()))) {
                reached += 1;
            }
        }
        reached
    }

    /// Recherche itérative de `target` sur le réseau (spec §6.3), avec
    /// `FindNode { from: notre fiche }`. Les nœuds qui ont répondu et ne
    /// sont pas encore dans la table sont ensuite contactés (candidats).
    pub async fn lookup(self: &Arc<Self>, target: [u8; 32]) -> Vec<(NodeId, NodeRecord)> {
        let seeds: Vec<(NodeId, NodeRecord)> = self
            .table()
            .closest(&target, K)
            .into_iter()
            .map(|p| (p.id, p.record))
            .collect();
        let started = Instant::now();
        let ms = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut lookup = Lookup::new(target, seeds, self.policy, ms()).excluding(self.id);
        let req = Request::FindNode {
            target,
            from: Some(self.own_record()),
        };
        let mut calls = JoinSet::new();
        loop {
            for (id, record) in lookup.next_requests(ms()) {
                let pool = self.pool.clone();
                let req = req.clone();
                calls.spawn(async move {
                    let r = timeout(CALL_TIMEOUT, pool.request(id, &record.addrs(), &req)).await;
                    match r {
                        Ok(Ok(Response::Nodes { records })) => (id, Some(records)),
                        _ => (id, None),
                    }
                });
            }
            if lookup.is_done(ms()) {
                break;
            }
            match timeout(Duration::from_millis(100), calls.join_next()).await {
                // `from` : identifiant épinglé par TLS de la connexion
                // interrogée.
                Ok(Some(Ok((id, Some(records))))) => lookup.on_response(&id, records, unix_now()),
                Ok(Some(Ok((id, None)))) => lookup.on_failure(&id),
                Ok(Some(Err(_))) | Err(_) => {}
                Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        drop(calls);
        let candidates: Vec<(NodeId, Vec<SocketAddr>)> = {
            let table = self.table();
            lookup
                .responders()
                .into_iter()
                .filter(|(id, _)| table.get(id).is_none())
                .map(|(id, r)| (id, r.addrs()))
                .collect()
        };
        self.contact_all(candidates, MAX_RECALLS_IN_FLIGHT).await;
        lookup.result()
    }
}

/// Contrôle en cours d'un nœud de la table, levé à la destruction.
struct CheckGuard<'a> {
    dht: &'a Dht,
    id: NodeId,
}

impl Drop for CheckGuard<'_> {
    fn drop(&mut self) {
        lock(&self.dht.checking).remove(&self.id);
    }
}

/// Adresse de `record` qui porte l'IP source `remote` (le port peut
/// différer), par où commence le rappel ; `None` si aucune.
fn recall_start(record: &NodeRecord, remote: SocketAddr) -> Option<SocketAddr> {
    let ip = remote.ip().to_canonical();
    record
        .addrs()
        .into_iter()
        .find(|a| a.ip().to_canonical() == ip)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use barking_dht::distance;
    use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
    use barking_proto::pow;

    use super::*;

    fn dht() -> Dht {
        let cfg = DhtConfig {
            public_v4: Some("127.0.0.1:4433".parse().unwrap()),
            public_v6: None,
            bootstrap: vec![],
            allow_private_addrs: true,
            replication_bytes_per_hour: 512 << 20,
        };
        Dht::new(SigningKey::from_bytes(&[1; 32]), cfg, vec![], 4, None)
    }

    fn message(now: u64) -> Vec<u8> {
        Packet {
            kind: Kind::Message,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId([5; 16]),
            expires_at: u32::try_from(now + 86_400).unwrap(),
            mailbox: MailboxId([5; 16]),
            payload: vec![5; 16],
        }
        .encode()
    }

    /// Ajoute à la table un nœud d'identifiant `id`, dans son propre /24 ;
    /// la table ne vérifie pas les fiches.
    fn add(dht: &Dht, id: NodeId, n: u8) {
        let addr = SocketAddrV4::new([10, 0, n, 1].into(), 4433);
        let rec = NodeRecord::sign(&SigningKey::from_bytes(&[n; 32]), Some(addr), None, 0);
        assert_eq!(dht.table().on_contact(id, rec, 0), Insert::Added);
    }

    #[test]
    fn store_from_far_peer_is_not_responsible() {
        let now = unix_now();
        let policy = Policy {
            pow_bits: 4,
            ..Policy::default()
        };
        let d = dht();
        let packet = message(now);
        let mailbox = MailboxId([5; 16]);
        let hash = pow::content_hash(&packet);
        let bits = rules::pow_bits_for(&policy, 0, Tier::S, 0);
        let good = pow::solve(&hash, &mailbox, bits).unwrap();
        let key = mailbox_key(&mailbox);
        let far = NodeId(key.map(|b| !b));

        // Moins de 10 nœuds : fenêtre infinie, tout appelant est accepté.
        assert_eq!(d.check_store(&policy, &far, &packet, good, now), Ok(()));

        // Dix nœuds plus loin de la clé que nous : chacun ne diffère de notre
        // identifiant que par un bit que notre distance à la clé a à zéro.
        let own = d.id().0;
        let dist = distance(&own, &key);
        let mut added = Vec::new();
        for bit in (0..256usize).rev() {
            let (byte, mask) = (bit / 8, 0x80u8 >> (bit % 8));
            if dist[byte] & mask != 0 {
                continue;
            }
            let mut id = own;
            id[byte] ^= mask;
            add(&d, NodeId(id), u8::try_from(added.len() + 1).unwrap());
            added.push(NodeId(id));
            if added.len() == 10 {
                break;
            }
        }
        let near = added[0];
        // Ordre de §5.2 : le paquet avant la proximité.
        assert_eq!(
            d.check_store(&policy, &far, &[1, 2, 3], good, now),
            Err(ErrorReason::Malformed)
        );
        assert_eq!(
            d.check_store(&policy, &far, &packet, good, now),
            Err(ErrorReason::NotResponsible)
        );
        // Proche : la preuve est vérifiée ensuite.
        assert_eq!(d.check_store(&policy, &near, &packet, good, now), Ok(()));
        let weak = (0..)
            .find(|n| !pow::check(&hash, &mailbox, *n, bits))
            .unwrap();
        assert_eq!(
            d.check_store(&policy, &near, &packet, weak, now),
            Err(ErrorReason::PowTooWeak)
        );
    }

    #[test]
    fn recall_starts_at_the_source_ip() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let rec = NodeRecord::sign(
            &key,
            Some("1.2.3.4:4433".parse().unwrap()),
            Some("[2a01::1]:4433".parse().unwrap()),
            0,
        );
        // Même IP, autre port : le rappel part de l'adresse annoncée.
        assert_eq!(
            recall_start(&rec, "1.2.3.4:9999".parse().unwrap()),
            Some("1.2.3.4:4433".parse().unwrap())
        );
        assert_eq!(
            recall_start(&rec, "[2a01::1]:1".parse().unwrap()),
            Some("[2a01::1]:4433".parse().unwrap())
        );
        // IPv4 vue en IPv6 encapsulée (socket double pile).
        assert_eq!(
            recall_start(&rec, "[::ffff:1.2.3.4]:1".parse().unwrap()),
            Some("1.2.3.4:4433".parse().unwrap())
        );
        // IP absente de la fiche : aucun rappel.
        assert_eq!(recall_start(&rec, "1.2.3.5:4433".parse().unwrap()), None);
        assert_eq!(recall_start(&rec, "[2a01::2]:4433".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn concurrent_head_checks_count_one_failure() {
        // Endpoint IPv4 : l'adresse du nœud est joignable, mais personne
        // n'écoute (délai dépassé).
        let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let cfg = dht().cfg.clone();
        let d = Dht::new(SigningKey::from_bytes(&[1; 32]), cfg, vec![ep], 4, None);
        let id = NodeId([9; 32]);
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(addr) = dead.local_addr().unwrap() else {
            unreachable!()
        };
        let rec = NodeRecord::sign(&SigningKey::from_bytes(&[9; 32]), Some(addr), None, 0);
        assert_eq!(d.table().on_contact(id, rec, 0), Insert::Added);
        let fails = |d: &Dht| d.table().get(&id).map(|p| p.fails);
        // Contrôle déjà en cours : le second ne compte rien.
        let guard = d.begin_check(id).unwrap();
        assert!(d.begin_check(id).is_none());
        assert_eq!(d.check_alive(id).await, None);
        assert_eq!(fails(&d), Some(0));
        drop(guard);
        // Seul : l'échec est compté.
        assert_eq!(d.check_alive(id).await, None);
        assert_eq!(fails(&d), Some(1));
    }

    #[tokio::test]
    async fn unreachable_family_is_never_a_failure() {
        // Aucun endpoint : aucune adresse joignable, rien n'est jugé.
        let d = dht();
        let id = NodeId([9; 32]);
        add(&d, id, 1);
        assert_eq!(d.check_alive(id).await, None);
        assert_eq!(d.table().get(&id).map(|p| p.fails), Some(0));
        assert_eq!(
            d.verify(id, &["10.0.1.1:4433".parse().unwrap()]).await,
            None
        );
    }

    #[test]
    fn peer_rows_round_times_and_encode_records() {
        let d = dht();
        add(&d, NodeId([9; 32]), 1);
        let rows = d.peer_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].node_id, [9; 32]);
        let rec: NodeRecord = postcard::from_bytes(&rows[0].record).unwrap();
        assert_eq!(
            Some(&rec),
            d.table().get(&NodeId([9; 32])).map(|p| &p.record)
        );
        assert_eq!(rows[0].first_seen % 3600, 0);
    }
}
