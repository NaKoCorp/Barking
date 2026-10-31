//! Hash table in the node (spec §3.3, §4, §5.2, §6): `Ping`, `FindNode`,
//! `Store` and `FindValue` requests, direct contacts, network lookup and
//! maintenance (`maintain`).
//!
//! **Direct contact** (spec §6.1, and rule R5): a node enters the table
//! (`on_contact`) only with a record that
//! - is valid (`NodeRecord::verify`);
//! - gives the identifier pinned by TLS on the connection that carried it;
//! - was returned unchanged by a `Pong` at **each** of its addresses that
//!   this node can reach (at least one), each `Ping` going to that exact
//!   address. A family is reachable if we publish an address of that family
//!   and have an endpoint for it; an address of another family is neither
//!   called, nor verified, nor counted as a failure (spec §10).
//!
//! Without the last condition, a dual-stack record could claim an address in
//! a victim's /24 or /48 and take its slots. A record received in `Nodes`,
//! attached as `from`, or a node that answered during a lookup are only
//! candidates, verified this way.
//!
//! Logs give only node identifiers (base32), never an address or a mailbox.

pub mod maintain;
pub mod pool;
pub mod replicate;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use barking_dht::lookup::REQUEST_TIMEOUT_MS;
use barking_dht::{
    DiversityLimits, Insert, K, Lookup, RoutingTable, STALE_AFTER_SECS, mailbox_key,
};
use barking_proto::{
    ErrorReason, MAX_NODES_PER_RESPONSE, NodeId, NodeRecord, RecordPolicy, Request, Response,
};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::DhtConfig;
use crate::limits::{ConnectionSlot, PeerLimiter};
use crate::rules::{self, Policy};
use crate::server::{Shared, Stored, unix_now};
use crate::store::{MAX_PEER_ROWS, PeerRow};
use pool::PeerPool;
use replicate::Queue;

/// Timeout of a call to a peer, connection included (spec §6.3: 3 s).
pub const CALL_TIMEOUT: Duration = Duration::from_millis(REQUEST_TIMEOUT_MS);
/// At most one callback `Ping` per identifier over this duration (spec §6.2).
pub const RECALL_INTERVAL: Duration = Duration::from_secs(600);
/// At most one liveness check requested by replication per identifier over
/// this duration.
pub const LIVENESS_INTERVAL: Duration = Duration::from_secs(600);
/// At most this many callbacks in flight, all identifiers combined: a flood
/// of attached records does not turn the node into an amplifier.
const MAX_RECALLS_IN_FLIGHT: usize = 16;
/// Called-back identifiers kept; beyond this, the oldest are forgotten.
const RECALLS_SWEEP_AT: usize = 1024;
/// Bytes charged to a peer's bucket for a request without a packet.
const SMALL_REQUEST_BYTES: usize = 256;
/// At most this many chained promotions after a contact (oldest first).
const MAX_CONTACT_STEPS: usize = 4;

/// State of a node's hash table.
pub struct Dht {
    key: SigningKey,
    id: NodeId,
    cfg: DhtConfig,
    policy: RecordPolicy,
    /// Our record, republished by maintenance.
    record: Mutex<NodeRecord>,
    table: Mutex<RoutingTable>,
    pool: PeerPool,
    limiter: PeerLimiter,
    /// Last callback per identifier (spec §6.2).
    recalls: Mutex<HashMap<NodeId, Instant>>,
    recall_slots: Arc<Semaphore>,
    /// Table nodes currently being checked (`check_alive`): a second
    /// simultaneous check adds no failure.
    checking: Mutex<HashSet<NodeId>>,
    /// Share of the database queue for a calling identifier.
    db_jobs_per_peer: u32,
    /// Tests: period that replaces all maintenance cadences.
    tick: Option<Duration>,
    /// Order and queue of mailboxes to replicate (spec §5.3).
    queue: Mutex<Queue>,
    /// Wakes replication when the queue gains a mailbox.
    wake: Notify,
    /// Last liveness check requested by replication, per identifier.
    liveness: Mutex<HashMap<NodeId, Instant>>,
    /// Next instant at which replication may call each identifier.
    pace: Mutex<HashMap<NodeId, tokio::time::Instant>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Time rounded down to the hour (`peers` rows).
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
        limits: DiversityLimits,
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
            table: Mutex::new(RoutingTable::with_limits(id, limits)),
            limiter: PeerLimiter::new(),
            recalls: Mutex::new(HashMap::new()),
            recall_slots: Arc::new(Semaphore::new(MAX_RECALLS_IN_FLIGHT)),
            checking: Mutex::new(HashSet::new()),
            db_jobs_per_peer: db_jobs_per_peer.max(1),
            tick,
            queue: Mutex::new(Queue::default()),
            wake: Notify::new(),
            liveness: Mutex::new(HashMap::new()),
            pace: Mutex::new(HashMap::new()),
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

    /// Our current record, sent by `Pong` and `from`.
    pub fn own_record(&self) -> NodeRecord {
        lock(&self.record).clone()
    }

    /// Signs a new record dated `now` (spec §6.1).
    pub fn republish(&self, now: u64) {
        *lock(&self.record) =
            NodeRecord::sign(&self.key, self.cfg.public_v4, self.cfg.public_v6, now);
    }

    /// Access to the table (never held across an await).
    pub fn table(&self) -> MutexGuard<'_, RoutingTable> {
        lock(&self.table)
    }

    pub(crate) fn pool(&self) -> &PeerPool {
        &self.pool
    }

    pub(crate) fn replication_queue(&self) -> MutexGuard<'_, Queue> {
        lock(&self.queue)
    }

    pub(crate) fn replication_wake(&self) -> &Notify {
        &self.wake
    }

    /// A node has just entered the table: the held mailboxes for which it
    /// becomes one of the responsible nodes are queued (spec §5.3), based on
    /// the distances noted on the last pass, without walking the table.
    fn enqueue_for(&self, id: NodeId) {
        if self.replication_queue().enqueue_near(&id) {
            self.wake.notify_one();
        }
    }

    /// Instant at which replication may call `id`: the first free one, then
    /// reserved; the next call will wait `spacing` longer.
    pub(crate) fn replication_slot(&self, id: NodeId, spacing: Duration) -> tokio::time::Instant {
        let now = tokio::time::Instant::now();
        let mut pace = lock(&self.pace);
        if pace.len() >= RECALLS_SWEEP_AT {
            pace.retain(|_, t| *t > now);
        }
        let at = pace.get(&id).copied().unwrap_or(now).max(now);
        pace.insert(id, at + spacing);
        at
    }

    /// Liveness check of a responsible node left unanswered during
    /// replication: at most one per identifier and per `LIVENESS_INTERVAL`
    /// (`dht_tick` in tests), through `check_alive` (which alone counts the
    /// failure, and skips a check already in progress). True if the node is
    /// still in the table.
    pub async fn liveness_check(&self, id: NodeId) -> bool {
        let every = self.tick.unwrap_or(LIVENESS_INTERVAL);
        let now = Instant::now();
        let due = {
            let mut last = lock(&self.liveness);
            if last.len() >= RECALLS_SWEEP_AT {
                last.retain(|_, t| now.saturating_duration_since(*t) < every);
            }
            let due = last
                .get(&id)
                .is_none_or(|t| now.saturating_duration_since(*t) >= every);
            if due {
                last.insert(id, now);
            }
            due
        };
        if due {
            self.refresh_peer(id).await;
        }
        self.table().get(&id).is_some()
    }

    /// `peers` rows: active ones first, at most `MAX_PEER_ROWS`, dates
    /// rounded to the hour.
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

    /// Handles a table request. `peer`: calling node authenticated by its
    /// certificate; `remote`: source address of the connection; `group`: its
    /// slot in the address limiter, whose bucket has already admitted the
    /// request.
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
                // §5.2: 1. authenticated caller; 2. rate.
                let Some(id) = peer else {
                    return err(ErrorReason::Unsupported);
                };
                if let Err(r) = self.admit(peer, packet.len()) {
                    return err(r);
                }
                // 3. to 5. packet, proximity, proof.
                if let Err(r) = self.check_store(&shared.policy, &id, &packet, pow, unix_now()) {
                    return err(r);
                }
                // 6. and 7. acknowledgement and storage, with the identifier's
                // share of the queue, held by the blocking task.
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

    /// Bucket of the calling identifier, if authenticated (spec §5.2,
    /// point 2); the address group's bucket has already been passed.
    fn admit(&self, peer: Option<NodeId>, bytes: usize) -> Result<(), ErrorReason> {
        match peer {
            Some(id) if !self.limiter.admit(&id, bytes, Instant::now()) => {
                Err(ErrorReason::RateLimited)
            }
            _ => Ok(()),
        }
    }

    /// Attached record `from` (spec §4, §6.2): reserved to an authenticated
    /// caller, valid and matching its identifier, otherwise `Malformed`. It
    /// is then called back, at most once per identifier and per
    /// `RECALL_INTERVAL`, and only if it announces the connection's source
    /// IP (`remote`).
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

    /// Calls back a candidate attached as `from`: `Ping` first to its
    /// address carrying the source IP `remote`, then to the others, and
    /// contact if everything matches. Nothing if none of its addresses has
    /// this IP: otherwise any identifier could make every node ping
    /// addresses of its choosing (reflection toward a victim). Nothing
    /// either if it is already in the table with this record and seen
    /// recently.
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

    /// Preconditions of a `Store` without a database (spec §5.2, points 3 to
    /// 5), in order: packet, proximity of the caller and of ourselves, base
    /// proof.
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

    /// `Ping` of node `id` at address `addr`; its record if it is valid and
    /// gives `id` (the connection is pinned to `id` by TLS).
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

    /// Direct contact with `id`, first reached at one of `start`: its record
    /// if it is valid, gives `id`, and comes back unchanged from a `Ping` at
    /// each of its addresses reachable from here, at least one. An address
    /// of a family unreachable from here (unpublished, or without endpoint)
    /// is skipped.
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

    /// Brings into the table a node whose record has just been verified by
    /// `verify`. Full bucket: the oldest is pinged; it stays if it answers,
    /// otherwise its failure is counted and, if it is removed, the reserve
    /// candidate is contacted and then promoted.
    pub async fn admit_contact(&self, id: NodeId, record: NodeRecord) {
        let mut next = Some((id, record));
        for _ in 0..MAX_CONTACT_STEPS {
            let Some((id, record)) = next.take() else {
                return;
            };
            // Result bound first: the table guard is released before
            // `enqueue_for`, which takes it again.
            let inserted = self.table().on_contact(id, record, unix_now());
            let head = match inserted {
                Insert::Added => {
                    tracing::debug!("peer added to the table: {id}");
                    self.enqueue_for(id);
                    return;
                }
                Insert::Pending { ping } => ping,
                Insert::Updated | Insert::Rejected(_) => return,
            };
            next = self.check_alive(head).await;
        }
    }

    /// Pings a table node. If it answers, the contact is noted; otherwise
    /// the failure is counted, and the reserve candidate that replaces it, if
    /// it is removed, is returned once verified. A check already in progress
    /// for `id` makes this one skip: the same timeout is counted only once.
    /// A record with no address reachable from here is not judged.
    async fn check_alive(&self, id: NodeId) -> Option<(NodeId, NodeRecord)> {
        let _check = self.begin_check(id)?;
        let known = self.table().get(&id).map(|p| p.record.clone())?;
        if !known.addrs().iter().any(|a| self.pool.can_reach(a)) {
            return None;
        }
        if let Some(r) = self.verify(id, &known.addrs()).await {
            // Still active: it stays (refreshed), nothing to promote.
            self.table().on_contact(id, r, unix_now());
            return None;
        }
        let candidate = self.table().on_failure(&id)?;
        tracing::debug!("peer removed from the table: {id}");
        self.try_candidate(candidate).await
    }

    /// Contacts the reserve candidate that replaces a removed node: its
    /// record if it answers, otherwise its failure is counted.
    async fn try_candidate(&self, candidate: NodeId) -> Option<(NodeId, NodeRecord)> {
        let rec = self.table().get(&candidate).map(|p| p.record.clone())?;
        match self.verify(candidate, &rec.addrs()).await {
            Some(r) => Some((candidate, r)),
            None => {
                self.table().on_failure(&candidate);
                None
            }
        }
    }

    /// Marks `id` as being checked; `None` if it already is.
    fn begin_check(&self, id: NodeId) -> Option<CheckGuard<'_>> {
        // `then` and not `then_some`: a guard built for nothing would be
        // dropped under the lock, and would remove the check in progress.
        let fresh = lock(&self.checking).insert(id);
        fresh.then(|| CheckGuard { dht: self, id })
    }

    /// Maintenance of a table node: check, then possible promotion of its
    /// replacement.
    pub async fn refresh_peer(&self, id: NodeId) {
        if let Some((c, r)) = self.check_alive(id).await {
            self.admit_contact(c, r).await;
        }
    }

    /// Contacts each node of `targets` (identifier, starting addresses),
    /// `parallel` at a time; returns the number of nodes reached.
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

    /// Iterative lookup of `target` on the network (spec §6.3), with
    /// `FindNode { from: our record }`. Nodes that answered and are not yet
    /// in the table are then contacted (candidates).
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
                // `from`: identifier pinned by TLS of the queried
                // connection.
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

/// Table rebuilt offline from the `peers` rows (`status` and `peers`
/// commands), at the spec's limits: oldest first, as the live table keeps
/// them. An unreadable row, or one whose record does not give the
/// identifier, is discarded; records are not re-verified (date, puzzle), the
/// node did it before storing them.
pub fn table_from_rows(own: NodeId, rows: &[PeerRow]) -> RoutingTable {
    let mut table = RoutingTable::new(own);
    let mut sorted: Vec<&PeerRow> = rows.iter().collect();
    sorted.sort_by_key(|r| (r.first_seen, r.node_id));
    for row in sorted {
        let Ok(record) = postcard::from_bytes::<NodeRecord>(&row.record) else {
            continue;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&record.public_key) else {
            continue;
        };
        let id = NodeId::from_public_key(&key);
        if id.0 == row.node_id {
            table.on_contact(id, record, row.last_seen);
        }
    }
    table
}

/// Check in progress of a table node, lifted on drop.
struct CheckGuard<'a> {
    dht: &'a Dht,
    id: NodeId,
}

impl Drop for CheckGuard<'_> {
    fn drop(&mut self) {
        lock(&self.dht.checking).remove(&self.id);
    }
}

/// Address of `record` carrying the source IP `remote` (the port may
/// differ), where the callback starts; `None` if none.
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
        Dht::new(
            SigningKey::from_bytes(&[1; 32]),
            cfg,
            vec![],
            4,
            None,
            DiversityLimits::SPEC,
        )
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

    /// Adds to the table a node with identifier `id`, in its own /24; the
    /// table does not verify records.
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

        // Fewer than 10 nodes: infinite window, every caller is accepted.
        assert_eq!(d.check_store(&policy, &far, &packet, good, now), Ok(()));

        // Ten nodes farther from the key than we are: each differs from our
        // identifier only by a bit that our distance to the key has at zero.
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
        // Order of §5.2: the packet before proximity.
        assert_eq!(
            d.check_store(&policy, &far, &[1, 2, 3], good, now),
            Err(ErrorReason::Malformed)
        );
        assert_eq!(
            d.check_store(&policy, &far, &packet, good, now),
            Err(ErrorReason::NotResponsible)
        );
        // Near: the proof is verified next.
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
        // Same IP, other port: the callback starts from the announced address.
        assert_eq!(
            recall_start(&rec, "1.2.3.4:9999".parse().unwrap()),
            Some("1.2.3.4:4433".parse().unwrap())
        );
        assert_eq!(
            recall_start(&rec, "[2a01::1]:1".parse().unwrap()),
            Some("[2a01::1]:4433".parse().unwrap())
        );
        // IPv4 seen as encapsulated IPv6 (dual-stack socket).
        assert_eq!(
            recall_start(&rec, "[::ffff:1.2.3.4]:1".parse().unwrap()),
            Some("1.2.3.4:4433".parse().unwrap())
        );
        // IP absent from the record: no callback.
        assert_eq!(recall_start(&rec, "1.2.3.5:4433".parse().unwrap()), None);
        assert_eq!(recall_start(&rec, "[2a01::2]:4433".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn concurrent_head_checks_count_one_failure() {
        // IPv4 endpoint: the node's address is reachable, but nobody is
        // listening (timeout).
        let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let cfg = dht().cfg.clone();
        let d = Dht::new(
            SigningKey::from_bytes(&[1; 32]),
            cfg,
            vec![ep],
            4,
            None,
            DiversityLimits::SPEC,
        );
        let id = NodeId([9; 32]);
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(addr) = dead.local_addr().unwrap() else {
            unreachable!()
        };
        let rec = NodeRecord::sign(&SigningKey::from_bytes(&[9; 32]), Some(addr), None, 0);
        assert_eq!(d.table().on_contact(id, rec, 0), Insert::Added);
        let fails = |d: &Dht| d.table().get(&id).map(|p| p.fails);
        // Check already in progress: the second counts nothing.
        let guard = d.begin_check(id).unwrap();
        assert!(d.begin_check(id).is_none());
        assert_eq!(d.check_alive(id).await, None);
        assert_eq!(fails(&d), Some(0));
        drop(guard);
        // Alone: the failure is counted.
        assert_eq!(d.check_alive(id).await, None);
        assert_eq!(fails(&d), Some(1));
    }

    #[tokio::test]
    async fn replication_slots_are_spaced_per_peer() {
        let d = dht();
        let gap = Duration::from_millis(100);
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let first = d.replication_slot(a, gap);
        let second = d.replication_slot(a, gap);
        assert!(second >= first + gap);
        assert!(d.replication_slot(a, gap) >= second + gap);
        // Another responsible node does not wait.
        assert!(d.replication_slot(b, gap) < second);
    }

    #[tokio::test]
    async fn liveness_check_counts_once_per_interval() {
        let ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let cfg = dht().cfg.clone();
        let d = Dht::new(
            SigningKey::from_bytes(&[1; 32]),
            cfg,
            vec![ep],
            4,
            None,
            DiversityLimits::SPEC,
        );
        let id = NodeId([9; 32]);
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(addr) = dead.local_addr().unwrap() else {
            unreachable!()
        };
        let rec = NodeRecord::sign(&SigningKey::from_bytes(&[9; 32]), Some(addr), None, 0);
        assert_eq!(d.table().on_contact(id, rec, 0), Insert::Added);
        // First check: no answer, one failure.
        assert!(d.liveness_check(id).await);
        assert_eq!(d.table().get(&id).map(|p| p.fails), Some(1));
        // Within 10 min: no new check, nothing counted.
        assert!(d.liveness_check(id).await);
        assert_eq!(d.table().get(&id).map(|p| p.fails), Some(1));
    }

    #[tokio::test]
    async fn unreachable_family_is_never_a_failure() {
        // No endpoint: no reachable address, nothing is judged.
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
