//! Anti-abuse limits (spec §5), kept in memory only.
//!
//! - Concurrent connections, by tier: per address (IPv4 /32, IPv6 /64),
//!   per IPv6 /56 and /48, per IPv4 /24, and in total. IPv4 encapsulated in
//!   IPv6 is mapped back to IPv4. Full table: the longest-idle connection
//!   of the most represented /48 (or /24) is evicted, if that group weighs
//!   more than the newcomer's; otherwise refusal.
//! - Per address group (/32 or /64), shared by its connections: token
//!   bucket (requests and bytes, burst ×`burst`, half full at the start),
//!   reserved response bytes, database operations in progress. A group's
//!   state outlives its connections as long as its bucket has not returned
//!   to its starting level: reconnecting does not refill it.
//!
//! - Per authenticated node identifier (`PeerLimiter`, spec §5.2): bucket
//!   of 50 requests/s and 1 MiB/s, burst ×5, full at the start, and a share
//!   of the database queue. Adds to that of the address group.
//!
//! Addresses live only in these tables, for the duration of the connections
//! (and of the bucket's return to its starting level, a few seconds); they
//! are neither written, nor logged, nor displayable (the keys do not
//! implement `Debug`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use barking_proto::NodeId;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitConfig {
    pub max_connections: u32,
    /// Per IPv4 address (/32) or IPv6 /64 prefix.
    pub max_connections_per_ip: u32,
    pub max_connections_per_ipv6_56: u32,
    pub max_connections_per_ipv6_48: u32,
    pub max_connections_per_ipv4_24: u32,
    pub requests_per_sec: u32,
    pub bytes_per_sec: u64,
    /// Bucket capacity, in seconds of throughput.
    pub burst: u32,
}

impl Default for LimitConfig {
    fn default() -> Self {
        LimitConfig {
            max_connections: 1_000,
            max_connections_per_ip: 8,
            max_connections_per_ipv6_56: 32,
            max_connections_per_ipv6_48: 64,
            max_connections_per_ipv4_24: 32,
            requests_per_sec: 20,
            bytes_per_sec: 1 << 20,
            burst: 5,
        }
    }
}

/// Group of an address: whole IPv4, or IPv6 /64 prefix.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IpKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

/// Enclosing prefixes, counted for the per-tier caps.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum PrefixKey {
    V6_56([u8; 7]),
    V6_48([u8; 6]),
    V4_24([u8; 3]),
}

/// Group and prefixes (from narrowest to widest; the last one is the
/// eviction group: /48 or /24).
fn keys(ip: IpAddr) -> (IpKey, Vec<PrefixKey>) {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (IpKey::V4(o), vec![PrefixKey::V4_24([o[0], o[1], o[2]])])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut p64 = [0u8; 8];
            p64.copy_from_slice(&o[..8]);
            let mut p56 = [0u8; 7];
            p56.copy_from_slice(&o[..7]);
            let mut p48 = [0u8; 6];
            p48.copy_from_slice(&o[..6]);
            (
                IpKey::V6(p64),
                vec![PrefixKey::V6_56(p56), PrefixKey::V6_48(p48)],
            )
        }
    }
}

/// An address group: open connections, throughput, reserved response
/// bytes, database operations in progress.
struct Group {
    conns: u32,
    bytes: usize,
    db_jobs: u32,
    budget: ConnBudget,
}

impl Group {
    /// No connection nor work in progress, and bucket back at its starting
    /// level: equivalent to a fresh group, can be forgotten.
    fn forgettable(&mut self, now: Instant) -> bool {
        self.conns == 0 && self.bytes == 0 && self.db_jobs == 0 && self.budget.settled(now)
    }
}

/// An open connection (for eviction).
struct ConnEntry {
    group: IpKey,
    prefixes: Vec<PrefixKey>,
    last_active: Instant,
    evict: Arc<Notify>,
}

#[derive(Default)]
struct Table {
    groups: HashMap<IpKey, Group>,
    prefixes: HashMap<PrefixKey, u32>,
    conns: HashMap<u64, ConnEntry>,
    /// Database operations in progress per /48 or /24.
    prefix_db: HashMap<PrefixKey, u32>,
    next_id: u64,
    total: u32,
}

impl Table {
    /// Removes a connection from the counters (closing or eviction).
    fn remove_conn(&mut self, id: u64, now: Instant) -> Option<ConnEntry> {
        let e = self.conns.remove(&id)?;
        self.total = self.total.saturating_sub(1);
        for p in &e.prefixes {
            if let Some(n) = self.prefixes.get_mut(p) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.prefixes.remove(p);
                }
            }
        }
        if let Some(g) = self.groups.get_mut(&e.group) {
            g.conns = g.conns.saturating_sub(1);
        }
        self.forget_if_idle(e.group, now);
        Some(e)
    }

    fn forget_if_idle(&mut self, key: IpKey, now: Instant) {
        if self
            .groups
            .get_mut(&key)
            .is_some_and(|g| g.forgettable(now))
        {
            self.groups.remove(&key);
        }
    }

    /// Forgets idle groups that returned to their starting level, when
    /// there are many of them (amortized cost).
    fn sweep(&mut self, now: Instant) {
        let live = self.total as usize;
        if self.groups.len() > 2 * live + 256 {
            self.groups.retain(|_, g| !g.forgettable(now));
        }
    }
}

/// Counter of open connections and state per address group.
pub struct Limiter {
    cfg: LimitConfig,
    table: Mutex<Table>,
}

impl Limiter {
    pub fn new(cfg: LimitConfig) -> Arc<Limiter> {
        Arc::new(Limiter {
            cfg,
            table: Mutex::new(Table::default()),
        })
    }

    pub fn config(&self) -> &LimitConfig {
        &self.cfg
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn prefix_cap(&self, p: &PrefixKey) -> u32 {
        match p {
            PrefixKey::V6_56(_) => self.cfg.max_connections_per_ipv6_56,
            PrefixKey::V6_48(_) => self.cfg.max_connections_per_ipv6_48,
            PrefixKey::V4_24(_) => self.cfg.max_connections_per_ipv4_24,
        }
    }

    /// Reserves a slot for a connection from `ip`, or `None` if a limit is
    /// reached. Full table: evicts the longest-idle connection of the most
    /// represented eviction group (/48 or /24), if it has at least two more
    /// connections than the newcomer's. The slot is returned when the guard
    /// is dropped.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Option<ConnectionSlot> {
        let (key, prefixes) = keys(ip);
        let mut t = self.table();
        t.sweep(now);
        if t.groups.get(&key).map_or(0, |g| g.conns) >= self.cfg.max_connections_per_ip {
            return None;
        }
        for p in &prefixes {
            if t.prefixes.get(p).copied().unwrap_or(0) >= self.prefix_cap(p) {
                return None;
            }
        }
        if t.total >= self.cfg.max_connections {
            let top = *prefixes.last()?;
            let mine = t.prefixes.get(&top).copied().unwrap_or(0);
            // Most represented eviction group (same tier: /48 or /24).
            let (victim_group, count) = t
                .prefixes
                .iter()
                .filter(|(p, _)| matches!(p, PrefixKey::V6_48(_) | PrefixKey::V4_24(_)))
                .max_by_key(|(_, n)| **n)
                .map(|(p, n)| (*p, *n))?;
            if count < mine.saturating_add(2) {
                return None;
            }
            let victim = t
                .conns
                .iter()
                .filter(|(_, e)| e.prefixes.last() == Some(&victim_group))
                .min_by_key(|(_, e)| e.last_active)
                .map(|(id, _)| *id)?;
            if let Some(e) = t.remove_conn(victim, now) {
                e.evict.notify_one();
            }
        }
        let cfg = self.cfg;
        let g = t.groups.entry(key).or_insert_with(|| Group {
            conns: 0,
            bytes: 0,
            db_jobs: 0,
            budget: ConnBudget::new(&cfg, now),
        });
        g.conns += 1;
        for p in &prefixes {
            *t.prefixes.entry(*p).or_insert(0) += 1;
        }
        t.total += 1;
        let id = t.next_id;
        t.next_id += 1;
        let top = *prefixes.last()?;
        let evict = Arc::new(Notify::new());
        t.conns.insert(
            id,
            ConnEntry {
                group: key,
                prefixes,
                last_active: now,
                evict: Arc::clone(&evict),
            },
        );
        Some(ConnectionSlot {
            limiter: Arc::clone(self),
            id,
            key,
            top,
            evict,
        })
    }

    /// Total number of open connections.
    pub fn connections(&self) -> u32 {
        self.table().total
    }
}

/// Slot reserved for a connection.
pub struct ConnectionSlot {
    limiter: Arc<Limiter>,
    id: u64,
    key: IpKey,
    /// Enclosing /48 or /24.
    top: PrefixKey,
    evict: Arc<Notify>,
}

impl ConnectionSlot {
    /// Notified when the connection is evicted (full table): it must be
    /// closed. Its slot is already returned.
    pub fn evicted(&self) -> &Notify {
        &self.evict
    }

    /// Records activity on the connection (request received).
    pub fn touch(&self, now: Instant) {
        if let Some(e) = self.limiter.table().conns.get_mut(&self.id) {
            e.last_active = now;
        }
    }

    /// Admits a request of cost `cost` (in requests) and `bytes` bytes if the
    /// group's bucket allows it, and debits it. False if the group is no
    /// longer tracked (evicted connection).
    pub fn admit(&self, cost: u32, bytes: usize, now: Instant) -> bool {
        let mut t = self.limiter.table();
        t.groups
            .get_mut(&self.key)
            .is_some_and(|g| g.budget.admit(cost, bytes, now))
    }

    /// Debits the bytes of a response from the group's bucket.
    pub fn charge_bytes(&self, bytes: usize, now: Instant) {
        if let Some(g) = self.limiter.table().groups.get_mut(&self.key) {
            g.budget.charge_bytes(bytes, now);
        }
    }

    /// Reserves `n` response bytes for this connection's address group,
    /// without exceeding `cap`.
    pub fn try_reserve_bytes(&self, n: usize, cap: usize) -> bool {
        let mut t = self.limiter.table();
        let Some(g) = t.groups.get_mut(&self.key) else {
            return false;
        };
        match g.bytes.checked_add(n) {
            Some(v) if v <= cap => {
                g.bytes = v;
                true
            }
            _ => false,
        }
    }

    /// Returns `n` bytes reserved by `try_reserve_bytes`.
    pub fn release_bytes(&self, n: usize) {
        let mut t = self.limiter.table();
        if let Some(g) = t.groups.get_mut(&self.key) {
            g.bytes = g.bytes.saturating_sub(n);
        }
        t.forget_if_idle(self.key, Instant::now());
    }

    /// Bytes reserved by this connection's address group.
    pub fn group_bytes(&self) -> usize {
        self.limiter
            .table()
            .groups
            .get(&self.key)
            .map_or(0, |g| g.bytes)
    }

    /// Reserves a database operation: at most `group_cap` in progress for the
    /// group (/64 or /32) and `prefix_cap` for the enclosing /48 or /24;
    /// returned when the guard is dropped.
    pub fn try_db_job(&self, group_cap: u32, prefix_cap: u32) -> Option<GroupDbJob> {
        let mut t = self.limiter.table();
        if t.prefix_db.get(&self.top).copied().unwrap_or(0) >= prefix_cap {
            return None;
        }
        let g = t.groups.get_mut(&self.key)?;
        if g.db_jobs >= group_cap {
            return None;
        }
        g.db_jobs += 1;
        *t.prefix_db.entry(self.top).or_insert(0) += 1;
        Some(GroupDbJob {
            limiter: Arc::clone(&self.limiter),
            key: self.key,
            top: self.top,
        })
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        // Already removed if it was evicted.
        self.limiter.table().remove_conn(self.id, Instant::now());
    }
}

/// Database operation counted for an address group.
pub struct GroupDbJob {
    limiter: Arc<Limiter>,
    key: IpKey,
    top: PrefixKey,
}

impl Drop for GroupDbJob {
    fn drop(&mut self) {
        let mut t = self.limiter.table();
        if let Some(g) = t.groups.get_mut(&self.key) {
            g.db_jobs = g.db_jobs.saturating_sub(1);
        }
        if let Some(n) = t.prefix_db.get_mut(&self.top) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                t.prefix_db.remove(&self.top);
            }
        }
        t.forget_if_idle(self.key, Instant::now());
    }
}

/// Requests per second of a node identifier.
pub const PEER_REQUESTS_PER_SEC: f64 = 50.0;
/// Bytes per second of a node identifier.
pub const PEER_BYTES_PER_SEC: f64 = (1 << 20) as f64;
/// Burst of the per-identifier buckets, in seconds of throughput.
pub const PEER_BURST: f64 = 5.0;
/// Number of tracked identifiers beyond which buckets that returned to
/// full are forgotten (amortized cost).
const PEER_SWEEP_AT: usize = 4096;

/// State of a calling node identifier.
struct PeerState {
    requests: TokenBucket,
    bytes: TokenBucket,
    db_jobs: u32,
}

impl PeerState {
    fn new(now: Instant) -> PeerState {
        let r = PEER_REQUESTS_PER_SEC * PEER_BURST;
        let b = PEER_BYTES_PER_SEC * PEER_BURST;
        PeerState {
            requests: TokenBucket::new(PEER_REQUESTS_PER_SEC, r, r, now),
            bytes: TokenBucket::new(PEER_BYTES_PER_SEC, b, b, now),
            db_jobs: 0,
        }
    }

    /// No work in progress, buckets full: equivalent to a fresh state.
    fn forgettable(&mut self, now: Instant) -> bool {
        self.db_jobs == 0
            && self.requests.level(now) >= self.requests.capacity
            && self.bytes.level(now) >= self.bytes.capacity
    }
}

/// Throughput and database queue per authenticated node identifier (spec
/// §5.2, points 2 and 7). In memory only; identifiers that returned to the
/// fresh state are forgotten when they become numerous.
#[derive(Clone, Default)]
pub struct PeerLimiter {
    peers: Arc<Mutex<HashMap<NodeId, PeerState>>>,
}

impl PeerLimiter {
    pub fn new() -> PeerLimiter {
        PeerLimiter::default()
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, PeerState>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admits a request of `bytes` bytes from `id` if its buckets allow it,
    /// and debits it. Otherwise nothing is debited.
    pub fn admit(&self, id: &NodeId, bytes: usize, now: Instant) -> bool {
        let mut peers = self.peers();
        if peers.len() >= PEER_SWEEP_AT {
            peers.retain(|_, p| !p.forgettable(now));
        }
        let p = peers.entry(*id).or_insert_with(|| PeerState::new(now));
        let b = bytes as f64;
        if p.requests.available(1.0, now) && p.bytes.available(b, now) {
            p.requests.charge(1.0, now);
            p.bytes.charge(b, now);
            true
        } else {
            false
        }
    }

    /// Reserves a database operation for `id`: at most `cap` in progress;
    /// returned when the guard is dropped.
    pub fn try_db_job(&self, id: &NodeId, cap: u32) -> Option<PeerDbJob> {
        let mut peers = self.peers();
        let p = peers
            .entry(*id)
            .or_insert_with(|| PeerState::new(Instant::now()));
        if p.db_jobs >= cap {
            return None;
        }
        p.db_jobs += 1;
        Some(PeerDbJob {
            limiter: self.clone(),
            id: *id,
        })
    }
}

/// Database operation counted for a node identifier.
pub struct PeerDbJob {
    limiter: PeerLimiter,
    id: NodeId,
}

impl Drop for PeerDbJob {
    fn drop(&mut self) {
        if let Some(p) = self.limiter.peers().get_mut(&self.id) {
            p.db_jobs = p.db_jobs.saturating_sub(1);
        }
    }
}

/// Token bucket: `rate` tokens per second, `capacity` at most.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// Bucket holding `tokens` tokens at the start.
    pub fn new(rate: f64, capacity: f64, tokens: f64, now: Instant) -> TokenBucket {
        TokenBucket {
            rate,
            capacity,
            tokens: tokens.min(capacity),
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        self.last = now;
    }

    fn available(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= n
    }

    /// Takes `n` tokens unconditionally; the bucket can go into debt down to
    /// `-capacity` (a large response slows down the following requests).
    fn charge(&mut self, n: f64, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - n).max(-self.capacity);
    }

    fn level(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens
    }
}

/// Throughput budget of an address group: requests and bytes. The buckets
/// are half full at the start.
#[derive(Debug, Clone)]
pub struct ConnBudget {
    requests: TokenBucket,
    bytes: TokenBucket,
}

impl ConnBudget {
    pub fn new(cfg: &LimitConfig, now: Instant) -> ConnBudget {
        let burst = f64::from(cfg.burst.max(1));
        let rps = f64::from(cfg.requests_per_sec);
        let bps = cfg.bytes_per_sec as f64;
        ConnBudget {
            requests: TokenBucket::new(rps, rps * burst, rps * burst / 2.0, now),
            bytes: TokenBucket::new(bps, bps * burst, bps * burst / 2.0, now),
        }
    }

    /// Admits a request of cost `cost` and `bytes` bytes if both buckets
    /// allow it, and debits it. Otherwise nothing is debited.
    pub fn admit(&mut self, cost: u32, bytes: usize, now: Instant) -> bool {
        let c = f64::from(cost.max(1));
        let b = bytes as f64;
        if self.requests.available(c, now) && self.bytes.available(b, now) {
            self.requests.charge(c, now);
            self.bytes.charge(b, now);
            true
        } else {
            false
        }
    }

    /// Debits the bytes of a response.
    pub fn charge_bytes(&mut self, bytes: usize, now: Instant) {
        self.bytes.charge(bytes as f64, now);
    }

    /// Buckets back at (at least) their starting level.
    fn settled(&mut self, now: Instant) -> bool {
        let r = self.requests.capacity / 2.0;
        let b = self.bytes.capacity / 2.0;
        self.requests.level(now) >= r && self.bytes.level(now) >= b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg() -> LimitConfig {
        LimitConfig {
            max_connections: 5,
            max_connections_per_ip: 2,
            ..LimitConfig::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn acq(l: &Arc<Limiter>, s: &str) -> Option<ConnectionSlot> {
        l.try_acquire(ip(s), Instant::now())
    }

    fn wide() -> Arc<Limiter> {
        Limiter::new(LimitConfig {
            max_connections: 10_000,
            ..LimitConfig::default()
        })
    }

    #[test]
    fn peer_limiter_caps_rate() {
        let l = PeerLimiter::new();
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let now = Instant::now();
        // Burst ×5 of 50 req/s, full at the start: 250 requests.
        for i in 0..250 {
            assert!(l.admit(&a, 100, now), "request {i}");
        }
        assert!(!l.admit(&a, 100, now), "251st request of the same second");
        // Another identifier is not affected.
        assert!(l.admit(&b, 100, now));
        // One second later: 50 more requests.
        let later = now + Duration::from_secs(1);
        for _ in 0..50 {
            assert!(l.admit(&a, 100, later));
        }
        assert!(!l.admit(&a, 100, later));
        // Bytes: 1 MiB/s, burst of 5 MiB.
        let c = NodeId([3; 32]);
        assert!(l.admit(&c, 5 << 20, now));
        assert!(!l.admit(&c, 1, now));
    }

    #[test]
    fn peer_db_jobs_are_capped_per_id() {
        let l = PeerLimiter::new();
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let j1 = l.try_db_job(&a, 2).unwrap();
        let _j2 = l.try_db_job(&a, 2).unwrap();
        assert!(l.try_db_job(&a, 2).is_none());
        assert!(l.try_db_job(&b, 2).is_some());
        drop(j1);
        assert!(l.try_db_job(&a, 2).is_some());
    }

    #[test]
    fn per_ip_limit_and_release() {
        let l = Limiter::new(cfg());
        let a = acq(&l, "192.0.2.1").unwrap();
        let _b = acq(&l, "192.0.2.1").unwrap();
        assert!(acq(&l, "192.0.2.1").is_none());
        // Another address: accepted.
        let _c = acq(&l, "192.0.2.2").unwrap();
        drop(a);
        assert!(acq(&l, "192.0.2.1").is_some());
    }

    #[test]
    fn ipv6_grouped_by_64_and_mapped_v4() {
        let l = Limiter::new(cfg());
        let _a = acq(&l, "2001:db8:1:2::1").unwrap();
        let _b = acq(&l, "2001:db8:1:2:ffff:ffff:ffff:ffff").unwrap();
        // Same /64: refused.
        assert!(acq(&l, "2001:db8:1:2::99").is_none());
        // Another /64: accepted.
        let _c = acq(&l, "2001:db8:1:3::1").unwrap();
        // Encapsulated IPv4 = same key as the IPv4.
        let _d = acq(&l, "198.51.100.7").unwrap();
        let _e = acq(&l, "::ffff:198.51.100.7").unwrap();
        assert!(acq(&l, "198.51.100.7").is_none());
    }

    #[test]
    fn ipv6_hierarchical_caps() {
        let l = wide();
        let mut held = Vec::new();
        // One /56: at most 32 connections, spread over 32 /64s.
        for i in 0..32u32 {
            held.push(acq(&l, &format!("2001:db8:1:{i:x}::1")).unwrap());
        }
        assert!(acq(&l, "2001:db8:1:ff::1").is_none());
        // Another /56 of the same /48: 32 more, then the /48 is full (64).
        for i in 0..32u32 {
            held.push(acq(&l, &format!("2001:db8:1:1{i:02x}::1")).unwrap());
        }
        assert!(acq(&l, "2001:db8:1:200::1").is_none());
        // Another /48: accepted.
        held.push(acq(&l, "2001:db8:2::1").unwrap());
        // A slot returned in the first /56: accepted there again.
        held.remove(0);
        assert!(acq(&l, "2001:db8:1:ff::1").is_some());
    }

    #[test]
    fn ipv4_hierarchical_caps() {
        let l = wide();
        let mut held = Vec::new();
        for i in 1..=32u8 {
            held.push(
                l.try_acquire(IpAddr::from([10, 0, 0, i]), Instant::now())
                    .unwrap(),
            );
        }
        // The /24 is full (32).
        assert!(acq(&l, "10.0.0.200").is_none());
        held.push(acq(&l, "10.0.1.1").unwrap());
    }

    #[test]
    fn caps_are_configurable() {
        let l = Limiter::new(LimitConfig {
            max_connections: 10_000,
            max_connections_per_ipv6_56: 2,
            max_connections_per_ipv6_48: 3,
            max_connections_per_ipv4_24: 1,
            ..LimitConfig::default()
        });
        let _a = acq(&l, "2001:db8:0:1::1").unwrap();
        let _b = acq(&l, "2001:db8:0:2::1").unwrap();
        assert!(acq(&l, "2001:db8:0:3::1").is_none());
        let _c = acq(&l, "2001:db8:0:100::1").unwrap();
        assert!(acq(&l, "2001:db8:0:200::1").is_none());
        let _d = acq(&l, "10.0.0.1").unwrap();
        assert!(acq(&l, "10.0.0.2").is_none());
    }

    #[test]
    fn full_table_evicts_longest_idle_of_largest_group() {
        let l = Limiter::new(LimitConfig {
            max_connections: 6,
            ..LimitConfig::default()
        });
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        // Group A (10.0.0.0/24): 4 connections; B and C: one each.
        let a: Vec<_> = (1..=4u8)
            .map(|i| l.try_acquire(IpAddr::from([10, 0, 0, i]), at(0)).unwrap())
            .collect();
        let _b = l.try_acquire(ip("10.1.0.1"), at(0)).unwrap();
        let _c = l.try_acquire(ip("2001:db8::1"), at(0)).unwrap();
        // A[2] is the longest-idle of A.
        for (i, s) in a.iter().enumerate() {
            if i != 2 {
                s.touch(at(10));
            }
        }
        assert_eq!(l.connections(), 6);
        let d = l.try_acquire(ip("10.2.0.1"), at(20)).unwrap();
        assert_eq!(l.connections(), 6);
        // A[2] is evicted: notified, its slot already returned.
        let evicted: Vec<bool> = a
            .iter()
            .map(|s| {
                let n = s.evicted().notified();
                tokio::pin!(n);
                n.as_mut().enable()
            })
            .collect();
        assert_eq!(evicted, [false, false, true, false]);
        // Dropping the evicted guard does not return its slot a second time.
        drop(a);
        assert_eq!(l.connections(), 3);
        drop(d);
        assert_eq!(l.connections(), 2);
    }

    #[test]
    fn full_table_refuses_when_no_group_dominates() {
        let l = Limiter::new(LimitConfig {
            max_connections: 3,
            ..LimitConfig::default()
        });
        let _a = acq(&l, "10.0.0.1").unwrap();
        let _b = acq(&l, "10.0.0.2").unwrap();
        let _c = acq(&l, "10.1.0.1").unwrap();
        // Newcomer of the most represented group: refusal, no eviction.
        assert!(acq(&l, "10.0.0.3").is_none());
        // Group A (2) against a new group (0): eviction.
        let _d = acq(&l, "10.2.0.1").unwrap();
        // Then A (1), B (1), D (1): nobody dominates, refusal.
        assert!(acq(&l, "10.3.0.1").is_none());
    }

    #[test]
    fn group_byte_reservation() {
        let l = Limiter::new(cfg());
        let a = acq(&l, "2001:db8::1").unwrap();
        let b = acq(&l, "2001:db8::2").unwrap();
        let c = acq(&l, "2001:db9::1").unwrap();
        assert!(a.try_reserve_bytes(600, 1000));
        // Same /64: shared allowance.
        assert!(!b.try_reserve_bytes(500, 1000));
        assert!(b.try_reserve_bytes(400, 1000));
        assert_eq!(a.group_bytes(), 1000);
        // Another group: independent.
        assert!(c.try_reserve_bytes(1000, 1000));
        a.release_bytes(600);
        assert!(b.try_reserve_bytes(600, 1000));
        assert!(!a.try_reserve_bytes(usize::MAX, usize::MAX));
    }

    #[test]
    fn global_limit() {
        let l = Limiter::new(cfg());
        let slots: Vec<_> = (1..=5u8)
            .map(|i| {
                l.try_acquire(IpAddr::from([10, i, 0, 1]), Instant::now())
                    .unwrap()
            })
            .collect();
        assert_eq!(l.connections(), 5);
        // No group dominates: refusal.
        assert!(
            l.try_acquire(IpAddr::from([10, 9, 0, 1]), Instant::now())
                .is_none()
        );
        drop(slots);
        assert_eq!(l.connections(), 0);
        let t = l.table();
        assert!(t.conns.is_empty() && t.prefixes.is_empty());
    }

    #[test]
    fn reconnect_does_not_refill_group_bucket() {
        let l = Limiter::new(LimitConfig::default());
        let t0 = Instant::now();
        let a = l.try_acquire(ip("192.0.2.1"), t0).unwrap();
        // Half full at the start: 50 requests.
        let mut n = 0;
        while a.admit(1, 10, t0) {
            n += 1;
        }
        assert_eq!(n, 50);
        drop(a);
        // Immediate reconnection, or by another connection of the group: empty.
        let b = l.try_acquire(ip("192.0.2.1"), t0).unwrap();
        let c = l.try_acquire(ip("192.0.2.1"), t0).unwrap();
        assert!(!b.admit(1, 10, t0));
        assert!(!c.admit(1, 10, t0));
        drop((b, c));
        // Another address has its own bucket.
        let d = l.try_acquire(ip("192.0.2.2"), t0).unwrap();
        assert!(d.admit(1, 10, t0));
        drop(d);
        // Once the bucket is back at its starting level, the group is forgotten.
        let later = t0 + Duration::from_secs(10);
        let e = l.try_acquire(ip("192.0.2.9"), later).unwrap();
        drop(e);
        let mut t = l.table();
        t.groups.retain(|_, g| !g.forgettable(later));
        assert!(t.groups.is_empty());
    }

    #[test]
    fn group_db_jobs_capped() {
        let l = Limiter::new(LimitConfig::default());
        let a = acq(&l, "192.0.2.1").unwrap();
        let b = acq(&l, "192.0.2.1").unwrap();
        let other = acq(&l, "192.0.2.2").unwrap();
        let j1 = a.try_db_job(2, 100).unwrap();
        let _j2 = b.try_db_job(2, 100).unwrap();
        // The group has its two slots, whichever the connection.
        assert!(a.try_db_job(2, 100).is_none());
        assert!(b.try_db_job(2, 100).is_none());
        // Another group is not affected.
        assert!(other.try_db_job(2, 100).is_some());
        drop(j1);
        assert!(a.try_db_job(2, 100).is_some());
    }

    #[test]
    fn prefix_db_jobs_capped_across_its_groups() {
        let l = wide();
        // Four /64s of the same /56 (hence of the same /48), allowance of 4 each,
        // allowance of 8 for the /48.
        let slots: Vec<_> = (0..4u32)
            .map(|i| acq(&l, &format!("2001:db8:1:{i:x}::1")).unwrap())
            .collect();
        let mut jobs = Vec::new();
        for s in &slots {
            while let Some(j) = s.try_db_job(4, 8) {
                jobs.push(j);
            }
        }
        assert_eq!(jobs.len(), 8);
        // Another /48 is not affected; IPv4: allowance per /24.
        let other = acq(&l, "2001:db8:2::1").unwrap();
        assert!(other.try_db_job(4, 8).is_some());
        let v4: Vec<_> = (1..=3u8)
            .map(|i| {
                l.try_acquire(IpAddr::from([10, 0, 0, i]), Instant::now())
                    .unwrap()
            })
            .collect();
        let mut v4jobs = Vec::new();
        for s in &v4 {
            while let Some(j) = s.try_db_job(4, 5) {
                v4jobs.push(j);
            }
        }
        assert_eq!(v4jobs.len(), 5);
        // A slot returned in the /48: can be taken again.
        jobs.pop();
        assert!(slots[0].try_db_job(4, 8).is_none());
        assert!(slots[1].try_db_job(4, 8).is_some());
        drop(jobs);
        assert!(l.table().prefix_db.len() <= 3);
    }

    #[test]
    fn request_cost_and_refill() {
        let t0 = Instant::now();
        let c = LimitConfig::default();
        let mut b = ConnBudget::new(&c, t0);
        // Half full at the start (burst ×5): 50 requests, then refusal.
        for _ in 0..50 {
            assert!(b.admit(1, 10, t0));
        }
        assert!(!b.admit(1, 10, t0));
        // 1 s later: 20 more, or two requests of cost 9.
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.admit(9, 10, t1));
        assert!(b.admit(9, 10, t1));
        assert!(!b.admit(9, 10, t1));
        assert!(b.admit(1, 10, t1));
        assert!(b.admit(1, 10, t1));
        assert!(!b.admit(1, 10, t1));
        // Full after 10 s: 100 requests.
        let t2 = t1 + Duration::from_secs(10);
        for _ in 0..100 {
            assert!(b.admit(1, 10, t2));
        }
        assert!(!b.admit(1, 10, t2));
    }

    #[test]
    fn byte_bucket_and_response_debt() {
        let t0 = Instant::now();
        let c = LimitConfig::default();
        let mut b = ConnBudget::new(&c, t0);
        assert!(!b.admit(1, 5 << 19 | 1, t0));
        assert!(b.admit(1, 5 << 19, t0));
        assert!(!b.admit(1, 1, t0));
        // A response puts the bucket into debt: one has to wait longer.
        b.charge_bytes(1 << 20, t0);
        assert!(!b.admit(1, 1, t0 + Duration::from_millis(900)));
        assert!(b.admit(1, 1, t0 + Duration::from_millis(1100)));
    }
}
