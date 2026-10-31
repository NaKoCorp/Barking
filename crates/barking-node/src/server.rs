//! QUIC server of the node (spec §3.2, §4, §5): network shell around the
//! rules of `rules`.
//!
//! Documented choices:
//! - **Database**: a single `NodeStore` behind a `Mutex`, each operation in
//!   `spawn_blocking`. Writes (and reads) are serialized on a single SQLite
//!   connection: no race between the quota check and the insertion. The
//!   queue is bounded: at most `max_db_jobs` (64) operations in progress or
//!   pending, `max(1, max_db_jobs / 16)` per address group (/64, /32) and
//!   `max(1, max_db_jobs / 8)` per /48 or /24; beyond that `RateLimited`. A
//!   deposit first goes through `rules::precheck` (shape, expiry, minimal
//!   proof) without taking a slot. The token is held by the blocking task
//!   itself: abandoning the request only frees the slot once the work is
//!   finished.
//! - **Response memory**: each request reserves in advance the maximum size
//!   of its response (for `Fetch`: the page requested by the client,
//!   between 16 KiB and ~1 MiB, plus the encoding margin), then brought down
//!   to the encoded size. Three caps: one page per connection (1 MiB), 1/16
//!   of the global budget per address group (`max_response_bytes_per_ip`,
//!   4 MiB) and the global budget (`max_response_bytes_in_flight`, 64 MiB).
//!   Cap reached: `RateLimited`. The reservation is returned when the peer
//!   has acknowledged the whole response, or at the write deadline (stream
//!   then reset): `request_timeout + size / min_send_rate` (32 KiB/s), at
//!   most 60 s. Real memory: about twice the budget (items read from the
//!   database, encoded body, then copy held by quinn until acknowledgement).
//! - **Tasks**: the streams of a connection live in a `JoinSet` of the
//!   connection; the limiter slot is only returned after they end
//!   (abandoned on close).
//! - **Addresses**: a connection is only accepted after address validation
//!   (QUIC `Retry` token), so that a spoofed address does not reserve a slot
//!   in the limiter. The limiter groups by IP (/64 in IPv6) with caps per
//!   /56, /48 and /24, in memory only; no address is logged. An evicted
//!   connection (full table) is closed with the `CLOSE_EVICTED` code.
//! - **Timeouts**: handshake and `Hello` under `hello_timeout` (5 s);
//!   connection closed without a new request for `idle_timeout` (60 s, also
//!   the QUIC idle timeout); reading a request under `request_timeout`
//!   (10 s).
//! - **Streams**: at most `max_streams` (4) simultaneous bidirectional
//!   streams per connection, no unidirectional stream; reduced receive
//!   (256 KiB) and send (2 MiB) windows: bounded memory per connection.
//! - **Frames**: a frame that is too large, truncated or too slow closes the
//!   stream without a response; an unreadable body receives
//!   `Error(Malformed)`.
//! - **Throughput**: each request after `Hello` goes through the token
//!   bucket of its address group (`RateLimited` otherwise; a fetch costs
//!   `fetch_cost`); the bytes of each response are debited from it whether
//!   the response is acknowledged, cut, stopped by the peer or expired.
//!   After `MAX_CONSECUTIVE_REFUSALS` (20) consecutive throughput refusals,
//!   the connection is closed.
//! - **Purge** of expired items at startup then every 60 s.
//! - **Hash table** (`[dht]`, spec §3.3, §4): the identifier of a caller
//!   presenting a node certificate is read once per connection and passed to
//!   the table requests (`dht`). Without `[dht]`, they receive `Unsupported`
//!   and no table task starts. With it, two background tasks: table
//!   maintenance (`dht::maintain`) and replication between responsible
//!   nodes (`dht::replicate`).

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_dht::DiversityLimits;
use barking_packet::Tier;
use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::{
    ErrorReason, Limits, MAX_HOLDINGS_PER_PAGE, NodeId, PROTOCOL_VERSION, Request, Response, tls,
};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::DhtConfig;
use crate::dht::replicate::{self, PassReport};
use crate::dht::{Dht, maintain};
use crate::limits::{ConnectionSlot, GroupDbJob, LimitConfig, Limiter};
use crate::rules::{self, MAX_MAILBOXES_PER_FETCH, Policy};
use crate::store::NodeStore;
use crate::{Error, Result};

/// Interval between purges of expired items.
pub const PURGE_INTERVAL: Duration = Duration::from_secs(60);
/// Packet bytes per fetch page: the margin leaves room for the encoding of
/// the response (lengths, cursor) under `MAX_RESPONSE_BYTES`.
pub const FETCH_PAGE_BYTES: usize = MAX_RESPONSE_BYTES - 32 * 1024;
/// Receive window per stream: a request is at most 64 KiB.
const STREAM_WINDOW: u32 = 2 * MAX_REQUEST_BYTES as u32;
/// Unacknowledged response bytes per connection.
const SEND_WINDOW: u64 = 2 * MAX_RESPONSE_BYTES as u64;

/// Encoding margin of a page (item lengths, cursor, header).
const PAGE_OVERHEAD: usize = 8 * 1024;
/// Maximum write deadline of a response.
pub const MAX_WRITE_DEADLINE: Duration = Duration::from_secs(60);
/// Response reservation of a request other than `Fetch`, `FindNode` and
/// `FindValue`.
const SMALL_RESPONSE_BYTES: usize = 4 * 1024;
/// Reservation of a `Nodes` response (20 records of under 200 bytes).
const NODES_RESPONSE_BYTES: usize = 8 * 1024;
/// Reservation of a `Holdings` page: 1,024 fingerprints and the encoding
/// margin.
const HOLDINGS_RESPONSE_BYTES: usize = MAX_HOLDINGS_PER_PAGE * 32 + 1024;
/// Consecutive throughput refusals before the connection is closed.
pub const MAX_CONSECUTIVE_REFUSALS: u32 = 20;

/// Default values from the spec (reused by the configuration).
pub const DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT: usize = 64 << 20;
pub const DEFAULT_MAX_RESPONSE_BYTES_PER_IP: usize = 4 << 20;
pub const DEFAULT_MIN_SEND_RATE: u64 = 32 * 1024;
pub const DEFAULT_MAX_DB_JOBS: usize = 64;

/// Close codes (application).
const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_IDLE: u32 = 2;
const CLOSE_ABUSE: u32 = 3;
const CLOSE_EVICTED: u32 = 4;
const STREAM_REFUSED: u32 = 1;

pub struct ServerConfig {
    /// Already-bound UDP sockets (one per listen address).
    pub sockets: Vec<UdpSocket>,
    /// Identity key of the node.
    pub key: SigningKey,
    pub limits: LimitConfig,
    pub hello_timeout: Duration,
    pub idle_timeout: Duration,
    pub request_timeout: Duration,
    pub max_streams: u32,
    /// Response bytes in flight (reserved, unacknowledged), all peers combined.
    pub max_response_bytes_in_flight: usize,
    /// Response bytes in flight per address group (/64 in IPv6).
    pub max_response_bytes_per_ip: usize,
    /// Minimum expected rate of a reader: extends the write deadline of a
    /// response by `size / min_send_rate`.
    pub min_send_rate: u64,
    /// Database operations in progress or pending, all peers combined.
    pub max_db_jobs: usize,
    /// Share of a /48 or /24; `None`: `max_db_jobs / 8` (at least 1). That of
    /// a /64 or /32 is `max_db_jobs / 16` (at least 1).
    pub max_db_jobs_per_prefix: Option<usize>,
    /// Protocol versions served: `min_version..=version`.
    pub version: u16,
    pub min_version: u16,
    /// Observable gauges (tests, aggregated logs).
    pub stats: Arc<ServerStats>,
    /// Hash table between nodes; `None`: disabled.
    pub dht: Option<DhtConfig>,
    /// Tests: brings all the table maintenance and replication cadences down
    /// to this period. `None`: spec values.
    pub dht_tick: Option<Duration>,
    /// Tests only, never read from the configuration: diversity limits on the
    /// table's addresses. Default: those of the spec. The network tests lift
    /// them, all their nodes sharing the /24 of 127.0.0.1.
    pub dht_diversity: DiversityLimits,
    /// Tests only (feature `test-harness`, never in a production build),
    /// never read from the configuration: answers `Ok` to `Deposit` and
    /// `Store` without keeping anything, as a node that loses messages
    /// would. Default: false.
    #[cfg(feature = "test-harness")]
    pub test_swallow_deposits: bool,
    /// Tests only (feature `test-harness`): delays every response (`Hello`
    /// included) by this much, as a slow link would. Default: `None`.
    #[cfg(feature = "test-harness")]
    pub test_response_delay: Option<Duration>,
    /// Tests only (feature `test-harness`): sends every response after
    /// `Hello` at this many bytes per second at most, as a slow link would
    /// (the write deadline still applies). Default: `None`.
    #[cfg(feature = "test-harness")]
    pub test_send_rate: Option<u64>,
}

/// Gauge: current value and maximum reached.
#[derive(Debug, Default)]
pub struct Gauge {
    now: AtomicUsize,
    peak: AtomicUsize,
}

impl Gauge {
    pub fn now(&self) -> usize {
        self.now.load(Ordering::Relaxed)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Maximum reached since the last call, then the peak is reset to the
    /// current value (periodic reports).
    pub fn take_peak(&self) -> usize {
        self.peak
            .swap(self.now.load(Ordering::Relaxed), Ordering::Relaxed)
    }

    fn add(&self, n: usize) {
        let v = self.now.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(v, Ordering::Relaxed);
    }

    fn sub(&self, n: usize) {
        self.now.fetch_sub(n, Ordering::Relaxed);
    }
}

/// Server gauges (no per-peer data).
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Database operations in progress or pending.
    pub db_jobs: Gauge,
    /// Reserved response bytes.
    pub response_bytes: Gauge,
    /// Open connections.
    pub connections: Gauge,
    /// Accepted deposits (cumulative since the last `drain`).
    deposits_ok: AtomicU64,
    /// Fetches served.
    fetches: AtomicU64,
    /// Expired rows purged.
    purged: AtomicU64,
    /// Refusals per reason (index: `reason_index`).
    refusals: [AtomicU64; REASONS.len()],
    /// Replication: since startup, and since the last `drain`.
    replication: Mutex<ReplicationStats>,
    replication_period: Mutex<ReplicationStats>,
}

/// Numbers of the last passes that replicated something, kept.
const SENDING_PASSES_KEPT: usize = 64;

/// Replication passes: count, sum of the tallies and last tally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationStats {
    pub passes: u64,
    pub total: PassReport,
    pub last: Option<PassReport>,
    /// Numbers (1, 2…) of the last `SENDING_PASSES_KEPT` passes of which at
    /// least one send was accepted.
    pub sending_passes: VecDeque<u64>,
}

impl ReplicationStats {
    fn record(&mut self, r: &PassReport) {
        self.passes += 1;
        self.total.add(r);
        self.last = Some(r.clone());
        if r.sent > 0 {
            if self.sending_passes.len() >= SENDING_PASSES_KEPT {
                self.sending_passes.pop_front();
            }
            self.sending_passes.push_back(self.passes);
        }
    }
}

/// Error reasons, in the order of `reason_index`.
const REASONS: [ErrorReason; 13] = [
    ErrorReason::VersionTooOld,
    ErrorReason::Malformed,
    ErrorReason::Expired,
    ErrorReason::TooFarInFuture,
    ErrorReason::WrongTier,
    ErrorReason::PowTooWeak,
    ErrorReason::UnknownAckTarget,
    ErrorReason::MailboxFull,
    ErrorReason::NodeFull,
    ErrorReason::RateLimited,
    ErrorReason::TooManyMailboxes,
    ErrorReason::Unsupported,
    ErrorReason::NotResponsible,
];

fn reason_index(r: ErrorReason) -> usize {
    // No wildcard: a new reason makes compilation fail here.
    match r {
        ErrorReason::VersionTooOld => 0,
        ErrorReason::Malformed => 1,
        ErrorReason::Expired => 2,
        ErrorReason::TooFarInFuture => 3,
        ErrorReason::WrongTier => 4,
        ErrorReason::PowTooWeak => 5,
        ErrorReason::UnknownAckTarget => 6,
        ErrorReason::MailboxFull => 7,
        ErrorReason::NodeFull => 8,
        ErrorReason::RateLimited => 9,
        ErrorReason::TooManyMailboxes => 10,
        ErrorReason::Unsupported => 11,
        ErrorReason::NotResponsible => 12,
    }
}

impl ServerStats {
    /// Counts a refusal (never an address, mailbox or packet identifier).
    pub fn refuse(&self, reason: ErrorReason) {
        self.refusals[reason_index(reason)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn deposit_ok(&self) {
        self.deposits_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fetch_served(&self) {
        self.fetches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn purged(&self, n: usize) {
        self.purged.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Counts a replication pass.
    pub fn replicated(&self, r: &PassReport) {
        for m in [&self.replication, &self.replication_period] {
            m.lock().unwrap_or_else(PoisonError::into_inner).record(r);
        }
    }

    /// Replication passes since startup.
    pub fn replication(&self) -> ReplicationStats {
        self.replication
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Collects the counters since the last call (reset to zero, peaks
    /// brought down to the current value): one report per period.
    pub fn drain(&self) -> Report {
        let take = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        Report {
            deposits_ok: take(&self.deposits_ok),
            fetches: take(&self.fetches),
            purged: take(&self.purged),
            refusals: REASONS
                .iter()
                .map(|r| (*r, take(&self.refusals[reason_index(*r)])))
                .filter(|(_, n)| *n > 0)
                .collect(),
            connections: self.connections.now(),
            connections_peak: self.connections.take_peak(),
            db_jobs_peak: self.db_jobs.take_peak(),
            response_bytes_peak: self.response_bytes.take_peak(),
            replication: std::mem::take(
                &mut *self
                    .replication_period
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
            ),
        }
    }
}

/// Aggregated counters of a period (no per-peer data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub deposits_ok: u64,
    pub fetches: u64,
    pub purged: u64,
    /// Refusals per reason (zero reasons omitted).
    pub refusals: Vec<(ErrorReason, u64)>,
    pub connections: usize,
    pub connections_peak: usize,
    pub db_jobs_peak: usize,
    pub response_bytes_peak: usize,
    /// Replication passes of the period (`last`: the latest).
    pub replication: ReplicationStats,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "deposits accepted: {}, fetches: {}, expired purged: {}, refusals: ",
            self.deposits_ok, self.fetches, self.purged
        )?;
        if self.refusals.is_empty() {
            f.write_str("none")?;
        }
        for (i, (r, n)) in self.refusals.iter().enumerate() {
            write!(f, "{}{r:?}={n}", if i == 0 { "" } else { ", " })?;
        }
        write!(
            f,
            ", open connections: {} (peak {}), database operations peak: {}, response bytes peak: {}",
            self.connections, self.connections_peak, self.db_jobs_peak, self.response_bytes_peak
        )?;
        if self.replication.passes > 0 {
            write!(
                f,
                ", replication: {} passes, {}",
                self.replication.passes, self.replication.total
            )?;
        }
        Ok(())
    }
}

/// Logs an aggregated report every period (no address).
pub async fn report_loop(stats: Arc<ServerStats>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tick.tick().await;
        tracing::info!("{}", stats.drain());
    }
}

/// Global token budget, mirrored in a gauge.
struct Budget {
    sem: Arc<Semaphore>,
    stats: Arc<ServerStats>,
    gauge: fn(&ServerStats) -> &Gauge,
}

impl Budget {
    fn new(cap: usize, stats: Arc<ServerStats>, gauge: fn(&ServerStats) -> &Gauge) -> Arc<Budget> {
        Arc::new(Budget {
            sem: Arc::new(Semaphore::new(cap)),
            stats,
            gauge,
        })
    }

    fn gauge(&self) -> &Gauge {
        (self.gauge)(&self.stats)
    }

    fn held(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> Held {
        self.gauge().add(permit.num_permits());
        Held {
            budget: Arc::clone(self),
            permit: Some(permit),
        }
    }

    /// Reserves `n` tokens without waiting.
    fn try_take(self: &Arc<Self>, n: usize) -> Option<Held> {
        let n = u32::try_from(n).ok()?;
        let permit = Arc::clone(&self.sem).try_acquire_many_owned(n).ok()?;
        Some(self.held(permit))
    }

    /// Reserves `n` tokens, waiting if needed (internal tasks).
    async fn take(self: &Arc<Self>, n: u32) -> Option<Held> {
        let permit = Arc::clone(&self.sem).acquire_many_owned(n).await.ok()?;
        Some(self.held(permit))
    }
}

/// Reserved tokens, returned on drop.
struct Held {
    budget: Arc<Budget>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Held {
    /// Brings the reservation down to `keep` tokens.
    fn shrink(&mut self, keep: usize) {
        if let Some(p) = self.permit.as_mut() {
            let extra = p.num_permits().saturating_sub(keep);
            if let Some(e) = p.split(extra) {
                // Gauge decremented before the tokens become free again.
                self.budget.gauge().sub(e.num_permits());
                drop(e);
            }
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(p) = self.permit.take() {
            self.budget.gauge().sub(p.num_permits());
            drop(p);
        }
    }
}

impl ServerConfig {
    /// Spec values.
    pub fn new(sockets: Vec<UdpSocket>, key: SigningKey) -> ServerConfig {
        ServerConfig {
            sockets,
            key,
            limits: LimitConfig::default(),
            hello_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            max_streams: 4,
            max_response_bytes_in_flight: DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT,
            max_response_bytes_per_ip: DEFAULT_MAX_RESPONSE_BYTES_PER_IP,
            min_send_rate: DEFAULT_MIN_SEND_RATE,
            max_db_jobs: DEFAULT_MAX_DB_JOBS,
            max_db_jobs_per_prefix: None,
            version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION,
            stats: Arc::new(ServerStats::default()),
            dht: None,
            dht_tick: None,
            dht_diversity: DiversityLimits::SPEC,
            #[cfg(feature = "test-harness")]
            test_swallow_deposits: false,
            #[cfg(feature = "test-harness")]
            test_response_delay: None,
            #[cfg(feature = "test-harness")]
            test_send_rate: None,
        }
    }
}

/// State shared by all connections.
pub(crate) struct Shared {
    store: Mutex<NodeStore>,
    pub(crate) policy: Policy,
    node_id: NodeId,
    version: u16,
    min_version: u16,
    hello_timeout: Duration,
    idle_timeout: Duration,
    request_timeout: Duration,
    limiter: Arc<Limiter>,
    db: Arc<Budget>,
    /// Database operations in progress or pending per address group.
    db_jobs_per_group: u32,
    /// Same per /48 (IPv6) or /24 (IPv4).
    db_jobs_per_prefix: u32,
    responses: Arc<Budget>,
    response_bytes_per_ip: usize,
    min_send_rate: u64,
    stats: Arc<ServerStats>,
    /// Hash table, if `[dht]` is configured.
    dht: Option<Arc<Dht>>,
    /// Tests only: see `ServerConfig::test_swallow_deposits`.
    #[cfg(feature = "test-harness")]
    swallow_deposits: bool,
    /// Tests only: see `ServerConfig::test_response_delay`.
    #[cfg(feature = "test-harness")]
    response_delay: Option<Duration>,
    /// Tests only: see `ServerConfig::test_send_rate`.
    #[cfg(feature = "test-harness")]
    send_rate: Option<u64>,
}

impl Shared {
    pub(crate) fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Tests only: the artificial delay before a response, if configured.
    async fn test_delay(&self) {
        #[cfg(feature = "test-harness")]
        if let Some(d) = self.response_delay {
            tokio::time::sleep(d).await;
        }
    }

    /// Tests only: this node loses what it accepts.
    fn swallows_deposits(&self) -> bool {
        #[cfg(feature = "test-harness")]
        return self.swallow_deposits;
        #[cfg(not(feature = "test-harness"))]
        false
    }

    /// Sends a response (see `respond`), paced in tests if configured.
    async fn send_response(&self, send: &mut SendStream, bytes: &[u8]) -> bool {
        let limit = self.write_deadline(bytes.len());
        #[cfg(feature = "test-harness")]
        if let Some(rate) = self.send_rate {
            return respond_paced(send, bytes, limit, rate).await;
        }
        respond(send, bytes, limit).await
    }

    /// Write deadline of a response of `len` bytes.
    fn write_deadline(&self, len: usize) -> Duration {
        write_deadline(self.request_timeout, len, self.min_send_rate)
    }
}

/// `request_timeout + len / rate`, at most `MAX_WRITE_DEADLINE`.
pub fn write_deadline(request_timeout: Duration, len: usize, rate: u64) -> Duration {
    let extra = Duration::from_secs_f64(len as f64 / rate.max(1) as f64);
    request_timeout
        .saturating_add(extra)
        .min(MAX_WRITE_DEADLINE)
}

/// Page size served for a request of `max_bytes`.
pub fn fetch_page_bytes(max_bytes: u32) -> usize {
    (max_bytes as usize).clamp(barking_proto::MIN_PAGE_BYTES as usize, FETCH_PAGE_BYTES)
}

/// Response reservation of a page: the page, or a single larger item
/// (tier L), plus the encoding margin.
fn fetch_reserve(max_bytes: u32) -> usize {
    (fetch_page_bytes(max_bytes).max(Tier::L.size()) + PAGE_OVERHEAD).min(MAX_RESPONSE_BYTES)
}

/// Outcome of a database operation.
pub(crate) enum Stored<T> {
    Done(T),
    /// Database queue full.
    Busy,
    /// Internal error (logged).
    Failed,
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    /// Runs `f` on the database, outside the async loop. `wait`: waits for a
    /// slot in the queue (internal tasks) instead of answering `Busy`.
    /// `group`: the request comes from this address group, which is only
    /// entitled to `db_jobs_per_group` slots at a time (`Busy` beyond).
    pub(crate) async fn with_store<T: Send + 'static>(
        self: &Arc<Self>,
        wait: bool,
        group: Option<&ConnectionSlot>,
        f: impl FnOnce(&mut NodeStore, &Policy) -> Result<T> + Send + 'static,
    ) -> Stored<T> {
        let group_job: Option<GroupDbJob> = match group {
            Some(g) => match g.try_db_job(self.db_jobs_per_group, self.db_jobs_per_prefix) {
                Some(j) => Some(j),
                None => return Stored::Busy,
            },
            None => None,
        };
        let slot = if wait {
            self.db.take(1).await
        } else {
            self.db.try_take(1)
        };
        let Some(slot) = slot else {
            return Stored::Busy;
        };
        let me = Arc::clone(self);
        let r = tokio::task::spawn_blocking(move || {
            // The slots are returned at the end of the work, even if the request
            // was abandoned in the meantime.
            let _slot = slot;
            let _group_job = group_job;
            let mut store = me.store.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut store, &me.policy)
        })
        .await;
        match r {
            Ok(Ok(v)) => Stored::Done(v),
            Ok(Err(e)) => {
                tracing::error!("internal storage error: {e}");
                Stored::Failed
            }
            Err(_) => {
                tracing::error!("storage task interrupted");
                Stored::Failed
            }
        }
    }
}

/// Runs the node until `shutdown`.
pub async fn run(
    config: ServerConfig,
    store: NodeStore,
    policy: Policy,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    policy.validate()?;
    if config.min_version > config.version {
        return Err(Error::Config("min_version > version".into()));
    }
    if config.sockets.is_empty() {
        return Err(Error::Config("no listen address".into()));
    }
    if config.max_db_jobs == 0
        || config.max_response_bytes_in_flight < MAX_RESPONSE_BYTES
        || config.max_response_bytes_per_ip < MAX_RESPONSE_BYTES
        || config.min_send_rate == 0
    {
        return Err(Error::Config(
            "max_db_jobs or min_send_rate is zero, or response budget under 1 MiB".into(),
        ));
    }

    let mut qcfg = tls::quinn_server_config(&config.key);
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(config.max_streams.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(STREAM_WINDOW.into())
        // Memory held per connection is bounded: 256 KiB on receive, 2 MiB of
        // responses awaiting acknowledgement.
        .receive_window((2 * STREAM_WINDOW).into())
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            config
                .idle_timeout
                .try_into()
                .map_err(|_| Error::Config("idle_timeout too large".into()))?,
        ));
    qcfg.transport_config(Arc::new(transport));
    qcfg.migration(false);

    let runtime =
        quinn::default_runtime().ok_or_else(|| Error::Config("no tokio runtime".into()))?;
    let mut endpoints = Vec::new();
    for socket in config.sockets {
        endpoints.push(Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(qcfg.clone()),
            socket,
            runtime.clone(),
        )?);
    }
    // Outbound calls to peers leave from the same endpoints, hence from the
    // same UDP port (spec §3.3).
    // Without a public address, the table is disabled (spec §8).
    let dht_cfg = config.dht.filter(|d| {
        let has_addr = d.public_v4.is_some() || d.public_v6.is_some();
        if !has_addr {
            tracing::warn!("[dht] without public_addr: table disabled, plain relay");
        }
        has_addr
    });
    let dht = dht_cfg.map(|d| {
        Arc::new(Dht::new(
            config.key.clone(),
            d,
            endpoints.clone(),
            db_jobs_per_group(config.max_db_jobs),
            config.dht_tick,
            config.dht_diversity,
        ))
    });

    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        policy,
        node_id: NodeId::from_public_key(&config.key.verifying_key()),
        version: config.version,
        min_version: config.min_version,
        hello_timeout: config.hello_timeout,
        idle_timeout: config.idle_timeout,
        request_timeout: config.request_timeout,
        limiter: Limiter::new(config.limits),
        db: Budget::new(config.max_db_jobs, Arc::clone(&config.stats), |s| {
            &s.db_jobs
        }),
        db_jobs_per_group: db_jobs_per_group(config.max_db_jobs),
        db_jobs_per_prefix: config.max_db_jobs_per_prefix.map_or_else(
            || db_jobs_per_prefix(config.max_db_jobs),
            |n| u32::try_from(n.max(1)).unwrap_or(u32::MAX),
        ),
        responses: Budget::new(
            config.max_response_bytes_in_flight,
            Arc::clone(&config.stats),
            |s| &s.response_bytes,
        ),
        response_bytes_per_ip: config.max_response_bytes_per_ip,
        min_send_rate: config.min_send_rate,
        stats: Arc::clone(&config.stats),
        dht: dht.clone(),
        #[cfg(feature = "test-harness")]
        swallow_deposits: config.test_swallow_deposits,
        #[cfg(feature = "test-harness")]
        response_delay: config.test_response_delay,
        #[cfg(feature = "test-harness")]
        send_rate: config.test_send_rate,
    });

    if let Stored::Done(n) = shared
        .with_store(true, None, |s, _| s.purge_expired(unix_now()))
        .await
    {
        shared.stats.purged(n);
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    for ep in &endpoints {
        tasks.spawn(accept_loop(
            ep.clone(),
            Arc::clone(&shared),
            stop_rx.clone(),
        ));
    }
    tasks.spawn(purge_loop(Arc::clone(&shared), stop_rx.clone()));
    if let Some(d) = &dht {
        tasks.spawn(replicate::run(
            Arc::clone(d),
            Arc::clone(&shared),
            stop_rx.clone(),
        ));
    }
    // Table maintenance, awaited on shutdown: it saves `peers`.
    let maintenance =
        dht.map(|d| tokio::spawn(maintain::run(d, Arc::clone(&shared), stop_rx.clone())));

    shutdown.await;
    let _ = stop_tx.send(true);
    if let Some(mut m) = maintenance
        && timeout(Duration::from_secs(10), &mut m).await.is_err()
    {
        m.abort();
    }
    for ep in &endpoints {
        ep.close(CLOSE_NORMAL.into(), b"arret");
    }
    for ep in &endpoints {
        let _ = timeout(Duration::from_secs(2), ep.wait_idle()).await;
    }
    tasks.shutdown().await;
    Ok(())
}

async fn purge_loop(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(PURGE_INTERVAL);
    tick.tick().await; // first tick is immediate: the startup purge is done.
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Stored::Done(n) =
                    shared.with_store(true, None, |s, _| s.purge_expired(unix_now())).await
                {
                    shared.stats.purged(n);
                }
            }
            _ = stop.changed() => return,
        }
    }
}

async fn accept_loop(ep: Endpoint, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut conns = JoinSet::new();
    loop {
        let incoming = tokio::select! {
            i = ep.accept() => i,
            _ = stop.changed() => None,
        };
        let Some(incoming) = incoming else { break };
        // Reaps finished tasks.
        while conns.try_join_next().is_some() {}
        admit(incoming, &shared, &mut conns, &stop);
    }
    conns.shutdown().await;
}

fn admit(
    incoming: Incoming,
    shared: &Arc<Shared>,
    conns: &mut JoinSet<()>,
    stop: &watch::Receiver<bool>,
) {
    if !incoming.remote_address_validated() {
        if incoming.may_retry() {
            // Stateless token: the client comes back to prove its address.
            let _ = incoming.retry();
        } else {
            incoming.ignore();
        }
        return;
    }
    let Some(slot) = shared
        .limiter
        .try_acquire(incoming.remote_address().ip(), Instant::now())
    else {
        incoming.refuse();
        return;
    };
    let shared = Arc::clone(shared);
    let stop = stop.clone();
    conns.spawn(async move {
        shared.stats.connections.add(1);
        let _open = OpenConnection(Arc::clone(&shared.stats));
        serve_connection(incoming, slot, shared, stop).await;
    });
}

/// Count of an open connection (even if its task is abandoned).
struct OpenConnection(Arc<ServerStats>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.connections.sub(1);
    }
}

async fn serve_connection(
    incoming: Incoming,
    slot: ConnectionSlot,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + shared.hello_timeout;
    let Ok(Ok(conn)) = tokio::time::timeout_at(deadline, async { incoming.accept()?.await }).await
    else {
        return;
    };
    match tokio::time::timeout_at(deadline, hello(&conn, &shared)).await {
        Ok(true) => {}
        _ => {
            conn.close(CLOSE_PROTOCOL.into(), b"hello");
            return;
        }
    }

    // Identifier of the caller if it presented a node certificate.
    let peer = tls::peer_node_id(&conn);
    let conn_state = Arc::new(ConnState {
        peer,
        remote: conn.remote_address(),
        refusals: AtomicU32::new(0),
        conn: conn.clone(),
        reserved: AtomicUsize::new(0),
        slot,
    });
    // Streams of this connection: bounded by QUIC (`max_streams`), awaited or
    // abandoned before returning the limiter slot.
    let mut streams = JoinSet::new();
    loop {
        while streams.try_join_next().is_some() {}
        let next = tokio::select! {
            r = timeout(shared.idle_timeout, conn.accept_bi()) => r,
            _ = stop.changed() => {
                conn.close(CLOSE_NORMAL.into(), b"arret");
                break;
            }
            // Connection table full: slot ceded to another group.
            _ = conn_state.slot.evicted().notified() => {
                conn.close(CLOSE_EVICTED.into(), b"evince");
                break;
            }
        };
        match next {
            Err(_) => {
                conn.close(CLOSE_IDLE.into(), b"inactif");
                break;
            }
            Ok(Err(_)) => break,
            Ok(Ok((send, recv))) => {
                streams.spawn(serve_stream(
                    send,
                    recv,
                    Arc::clone(&shared),
                    Arc::clone(&conn_state),
                ));
            }
        }
    }
    streams.shutdown().await;
}

/// State of a connection shared by its streams.
struct ConnState {
    /// Calling node authenticated by its certificate (spec §3.3).
    peer: Option<NodeId>,
    /// Source address (in memory only, never logged): the callback for a
    /// `from` record is only made if it announces it (spec §6.2).
    remote: SocketAddr,
    /// Consecutive throughput refusals.
    refusals: AtomicU32,
    conn: Connection,
    /// Response bytes reserved by this connection (at most one page).
    reserved: AtomicUsize,
    /// Limiter slot (and address-group state: rate bucket, reservations):
    /// returned when the connection and its streams are finished.
    slot: ConnectionSlot,
}

/// Response reservation counted at three levels: connection, address
/// group, global budget.
struct Reservation {
    held: Held,
    state: Arc<ConnState>,
    n: usize,
}

impl Reservation {
    fn try_new(shared: &Shared, state: &Arc<ConnState>, n: usize) -> Option<Reservation> {
        state
            .reserved
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(n).filter(|t| *t <= MAX_RESPONSE_BYTES)
            })
            .ok()?;
        if !state
            .slot
            .try_reserve_bytes(n, shared.response_bytes_per_ip)
        {
            state.reserved.fetch_sub(n, Ordering::Relaxed);
            return None;
        }
        let Some(held) = shared.responses.try_take(n) else {
            state.slot.release_bytes(n);
            state.reserved.fetch_sub(n, Ordering::Relaxed);
            return None;
        };
        Some(Reservation {
            held,
            state: Arc::clone(state),
            n,
        })
    }

    /// Brings the reservation down to `keep` bytes (never above the
    /// reservation).
    fn shrink(&mut self, keep: usize) {
        let extra = self.n.saturating_sub(keep);
        self.held.shrink(keep);
        self.state.slot.release_bytes(extra);
        self.state.reserved.fetch_sub(extra, Ordering::Relaxed);
        self.n -= extra;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.slot.release_bytes(self.n);
        self.state.reserved.fetch_sub(self.n, Ordering::Relaxed);
    }
}

/// Reads a request; `None` if the stream was closed (frame too large,
/// truncated, too slow). Also returns the size read.
async fn read_request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    limit: Duration,
) -> Option<(core::result::Result<Request, ()>, usize)> {
    match timeout(
        limit,
        frame::read_counted::<Request>(recv, MAX_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok((req, size))) => Some((Ok(req), size)),
        Ok(Err(FrameError::Malformed)) => Some((Err(()), MAX_REQUEST_BYTES)),
        Ok(Err(_)) | Err(_) => {
            let _ = recv.stop(STREAM_REFUSED.into());
            let _ = send.reset(STREAM_REFUSED.into());
            None
        }
    }
}

/// Writes the response and waits for its complete acknowledgement, within
/// `limit`; otherwise (timeout, stopped by the peer) the stream is reset.
/// True if acknowledged.
async fn respond(send: &mut SendStream, bytes: &[u8], limit: Duration) -> bool {
    let sent = timeout(limit, async {
        send.write_all(bytes).await.ok()?;
        send.finish().ok()?;
        send.stopped().await.ok()
    })
    .await;
    match sent {
        Ok(Some(None)) => true,
        _ => {
            let _ = send.reset(STREAM_REFUSED.into());
            false
        }
    }
}

/// Tests only: `respond`, writing at `rate` bytes per second at most.
#[cfg(feature = "test-harness")]
async fn respond_paced(send: &mut SendStream, bytes: &[u8], limit: Duration, rate: u64) -> bool {
    const CHUNK: usize = 4096;
    let sent = timeout(limit, async {
        for chunk in bytes.chunks(CHUNK) {
            send.write_all(chunk).await.ok()?;
            let pause = chunk.len() as f64 / rate.max(1) as f64;
            tokio::time::sleep(Duration::from_secs_f64(pause)).await;
        }
        send.finish().ok()?;
        send.stopped().await.ok()
    })
    .await;
    match sent {
        Ok(Some(None)) => true,
        _ => {
            let _ = send.reset(STREAM_REFUSED.into());
            false
        }
    }
}

fn encode(resp: &Response) -> Vec<u8> {
    frame::encode(resp, MAX_RESPONSE_BYTES).unwrap_or_else(|_| {
        // A page is bounded under `MAX_RESPONSE_BYTES`: does not happen.
        frame::encode(&Response::Error(ErrorReason::NodeFull), MAX_RESPONSE_BYTES)
            .unwrap_or_default()
    })
}

/// First stream: `Hello` is mandatory. True if the connection can continue.
async fn hello(conn: &Connection, shared: &Arc<Shared>) -> bool {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
        return false;
    };
    let Some((req, _)) = read_request(&mut send, &mut recv, shared.hello_timeout).await else {
        return false;
    };
    let (resp, ok) = match req {
        Ok(Request::Hello {
            version,
            min_version,
        }) if min_version <= version => {
            if !barking_proto::versions_overlap(
                min_version,
                version,
                shared.min_version,
                shared.version,
            ) {
                (Response::Error(ErrorReason::VersionTooOld), false)
            } else {
                (
                    Response::Hello {
                        version: shared.version,
                        min_version: shared.min_version,
                        node_id: shared.node_id,
                        pow_bits: shared.policy.pow_bits,
                        limits: Limits {
                            max_mailboxes_per_fetch: MAX_MAILBOXES_PER_FETCH as u16,
                            max_request_bytes: MAX_REQUEST_BYTES as u32,
                            max_response_bytes: MAX_RESPONSE_BYTES as u32,
                        },
                    },
                    true,
                )
            }
        }
        _ => (Response::Error(ErrorReason::Malformed), false),
    };
    if let Response::Error(r) = &resp {
        shared.stats.refuse(*r);
    }
    shared.test_delay().await;
    // Waits for the acknowledgement: the response arrives before any close.
    respond(&mut send, &encode(&resp), shared.hello_timeout).await;
    ok
}

async fn serve_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    shared: Arc<Shared>,
    state: Arc<ConnState>,
) {
    let Some((req, size)) = read_request(&mut send, &mut recv, shared.request_timeout).await else {
        return;
    };
    let now = Instant::now();
    state.slot.touch(now);
    let cost = match &req {
        Ok(Request::Fetch { mailboxes, .. }) => fetch_cost(mailboxes.len()),
        _ => 1,
    };
    let admitted = state.slot.admit(cost, size, now);
    if !admitted {
        shared.stats.refuse(ErrorReason::RateLimited);
        let n = state.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_CONSECUTIVE_REFUSALS {
            state.conn.close(CLOSE_ABUSE.into(), b"debit");
            return;
        }
        let bytes = encode(&Response::Error(ErrorReason::RateLimited));
        shared.test_delay().await;
        respond(&mut send, &bytes, shared.write_deadline(bytes.len())).await;
        state.charge(bytes.len());
        return;
    }
    state.refusals.store(0, Ordering::Relaxed);

    // Response reservation taken before any work; cap reached: refusal.
    let reserve = match &req {
        Ok(Request::Fetch { max_bytes, .. }) => fetch_reserve(*max_bytes),
        // Without a table, these requests receive `Unsupported`: small reservation.
        Ok(Request::FindNode { .. }) if shared.dht.is_some() => NODES_RESPONSE_BYTES,
        Ok(Request::FindValue { .. }) if shared.dht.is_some() => HOLDINGS_RESPONSE_BYTES,
        _ => SMALL_RESPONSE_BYTES,
    };
    let (bytes, held) = match Reservation::try_new(&shared, &state, reserve) {
        None => {
            shared.stats.refuse(ErrorReason::RateLimited);
            (encode(&Response::Error(ErrorReason::RateLimited)), None)
        }
        Some(mut held) => {
            let resp = match req {
                Err(()) => Response::Error(ErrorReason::Malformed),
                Ok(req) => match handle(req, &shared, &state).await {
                    Stored::Done(r) => r,
                    Stored::Busy => Response::Error(ErrorReason::RateLimited),
                    Stored::Failed => {
                        // Internal error (already logged): stream closed.
                        let _ = send.reset(STREAM_REFUSED.into());
                        return;
                    }
                },
            };
            if let Response::Error(r) = &resp {
                shared.stats.refuse(*r);
            }
            // The reservation covers the response: page bounded by `fetch_reserve`.
            let bytes = encode(&resp);
            held.shrink(bytes.len());
            (bytes, Some(held))
        }
    };
    shared.test_delay().await;
    // Throughput counted on the size sent, whether the response is
    // acknowledged, cut, stopped by the peer or expired.
    shared.send_response(&mut send, &bytes).await;
    drop(held);
    state.charge(bytes.len());
}

impl ConnState {
    fn charge(&self, bytes: usize) {
        self.slot.charge_bytes(bytes, Instant::now());
    }
}

/// Cost of a fetch in request tokens: 1, plus 1 per block of 8 mailboxes
/// (each mailbox is an index read).
pub fn fetch_cost(mailboxes: usize) -> u32 {
    u32::try_from(1 + mailboxes.div_ceil(8)).unwrap_or(u32::MAX)
}

/// Share of the database queue of an address group: 1/16, at least 1.
pub fn db_jobs_per_group(max_db_jobs: usize) -> u32 {
    u32::try_from((max_db_jobs / 16).max(1)).unwrap_or(u32::MAX)
}

/// Share of the database queue of a /48 or /24: 1/8, at least 1.
pub fn db_jobs_per_prefix(max_db_jobs: usize) -> u32 {
    u32::try_from((max_db_jobs / 8).max(1)).unwrap_or(u32::MAX)
}

/// Handles a request after `Hello`; `peer`: authenticated calling node.
async fn handle(req: Request, shared: &Arc<Shared>, state: &ConnState) -> Stored<Response> {
    let group = &state.slot;
    let to_resp = |r: core::result::Result<Response, ErrorReason>| match r {
        Ok(resp) => resp,
        Err(e) => Response::Error(e),
    };
    match req {
        Request::Hello { .. } => Stored::Done(Response::Error(ErrorReason::Malformed)),
        // Tests only: a node that loses what it accepts.
        Request::Deposit { .. } | Request::Store { .. } if shared.swallows_deposits() => {
            Stored::Done(Response::Ok)
        }
        Request::Deposit { packet, pow } => {
            // Shape, expiry and proof at the base difficulty are checked before
            // taking a slot in the database queue.
            if let Err(r) = rules::precheck(&shared.policy, &packet, pow, unix_now()) {
                return Stored::Done(Response::Error(r));
            }
            match shared
                .with_store(false, Some(group), move |s, p| {
                    rules::deposit(s, p, &packet, pow, unix_now())
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(r.map(|()| {
                    shared.stats.deposit_ok();
                    Response::Ok
                }))),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Fetch {
            mailboxes,
            cursor,
            max_bytes,
        } => {
            let page = fetch_page_bytes(max_bytes);
            match shared
                .with_store(false, Some(group), move |s, _| {
                    rules::fetch(s, &mailboxes, cursor, page)
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(r.map(|(items, next)| {
                    shared.stats.fetch_served();
                    Response::Items { items, next }
                }))),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Ping { .. }
        | Request::FindNode { .. }
        | Request::Store { .. }
        | Request::FindValue { .. } => match &shared.dht {
            None => Stored::Done(Response::Error(ErrorReason::Unsupported)),
            Some(dht) => {
                dht.handle(req, state.peer, state.remote, shared, group)
                    .await
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_drains_counters_and_peaks() {
        let st = ServerStats::default();
        st.deposit_ok();
        st.deposit_ok();
        st.fetch_served();
        st.purged(3);
        st.refuse(ErrorReason::PowTooWeak);
        st.refuse(ErrorReason::PowTooWeak);
        st.refuse(ErrorReason::RateLimited);
        st.connections.add(5);
        st.connections.sub(3);
        let r = st.drain();
        assert_eq!((r.deposits_ok, r.fetches, r.purged), (2, 1, 3));
        assert_eq!(
            r.refusals,
            vec![(ErrorReason::PowTooWeak, 2), (ErrorReason::RateLimited, 1)]
        );
        assert_eq!((r.connections, r.connections_peak), (2, 5));
        let line = r.to_string();
        assert!(
            line.contains("PowTooWeak=2") && line.contains("peak 5"),
            "{line}"
        );
        // Next period: counters at zero, peak brought down to the current value.
        let r = st.drain();
        assert_eq!((r.deposits_ok, r.fetches, r.purged), (0, 0, 0));
        assert!(r.refusals.is_empty());
        assert_eq!((r.connections, r.connections_peak), (2, 2));
    }

    #[test]
    fn write_deadline_scales_with_size() {
        let t = Duration::from_secs(10);
        let r = 32 * 1024;
        assert_eq!(write_deadline(t, 0, r), t);
        assert_eq!(write_deadline(t, 32 * 1024, r), Duration::from_secs(11));
        assert_eq!(write_deadline(t, 1 << 20, r), Duration::from_secs(42));
        assert_eq!(write_deadline(t, 100 << 20, r), MAX_WRITE_DEADLINE);
    }

    #[test]
    fn fetch_page_and_reserve_bounds() {
        assert_eq!(fetch_page_bytes(0), 16 * 1024);
        assert_eq!(fetch_page_bytes(64 * 1024), 64 * 1024);
        assert_eq!(fetch_page_bytes(u32::MAX), FETCH_PAGE_BYTES);
        // A single L item always fits in the reservation.
        assert!(fetch_reserve(0) >= Tier::L.size() + PAGE_OVERHEAD);
        assert!(fetch_reserve(u32::MAX) <= MAX_RESPONSE_BYTES);
        assert!(fetch_reserve(u32::MAX) >= FETCH_PAGE_BYTES + PAGE_OVERHEAD);
    }
}
