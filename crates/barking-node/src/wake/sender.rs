//! Bounded wake sender: hands sealed push tokens to the relays named in the
//! subscriptions. The queue is bounded (excess wake-ups are dropped and
//! counted), batches are grouped per relay, a relay receives at most
//! `WAKES_PER_SEC_PER_RELAY` tokens per second, a batch the relay did not
//! accept gets a single retry, and a relay that could not be reached is
//! skipped for `RELAY_FAILURE_BACKOFF`. One host holds at most
//! `MAX_SENDS_PER_HOST` of the send permits. Nothing here logs a relay host,
//! an address or a token.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use barking_proto::MAX_WAKE_ITEMS;
use barking_proto::client::{Client, Session};
use barking_proto::push::RelayRef;
use barking_proto::routable;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};

use super::WakeOrder;
use crate::server::ServerStats;

/// Wake-ups waiting or in flight, all relays together.
pub const WAKE_QUEUE: usize = 10_000;
/// Tokens handed to one relay per second (one full batch may go at once).
pub const WAKES_PER_SEC_PER_RELAY: u32 = 50;
/// Delay before the single retry of a failed batch.
pub const WAKE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Bound on connecting to a relay (name resolution included).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on one `Wake` request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a batch could not be handed to a relay.
#[derive(Debug)]
pub enum WakeError {
    /// Name resolution failed.
    Resolve,
    /// The name resolves only to private, local or otherwise unroutable addresses.
    NoRoutableAddress,
    /// No address accepted a QUIC connection with the expected identity.
    Connect,
    /// The relay did not accept the request.
    Request,
}

/// How batches reach a relay.
pub trait WakeTransport: Send + Sync + 'static {
    fn send(
        &self,
        relay: &RelayRef,
        items: Vec<Vec<u8>>,
    ) -> impl Future<Output = Result<(), WakeError>> + Send;
}

/// Sessions kept at most (least recently used evicted).
pub const MAX_KEPT_SESSIONS: usize = 64;
/// A kept session unused for this long is dropped (the idle timeouts of both
/// ends would have killed it anyway).
pub const SESSION_IDLE: Duration = Duration::from_secs(20);
/// Sends in progress at once, all relays together (bounds sockets and
/// blocking resolver threads).
pub const MAX_CONCURRENT_RELAY_SENDS: usize = 32;
/// Addresses tried per relay.
const MAX_ADDRS: usize = 4;
/// A relay that could not be reached (resolution, no usable address,
/// connection) is skipped this long: its orders are dropped, counted as
/// failed, without taking a permit.
pub const RELAY_FAILURE_BACKOFF: Duration = Duration::from_secs(300);
/// Permits one relay host may hold at once (out of
/// `MAX_CONCURRENT_RELAY_SENDS`). A worker sends one batch at a time, so the
/// share is counted per host: many relays named on one host (distinct ids or
/// ports) cannot take every permit.
pub const MAX_SENDS_PER_HOST: usize = 4;
/// Relays remembered in backoff at most (oldest forgotten first).
const MAX_BACKOFF_ENTRIES: usize = WAKE_QUEUE;

/// True if a resolved relay address may be dialled. An IPv6 carrying an
/// IPv4 (mapped, compatible, NAT64, 6to4, Teredo) is refused even when
/// private addresses are allowed (spec §3.4): it would hide the IPv4 it
/// reaches from the routable filter.
pub(crate) fn wake_address_ok(a: &SocketAddr, allow_private: bool) -> bool {
    if let std::net::IpAddr::V6(v6) = a.ip() {
        let s = v6.segments();
        if barking_proto::embeds_ipv4(&v6)
            // 64:ff9b::/96 NAT64 and 64:ff9b:1::/48 local-use NAT64.
            || (s[0] == 0x64 && s[1] == 0xff9b && (s[2..6] == [0; 4] || s[2] == 1))
            // 2002::/16 6to4.
            || s[0] == 0x2002
            // 2001::/32 Teredo.
            || (s[0] == 0x2001 && s[1] == 0)
        {
            return false;
        }
    }
    allow_private || routable(a)
}

/// Tries `addrs` in turn until one gives a session; each address gets an
/// equal share of the time left before `deadline`, so that one that never
/// answers does not starve the next ones.
async fn connect_any(
    addrs: &[SocketAddr],
    id: barking_proto::NodeId,
    deadline: Instant,
) -> Result<Session, WakeError> {
    for (i, addr) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let share = left / u32::try_from(addrs.len() - i).unwrap_or(1);
        if let Ok(Ok(s)) = timeout(share, Client::connect(*addr, id)).await {
            return Ok(s);
        }
    }
    Err(WakeError::Connect)
}

/// Bounded map of kept values, least recently used evicted.
struct Kept<V> {
    max: usize,
    map: HashMap<RelayRef, (V, Instant)>,
}

impl<V: Clone> Kept<V> {
    fn new(max: usize) -> Kept<V> {
        Kept {
            max,
            map: HashMap::new(),
        }
    }

    /// The value, refreshed; an entry idle longer than `SESSION_IDLE` is dropped.
    fn get(&mut self, relay: &RelayRef) -> Option<V> {
        let now = Instant::now();
        match self.map.get_mut(relay) {
            Some((v, used)) if now.duration_since(*used) <= SESSION_IDLE => {
                *used = now;
                Some(v.clone())
            }
            Some(_) => {
                self.map.remove(relay);
                None
            }
            None => None,
        }
    }

    fn insert(&mut self, relay: RelayRef, v: V) {
        let now = Instant::now();
        self.map
            .retain(|_, (_, used)| now.duration_since(*used) <= SESSION_IDLE);
        if !self.map.contains_key(&relay) && self.map.len() >= self.max {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, (_, u))| *u)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.map.remove(&k);
            }
        }
        self.map.insert(relay, (v, now));
    }

    fn remove(&mut self, relay: &RelayRef) {
        self.map.remove(relay);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// QUIC transport: one kept `Session` per relay (bounded), reopened when dead.
pub struct QuicWakeTransport {
    /// Tests only: skip the routable-address filter (local fake relay).
    allow_private: bool,
    sessions: Mutex<Kept<Arc<Session>>>,
}

impl QuicWakeTransport {
    pub fn new(allow_private: bool) -> QuicWakeTransport {
        QuicWakeTransport {
            allow_private,
            sessions: Mutex::new(Kept::new(MAX_KEPT_SESSIONS)),
        }
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, Kept<Arc<Session>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolves the relay and keeps only addresses worth connecting to.
    async fn addresses(&self, relay: &RelayRef) -> Result<Vec<SocketAddr>, WakeError> {
        // Bracketed IPv6 literals: the resolver wants the bare address.
        let host = relay
            .host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&relay.host);
        let found = tokio::net::lookup_host((host, relay.port))
            .await
            .map_err(|_| WakeError::Resolve)?;
        let addrs: Vec<SocketAddr> = found
            .filter(|a| wake_address_ok(a, self.allow_private))
            .take(MAX_ADDRS)
            .collect();
        if addrs.is_empty() {
            Err(WakeError::NoRoutableAddress)
        } else {
            Ok(addrs)
        }
    }

    /// Name resolution and connection, together bounded by `CONNECT_TIMEOUT`;
    /// the time left after resolution is shared between the addresses.
    async fn connect(&self, relay: &RelayRef) -> Result<Arc<Session>, WakeError> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let addrs = tokio::time::timeout_at(deadline, self.addresses(relay))
            .await
            .map_err(|_| WakeError::Resolve)??;
        let session = Arc::new(connect_any(&addrs, relay.id, deadline).await?);
        self.sessions().insert(relay.clone(), session.clone());
        Ok(session)
    }

    async fn request(session: &Session, items: Vec<Vec<u8>>) -> Result<(), WakeError> {
        match timeout(REQUEST_TIMEOUT, session.wake(items)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(WakeError::Request),
        }
    }
}

impl WakeTransport for QuicWakeTransport {
    async fn send(&self, relay: &RelayRef, items: Vec<Vec<u8>>) -> Result<(), WakeError> {
        let kept = self.sessions().get(relay);
        if let Some(session) = kept {
            // A session idle for a while is usually dead: when a kept session
            // fails, reconnect at once, so that the worker's single retry
            // is not spent on staleness.
            if session.connection().close_reason().is_none()
                && Self::request(&session, items.clone()).await.is_ok()
            {
                return Ok(());
            }
            self.sessions().remove(relay);
        }
        let session = self.connect(relay).await?;
        let r = Self::request(&session, items).await;
        if r.is_err() {
            self.sessions().remove(relay);
        }
        r
    }
}

/// Orders waiting per relay; a relay with an entry has a worker task.
#[derive(Default)]
struct Queues {
    /// Orders waiting or in flight, all relays.
    total: usize,
    per_relay: HashMap<RelayRef, VecDeque<Vec<u8>>>,
}

struct Inner<T> {
    transport: T,
    stats: Arc<ServerStats>,
    queues: Mutex<Queues>,
    /// Bounds the sends in progress (`MAX_CONCURRENT_RELAY_SENDS`).
    sends: Semaphore,
    /// Per-host share of the sends (`MAX_SENDS_PER_HOST`); an entry lives
    /// while a send to that host waits or runs.
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Relays that could not be reached, and until when they are skipped.
    backoff: Mutex<HashMap<RelayRef, Instant>>,
}

impl<T> Inner<T> {
    fn in_backoff(&self, relay: &RelayRef) -> bool {
        let mut b = self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
        match b.get(relay) {
            Some(until) if Instant::now() < *until => true,
            Some(_) => {
                b.remove(relay);
                false
            }
            None => false,
        }
    }

    fn start_backoff(&self, relay: &RelayRef) {
        let now = Instant::now();
        let mut b = self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
        b.retain(|_, until| now < *until);
        if !b.contains_key(relay) && b.len() >= MAX_BACKOFF_ENTRIES {
            let first = b.iter().min_by_key(|(_, u)| **u).map(|(k, _)| k.clone());
            if let Some(k) = first {
                b.remove(&k);
            }
        }
        b.insert(relay.clone(), now + RELAY_FAILURE_BACKOFF);
    }

    fn host_share(&self, relay: &RelayRef) -> Arc<Semaphore> {
        self.hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(relay.host.to_ascii_lowercase())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_SENDS_PER_HOST)))
            .clone()
    }

    /// Forgets the host entry once nobody waits on or holds it.
    fn release_host(&self, relay: &RelayRef, share: Arc<Semaphore>) {
        let host = relay.host.to_ascii_lowercase();
        let mut h = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        drop(share);
        if h.get(&host).is_some_and(|s| Arc::strong_count(s) == 1) {
            h.remove(&host);
        }
    }
}

/// Handle to the sender: enqueueing never blocks.
pub struct WakeSender<T: WakeTransport = QuicWakeTransport> {
    inner: Arc<Inner<T>>,
}

impl<T: WakeTransport> WakeSender<T> {
    /// Creates the sender. Workers (one per relay with pending orders) are
    /// spawned on the current Tokio runtime by `enqueue`.
    pub fn spawn(transport: T, stats: Arc<ServerStats>) -> WakeSender<T> {
        WakeSender {
            inner: Arc::new(Inner {
                transport,
                stats,
                queues: Mutex::new(Queues::default()),
                sends: Semaphore::new(MAX_CONCURRENT_RELAY_SENDS),
                hosts: Mutex::default(),
                backoff: Mutex::default(),
            }),
        }
    }

    /// Queues wake-ups. Beyond `WAKE_QUEUE` pending orders, the excess is
    /// lost and counted in `ServerStats::wake_dropped`.
    pub fn enqueue(&self, orders: Vec<WakeOrder>) {
        let mut dropped = 0u64;
        let mut start = Vec::new();
        {
            let mut q = self
                .inner
                .queues
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for o in orders {
                if q.total >= WAKE_QUEUE {
                    dropped += 1;
                    continue;
                }
                q.total += 1;
                match q.per_relay.get_mut(&o.relay) {
                    Some(items) => items.push_back(o.sealed),
                    None => {
                        start.push(o.relay.clone());
                        q.per_relay.insert(o.relay, VecDeque::from([o.sealed]));
                    }
                }
            }
        }
        if dropped > 0 {
            self.inner.stats.add_wake_dropped(dropped);
        }
        for relay in start {
            tokio::spawn(relay_worker(self.inner.clone(), relay));
        }
    }
}

/// One send attempt, holding a permit of its host's share, then a global
/// permit, only while it runs.
async fn send_bounded<T: WakeTransport>(
    inner: &Inner<T>,
    relay: &RelayRef,
    batch: Vec<Vec<u8>>,
) -> Result<(), WakeError> {
    let share = inner.host_share(relay);
    let result = async {
        // The semaphores are never closed.
        let _host = share.acquire().await.map_err(|_| WakeError::Connect)?;
        let _permit = inner
            .sends
            .acquire()
            .await
            .map_err(|_| WakeError::Connect)?;
        inner.transport.send(relay, batch).await
    }
    .await;
    inner.release_host(relay, share);
    result
}

/// Sends the batches of one relay until its queue is empty.
async fn relay_worker<T: WakeTransport>(inner: Arc<Inner<T>>, relay: RelayRef) {
    loop {
        let batch: Vec<Vec<u8>> = {
            let mut q = inner.queues.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(items) = q.per_relay.get_mut(&relay) else {
                return;
            };
            let n = items.len().min(MAX_WAKE_ITEMS);
            let batch: Vec<Vec<u8>> = items.drain(..n).collect();
            if batch.is_empty() {
                // Decided under the lock: a concurrent `enqueue` either sees
                // the entry (and the order is picked up) or creates a worker.
                q.per_relay.remove(&relay);
                return;
            }
            batch
        };
        let n = batch.len();
        if inner.in_backoff(&relay) {
            // Unreachable a moment ago: dropped without taking a permit.
            inner.stats.add_wake_failed(n as u64);
            let mut q = inner.queues.lock().unwrap_or_else(PoisonError::into_inner);
            q.total = q.total.saturating_sub(n);
            continue;
        }
        let mut result = send_bounded(&inner, &relay, batch.clone()).await;
        if matches!(result, Err(WakeError::Request)) {
            // The relay was reached: worth a single retry.
            tokio::time::sleep(WAKE_RETRY_DELAY).await;
            result = send_bounded(&inner, &relay, batch).await;
        }
        match result {
            Ok(()) => inner.stats.add_wake_sent(n as u64),
            Err(e) => {
                if !matches!(e, WakeError::Request) {
                    inner.start_backoff(&relay);
                }
                inner.stats.add_wake_failed(n as u64);
            }
        }
        {
            let mut q = inner.queues.lock().unwrap_or_else(PoisonError::into_inner);
            q.total = q.total.saturating_sub(n);
        }
        // Pace: n tokens at WAKES_PER_SEC_PER_RELAY per second.
        let pause = Duration::from_secs_f64(n as f64 / f64::from(WAKES_PER_SEC_PER_RELAY));
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use barking_proto::NodeId;
    use barking_proto::push::RelayRef;
    use tokio::time::Instant;

    use super::*;
    use crate::server::ServerStats;
    use crate::testing::FakeRelay;
    use crate::wake::WakeOrder;

    fn relay(host: &str) -> RelayRef {
        RelayRef {
            host: host.to_string(),
            port: 4433,
            id: NodeId([7; 32]),
        }
    }

    fn orders(r: &RelayRef, n: usize) -> Vec<WakeOrder> {
        (0..n)
            .map(|i| WakeOrder {
                relay: r.clone(),
                sealed: vec![u8::try_from(i % 256).unwrap(); 8],
            })
            .collect()
    }

    type Calls = Arc<Mutex<Vec<(Duration, RelayRef, usize)>>>;

    /// Records every call; fails the first `fail` calls; `block`: never answers.
    #[derive(Clone)]
    struct Fake {
        t0: Instant,
        calls: Calls,
        fail: Arc<AtomicUsize>,
        block: bool,
    }

    impl Fake {
        fn new(fail: usize, block: bool) -> Fake {
            Fake {
                t0: Instant::now(),
                calls: Arc::default(),
                fail: Arc::new(AtomicUsize::new(fail)),
                block,
            }
        }
    }

    impl WakeTransport for Fake {
        fn send(
            &self,
            relay: &RelayRef,
            items: Vec<Vec<u8>>,
        ) -> impl Future<Output = Result<(), WakeError>> + Send {
            let this = self.clone();
            let relay = relay.clone();
            async move {
                this.calls
                    .lock()
                    .unwrap()
                    .push((this.t0.elapsed(), relay, items.len()));
                if this.block {
                    std::future::pending::<()>().await;
                }
                let left = this.fail.load(Ordering::SeqCst);
                if left > 0 {
                    this.fail.store(left - 1, Ordering::SeqCst);
                    return Err(WakeError::Request);
                }
                Ok(())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn batches_of_100_per_relay() {
        let fake = Fake::new(0, false);
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake.clone(), stats.clone());
        let (a, b) = (relay("a.example"), relay("b.example"));
        sender.enqueue(orders(&a, 250));
        sender.enqueue(orders(&b, 30));
        tokio::time::sleep(Duration::from_secs(30)).await;
        let calls = fake.calls.lock().unwrap();
        let sizes = |r: &RelayRef| -> Vec<usize> {
            calls.iter().filter(|c| &c.1 == r).map(|c| c.2).collect()
        };
        assert_eq!(sizes(&a), vec![100, 100, 50]);
        assert_eq!(sizes(&b), vec![30]);
        assert_eq!(stats.wake_sent(), 280);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_is_50_per_second_per_relay() {
        let fake = Fake::new(0, false);
        let sender = WakeSender::spawn(fake.clone(), Arc::new(ServerStats::default()));
        sender.enqueue(orders(&relay("a.example"), 200));
        tokio::time::sleep(Duration::from_secs(30)).await;
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, Duration::ZERO, "one full batch goes at once");
        // Cumulative items sent by time t never exceed 50 * t + 100.
        let mut sent = 0;
        for (t, _, n) in calls.iter() {
            sent += n;
            assert!(
                sent as f64 <= 50.0 * t.as_secs_f64() + 100.0,
                "{sent} at {t:?}"
            );
        }
        assert!(calls[1].0 >= Duration::from_secs(2), "{:?}", calls[1].0);
    }

    #[tokio::test(start_paused = true)]
    async fn one_retry_then_drop() {
        let fake = Fake::new(2, false);
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake.clone(), stats.clone());
        sender.enqueue(orders(&relay("a.example"), 1));
        tokio::time::sleep(Duration::from_secs(30)).await;
        {
            let calls = fake.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert!(calls[1].0 - calls[0].0 >= WAKE_RETRY_DELAY);
        }
        assert_eq!((stats.wake_sent(), stats.wake_failed()), (0, 1));

        let fake = Fake::new(1, false);
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake.clone(), stats.clone());
        sender.enqueue(orders(&relay("a.example"), 1));
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(fake.calls.lock().unwrap().len(), 2);
        assert_eq!((stats.wake_sent(), stats.wake_failed()), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn full_queue_drops_and_counts() {
        let fake = Fake::new(0, true);
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake, stats.clone());
        sender.enqueue(orders(&relay("a.example"), WAKE_QUEUE + 5));
        assert_eq!(stats.wake_dropped(), 5);
        // Still full while the transport is blocked: everything more is lost.
        sender.enqueue(orders(&relay("b.example"), 3));
        assert_eq!(stats.wake_dropped(), 8);
    }

    #[tokio::test]
    async fn private_resolution_is_dropped() {
        let t = QuicWakeTransport::new(false);
        // `127.1` and `0x7f.1` are non-canonical spellings that pass the
        // syntax check; the resolver maps them to loopback.
        for host in ["localhost", "127.1"] {
            let r = relay(host);
            assert!(r.well_formed() || host == "localhost");
            let err = t.send(&r, vec![vec![1; 8]]).await.unwrap_err();
            assert!(
                matches!(err, WakeError::NoRoutableAddress),
                "{host}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn quic_transport_reaches_fake_relay() {
        let relay = FakeRelay::start().await;
        let t = QuicWakeTransport::new(true);
        let items = vec![vec![1u8; 8], vec![2u8; 8]];
        t.send(&relay.relay_ref(), items.clone()).await.unwrap();
        // The session is reused for a second batch.
        t.send(&relay.relay_ref(), vec![vec![3u8; 8]])
            .await
            .unwrap();
        let got = relay.received();
        assert_eq!(got, vec![vec![1u8; 8], vec![2u8; 8], vec![3u8; 8]]);
        relay.stop();
    }

    #[tokio::test]
    async fn dead_kept_session_reconnects_without_retry() {
        let relay = FakeRelay::start().await;
        let t = QuicWakeTransport::new(true);
        t.send(&relay.relay_ref(), vec![vec![1u8; 8]])
            .await
            .unwrap();
        relay.close_connections();
        let t0 = std::time::Instant::now();
        // First attempt (no worker retry involved) must succeed at once.
        t.send(&relay.relay_ref(), vec![vec![2u8; 8]])
            .await
            .unwrap();
        assert!(t0.elapsed() < WAKE_RETRY_DELAY);
        assert_eq!(relay.received(), vec![vec![1u8; 8], vec![2u8; 8]]);
        relay.stop();
    }

    #[tokio::test]
    async fn dead_session_through_sender_counts_no_failure() {
        let relay = FakeRelay::start().await;
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(QuicWakeTransport::new(true), stats.clone());
        let r = relay.relay_ref();
        sender.enqueue(orders(&r, 1));
        while stats.wake_sent() < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        relay.close_connections();
        sender.enqueue(orders(&r, 1));
        let t0 = std::time::Instant::now();
        while stats.wake_sent() < 2 {
            assert!(t0.elapsed() < WAKE_RETRY_DELAY, "delayed like a retry");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(stats.wake_failed(), 0);
        relay.stop();
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_sends_are_capped() {
        #[derive(Clone, Default)]
        struct Slow {
            now: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }
        impl WakeTransport for Slow {
            async fn send(&self, _: &RelayRef, _: Vec<Vec<u8>>) -> Result<(), WakeError> {
                let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.now.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        }
        let slow = Slow::default();
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(slow.clone(), stats.clone());
        for i in 0..200 {
            sender.enqueue(orders(&relay(&format!("r{i}.example")), 1));
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(stats.wake_sent(), 200);
        let peak = slow.peak.load(Ordering::SeqCst);
        assert!(peak <= MAX_CONCURRENT_RELAY_SENDS, "{peak}");
        assert!(peak > 1);
    }

    /// Hosts starting with `dead` behave as blackholed relays: each attempt
    /// hangs for `CONNECT_TIMEOUT`, then fails to connect. Others answer.
    #[derive(Clone)]
    struct Blackholes {
        t0: Instant,
        calls: Calls,
    }

    impl Blackholes {
        fn new() -> Blackholes {
            Blackholes {
                t0: Instant::now(),
                calls: Arc::default(),
            }
        }

        fn calls_to(&self, host: &str) -> Vec<Duration> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.1.host == host)
                .map(|c| c.0)
                .collect()
        }
    }

    impl WakeTransport for Blackholes {
        async fn send(&self, relay: &RelayRef, items: Vec<Vec<u8>>) -> Result<(), WakeError> {
            self.calls
                .lock()
                .unwrap()
                .push((self.t0.elapsed(), relay.clone(), items.len()));
            if relay.host.starts_with("dead") {
                tokio::time::sleep(CONNECT_TIMEOUT).await;
                return Err(WakeError::Connect);
            }
            Ok(())
        }
    }

    fn relay_with_id(host: &str, id: u8) -> RelayRef {
        RelayRef {
            id: NodeId([id; 32]),
            ..relay(host)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blackholed_relays_do_not_delay_a_healthy_one() {
        let fake = Blackholes::new();
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake.clone(), stats.clone());
        // 100 relays on one blackholed host (distinct ids), queued first.
        for i in 0..100u8 {
            sender.enqueue(orders(&relay_with_id("dead.example", i), 1));
        }
        sender.enqueue(orders(&relay("a.example"), 1));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.calls_to("a.example"), vec![Duration::ZERO]);
        assert_eq!(stats.wake_sent(), 1);
        // A host never holds more than its share of the permits.
        let dead_now = fake.calls_to("dead.example").len();
        assert!(dead_now <= MAX_SENDS_PER_HOST, "{dead_now}");
    }

    #[tokio::test(start_paused = true)]
    async fn failed_connect_backs_off_without_retry() {
        let fake = Blackholes::new();
        let stats = Arc::new(ServerStats::default());
        let sender = WakeSender::spawn(fake.clone(), stats.clone());
        let dead = relay("dead.example");
        sender.enqueue(orders(&dead, 1));
        tokio::time::sleep(Duration::from_secs(60)).await;
        // No retry after a connection failure.
        assert_eq!(fake.calls_to("dead.example").len(), 1);
        assert_eq!(stats.wake_failed(), 1);
        // During the backoff, orders are dropped without an attempt.
        sender.enqueue(orders(&dead, 3));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.calls_to("dead.example").len(), 1);
        assert_eq!(stats.wake_failed(), 4);
        // Once the backoff has expired, the relay is tried again.
        tokio::time::sleep(RELAY_FAILURE_BACKOFF).await;
        sender.enqueue(orders(&dead, 1));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.calls_to("dead.example").len(), 2);
    }

    #[tokio::test]
    async fn blackholed_first_address_does_not_block_the_next() {
        let relay = FakeRelay::start().await;
        // A UDP socket that never answers.
        let hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let r = relay.relay_ref();
        let addrs = vec![
            hole.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], r.port)),
        ];
        let t0 = std::time::Instant::now();
        let budget = Duration::from_secs(4);
        let session = connect_any(&addrs, r.id, tokio::time::Instant::now() + budget).await;
        assert!(session.is_ok(), "the second address was not tried");
        assert!(t0.elapsed() < budget);
        relay.stop();
    }

    #[test]
    fn ipv4_in_ipv6_relay_addresses_are_refused() {
        let ok = |s: &str, allow_private: bool| wake_address_ok(&s.parse().unwrap(), allow_private);
        for a in [
            "[::ffff:8.8.8.8]:4433",
            "[::8.8.8.8]:4433",
            "[64:ff9b::808:808]:4433",
            "[2002:808:808::1]:4433",
            "[2001:0:808:808::1]:4433",
        ] {
            assert!(!ok(a, false), "{a}");
            // Refused even when private addresses are allowed (tests).
            assert!(!ok(a, true), "{a}");
        }
        assert!(ok("8.8.8.8:4433", false));
        assert!(ok("[2606:4700::1111]:4433", false));
        assert!(!ok("127.0.0.1:4433", false));
        assert!(ok("127.0.0.1:4433", true));
        assert!(ok("[::1]:4433", true));
    }

    #[test]
    fn kept_sessions_are_bounded_and_lru() {
        let mut k: Kept<usize> = Kept::new(MAX_KEPT_SESSIONS);
        for i in 0..(MAX_KEPT_SESSIONS * 3) {
            k.insert(relay(&format!("r{i}.example")), i);
            assert!(k.len() <= MAX_KEPT_SESSIONS);
        }
        // Oldest evicted, newest kept.
        assert_eq!(k.get(&relay("r0.example")), None);
        let last = MAX_KEPT_SESSIONS * 3 - 1;
        assert_eq!(k.get(&relay(&format!("r{last}.example"))), Some(last));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_kept_session_is_dropped() {
        let mut k: Kept<u8> = Kept::new(4);
        k.insert(relay("a.example"), 1);
        tokio::time::sleep(SESSION_IDLE + Duration::from_secs(1)).await;
        assert_eq!(k.get(&relay("a.example")), None);
    }
}
