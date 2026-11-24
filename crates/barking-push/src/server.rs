//! QUIC server of the relay: `Hello`, then `Wake`; everything else is
//! `Unsupported`. Stateless apart from the in-memory connection counters and
//! the token limiter. No address, node, token or mailbox is logged.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_proto::client::MIN_PROTOCOL_VERSION;
use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::push::{ApnsEnv, WakeToken, open};
use barking_proto::{
    ErrorReason, Limits, MAX_WAKE_ITEMS, NodeId, PROTOCOL_VERSION, Request, Response, tls,
    versions_overlap,
};
use ed25519_dalek::SigningKey;
use quinn::{Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::health::{ApnsHealth, PROBE_EVERY};
use crate::limit::{IntakeBudget, TokenLimiter};
use crate::stats::RelayStats;

/// Idle connections are closed after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Concurrent bidirectional streams per connection.
pub const MAX_STREAMS: u32 = 4;
/// Pushes in flight at once.
pub const MAX_INFLIGHT_PUSHES: usize = 256;
/// QUIC and TLS handshake budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A push that takes longer is abandoned and counted as failed.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(30);
/// Time to read a request, then to deliver the response.
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// Application close code of a stopped endpoint.
const CLOSE_STOP: u32 = 0;
const STREAM_REFUSED: u32 = 1;
/// Application close code of a connection refused while APNs fails.
const CLOSE_UNAVAILABLE: u32 = 2;

/// Result of one push to APNs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Sent,
    /// APNs says the device token is no longer valid (HTTP 410).
    Unregistered,
    /// Any other failure: the HTTP status, or 0 if there was none.
    Failed(u16),
}

/// Delivers one wake-up to a device.
pub trait Pusher: Send + Sync + 'static {
    fn push(&self, token: WakeToken) -> impl Future<Output = PushOutcome> + Send;
    /// Checks that APNs accepts this relay's requests in `env`, without
    /// reaching any device: answered like `push`.
    fn probe(&self, env: ApnsEnv) -> impl Future<Output = PushOutcome> + Send;
}

/// Connection caps. Peers are counted per IPv4 address and per IPv6 /64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnLimits {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            max_connections: 10_000,
            max_connections_per_ip: 16,
        }
    }
}

/// Binds one QUIC endpoint per listen address (`host:port`, no name
/// resolution), with the relay identity and transport limits.
pub fn bind(listen: &[String], key: &SigningKey) -> std::io::Result<Vec<Endpoint>> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(MAX_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(
            IDLE_TIMEOUT.try_into().expect("60 s fits an idle timeout"),
        ));
    let transport = Arc::new(transport);
    let mut endpoints = Vec::with_capacity(listen.len());
    for addr in listen {
        let addr: SocketAddr = addr.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid listen address")
        })?;
        let mut cfg = tls::quinn_server_config(key);
        cfg.transport_config(transport.clone());
        cfg.migration(false);
        endpoints.push(Endpoint::server(cfg, addr)?);
    }
    Ok(endpoints)
}

/// Connection counters, global and per address group.
struct Conns {
    limits: ConnLimits,
    state: Mutex<ConnState>,
}

#[derive(Default)]
struct ConnState {
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

/// A connection slot, released on drop.
struct Slot {
    conns: Arc<Conns>,
    ip: IpAddr,
}

impl Conns {
    fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Option<Slot> {
        let ip = group(peer);
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.total >= self.limits.max_connections {
            return None;
        }
        let n = st.per_ip.entry(ip).or_insert(0);
        if *n >= self.limits.max_connections_per_ip {
            return None;
        }
        *n += 1;
        st.total += 1;
        Some(Slot {
            conns: self.clone(),
            ip,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self
            .conns
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        st.total = st.total.saturating_sub(1);
        if let Some(n) = st.per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                st.per_ip.remove(&self.ip);
            }
        }
    }
}

/// Address group of a peer: IPv4 as is (IPv4-mapped IPv6 unwrapped), IPv6 by
/// its /64.
fn group(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        v4 => v4,
    }
}

struct Shared<P> {
    node_id: NodeId,
    keys: Vec<(u8, StaticSecret)>,
    pusher: Arc<P>,
    stats: Arc<RelayStats>,
    limiter: Mutex<TokenLimiter>,
    intake: Mutex<IntakeBudget>,
    inflight: Arc<Semaphore>,
    /// APNs health; `stats.unavailable` mirrors its last announced state and
    /// is only changed under this lock, so each transition is logged once.
    health: Mutex<ApnsHealth>,
}

impl<P> Shared<P> {
    /// Records one APNs outcome (push or probe) for `env`.
    fn record(&self, o: PushOutcome, env: ApnsEnv) {
        let now = Instant::now();
        let mut h = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        h.record(o, env, now);
        self.announce(h.available(now));
    }

    /// Whether the relay serves; a time-based transition is noticed here.
    fn available(&self) -> bool {
        let h = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let available = h.available(Instant::now());
        self.announce(available);
        available
    }

    /// Logs a change of state. Called with `health` locked.
    fn announce(&self, available: bool) {
        let was_unavailable = self.stats.unavailable.swap(!available, Relaxed);
        if was_unavailable == available {
            if available {
                tracing::info!("relay available again");
            } else {
                tracing::warn!("relay unavailable: APNs failing");
            }
        }
    }
}

/// Day number since the Unix epoch.
fn day_of(unix_secs: u64) -> u64 {
    unix_secs / 86_400
}

fn today() -> u64 {
    day_of(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// Serves `endpoints` until `stop` turns true (or its sender is dropped), then
/// closes them. `node_id` is the identity of the key the endpoints were bound
/// with.
pub async fn serve<P: Pusher>(
    endpoints: Vec<Endpoint>,
    node_id: NodeId,
    keys: Vec<(u8, StaticSecret)>,
    pusher: Arc<P>,
    stats: Arc<RelayStats>,
    limits: ConnLimits,
    stop: watch::Receiver<bool>,
) {
    serve_inner(
        endpoints,
        node_id,
        keys,
        pusher,
        stats,
        limits,
        stop,
        PROBE_EVERY,
    )
    .await;
}

/// `serve` with the probe interval as a parameter (shorter in tests).
#[allow(clippy::too_many_arguments)]
async fn serve_inner<P: Pusher>(
    endpoints: Vec<Endpoint>,
    node_id: NodeId,
    keys: Vec<(u8, StaticSecret)>,
    pusher: Arc<P>,
    stats: Arc<RelayStats>,
    limits: ConnLimits,
    stop: watch::Receiver<bool>,
    probe_every: Duration,
) {
    stats.unavailable.store(false, Relaxed);
    let shared = Arc::new(Shared {
        node_id,
        keys,
        pusher,
        stats,
        limiter: Mutex::new(TokenLimiter::new()),
        intake: Mutex::new(IntakeBudget::new()),
        inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_PUSHES)),
        health: Mutex::new(ApnsHealth::new(Instant::now())),
    });
    let prober = tokio::spawn(probe_loop(shared.clone(), probe_every, stop.clone()));
    let conns = Arc::new(Conns {
        limits,
        state: Mutex::default(),
    });
    let mut loops = Vec::new();
    for ep in endpoints {
        loops.push(tokio::spawn(accept_loop(
            ep,
            shared.clone(),
            conns.clone(),
            stop.clone(),
        )));
    }
    for l in loops {
        let _ = l.await;
    }
    let _ = prober.await;
}

/// While the relay is unavailable, probes APNs every `every` in the
/// environment of the last fault; a probe that is not a relay fault puts
/// the relay back in service.
async fn probe_loop<P: Pusher>(
    shared: Arc<Shared<P>>,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // first tick is immediate
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    return;
                }
                continue;
            }
        }
        if shared.available() {
            continue;
        }
        let env = shared
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .probe_env();
        // Abandoned on stop, so that `serve` does not wait for APNs.
        let outcome = tokio::select! {
            o = timeout(PUSH_TIMEOUT, shared.pusher.probe(env)) => {
                o.unwrap_or(PushOutcome::Failed(0))
            }
            _ = stop.wait_for(|s| *s) => return,
        };
        shared.record(outcome, env);
    }
}

async fn accept_loop<P: Pusher>(
    ep: Endpoint,
    shared: Arc<Shared<P>>,
    conns: Arc<Conns>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            incoming = ep.accept() => {
                let Some(incoming) = incoming else { return };
                // The source address of an Initial can be spoofed: before
                // counting anything against it, the client must prove it
                // (stateless Retry token), as barking-node does.
                if !incoming.remote_address_validated() {
                    if incoming.may_retry() {
                        let _ = incoming.retry();
                    } else {
                        incoming.ignore();
                    }
                    continue;
                }
                // A relay whose APNs sends fail steps aside: nodes move on
                // to another replica when the connection is refused.
                if !shared.available() {
                    incoming.refuse();
                    continue;
                }
                // Refused before any handshake work if a cap is reached.
                let Some(slot) = conns.try_acquire(incoming.remote_address().ip()) else {
                    incoming.refuse();
                    continue;
                };
                tokio::spawn(connection(incoming, shared.clone(), slot));
            }
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    ep.close(CLOSE_STOP.into(), b"stop");
                    return;
                }
            }
        }
    }
}

async fn connection<P: Pusher>(incoming: Incoming, shared: Arc<Shared<P>>, _slot: Slot) {
    let Ok(Ok(conn)) = timeout(HANDSHAKE_TIMEOUT, async { incoming.accept()?.await }).await else {
        return;
    };
    let peer = group(conn.remote_address().ip());
    // The transport limits the open streams to MAX_STREAMS; the idle timeout
    // ends a silent connection.
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(stream(send, recv, peer, conn.clone(), shared.clone()));
    }
}

async fn stream<P: Pusher>(
    mut send: SendStream,
    mut recv: RecvStream,
    peer: IpAddr,
    conn: quinn::Connection,
    shared: Arc<Shared<P>>,
) {
    let req = timeout(
        STREAM_TIMEOUT,
        frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES),
    )
    .await;
    let (resp, close) = match req {
        Ok(Ok(req)) => handle(req, peer, &shared).await,
        Ok(Err(FrameError::Malformed)) => (Response::Error(ErrorReason::Malformed), false),
        Ok(Err(_)) | Err(_) => {
            let _ = recv.stop(STREAM_REFUSED.into());
            let _ = send.reset(STREAM_REFUSED.into());
            return;
        }
    };
    let bytes = frame::encode(&resp, MAX_RESPONSE_BYTES).unwrap_or_default();
    // Waits for the acknowledgement so that the response precedes any close.
    let sent = timeout(STREAM_TIMEOUT, async {
        send.write_all(&bytes).await.ok()?;
        send.finish().ok()?;
        send.stopped().await.ok()
    })
    .await;
    if !matches!(sent, Ok(Some(None))) {
        let _ = send.reset(STREAM_REFUSED.into());
    }
    if close {
        conn.close(CLOSE_UNAVAILABLE.into(), b"unavailable");
    }
}

/// The response, and whether to close the connection once it is delivered.
async fn handle<P: Pusher>(
    req: Request,
    peer: IpAddr,
    shared: &Arc<Shared<P>>,
) -> (Response, bool) {
    let resp = match req {
        Request::Hello {
            version,
            min_version,
        } => {
            if min_version > version
                || !versions_overlap(min_version, version, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION)
            {
                return (Response::Error(ErrorReason::VersionTooOld), false);
            }
            Response::Hello {
                version: PROTOCOL_VERSION,
                min_version: MIN_PROTOCOL_VERSION,
                node_id: shared.node_id,
                pow_bits: 0,
                limits: Limits {
                    max_mailboxes_per_fetch: 1,
                    max_request_bytes: MAX_REQUEST_BYTES as u32,
                    max_response_bytes: MAX_RESPONSE_BYTES as u32,
                    wake: false,
                },
            }
        }
        Request::Wake { items } => {
            if items.len() > MAX_WAKE_ITEMS {
                return (Response::Error(ErrorReason::Malformed), false);
            }
            if !shared.available() {
                // Refused unopened; an updated node reroutes on an error,
                // an older one when its next connection is refused.
                shared
                    .stats
                    .refused_unavailable
                    .fetch_add(items.len() as u64, Relaxed);
                return (Response::Error(ErrorReason::NodeFull), true);
            }
            wake(items, peer, shared).await;
            // Always `Ok`: nothing about a device is revealed to the node.
            Response::Ok
        }
        _ => Response::Error(ErrorReason::Unsupported),
    };
    (resp, false)
}

/// Takes the peer's intake budget before any decryption, opens the granted
/// items off the async workers, then checks and limits each one.
async fn wake<P: Pusher>(mut items: Vec<Vec<u8>>, peer: IpAddr, shared: &Arc<Shared<P>>) {
    let stats = &shared.stats;
    let n = items.len();
    stats.wakes_in.fetch_add(n as u64, Relaxed);
    let granted = shared
        .intake
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take(peer, u32::try_from(n).unwrap_or(u32::MAX), Instant::now());
    let granted = usize::try_from(granted).map_or(n, |g| g.min(n));
    stats.over_budget.fetch_add((n - granted) as u64, Relaxed);
    items.truncate(granted);
    if items.is_empty() {
        return;
    }
    let opener = shared.clone();
    let Ok(opened) = tokio::task::spawn_blocking(move || {
        items
            .iter()
            .map(|item| open(&opener.keys, item))
            .collect::<Vec<_>>()
    })
    .await
    else {
        stats.invalid.fetch_add(granted as u64, Relaxed);
        return;
    };
    let day = today();
    for token in opened {
        wake_item(token, day, shared);
    }
}

/// Checks and limits one opened item, then spawns its push (not awaited: the
/// response to `Wake` does not wait for APNs).
fn wake_item<P: Pusher>(token: Option<WakeToken>, day: u64, shared: &Arc<Shared<P>>) {
    let stats = &shared.stats;
    let Some(token) = token else {
        stats.invalid.fetch_add(1, Relaxed);
        return;
    };
    if u64::from(token.expires_day) < day {
        stats.expired.fetch_add(1, Relaxed);
        return;
    }
    // Permit first: an item shed for lack of one does not spend the
    // device's quota.
    let Ok(permit) = shared.inflight.clone().try_acquire_owned() else {
        stats.shed.fetch_add(1, Relaxed);
        return;
    };
    let allowed = shared
        .limiter
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .allow(&token.apns_token, Instant::now());
    if !allowed {
        stats.limited.fetch_add(1, Relaxed);
        return;
    }
    let shared = shared.clone();
    tokio::spawn(async move {
        let env = token.env;
        let outcome = timeout(PUSH_TIMEOUT, shared.pusher.push(token))
            .await
            .unwrap_or(PushOutcome::Failed(0));
        drop(permit);
        shared.record(outcome, env);
        match outcome {
            PushOutcome::Sent => shared.stats.sent.fetch_add(1, Relaxed),
            PushOutcome::Unregistered => shared.stats.unregistered.fetch_add(1, Relaxed),
            PushOutcome::Failed(code) => {
                shared.stats.record_failure(code);
                0
            }
        };
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU16, AtomicUsize};

    use barking_proto::client::{Client, ClientError};
    use barking_proto::push::{WakeReason, seal};
    use x25519_dalek::PublicKey;

    use super::*;

    /// A key that solves the node puzzle (as in `tests/relay.rs`).
    const SEED: [u8; 32] = [
        66, 125, 129, 83, 32, 106, 225, 91, 180, 232, 72, 26, 247, 131, 101, 82, 217, 244, 181, 75,
        156, 236, 14, 63, 198, 19, 50, 80, 99, 40, 172, 214,
    ];
    const PROBE_TEST_EVERY: Duration = Duration::from_millis(50);
    const WAIT: Duration = Duration::from_secs(10);

    /// Every push fails with 403 (bad credentials on the relay side); the
    /// probe answers `probe_code`, switchable during the test.
    struct Failing {
        pushes: AtomicUsize,
        probes: Mutex<Vec<ApnsEnv>>,
        probe_code: AtomicU16,
    }

    impl Failing {
        fn new(probe_code: u16) -> Arc<Self> {
            Arc::new(Failing {
                pushes: AtomicUsize::new(0),
                probes: Mutex::default(),
                probe_code: AtomicU16::new(probe_code),
            })
        }
    }

    impl Pusher for Failing {
        async fn push(&self, _token: WakeToken) -> PushOutcome {
            self.pushes.fetch_add(1, Relaxed);
            PushOutcome::Failed(403)
        }
        async fn probe(&self, env: ApnsEnv) -> PushOutcome {
            self.probes.lock().unwrap().push(env);
            PushOutcome::Failed(self.probe_code.load(Relaxed))
        }
    }

    struct Relay {
        addr: SocketAddr,
        id: NodeId,
        stats: Arc<RelayStats>,
        secret: StaticSecret,
        stop: watch::Sender<bool>,
    }

    fn start(pusher: Arc<Failing>) -> Relay {
        let key = SigningKey::from_bytes(&SEED);
        let id = NodeId::from_public_key(&key.verifying_key());
        let endpoints = bind(&["127.0.0.1:0".to_string()], &key).unwrap();
        let addr = endpoints[0].local_addr().unwrap();
        let secret = StaticSecret::from([7u8; 32]);
        let stats = Arc::new(RelayStats::default());
        let (stop, rx) = watch::channel(false);
        tokio::spawn(serve_inner(
            endpoints,
            id,
            vec![(3, secret.clone())],
            pusher,
            stats.clone(),
            ConnLimits::default(),
            rx,
            PROBE_TEST_EVERY,
        ));
        Relay {
            addr,
            id,
            stats,
            secret,
            stop,
        }
    }

    fn token(byte: u8, expires_day: u64) -> WakeToken {
        WakeToken {
            apns_token: vec![byte; 32],
            env: ApnsEnv::Sandbox,
            collapse: [byte; 16],
            expires_day: u32::try_from(expires_day).unwrap(),
            reason: WakeReason::Message,
        }
    }

    impl Relay {
        fn sealed(&self, t: &WakeToken) -> Vec<u8> {
            seal(
                PublicKey::from(&self.secret).as_bytes(),
                3,
                t,
                &mut rand::rng(),
            )
        }

        /// Five pushes failing on the relay side, one `Wake` each, then waits
        /// for the relay to step aside.
        async fn fail_five(&self, session: &barking_proto::client::Session) {
            for b in 1..=5u8 {
                session
                    .wake(vec![self.sealed(&token(b, today() + 1))])
                    .await
                    .unwrap();
            }
            let deadline = tokio::time::Instant::now() + WAIT;
            while !self.stats.unavailable.load(Relaxed) {
                assert!(tokio::time::Instant::now() < deadline, "never unavailable");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    #[tokio::test]
    async fn unavailable_relay_answers_node_full_unopened() {
        let pusher = Failing::new(403);
        let relay = start(pusher.clone());
        let session = Client::connect(relay.addr, relay.id).await.unwrap();
        relay.fail_five(&session).await;
        assert_eq!(relay.stats.snapshot().wakes_in, 5);

        let err = session
            .wake(vec![relay.sealed(&token(6, today() + 1))])
            .await
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Refused(ErrorReason::NodeFull)),
            "{err:?}"
        );
        let s = relay.stats.snapshot();
        assert_eq!((s.wakes_in, s.refused_unavailable), (5, 1));
        assert_eq!(pusher.pushes.load(Relaxed), 5);
        // The connection is closed after the response.
        timeout(WAIT, session.connection().closed())
            .await
            .expect("connection closed after NodeFull");
        let _ = relay.stop.send(true);
    }

    #[tokio::test]
    async fn unavailable_relay_refuses_new_connections() {
        let relay = start(Failing::new(403));
        let session = Client::connect(relay.addr, relay.id).await.unwrap();
        relay.fail_five(&session).await;
        let r = timeout(WAIT, Client::connect(relay.addr, relay.id))
            .await
            .expect("refused promptly");
        assert!(r.is_err(), "connection accepted while unavailable");
        let _ = relay.stop.send(true);
    }

    #[tokio::test]
    async fn successful_probe_restores_service() {
        let pusher = Failing::new(403);
        let relay = start(pusher.clone());
        let session = Client::connect(relay.addr, relay.id).await.unwrap();
        relay.fail_five(&session).await;
        // Failing probes keep it aside.
        tokio::time::sleep(PROBE_TEST_EVERY * 4).await;
        assert!(relay.stats.unavailable.load(Relaxed));
        assert!(!pusher.probes.lock().unwrap().is_empty());
        assert!(
            pusher
                .probes
                .lock()
                .unwrap()
                .iter()
                .all(|e| *e == ApnsEnv::Sandbox)
        );
        // APNs now answers BadDeviceToken: credentials are fine again.
        pusher.probe_code.store(400, Relaxed);
        let deadline = tokio::time::Instant::now() + WAIT;
        let session = loop {
            if let Ok(s) = Client::connect(relay.addr, relay.id).await {
                break s;
            }
            assert!(tokio::time::Instant::now() < deadline, "never restored");
            tokio::time::sleep(PROBE_TEST_EVERY).await;
        };
        assert!(!relay.stats.unavailable.load(Relaxed));
        session
            .wake(vec![relay.sealed(&token(7, today() + 1))])
            .await
            .unwrap();
        let _ = relay.stop.send(true);
    }

    #[tokio::test]
    async fn wake_after_switch_is_refused_unopened() {
        let pusher = Failing::new(403);
        let relay = start(pusher.clone());
        let session = Client::connect(relay.addr, relay.id).await.unwrap();
        relay.fail_five(&session).await;
        let before = relay.stats.snapshot();
        // Would count as invalid and expired if opened.
        let garbage = vec![0xAB; 50];
        let expired = relay.sealed(&token(8, today() - 1));
        let err = session.wake(vec![garbage, expired]).await.unwrap_err();
        assert!(
            matches!(err, ClientError::Refused(ErrorReason::NodeFull)),
            "{err:?}"
        );
        let after = relay.stats.snapshot();
        assert_eq!(
            (after.wakes_in, after.invalid, after.expired),
            (before.wakes_in, before.invalid, before.expired)
        );
        assert_eq!(after.refused_unavailable, 2);
        assert_eq!(pusher.pushes.load(Relaxed), 5);
        let _ = relay.stop.send(true);
    }
}
