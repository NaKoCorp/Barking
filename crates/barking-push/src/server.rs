//! QUIC server of the relay: `Hello`, then `Wake`; everything else is
//! `Unsupported`. Stateless apart from the in-memory connection counters and
//! the token limiter. No address, node, token or mailbox is logged.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::push::{WakeToken, open};
use barking_proto::{
    ErrorReason, Limits, MAX_WAKE_ITEMS, NodeId, PROTOCOL_VERSION, Request, Response, tls,
    versions_overlap,
};
use ed25519_dalek::SigningKey;
use quinn::{Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::limit::TokenLimiter;
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
    inflight: Arc<Semaphore>,
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
    let shared = Arc::new(Shared {
        node_id,
        keys,
        pusher,
        stats,
        limiter: Mutex::new(TokenLimiter::new()),
        inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_PUSHES)),
    });
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
    // The transport limits the open streams to MAX_STREAMS; the idle timeout
    // ends a silent connection.
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(stream(send, recv, shared.clone()));
    }
}

async fn stream<P: Pusher>(mut send: SendStream, mut recv: RecvStream, shared: Arc<Shared<P>>) {
    let req = timeout(
        STREAM_TIMEOUT,
        frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES),
    )
    .await;
    let resp = match req {
        Ok(Ok(req)) => handle(req, &shared),
        Ok(Err(FrameError::Malformed)) => Response::Error(ErrorReason::Malformed),
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
}

fn handle<P: Pusher>(req: Request, shared: &Arc<Shared<P>>) -> Response {
    match req {
        Request::Hello {
            version,
            min_version,
        } => {
            if min_version > version
                || !versions_overlap(min_version, version, PROTOCOL_VERSION, PROTOCOL_VERSION)
            {
                return Response::Error(ErrorReason::VersionTooOld);
            }
            Response::Hello {
                version: PROTOCOL_VERSION,
                min_version: PROTOCOL_VERSION,
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
                return Response::Error(ErrorReason::Malformed);
            }
            let day = today();
            for item in &items {
                wake_item(item, day, shared);
            }
            // Always `Ok`: nothing about a device is revealed to the node.
            Response::Ok
        }
        _ => Response::Error(ErrorReason::Unsupported),
    }
}

/// Opens, checks and limits one item, then spawns its push (not awaited: the
/// response to `Wake` does not wait for APNs).
fn wake_item<P: Pusher>(item: &[u8], day: u64, shared: &Arc<Shared<P>>) {
    let stats = &shared.stats;
    stats.wakes_in.fetch_add(1, Relaxed);
    let Some(token) = open(&shared.keys, item) else {
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
        let outcome = timeout(PUSH_TIMEOUT, shared.pusher.push(token))
            .await
            .unwrap_or(PushOutcome::Failed(0));
        drop(permit);
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
