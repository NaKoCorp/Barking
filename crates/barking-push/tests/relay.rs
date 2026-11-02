//! Relay integration tests: real QUIC on 127.0.0.1, a recording `Pusher`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_proto::client::{Client, ClientError};
use barking_proto::push::{ApnsEnv, WakeToken, seal};
use barking_proto::{ErrorReason, MAX_WAKE_ITEMS, NodeId, Request, Response};
use barking_push::{ConnLimits, PushOutcome, Pusher, RelayStats, bind, serve};
use ed25519_dalek::SigningKey;
use tokio::sync::{Notify, watch};
use x25519_dalek::{PublicKey, StaticSecret};

/// A key that solves the node puzzle (first key of the node test harness).
const SEED: [u8; 32] = [
    66, 125, 129, 83, 32, 106, 225, 91, 180, 232, 72, 26, 247, 131, 101, 82, 217, 244, 181, 75,
    156, 236, 14, 63, 198, 19, 50, 80, 99, 40, 172, 214,
];

#[derive(Default)]
struct Recorder {
    got: Mutex<Vec<WakeToken>>,
    notify: Notify,
}

impl Pusher for Recorder {
    async fn push(&self, token: WakeToken) -> PushOutcome {
        self.got.lock().unwrap().push(token);
        self.notify.notify_waiters();
        PushOutcome::Sent
    }
}

struct Relay {
    addr: std::net::SocketAddr,
    id: NodeId,
    pusher: Arc<Recorder>,
    stats: Arc<RelayStats>,
    secret: StaticSecret,
    stop: watch::Sender<bool>,
}

fn today() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    u32::try_from(secs / 86_400).unwrap()
}

fn token(byte: u8, expires_day: u32) -> WakeToken {
    WakeToken {
        apns_token: vec![byte; 32],
        env: ApnsEnv::Sandbox,
        collapse: [byte; 16],
        expires_day,
    }
}

async fn start(limits: ConnLimits) -> Relay {
    let pusher = Arc::new(Recorder::default());
    start_with(limits, pusher.clone(), pusher).await
}

/// Relay served by `served`; `recorder` is what `Relay::pusher` exposes.
async fn start_with<P: Pusher>(
    limits: ConnLimits,
    served: Arc<P>,
    recorder: Arc<Recorder>,
) -> Relay {
    let key = SigningKey::from_bytes(&SEED);
    let id = NodeId::from_public_key(&key.verifying_key());
    let endpoints = bind(&["127.0.0.1:0".to_string()], &key).unwrap();
    let addr = endpoints[0].local_addr().unwrap();
    let secret = StaticSecret::from([7u8; 32]);
    let pusher = recorder;
    let stats = Arc::new(RelayStats::default());
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(
        endpoints,
        id,
        vec![(3, secret.clone())],
        served,
        stats.clone(),
        limits,
        rx,
    ));
    Relay {
        addr,
        id,
        pusher,
        stats,
        secret,
        stop,
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

    async fn wait_pushed(&self, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.pusher.got.lock().unwrap().len() < n {
            assert!(tokio::time::Instant::now() < deadline, "push not received");
            let _ = tokio::time::timeout(Duration::from_millis(50), self.pusher.notify.notified())
                .await;
        }
    }
}

#[tokio::test]
async fn valid_wake_reaches_pusher() {
    let relay = start(ConnLimits::default()).await;
    let t = token(1, today() + 1);
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    session.wake(vec![relay.sealed(&t)]).await.unwrap();
    relay.wait_pushed(1).await;
    assert_eq!(relay.pusher.got.lock().unwrap().as_slice(), &[t]);
    assert_eq!(relay.stats.snapshot().wakes_in, 1);
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn invalid_expired_and_unknown_key_are_counted() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();

    let expired = relay.sealed(&token(2, today().saturating_sub(1)));
    let unknown_key = seal(
        PublicKey::from(&relay.secret).as_bytes(),
        9, // no such key id
        &token(3, today() + 1),
        &mut rand::rng(),
    );
    let other = StaticSecret::from([8u8; 32]);
    let wrong_key = seal(
        PublicKey::from(&other).as_bytes(),
        3,
        &token(4, today() + 1),
        &mut rand::rng(),
    );
    let garbage = vec![0xAB; 50];
    for item in [expired, unknown_key, wrong_key, garbage] {
        session.wake(vec![item]).await.unwrap();
    }
    let s = relay.stats.snapshot();
    assert_eq!((s.wakes_in, s.invalid, s.expired), (4, 3, 1));
    assert!(relay.pusher.got.lock().unwrap().is_empty());
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn more_than_100_items_is_malformed() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let item = relay.sealed(&token(5, today() + 1));
    let err = session
        .wake(vec![item.clone(); MAX_WAKE_ITEMS + 1])
        .await
        .unwrap_err();
    assert!(
        matches!(err, ClientError::Refused(ErrorReason::Malformed)),
        "{err:?}"
    );
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn exactly_100_items_is_accepted() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let item = relay.sealed(&token(5, today() + 1));
    assert_eq!(MAX_WAKE_ITEMS, 100);
    session.wake(vec![item; MAX_WAKE_ITEMS]).await.unwrap();
    relay.wait_pushed(6).await; // the bucket of 6; the rest is limited
    let s = relay.stats.snapshot();
    assert_eq!((s.wakes_in, s.limited), (100, 94));
    let _ = relay.stop.send(true);
}

/// A pusher that never completes.
struct Hung;
impl Pusher for Hung {
    async fn push(&self, _token: WakeToken) -> PushOutcome {
        std::future::pending().await
    }
}

#[tokio::test]
async fn ok_returns_while_push_is_pending() {
    let relay = start_with(ConnLimits::default(), Arc::new(Hung), Arc::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let item = relay.sealed(&token(7, today() + 1));
    tokio::time::timeout(Duration::from_secs(5), session.wake(vec![item]))
        .await
        .expect("response does not wait for the push")
        .unwrap();
    let s = relay.stats.snapshot();
    assert_eq!((s.wakes_in, s.sent, s.failed), (1, 0, 0));
    let _ = relay.stop.send(true);
}

/// Answers by the first byte of the device token.
struct Scripted;
impl Pusher for Scripted {
    async fn push(&self, token: WakeToken) -> PushOutcome {
        match token.apns_token[0] {
            1 => PushOutcome::Sent,
            2 => PushOutcome::Unregistered,
            3 | 4 => PushOutcome::Failed(429),
            5 => PushOutcome::Failed(503),
            _ => PushOutcome::Failed(418),
        }
    }
}

#[tokio::test]
async fn apns_errors_are_counted_by_code() {
    let relay = start_with(ConnLimits::default(), Arc::new(Scripted), Arc::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let items: Vec<_> = (1..=6u8)
        .map(|b| relay.sealed(&token(b, today() + 1)))
        .collect();
    session.wake(items).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while {
        let s = relay.stats.snapshot();
        s.sent + s.unregistered + s.failed < 6
    } {
        assert!(tokio::time::Instant::now() < deadline, "pushes not done");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let s = relay.stats.snapshot();
    assert_eq!((s.sent, s.unregistered, s.failed), (1, 1, 4));
    let slot = |code: u16| {
        barking_push::stats::APNS_CODES
            .iter()
            .position(|c| *c == code)
            .unwrap()
    };
    assert_eq!(s.apns_errors[slot(429)], 2);
    assert_eq!(s.apns_errors[slot(503)], 1);
    assert_eq!(s.apns_errors[barking_push::stats::APNS_SLOTS - 1], 1); // 418: other
    assert_eq!(s.apns_errors.iter().sum::<u64>(), 4);
    // `take` resets everything.
    assert_eq!(relay.stats.take().failed, 4);
    assert_eq!(relay.stats.snapshot(), Default::default());
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn hello_announces_relay_limits() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    assert_eq!(session.pow_bits(), 0);
    let l = session.limits();
    assert_eq!(l.max_mailboxes_per_fetch, 1);
    assert_eq!(
        l.max_request_bytes as usize,
        barking_proto::frame::MAX_REQUEST_BYTES
    );
    assert_eq!(
        l.max_response_bytes as usize,
        barking_proto::frame::MAX_RESPONSE_BYTES
    );
    assert!(!l.wake);
    assert!(!session.wake_supported());
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn clients_connect_through_retry() {
    // The first Initial of every client carries an unvalidated source
    // address and is answered with a Retry; connecting and waking still work.
    let relay = start(ConnLimits {
        max_connections: 100,
        max_connections_per_ip: 1,
    })
    .await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    session
        .wake(vec![relay.sealed(&token(8, today() + 1))])
        .await
        .unwrap();
    relay.wait_pushed(1).await;
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn other_requests_are_unsupported() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let resp = session
        .request(&Request::Fetch {
            mailboxes: vec![],
            cursor: None,
            max_bytes: 1024,
        })
        .await
        .unwrap();
    assert_eq!(resp, Response::Error(ErrorReason::Unsupported));
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn repeated_token_is_rate_limited() {
    let relay = start(ConnLimits::default()).await;
    let session = Client::connect(relay.addr, relay.id).await.unwrap();
    let item = relay.sealed(&token(6, today() + 1));
    session.wake(vec![item; 8]).await.unwrap();
    relay.wait_pushed(6).await;
    let s = relay.stats.snapshot();
    assert_eq!((s.wakes_in, s.limited), (8, 2));
    let _ = relay.stop.send(true);
}

#[tokio::test]
async fn per_ip_connection_cap_refuses_extra_connections() {
    let relay = start(ConnLimits {
        max_connections: 100,
        max_connections_per_ip: 1,
    })
    .await;
    let first = Client::connect(relay.addr, relay.id).await.unwrap();
    assert!(Client::connect(relay.addr, relay.id).await.is_err());
    drop(first);
    let _ = relay.stop.send(true);
}
