//! Network integration: a real QUIC node on 127.0.0.1 (free port), the
//! `barking-proto` client, and rigged peers for the hostile cases.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::{Core, ReceiveOutcome};
use barking_node::limits::LimitConfig;
use barking_node::server::{self, ServerConfig, ServerStats};
use barking_node::{NodeStore, Policy};
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
use barking_proto::client::{self, Client, ClientError};
use barking_proto::frame::{self, MAX_REQUEST_BYTES};
use barking_proto::{ErrorReason, NodeId, PROTOCOL_VERSION, Request, Response, tls};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Generous timeout for any test wait.
const LONG: Duration = Duration::from_secs(20);
/// Reduced difficulty for fast tests.
const TEST_BITS: u8 = 8;

/// Precomputed puzzle-solving keys: each test runs in its own process
/// under cargo-nextest, so a key drawn at run time would cost every test.
fn key(n: usize) -> SigningKey {
    barking_node::testing::key(n)
}

fn id_of(k: &SigningKey) -> NodeId {
    NodeId::from_public_key(&k.verifying_key())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn policy() -> Policy {
    Policy {
        pow_bits: TEST_BITS,
        ..Policy::default()
    }
}

struct Node {
    addr: SocketAddr,
    id: NodeId,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<barking_node::Result<()>>,
}

impl Node {
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        timeout(LONG, self.task).await.unwrap().unwrap().unwrap();
    }
}

fn start_with(
    db: &Path,
    key: SigningKey,
    policy: Policy,
    tweak: impl FnOnce(&mut ServerConfig),
) -> Node {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let id = id_of(&key);
    let mut cfg = ServerConfig::new(vec![socket], key);
    tweak(&mut cfg);
    let store = NodeStore::open(db).unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(server::run(cfg, store, policy, async move {
        let _ = rx.await;
    }));
    Node {
        addr,
        id,
        stop: Some(tx),
        task,
    }
}

fn start(db: &Path) -> Node {
    start_with(db, key(0), policy(), |_| {})
}

fn db() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("node.db");
    (d, p)
}

/// Valid synthetic message packet (tier S) in mailbox `mb`.
fn message(n: u32, mb: u8) -> Vec<u8> {
    message_tier(n, mb, Tier::S)
}

/// Expiry fixed once and for all: the same packet has the same bytes
/// from one call to the next.
fn expiry() -> u32 {
    static E: OnceLock<u32> = OnceLock::new();
    *E.get_or_init(|| u32::try_from(now() + 86_400).unwrap())
}

fn message_tier(n: u32, mb: u8, tier: Tier) -> Vec<u8> {
    let mut id = [0u8; 16];
    id[..4].copy_from_slice(&n.to_le_bytes());
    id[4] = mb;
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: PacketId(id),
        expires_at: expiry(),
        mailbox: MailboxId([mb; 16]),
        payload: vec![n as u8; 16],
    }
    .encode()
}

async fn raw_stream(conn: &quinn::Connection, bytes: &[u8], finish: bool) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // The node may cut the stream during the send: errors ignored.
    let _ = send.write_all(bytes).await;
    if finish {
        let _ = send.finish();
    }
    timeout(LONG, recv.read_to_end(1 << 21))
        .await
        .expect("the node must close the stream")
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_then_fetch_roundtrip() {
    let (_d, path) = db();
    let node = start(&path);
    let t = now();
    let mut rng = StdRng::seed_from_u64(7);

    let dir = tempfile::tempdir().unwrap();
    let (mut alice, _) =
        Core::create(&dir.path().join("a.db"), &[1; 32], "alice", t, &mut rng).unwrap();
    let (mut bob, _) =
        Core::create(&dir.path().join("b.db"), &[2; 32], "bob", t, &mut rng).unwrap();
    let ca = alice.contact_card("Alice").unwrap();
    let cb = bob.contact_card("Bob").unwrap();
    let bob_fp = alice.add_contact(&cb, Some("bob"), t, &mut rng).unwrap();
    bob.add_contact(&ca, Some("alice"), t, &mut rng).unwrap();

    let packets = alice.send_text(&bob_fp, "hello Bob", t, &mut rng).unwrap();
    let mut sa = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(sa.node_id(), node.id);
    assert_eq!(sa.pow_bits(), TEST_BITS);
    for p in &packets {
        assert_eq!(sa.deposit(&p.encode()).await.unwrap(), Ok(()));
    }

    let mut sb = Client::connect(node.addr, node.id).await.unwrap();
    let items = sb.fetch(&bob.watched_mailboxes(t).unwrap()).await.unwrap();
    assert!(!items.is_empty());
    let mut acks = Vec::new();
    let mut text = None;
    for it in &items {
        if let ReceiveOutcome::Message { text: m, ack, .. } =
            bob.receive(it, "node", t, &mut rng).unwrap()
        {
            text = Some(m);
            acks.push(ack);
        }
    }
    assert_eq!(text.as_deref(), Some("hello Bob"));
    for a in &acks {
        assert_eq!(sb.deposit(&a.encode()).await.unwrap(), Ok(()));
    }

    // The ack deleted the copy: Alice now fetches only the ack.
    let items = sa
        .fetch(&alice.watched_mailboxes(t).unwrap())
        .await
        .unwrap();
    let got_ack = items.iter().any(|it| {
        matches!(
            alice.receive(it, "node", t, &mut rng).unwrap(),
            ReceiveOutcome::AckReceived { .. }
        )
    });
    assert!(got_ack);
    let again = sb.fetch(&bob.watched_mailboxes(t).unwrap()).await.unwrap();
    assert!(packets.iter().all(|p| !again.contains(&p.encode())));
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_node_id_refused_by_client() {
    let (_d, path) = db();
    // The node presents a valid self-signed certificate, but for another
    // identifier (puzzle solved): man in the middle refused.
    let node = start_with(&path, key(1), policy(), |_| {});
    let r = Client::connect(node.addr, id_of(&key(0))).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
    // Control: the right identifier passes.
    Client::connect(node.addr, node.id).await.unwrap();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_id_without_puzzle_refused() {
    let (_d, path) = db();
    let weak = SigningKey::from_bytes(&[9; 32]);
    assert!(!id_of(&weak).puzzle_ok());
    let node = start_with(&path, weak, policy(), |_| {});
    let r = Client::connect(node.addr, node.id).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
    node.stop().await;
}

/// Rigged peer: presents the real node's certificate `victim` but signs the
/// TLS handshake with another key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stolen_certificate_without_key_refused() {
    let victim = key(0);
    let attacker = SigningKey::from_bytes(&[3; 32]);
    let cert = tls::self_signed_cert(&victim);
    let der = tls::pkcs8_der(&attacker);
    let signer = rustls::crypto::ring::sign::any_eddsa_type(
        &rustls::pki_types::PrivatePkcs8KeyDer::from(&der[..]),
    )
    .unwrap();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert], signer));
    #[derive(Debug)]
    struct Fixed(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(Fixed(certified)));
    cfg.alpn_protocols = vec![barking_proto::ALPN.to_vec()];
    let qcfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(cfg).unwrap(),
    ));
    let ep = quinn::Endpoint::server(qcfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = ep.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        if let Some(inc) = ep.accept().await {
            let _ = inc.await;
        }
    });
    let r = Client::connect(addr, id_of(&victim)).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
    srv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_version_refused() {
    let (_d, path) = db();
    // A default node (protocol version 2) no longer accepts version 1.
    let node = start(&path);
    // A raw version-1 request: `Error(VersionTooOld)`, then closing.
    let (_ep, conn) = client::open_connection(node.addr, node.id).await.unwrap();
    let resp = client::request(
        &conn,
        &Request::Hello {
            version: 1,
            min_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(resp, Response::Error(ErrorReason::VersionTooOld));
    timeout(LONG, conn.closed()).await.unwrap();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_before_hello_refused() {
    let (_d, path) = db();
    let node = start(&path);
    let (_ep, conn) = client::open_connection(node.addr, node.id).await.unwrap();
    let resp = client::request(
        &conn,
        &Request::Fetch {
            mailboxes: vec![MailboxId([1; 16])],
            cursor: None,
            max_bytes: 1 << 20,
        },
    )
    .await
    .unwrap();
    assert_eq!(resp, Response::Error(ErrorReason::Malformed));
    timeout(LONG, conn.closed()).await.unwrap();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_timeout_and_idle_close_connection() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.hello_timeout = Duration::from_millis(500);
        c.idle_timeout = Duration::from_millis(800);
    });
    // No Hello: closed.
    let (_ep, conn) = client::open_connection(node.addr, node.id).await.unwrap();
    timeout(LONG, conn.closed()).await.unwrap();
    // Hello then silence: closed for inactivity.
    let s = Client::connect(node.addr, node.id).await.unwrap();
    timeout(LONG, s.connection().closed()).await.unwrap();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_or_truncated_frame_closes_stream() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.request_timeout = Duration::from_millis(500);
    });
    let s = Client::connect(node.addr, node.id).await.unwrap();
    let conn = s.connection().clone();

    // Announced length beyond 64 KiB: stream closed without a response.
    let mut big = ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().to_vec();
    big.extend_from_slice(&[0u8; 1024]);
    assert!(raw_stream(&conn, &big, true).await.is_empty());
    // 4 GiB announced: no buffer, stream closed.
    assert!(
        raw_stream(&conn, &u32::MAX.to_be_bytes(), false)
            .await
            .is_empty()
    );
    // Truncated frame (the client cuts in the middle).
    let mut cut = 100u32.to_be_bytes().to_vec();
    cut.extend_from_slice(&[0u8; 10]);
    assert!(raw_stream(&conn, &cut, true).await.is_empty());
    // Truncated frame without end of stream: cut by the read timeout.
    assert!(raw_stream(&conn, &cut, false).await.is_empty());
    // Corps invalide : `Error(Malformed)`.
    let mut junk = 3u32.to_be_bytes().to_vec();
    junk.extend_from_slice(&[0xff; 3]);
    let resp = raw_stream(&conn, &junk, true).await;
    let mut r = &resp[..];
    assert_eq!(
        frame::read::<Response>(&mut r, frame::MAX_RESPONSE_BYTES)
            .await
            .unwrap(),
        Response::Error(ErrorReason::Malformed)
    );

    // The same connection and a second connection are still served.
    assert_eq!(
        s.request(&Request::Ping { from: None }).await.unwrap(),
        Response::Error(ErrorReason::Unsupported)
    );
    let mut s2 = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(s2.deposit(&message(1, 1)).await.unwrap(), Ok(()));
    assert_eq!(
        s2.fetch(&[MailboxId([1; 16])]).await.unwrap(),
        vec![message(1, 1)]
    );
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 1;
        c.limits.burst = 5;
    });
    let s = Client::connect(node.addr, node.id).await.unwrap();
    let mut seen = Vec::new();
    for _ in 0..20 {
        seen.push(s.request(&Request::Ping { from: None }).await.unwrap());
    }
    assert_eq!(seen[0], Response::Error(ErrorReason::Unsupported));
    assert!(seen.contains(&Response::Error(ErrorReason::RateLimited)));
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_rate_limited() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.bytes_per_sec = 1_000;
        c.limits.burst = 2;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let mut refused = false;
    for n in 0..20 {
        if s.deposit(&message(n, 2)).await.unwrap() == Err(ErrorReason::RateLimited) {
            refused = true;
            break;
        }
    }
    assert!(refused);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_connections_per_ip() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.max_connections_per_ip = 2;
    });
    let a = Client::connect(node.addr, node.id).await.unwrap();
    let _b = Client::connect(node.addr, node.id).await.unwrap();
    let r = Client::connect(node.addr, node.id).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
    // A slot frees up on close.
    a.close().await;
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        if Client::connect(node.addr, node.id).await.is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dht_requests_unsupported() {
    let (_d, path) = db();
    let node = start(&path);
    let s = Client::connect(node.addr, node.id).await.unwrap();
    for req in [
        Request::Ping { from: None },
        Request::FindNode {
            target: [1; 32],
            from: None,
        },
        Request::Store {
            packet: message(1, 1),
            pow: 0,
        },
        Request::FindValue {
            mailbox: MailboxId([1; 16]),
            cursor: None,
        },
    ] {
        assert_eq!(
            s.request(&req).await.unwrap(),
            Response::Error(ErrorReason::Unsupported)
        );
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_sees_committed_deposit() {
    let (_d, path) = db();
    let node = start(&path);
    let mut writer = Client::connect(node.addr, node.id).await.unwrap();
    let mut reader = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..5 {
        assert_eq!(writer.deposit(&message(n, 4)).await.unwrap(), Ok(()));
        // Fetched by another connection right after the `Ok`.
        let items = reader.fetch(&[MailboxId([4; 16])]).await.unwrap();
        assert_eq!(items, (0..=n).map(|k| message(k, 4)).collect::<Vec<_>>());
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_keeps_confirmed_deposits() {
    let (_d, path) = db();
    let node = start(&path);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..5 {
        assert_eq!(s.deposit(&message(n, 3)).await.unwrap(), Ok(()));
    }
    drop(s);
    // Abrupt shutdown: the server task is abandoned without clean closing.
    node.task.abort();
    let _ = node.task.await;

    let node = start(&path);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let items = s.fetch(&[MailboxId([3; 16])]).await.unwrap();
    assert_eq!(items, (0..5).map(|n| message(n, 3)).collect::<Vec<_>>());
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_retries_progressive_pow() {
    let (_d, path) = db();
    // Base difficulty 4: beyond 64 packets the mailbox requires 5,
    // beyond 128, 6. The client raises its proof on `PowTooWeak`.
    let node = start_with(
        &path,
        key(0),
        Policy {
            pow_bits: 4,
            ..Policy::default()
        },
        |c| c.limits.requests_per_sec = 10_000,
    );
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..200 {
        assert_eq!(s.deposit(&message(n, 4)).await.unwrap(), Ok(()), "n={n}");
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_splits_mailboxes_and_pages() {
    let (_d, path) = db();
    let node = start(&path);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let boxes: Vec<MailboxId> = (0..150u8).map(|n| MailboxId([n; 16])).collect();
    for n in [0u8, 63, 64, 149] {
        assert_eq!(s.deposit(&message(u32::from(n), n)).await.unwrap(), Ok(()));
    }
    let items = s.fetch(&boxes).await.unwrap();
    assert_eq!(items.len(), 4);
    assert!(!s.last_fetch_truncated());
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Complete);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_with_excessive_pow_refused() {
    let (_d, path) = db();
    let node = start_with(
        &path,
        key(0),
        Policy {
            pow_bits: 25,
            ..Policy::default()
        },
        |_| {},
    );
    let r = timeout(LONG, node.task).await.unwrap().unwrap();
    assert!(r.is_err());
}

/// Fake node: authentic TLS (key `k`), responses supplied by `answer`.
fn fake_node(
    k: SigningKey,
    answer: impl Fn(Request) -> Option<Response> + Send + Sync + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    slow_fake_node(k, move |req| (answer(req), Duration::ZERO))
}

/// `fake_node` answering (or cutting the stream) after the delay given
/// with each answer, as a slow link or a node's write deadline would.
fn slow_fake_node(
    k: SigningKey,
    answer: impl Fn(Request) -> (Option<Response>, Duration) + Send + Sync + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let ep = quinn::Endpoint::server(tls::quinn_server_config(&k), "127.0.0.1:0".parse().unwrap())
        .unwrap();
    let addr = ep.local_addr().unwrap();
    let answer = Arc::new(answer);
    let h = tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            let answer = answer.clone();
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(req) = frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES).await else {
                        return;
                    };
                    let (resp, delay) = answer(req);
                    tokio::time::sleep(delay).await;
                    match resp {
                        Some(resp) => {
                            let _ = frame::write(&mut send, &resp, frame::MAX_RESPONSE_BYTES).await;
                            let _ = send.finish();
                        }
                        // Stream cut, like a node whose write deadline expires.
                        None => {
                            let _ = send.reset(1u32.into());
                        }
                    }
                }
            });
        }
    });
    (addr, h)
}

fn hello(k: &SigningKey, pow_bits: u8) -> Response {
    Response::Hello {
        version: PROTOCOL_VERSION,
        min_version: PROTOCOL_VERSION,
        node_id: id_of(k),
        pow_bits,
        limits: barking_proto::Limits {
            max_mailboxes_per_fetch: 64,
            max_request_bytes: MAX_REQUEST_BYTES as u32,
            max_response_bytes: frame::MAX_RESPONSE_BYTES as u32,
            wake: false,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_excessive_pow_bits() {
    let k = key(0);
    let h = hello(&k, 30);
    let (addr, srv) = fake_node(k.clone(), move |_| Some(h.clone()));
    let r = Client::connect(addr, id_of(&k)).await;
    assert!(matches!(r, Err(ClientError::Protocol(_))), "{:?}", r.err());
    srv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_caps_hostile_pagination() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| {
        Some(match req {
            Request::Hello { .. } => h.clone(),
            Request::Fetch { cursor, .. } => Response::Items {
                items: vec![vec![0; 8]; 100],
                next: Some(cursor.unwrap_or(0) + 1),
            },
            _ => Response::Error(ErrorReason::Unsupported),
        })
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    let items = timeout(LONG, s.fetch(&[MailboxId([1; 16])]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(items.len(), client::MAX_FETCH_ITEMS);
    assert!(s.last_fetch_truncated());
    // Pages of 800 bytes announcing more: the node paces them.
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Paced);
    srv.abort();
}

/// A page holding more items than any node puts in one: protocol error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_page_beyond_item_cap() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| {
        Some(match req {
            Request::Hello { .. } => h.clone(),
            Request::Fetch { .. } => Response::Items {
                items: vec![vec![0; 8]; barking_proto::MAX_PAGE_ITEMS + 1],
                next: None,
            },
            _ => Response::Error(ErrorReason::Unsupported),
        })
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    let r = timeout(LONG, s.fetch(&[MailboxId([1; 16])])).await.unwrap();
    assert!(matches!(r, Err(ClientError::Protocol(_))), "{r:?}");
    srv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_caps_page_count() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| {
        Some(match req {
            Request::Hello { .. } => h.clone(),
            Request::Fetch { cursor, .. } => Response::Items {
                items: vec![vec![1]],
                next: Some(cursor.unwrap_or(0) + 1),
            },
            _ => Response::Error(ErrorReason::Unsupported),
        })
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    let items = timeout(Duration::from_secs(60), s.fetch(&[MailboxId([1; 16])]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(items.len(), client::MAX_FETCH_PAGES);
    assert!(s.last_fetch_truncated());
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Paced);
    srv.abort();
}

/// Connection whose reader barely opens its receive window:
/// responses stay blocked on the node side.
async fn stuck_connection(addr: SocketAddr, id: NodeId) -> (quinn::Endpoint, quinn::Connection) {
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls::client_config(id)).unwrap();
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut t = quinn::TransportConfig::default();
    t.stream_receive_window(2048u32.into())
        .receive_window(8192u32.into());
    cfg.transport_config(Arc::new(t));
    ep.set_default_client_config(cfg);
    let conn = ep.connect(addr, tls::CERT_NAME).unwrap().await.unwrap();
    let r = client::request(
        &conn,
        &Request::Hello {
            version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    assert!(matches!(r, Response::Hello { .. }));
    (ep, conn)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stuck_readers_bounded_by_global_cap() {
    let (_d, path) = db();
    let stats = Arc::new(ServerStats::default());
    const CAP: usize = 2 << 20;
    let st = stats.clone();
    let node = start_with(&path, key(0), policy(), move |c| {
        c.stats = st;
        c.max_response_bytes_in_flight = CAP;
        c.request_timeout = Duration::from_secs(5);
        // Write deadline ≈ request_timeout: short test.
        c.min_send_rate = 1 << 30;
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 1 << 30;
    });
    // More than one page of L packets in mailbox 9.
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..70 {
        assert_eq!(
            s.deposit(&message_tier(n, 9, Tier::L)).await.unwrap(),
            Ok(())
        );
    }
    // 3 connections × 4 fetch streams never read.
    let fetch = frame::encode(
        &Request::Fetch {
            mailboxes: vec![MailboxId([9; 16])],
            cursor: None,
            max_bytes: 1 << 20,
        },
        MAX_REQUEST_BYTES,
    )
    .unwrap();
    let mut held = Vec::new();
    let mut endpoints = Vec::new();
    for _ in 0..3 {
        let (ep, conn) = stuck_connection(node.addr, node.id).await;
        for _ in 0..4 {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(&fetch).await.unwrap();
            send.finish().unwrap();
            held.push((send, recv));
        }
        endpoints.push((ep, conn));
    }
    // Synchronize on the node's gauge rather than a fixed delay.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.response_bytes.now() <= 1 << 20 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "blocked streams not reserved"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(stats.response_bytes.peak() <= CAP);
    // Another client is still served.
    let mut other = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(other.deposit(&message(1, 1)).await.unwrap(), Ok(()));
    // Past `request_timeout`, the blocked streams are cut and memory returned.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.response_bytes.now() != 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        other.fetch(&[MailboxId([1; 16])]).await.unwrap(),
        vec![message(1, 1)]
    );
    assert!(stats.response_bytes.peak() <= CAP);
    drop(held);
    drop(endpoints);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_queue_bounded_across_connection_churn() {
    let (_d, path) = db();
    let stats = Arc::new(ServerStats::default());
    let st = stats.clone();
    let node = start_with(&path, key(0), policy(), move |c| {
        c.stats = st;
        c.max_db_jobs = 1;
        c.limits.requests_per_sec = 10_000;
    });
    // Enough to make a 64-mailbox fetch non-instantaneous.
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..64u32 {
        assert_eq!(s.deposit(&message(n, n as u8)).await.unwrap(), Ok(()));
    }
    s.close().await;
    let boxes: Vec<MailboxId> = (0..64u8).map(|n| MailboxId([n; 16])).collect();
    let mut limited = 0;
    for round in 0..10u32 {
        let s = Client::connect(node.addr, node.id).await.unwrap();
        let mut reqs = Vec::new();
        for _ in 0..4 {
            let conn = s.connection().clone();
            let req = Request::Fetch {
                mailboxes: boxes.clone(),
                cursor: None,
                max_bytes: 16 * 1024,
            };
            reqs.push(tokio::spawn(
                async move { client::request(&conn, &req).await },
            ));
        }
        if round % 2 == 0 {
            for r in reqs {
                if let Ok(Ok(Response::Error(ErrorReason::RateLimited))) = r.await {
                    limited += 1;
                }
            }
        }
        // Odd rounds: closing while requests are in progress.
        s.close().await;
        assert!(stats.db_jobs.peak() <= 1);
    }
    // Four simultaneous fetches for a single slot: refusals.
    assert!(limited > 0);
    // All connections and their base jobs finish.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.db_jobs.now() != 0 || stats.connections.now() != 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stats.db_jobs.peak() <= 1);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(s.deposit(&message(999, 6)).await.unwrap(), Ok(()));
    node.stop().await;
}

/// Reader that stops the stream (STOP_SENDING): the response is still
/// debited from its byte bucket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_reader_is_charged() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 100 * 1024;
        c.limits.burst = 2;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    // 20 L packets (320 KiB) deposited from another connection (its own
    // bucket, awaited when it is empty).
    let mut filler = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..20 {
        loop {
            match filler.deposit(&message_tier(n, 11, Tier::L)).await.unwrap() {
                Ok(()) => break,
                Err(ErrorReason::RateLimited) => {
                    tokio::time::sleep(Duration::from_millis(100)).await
                }
                Err(e) => panic!("{e:?}"),
            }
        }
    }
    let page = frame::encode(
        &Request::Fetch {
            mailboxes: vec![MailboxId([11; 16])],
            cursor: None,
            max_bytes: 1 << 20,
        },
        MAX_REQUEST_BYTES,
    )
    .unwrap();
    let conn = s.connection().clone();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&page).await.unwrap();
    send.finish().unwrap();
    recv.stop(7u32.into()).unwrap();
    // The stopped response (~320 KiB) exceeds the bucket's capacity (200 KiB):
    // the following requests are limited until it is refilled.
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        if s.request(&Request::Ping { from: None }).await.unwrap()
            == Response::Error(ErrorReason::RateLimited)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "stopped response not debited"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = s.fetch(&[]).await;
    node.stop().await;
}

/// A page that is too slow (stream cut by the node) is requested again smaller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_shrinks_page_after_reset() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = asked.clone();
    let (addr, srv) = fake_node(k.clone(), move |req| match req {
        Request::Hello { .. } => Some(h.clone()),
        Request::Fetch {
            cursor, max_bytes, ..
        } => {
            log.lock().unwrap().push((cursor, max_bytes));
            // "Slow" link: any page beyond 64 KiB is cut.
            if max_bytes > 64 * 1024 {
                return None;
            }
            let c = cursor.unwrap_or(0);
            Some(Response::Items {
                items: vec![vec![c as u8]],
                next: (c < 2).then_some(c + 1),
            })
        }
        _ => Some(Response::Error(ErrorReason::Unsupported)),
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    let items = s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(items, vec![vec![0], vec![1], vec![2]]);
    assert!(!s.last_fetch_truncated());
    // The default call deadline (120 s) holds two 256 KiB page timeouts,
    // not two 1 MiB ones: the first page is asked at 256 KiB.
    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            (None, 256 << 10),
            (None, 64 << 10),
            (Some(1), 64 << 10),
            (Some(2), 64 << 10)
        ]
    );
    assert_eq!(s.page_bytes(), 64 << 10);
    // The size reached is kept for the next call on the session.
    asked.lock().unwrap().clear();
    s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(asked.lock().unwrap()[0], (None, 64 << 10));
    srv.abort();
}

/// All sizes cut: give up after 16 KiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_gives_up_below_smallest_page() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| match req {
        Request::Hello { .. } => Some(h.clone()),
        _ => None,
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    assert!(s.fetch(&[MailboxId([1; 16])]).await.is_err());
    srv.abort();
}

/// A node resetting every page above 16 KiB costs it nothing: this
/// session goes on at 16 KiB, but the size carried to the next sessions
/// stops at 64 KiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resets_carry_no_page_below_64_kib() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = asked.clone();
    let (addr, srv) = fake_node(k.clone(), move |req| match req {
        Request::Hello { .. } => Some(h.clone()),
        Request::Fetch {
            cursor, max_bytes, ..
        } => {
            log.lock().unwrap().push(max_bytes);
            if max_bytes > barking_proto::MIN_PAGE_BYTES {
                return None;
            }
            let c = cursor.unwrap_or(0);
            Some(Response::Items {
                items: vec![vec![c as u8; 12 * 1024]],
                next: (c < 2).then_some(c + 1),
            })
        }
        _ => Some(Response::Error(ErrorReason::Unsupported)),
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(asked.lock().unwrap()[..2], [256 << 10, 64 << 10]);
    assert_eq!(*asked.lock().unwrap().last().unwrap(), 16 << 10);
    assert_eq!(s.page_bytes(), client::MIN_CARRIED_PAGE_BYTES);
    assert!(!s.page_confirmed());
    // The session itself keeps its 16 KiB pages.
    asked.lock().unwrap().clear();
    s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(asked.lock().unwrap()[0], 16 << 10);
    srv.abort();
}

/// A node that resets its larger pages, then paces one small item per
/// 16 KiB page until the page cap: reported paced, although no 16 KiB page
/// is far below its size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_items_paced_at_16_kib_are_paced() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| match req {
        Request::Hello { .. } => Some(h.clone()),
        Request::Fetch {
            cursor, max_bytes, ..
        } => {
            if max_bytes > barking_proto::MIN_PAGE_BYTES {
                return None;
            }
            Some(Response::Items {
                items: vec![vec![0; Tier::S.size()]],
                next: Some(cursor.unwrap_or(0) + 1),
            })
        }
        _ => Some(Response::Error(ErrorReason::Unsupported)),
    });
    let mut s = Client::connect(addr, id_of(&k)).await.unwrap();
    let items = timeout(Duration::from_secs(60), s.fetch(&[MailboxId([1; 16])]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(items.len(), client::MAX_FETCH_PAGES - 2);
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Paced);
    srv.abort();
}

/// A real node serving 16 KiB pages of mixed sizes, cut by the call's
/// deadline: its pages end where the next item does not fit, never paced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_node_at_16_kib_is_never_paced() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let boxes: Vec<MailboxId> = (40..44).map(|b| MailboxId([b; 16])).collect();
    for n in 0..150u32 {
        let tier = if n % 3 == 2 { Tier::S } else { Tier::M };
        let mb = 40 + (n % 4) as u8;
        assert_eq!(s.deposit(&message_tier(n, mb, tier)).await.unwrap(), Ok(()));
    }
    s.close().await;
    node.stop().await;
    // The same store behind a slow node: a few pages per call.
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.test_response_delay = Some(Duration::from_millis(250));
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    s.set_page_bytes(barking_proto::MIN_PAGE_BYTES);
    s.set_fetch_deadline(Duration::from_millis(1_200));
    let items = s.fetch(&boxes).await.unwrap();
    // Several continued pages taken, the rest left by the deadline.
    assert!(items.len() > 2 * 16 && items.len() < 150, "{}", items.len());
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Deadline);
    node.stop().await;
}

/// Delay before a slow node cuts a 64 KiB page: below a default node's
/// write deadline (10 s + 64 KiB at 32 KiB/s), as a node with a tighter
/// one would.
const LATE_CUT: Duration = Duration::from_secs(9);
/// Delay of each 16 KiB page of a slow node: 10 KiB in it, about 4 KiB/s.
const SLOW_PAGE: Duration = Duration::from_millis(2_500);

/// A node on a slow link: pages above 64 KiB cut at once, 64 KiB pages cut
/// after `cut_64k`, 16 KiB pages of one 10 KiB item after `SLOW_PAGE`,
/// `pages` of them per call. Logs the sizes asked.
fn slow_link_node(
    k: SigningKey,
    cut_64k: Duration,
    pages: u64,
) -> (SocketAddr, JoinHandle<()>, Arc<std::sync::Mutex<Vec<u32>>>) {
    let h = hello(&k, TEST_BITS);
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = asked.clone();
    let (addr, srv) = slow_fake_node(k, move |req| match req {
        Request::Hello { .. } => (Some(h.clone()), Duration::ZERO),
        Request::Fetch {
            cursor, max_bytes, ..
        } => {
            log.lock().unwrap().push(max_bytes);
            if max_bytes > 64 << 10 {
                return (None, Duration::ZERO);
            }
            if max_bytes > barking_proto::MIN_PAGE_BYTES {
                return (None, cut_64k);
            }
            let c = cursor.unwrap_or(0);
            let page = Response::Items {
                items: vec![vec![c as u8; 10 << 10]],
                next: (c + 1 < pages).then_some(c + 1),
            };
            (Some(page), SLOW_PAGE)
        }
        _ => (
            Some(Response::Error(ErrorReason::Unsupported)),
            Duration::ZERO,
        ),
    });
    (addr, srv, asked)
}

/// A 64 KiB page cut late, then a slow 16 KiB page measured: the link is
/// slow, 16 KiB is carried and confirmed. Cut at once: 64 KiB carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_cut_at_a_slow_rate_carries_16_kib() {
    let (addr, srv, _) = slow_link_node(key(0), LATE_CUT, 1);
    let mut s = Client::connect(addr, id_of(&key(0))).await.unwrap();
    s.set_page_bytes(64 << 10);
    s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(s.page_bytes(), barking_proto::MIN_PAGE_BYTES);
    assert!(s.page_confirmed());
    srv.abort();

    let (addr, srv, _) = slow_link_node(key(0), Duration::ZERO, 1);
    let mut s = Client::connect(addr, id_of(&key(0))).await.unwrap();
    s.set_page_bytes(64 << 10);
    s.fetch(&[MailboxId([1; 16])]).await.unwrap();
    assert_eq!(s.page_bytes(), client::MIN_CARRIED_PAGE_BYTES);
    assert!(!s.page_confirmed());
    srv.abort();
}

/// A real node on a slow link (4 KiB/s) whose operator tightened its
/// request timeout: its write deadline cuts a 64 KiB page at about 9 s, below
/// a default node's 12 s. The client still learns the link is slow and
/// carries 16 KiB, confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tight_write_deadline_cut_still_carries_16_kib() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..48u32 {
        assert_eq!(
            s.deposit(&message_tier(n, 45, Tier::M)).await.unwrap(),
            Ok(())
        );
    }
    s.close().await;
    node.stop().await;
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.request_timeout = Duration::from_secs(7);
        c.test_send_rate = Some(4 * 1024);
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    s.set_page_bytes(64 << 10);
    // Room for a 64 KiB page first (twice its 24 s timeout).
    s.set_fetch_deadline(Duration::from_secs(60));
    let started = tokio::time::Instant::now();
    let items = s.fetch(&[MailboxId([45; 16])]).await.unwrap();
    assert_eq!(items.len(), 48);
    assert!(started.elapsed() >= Duration::from_secs(8));
    assert_eq!(s.page_bytes(), barking_proto::MIN_PAGE_BYTES);
    assert!(s.page_confirmed());
    node.stop().await;
}

/// As `QuicDialer` does: the stored size set before each fetch on the same
/// session. The calls after the first one start from the 16 KiB reached
/// (no 64 KiB page cut again) and keep it confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kept_session_keeps_its_small_pages_across_calls() {
    let (addr, srv, asked) = slow_link_node(key(0), LATE_CUT, 1);
    let mut s = Client::connect(addr, id_of(&key(0))).await.unwrap();
    // The caller's stored size stays 64 KiB (say, grown back by a
    // recovery since).
    let stored = 64 << 10;
    for call in 0..3 {
        asked.lock().unwrap().clear();
        s.set_page_bytes(stored);
        s.fetch(&[MailboxId([1; 16])]).await.unwrap();
        let first = asked.lock().unwrap()[0];
        let want = if call == 0 { 64 << 10 } else { 16 << 10 };
        assert_eq!(first, want, "call {call}");
        assert!(s.page_confirmed(), "call {call}");
        assert_eq!(s.page_bytes(), barking_proto::MIN_PAGE_BYTES);
    }
    srv.abort();
}

/// Pages of 245-byte items while the cursor is below `small`, then pages
/// filled with 16 KiB items as an honest node would; every response after
/// 50 ms.
fn cut_early_node(k: SigningKey, small: u64) -> (SocketAddr, JoinHandle<()>) {
    let h = hello(&k, TEST_BITS);
    slow_fake_node(k, move |req| match req {
        Request::Hello { .. } => (Some(h.clone()), Duration::ZERO),
        Request::Fetch {
            cursor, max_bytes, ..
        } => {
            let c = cursor.unwrap_or(0);
            let items = if c < small {
                vec![vec![0; Tier::S.size()]]
            } else {
                let n = (max_bytes as usize / Tier::L.size()).max(1);
                vec![vec![1; Tier::L.size()]; n]
            };
            let page = Response::Items {
                items,
                next: Some(c + 1),
            };
            (Some(page), Duration::from_millis(50))
        }
        _ => (
            Some(Response::Error(ErrorReason::Unsupported)),
            Duration::ZERO,
        ),
    })
}

/// One page cut before an item that fitted may be an honest node's (an ack
/// deleted the item that ended it in between): not paced. Two are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_page_cut_early_is_not_paced() {
    for (small, stop) in [
        (2, client::FetchStop::Deadline),
        (3, client::FetchStop::Paced),
    ] {
        let (addr, srv) = cut_early_node(key(0), small);
        let mut s = Client::connect(addr, id_of(&key(0))).await.unwrap();
        s.set_page_bytes(barking_proto::MIN_PAGE_BYTES);
        s.set_fetch_deadline(Duration::from_millis(1_500));
        s.fetch(&[MailboxId([1; 16])]).await.unwrap();
        assert_eq!(s.last_fetch_stop(), stop, "{small} small pages");
        srv.abort();
    }
}

/// The node serves the requested page size (floor 16 KiB).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_honors_requested_page_size() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..40 {
        assert_eq!(
            s.deposit(&message_tier(n, 12, Tier::M)).await.unwrap(),
            Ok(())
        );
    }
    for (asked, per_page) in [(0u32, 16usize), (16 * 1024, 16), (32 * 1024, 32)] {
        let r = s
            .request(&Request::Fetch {
                mailboxes: vec![MailboxId([12; 16])],
                cursor: None,
                max_bytes: asked,
            })
            .await
            .unwrap();
        let Response::Items { items, next } = r else {
            panic!("{r:?}")
        };
        assert_eq!(items.len(), per_page, "requested {asked}");
        assert!(next.is_some());
    }
    node.stop().await;
}

/// An address group takes only its share of the response budget; a
/// client of another group always fetches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_group_capped_share_of_response_budget() {
    let Ok(v6) = UdpSocket::bind("[::1]:0") else {
        eprintln!("local IPv6 unavailable: test skipped");
        return;
    };
    let v6_addr = v6.local_addr().unwrap();
    let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = v4.local_addr().unwrap();
    let (_d, path) = db();
    let k = key(0);
    let id = id_of(&k);
    let stats = Arc::new(ServerStats::default());
    let mut cfg = ServerConfig::new(vec![v4, v6], k);
    cfg.stats = stats.clone();
    cfg.request_timeout = Duration::from_secs(10);
    cfg.limits.requests_per_sec = 10_000;
    cfg.limits.bytes_per_sec = 1 << 30;
    const PER_IP: usize = 4 << 20;
    assert_eq!(cfg.max_response_bytes_per_ip, PER_IP);
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(server::run(
        cfg,
        NodeStore::open(&path).unwrap(),
        policy(),
        async move {
            let _ = rx.await;
        },
    ));
    let node = Node {
        addr,
        id,
        stop: Some(tx),
        task,
    };
    let mut s = Client::connect(addr, id).await.unwrap();
    for n in 0..70 {
        assert_eq!(
            s.deposit(&message_tier(n, 9, Tier::L)).await.unwrap(),
            Ok(())
        );
    }
    // 7 blocked IPv4 connections (one page each at most).
    let fetch = frame::encode(
        &Request::Fetch {
            mailboxes: vec![MailboxId([9; 16])],
            cursor: None,
            max_bytes: 1 << 20,
        },
        MAX_REQUEST_BYTES,
    )
    .unwrap();
    s.close().await;
    let mut held = Vec::new();
    let mut endpoints = Vec::new();
    for _ in 0..7 {
        let (ep, conn) = stuck_connection(addr, id).await;
        for _ in 0..2 {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(&fetch).await.unwrap();
            send.finish().unwrap();
            held.push((send, recv));
        }
        endpoints.push((ep, conn));
    }
    // Four pages (~1 MiB each) fit within the group's share.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.response_bytes.now() < 4_000_000 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "blocked streams not reserved"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        stats.response_bytes.peak() <= PER_IP,
        "{}",
        stats.response_bytes.peak()
    );
    // The IPv4 group is full: its fetch is refused.
    let mut v4c = Client::connect(addr, id).await.unwrap();
    assert!(matches!(
        v4c.fetch(&[MailboxId([9; 16])]).await,
        Err(ClientError::Refused(ErrorReason::RateLimited))
    ));
    // An IPv6 client fetches normally.
    let mut v6c = Client::connect(v6_addr, id).await.unwrap();
    let items = v6c.fetch(&[MailboxId([9; 16])]).await.unwrap();
    assert_eq!(items.len(), 70);
    drop(held);
    drop(endpoints);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_rate_limit_closes_connection() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 1;
        c.limits.burst = 1;
    });
    let s = Client::connect(node.addr, node.id).await.unwrap();
    let mut closed = false;
    for _ in 0..100 {
        if s.request(&Request::Ping { from: None }).await.is_err() {
            closed = true;
            break;
        }
    }
    assert!(closed);
    timeout(LONG, s.connection().closed()).await.unwrap();
    node.stop().await;
}

#[test]
fn limit_defaults_match_spec() {
    let l = LimitConfig::default();
    assert_eq!(
        (
            l.max_connections,
            l.max_connections_per_ip,
            l.requests_per_sec,
            l.bytes_per_sec,
            l.burst
        ),
        (1_000, 8, 20, 1 << 20, 5)
    );
    let c = ServerConfig::new(vec![], key(0));
    assert_eq!(c.hello_timeout, Duration::from_secs(5));
    assert_eq!(c.idle_timeout, Duration::from_secs(60));
    assert_eq!(c.max_streams, 4);
    assert_eq!(c.max_response_bytes_in_flight, 64 << 20);
}

/// The rate bucket is the address group's: reconnecting does not
/// refill it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_does_not_refill_rate_bucket() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 1;
        c.limits.burst = 10;
    });
    let s = Client::connect(node.addr, node.id).await.unwrap();
    // Bucket emptied (without reaching the abuse close).
    let mut drained = false;
    for _ in 0..15 {
        if s.request(&Request::Ping { from: None }).await.unwrap()
            == Response::Error(ErrorReason::RateLimited)
        {
            drained = true;
            break;
        }
    }
    assert!(drained);
    s.close().await;
    // New connection from the same address: still limited.
    let s = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(
        s.request(&Request::Ping { from: None }).await.unwrap(),
        Response::Error(ErrorReason::RateLimited)
    );
    node.stop().await;
}

/// A false proof of work at the base difficulty is refused without
/// taking a place in the database queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_pow_never_takes_db_job() {
    let (_d, path) = db();
    let stats = Arc::new(ServerStats::default());
    let st = stats.clone();
    let node = start_with(
        &path,
        key(0),
        Policy {
            pow_bits: 20,
            ..Policy::default()
        },
        move |c| {
            c.stats = st;
            c.limits.requests_per_sec = 10_000;
        },
    );
    let s = Client::connect(node.addr, node.id).await.unwrap();
    // The startup purge (done before accepting) took its place: forgotten.
    assert_eq!(stats.db_jobs.now(), 0);
    stats.db_jobs.take_peak();
    let mut refused = 0;
    for n in 0..20u32 {
        let p = message(n, 7);
        let h = barking_proto::pow::content_hash(&p);
        // A nonce that does not pass the base difficulty.
        let bad = (0u64..)
            .find(|x| !barking_proto::pow::check(&h, &MailboxId([7; 16]), *x, 20))
            .unwrap();
        let r = s
            .request(&Request::Deposit {
                packet: p,
                pow: bad,
            })
            .await
            .unwrap();
        if r == Response::Error(ErrorReason::PowTooWeak) {
            refused += 1;
        }
    }
    assert_eq!(refused, 20);
    assert_eq!(stats.db_jobs.peak(), 0);
    node.stop().await;
}

/// Resumed fetch: a byte budget cuts the fetch, the next resumes
/// at each mailbox's position; the position survives a change of the
/// mailbox list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumable_fetch_continues_where_it_stopped() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 1 << 30;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..100 {
        assert_eq!(
            s.deposit(&message_tier(n, 9, Tier::L)).await.unwrap(),
            Ok(())
        );
    }
    for n in 0..5 {
        assert_eq!(s.deposit(&message(1000 + n, 8)).await.unwrap(), Ok(()));
    }
    let nine = [MailboxId([9; 16])];
    let mut resume = client::FetchResume::default();
    // Budget under one page: a whole page anyway.
    let first = s.fetch_resumable(&nine, &mut resume, 1).await.unwrap();
    assert!(s.last_fetch_truncated());
    assert_eq!(s.last_fetch_stop(), client::FetchStop::ClientLimit);
    assert!(!first.is_empty() && first.len() < 100);
    assert!(resume.seen[&[9; 16]] > 0);
    // List changed (mailbox 8 added): mailbox 9 resumes at its position,
    // mailbox 8 is read from the start.
    let both = [MailboxId([8; 16]), MailboxId([9; 16])];
    let mut all = first.clone();
    loop {
        let more = s
            .fetch_resumable(&both, &mut resume, 1 << 20)
            .await
            .unwrap();
        all.extend(more);
        if !s.last_fetch_truncated() {
            break;
        }
    }
    let mut want: Vec<Vec<u8>> = (0..100).map(|n| message_tier(n, 9, Tier::L)).collect();
    want.extend((0..5).map(|n| message(1000 + n, 8)));
    for w in &want {
        assert!(all.contains(w));
    }
    // No re-read from the start: at most one page re-read per mailbox.
    assert!(all.len() < want.len() + 70, "{}", all.len());
    // Mailbox removed: forgotten.
    resume.retain(&nine);
    assert!(!resume.seen.contains_key(&[8; 16]));
    node.stop().await;
}

/// The client starts from the base difficulty plus the tier surcharge, and
/// a proof budget stops it before computing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_pow_budget_and_tier_surcharge() {
    let (_d, path) = db();
    let node = start(&path);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(
        s.deposit(&message_tier(1, 5, Tier::L)).await.unwrap(),
        Ok(())
    );
    // A single proof, at base + 6 bits: no new attempt.
    assert_eq!(
        s.pow_spent(),
        barking_proto::pow::expected_work(TEST_BITS + 6)
    );
    s.set_pow_budget(Some(s.pow_spent()));
    assert!(matches!(
        s.deposit(&message(2, 5)).await,
        Err(ClientError::PowBudget)
    ));
    node.stop().await;
}

/// A node that drops the connection after a page: the pickup keeps the
/// page taken, reports a lost connection, and the next call resumes after
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_cut_by_the_node_keeps_taken_pages() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 1 << 30;
        c.test_close_after_fetches = Some(1);
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let want: Vec<Vec<u8>> = (0..100).map(|n| message_tier(n, 9, Tier::L)).collect();
    for p in &want {
        assert_eq!(s.deposit(p).await.unwrap(), Ok(()));
    }
    let nine = [MailboxId([9; 16])];
    let mut resume = client::FetchResume::default();
    let mut all = s
        .fetch_resumable(&nine, &mut resume, 1 << 30)
        .await
        .unwrap();
    assert_eq!(s.last_fetch_stop(), client::FetchStop::Connection);
    assert!(!all.is_empty() && all.len() < want.len(), "{}", all.len());
    // Each new connection takes one more page, from where the last stopped.
    for _ in 0..want.len() {
        let mut s = Client::connect(node.addr, node.id).await.unwrap();
        all.extend(
            s.fetch_resumable(&nine, &mut resume, 1 << 30)
                .await
                .unwrap(),
        );
        if s.last_fetch_stop() == client::FetchStop::Complete {
            break;
        }
        assert_eq!(s.last_fetch_stop(), client::FetchStop::Connection);
    }
    assert_eq!(all, want);
    node.stop().await;
}

/// The node's rate limit after pages already taken: a partial pickup
/// stopped at `RateLimited`; with no page taken, a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_rate_limited_after_pages() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 1 << 30;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let want: Vec<Vec<u8>> = (0..200).map(|n| message_tier(n, 9, Tier::L)).collect();
    for p in &want {
        assert_eq!(s.deposit(p).await.unwrap(), Ok(()));
    }
    s.close().await;
    node.stop().await;
    // Same store, tight bucket: 1 request/s, 4 tokens at the start, 2 per
    // page of a single mailbox.
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 1;
        c.limits.burst = 8;
        c.limits.bytes_per_sec = 1 << 30;
    });
    assert_eq!(barking_node::server::fetch_cost(1), 2);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    let nine = [MailboxId([9; 16])];
    let mut resume = client::FetchResume::default();
    let taken = s
        .fetch_resumable(&nine, &mut resume, 1 << 30)
        .await
        .unwrap();
    assert_eq!(s.last_fetch_stop(), client::FetchStop::RateLimited);
    assert!(
        !taken.is_empty() && taken.len() < want.len(),
        "{}",
        taken.len()
    );
    assert_eq!(taken[..], want[..taken.len()]);
    // Bucket empty: no page taken, the refusal comes back as an error.
    assert!(matches!(
        s.fetch_resumable(&nine, &mut resume, 1 << 30).await,
        Err(ClientError::Refused(ErrorReason::RateLimited))
    ));
    node.stop().await;
}
