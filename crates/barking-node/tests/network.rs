//! Intégration réseau : un vrai nœud QUIC sur 127.0.0.1 (port libre), le
//! client de `barking-proto`, et des pairs bricolés pour les cas hostiles.

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
use barking_proto::{ErrorReason, NodeId, Request, Response, generate_node_key, tls};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Délai généreux pour toute attente de test.
const LONG: Duration = Duration::from_secs(20);
/// Difficulté réduite pour des tests rapides.
const TEST_BITS: u8 = 8;

fn key(n: usize) -> SigningKey {
    static KEYS: OnceLock<Vec<SigningKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(4242);
        (0..2).map(|_| generate_node_key(&mut rng)).collect()
    })[n]
        .clone()
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

/// Paquet de message synthétique valide (palier S) dans la boîte `mb`.
fn message(n: u32, mb: u8) -> Vec<u8> {
    message_tier(n, mb, Tier::S)
}

/// Expiration fixée une fois pour toutes : un même paquet a les mêmes octets
/// d'un appel à l'autre.
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
    // Le nœud peut couper le flux pendant l'envoi : erreurs ignorées.
    let _ = send.write_all(bytes).await;
    if finish {
        let _ = send.finish();
    }
    timeout(LONG, recv.read_to_end(1 << 21))
        .await
        .expect("le nœud doit fermer le flux")
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

    let packets = alice.send_text(&bob_fp, "salut Bob", t, &mut rng).unwrap();
    let mut sa = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(sa.node_id(), node.id);
    assert_eq!(sa.pow_bits(), TEST_BITS);
    for p in &packets {
        assert_eq!(sa.deposit(&p.encode()).await.unwrap(), Ok(()));
    }

    let mut sb = Client::connect(node.addr, node.id).await.unwrap();
    let items = sb.fetch(&bob.watched_mailboxes(t)).await.unwrap();
    assert!(!items.is_empty());
    let mut acks = Vec::new();
    let mut text = None;
    for it in &items {
        if let ReceiveOutcome::Message { text: m, ack, .. } =
            bob.receive(it, "nœud", t, &mut rng).unwrap()
        {
            text = Some(m);
            acks.push(ack);
        }
    }
    assert_eq!(text.as_deref(), Some("salut Bob"));
    for a in &acks {
        assert_eq!(sb.deposit(&a.encode()).await.unwrap(), Ok(()));
    }

    // L'accusé a supprimé la copie : Alice ne relève plus que l'accusé.
    let items = sa.fetch(&alice.watched_mailboxes(t)).await.unwrap();
    let got_ack = items.iter().any(|it| {
        matches!(
            alice.receive(it, "nœud", t, &mut rng).unwrap(),
            ReceiveOutcome::AckReceived { .. }
        )
    });
    assert!(got_ack);
    let again = sb.fetch(&bob.watched_mailboxes(t)).await.unwrap();
    assert!(packets.iter().all(|p| !again.contains(&p.encode())));
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_node_id_refused_by_client() {
    let (_d, path) = db();
    // Le nœud présente un certificat autosigné valide, mais pour un autre
    // identifiant (puzzle résolu) : homme du milieu refusé.
    let node = start_with(&path, key(1), policy(), |_| {});
    let r = Client::connect(node.addr, id_of(&key(0))).await;
    assert!(matches!(r, Err(ClientError::Connect(_))), "{:?}", r.err());
    // Témoin : le bon identifiant passe.
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

/// Pair bricolé : présente le certificat du vrai nœud `victim` mais signe la
/// poignée de main TLS avec une autre clé.
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
    // Nœud d'une version future qui n'accepte plus la version 0.
    let node = start_with(&path, key(0), policy(), |c| {
        c.version = 1;
        c.min_version = 1;
    });
    let r = Client::connect(node.addr, node.id).await;
    assert!(matches!(r, Err(ClientError::Version)), "{:?}", r.err());
    // Requête brute : `Error(VersionTooOld)`, puis fermeture.
    let (_ep, conn) = client::open_connection(node.addr, node.id).await.unwrap();
    let resp = client::request(
        &conn,
        &Request::Hello {
            version: 0,
            min_version: 0,
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
    // Pas de Hello : fermée.
    let (_ep, conn) = client::open_connection(node.addr, node.id).await.unwrap();
    timeout(LONG, conn.closed()).await.unwrap();
    // Hello puis silence : fermée pour inactivité.
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

    // Longueur annoncée au-delà de 64 Kio : flux fermé sans réponse.
    let mut big = ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().to_vec();
    big.extend_from_slice(&[0u8; 1024]);
    assert!(raw_stream(&conn, &big, true).await.is_empty());
    // 4 Gio annoncés : pas de tampon, flux fermé.
    assert!(
        raw_stream(&conn, &u32::MAX.to_be_bytes(), false)
            .await
            .is_empty()
    );
    // Trame tronquée (le client coupe au milieu).
    let mut cut = 100u32.to_be_bytes().to_vec();
    cut.extend_from_slice(&[0u8; 10]);
    assert!(raw_stream(&conn, &cut, true).await.is_empty());
    // Trame tronquée sans fin de flux : coupée par le délai de lecture.
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

    // La même connexion et une seconde connexion sont toujours servies.
    assert_eq!(
        s.request(&Request::Ping).await.unwrap(),
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
        seen.push(s.request(&Request::Ping).await.unwrap());
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
    // Une place se libère à la fermeture.
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
        Request::Ping,
        Request::FindNode { target: [1; 32] },
        Request::Store {
            packet: message(1, 1),
        },
        Request::FindValue {
            mailbox: MailboxId([1; 16]),
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
async fn restart_keeps_confirmed_deposits() {
    let (_d, path) = db();
    let node = start(&path);
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..5 {
        assert_eq!(s.deposit(&message(n, 3)).await.unwrap(), Ok(()));
    }
    drop(s);
    // Arrêt brutal : la tâche du serveur est abandonnée sans fermeture propre.
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
    // Difficulté de base 4 : au-delà de 64 paquets la boîte en exige 5,
    // au-delà de 128, 6. Le client relève sa preuve sur `PowTooWeak`.
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

/// Faux nœud : TLS authentique (clé `k`), réponses fournies par `answer`.
fn fake_node(
    k: SigningKey,
    answer: impl Fn(Request) -> Option<Response> + Send + Sync + 'static,
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
                    match answer(req) {
                        Some(resp) => {
                            let _ = frame::write(&mut send, &resp, frame::MAX_RESPONSE_BYTES).await;
                            let _ = send.finish();
                        }
                        // Flux coupé, comme un nœud dont l'échéance d'écriture expire.
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
        version: 0,
        min_version: 0,
        node_id: id_of(k),
        pow_bits,
        limits: barking_proto::Limits {
            max_mailboxes_per_fetch: 64,
            max_request_bytes: MAX_REQUEST_BYTES as u32,
            max_response_bytes: frame::MAX_RESPONSE_BYTES as u32,
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
    srv.abort();
}

/// Connexion dont le lecteur n'ouvre presque pas sa fenêtre de réception :
/// les réponses restent bloquées côté nœud.
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
            version: 0,
            min_version: 0,
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
        // Échéance d'écriture ≈ request_timeout : test court.
        c.min_send_rate = 1 << 30;
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 1 << 30;
    });
    // Plus d'une page de paquets L dans la boîte 9.
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    for n in 0..70 {
        assert_eq!(
            s.deposit(&message_tier(n, 9, Tier::L)).await.unwrap(),
            Ok(())
        );
    }
    // 3 connexions × 4 flux de relève jamais lus.
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
    // Synchronisation sur la jauge du nœud plutôt qu'un délai fixe.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.response_bytes.now() <= 1 << 20 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "flux bloqués non réservés"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(stats.response_bytes.peak() <= CAP);
    // Un autre client est toujours servi.
    let mut other = Client::connect(node.addr, node.id).await.unwrap();
    assert_eq!(other.deposit(&message(1, 1)).await.unwrap(), Ok(()));
    // Passé `request_timeout`, les flux bloqués sont coupés et la mémoire rendue.
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
    // De quoi rendre une relève de 64 boîtes non instantanée.
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
        // Tours impairs : fermeture pendant que les requêtes sont en cours.
        s.close().await;
        assert!(stats.db_jobs.peak() <= 1);
    }
    // Quatre relèves simultanées pour une seule place : des refus.
    assert!(limited > 0);
    // Toutes les connexions et leurs travaux de base se terminent.
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

/// Lecteur qui arrête le flux (STOP_SENDING) : la réponse est quand même
/// débitée de son seau d'octets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_reader_is_charged() {
    let (_d, path) = db();
    let node = start_with(&path, key(0), policy(), |c| {
        c.limits.requests_per_sec = 10_000;
        c.limits.bytes_per_sec = 100 * 1024;
        c.limits.burst = 2;
    });
    let mut s = Client::connect(node.addr, node.id).await.unwrap();
    // 20 paquets L (320 Kio) déposés depuis une autre connexion (son propre
    // seau, attendu quand il est vide).
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
    // La réponse arrêtée (~320 Kio) dépasse la capacité du seau (200 Kio) :
    // les requêtes suivantes sont limitées tant qu'il n'est pas rechargé.
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        if s.request(&Request::Ping).await.unwrap() == Response::Error(ErrorReason::RateLimited) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "réponse arrêtée non débitée"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = s.fetch(&[]).await;
    node.stop().await;
}

/// Une page trop lente (flux coupé par le nœud) est redemandée plus petite.
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
            // Lien « lent » : toute page au-delà de 64 Kio est coupée.
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
    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            (None, 1 << 20),
            (None, 256 << 10),
            (None, 64 << 10),
            (Some(1), 64 << 10),
            (Some(2), 64 << 10)
        ]
    );
    srv.abort();
}

/// Toutes les tailles coupées : abandon après 16 Kio.
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

/// Le nœud sert la taille de page demandée (plancher 16 Kio).
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
        assert_eq!(items.len(), per_page, "demande {asked}");
        assert!(next.is_some());
    }
    node.stop().await;
}

/// Un groupe d'adresses ne prend que sa part du budget de réponses ; un
/// client d'un autre groupe relève toujours.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_group_capped_share_of_response_budget() {
    let Ok(v6) = UdpSocket::bind("[::1]:0") else {
        eprintln!("IPv6 local indisponible : test ignoré");
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
    // 7 connexions IPv4 bloquées (une page chacune au plus).
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
    // Quatre pages (~1 Mio chacune) tiennent dans la part du groupe.
    let deadline = tokio::time::Instant::now() + LONG;
    while stats.response_bytes.now() < 4_000_000 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "flux bloqués non réservés"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        stats.response_bytes.peak() <= PER_IP,
        "{}",
        stats.response_bytes.peak()
    );
    // Le groupe IPv4 est plein : sa relève est refusée.
    let mut v4c = Client::connect(addr, id).await.unwrap();
    assert!(matches!(
        v4c.fetch(&[MailboxId([9; 16])]).await,
        Err(ClientError::Refused(ErrorReason::RateLimited))
    ));
    // Un client IPv6 relève normalement.
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
        if s.request(&Request::Ping).await.is_err() {
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
