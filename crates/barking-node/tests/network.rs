//! Intégration réseau : un vrai nœud QUIC sur 127.0.0.1 (port libre), le
//! client de `barking-proto`, et des pairs bricolés pour les cas hostiles.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::{Core, ReceiveOutcome};
use barking_node::limits::LimitConfig;
use barking_node::server::{self, ServerConfig};
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
    let mut id = [0u8; 16];
    id[..4].copy_from_slice(&n.to_le_bytes());
    id[4] = mb;
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId(id),
        expires_at: u32::try_from(now() + 86_400).unwrap(),
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
    answer: impl Fn(Request) -> Response + Send + Sync + 'static,
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
                    let _ = frame::write(&mut send, &answer(req), frame::MAX_RESPONSE_BYTES).await;
                    let _ = send.finish();
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
    let (addr, srv) = fake_node(k.clone(), move |_| h.clone());
    let r = Client::connect(addr, id_of(&k)).await;
    assert!(matches!(r, Err(ClientError::Protocol(_))), "{:?}", r.err());
    srv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_caps_hostile_pagination() {
    let k = key(0);
    let h = hello(&k, TEST_BITS);
    let (addr, srv) = fake_node(k.clone(), move |req| match req {
        Request::Hello { .. } => h.clone(),
        Request::Fetch { cursor, .. } => Response::Items {
            items: vec![vec![0; 8]; 100],
            next: Some(cursor.unwrap_or(0) + 1),
        },
        _ => Response::Error(ErrorReason::Unsupported),
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
}
