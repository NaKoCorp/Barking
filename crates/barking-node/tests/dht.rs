//! Table de hachage entre nœuds sur 127.0.0.1 : fiches, appels authentifiés,
//! refus et amorçage, avec de vrais nœuds QUIC.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_dht::{BootstrapEntry, DiversityLimits, distance, mailbox_key};
use barking_node::config::{DEFAULT_REPLICATION_BYTES_PER_HOUR, DhtConfig};
use barking_node::server::{self, ServerConfig, ServerStats};
use barking_node::{NodeStore, Policy};
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier, ack};
use barking_proto::client::{self, Client, Session};
use barking_proto::{ErrorReason, NodeId, NodeRecord, RecordPolicy, Request, Response, pow};
use ed25519_dalek::SigningKey;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Délai généreux pour toute attente de test.
const LONG: Duration = Duration::from_secs(20);
/// Difficulté réduite pour des tests rapides.
const TEST_BITS: u8 = 8;
/// Cadence d'entretien des tests.
const TICK: Duration = Duration::from_millis(200);

/// Graines de clés qui résolvent le puzzle de 20 bits : les onze premières
/// clés de `generate_node_key` sur `StdRng::seed_from_u64(4243)`, tirées une
/// fois en mode optimisé (~15 s par clé sans optimisation). Vérifiées par
/// `test_keys_solve_puzzle`.
const SEEDS: [[u8; 32]; 11] = [
    [
        66, 125, 129, 83, 32, 106, 225, 91, 180, 232, 72, 26, 247, 131, 101, 82, 217, 244, 181, 75,
        156, 236, 14, 63, 198, 19, 50, 80, 99, 40, 172, 214,
    ],
    [
        132, 124, 253, 169, 65, 12, 180, 150, 216, 192, 72, 216, 245, 177, 206, 219, 134, 97, 245,
        5, 63, 158, 43, 124, 74, 232, 33, 130, 79, 123, 173, 159,
    ],
    [
        234, 137, 237, 175, 142, 105, 110, 146, 110, 20, 38, 242, 125, 235, 114, 172, 231, 15, 182,
        90, 226, 94, 55, 247, 224, 138, 67, 252, 70, 225, 56, 156,
    ],
    [
        166, 182, 165, 103, 105, 4, 202, 102, 34, 253, 254, 113, 121, 70, 72, 199, 59, 6, 50, 5, 5,
        79, 142, 48, 79, 62, 60, 146, 133, 166, 36, 137,
    ],
    [
        181, 107, 144, 32, 133, 91, 24, 125, 131, 19, 59, 4, 163, 25, 94, 26, 188, 68, 48, 99, 139,
        21, 14, 153, 137, 147, 95, 178, 173, 241, 135, 60,
    ],
    [
        143, 9, 122, 62, 15, 150, 214, 180, 8, 202, 136, 239, 60, 164, 122, 76, 126, 126, 205, 31,
        254, 86, 31, 61, 35, 75, 140, 11, 153, 195, 38, 31,
    ],
    [
        100, 45, 18, 125, 17, 100, 71, 236, 188, 86, 88, 173, 1, 219, 74, 150, 172, 49, 7, 166, 21,
        85, 113, 31, 196, 96, 235, 121, 65, 81, 37, 79,
    ],
    [
        108, 2, 96, 230, 104, 186, 14, 87, 51, 93, 113, 146, 186, 122, 40, 106, 197, 25, 211, 137,
        48, 62, 158, 201, 63, 90, 197, 153, 234, 2, 137, 198,
    ],
    [
        100, 235, 137, 137, 164, 69, 18, 125, 42, 2, 92, 148, 76, 239, 254, 124, 121, 53, 100, 210,
        223, 3, 61, 255, 247, 186, 230, 223, 182, 226, 78, 49,
    ],
    [
        31, 218, 187, 199, 22, 51, 5, 234, 203, 4, 46, 116, 191, 59, 174, 161, 96, 208, 232, 157,
        43, 32, 245, 66, 69, 19, 53, 207, 121, 21, 18, 98,
    ],
    [
        154, 84, 109, 217, 229, 209, 30, 44, 94, 56, 148, 35, 60, 27, 37, 204, 66, 116, 195, 68,
        71, 85, 233, 218, 72, 130, 249, 253, 120, 51, 172, 162,
    ],
];

fn key(n: usize) -> SigningKey {
    SigningKey::from_bytes(&SEEDS[n])
}

#[test]
fn test_keys_solve_puzzle() {
    for n in 0..SEEDS.len() {
        assert!(id_of(&key(n)).puzzle_ok(), "clé {n}");
    }
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
    /// Adresse IPv6 d'écoute, si le nœud a aussi un socket `[::1]`.
    v6: Option<SocketAddr>,
    id: NodeId,
    stats: Arc<ServerStats>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<barking_node::Result<()>>,
    _dir: tempfile::TempDir,
}

impl Node {
    fn entry(&self) -> BootstrapEntry {
        BootstrapEntry {
            id: self.id,
            addr: self.addr,
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        timeout(LONG, self.task).await.unwrap().unwrap().unwrap();
    }
}

/// Démarre le nœud de clé `key(n)` ; table active si `bootstrap` est
/// `Some`, amorcée sur ces nœuds.
fn start(n: usize, bootstrap: Option<Vec<BootstrapEntry>>) -> Node {
    start_with(n, bootstrap, None, false)
}

/// Comme `start`, avec en plus le socket IPv6 `v6`, publié dans la fiche si
/// `publish_v6`.
fn start_with(
    n: usize,
    bootstrap: Option<Vec<BootstrapEntry>>,
    v6: Option<UdpSocket>,
    publish_v6: bool,
) -> Node {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let v6_addr = v6.as_ref().map(|s| s.local_addr().unwrap());
    let dht = bootstrap.map(|bootstrap| DhtConfig {
        public_v4: match addr {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(_) => None,
        },
        public_v6: match v6_addr {
            Some(SocketAddr::V6(a)) if publish_v6 => Some(a),
            _ => None,
        },
        bootstrap,
        allow_private_addrs: true,
        replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
    });
    let sockets = vec![socket].into_iter().chain(v6).collect();
    let mut node = start_raw(n, sockets, addr, dht, DiversityLimits::SPEC);
    node.v6 = v6_addr;
    node
}

/// Démarre le nœud de clé `key(n)` sur `sockets`, joint par les tests à
/// `addr`, avec la table `dht` aux limites de diversité `limits`.
fn start_raw(
    n: usize,
    sockets: Vec<UdpSocket>,
    addr: SocketAddr,
    dht: Option<DhtConfig>,
    limits: DiversityLimits,
) -> Node {
    start_limited(n, sockets, addr, dht, limits, true, TEST_BITS)
}

/// Comme `start_raw` ; `shared_ip` : tous les nœuds et le client de test
/// partagent 127.0.0.1, les plafonds par adresse et le débit de ce groupe
/// sont levés. Sinon seul le plafond de connexions par /24 l'est, et les
/// seaux de débit gardent leurs valeurs de la spec.
fn start_limited(
    n: usize,
    sockets: Vec<UdpSocket>,
    addr: SocketAddr,
    dht: Option<DhtConfig>,
    limits: DiversityLimits,
    shared_ip: bool,
    pow_bits: u8,
) -> Node {
    let k = key(n);
    let id = id_of(&k);
    let mut cfg = ServerConfig::new(sockets, k);
    cfg.dht = dht;
    cfg.dht_tick = Some(TICK);
    cfg.dht_diversity = limits;
    cfg.limits.max_connections_per_ipv4_24 = 1_000;
    if shared_ip {
        cfg.limits.max_connections_per_ip = 1_000;
        cfg.limits.requests_per_sec = 10_000;
        cfg.limits.bytes_per_sec = 1 << 30;
    }
    let stats = Arc::clone(&cfg.stats);
    let dir = tempfile::tempdir().unwrap();
    let db: PathBuf = dir.path().join("node.db");
    let store = NodeStore::open(&db).unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let policy = Policy {
        pow_bits,
        ..Policy::default()
    };
    let task = tokio::spawn(server::run(cfg, store, policy, async move {
        let _ = rx.await;
    }));
    Node {
        addr,
        v6: None,
        id,
        stats,
        stop: Some(tx),
        task,
        _dir: dir,
    }
}

async fn anon(node: &Node) -> Session {
    timeout(LONG, Client::connect(node.addr, node.id))
        .await
        .unwrap()
        .unwrap()
}

/// Connexion d'un nœud appelant, authentifié par le certificat de
/// `key(caller)`.
async fn as_peer(node: &Node, caller: usize) -> (quinn::Endpoint, quinn::Connection) {
    as_peer_at(node, node.addr, caller).await
}

/// Comme `as_peer`, vers l'adresse `addr` du nœud.
async fn as_peer_at(
    node: &Node,
    addr: SocketAddr,
    caller: usize,
) -> (quinn::Endpoint, quinn::Connection) {
    let bind = if addr.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let ep = quinn::Endpoint::client(bind.parse().unwrap()).unwrap();
    let conn = timeout(LONG, client::connect_peer(&ep, addr, node.id, &key(caller)))
        .await
        .unwrap()
        .unwrap();
    (ep, conn)
}

async fn ask(conn: &quinn::Connection, req: &Request) -> Response {
    timeout(LONG, client::request(conn, req))
        .await
        .unwrap()
        .unwrap()
}

fn message(n: u8) -> Vec<u8> {
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId([n; 16]),
        expires_at: u32::try_from(now() + 86_400).unwrap(),
        mailbox: MailboxId([n; 16]),
        payload: vec![n; 16],
    }
    .encode()
}

/// Les quatre requêtes de la table.
fn dht_requests() -> Vec<Request> {
    vec![
        Request::Ping { from: None },
        Request::FindNode {
            target: [0; 32],
            from: None,
        },
        Request::Store {
            packet: message(1),
            pow: 0,
        },
        Request::FindValue {
            mailbox: MailboxId([1; 16]),
            cursor: None,
        },
    ]
}

#[tokio::test]
async fn dht_disabled_without_public_addr() {
    let node = start(0, None);
    let s = anon(&node).await;
    let (_ep, peer) = as_peer(&node, 1).await;
    for req in dht_requests() {
        assert_eq!(
            s.request(&req).await.unwrap(),
            Response::Error(ErrorReason::Unsupported),
            "{req:?}"
        );
        assert_eq!(
            ask(&peer, &req).await,
            Response::Error(ErrorReason::Unsupported),
            "{req:?} (appelant authentifié)"
        );
    }
    node.stop().await;
}

#[tokio::test]
async fn ping_returns_own_record() {
    let node = start(0, Some(vec![]));
    let s = anon(&node).await;
    let Response::Pong { record } = s.request(&Request::Ping { from: None }).await.unwrap() else {
        panic!("Pong attendu");
    };
    assert_eq!(
        record.verify(now(), &RecordPolicy::network(true)),
        Ok(node.id)
    );
    assert_eq!(record.addrs(), vec![node.addr]);
    // Sans adresse privée permise, la fiche de test n'est pas routable.
    assert!(record.verify(now(), &RecordPolicy::network(false)).is_err());
    node.stop().await;
}

#[tokio::test]
async fn anonymous_store_is_unsupported() {
    let node = start(0, Some(vec![]));
    let s = anon(&node).await;
    for req in &dht_requests()[2..] {
        assert_eq!(
            s.request(req).await.unwrap(),
            Response::Error(ErrorReason::Unsupported),
            "{req:?}"
        );
    }
    node.stop().await;
}

#[tokio::test]
async fn from_record_must_match_certificate() {
    let node = start(0, Some(vec![]));
    let addr = match node.addr {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let other = NodeRecord::sign(&key(2), Some(addr), None, now());
    let mine = NodeRecord::sign(&key(1), Some(addr), None, now());
    let (_ep, peer) = as_peer(&node, 1).await;
    // Fiche d'une autre clé que le certificat : refusée.
    for req in [
        Request::Ping {
            from: Some(other.clone()),
        },
        Request::FindNode {
            target: [0; 32],
            from: Some(other.clone()),
        },
    ] {
        assert_eq!(
            ask(&peer, &req).await,
            Response::Error(ErrorReason::Malformed),
            "{req:?}"
        );
    }
    // Fiche jointe par un client anonyme : refusée.
    let s = anon(&node).await;
    assert_eq!(
        s.request(&Request::Ping {
            from: Some(mine.clone())
        })
        .await
        .unwrap(),
        Response::Error(ErrorReason::Malformed)
    );
    // Fiche du certificat : acceptée.
    assert!(matches!(
        ask(&peer, &Request::Ping { from: Some(mine) }).await,
        Response::Pong { .. }
    ));
    node.stop().await;
}

#[tokio::test]
async fn store_and_find_value_from_peer() {
    let node = start(0, Some(vec![]));
    let (_ep, peer) = as_peer(&node, 1).await;
    let packet = message(7);
    let mailbox = MailboxId([7; 16]);
    let hash = pow::content_hash(&packet);
    // Preuve de base sans le palier : trop faible (point 5 de §5.2).
    let weak = pow::solve(&hash, &mailbox, TEST_BITS).unwrap();
    let base = barking_node::rules::pow_bits_for(&policy(), 0, Tier::S, 0);
    let good = pow::solve(&hash, &mailbox, base).unwrap();
    if !pow::check(&hash, &mailbox, weak, base) {
        assert_eq!(
            ask(
                &peer,
                &Request::Store {
                    packet: packet.clone(),
                    pow: weak
                }
            )
            .await,
            Response::Error(ErrorReason::PowTooWeak)
        );
    }
    // Paquet illisible : refusé avant toute autre règle.
    assert_eq!(
        ask(
            &peer,
            &Request::Store {
                packet: vec![1, 2, 3],
                pow: good
            }
        )
        .await,
        Response::Error(ErrorReason::Malformed)
    );
    assert_eq!(
        ask(
            &peer,
            &Request::Store {
                packet: packet.clone(),
                pow: good
            }
        )
        .await,
        Response::Ok
    );
    assert_eq!(
        ask(
            &peer,
            &Request::FindValue {
                mailbox,
                cursor: None
            }
        )
        .await,
        Response::Holdings {
            hashes: vec![hash],
            next: None
        }
    );
    node.stop().await;
}

/// Identifiants renvoyés par `FindNode` sur la table de `node`.
async fn known_by(node: &Node) -> HashSet<NodeId> {
    let s = anon(node).await;
    let Response::Nodes { records } = s
        .request(&Request::FindNode {
            target: node.id.0,
            from: None,
        })
        .await
        .unwrap()
    else {
        panic!("Nodes attendu");
    };
    records
        .iter()
        .map(|r| r.verify(now(), &RecordPolicy::network(true)).unwrap())
        .collect()
}

#[tokio::test]
async fn three_nodes_learn_each_other() {
    let b = start(1, Some(vec![]));
    let a = start(0, Some(vec![b.entry()]));
    let c = start(2, Some(vec![a.entry()]));
    let nodes = [&a, &b, &c];
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        let mut all = true;
        for n in nodes {
            let want: HashSet<NodeId> = nodes
                .iter()
                .map(|m| m.id)
                .filter(|id| *id != n.id)
                .collect();
            if known_by(n).await != want {
                all = false;
            }
        }
        if all {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "les tables ne se sont pas remplies"
        );
        tokio::time::sleep(TICK).await;
    }
    for n in [a, b, c] {
        n.stop().await;
    }
}

/// Socket `[::1]`, ou `None` si l'IPv6 locale manque (test ignoré).
fn local_v6() -> Option<UdpSocket> {
    let s = UdpSocket::bind("[::1]:0").ok();
    if s.is_none() {
        eprintln!("IPv6 local indisponible : test ignoré");
    }
    s
}

#[tokio::test]
async fn recall_requires_source_ip() {
    let Some(v6) = local_v6() else { return };
    let node = start_with(0, Some(vec![]), Some(v6), false);
    // Observateur : l'adresse annoncée par la fiche jointe ; il ne fait que
    // compter les datagrammes reçus (un rappel y enverrait un `Initial`).
    let watch = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(at) = watch.local_addr().unwrap() else {
        unreachable!()
    };
    let record = NodeRecord::sign(&key(1), Some(at), None, now());
    let ping = Request::Ping { from: Some(record) };
    let mut buf = [0u8; 2048];
    // Appel depuis ::1 : la fiche n'annonce pas cette IP, aucun rappel.
    let (_ep6, from_v6) = as_peer_at(&node, node.v6.unwrap(), 1).await;
    assert!(matches!(ask(&from_v6, &ping).await, Response::Pong { .. }));
    assert!(
        timeout(Duration::from_millis(1500), watch.recv_from(&mut buf))
            .await
            .is_err(),
        "rappel vers une adresse que l'appelant n'utilise pas"
    );
    // Appel depuis 127.0.0.1 (autre port que l'adresse annoncée) : rappel.
    let (_ep4, from_v4) = as_peer(&node, 1).await;
    assert!(matches!(ask(&from_v4, &ping).await, Response::Pong { .. }));
    timeout(LONG, watch.recv_from(&mut buf))
        .await
        .expect("rappel attendu")
        .unwrap();
    node.stop().await;
}

#[tokio::test]
async fn dual_stack_peer_is_admitted_by_v4_only_node() {
    let Some(v6) = local_v6() else { return };
    // B publie une IPv4 et une IPv6 ; A n'a qu'un endpoint IPv4 et ne peut
    // pas vérifier l'IPv6 de B : elle est sautée, pas comptée en échec.
    let b = start_with(1, Some(vec![]), Some(v6), true);
    let a = start(0, Some(vec![b.entry()]));
    let deadline = tokio::time::Instant::now() + LONG;
    while !known_by(&a).await.contains(&b.id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "le pair à double pile n'est pas entré"
        );
        tokio::time::sleep(TICK).await;
    }
    // Et il y reste au fil des cycles d'entretien.
    tokio::time::sleep(5 * TICK).await;
    assert!(known_by(&a).await.contains(&b.id));
    for n in [a, b] {
        n.stop().await;
    }
}

#[tokio::test]
async fn dual_stack_listener_publishing_v4_skips_peer_v6() {
    if local_v6().is_none() {
        return;
    }
    // A écoute sur `[::]` (double pile, comme `listen` par défaut) mais ne
    // publie qu'une IPv4 : l'IPv6 d'un pair n'est pas vérifiée chez lui.
    let Ok(any) = UdpSocket::bind("[::]:0") else {
        eprintln!("[::] indisponible : test ignoré");
        return;
    };
    let port = any.local_addr().unwrap().port();
    let a_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    // B publie une IPv4 qui répond et une IPv6 où personne n'écoute.
    let dead = UdpSocket::bind("[::1]:0").unwrap();
    let SocketAddr::V6(dead_v6) = dead.local_addr().unwrap() else {
        unreachable!()
    };
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_addr = b_sock.local_addr().unwrap();
    let dht = |v4: SocketAddr, v6, bootstrap| DhtConfig {
        public_v4: match v4 {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(_) => None,
        },
        public_v6: v6,
        bootstrap,
        allow_private_addrs: true,
        replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
    };
    let b = start_raw(
        1,
        vec![b_sock],
        b_addr,
        Some(dht(b_addr, Some(dead_v6), vec![])),
        DiversityLimits::SPEC,
    );
    let a = start_raw(
        0,
        vec![any],
        a_addr,
        Some(dht(a_addr, None, vec![b.entry()])),
        DiversityLimits::SPEC,
    );
    let deadline = tokio::time::Instant::now() + LONG;
    while !known_by(&a).await.contains(&b.id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "le pair à double pile n'est pas entré"
        );
        tokio::time::sleep(TICK).await;
    }
    tokio::time::sleep(5 * TICK).await;
    assert!(known_by(&a).await.contains(&b.id));
    drop(dead);
    for n in [a, b] {
        n.stop().await;
    }
}

/// Attend que `watch` reste muet pendant `quiet` (les `Initial` d'un appel
/// sans réponse sont répétés jusqu'à son délai).
async fn drain_until_quiet(watch: &tokio::net::UdpSocket, quiet: Duration) {
    let mut buf = [0u8; 2048];
    while timeout(quiet, watch.recv_from(&mut buf)).await.is_ok() {}
}

#[tokio::test]
async fn recall_at_most_once_per_interval() {
    let node = start(0, Some(vec![]));
    let watch = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(at) = watch.local_addr().unwrap() else {
        unreachable!()
    };
    let record = NodeRecord::sign(&key(1), Some(at), None, now());
    let ping = Request::Ping { from: Some(record) };
    let mut buf = [0u8; 2048];
    let (_ep, peer) = as_peer(&node, 1).await;
    assert!(matches!(ask(&peer, &ping).await, Response::Pong { .. }));
    timeout(LONG, watch.recv_from(&mut buf))
        .await
        .expect("premier rappel attendu")
        .unwrap();
    // Le rappel abandonne après son délai (3 s) : plus rien n'arrive.
    drain_until_quiet(&watch, Duration::from_millis(3500)).await;
    // Même identifiant dans les 10 min : aucun nouveau rappel.
    assert!(matches!(ask(&peer, &ping).await, Response::Pong { .. }));
    assert!(
        timeout(Duration::from_millis(2000), watch.recv_from(&mut buf))
            .await
            .is_err(),
        "second rappel du même identifiant dans l'intervalle"
    );
    node.stop().await;
}

#[tokio::test]
async fn dual_stack_record_with_silent_second_address_is_refused() {
    let Some(v6) = local_v6() else { return };
    // A publie IPv4 et IPv6 et peut joindre les deux familles. B publie une
    // IPv4 qui répond et une IPv6 où personne n'écoute : sa fiche n'est pas
    // vérifiée à chacune de ses adresses, il n'entre jamais chez A.
    let dead = UdpSocket::bind("[::1]:0").unwrap();
    let SocketAddr::V6(dead_v6) = dead.local_addr().unwrap() else {
        unreachable!()
    };
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(b_v4) = b_sock.local_addr().unwrap() else {
        unreachable!()
    };
    let b = start_raw(
        1,
        vec![b_sock],
        b_v4.into(),
        Some(DhtConfig {
            public_v4: Some(b_v4),
            public_v6: Some(dead_v6),
            bootstrap: vec![],
            allow_private_addrs: true,
            replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
        }),
        DiversityLimits::SPEC,
    );
    let a = start_with(0, Some(vec![b.entry()]), Some(v6), true);
    // Témoin : B, qui ne joint que l'IPv4, fait entrer A.
    let deadline = tokio::time::Instant::now() + LONG;
    while !known_by(&b).await.contains(&a.id) {
        assert!(tokio::time::Instant::now() < deadline, "A n'est pas entré");
        tokio::time::sleep(TICK).await;
    }
    // Plusieurs délais d'appel plus tard, B n'est toujours pas chez A.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!known_by(&a).await.contains(&b.id));
    drop(dead);
    for n in [a, b] {
        n.stop().await;
    }
}

// --- Recopie entre responsables, sur un réseau de 8 nœuds (spec §5.3, §9) ---

/// Délai des scénarios de recopie (plusieurs passes, délais d'appel de 3 s).
const REPLICATION_WAIT: Duration = Duration::from_secs(90);

/// Limites de diversité des tests : tous les nœuds partagent le /24 de
/// 127.0.0.1.
const LOCAL: DiversityLimits = DiversityLimits::NONE;

/// Démarre le nœud `n` en IPv4 local, table active amorcée sur
/// `bootstrap`, avec `budget` octets de recopie par heure.
fn start_dht(
    n: usize,
    bootstrap: Vec<BootstrapEntry>,
    limits: DiversityLimits,
    budget: u64,
) -> Node {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let SocketAddr::V4(v4) = addr else {
        unreachable!()
    };
    let dht = DhtConfig {
        public_v4: Some(v4),
        public_v6: None,
        bootstrap,
        allow_private_addrs: true,
        replication_bytes_per_hour: budget,
    };
    start_raw(n, vec![socket], addr, Some(dht), limits)
}

/// Attend que chaque nœud de `nodes` connaisse tous les autres.
async fn wait_full_tables(nodes: &[&Node]) {
    let deadline = tokio::time::Instant::now() + LONG;
    for n in nodes {
        let want: HashSet<NodeId> = nodes
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != n.id)
            .collect();
        while !known_by(n).await.is_superset(&want) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "les tables ne se sont pas remplies"
            );
            tokio::time::sleep(TICK).await;
        }
    }
}

/// Réseau des nœuds `keys`, amorcés depuis le premier, démarrés l'un après
/// l'autre (chacun connu du premier avant le suivant), avec `budget(n)`
/// octets de recopie par heure.
async fn network(keys: std::ops::Range<usize>, budget: impl Fn(usize) -> u64) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::new();
    for n in keys {
        let boot = nodes.first().map(|f| vec![f.entry()]).unwrap_or_default();
        let node = start_dht(n, boot, LOCAL, budget(n));
        if let Some(first) = nodes.first() {
            let deadline = tokio::time::Instant::now() + LONG;
            while !known_by(first).await.contains(&node.id) {
                assert!(tokio::time::Instant::now() < deadline, "nœud {n} non joint");
                tokio::time::sleep(TICK).await;
            }
        }
        nodes.push(node);
    }
    wait_full_tables(&nodes.iter().collect::<Vec<_>>()).await;
    nodes
}

/// Indices de `ids` triés par distance à la clé de `mailbox`.
fn by_distance(ids: &[NodeId], mailbox: &MailboxId) -> Vec<usize> {
    let key = mailbox_key(mailbox);
    let mut order: Vec<usize> = (0..ids.len()).collect();
    order.sort_by_key(|&i| distance(&ids[i].0, &key));
    order
}

/// Message `id` de la boîte `mailbox`.
fn message_in(mailbox: MailboxId, id: PacketId) -> Vec<u8> {
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id,
        expires_at: u32::try_from(now() + 86_400).unwrap(),
        mailbox,
        payload: vec![id.0[0]; 16],
    }
    .encode()
}

/// Message accusable et son accusé.
fn message_and_ack(mailbox: MailboxId, secret: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let msg = message_in(mailbox, ack::packet_id_for(&secret));
    let acked = Packet::decode(&msg).unwrap();
    let ack = Packet::ack(&acked, secret, now(), &mut rand::rng()).encode();
    (msg, ack)
}

async fn deposit(node: &Node, packet: &[u8]) {
    let mut s = anon(node).await;
    assert_eq!(
        timeout(LONG, s.deposit(packet)).await.unwrap().unwrap(),
        Ok(())
    );
    s.close().await;
}

/// Ce que `node` sert pour `mailbox`.
async fn held(node: &Node, mailbox: MailboxId) -> Vec<Vec<u8>> {
    let mut s = anon(node).await;
    let items = timeout(LONG, s.fetch(&[mailbox])).await.unwrap().unwrap();
    s.close().await;
    items
}

/// Attend que `cond` soit vrai de chacun de `nodes`.
async fn wait_all<F>(nodes: &[&Node], mailbox: MailboxId, what: &str, cond: F)
where
    F: Fn(&[Vec<u8>]) -> bool,
{
    let deadline = tokio::time::Instant::now() + REPLICATION_WAIT;
    for n in nodes {
        while !cond(&held(n, mailbox).await) {
            assert!(tokio::time::Instant::now() < deadline, "{what}");
            tokio::time::sleep(TICK).await;
        }
    }
}

fn ids(nodes: &[Node]) -> Vec<NodeId> {
    nodes.iter().map(|n| n.id).collect()
}

async fn stop_all(nodes: Vec<Node>) {
    for n in nodes {
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_reaches_all_five_responsibles() {
    let nodes = network(0..8, |_| DEFAULT_REPLICATION_BYTES_PER_HOUR).await;
    let mailbox = MailboxId([0x51; 16]);
    let order = by_distance(&ids(&nodes), &mailbox);
    let msg = message_in(mailbox, PacketId([0x51; 16]));
    for &i in &order[..3] {
        deposit(&nodes[i], &msg).await;
    }
    let five: Vec<&Node> = order[..5].iter().map(|&i| &nodes[i]).collect();
    wait_all(&five, mailbox, "copie absente d'un responsable", |items| {
        items.contains(&msg)
    })
    .await;
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_on_one_clears_all_five() {
    let nodes = network(0..8, |_| DEFAULT_REPLICATION_BYTES_PER_HOUR).await;
    let mailbox = MailboxId([0x52; 16]);
    let order = by_distance(&ids(&nodes), &mailbox);
    let (msg, ack) = message_and_ack(mailbox, [0x52; 16]);
    for &i in &order[..3] {
        deposit(&nodes[i], &msg).await;
    }
    let five: Vec<&Node> = order[..5].iter().map(|&i| &nodes[i]).collect();
    wait_all(&five, mailbox, "copie absente d'un responsable", |items| {
        items.contains(&msg)
    })
    .await;
    deposit(&nodes[order[4]], &ack).await;
    wait_all(
        &five,
        mailbox,
        "message encore servi après l'accusé",
        |items| !items.contains(&msg),
    )
    .await;
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_two_responsibles_recopies_to_next() {
    let nodes = network(0..8, |_| DEFAULT_REPLICATION_BYTES_PER_HOUR).await;
    let mailbox = MailboxId([0x53; 16]);
    let order = by_distance(&ids(&nodes), &mailbox);
    let msg = message_in(mailbox, PacketId([0x53; 16]));
    for &i in &order[..3] {
        deposit(&nodes[i], &msg).await;
    }
    let five: Vec<&Node> = order[..5].iter().map(|&i| &nodes[i]).collect();
    wait_all(&five, mailbox, "copie absente d'un responsable", |items| {
        items.contains(&msg)
    })
    .await;
    // Arrêt des 4ᵉ et 5ᵉ responsables.
    let mut slots: Vec<Option<Node>> = nodes.into_iter().map(Some).collect();
    for &i in &order[3..5] {
        slots[i].take().unwrap().stop().await;
    }
    let holders: Vec<usize> = order[..3].to_vec();
    let passes_at_stop: Vec<u64> = holders
        .iter()
        .map(|&i| slots[i].as_ref().unwrap().stats.replication().passes)
        .collect();
    let next: Vec<&Node> = order[5..7]
        .iter()
        .map(|&i| slots[i].as_ref().unwrap())
        .collect();
    wait_all(
        &next,
        mailbox,
        "pas de recopie vers les suivants",
        |items| items.contains(&msg),
    )
    .await;
    // Recopie dans les 3 passes qui suivent l'arrêt, chez au moins un des
    // gardiens restants : chaque passe sans réponse demande un contrôle de
    // vie (un par pair et par `TICK` ici), 3 contrôles sans réponse
    // retirent le nœud, et la boîte va au suivant dans la même passe. La
    // passe en cours au moment de l'arrêt, qui a pu joindre les nœuds
    // arrêtés, est comptée en plus. Le numéro est celui de la première
    // passe d'envoi après l'arrêt, noté par la passe elle-même.
    let fastest = holders
        .iter()
        .zip(&passes_at_stop)
        .filter_map(|(&i, before)| {
            let r = slots[i].as_ref().unwrap().stats.replication();
            let first = r.sending_passes.iter().find(|p| *p > before)?;
            Some(first - before)
        })
        .min()
        .expect("aucun gardien n'a recopié");
    assert!(
        fastest <= 3 + 1,
        "recopie à la passe {fastest} après l'arrêt"
    );
    stop_all(slots.into_iter().flatten().collect()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_responsible_is_skipped_quietly() {
    // Dix nœuds aux limites locales et un nœud A aux limites de la spec :
    // A ne garde que 2 pairs du /24 local, se croit responsable de toute
    // boîte (moins de 10 nœuds dans sa table), alors que les autres, qui
    // voient 10 nœuds, le savent le plus loin de la clé.
    let mut nodes = network(0..10, |_| DEFAULT_REPLICATION_BYTES_PER_HOUR).await;
    let a = start_dht(
        10,
        vec![nodes[0].entry()],
        DiversityLimits::SPEC,
        DEFAULT_REPLICATION_BYTES_PER_HOUR,
    );
    nodes.push(a);
    let refs: Vec<&Node> = nodes[..10].iter().collect();
    let deadline = tokio::time::Instant::now() + LONG;
    for n in &refs {
        while known_by(n).await.len() < 10 {
            assert!(tokio::time::Instant::now() < deadline, "tables incomplètes");
            tokio::time::sleep(TICK).await;
        }
    }
    // Boîte dont A est le plus loin des 11 nœuds.
    let all = ids(&nodes);
    let mailbox = (0..=255u8)
        .map(|b| MailboxId([b; 16]))
        .find(|m| by_distance(&all, m)[10] == 10)
        .unwrap();
    let a = &nodes[10];
    let msg = message_in(mailbox, PacketId([0x54; 16]));
    deposit(a, &msg).await;
    let deadline = tokio::time::Instant::now() + REPLICATION_WAIT;
    let report = loop {
        let r = a.stats.replication();
        if let Some(last) = r.last.filter(|l| l.not_responsible > 0) {
            break last;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "aucun NotResponsible"
        );
        tokio::time::sleep(TICK).await;
    };
    // Une seule tentative par pair et par passe (A a 2 pairs au plus), rien
    // de recopié, aucun pair sauté.
    assert!(report.not_responsible <= 2, "{report:?}");
    assert_eq!((report.sent, report.skipped_peers), (0, 0), "{report:?}");
    for n in &refs {
        assert!(!held(n, mailbox).await.contains(&msg));
    }
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_copied_before_packet_is_tolerated() {
    // A, seul, reçoit un message puis son accusé : il ne garde que l'accusé.
    let a = start_dht(0, vec![], LOCAL, DEFAULT_REPLICATION_BYTES_PER_HOUR);
    let mailbox = MailboxId([0x55; 16]);
    let (msg, ack) = message_and_ack(mailbox, [0x55; 16]);
    deposit(&a, &msg).await;
    deposit(&a, &ack).await;
    assert_eq!(held(&a, mailbox).await, vec![ack.clone()]);
    // Les autres arrivent ensuite : l'accusé leur est recopié, sans le
    // paquet qu'aucun d'eux n'a.
    let entry = a.entry();
    let mut nodes = vec![a];
    for n in 1..8 {
        nodes.push(start_dht(
            n,
            vec![entry],
            LOCAL,
            DEFAULT_REPLICATION_BYTES_PER_HOUR,
        ));
    }
    wait_full_tables(&nodes.iter().collect::<Vec<_>>()).await;
    let deadline = tokio::time::Instant::now() + REPLICATION_WAIT;
    let report = loop {
        if let Some(last) = nodes[0]
            .stats
            .replication()
            .last
            .filter(|l| l.unknown_ack > 0)
        {
            break last;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "accusé jamais recopié"
        );
        tokio::time::sleep(TICK).await;
    };
    assert_eq!((report.sent, report.skipped_peers), (0, 0), "{report:?}");
    for n in &nodes[1..] {
        assert!(held(n, mailbox).await.is_empty());
    }
    assert_eq!(held(&nodes[0], mailbox).await, vec![ack]);
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replication_budget_stops_pass() {
    let mailbox = MailboxId([0x56; 16]);
    let all: Vec<NodeId> = (0..8).map(|n| id_of(&key(n))).collect();
    let r = by_distance(&all, &mailbox)[0];
    // R n'a droit qu'à 1 octet par heure.
    let nodes = network(0..8, |n| {
        if n == r {
            1
        } else {
            DEFAULT_REPLICATION_BYTES_PER_HOUR
        }
    })
    .await;
    let first = message_in(mailbox, PacketId([0x56; 16]));
    let second = message_in(mailbox, PacketId([0x57; 16]));
    deposit(&nodes[r], &first).await;
    deposit(&nodes[r], &second).await;
    let deadline = tokio::time::Instant::now() + REPLICATION_WAIT;
    while nodes[r].stats.replication().passes < 3 {
        assert!(tokio::time::Instant::now() < deadline, "passes trop lentes");
        tokio::time::sleep(TICK).await;
    }
    let rep = nodes[r].stats.replication();
    // Un élément envoyé, puis plus rien de l'heure.
    assert!(rep.total.bytes <= first.len() as u64, "{rep:?}");
    assert!(rep.total.sent <= 1, "{rep:?}");
    assert!(rep.last.as_ref().unwrap().budget_exhausted, "{rep:?}");
    for (i, n) in nodes.iter().enumerate() {
        if i != r {
            assert!(!held(n, mailbox).await.contains(&second), "nœud {i}");
        }
    }
    stop_all(nodes).await;
}

/// Nœud `n` sur sa propre adresse 127.0.0.(10 + n) (son propre groupe chez
/// les autres), aux seaux de débit de la spec ; `None` si l'adresse ne se
/// lie pas (macOS sans alias de 127.0.0.x).
fn start_own_ip(n: usize, bootstrap: Vec<BootstrapEntry>) -> Option<Node> {
    let ip = std::net::Ipv4Addr::new(127, 0, 0, 10 + u8::try_from(n).unwrap());
    let socket = UdpSocket::bind((ip, 0)).ok()?;
    let SocketAddr::V4(v4) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    let dht = DhtConfig {
        public_v4: Some(v4),
        public_v6: None,
        bootstrap,
        allow_private_addrs: true,
        replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
    };
    Some(start_limited(
        n,
        vec![socket],
        v4.into(),
        Some(dht),
        LOCAL,
        false,
        TEST_BITS,
    ))
}

/// Dépose en réessayant après un `RateLimited` (le client de test a aussi
/// son seau chez le nœud).
async fn deposit_paced(node: &Node, packet: &[u8]) {
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        let mut s = anon(node).await;
        let r = timeout(LONG, s.deposit(packet)).await.unwrap().unwrap();
        s.close().await;
        match r {
            Ok(()) => return,
            Err(ErrorReason::RateLimited) => {
                assert!(tokio::time::Instant::now() < deadline, "dépôt refusé");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => panic!("dépôt refusé : {e:?}"),
        }
    }
}

/// Nombre de `msgs` que `node` sert, ou `None` si la relève est refusée.
async fn count_held(node: &Node, mailbox: MailboxId, msgs: &[Vec<u8>]) -> Option<usize> {
    let mut s = timeout(LONG, Client::connect(node.addr, node.id))
        .await
        .ok()?
        .ok()?;
    let items = timeout(LONG, s.fetch(&[mailbox])).await.ok()?.ok()?;
    s.close().await;
    Some(msgs.iter().filter(|m| items.contains(m)).count())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replication_paces_under_default_rate_limits() {
    // Chaque nœud a sa propre IP : ses appels passent par le seau de son
    // groupe chez l'appelé (20 requêtes/s, rafale ×5), non levé ici.
    let Some(first) = start_own_ip(0, vec![]) else {
        eprintln!("127.0.0.x indisponible (pas d'alias) : test ignoré");
        return;
    };
    let entry = first.entry();
    let mut nodes = vec![first];
    for n in 1..8 {
        let Some(node) = start_own_ip(n, vec![entry]) else {
            eprintln!("127.0.0.x indisponible (pas d'alias) : test ignoré");
            stop_all(nodes).await;
            return;
        };
        nodes.push(node);
    }
    wait_full_tables(&nodes.iter().collect::<Vec<_>>()).await;
    let mailbox = MailboxId([0x58; 16]);
    let order = by_distance(&ids(&nodes), &mailbox);
    // Plus d'éléments que la rafale du seau d'un groupe : sans rythme, la
    // recopie serait refusée (`RateLimited`) en cours de route.
    let msgs: Vec<Vec<u8>> = (0..60u8)
        .map(|i| {
            let mut id = [0x58; 16];
            id[0] = i;
            message_in(mailbox, PacketId(id))
        })
        .collect();
    let r = order[0];
    for m in &msgs {
        deposit_paced(&nodes[r], m).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    let deadline = tokio::time::Instant::now() + 2 * REPLICATION_WAIT;
    for &i in &order[..5] {
        while count_held(&nodes[i], mailbox, &msgs).await != Some(msgs.len()) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "copies incomplètes chez le nœud {i}"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    // La recopie s'est tenue sous le seau : aucun refus de débit, aucun
    // responsable sauté.
    let rep = nodes[r].stats.replication();
    assert_eq!(
        (rep.total.rate_limited, rep.total.skipped_peers),
        (0, 0),
        "{rep:?}"
    );
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn message_too_weak_for_peer_is_not_sent() {
    // P annonce 12 bits de plus que R dans `Hello`. La preuve d'un message
    // déposé chez R vise la difficulté de R : elle n'atteint celle de P
    // qu'avec une chance de 2^-12. R ne lui envoie donc rien.
    let r = start_dht(0, vec![], LOCAL, DEFAULT_REPLICATION_BYTES_PER_HOUR);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(v4) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    let dht = DhtConfig {
        public_v4: Some(v4),
        public_v6: None,
        bootstrap: vec![r.entry()],
        allow_private_addrs: true,
        replication_bytes_per_hour: DEFAULT_REPLICATION_BYTES_PER_HOUR,
    };
    let p = start_limited(
        1,
        vec![socket],
        v4.into(),
        Some(dht),
        LOCAL,
        true,
        TEST_BITS + 12,
    );
    wait_full_tables(&[&r, &p]).await;
    let mailbox = MailboxId([0x59; 16]);
    let msg = message_in(mailbox, PacketId([0x59; 16]));
    deposit(&r, &msg).await;
    let deadline = tokio::time::Instant::now() + REPLICATION_WAIT;
    let rep = loop {
        let rep = r.stats.replication();
        if rep.total.pow_too_weak > 0 {
            break rep;
        }
        assert!(tokio::time::Instant::now() < deadline, "{rep:?}");
        tokio::time::sleep(TICK).await;
    };
    // Rien n'est parti vers P (aucun octet envoyé), qui ne garde rien.
    assert_eq!((rep.total.bytes, rep.total.sent), (0, 0), "{rep:?}");
    assert!(held(&p, mailbox).await.is_empty());
    stop_all(vec![r, p]).await;
}
