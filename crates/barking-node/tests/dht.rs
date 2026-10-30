//! Table de hachage entre nœuds sur 127.0.0.1 : fiches, appels authentifiés,
//! refus et amorçage, avec de vrais nœuds QUIC.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_dht::BootstrapEntry;
use barking_node::config::DhtConfig;
use barking_node::server::{self, ServerConfig};
use barking_node::{NodeStore, Policy};
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
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

/// Graines de clés qui résolvent le puzzle de 20 bits : les trois premières
/// clés de `generate_node_key` sur `StdRng::seed_from_u64(4243)`, tirées une
/// fois en mode optimisé (~15 s par clé sans optimisation). Vérifiées par
/// `test_keys_solve_puzzle`.
const SEEDS: [[u8; 32]; 3] = [
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
        replication_bytes_per_hour: 512 << 20,
    });
    let mut node = start_raw(n, vec![socket].into_iter().chain(v6).collect(), addr, dht);
    node.v6 = v6_addr;
    node
}

/// Démarre le nœud de clé `key(n)` sur `sockets`, joint par les tests à
/// `addr`, avec la table `dht`.
fn start_raw(n: usize, sockets: Vec<UdpSocket>, addr: SocketAddr, dht: Option<DhtConfig>) -> Node {
    let k = key(n);
    let id = id_of(&k);
    let mut cfg = ServerConfig::new(sockets, k);
    cfg.dht = dht;
    cfg.dht_tick = Some(TICK);
    let dir = tempfile::tempdir().unwrap();
    let db: PathBuf = dir.path().join("node.db");
    let store = NodeStore::open(&db).unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(server::run(cfg, store, policy(), async move {
        let _ = rx.await;
    }));
    Node {
        addr,
        v6: None,
        id,
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
        replication_bytes_per_hour: 512 << 20,
    };
    let b = start_raw(
        1,
        vec![b_sock],
        b_addr,
        Some(dht(b_addr, Some(dead_v6), vec![])),
    );
    let a = start_raw(
        0,
        vec![any],
        a_addr,
        Some(dht(a_addr, None, vec![b.entry()])),
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
