//! Hash table between nodes on 127.0.0.1: records, authenticated calls,
//! refusals and bootstrap, with real QUIC nodes.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_dht::{BootstrapEntry, DiversityLimits, distance, mailbox_key};
use barking_node::Policy;
use barking_node::config::{DEFAULT_REPLICATION_BYTES_PER_HOUR, DhtConfig};
use barking_node::testing::{
    LOCAL, LONG, NodeSpec, TEST_BITS, TICK, TestNode as Node, anon, id_of, key, known_by, network,
    start_dht, start_node, stop_all, wait_full_tables,
};
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier, ack};
use barking_proto::client::{self, Client};
use barking_proto::{ErrorReason, NodeId, NodeRecord, RecordPolicy, Request, Response, pow};
use tokio::time::timeout;

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

/// Starts the node with key `key(n)`; table active if `bootstrap` is
/// `Some`, bootstrapped on those nodes.
fn start(n: usize, bootstrap: Option<Vec<BootstrapEntry>>) -> Node {
    start_with(n, bootstrap, None, false)
}

/// Like `start`, plus the IPv6 socket `v6`, published in the record if
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

/// Starts the node with key `key(n)` on `sockets`, reached by the tests at
/// `addr`, with the `dht` table at diversity limits `limits`.
fn start_raw(
    n: usize,
    sockets: Vec<UdpSocket>,
    addr: SocketAddr,
    dht: Option<DhtConfig>,
    limits: DiversityLimits,
) -> Node {
    start_limited(n, sockets, addr, dht, limits, true, TEST_BITS)
}

/// Like `start_raw`; `shared_ip`: all nodes and the test client
/// share 127.0.0.1, the per-address caps and this group's rate
/// are lifted. Otherwise only the per-/24 connection cap is, and the
/// rate buckets keep their spec values.
fn start_limited(
    n: usize,
    sockets: Vec<UdpSocket>,
    addr: SocketAddr,
    dht: Option<DhtConfig>,
    limits: DiversityLimits,
    shared_ip: bool,
    pow_bits: u8,
) -> Node {
    let mut spec = NodeSpec::new(n, dht);
    spec.limits = limits;
    spec.shared_ip = shared_ip;
    spec.pow_bits = pow_bits;
    start_node(spec, sockets, addr)
}

/// Connection of a calling node, authenticated by the certificate of
/// `key(caller)`.
async fn as_peer(node: &Node, caller: usize) -> (quinn::Endpoint, quinn::Connection) {
    as_peer_at(node, node.addr, caller).await
}

/// Like `as_peer`, to the node's address `addr`.
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

/// The four table requests.
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
            "{req:?} (authenticated caller)"
        );
    }
    node.stop().await;
}

#[tokio::test]
async fn ping_returns_own_record() {
    let node = start(0, Some(vec![]));
    let s = anon(&node).await;
    let Response::Pong { record } = s.request(&Request::Ping { from: None }).await.unwrap() else {
        panic!("Pong expected");
    };
    assert_eq!(
        record.verify(now(), &RecordPolicy::network(true)),
        Ok(node.id)
    );
    assert_eq!(record.addrs(), vec![node.addr]);
    // Without private addresses allowed, the test record is not routable.
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
    // Record of a key other than the certificate's: refused.
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
    // Record attached by an anonymous client: refused.
    let s = anon(&node).await;
    assert_eq!(
        s.request(&Request::Ping {
            from: Some(mine.clone())
        })
        .await
        .unwrap(),
        Response::Error(ErrorReason::Malformed)
    );
    // Certificate's record: accepted.
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
    // Base proof without the tier: too weak (point 5 of §5.2).
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
    // Unreadable packet: refused before any other rule.
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
            "the tables did not fill up"
        );
        tokio::time::sleep(TICK).await;
    }
    for n in [a, b, c] {
        n.stop().await;
    }
}

/// `[::1]` socket, or `None` if local IPv6 is missing (test skipped).
fn local_v6() -> Option<UdpSocket> {
    let s = UdpSocket::bind("[::1]:0").ok();
    if s.is_none() {
        eprintln!("local IPv6 unavailable: test skipped");
    }
    s
}

#[tokio::test]
async fn recall_requires_source_ip() {
    let Some(v6) = local_v6() else { return };
    let node = start_with(0, Some(vec![]), Some(v6), false);
    // Observer: the address announced by the attached record; it only
    // counts received datagrams (a callback would send an `Initial` there).
    let watch = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(at) = watch.local_addr().unwrap() else {
        unreachable!()
    };
    let record = NodeRecord::sign(&key(1), Some(at), None, now());
    let ping = Request::Ping { from: Some(record) };
    let mut buf = [0u8; 2048];
    // Call from ::1: the record does not announce this IP, no callback.
    let (_ep6, from_v6) = as_peer_at(&node, node.v6.unwrap(), 1).await;
    assert!(matches!(ask(&from_v6, &ping).await, Response::Pong { .. }));
    assert!(
        timeout(Duration::from_millis(1500), watch.recv_from(&mut buf))
            .await
            .is_err(),
        "callback to an address the caller does not use"
    );
    // Call from 127.0.0.1 (port other than the announced address): callback.
    let (_ep4, from_v4) = as_peer(&node, 1).await;
    assert!(matches!(ask(&from_v4, &ping).await, Response::Pong { .. }));
    timeout(LONG, watch.recv_from(&mut buf))
        .await
        .expect("callback expected")
        .unwrap();
    node.stop().await;
}

#[tokio::test]
async fn dual_stack_peer_is_admitted_by_v4_only_node() {
    let Some(v6) = local_v6() else { return };
    // B publishes an IPv4 and an IPv6; A has only an IPv4 endpoint and cannot
    // verify B's IPv6: it is skipped, not counted as a failure.
    let b = start_with(1, Some(vec![]), Some(v6), true);
    let a = start(0, Some(vec![b.entry()]));
    let deadline = tokio::time::Instant::now() + LONG;
    while !known_by(&a).await.contains(&b.id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dual-stack peer did not enter"
        );
        tokio::time::sleep(TICK).await;
    }
    // And it stays there across maintenance cycles.
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
    // A listens on `[::]` (dual stack, like the default `listen`) but only
    // publishes an IPv4: a peer's IPv6 is not verified here.
    let Ok(any) = UdpSocket::bind("[::]:0") else {
        eprintln!("[::] unavailable: test skipped");
        return;
    };
    let port = any.local_addr().unwrap().port();
    let a_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    // B publishes an IPv4 that answers and an IPv6 where nobody listens.
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
            "the dual-stack peer did not enter"
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

/// Waits for `watch` to stay silent for `quiet` (the `Initial`s of an
/// unanswered call are repeated until its timeout).
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
        .expect("first callback expected")
        .unwrap();
    // The callback gives up after its timeout (3 s): nothing arrives anymore.
    drain_until_quiet(&watch, Duration::from_millis(3500)).await;
    // Same identifier within 10 min: no new callback.
    assert!(matches!(ask(&peer, &ping).await, Response::Pong { .. }));
    assert!(
        timeout(Duration::from_millis(2000), watch.recv_from(&mut buf))
            .await
            .is_err(),
        "second callback for the same identifier within the interval"
    );
    node.stop().await;
}

#[tokio::test]
async fn dual_stack_record_with_silent_second_address_is_refused() {
    let Some(v6) = local_v6() else { return };
    // A publishes IPv4 and IPv6 and can reach both families. B publishes an
    // IPv4 that answers and an IPv6 where nobody listens: its record is not
    // verified at each of its addresses, it never enters A.
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
    // Control: B, which reaches only IPv4, makes A enter.
    let deadline = tokio::time::Instant::now() + LONG;
    while !known_by(&b).await.contains(&a.id) {
        assert!(tokio::time::Instant::now() < deadline, "A did not enter");
        tokio::time::sleep(TICK).await;
    }
    // Several call timeouts later, B is still not in A.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!known_by(&a).await.contains(&b.id));
    drop(dead);
    for n in [a, b] {
        n.stop().await;
    }
}

// --- Replication between responsible nodes, on an 8-node network (spec §5.3, §9) ---

/// Timeout of the replication scenarios (several passes, 3 s call timeouts).
const REPLICATION_WAIT: Duration = Duration::from_secs(90);

/// Indices of `ids` sorted by distance to the key of `mailbox`.
fn by_distance(ids: &[NodeId], mailbox: &MailboxId) -> Vec<usize> {
    let key = mailbox_key(mailbox);
    let mut order: Vec<usize> = (0..ids.len()).collect();
    order.sort_by_key(|&i| distance(&ids[i].0, &key));
    order
}

/// Message `id` of mailbox `mailbox`.
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

/// Acknowledgeable message and its ack.
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

/// What `node` serves for `mailbox`.
async fn held(node: &Node, mailbox: MailboxId) -> Vec<Vec<u8>> {
    let mut s = anon(node).await;
    let items = timeout(LONG, s.fetch(&[mailbox])).await.unwrap().unwrap();
    s.close().await;
    items
}

/// Waits for `cond` to hold for each of `nodes`.
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
    wait_all(
        &five,
        mailbox,
        "copy missing from a responsible node",
        |items| items.contains(&msg),
    )
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
    wait_all(
        &five,
        mailbox,
        "copy missing from a responsible node",
        |items| items.contains(&msg),
    )
    .await;
    deposit(&nodes[order[4]], &ack).await;
    wait_all(
        &five,
        mailbox,
        "message still served after the ack",
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
    wait_all(
        &five,
        mailbox,
        "copy missing from a responsible node",
        |items| items.contains(&msg),
    )
    .await;
    // Shutdown of the 4th and 5th responsible nodes.
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
        "no replication to the following ones",
        |items| items.contains(&msg),
    )
    .await;
    // Replication within the 3 passes following the shutdown, at at least one of
    // the remaining holders: each unanswered pass requests a liveness
    // check (one per peer and per `TICK` here), 3 unanswered checks
    // remove the node, and the mailbox goes to the next one in the same pass. The
    // pass in progress at the time of the shutdown, which may have reached the
    // stopped nodes, is counted on top. The number is that of the first
    // sending pass after the shutdown, noted by the pass itself.
    let fastest = holders
        .iter()
        .zip(&passes_at_stop)
        .filter_map(|(&i, before)| {
            let r = slots[i].as_ref().unwrap().stats.replication();
            let first = r.sending_passes.iter().find(|p| *p > before)?;
            Some(first - before)
        })
        .min()
        .expect("no holder replicated");
    assert!(
        fastest <= 3 + 1,
        "replication at pass {fastest} after the shutdown"
    );
    stop_all(slots.into_iter().flatten().collect()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_responsible_is_skipped_quietly() {
    // Ten nodes at local limits and a node A at the spec's limits:
    // A keeps only 2 peers of the local /24, believes itself responsible for any
    // mailbox (fewer than 10 nodes in its table), whereas the others, who
    // see 10 nodes, know it to be the farthest from the key.
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
            assert!(tokio::time::Instant::now() < deadline, "incomplete tables");
            tokio::time::sleep(TICK).await;
        }
    }
    // Mailbox for which A is the farthest of the 11 nodes.
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
        assert!(tokio::time::Instant::now() < deadline, "no NotResponsible");
        tokio::time::sleep(TICK).await;
    };
    // A single attempt per peer and per pass (A has at most 2 peers), nothing
    // replicated, no peer skipped.
    assert!(report.not_responsible <= 2, "{report:?}");
    assert_eq!((report.sent, report.skipped_peers), (0, 0), "{report:?}");
    for n in &refs {
        assert!(!held(n, mailbox).await.contains(&msg));
    }
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_copied_before_packet_is_tolerated() {
    // A, alone, receives a message then its ack: it keeps only the ack.
    let a = start_dht(0, vec![], LOCAL, DEFAULT_REPLICATION_BYTES_PER_HOUR);
    let mailbox = MailboxId([0x55; 16]);
    let (msg, ack) = message_and_ack(mailbox, [0x55; 16]);
    deposit(&a, &msg).await;
    deposit(&a, &ack).await;
    assert_eq!(held(&a, mailbox).await, vec![ack.clone()]);
    // The others arrive afterwards: the ack is replicated to them, without the
    // packet that none of them has.
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
            "ack never replicated"
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
    // R is entitled to only 1 byte per hour.
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
        assert!(tokio::time::Instant::now() < deadline, "passes too slow");
        tokio::time::sleep(TICK).await;
    }
    let rep = nodes[r].stats.replication();
    // One item sent, then nothing more for the hour.
    assert!(rep.total.bytes <= first.len() as u64, "{rep:?}");
    assert!(rep.total.sent <= 1, "{rep:?}");
    assert!(rep.last.as_ref().unwrap().budget_exhausted, "{rep:?}");
    for (i, n) in nodes.iter().enumerate() {
        if i != r {
            assert!(!held(n, mailbox).await.contains(&second), "node {i}");
        }
    }
    stop_all(nodes).await;
}

/// Node `n` on its own address 127.0.0.(10 + n) (its own group at
/// the others), at the spec's rate buckets; `None` if the address does not
/// bind (macOS without 127.0.0.x aliases).
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

/// Deposits, retrying after a `RateLimited` (the test client also has
/// its bucket at the node).
async fn deposit_paced(node: &Node, packet: &[u8]) {
    let deadline = tokio::time::Instant::now() + LONG;
    loop {
        let mut s = anon(node).await;
        let r = timeout(LONG, s.deposit(packet)).await.unwrap().unwrap();
        s.close().await;
        match r {
            Ok(()) => return,
            Err(ErrorReason::RateLimited) => {
                assert!(tokio::time::Instant::now() < deadline, "deposit refused");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => panic!("deposit refused: {e:?}"),
        }
    }
}

/// Number of `msgs` that `node` serves, or `None` if the fetch is refused.
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
    // Each node has its own IP: its calls go through its group's bucket
    // at the callee (20 requests/s, burst x5), not lifted here.
    let Some(first) = start_own_ip(0, vec![]) else {
        eprintln!("127.0.0.x unavailable (no alias): test skipped");
        return;
    };
    let entry = first.entry();
    let mut nodes = vec![first];
    for n in 1..8 {
        let Some(node) = start_own_ip(n, vec![entry]) else {
            eprintln!("127.0.0.x unavailable (no alias): test skipped");
            stop_all(nodes).await;
            return;
        };
        nodes.push(node);
    }
    wait_full_tables(&nodes.iter().collect::<Vec<_>>()).await;
    let mailbox = MailboxId([0x58; 16]);
    let order = by_distance(&ids(&nodes), &mailbox);
    // More items than a group bucket's burst: without pacing, the
    // replication would be refused (`RateLimited`) along the way.
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
                "incomplete copies at node {i}"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    // Replication stayed under the bucket: no rate refusal, no
    // responsible node skipped.
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
    // P announces 12 bits more than R in `Hello`. The proof of a message
    // deposited at R targets R's difficulty: it reaches P's only with a
    // 2^-12 chance. R therefore sends it nothing.
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
    // Nothing went to P (no byte sent), which keeps nothing.
    assert_eq!((rep.total.bytes, rep.total.sent), (0, 0), "{rep:?}");
    assert!(held(&p, mailbox).await.is_empty());
    stop_all(vec![r, p]).await;
}
