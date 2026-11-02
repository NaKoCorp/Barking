//! Test harness: real nodes on 127.0.0.1, for the integration tests of this
//! crate and of the client crates (`barking-net`, `barking-cli`).
//!
//! Behind the non-default `test-harness` feature: production builds
//! (`scripts/repro-build.sh`, `cargo build -p barking-node`) never compile
//! it. Everything here relaxes the spec for a single shared address: private
//! addresses allowed, diversity limits lifted, per-address caps raised,
//! cadences brought down to `TICK`, and the test-only hooks of
//! `ServerConfig` (`test_swallow_deposits`, `test_response_delay`,
//! `test_send_rate`).

use std::collections::HashSet;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_dht::{BootstrapEntry, DiversityLimits};
use barking_proto::client::{Client, Session};
use barking_proto::{NodeId, RecordPolicy, Request, Response};
use ed25519_dalek::SigningKey;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::{DEFAULT_REPLICATION_BYTES_PER_HOUR, DhtConfig};
use crate::server::{self, ServerConfig, ServerStats};
use crate::wake::WakeConfig;
use crate::{NodeStore, Policy};

/// Generous timeout for any test wait.
pub const LONG: Duration = Duration::from_secs(20);
/// Reduced proof-of-work difficulty for fast tests.
pub const TEST_BITS: u8 = 8;
/// Maintenance and replication cadence of the test nodes.
pub const TICK: Duration = Duration::from_millis(200);
/// Diversity limits of the local networks: all nodes share the /24 of
/// 127.0.0.1.
pub const LOCAL: DiversityLimits = DiversityLimits::NONE;

/// Key seeds that solve the 20-bit puzzle: the first eleven keys of
/// `generate_node_key` on `StdRng::seed_from_u64(4243)`, drawn once in
/// optimized mode (~15 s per key without optimization).
pub const SEEDS: [[u8; 32]; 11] = [
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

/// Node key `n` (a seed of `SEEDS`).
pub fn key(n: usize) -> SigningKey {
    SigningKey::from_bytes(&SEEDS[n])
}

pub fn id_of(k: &SigningKey) -> NodeId {
    NodeId::from_public_key(&k.verifying_key())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// How a test node runs; kept so that it can be restarted as it was.
#[derive(Clone, Debug)]
pub struct NodeSpec {
    /// Key index in `SEEDS`.
    pub n: usize,
    /// Hash table; `None`: plain relay.
    pub dht: Option<DhtConfig>,
    /// Diversity limits of the table.
    pub limits: DiversityLimits,
    /// All nodes and the test clients share 127.0.0.1: the per-address
    /// caps and that group's rate are lifted. Otherwise only the per-/24
    /// connection cap is, and the rate buckets keep their spec values.
    pub shared_ip: bool,
    /// Base proof-of-work difficulty.
    pub pow_bits: u8,
    /// `ServerConfig::test_swallow_deposits`.
    pub swallow_deposits: bool,
    /// `ServerConfig::test_response_delay`.
    pub response_delay: Option<Duration>,
    /// `ServerConfig::test_send_rate`.
    pub send_rate: Option<u64>,
    /// `ServerConfig::wake`.
    pub wake: WakeConfig,
    /// `ServerConfig::wake_allow_private`: the fake relay is on 127.0.0.1.
    pub wake_allow_private: bool,
}

impl NodeSpec {
    /// Node `n` with the table `dht`, spec diversity limits, shared
    /// address, `TEST_BITS`, no hook.
    pub fn new(n: usize, dht: Option<DhtConfig>) -> NodeSpec {
        NodeSpec {
            n,
            dht,
            limits: DiversityLimits::SPEC,
            shared_ip: true,
            pow_bits: TEST_BITS,
            swallow_deposits: false,
            response_delay: None,
            send_rate: None,
            wake: WakeConfig::default(),
            wake_allow_private: false,
        }
    }
}

/// A node running in the test's runtime.
pub struct TestNode {
    /// Address the tests reach it at.
    pub addr: SocketAddr,
    /// Listening IPv6 address, if the node also has a `[::1]` socket.
    pub v6: Option<SocketAddr>,
    pub id: NodeId,
    pub stats: Arc<ServerStats>,
    spec: NodeSpec,
    stop: oneshot::Sender<()>,
    task: JoinHandle<crate::Result<()>>,
    dir: tempfile::TempDir,
}

/// A stopped node, its database kept, to start again on the same address.
pub struct StoppedNode {
    pub addr: SocketAddr,
    /// Settings of the next start (the previous ones by default).
    pub spec: NodeSpec,
    dir: tempfile::TempDir,
}

impl TestNode {
    /// Earliest time a pending wake-up becomes due, read from the node's
    /// database (`None`: no subscription is pending).
    pub fn wake_next_due(&self) -> Option<u64> {
        let store = NodeStore::open_read_only(self.dir.path().join("node.db"))
            .expect("node database opens read-only");
        crate::wake::next_due(&store).expect("next_due reads")
    }

    pub fn entry(&self) -> BootstrapEntry {
        BootstrapEntry {
            id: self.id,
            addr: self.addr,
        }
    }

    /// Stops the node and drops its database.
    pub async fn stop(self) {
        self.halt().await;
    }

    /// Stops the node, keeping its database for `StoppedNode::restart`.
    pub async fn halt(self) -> StoppedNode {
        let _ = self.stop.send(());
        timeout(LONG, self.task)
            .await
            .expect("node stops in time")
            .expect("node task")
            .expect("node ran");
        StoppedNode {
            addr: self.addr,
            spec: self.spec,
            dir: self.dir,
        }
    }
}

impl StoppedNode {
    /// Starts the node again on its address, with its database.
    pub async fn restart(self) -> TestNode {
        // The port was just released: retried briefly if still held.
        let deadline = tokio::time::Instant::now() + LONG;
        let socket = loop {
            match UdpSocket::bind(self.addr) {
                Ok(s) => break s,
                Err(e) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "port not released: {e}"
                    );
                    tokio::time::sleep(TICK).await;
                }
            }
        };
        launch(self.spec, vec![socket], self.addr, self.dir)
    }
}

/// Starts node `spec` on `sockets`, reached by the tests at `addr`, with a
/// fresh database.
pub fn start_node(spec: NodeSpec, sockets: Vec<UdpSocket>, addr: SocketAddr) -> TestNode {
    let dir = tempfile::tempdir().expect("temporary directory");
    launch(spec, sockets, addr, dir)
}

fn launch(
    spec: NodeSpec,
    sockets: Vec<UdpSocket>,
    addr: SocketAddr,
    dir: tempfile::TempDir,
) -> TestNode {
    let k = key(spec.n);
    let id = id_of(&k);
    let mut cfg = ServerConfig::new(sockets, k);
    cfg.dht = spec.dht.clone();
    cfg.dht_tick = Some(TICK);
    cfg.dht_diversity = spec.limits;
    cfg.limits.max_connections_per_ipv4_24 = 1_000;
    if spec.shared_ip {
        cfg.limits.max_connections_per_ip = 1_000;
        cfg.limits.requests_per_sec = 10_000;
        cfg.limits.bytes_per_sec = 1 << 30;
    }
    cfg.test_swallow_deposits = spec.swallow_deposits;
    cfg.test_response_delay = spec.response_delay;
    cfg.test_send_rate = spec.send_rate;
    cfg.wake = spec.wake.clone();
    cfg.wake_allow_private = spec.wake_allow_private;
    let stats = Arc::clone(&cfg.stats);
    let store = NodeStore::open(dir.path().join("node.db")).expect("node database");
    let (tx, rx) = oneshot::channel::<()>();
    let policy = Policy {
        pow_bits: spec.pow_bits,
        ..Policy::default()
    };
    let task = tokio::spawn(server::run(cfg, store, policy, async move {
        let _ = rx.await;
    }));
    TestNode {
        addr,
        v6: None,
        id,
        stats,
        spec,
        stop: tx,
        task,
        dir,
    }
}

/// Table settings of a node at `v4`, private addresses allowed.
pub fn local_dht(v4: SocketAddrV4, bootstrap: Vec<BootstrapEntry>, budget: u64) -> DhtConfig {
    DhtConfig {
        public_v4: Some(v4),
        public_v6: None,
        bootstrap,
        allow_private_addrs: true,
        replication_bytes_per_hour: budget,
    }
}

/// A free port on 127.0.0.1.
pub fn local_socket() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("local socket");
    let SocketAddr::V4(v4) = socket.local_addr().expect("local address") else {
        unreachable!("bound on IPv4")
    };
    (socket, v4)
}

/// Starts node `n` on local IPv4, table active bootstrapped on
/// `bootstrap`, with `budget` replication bytes per hour.
pub fn start_dht(
    n: usize,
    bootstrap: Vec<BootstrapEntry>,
    limits: DiversityLimits,
    budget: u64,
) -> TestNode {
    let (socket, v4) = local_socket();
    let mut spec = NodeSpec::new(n, Some(local_dht(v4, bootstrap, budget)));
    spec.limits = limits;
    start_node(spec, vec![socket], SocketAddr::V4(v4))
}

/// Anonymous session with `node`.
pub async fn anon(node: &TestNode) -> Session {
    timeout(LONG, Client::connect(node.addr, node.id))
        .await
        .expect("connects in time")
        .expect("connects")
}

/// Identifiers returned by `FindNode` on `node`'s table.
pub async fn known_by(node: &TestNode) -> HashSet<NodeId> {
    let s = anon(node).await;
    let Response::Nodes { records } = s
        .request(&Request::FindNode {
            target: node.id.0,
            from: None,
        })
        .await
        .expect("FindNode answered")
    else {
        panic!("Nodes expected");
    };
    records
        .iter()
        .map(|r| {
            r.verify(now(), &RecordPolicy::network(true))
                .expect("valid record")
        })
        .collect()
}

/// Waits for each node of `nodes` to know all the others.
pub async fn wait_full_tables(nodes: &[&TestNode]) {
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
                "the tables did not fill up"
            );
            tokio::time::sleep(TICK).await;
        }
    }
}

/// Network of the nodes `keys`, bootstrapped from the first, started one
/// after the other (each known to the first before the next), with
/// `budget(n)` replication bytes per hour.
pub async fn network(keys: std::ops::Range<usize>, budget: impl Fn(usize) -> u64) -> Vec<TestNode> {
    network_with(keys, |spec| {
        if let Some(d) = &mut spec.dht {
            d.replication_bytes_per_hour = budget(spec.n);
        }
    })
    .await
}

/// Like `network`, at the default replication budget, each node's settings
/// adjusted by `configure` before it starts.
pub async fn network_with(
    keys: std::ops::Range<usize>,
    configure: impl Fn(&mut NodeSpec),
) -> Vec<TestNode> {
    let mut nodes: Vec<TestNode> = Vec::new();
    for n in keys {
        let boot = nodes.first().map(|f| vec![f.entry()]).unwrap_or_default();
        let (socket, v4) = local_socket();
        let mut spec = NodeSpec::new(
            n,
            Some(local_dht(v4, boot, DEFAULT_REPLICATION_BYTES_PER_HOUR)),
        );
        spec.limits = LOCAL;
        configure(&mut spec);
        let node = start_node(spec, vec![socket], SocketAddr::V4(v4));
        if let Some(first) = nodes.first() {
            let deadline = tokio::time::Instant::now() + LONG;
            while !known_by(first).await.contains(&node.id) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "node {n} not reached"
                );
                tokio::time::sleep(TICK).await;
            }
        }
        nodes.push(node);
    }
    wait_full_tables(&nodes.iter().collect::<Vec<_>>()).await;
    nodes
}

/// Stops every node of `nodes`.
pub async fn stop_all(nodes: Vec<TestNode>) {
    for n in nodes {
        n.stop().await;
    }
}

/// Minimal push relay for tests: QUIC server that answers `Hello`,
/// records the items of every `Wake` and answers `Ok`. Key: the last of `SEEDS`.
pub struct FakeRelay {
    addr: SocketAddr,
    id: NodeId,
    received: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    conns: Arc<std::sync::Mutex<Vec<quinn::Connection>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeRelay {
    pub async fn start() -> FakeRelay {
        use barking_proto::frame::{self, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
        // Clients check the node puzzle on the TLS identity: only a key of
        // `SEEDS` works (the last one; `key(900)` does not exist).
        let k = key(SEEDS.len() - 1);
        let id = id_of(&k);
        // One endpoint per family on the same port (no reliance on the
        // dual-stack default of the host): a name such as `localhost` may
        // resolve to `::1` before `127.0.0.1`, and a relay serving only one of
        // them would stall the sender until its connect timeout.
        let ep = quinn::Endpoint::server(
            barking_proto::tls::quinn_server_config(&k),
            "127.0.0.1:0".parse().unwrap(),
        )
        .expect("binds a local UDP socket");
        let addr = ep.local_addr().unwrap();
        let received: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let log = received.clone();
        let conns: Arc<std::sync::Mutex<Vec<quinn::Connection>>> = Arc::default();
        let kept = conns.clone();
        let port = addr.port();
        let ep6 = quinn::Endpoint::server(
            barking_proto::tls::quinn_server_config(&k),
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        )
        .ok();
        let mut tasks = Vec::new();
        for ep in std::iter::once(ep).chain(ep6) {
            let log = log.clone();
            let kept = kept.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(incoming) = ep.accept().await {
                    let log = log.clone();
                    let kept = kept.clone();
                    tokio::spawn(async move {
                        let Ok(conn) = incoming.await else { return };
                        kept.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(conn.clone());
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let Ok(req) =
                                frame::read::<Request>(&mut recv, MAX_REQUEST_BYTES).await
                            else {
                                return;
                            };
                            let resp = match req {
                                Request::Hello { .. } => Response::Hello {
                                    version: 1,
                                    min_version: 1,
                                    node_id: id,
                                    pow_bits: TEST_BITS,
                                    limits: barking_proto::Limits {
                                        max_mailboxes_per_fetch: 1,
                                        max_request_bytes: MAX_REQUEST_BYTES as u32,
                                        max_response_bytes: MAX_RESPONSE_BYTES as u32,
                                        wake: false,
                                    },
                                },
                                Request::Wake { items } => {
                                    log.lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .extend(items);
                                    Response::Ok
                                }
                                _ => Response::Error(barking_proto::ErrorReason::Unsupported),
                            };
                            let _ = frame::write(&mut send, &resp, MAX_RESPONSE_BYTES).await;
                            let _ = send.finish();
                        }
                    });
                }
            }));
        }
        FakeRelay {
            addr,
            id,
            received,
            conns,
            tasks,
        }
    }

    /// Closes every open connection (as an idle timeout would); the relay
    /// keeps accepting new ones.
    pub fn close_connections(&self) {
        for c in self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            c.close(1u32.into(), b"test");
        }
    }

    /// Where the relay is reached (host `127.0.0.1`).
    pub fn relay_ref(&self) -> barking_proto::push::RelayRef {
        barking_proto::push::RelayRef {
            host: "127.0.0.1".to_string(),
            port: self.addr.port(),
            id: self.id,
        }
    }

    /// Sealed tokens received so far, in order.
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn stop(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_solve_puzzle() {
        for n in 0..SEEDS.len() {
            assert!(id_of(&key(n)).puzzle_ok(), "key {n}");
        }
    }
}
