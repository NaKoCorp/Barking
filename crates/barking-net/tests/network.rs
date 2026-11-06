//! The network client against real nodes: 8 `barking-node`s on 127.0.0.1
//! (`barking_node::testing`), and clients driving real `barking-core` cores
//! through `barking_net::sync` (spec §1, success criteria; §9).
//!
//! On a single address the client keeps at most `MAX_PER_PREFIX` (2)
//! responsibles per mailbox: the two closest nodes.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::identity::Fingerprint;
use barking_core::transparency::{AvoidReason, TransparencyEvent};
use barking_core::{Core, ReceiveOutcome, RouteStep};
use barking_dht::{distance, mailbox_key};
use barking_net::push::PushConfig;
use barking_net::score::{START_SCORE, ScoreEvent};
use barking_net::sync::short_id;
use barking_net::{NetState, QuicDialer, SyncOptions, SyncReport, sync};
use barking_node::testing::{FakeRelay, StoppedNode, TestNode, id_of, key, network, network_with};
use barking_packet::{Kind, MailboxId, Packet};
use barking_proto::NodeId;
use barking_proto::pow::content_hash;
use barking_proto::push::{ApnsEnv, open};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use x25519_dalek::{PublicKey, StaticSecret};

/// Nodes of the test network.
const NODES: usize = 8;
/// Longest sync of these tests (nodes are local).
const SYNC_DEADLINE: Duration = Duration::from_secs(60);
/// A sync with every node down ends after 3 failed dials and the probe of
/// the node added by hand, 10 s each (spec §6), far within the production
/// deadline (180 s) it is given.
const DOWN_ENDS_WITHIN: Duration = Duration::from_secs(55);

/// The timing-sensitive tests run one at a time.
static TIMING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// --- Client log capture ---

/// Everything the client crates logged in this test binary.
static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

struct LogSink(Arc<Mutex<Vec<u8>>>);

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs (once) a subscriber keeping every event of the client crates,
/// at every level. The nodes run in the same process: their own crate
/// (`barking_node`) and the transport libraries they share with the client
/// (`quinn`, `rustls`) are left out.
fn capture_logs() -> Arc<Mutex<Vec<u8>>> {
    Arc::clone(LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buf);
        let targets = Targets::new()
            .with_target("barking_net", tracing::Level::TRACE)
            .with_target("barking_core", tracing::Level::TRACE)
            .with_target("barking_proto", tracing::Level::TRACE)
            .with_target("barking_dht", tracing::Level::TRACE);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || LogSink(Arc::clone(&sink)))
            .with_filter(targets);
        tracing_subscriber::registry().with(layer).init();
        buf
    }))
}

// --- Clients ---

/// A client: its home directory (the core's database) and its core.
struct Client {
    home: tempfile::TempDir,
    core: Core,
}

fn client(name: &str, seed: u8) -> Client {
    let home = tempfile::tempdir().unwrap();
    let (core, _) = Core::create(
        &home.path().join("core.db"),
        &[seed; 32],
        name,
        now(),
        &mut rand::rng(),
    )
    .unwrap();
    Client { home, core }
}

/// Alice and Bob, each holding the other's contact card (handed over out of
/// band, before any sync: the cards carry no node hint). Returns their
/// contact entries for each other: (Bob in Alice's, Alice in Bob's).
fn strangers() -> (Client, Client, Fingerprint, Fingerprint) {
    let mut alice = client("alice", 1);
    let mut bob = client("bob", 2);
    let card_a = alice.core.contact_card("Alice").unwrap();
    let card_b = bob.core.contact_card("Bob").unwrap();
    let rng = &mut rand::rng();
    let fa = bob
        .core
        .add_contact(&card_a, Some("alice"), now(), rng)
        .unwrap();
    let fb = alice
        .core
        .add_contact(&card_b, Some("bob"), now(), rng)
        .unwrap();
    (alice, bob, fb, fa)
}

/// `strangers` who already exchanged a first message and its reply
/// directly (receipts included): both hold a session, nothing waits.
fn acquainted() -> (Client, Client, Fingerprint, Fingerprint) {
    let (mut alice, mut bob, fb, fa) = strangers();
    let rng = &mut rand::rng();
    let t = now();
    for p in alice.core.send_text(&fb, "hello", t, rng).unwrap() {
        let ReceiveOutcome::Message { ack, .. } =
            bob.core.receive(&p.encode(), "test", t, rng).unwrap()
        else {
            panic!("message expected");
        };
        alice.core.receive(&ack.encode(), "test", t, rng).unwrap();
    }
    for p in bob.core.send_text(&fa, "hi", t, rng).unwrap() {
        let ReceiveOutcome::Message { ack, .. } =
            alice.core.receive(&p.encode(), "test", t, rng).unwrap()
        else {
            panic!("message expected");
        };
        bob.core.receive(&ack.encode(), "test", t, rng).unwrap();
    }
    (alice, bob, fb, fa)
}

/// What a client is bootstrapped on: one node, added by hand.
fn seed(node: &TestNode) -> (NodeId, SocketAddr) {
    (node.id, node.addr)
}

fn options(seed: (NodeId, SocketAddr)) -> SyncOptions {
    SyncOptions {
        deadline: SYNC_DEADLINE,
        manual_nodes: vec![seed],
        builtin: Vec::new(),
        allow_private: true,
        ..SyncOptions::default()
    }
}

/// A sync of `c` with every node down: it ends early, as network down,
/// although it is given the production deadline.
async fn down_sync(c: &mut Client, boot: (NodeId, SocketAddr)) -> SyncReport {
    let opts = SyncOptions {
        deadline: barking_net::sync::SYNC_DEADLINE,
        ..options(boot)
    };
    let start = tokio::time::Instant::now();
    let r = sync(&mut c.core, &QuicDialer, opts).await;
    let took = start.elapsed();
    assert!(took < DOWN_ENDS_WITHIN, "took {took:?}");
    assert!(!r.network_up && !r.maintenance_done, "{r:?}");
    assert!(!r.polled_all_sessions, "{r:?}");
    r
}

/// One sync of `c`, bootstrapped (if needed) on `seed` only.
async fn sync_on(c: &mut Client, boot: (NodeId, SocketAddr)) -> SyncReport {
    let report = sync(&mut c.core, &QuicDialer, options(boot)).await;
    assert_eq!(report.error, None);
    report
}

/// Syncs `c` until its view holds every node of the network with its
/// record: deposits and fetches then go to the true responsibles.
async fn warm_up(c: &mut Client, boot: (NodeId, SocketAddr)) {
    for _ in 0..3 {
        sync_on(c, boot).await;
        let st = state(c);
        if st
            .view
            .entries()
            .filter(|(_, e)| e.record.is_some())
            .count()
            == NODES
        {
            return;
        }
    }
    panic!("the view did not fill up");
}

/// Texts of the messages a sync received.
fn texts(report: &SyncReport) -> Vec<String> {
    report
        .received
        .iter()
        .filter_map(|o| match o {
            ReceiveOutcome::Message { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn state(c: &mut Client) -> NetState {
    NetState::load(&mut c.core, now(), true).unwrap()
}

/// Mailboxes of the messages waiting in the send queue.
fn outbox_mailboxes(c: &mut Client) -> Vec<MailboxId> {
    c.core
        .pending_outbox(now())
        .unwrap()
        .iter()
        .filter_map(|b| Packet::decode(b).ok())
        .filter(|p| p.kind == Kind::Message)
        .map(|p| p.mailbox)
        .collect()
}

/// Node indices sorted by distance to `mailbox`'s key: the first two are
/// its responsibles for a client on 127.0.0.1.
fn closest(mailbox: &MailboxId) -> Vec<usize> {
    let target = mailbox_key(mailbox);
    let mut order: Vec<usize> = (0..NODES).collect();
    order.sort_by_key(|&n| distance(&id_of(&key(n)).0, &target));
    order
}

/// Raises `id`'s score in `c`'s view with `Found` events (as loss audits
/// would) until it ranks first among `others` for deposits and fetches
/// (`id` is the closer node: it ranks first on a tie).
fn pin_best(c: &mut Client, id: NodeId, others: &[NodeId]) {
    let mut st = state(c);
    let score = |st: &NetState, id: &NodeId| st.view.get(id).map_or(0.0, |e| e.score.value());
    let best_other = others.iter().map(|o| score(&st, o)).fold(0.0f32, f32::max);
    while score(&st, &id) < best_other {
        st.view.apply_score(&id, ScoreEvent::Found, now(), true);
    }
    st.save(&mut c.core).unwrap();
}

/// Every node, stopped together (databases kept).
async fn halt_all(nodes: Vec<TestNode>) -> Vec<StoppedNode> {
    let tasks: Vec<_> = nodes.into_iter().map(|n| tokio::spawn(n.halt())).collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

/// Every node started again, with `delay` before each response.
async fn restart_all(stopped: Vec<StoppedNode>, delay: Option<Duration>) -> Vec<TestNode> {
    let mut out = Vec::new();
    for mut s in stopped {
        s.spec.response_delay = delay;
        out.push(s.restart().await);
    }
    out
}

/// Every node started again, its responses sent at `rate` bytes per second.
async fn restart_paced(stopped: Vec<StoppedNode>, rate: u64) -> Vec<TestNode> {
    let mut out = Vec::new();
    for mut s in stopped {
        s.spec.send_rate = Some(rate);
        out.push(s.restart().await);
    }
    out
}

async fn stop_all(nodes: Vec<TestNode>) {
    barking_node::testing::stop_all(nodes).await;
}

/// Alice bootstrapped on node `a` only, Bob on node `b` only; Alice's first
/// message goes through Bob's introduction mailbox, his reply through
/// their session. Returns both clients once each received the other's
/// message.
async fn exchange_from_single_seeds(nodes: &[TestNode], a: usize, b: usize) -> (Client, Client) {
    let (mut alice, mut bob, fb, fa) = strangers();
    let rng = &mut rand::rng();
    alice
        .core
        .send_text(&fb, "hello from alice", now(), rng)
        .unwrap();
    let mut bob_got = Vec::new();
    for _ in 0..4 {
        let r = sync_on(&mut alice, seed(&nodes[a])).await;
        assert!(r.network_up);
        bob_got.extend(texts(&sync_on(&mut bob, seed(&nodes[b])).await));
        if !bob_got.is_empty() {
            break;
        }
    }
    assert_eq!(bob_got, ["hello from alice"]);

    bob.core
        .send_text(&fa, "hello from bob", now(), rng)
        .unwrap();
    let mut alice_got = Vec::new();
    for _ in 0..4 {
        sync_on(&mut bob, seed(&nodes[b])).await;
        alice_got.extend(texts(&sync_on(&mut alice, seed(&nodes[a])).await));
        if !alice_got.is_empty() {
            break;
        }
    }
    assert_eq!(alice_got, ["hello from bob"]);
    (alice, bob)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_discover_from_different_single_seeds() {
    capture_logs();
    let nodes = network(0..NODES, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    let (mut alice, mut bob) = exchange_from_single_seeds(&nodes, 0, 5).await;
    for (name, c) in [("alice", &mut alice), ("bob", &mut bob)] {
        let st = state(c);
        let known: HashSet<NodeId> = st.view.entries().map(|(id, _)| *id).collect();
        assert!(known.len() >= 6, "{name} knows only {} nodes", known.len());
    }
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swallowing_node_is_avoided_and_message_still_arrives() {
    capture_logs();
    let (mut alice, mut bob, fb, _) = acquainted();
    let rng = &mut rand::rng();
    let sent = ["one", "two", "three"];
    for text in sent {
        alice.core.send_text(&fb, text, now(), rng).unwrap();
    }
    // All three in one session mailbox: its closest node swallows deposits.
    let mailboxes = outbox_mailboxes(&mut alice);
    assert_eq!(mailboxes.len(), 3);
    let mailbox = mailboxes[0];
    assert!(mailboxes.iter().all(|m| *m == mailbox));
    let order = closest(&mailbox);
    let (swallower, honest) = (order[0], order[1]);
    let swallower_id = id_of(&key(swallower));
    let honest_id = id_of(&key(honest));
    let mut nodes = network_with(0..NODES, |spec| {
        spec.swallow_deposits = spec.n == swallower;
    })
    .await;
    // Both clients start on a node that is neither responsible.
    let boot = seed(&nodes[order[2]]);

    // Bootstrap with no proof-of-work budget: the messages wait.
    let mut opts = options(boot);
    opts.pow_budget = 0;
    let r = sync(&mut alice.core, &QuicDialer, opts).await;
    assert!(r.network_up && r.first_copies == 0, "{r:?}");
    let st = state(&mut alice);
    for id in [swallower_id, honest_id] {
        assert!(st.view.get(&id).is_some_and(|e| e.record.is_some()));
    }

    // The swallowing node is the best responsible and the other one is
    // unreachable: the first copies all go to the swallowing node, and no
    // copy lands anywhere else.
    let stopped = nodes.remove(honest).halt().await;
    pin_best(&mut alice, swallower_id, &[honest_id]);
    let r = sync_on(&mut alice, boot).await;
    assert_eq!((r.first_copies, r.extra_copies), (3, 0), "{r:?}");
    assert!(r.avoided.is_empty());
    let st = state(&mut alice);
    for bytes in message_packets(&mut alice) {
        assert_eq!(st.ledger.holders(&content_hash(&bytes)), [swallower_id]);
    }
    nodes.insert(honest, stopped.restart().await);

    // The next fetch from it audits the mailbox: three losses, the node is
    // avoided, and the messages are deposited again elsewhere right away:
    // on the other responsible and, the avoided node leaving room among
    // the closest, on the next one (three client copies at most).
    pin_best(&mut alice, swallower_id, &[honest_id]);
    let r = sync_on(&mut alice, boot).await;
    assert_eq!(r.avoided, [short_id(&swallower_id)], "{r:?}");
    assert_eq!((r.first_copies, r.extra_copies), (0, 6), "{r:?}");
    let st = state(&mut alice);
    let entry = st.view.get(&swallower_id).unwrap();
    // An avoidance only starts when a loss leaves the score under
    // `AVOID_BELOW` (0.2); requests answered later in the same sync may
    // raise it a little since.
    assert!(entry.avoided(now()), "{entry:?}");
    assert!(entry.score.value() < START_SCORE, "{entry:?}");
    let log = alice.core.transparency_log(1000).unwrap();
    assert!(log.iter().any(|(_, e)| matches!(
        e,
        TransparencyEvent::NodeAvoided { node, reason: AvoidReason::MessageLost }
            if *node == short_id(&swallower_id)
    )));
    let next_id = id_of(&key(order[2]));
    for bytes in message_packets(&mut alice) {
        let mut holders = st.ledger.holders(&content_hash(&bytes));
        holders.sort_unstable_by_key(|n| n.0);
        let mut want = vec![honest_id, next_id];
        want.sort_unstable_by_key(|n| n.0);
        assert_eq!(holders, want);
    }

    // Bob, with no help: whichever responsible he prefers, the cross-check
    // reads the other one.
    let mut got = Vec::new();
    for _ in 0..4 {
        got.extend(texts(&sync_on(&mut bob, boot).await));
        if got.len() >= sent.len() {
            break;
        }
    }
    got.sort();
    let mut want: Vec<String> = sent.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want);
    stop_all(nodes).await;
}

/// Messages (not receipts) waiting in `c`'s send queue.
fn message_packets(c: &mut Client) -> Vec<Vec<u8>> {
    c.core
        .pending_outbox(now())
        .unwrap()
        .into_iter()
        .filter(|b| Packet::decode(b).is_ok_and(|p| p.kind == Kind::Message))
        .collect()
}

/// Fetch positions of `c`.
fn positions(c: &mut Client) -> HashMap<(NodeId, MailboxId), u64> {
    state(c).positions
}

fn scores(c: &mut Client) -> HashMap<NodeId, f32> {
    state(c)
        .view
        .entries()
        .map(|(id, e)| (*id, e.score.value()))
        .collect()
}

/// No position of `before` went missing or back.
fn assert_positions_kept(
    before: &HashMap<(NodeId, MailboxId), u64>,
    after: &HashMap<(NodeId, MailboxId), u64>,
    when: &str,
) {
    for (k, v) in before {
        let now = after.get(k).copied();
        assert!(now.is_some_and(|n| n >= *v), "{when}: {v} -> {now:?}");
    }
}

/// Incoming messages of `c` from `from`, in order.
fn inbox(c: &Client, from: &Fingerprint) -> Vec<String> {
    c.core
        .messages_with(from)
        .unwrap()
        .into_iter()
        .filter(|m| m.direction == barking_core::store::Direction::In)
        .map(|m| m.body)
        .collect()
}

/// Messages per batch of `cut_mid_sync_resumes`: 70 large (tier L, 16 KiB)
/// packets fill more than a 1 MiB fetch page.
const BATCH: usize = 70;

/// `BATCH` large messages tagged `tag`.
fn batch(tag: &str) -> Vec<String> {
    (0..BATCH)
        .map(|i| format!("{tag} {i:03} {}", "x".repeat(3_000)))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cut_mid_sync_resumes() {
    let _timing = TIMING.lock().await;
    capture_logs();
    let (mut alice, mut bob, fb, fa) = acquainted();
    let rng = &mut rand::rng();
    let nodes = network(0..NODES, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    let (sa, sb) = (seed(&nodes[1]), seed(&nodes[6]));

    warm_up(&mut alice, sa).await;
    warm_up(&mut bob, sb).await;

    // A first batch, fetched by Bob: more than one page (1 MiB) of large
    // messages in one mailbox, so that a position is recorded.
    let first = batch("first");
    for t in &first {
        alice.core.send_text(&fb, t, now(), rng).unwrap();
    }
    let r = sync_on(&mut alice, sa).await;
    assert_eq!(r.first_copies, BATCH, "{r:?}");
    let mut got = Vec::new();
    for _ in 0..3 {
        let r = sync_on(&mut bob, sb).await;
        got.extend(texts(&r));
        if got.len() == first.len() {
            break;
        }
    }
    assert_eq!(got.len(), first.len());
    let before = positions(&mut bob);
    assert!(before.values().any(|&p| p > 0), "{before:?}");

    // A second batch waits on the nodes.
    let second = batch("second");
    for t in &second {
        alice.core.send_text(&fb, t, now(), rng).unwrap();
    }
    let r = sync_on(&mut alice, sa).await;
    assert_eq!(r.first_copies, BATCH, "{r:?}");
    let bob_seed = sb;

    // Every response now waits `DELAY`, and every node stops while Bob's
    // fetch of the second batch is under way: a full page (1 MiB) waiting
    // on a node is the first one; it reaches Bob `DELAY` later, the next
    // one `DELAY` after that. The nodes stop in between. A fetch reserves
    // about 1 MiB before it reads anything, even an empty one, but only
    // briefly: the full page is the reservation still held 50 ms later.
    const DELAY: Duration = Duration::from_millis(400);
    let nodes = restart_all(halt_all(nodes).await, Some(DELAY)).await;
    let stats: Vec<_> = nodes.iter().map(|n| Arc::clone(&n.stats)).collect();
    let opts = options(bob_seed);
    let cut = async {
        let give_up = tokio::time::Instant::now() + SYNC_DEADLINE;
        let full = |s: &Arc<barking_node::server::ServerStats>| s.response_bytes.now() > 512 << 10;
        loop {
            if tokio::time::Instant::now() >= give_up {
                break;
            }
            let before: Vec<bool> = stats.iter().map(full).collect();
            tokio::time::sleep(Duration::from_millis(50)).await;
            if stats.iter().zip(&before).any(|(s, b)| *b && full(s)) {
                break;
            }
        }
        // Seen 50 to 100 ms into the first page's wait: stop halfway between
        // its delivery and the next page's.
        tokio::time::sleep(DELAY * 5 / 4).await;
        halt_all(nodes).await
    };
    let (r, stopped) = tokio::join!(sync(&mut bob.core, &QuicDialer, opts), cut);
    let after_cut = positions(&mut bob);
    assert_positions_kept(&before, &after_cut, "cut sync");
    // The page taken before the cut was kept: the fetch resumes past it.
    assert!(r.items_received > 0 && !r.polled_all_sessions, "{r:?}");
    assert!(
        after_cut
            .iter()
            .any(|(k, v)| before.get(k).is_some_and(|b| v > b)),
        "{before:?} -> {after_cut:?}"
    );

    // Network down: no node answers, no score goes down, nothing moves back.
    let scores_before = scores(&mut bob);
    down_sync(&mut bob, bob_seed).await;
    for (id, s) in scores(&mut bob) {
        let was = scores_before.get(&id).copied().unwrap_or(s);
        assert!(s >= was, "score lowered while the network was down");
    }
    let after_down = positions(&mut bob);
    assert_positions_kept(&after_cut, &after_down, "down sync");

    // Back up: the rest arrives, nothing lost, nothing twice.
    let nodes = restart_all(stopped, None).await;
    for _ in 0..3 {
        sync_on(&mut bob, sb).await;
        if inbox(&bob, &fa).len() > first.len() + second.len() {
            break;
        }
    }
    assert_positions_kept(&after_down, &positions(&mut bob), "resumed sync");
    let mut want = vec!["hello".to_string()];
    want.extend(first.iter().chain(&second).cloned());
    let mut got = inbox(&bob, &fa);
    got.sort();
    want.sort();
    assert_eq!(got, want);
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_network_puts_first_copy_before_maintenance() {
    let _timing = TIMING.lock().await;
    capture_logs();
    let (mut alice, _bob, fb, _) = acquainted();
    let rng = &mut rand::rng();
    let nodes = network(0..NODES, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    // Bootstrap and view maintenance at full speed.
    let r = sync_on(&mut alice, seed(&nodes[3])).await;
    assert!(r.network_up && r.maintenance_done);

    // Every response now waits `DELAY`; the sync gets `55 * DELAY`. Worst
    // case before the last first copy: 4 session groups on 4 nodes (8
    // delays), as many cross-checks on 4 other nodes (8), 30 first copies
    // and a connection (31): 47. Best case before maintenance: one group
    // (2), the cross-check of the new send mailbox (1), the first copies
    // (30), the extra copies (30), one introduction fetch (1): 64.
    const DELAY: Duration = Duration::from_millis(300);
    const MESSAGES: usize = 30;
    let nodes = restart_all(halt_all(nodes).await, Some(DELAY)).await;
    for i in 0..MESSAGES {
        alice
            .core
            .send_text(&fb, &format!("slow {i}"), now(), rng)
            .unwrap();
    }
    let mut opts = options(seed(&nodes[3]));
    opts.deadline = DELAY * 55;
    let r = sync(&mut alice.core, &QuicDialer, opts).await;
    assert!(r.network_up, "{r:?}");
    assert!(r.polled_all_sessions, "{r:?}");
    assert_eq!(r.first_copies, MESSAGES, "{r:?}");
    assert!(!r.maintenance_done, "{r:?}");
    stop_all(nodes).await;
}

/// Lowercase hex and base32 forms of `id`.
fn forms(id: &[u8]) -> [String; 2] {
    [
        data_encoding::HEXLOWER.encode(id),
        data_encoding::BASE32_NOPAD.encode(id).to_ascii_lowercase(),
    ]
}

/// Neither an address nor a mailbox (raw, hex or base32) in `text`/`bytes`.
fn assert_clean(what: &str, bytes: &[u8], mailboxes: &[MailboxId], addrs: &[String]) {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for a in addrs {
        assert!(!text.contains(a.as_str()), "{what} contains an address");
    }
    for m in mailboxes {
        for f in forms(&m.0) {
            assert!(!text.contains(f.as_str()), "{what} contains a mailbox");
        }
        assert!(
            !bytes.windows(16).any(|w| w == m.0),
            "{what} contains a raw mailbox"
        );
    }
}

fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_ip_or_mailbox_in_logs_or_plaintext_state() {
    let logs = capture_logs();
    tracing::info!(target: "barking_net", "log capture probe");
    let nodes = network(0..NODES, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    let (mut alice, mut bob) = exchange_from_single_seeds(&nodes, 2, 7).await;
    let (sa, sb) = (seed(&nodes[2]), seed(&nodes[7]));
    warm_up(&mut alice, sa).await;
    let t = now();
    let mut mailboxes = Vec::new();
    for c in [&mut alice, &mut bob] {
        mailboxes.extend(c.core.watched_mailboxes(t).unwrap());
        mailboxes.extend(outbox_mailboxes(c));
    }
    let mut addrs: Vec<String> = vec!["127.0.0.1".into(), "7f000001".into()];
    addrs.extend(nodes.iter().map(|n| n.addr.to_string()));

    // Failures while other nodes answer: both responsibles of one of
    // Alice's session mailboxes are down.
    let m = alice.core.watched_mailbox_groups(t).unwrap().sessions[0];
    let dead: Vec<NodeId> = closest(&m)[..2].iter().map(|&n| id_of(&key(n))).collect();
    let (gone, alive): (Vec<TestNode>, Vec<TestNode>) =
        nodes.into_iter().partition(|n| dead.contains(&n.id));
    let _gone = halt_all(gone).await;
    let before = scores(&mut alice);
    let r = sync_on(&mut alice, sa).await;
    assert!(r.network_up, "{r:?}");
    let after = scores(&mut alice);
    assert!(
        dead.iter().any(|id| after.get(id) < before.get(id)),
        "no failure counted: {before:?} -> {after:?}"
    );

    // Then every node down: both clients end early, as network down.
    let _stopped = halt_all(alive).await;
    let (ra, rb) = tokio::join!(down_sync(&mut alice, sa), down_sync(&mut bob, sb));
    assert!(ra.avoided.is_empty() && rb.avoided.is_empty());

    let logs = logs.lock().unwrap().clone();
    assert!(
        String::from_utf8_lossy(&logs).contains("log capture probe"),
        "logs not captured"
    );
    assert_clean("client logs", &logs, &mailboxes, &addrs);
    for c in [&alice, &bob] {
        for f in files_under(c.home.path()) {
            let bytes = std::fs::read(&f).unwrap();
            assert_clean(&f.display().to_string(), &bytes, &mailboxes, &addrs);
        }
    }
}

/// Messages per mailbox of `slow_link_backlog_and_intro_progress`: large
/// (16 KiB) packets, about 200 KiB in all.
const SLOW_BATCH: usize = 12;
/// Throughput of the nodes' responses in that test.
const SLOW_RATE: u64 = 32 * 1024;
/// Deadline of each of Bob's syncs there: a single page holding the whole
/// backlog of a mailbox (about 6 s at `SLOW_RATE`) would never fit.
const SLOW_SYNC: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_link_backlog_and_intro_progress() {
    let _timing = TIMING.lock().await;
    capture_logs();
    let (mut alice, mut bob, fb, fa) = acquainted();
    // Carol writes to Bob for the first time: his introduction mailbox.
    let mut carol = client("carol", 3);
    let rng = &mut rand::rng();
    let card_b = bob.core.contact_card("Bob").unwrap();
    let card_c = carol.core.contact_card("Carol").unwrap();
    let fc = bob
        .core
        .add_contact(&card_c, Some("carol"), now(), rng)
        .unwrap();
    let fbc = carol
        .core
        .add_contact(&card_b, Some("bob"), now(), rng)
        .unwrap();
    let nodes = network(0..NODES, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    let boot = seed(&nodes[4]);
    for c in [&mut alice, &mut bob, &mut carol] {
        warm_up(c, boot).await;
    }
    let from_alice = batch("session");
    let from_carol = batch("intro");
    for t in &from_alice[..SLOW_BATCH] {
        alice.core.send_text(&fb, t, now(), rng).unwrap();
    }
    for t in &from_carol[..SLOW_BATCH] {
        carol.core.send_text(&fbc, t, now(), rng).unwrap();
    }
    for c in [&mut alice, &mut carol] {
        let r = sync_on(c, boot).await;
        assert_eq!(r.first_copies, SLOW_BATCH, "{r:?}");
    }

    // A slow link from now on: every response at `SLOW_RATE`.
    let nodes = restart_paced(halt_all(nodes).await, SLOW_RATE).await;
    let mut syncs = 0;
    let mut empty = 0;
    while inbox(&bob, &fa).len() < 1 + SLOW_BATCH || inbox(&bob, &fc).len() < SLOW_BATCH {
        syncs += 1;
        assert!(syncs <= 8, "backlog stuck: {} syncs", syncs - 1);
        let opts = SyncOptions {
            deadline: SLOW_SYNC,
            ..options(boot)
        };
        let r = sync(&mut bob.core, &QuicDialer, opts).await;
        // Every sync takes its share of the backlog. On a loaded machine the
        // first one after the restart can spend its whole deadline
        // reconnecting at `SLOW_RATE`: one empty sync is tolerated, not two.
        if r.items_received == 0 {
            empty += 1;
            assert!(empty <= 1, "sync {syncs}, second empty sync: {r:?}");
        }
    }
    assert!(
        syncs > 1,
        "the backlog fitted in one sync: the link is not slow"
    );
    // The page size each link reached is kept for the next syncs.
    assert!(!state(&mut bob).page_bytes.is_empty());
    eprintln!("slow link: backlog fetched in {syncs} syncs");
    let mut got = inbox(&bob, &fa);
    got.extend(inbox(&bob, &fc));
    got.sort();
    let mut want = vec!["hello".to_string()];
    want.extend(from_alice[..SLOW_BATCH].iter().cloned());
    want.extend(from_carol[..SLOW_BATCH].iter().cloned());
    want.sort();
    assert_eq!(got, want);
    stop_all(nodes).await;
}

// --- Wake-ups ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribed_device_gets_a_wake_for_a_new_message() {
    let _timing = TIMING.lock().await;
    capture_logs();
    const SEAL_KEY_ID: u8 = 1;
    const APNS_TOKEN: [u8; 32] = [0xB0; 32];
    let relay = FakeRelay::start().await;
    // The fake relay listens on 127.0.0.1: the nodes are allowed to reach it.
    let nodes = network_with(0..NODES, |spec| spec.wake_allow_private = true).await;
    let boot = seed(&nodes[0]);
    let (mut alice, mut bob, fb, _) = acquainted();
    warm_up(&mut alice, boot).await;
    warm_up(&mut bob, boot).await;

    // Bob's device subscribes for wake-ups. Nodes refuse a literal private
    // address for the relay: it is named, and resolves to 127.0.0.1.
    let seal_secret = StaticSecret::from([0x5E; 32]);
    let mut relay_ref = relay.relay_ref();
    relay_ref.host = "localhost".to_string();
    let cfg = PushConfig {
        relay: relay_ref,
        seal_public: PublicKey::from(&seal_secret).to_bytes(),
        seal_key_id: SEAL_KEY_ID,
        apns_token: APNS_TOKEN.to_vec(),
        env: ApnsEnv::Sandbox,
    };
    let r = sync(
        &mut bob.core,
        &QuicDialer,
        SyncOptions {
            push: Some(cfg),
            ..options(boot)
        },
    )
    .await;
    assert_eq!(r.error, None);
    assert!(r.subscribed > 0, "{r:?}");
    assert!(relay.received().is_empty());

    // Alice writes, and her sync deposits the message (short deadline: the
    // deposits come early, maintenance is cut).
    alice
        .core
        .send_text(&fb, "wake up", now(), &mut rand::rng())
        .unwrap();
    let t0 = tokio::time::Instant::now();
    let r = sync(
        &mut alice.core,
        &QuicDialer,
        SyncOptions {
            deadline: Duration::from_secs(4),
            ..options(boot)
        },
    )
    .await;
    assert!(r.first_copies >= 1, "{r:?}");
    // The deposit happened after `t0`: the wake reached the relay less
    // than 5 s after it.
    while relay.received().is_empty() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "no wake-up 5 s after the deposit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!(
        "wake-up {:?} after the start of the sender's sync",
        t0.elapsed()
    );
    let token = open(&[(SEAL_KEY_ID, seal_secret)], &relay.received()[0])
        .expect("a token sealed for the device's key");
    assert_eq!(token.apns_token, APNS_TOKEN.to_vec());
    assert_eq!(token.env, ApnsEnv::Sandbox);
    relay.stop();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_and_fetch_record_route() {
    capture_logs();
    let nodes = network(0..1, |_| {
        barking_node::config::DEFAULT_REPLICATION_BYTES_PER_HOUR
    })
    .await;
    let node = short_id(&nodes[0].id);
    let (mut alice, mut bob, fb, fa) = strangers();
    alice
        .core
        .send_text(&fb, "route", now(), &mut rand::rng())
        .unwrap();
    let mut got = Vec::new();
    for _ in 0..4 {
        sync_on(&mut alice, seed(&nodes[0])).await;
        got.extend(texts(&sync_on(&mut bob, seed(&nodes[0])).await));
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got, ["route"]);

    let sent = alice.core.messages_with(&fb).unwrap()[0].id;
    let route = alice.core.message_route(sent).unwrap();
    assert!(
        route
            .iter()
            .any(|e| e.step == RouteStep::Deposited && e.node.as_deref() == Some(node.as_str())),
        "{route:?}"
    );
    let received = bob.core.messages_with(&fa).unwrap()[0].id;
    let route = bob.core.message_route(received).unwrap();
    assert!(
        route
            .iter()
            .any(|e| e.step == RouteStep::Fetched && e.node.as_deref() == Some(node.as_str())),
        "{route:?}"
    );
    // Fetched (recorded at the end of the sync) comes before Opened.
    let fetched = route.iter().position(|e| e.step == RouteStep::Fetched);
    let opened = route.iter().position(|e| e.step == RouteStep::Opened);
    assert!(opened.is_some() && fetched < opened, "{route:?}");
    stop_all(nodes).await;
}
