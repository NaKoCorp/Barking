//! Wake subscriptions and wake-ups, end to end: real nodes, a fake relay.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_dht::{distance, mailbox_key};
use barking_node::testing::{
    FakeRelay, LONG, NodeSpec, TICK, TestNode as Node, anon, local_socket, network_with,
    start_node, stop_all,
};
use barking_node::wake::WakeConfig;
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier, ack};
use barking_proto::push::{ApnsEnv, Subscription, WakeToken, cancel_hash, open, seal};
use barking_proto::{ErrorReason, Request, Response};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

const SEAL_KEY_ID: u8 = 1;
const COLLAPSE: [u8; 16] = [0xC0; 16];

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn today() -> u32 {
    u32::try_from(now() / 86_400).unwrap()
}

/// The test client's sealing key: the fake relay does not open tokens, the
/// test does.
fn seal_secret() -> StaticSecret {
    StaticSecret::from([0x5E; 32])
}

fn token() -> WakeToken {
    WakeToken {
        apns_token: vec![0xAB; 32],
        env: ApnsEnv::Sandbox,
        collapse: COLLAPSE,
        expires_day: today() + 1,
    }
}

fn subscription(relay: &FakeRelay, mailbox: MailboxId, secret_byte: u8) -> Subscription {
    let public = PublicKey::from(&seal_secret()).to_bytes();
    // Nodes refuse literal private addresses at subscription time: the fake
    // relay is reached by name, resolved to 127.0.0.1 (allowed by the harness).
    let mut relay_ref = relay.relay_ref();
    relay_ref.host = "localhost".to_string();
    Subscription {
        mailbox,
        relay: relay_ref,
        sealed: seal(&public, SEAL_KEY_ID, &token(), &mut rand::rng()),
        cancel_hash: cancel_hash(&[secret_byte; 32]),
        expires_day: today() + 1,
    }
}

fn opened(sealed: &[u8]) -> Option<WakeToken> {
    open(&[(SEAL_KEY_ID, seal_secret())], sealed)
}

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

async fn subscribe(node: &Node, sub: &Subscription) {
    let mut s = anon(node).await;
    assert!(s.wake_supported());
    assert_eq!(
        timeout(LONG, s.subscribe(sub)).await.unwrap().unwrap(),
        Ok(())
    );
    s.close().await;
}

async fn held(node: &Node, mailbox: MailboxId) -> Vec<Vec<u8>> {
    let mut s = anon(node).await;
    let items = timeout(LONG, s.fetch(&[mailbox])).await.unwrap().unwrap();
    s.close().await;
    items
}

/// A single node, wake enabled, relay reachable on 127.0.0.1.
fn single(wake: WakeConfig) -> Node {
    let (socket, v4) = local_socket();
    let mut spec = NodeSpec::new(0, None);
    spec.wake = wake;
    spec.wake_allow_private = true;
    start_node(spec, vec![socket], std::net::SocketAddr::V4(v4))
}

async fn wait_received(relay: &FakeRelay, n: usize, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    while relay.received().len() < n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} wake-ups received, {n} expected",
            relay.received().len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_wakes_within_five_seconds() {
    let relay = FakeRelay::start().await;
    let node = single(WakeConfig::default());
    let mailbox = MailboxId([0x61; 16]);
    subscribe(&node, &subscription(&relay, mailbox, 1)).await;
    let (msg, _) = message_and_ack(mailbox, [0x61; 16]);
    let t0 = tokio::time::Instant::now();
    deposit(&node, &msg).await;
    wait_received(&relay, 1, Duration::from_secs(5)).await;
    assert!(t0.elapsed() < Duration::from_secs(5));
    let got = relay.received();
    assert_eq!(got.len(), 1);
    assert_eq!(opened(&got[0]), Some(token()));
    relay.stop();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_copy_wakes_once() {
    let relay = FakeRelay::start().await;
    let nodes = network_with(0..8, |spec| spec.wake_allow_private = true).await;
    let mailbox = MailboxId([0x62; 16]);
    let key = mailbox_key(&mailbox);
    let mut order: Vec<usize> = (0..nodes.len()).collect();
    order.sort_by_key(|&i| distance(&nodes[i].id.0, &key));
    let (a, b, c) = (order[0], order[1], order[2]);
    // One subscription per node, same collapse tag, distinct sealed blobs.
    subscribe(&nodes[a], &subscription(&relay, mailbox, 1)).await;
    subscribe(&nodes[b], &subscription(&relay, mailbox, 2)).await;
    let (msg, _) = message_and_ack(mailbox, [0x62; 16]);
    deposit(&nodes[c], &msg).await;
    // The copies reach A and B (generous: several replication passes).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    for &i in &[a, b] {
        while !held(&nodes[i], mailbox).await.contains(&msg) {
            assert!(tokio::time::Instant::now() < deadline, "copy missing");
            tokio::time::sleep(TICK).await;
        }
    }
    wait_received(&relay, 2, Duration::from_secs(30)).await;
    // No more after further replication passes.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let got = relay.received();
    assert_eq!(got.len(), 2, "one wake-up per subscription, no more");
    // Nothing is left pending on A or B (a late extra mark would show here).
    assert_eq!(nodes[a].wake_next_due(), None);
    assert_eq!(nodes[b].wake_next_due(), None);
    for sealed in &got {
        assert_eq!(opened(sealed).unwrap().collapse, COLLAPSE);
    }
    relay.stop();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_never_wakes() {
    let relay = FakeRelay::start().await;
    let node = single(WakeConfig::default());
    let mailbox = MailboxId([0x63; 16]);
    // The message arrives before the subscription: it marks nothing, and the
    // subscription has never been woken, so a wrongly marked ack would be due
    // at once (no rate-limit shadow).
    let (msg, ack) = message_and_ack(mailbox, [0x63; 16]);
    deposit(&node, &msg).await;
    subscribe(&node, &subscription(&relay, mailbox, 1)).await;
    assert_eq!(node.wake_next_due(), None, "nothing pending before the ack");
    deposit(&node, &ack).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(relay.received().len(), 0);
    assert_eq!(
        node.wake_next_due(),
        None,
        "an ack must not mark a subscription"
    );
    relay.stop();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_refusals_through_client() {
    let relay = FakeRelay::start().await;
    let node = single(WakeConfig::default());
    let mut s = anon(&node).await;
    let mut sub = subscription(&relay, MailboxId([0x66; 16]), 1);
    sub.relay.host = "127.0.0.1".to_string();
    assert_eq!(
        s.subscribe(&sub).await.unwrap(),
        Err(ErrorReason::Malformed)
    );
    let mut sub = subscription(&relay, MailboxId([0x66; 16]), 1);
    sub.expires_day = today() + 30;
    assert_eq!(
        s.subscribe(&sub).await.unwrap(),
        Err(ErrorReason::TooFarInFuture)
    );
    s.close().await;
    relay.stop();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_disabled_node() {
    let relay = FakeRelay::start().await;
    let node = single(WakeConfig {
        enabled: false,
        ..WakeConfig::default()
    });
    let mut s = anon(&node).await;
    assert!(!s.wake_supported());
    let sub = subscription(&relay, MailboxId([0x64; 16]), 1);
    assert_eq!(
        s.subscribe(&sub).await.unwrap(),
        Err(ErrorReason::Unsupported)
    );
    s.close().await;
    relay.stop();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_ok_when_relay_down() {
    let relay = FakeRelay::start().await;
    let node = single(WakeConfig::default());
    let mailbox = MailboxId([0x65; 16]);
    subscribe(&node, &subscription(&relay, mailbox, 1)).await;
    relay.stop();
    // Several messages: the first wake-up fails, the node keeps answering.
    let mut all = Vec::new();
    for n in 0..3u8 {
        let msg = message_in(mailbox, PacketId([n + 1; 16]));
        deposit(&node, &msg).await;
        all.push(msg);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let items = held(&node, mailbox).await;
    for m in &all {
        assert!(items.contains(m));
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_request_is_unsupported_on_a_node() {
    let node = single(WakeConfig::default());
    let s = anon(&node).await;
    assert_eq!(
        s.request(&Request::Wake {
            items: vec![vec![1; 40]]
        })
        .await
        .unwrap(),
        Response::Error(ErrorReason::Unsupported)
    );
    node.stop().await;
}
