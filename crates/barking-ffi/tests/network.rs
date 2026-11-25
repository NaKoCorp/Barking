//! `Device` against a local test network: sync, quick sync, nodes added by hand.

use std::sync::Arc;

use barking_core::store::{Queries, Store};
use barking_ffi::{
    BarkingError, DefaultNode, DeliveryChange, DeliveryState, Device, DeviceConfig, Message,
    NodeOriginKind, PushSettings, Reliability,
};
use barking_node::testing::{
    FakeRelay, TICK, id_of, key, network, network_with, set_clock_offset, stop_all,
};

fn config(dir: &tempfile::TempDir, key_byte: u8) -> DeviceConfig {
    DeviceConfig {
        db_path: dir.path().join("barking.db").display().to_string(),
        lock_path: dir.path().join("barking.lock").display().to_string(),
        db_key: vec![key_byte; 32],
        lock_timeout_ms: 1_000,
        allow_private: true,
    }
}

/// Alice and Bob, each holding the other's card under an alias.
fn paired_devices(da: &tempfile::TempDir, db: &tempfile::TempDir) -> (Arc<Device>, Arc<Device>) {
    let alice = Device::create(config(da, 1), "alice-phone".into())
        .unwrap()
        .device;
    let bob = Device::create(config(db, 2), "bob-phone".into())
        .unwrap()
        .device;
    alice
        .add_contact(bob.contact_card("Bob".into()).unwrap(), Some("bob".into()))
        .unwrap();
    bob.add_contact(
        alice.contact_card("Alice".into()).unwrap(),
        Some("alice".into()),
    )
    .unwrap();
    (alice, bob)
}

#[tokio::test(flavor = "multi_thread")]
async fn quick_sync_receives_message() {
    // 3 nodes: each one is a responsible of every mailbox, so the quick sync
    // (best responsible only) finds the message without waiting for copies.
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (alice, bob) = paired_devices(&da, &db);
        for d in [&alice, &bob] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        assert!(bob.sync(30_000).unwrap().network_up);
        alice
            .send_text("bob".into(), "salut".into(), None, None)
            .unwrap();
        assert!(alice.sync(30_000).unwrap().network_up);
        let s = bob.quick_sync(20_000).unwrap();
        assert_eq!(s.error, None);
        assert_eq!(s.new_messages.len(), 1);
        assert_eq!(s.new_messages[0].name, "alice");
        assert_eq!(s.new_messages[0].text, "salut");
        assert_eq!(s.new_messages[0].contact, alice.fingerprint().unwrap());
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[test]
fn bad_node_input_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    assert!(matches!(
        d.add_node("XYZ".into(), "127.0.0.1:4433".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
    let valid = id_of(&key(0)).to_string();
    assert!(matches!(
        d.add_node(valid, "nowhere".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
}

fn push_settings(relay_id: String, port: u16) -> PushSettings {
    PushSettings {
        relay_host: "localhost".into(),
        relay_port: port,
        relay_id,
        seal_key_id: 1,
        seal_public: vec![0x5E; 32],
        apns_token: vec![0xB0; 32],
        sandbox: true,
    }
}

#[test]
fn bad_push_settings_are_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let good = push_settings(id_of(&key(0)).to_string(), 4433);
    let bad = [
        PushSettings {
            relay_id: "XYZ".into(),
            ..good.clone()
        },
        PushSettings {
            relay_port: 0,
            ..good.clone()
        },
        // A private IP literal: nodes refuse it, a name must be given.
        PushSettings {
            relay_host: "192.168.1.10".into(),
            ..good.clone()
        },
        PushSettings {
            seal_public: vec![1; 31],
            ..good.clone()
        },
        PushSettings {
            apns_token: Vec::new(),
            ..good.clone()
        },
        PushSettings {
            apns_token: vec![1; 129],
            ..good.clone()
        },
    ];
    for s in bad {
        assert!(
            matches!(
                d.set_push(Some(s.clone())),
                Err(BarkingError::InvalidInput { .. })
            ),
            "{s:?}"
        );
    }
    // The iOS 26 simulator gives 80-byte tokens.
    d.set_push(Some(PushSettings {
        apns_token: vec![0xB1; 80],
        ..good.clone()
    }))
    .unwrap();
    d.set_push(Some(PushSettings {
        apns_token: vec![0xB2; 128],
        ..good.clone()
    }))
    .unwrap();
    d.set_push(Some(good)).unwrap();
    d.set_push(None).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_settings_subscribe_wake_and_cancel() {
    let relay = FakeRelay::start().await;
    // The fake relay listens on 127.0.0.1: the nodes are allowed to reach it.
    let nodes = network_with(0..3, |spec| spec.wake_allow_private = true).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let settings = push_settings(relay.relay_ref().id.to_string(), relay.relay_ref().port);
    let received = {
        let relay = &relay;
        move || relay.received().len()
    };
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, bob) = paired_devices(&da, &db);
    for d in [&alice, &bob] {
        d.add_node(id.clone(), addr.clone()).unwrap();
    }
    let (alice2, bob2) = (alice.clone(), bob.clone());
    let s = tokio::task::spawn_blocking(move || {
        bob2.set_push(Some(settings)).unwrap();
        bob2.sync(30_000).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(s.error, None);
    assert!(s.subscribed > 0, "{s:?}");
    assert_eq!(received(), 0);

    tokio::task::spawn_blocking(move || {
        alice2
            .send_text("bob".into(), "wake up".into(), None, None)
            .unwrap();
        assert!(alice2.sync(30_000).unwrap().sent >= 1);
    })
    .await
    .unwrap();
    let t0 = tokio::time::Instant::now();
    while received() == 0 {
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(10),
            "no wake-up"
        );
        tokio::time::sleep(TICK).await;
    }

    // Push off: the next sync cancels every subscription held.
    let bob2 = bob.clone();
    let s = tokio::task::spawn_blocking(move || {
        bob2.set_push(None).unwrap();
        bob2.sync(30_000).unwrap()
    })
    .await
    .unwrap();
    assert!(s.unsubscribed > 0, "{s:?}");
    drop((alice, bob));
    relay.stop();
    stop_all(nodes).await;
}

#[test]
fn quick_sync_without_nodes_reports_network_down() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let s = d.quick_sync(2_000).unwrap();
    assert!(!s.network_up);
    assert!(s.new_messages.is_empty());
}

#[test]
fn nodes_lists_manual_node() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = id_of(&key(0)).to_string();
    d.add_node(id.clone(), "127.0.0.1:4433".into()).unwrap();
    let nodes = d.nodes().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, id);
    assert!(nodes[0].manual && !nodes[0].from_card);
    assert_eq!(nodes[0].addr, "127.0.0.1:4433");
}

#[test]
fn key_changes_is_empty_without_change() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob) = paired_devices(&da, &db);
    assert!(alice.key_changes(0).unwrap().is_empty());
}

#[test]
fn key_change_is_reported() {
    let (da, db, dc) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (alice, _bob) = paired_devices(&da, &db);
    // A new key under the alias "bob": the core logs a key change.
    let other = Device::create(config(&dc, 3), "c".into()).unwrap().device;
    let new_fp = alice
        .add_contact(
            other.contact_card("Bob".into()).unwrap(),
            Some("bob".into()),
        )
        .unwrap();
    let changes = alice.key_changes(0).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].contact, new_fp);
}

// --- Delivery states over the network (spec Lot M §5.9, §15.6) ---

/// Moves every packet of the send queue in `dir` past its expiry, as if a
/// day went by on this device.
fn expire_queue(dir: &tempfile::TempDir, key_byte: u8) {
    let store = Store::open(&dir.path().join("barking.db"), &[key_byte; 32]).unwrap();
    store
        .conn()
        .execute("UPDATE outbox SET expires_at = 1", ())
        .unwrap();
}

fn message(d: &Device, contact: &str, body: &str) -> Message {
    d.messages_with(contact.to_owned())
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
}

fn state(d: &Device, contact: &str, body: &str) -> DeliveryState {
    message(d, contact, body).delivery.unwrap().state
}

/// Runs `round` (syncs) until `done`, for 60 s at most: copies and receipts
/// travel between the nodes in the background, and on a loaded CI runner
/// one round is not always enough. False on timeout.
fn sync_until(mut round: impl FnMut(), done: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        round();
        if done() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(TICK);
    }
}

fn has_message(d: &Device, contact: &str, body: &str) -> bool {
    d.messages_with(contact.to_owned())
        .unwrap()
        .iter()
        .any(|m| m.body == body)
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_reports_delivery_changes() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (alice, bob) = paired_devices(&da, &db);
        for d in [&alice, &bob] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        bob.sync(30_000).unwrap();
        alice
            .send_text("bob".into(), "hello".into(), None, None)
            .unwrap();
        let sent = message(&alice, "bob", "hello").id;
        let change = DeliveryChange {
            contact: bob.fingerprint().unwrap(),
            message_id: sent,
        };

        // The deposit: the summary names the message.
        let s = alice.sync(30_000).unwrap();
        assert!(s.delivery_changes.contains(&change), "{s:?}");
        assert!(s.failed.is_empty(), "{s:?}");
        let d = message(&alice, "bob", "hello").delivery.unwrap();
        assert_eq!(d.state, DeliveryState::OnNetwork);
        assert!(d.deposited_at.is_some());
        let detail = alice.message_delivery(sent).unwrap().unwrap();
        assert!(!detail.relays.is_empty());
        assert!(detail.devices[0].node.is_some());

        // A received message has no delivery of its own.
        assert!(
            sync_until(
                || {
                    bob.sync(30_000).unwrap();
                },
                || has_message(&bob, "alice", "hello"),
            ),
            "bob never received the message"
        );
        let received = message(&bob, "alice", "hello");
        assert!(!received.outgoing);
        assert!(received.delivery.is_none());

        // Bob's receipt makes it `Received`, noted by the sync that
        // fetched it.
        let mut noted = false;
        sync_until(
            || {
                bob.sync(30_000).unwrap();
                let s = alice.sync(30_000).unwrap();
                noted |= s.delivery_changes.contains(&change);
            },
            || state(&alice, "bob", "hello") == DeliveryState::Received,
        );
        assert_eq!(state(&alice, "bob", "hello"), DeliveryState::Received);
        assert!(noted);
        let d = message(&alice, "bob", "hello").delivery.unwrap();
        assert!(d.received_at.is_some());
        assert_eq!(d.devices_received, 1);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_and_quick_sync_report_expired_messages() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (alice, bob) = paired_devices(&da, &db);
        alice.add_node(id, addr).unwrap();
        let fb = bob.fingerprint().unwrap();

        alice
            .send_text("bob".into(), "lost".into(), None, None)
            .unwrap();
        expire_queue(&da, 1);
        let s = alice.sync(30_000).unwrap();
        let lost = DeliveryChange {
            contact: fb.clone(),
            message_id: message(&alice, "bob", "lost").id,
        };
        assert_eq!(s.failed, vec![lost.clone()], "{s:?}");
        assert!(s.delivery_changes.contains(&lost), "{s:?}");

        alice
            .send_text("bob".into(), "lost too".into(), None, None)
            .unwrap();
        expire_queue(&da, 1);
        let s = alice.quick_sync(20_000).unwrap();
        let lost_too = DeliveryChange {
            contact: fb,
            message_id: message(&alice, "bob", "lost too").id,
        };
        assert_eq!(s.failed, vec![lost_too.clone()], "{s:?}");
        assert!(s.delivery_changes.contains(&lost_too), "{s:?}");
        let d = message(&alice, "bob", "lost too").delivery.unwrap();
        assert_eq!(d.state, DeliveryState::NotDelivered);
        assert_eq!(d.deposited_at, None);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

/// Puts the nodes' clock back on the system clock when dropped.
struct ClockReset;

impl Drop for ClockReset {
    fn drop(&mut self) {
        set_clock_offset(0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_reports_failed_after_verdict() {
    let _reset = ClockReset;
    let nodes = network_with(0..3, |spec| spec.purge_interval = Some(TICK)).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (da, alice, fb) = tokio::task::spawn_blocking(move || {
        let (alice, bob) = paired_devices(&da, &db);
        alice.add_node(id, addr).unwrap();
        alice
            .send_text("bob".into(), "lost".into(), None, None)
            .unwrap();
        alice.sync(30_000).unwrap();
        assert_eq!(state(&alice, "bob", "lost"), DeliveryState::OnNetwork);
        (da, alice, bob.fingerprint().unwrap())
    })
    .await
    .unwrap();

    // Bob stays offline; a day past its lifetime the relays purged the
    // message. Alice's packet expired three hours ago: past the
    // replication slack, within the nodes' ack grace.
    set_clock_offset(barking_core::packet::DEFAULT_TTL_SECS + 86_400);
    tokio::time::sleep(TICK * 5).await;
    tokio::task::spawn_blocking(move || {
        let store = Store::open(&da.path().join("barking.db"), &[1; 32]).unwrap();
        store
            .conn()
            .execute(
                "UPDATE outbox SET expires_at = CAST(strftime('%s', 'now') AS INTEGER) - 10800",
                (),
            )
            .unwrap();
        drop(store);
        let s = alice.sync(30_000).unwrap();
        let lost = DeliveryChange {
            contact: fb,
            message_id: message(&alice, "bob", "lost").id,
        };
        assert_eq!(s.failed, vec![lost], "{s:?}");
        let d = message(&alice, "bob", "lost").delivery.unwrap();
        assert_eq!(d.state, DeliveryState::NotDelivered);
        // Deposited, then failed: `expired_at` set too.
        assert!(d.deposited_at.is_some());
        assert!(d.expired_at.is_some());
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

// --- Node transparency (spec node transparency §6.4, §6.5) ---

/// Opens the core of the device in `dir` (key byte 1), outside the device:
/// the test edits the stored network state between two calls.
fn edit_net_state(dir: &tempfile::TempDir, f: impl FnOnce(&mut barking_net::NetState, u64)) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut core = barking_core::Core::open(&dir.path().join("barking.db"), &[1; 32], now).unwrap();
    let mut state = barking_net::NetState::load(&mut core, now, true).unwrap();
    f(&mut state, now);
    state.save(&mut core).unwrap();
}

/// A signed record of test key `n`, at `127.0.0.<n>:4433`, issued at `at`.
fn record_of(n: usize, at: u64) -> barking_proto::NodeRecord {
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, n as u8), 4433);
    barking_proto::NodeRecord::sign(&key(n), Some(addr), None, at)
}

#[test]
fn nodes_sorted_in_use_first() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = |n: usize| id_of(&key(n)).to_string();
    // Added by hand, never answered: in use, `New`.
    d.add_node(id(1), "127.0.0.1:4001".into()).unwrap();
    edit_net_state(&dir, |state, now| {
        let old = now - 8 * 86_400;
        // Discovered, seen eight days ago, never answered: not in use, `New`.
        assert!(state.view.insert(record_of(2, old), old));
        // Discovered, answered now: in use, `Good`.
        assert!(state.view.insert(record_of(3, now), now));
        state.view.confirm(&id_of(&key(3)), now);
        // Discovered, answered eight days ago: not in use, `Good`.
        assert!(state.view.insert(record_of(4, old), old));
        state.view.confirm(&id_of(&key(4)), old);
        state.latency.insert(id_of(&key(4)), vec![40]);
        // Discovered, answered eight days ago, slower: after node 4.
        assert!(state.view.insert(record_of(5, old), old));
        state.view.confirm(&id_of(&key(5)), old);
        state.latency.insert(id_of(&key(5)), vec![90]);
    });
    let nodes = d.nodes().unwrap();
    let order: Vec<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(order, [id(3), id(1), id(4), id(5), id(2)]);
    let by_id = |n: usize| nodes.iter().find(|x| x.id == id(n)).unwrap();
    assert!(by_id(1).in_use && by_id(3).in_use);
    assert!(!by_id(2).in_use && !by_id(4).in_use);
    assert_eq!(by_id(1).reliability, Reliability::New);
    assert_eq!(by_id(3).reliability, Reliability::Good);
    assert_eq!(by_id(1).kind, NodeOriginKind::Manual);
    assert_eq!(by_id(2).kind, NodeOriginKind::Discovered);
    assert_eq!(by_id(4).latency_ms, Some(40));
    assert_eq!(by_id(2).latency_ms, None);
    assert_eq!(by_id(1).my_subscriptions, 0);
    // No report cached: no origin.
    assert!(nodes.iter().all(|n| n.origin.is_none()));
    // Confirmed and not avoided, without node 3: 4 and 5.
    assert_eq!(d.usable_nodes_if_blocked(id(3)).unwrap(), 2);
    assert_eq!(d.usable_nodes_if_blocked(id(1)).unwrap(), 3);
}

/// A node forced to protocol 4 knows nothing of `Info`: no report, and
/// the version it spoke.
#[tokio::test(flavor = "multi_thread")]
async fn detail_of_v4_node_reports_unknown() {
    let nodes = network_with(0..1, |spec| spec.version = 4).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let dir = tempfile::tempdir().unwrap();
    tokio::task::spawn_blocking(move || {
        let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
        d.add_node(id.clone(), addr).unwrap();
        let detail = d.node_detail(id.clone()).unwrap();
        assert_eq!(detail.report, None);
        assert_eq!(detail.peer_version, None);
        assert_eq!(detail.fetched_at, None);
        // The refresh dials it: still no report, the version it speaks.
        let detail = d.refresh_node_info(id.clone()).unwrap();
        assert_eq!(detail.report, None);
        assert_eq!(detail.peer_version, Some(4));
        assert_eq!(detail.fetched_at, None);
        assert!(detail.node.latency_ms.is_some());
        // Nothing stored about the version: the cached detail does not know it.
        assert_eq!(d.node_detail(id).unwrap().peer_version, None);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_node_info_against_test_node() {
    let nodes = network(0..1, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let dir = tempfile::tempdir().unwrap();
    tokio::task::spawn_blocking(move || {
        let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
        assert!(matches!(
            d.node_detail(id.clone()),
            Err(BarkingError::NotFound)
        ));
        d.add_node(id.clone(), addr).unwrap();
        let detail = d.refresh_node_info(id.clone()).unwrap();
        let report = detail.report.clone().expect("a protocol 5 node reports");
        assert_eq!(report.protocol, 5);
        assert!(!report.software.is_empty());
        assert_eq!(detail.peer_version, Some(5));
        assert!(detail.fetched_at.is_some());
        assert!(detail.node.latency_ms.is_some());
        assert_eq!(detail.node.id, id);
        // Cached: the detail reads it back without a dial.
        let cached = d.node_detail(id.clone()).unwrap();
        assert_eq!(cached.report, Some(report));
        assert_eq!(cached.peer_version, Some(5));
        // The node answered as itself.
        assert_ne!(cached.node.reliability, Reliability::New);

        // A blocked node is never dialled.
        d.block_node(id.clone()).unwrap();
        assert!(matches!(
            d.refresh_node_info(id.clone()),
            Err(BarkingError::InvalidInput { detail }) if detail.contains("node is blocked")
        ));
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[test]
fn refresh_of_unreachable_node_is_network_error() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = id_of(&key(1)).to_string();
    // Nothing listens there.
    d.add_node(id.clone(), "127.0.0.1:9".into()).unwrap();
    assert!(matches!(
        d.refresh_node_info(id.clone()),
        Err(BarkingError::Network { .. })
    ));
    // The node stays, its detail unchanged.
    assert_eq!(d.node_detail(id).unwrap().report, None);
}

#[test]
fn block_then_add_node_fails() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = id_of(&key(1)).to_string();
    d.add_node(id.clone(), "127.0.0.1:4001".into()).unwrap();
    d.block_node(id.clone()).unwrap();
    assert!(d.nodes().unwrap().is_empty());
    let blocked = d.blocked_nodes().unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].id, id);
    assert!(blocked[0].at > 0);
    assert!(blocked[0].origin.is_none());
    assert!(matches!(
        d.node_detail(id.clone()),
        Err(BarkingError::NotFound)
    ));
    assert!(matches!(
        d.add_node(id.clone(), "127.0.0.1:4001".into()),
        Err(BarkingError::InvalidInput { detail }) if detail.contains("node is blocked")
    ));
    // The block is in the transparency log.
    assert!(
        d.transparency_log(10, None, false)
            .unwrap()
            .iter()
            .any(|e| e.key.contains("block"))
    );
    d.unblock_node(id.clone()).unwrap();
    assert!(d.blocked_nodes().unwrap().is_empty());
    d.add_node(id, "127.0.0.1:4001".into()).unwrap();
    assert_eq!(d.nodes().unwrap().len(), 1);
}

#[test]
fn default_nodes_flow() {
    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = |n: usize| id_of(&key(n)).to_string();
    let defaults: Vec<DefaultNode> = (1..=3)
        .map(|n| DefaultNode {
            id: id(n),
            addr: format!("127.0.0.1:400{n}"),
        })
        .collect();
    d.add_default_nodes(defaults.clone()).unwrap();
    let nodes = d.nodes().unwrap();
    assert_eq!(nodes.len(), 3);
    assert!(
        nodes
            .iter()
            .all(|n| n.kind == NodeOriginKind::Bootstrap && n.in_use && n.manual)
    );
    assert_eq!(d.dismissed_defaults_count().unwrap(), 0);

    // Removed: dismissed, not added again at the next launch.
    d.remove_node(id(1)).unwrap();
    assert_eq!(d.dismissed_defaults_count().unwrap(), 1);
    d.add_default_nodes(defaults.clone()).unwrap();
    assert!(d.nodes().unwrap().iter().all(|n| n.id != id(1)));

    // Blocked: stays blocked through a reset.
    d.block_node(id(2)).unwrap();
    d.add_default_nodes(defaults.clone()).unwrap();
    assert_eq!(d.nodes().unwrap().len(), 1);
    assert_eq!(d.reset_default_nodes(defaults.clone()).unwrap(), 1);
    assert_eq!(d.dismissed_defaults_count().unwrap(), 0);
    let ids: Vec<String> = d.nodes().unwrap().into_iter().map(|n| n.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&id(1)) && ids.contains(&id(3)) && !ids.contains(&id(2)));

    // An invalid entry is refused.
    assert!(matches!(
        d.add_default_nodes(vec![DefaultNode {
            id: "XYZ".into(),
            addr: "127.0.0.1:4001".into(),
        }]),
        Err(BarkingError::InvalidInput { .. })
    ));
}

/// The origin a cached report declares, checked against the IP base given
/// by `set_ipdb_path` (spec node transparency §6.3).
#[test]
fn origin_checked_against_ipdb() {
    use barking_ffi::{BlockedNode, OriginVerdictView, OriginView};
    use barking_net::geo::{Range, encode};
    use barking_proto::{FillTier, NodeInfoReport, NodeOrigin};

    let dir = tempfile::tempdir().unwrap();
    let d = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    let id = |n: usize| id_of(&key(n)).to_string();
    let report = |asn: u32, country: [u8; 2]| NodeInfoReport {
        software: "barking-node 0.5.0".into(),
        protocol: 5,
        uptime_secs: 60,
        storage: FillTier::Low,
        wake: None,
        push_link: None,
        origin: Some(NodeOrigin {
            asn,
            as_name: "Example".into(),
            country,
            for_v6: false,
        }),
    };
    edit_net_state(&dir, |state, now| {
        for (n, asn, country) in [(2, 64500, *b"FR"), (3, 64501, *b"DE"), (4, 64502, *b"fr")] {
            assert!(state.view.insert(record_of(n, now), now));
            state.info.insert(
                id_of(&key(n)),
                barking_net::state::CachedInfo {
                    report: report(asn, country),
                    fetched_at: now,
                },
            );
        }
    });
    let origin_of = |n: usize| {
        d.nodes()
            .unwrap()
            .into_iter()
            .find(|x| x.id == id(n))
            .unwrap()
            .origin
            .unwrap()
    };
    // A lowercase country is not what a node sends: the origin is dropped
    // on load (`NodeInfoReport::sanitized`).
    assert_eq!(
        d.nodes()
            .unwrap()
            .into_iter()
            .find(|x| x.id == id(4))
            .unwrap()
            .origin,
        None
    );
    // No base given: nothing to check against.
    assert_eq!(
        origin_of(2),
        OriginView {
            asn: 64500,
            as_name: "Example".into(),
            country: "FR".into(),
            verdict: OriginVerdictView::NotInBase,
        }
    );
    // A base that does not open: the same, no error.
    d.set_ipdb_path(dir.path().join("missing.bin").display().to_string());
    assert_eq!(origin_of(2).verdict, OriginVerdictView::NotInBase);

    // 127.0.0.0/8 is AS64500 in France.
    let v4 = |a: [u8; 4]| u128::from(u32::from(std::net::Ipv4Addr::from(a)));
    let base = dir.path().join("ipdb.bin");
    std::fs::write(
        &base,
        encode(
            "test",
            &[Range {
                start: v4([127, 0, 0, 0]),
                end: v4([127, 255, 255, 255]),
                asn: 64500,
                country: *b"FR",
            }],
            &[],
        ),
    )
    .unwrap();
    d.set_ipdb_path(base.display().to_string());
    assert_eq!(origin_of(2).verdict, OriginVerdictView::Matches);
    assert_eq!(
        origin_of(3).verdict,
        OriginVerdictView::Mismatch {
            declared_country: "DE".into(),
            observed_country: "FR".into(),
            declared_asn: 64501,
            observed_asn: 64500,
        }
    );
    let detail = d.node_detail(id(3)).unwrap();
    assert_eq!(detail.peer_version, Some(5));
    assert_eq!(detail.v4.as_deref(), Some("127.0.0.3:4433"));
    assert_eq!(detail.report.unwrap().software, "barking-node 0.5.0");

    // A blocked node keeps the origin it declared; its address left with it.
    d.block_node(id(3)).unwrap();
    let blocked: Vec<BlockedNode> = d.blocked_nodes().unwrap();
    let origin = blocked[0].origin.clone().unwrap();
    assert_eq!((origin.asn, origin.country.as_str()), (64501, "DE"));
    assert_eq!(origin.verdict, OriginVerdictView::NoRecord);
}
