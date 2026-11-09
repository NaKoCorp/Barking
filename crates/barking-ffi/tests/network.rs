//! `Device` against a local test network: sync, quick sync, nodes added by hand.

use std::sync::Arc;

use barking_core::store::{Queries, Store};
use barking_ffi::{
    BarkingError, DeliveryChange, DeliveryState, Device, DeviceConfig, Message, PushSettings,
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
        alice.send_text("bob".into(), "salut".into()).unwrap();
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
            apns_token: vec![1; 65],
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
        alice2.send_text("bob".into(), "wake up".into()).unwrap();
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
        alice.send_text("bob".into(), "hello".into()).unwrap();
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
        bob.sync(30_000).unwrap();
        let received = message(&bob, "alice", "hello");
        assert!(!received.outgoing);
        assert!(received.delivery.is_none());

        // Bob's receipt makes it `Received`, noted by the sync that
        // fetched it.
        let mut noted = false;
        for _ in 0..5 {
            bob.sync(30_000).unwrap();
            let s = alice.sync(30_000).unwrap();
            noted |= s.delivery_changes.contains(&change);
            if state(&alice, "bob", "hello") == DeliveryState::Received {
                break;
            }
        }
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

        alice.send_text("bob".into(), "lost".into()).unwrap();
        expire_queue(&da, 1);
        let s = alice.sync(30_000).unwrap();
        let lost = DeliveryChange {
            contact: fb.clone(),
            message_id: message(&alice, "bob", "lost").id,
        };
        assert_eq!(s.failed, vec![lost.clone()], "{s:?}");
        assert!(s.delivery_changes.contains(&lost), "{s:?}");

        alice.send_text("bob".into(), "lost too".into()).unwrap();
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
        alice.send_text("bob".into(), "lost".into()).unwrap();
        alice.sync(30_000).unwrap();
        assert_eq!(state(&alice, "bob", "lost"), DeliveryState::OnNetwork);
        (da, alice, bob.fingerprint().unwrap())
    })
    .await
    .unwrap();

    // Bob stays offline; two days later the relays purged the message.
    // Alice's packet expired three hours ago: past the replication slack,
    // within the nodes' ack grace.
    set_clock_offset(2 * 86_400);
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
