//! `Device` against a local test network: sync, quick sync, nodes added by hand.

use std::sync::Arc;

use barking_ffi::{BarkingError, Device, DeviceConfig};
use barking_node::testing::{id_of, key, network, stop_all};

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
fn outbox_counts_queued_packets() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob) = paired_devices(&da, &db);
    assert_eq!(alice.outbox_count().unwrap(), 0);
    alice.send_text("bob".into(), "hi".into()).unwrap();
    assert!(alice.outbox_count().unwrap() > 0);
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
