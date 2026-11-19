//! Reads during a long sync: they join the sync's lock instead of waiting
//! for it, while writes and other openings still wait (spec iOS foundations
//! §3.3).

mod common;

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use barking_ffi::{BarkingError, Device, DeviceConfig};
use barking_node::testing::{id_of, key};

/// A sync that runs for its whole deadline: its only node is a local port
/// that never answers (the socket must outlive the sync).
fn slow_node(d: &Device) -> UdpSocket {
    let hole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = hole.local_addr().unwrap().to_string();
    d.add_node(id_of(&key(0)).to_string(), addr).unwrap();
    hole
}

fn with_timeout(c: &DeviceConfig, ms: u64) -> DeviceConfig {
    let mut c = c.clone();
    c.lock_timeout_ms = ms;
    c
}

/// Waits until the sync holds the lock: an opening then gives up.
fn wait_for_sync_lock(cfg: &DeviceConfig) {
    let start = Instant::now();
    loop {
        match Device::open(with_timeout(cfg, 1)) {
            Err(BarkingError::Locked) => return,
            _ if start.elapsed() > Duration::from_secs(5) => panic!("the sync never took the lock"),
            _ => thread::sleep(Duration::from_millis(10)),
        }
    }
}

const SYNC_MS: u64 = 4_000;

#[test]
fn reads_do_not_wait_for_a_sync() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let cfg = common::config(&da, 1);
    let alice = common::device(&da, 1, "Alice");
    let bob = common::device(&db, 2, "Bob");
    alice
        .add_contact(bob.contact_card("Bob".into()).unwrap(), Some("bob".into()))
        .unwrap();
    alice.send_text("bob".into(), "hello".into()).unwrap();
    let id = alice.messages_with("bob".into()).unwrap()[0].id;
    let _hole = slow_node(&alice);

    let syncing = Arc::clone(&alice);
    let sync = thread::spawn(move || {
        let start = Instant::now();
        let s = syncing.sync(SYNC_MS);
        (s, start.elapsed())
    });
    wait_for_sync_lock(&cfg);

    // A conversation opens at once: every read it makes joins the sync's lock.
    let start = Instant::now();
    assert!(alice.removed().unwrap().is_none());
    let messages = alice.messages_with("bob".into()).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, "hello");
    assert!(alice.key_changes(0).unwrap().is_empty());
    assert_eq!(alice.deliveries_of(vec![id]).unwrap().len(), 1);
    let fp = alice.contacts().unwrap()[0].fingerprint.clone();
    alice.delivery_counts(fp).unwrap();
    assert_eq!(alice.chat_summaries().unwrap().len(), 1);
    alice.unread_counts().unwrap();
    alice.pending_count().unwrap();
    alice.pending_packets().unwrap();
    alice.message_delivery(id).unwrap();
    alice.message_route(id).unwrap();
    alice.display_name().unwrap();
    alice.fingerprint().unwrap();
    alice.my_devices().unwrap();
    alice.notification_prefs().unwrap();
    alice.wake_status().unwrap();
    alice.transparency_log(10, None, false).unwrap();
    let reads = start.elapsed();
    assert!(reads < Duration::from_secs(1), "reads took {reads:?}");

    // A write still waits for the sync: the lock keeps it out.
    let writer = Device::at(with_timeout(&cfg, 100)).unwrap();
    assert!(matches!(
        writer.send_text("bob".into(), "later".into()),
        Err(BarkingError::Locked)
    ));

    let (summary, took) = sync.join().unwrap();
    let summary = summary.unwrap();
    assert!(!summary.network_up);
    // The reads ran while the sync was in flight, not after it.
    assert!(took > reads + Duration::from_secs(1), "sync took {took:?}");
    // Once it is over, the lock is free again.
    assert!(Device::open(with_timeout(&cfg, 100)).is_ok());
    alice.send_text("bob".into(), "after".into()).unwrap();
}

#[test]
fn a_write_during_a_sync_waits_for_it() {
    let da = tempfile::tempdir().unwrap();
    let cfg = common::config(&da, 1);
    let alice = common::device(&da, 1, "Alice");
    let _hole = slow_node(&alice);
    let syncing = Arc::clone(&alice);
    let sync = thread::spawn(move || syncing.sync(1_500));
    wait_for_sync_lock(&cfg);
    // With a lock wait longer than the sync, the write goes through after it.
    let writer = Device::at(with_timeout(&cfg, 5_000)).unwrap();
    let start = Instant::now();
    writer.set_display_name("Alicia".into()).unwrap();
    assert!(start.elapsed() > Duration::from_millis(500));
    sync.join().unwrap().unwrap();
    assert_eq!(alice.display_name().unwrap(), "Alicia");
}
