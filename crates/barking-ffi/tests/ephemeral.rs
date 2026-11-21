//! Ephemeral messages through the FFI: sending with a delay, the fields the
//! app reads, "seen", expiry on every sync, and a notification that never
//! carries the text.

mod common;

use std::sync::Arc;

use barking_core::Core;
use barking_core::identity::root::Fingerprint;
use barking_core::store::{Direction, MessageId, MessageInsert, MessageStatus, Queries, Store};
use barking_ffi::{BarkingError, Device};
use barking_node::testing::{TestNode, network, stop_all, wait_packets};
use common::{config, device};

/// Alice holds Bob's card and the other way round; no network.
fn paired(
    da: &tempfile::TempDir,
    db: &tempfile::TempDir,
) -> (Arc<Device>, Arc<Device>, String, String) {
    let alice = device(da, 1, "Alice");
    let bob = device(db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    let fa = bob
        .add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
        .unwrap();
    (alice, bob, fb, fa)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Inserts, behind the device's back, a received ephemeral of `contact`
/// already due (`expire_at` in the past); returns its row.
fn insert_due(dir: &tempfile::TempDir, key_byte: u8, contact: &str, tag: u8) -> i64 {
    insert_ephemeral(dir, key_byte, contact, tag, 60, Some(1_000), 1_060)
}

/// Inserts, behind the device's back, a received ephemeral of `contact`
/// with these columns; returns its row.
fn insert_ephemeral(
    dir: &tempfile::TempDir,
    key_byte: u8,
    contact: &str,
    tag: u8,
    ttl: u32,
    seen_at: Option<u64>,
    expire_at: u64,
) -> i64 {
    let cfg = config(dir, key_byte);
    let path = std::path::Path::new(&cfg.db_path);
    let fp: Fingerprint = Core::open(path, &[key_byte; 32], now())
        .unwrap()
        .resolve(contact)
        .unwrap();
    let store = Store::open(path, &[key_byte; 32]).unwrap();
    assert!(
        store
            .insert_message_row(&MessageInsert {
                contact_fp: fp,
                direction: Direction::In,
                body: "secret".into(),
                status: MessageStatus::Received,
                at: 1_000,
                message_id: MessageId([tag; 16]),
                wire_id: Some([tag; 16]),
                reply_to: None,
                reply_ref: None,
                placeholder: false,
                ttl_secs: Some(ttl),
                seen_at,
                expire_at: Some(expire_at),
            })
            .unwrap()
    );
    store
        .conn()
        .query_row(
            "SELECT id FROM messages WHERE message_id = ?1",
            [[tag; 16].as_slice()],
            |r| r.get(0),
        )
        .unwrap()
}

/// Rows of the table itself, unfiltered (reads hide due rows anyway).
fn stored_rows(dir: &tempfile::TempDir, key_byte: u8) -> i64 {
    let cfg = config(dir, key_byte);
    let store = Store::open(std::path::Path::new(&cfg.db_path), &[key_byte; 32]).unwrap();
    store
        .conn()
        .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn send_text_with_ttl_round_trips_to_message_fields() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    let before = now();
    alice
        .send_text(fb.clone(), "vanishing".into(), None, Some(300))
        .unwrap();
    alice
        .send_text(fb.clone(), "plain".into(), None, None)
        .unwrap();
    let after = now();
    let messages = alice.messages_with(fb.clone()).unwrap();
    let m = messages.iter().find(|m| m.body == "vanishing").unwrap();
    assert_eq!(m.ttl_secs, Some(300));
    // Sent from here: seen at once, erased `ttl` after the send.
    let seen = m.seen_at.unwrap();
    assert!((before..=after).contains(&seen), "{m:?}");
    assert_eq!(m.expire_at, Some(seen + 300));
    let plain = messages.iter().find(|m| m.body == "plain").unwrap();
    assert_eq!(
        (plain.ttl_secs, plain.seen_at, plain.expire_at),
        (None, None, None)
    );
    // The app's timer: the earliest erasure.
    assert_eq!(alice.next_expiry().unwrap(), Some(seen + 300));
}

#[test]
fn send_text_refuses_a_ttl_out_of_bounds() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    for ttl in [0, 59, 604_801] {
        assert!(
            matches!(
                alice.send_text(fb.clone(), "x".into(), None, Some(ttl)),
                Err(BarkingError::InvalidInput { .. })
            ),
            "{ttl}"
        );
    }
    // Nothing written, nothing queued.
    assert!(alice.messages_with(fb.clone()).unwrap().is_empty());
    assert_eq!(alice.pending_count().unwrap(), 0);
    for ttl in [60, 604_800] {
        alice
            .send_text(fb.clone(), "x".into(), None, Some(ttl))
            .unwrap();
    }
}

#[test]
fn mark_seen_then_expire_ephemeral() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    // Nothing ephemeral: no timer, nothing to erase.
    assert_eq!(alice.next_expiry().unwrap(), None);
    assert!(alice.expire_ephemeral().unwrap().is_empty());
    let row = insert_due(&da, 1, &fb, 7);
    assert!(alice.messages_with(fb.clone()).unwrap().is_empty());
    assert_eq!(alice.next_expiry().unwrap(), Some(1_060));
    // Seen again: ignored (already seen, already due), no error.
    alice.mark_seen(vec![row, row + 1_000]).unwrap();
    assert_eq!(alice.expire_ephemeral().unwrap(), vec![row]);
    assert_eq!(alice.next_expiry().unwrap(), None);
    assert_eq!(stored_rows(&da, 1), 0);
    assert!(alice.expire_ephemeral().unwrap().is_empty());
}

/// A received ephemeral never shown: "seen" sets its erasure `ttl` later,
/// below the 7-day ceiling.
#[test]
fn mark_seen_sets_the_erasure() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    let ceiling = now() + 604_800;
    let row = insert_ephemeral(&da, 1, &fb, 9, 300, None, ceiling);
    let m = &alice.messages_with(fb.clone()).unwrap()[0];
    assert_eq!(
        (m.ttl_secs, m.seen_at, m.expire_at),
        (Some(300), None, Some(ceiling))
    );
    assert_eq!(alice.next_expiry().unwrap(), Some(ceiling));

    let before = now();
    alice.mark_seen(vec![row]).unwrap();
    let after = now();
    let m = &alice.messages_with(fb.clone()).unwrap()[0];
    let seen = m.seen_at.unwrap();
    assert!((before..=after).contains(&seen), "{m:?}");
    assert_eq!(m.expire_at, Some(seen + 300));
    assert_eq!(alice.next_expiry().unwrap(), Some(seen + 300));
    // Seen again: the first "seen" stays.
    alice.mark_seen(vec![row]).unwrap();
    assert_eq!(
        alice.messages_with(fb.clone()).unwrap()[0].seen_at,
        Some(seen)
    );
    // Not due yet: nothing erased.
    assert!(alice.expire_ephemeral().unwrap().is_empty());
}

#[test]
fn sync_runs_expiry_first() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    let row = insert_due(&da, 1, &fb, 7);
    assert_eq!(stored_rows(&da, 1), 1);
    // No node: the sync reaches no one, the expiry runs all the same.
    let s = alice.sync(1_000).unwrap();
    assert_eq!(s.expired, vec![row], "{s:?}");
    assert_eq!(stored_rows(&da, 1), 0);
    assert_eq!(alice.next_expiry().unwrap(), None);

    // The extension's quick sync too.
    let row = insert_due(&da, 1, &fb, 8);
    let s = alice.quick_sync(1_000).unwrap();
    assert_eq!(s.expired, vec![row], "{s:?}");
    assert_eq!(stored_rows(&da, 1), 0);
    // Nothing due: nothing in `expired`.
    assert!(alice.sync(1_000).unwrap().expired.is_empty());
}

/// A blocking device call, off the async test's thread.
async fn step<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

async fn settle(nodes: &[TestNode]) {
    let most = nodes.iter().map(TestNode::stored_packets).max().unwrap();
    wait_packets(nodes, most).await;
}

/// The notification of an ephemeral never carries its text; a plain one
/// still does.
#[tokio::test(flavor = "multi_thread")]
async fn new_message_for_ephemeral_has_no_text() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, bob, fb, dirs) = step(move || {
        let (da, db) = &dirs;
        let (a, b, fb, _fa) = paired(da, db);
        for d in [&a, &b] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        b.sync(30_000).unwrap();
        (a, b, fb, dirs)
    })
    .await;

    let a = alice.clone();
    step(move || {
        a.send_text(fb.clone(), "burn after reading".into(), None, Some(300))
            .unwrap();
        a.send_text(fb, "plain".into(), None, None).unwrap();
        a.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;
    let s = step(move || bob.sync(30_000).unwrap()).await;
    assert_eq!(s.new_messages.len(), 2, "{s:?}");
    let ephemeral = s.new_messages.iter().find(|m| m.ephemeral).unwrap();
    assert_eq!(ephemeral.text, "");
    assert!(!ephemeral.needs_update);
    let plain = s.new_messages.iter().find(|m| !m.ephemeral).unwrap();
    assert_eq!(plain.text, "plain");
    drop(dirs);
    stop_all(nodes).await;
}
