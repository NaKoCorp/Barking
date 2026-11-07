//! Delivery API (spec Lot M §5.10) without a network: states, detail,
//! groups, deletion, retry and pending packets. The syncs (deposit, ack,
//! verdict) are in `network.rs`, which starts real nodes.

mod common;

use std::sync::Arc;

use barking_core::store::{Queries, Store};
use barking_ffi::{BarkingError, DeliveryState, Device};
use common::device;

/// Alice holds Bob's card (no alias); returns her device and Bob's
/// fingerprint. Bob's device is dropped: nothing here reaches him.
fn alice_with_bob(da: &tempfile::TempDir, db: &tempfile::TempDir) -> (Arc<Device>, String) {
    let alice = device(da, 1, "Alice");
    let bob = device(db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    (alice, fb)
}

/// Moves every packet of Alice's send queue past its expiry, as if a day
/// went by without a node: her next read fails them (`expire_due`).
fn expire_queue(da: &tempfile::TempDir) {
    let store = Store::open(&da.path().join("barking.db"), &[1; 32]).unwrap();
    store
        .conn()
        .execute("UPDATE outbox SET expires_at = 1", ())
        .unwrap();
}

fn id_of(alice: &Device, fb: &str, body: &str) -> i64 {
    alice
        .messages_with(fb.to_owned())
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
        .id
}

#[test]
fn sent_message_carries_its_delivery() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "hello".into()).unwrap();
    let m = &alice.messages_with(fb.clone()).unwrap()[0];
    let d = m.delivery.as_ref().unwrap();
    assert_eq!(d.state, DeliveryState::Pending);
    assert!(d.sealed_at > 0);
    assert_eq!(
        (d.deposited_at, d.received_at, d.expired_at),
        (None, None, None)
    );
    assert_eq!(
        (
            d.devices,
            d.devices_received,
            d.devices_left,
            d.devices_tried
        ),
        (1, 0, 0, 0)
    );
    assert_eq!(d.devices_pending, 1);
    // The chats list's last message keeps it too.
    let s = alice.chat_summaries().unwrap();
    let last = s[0].last.as_ref().unwrap();
    assert_eq!(
        last.delivery.as_ref().map(|d| d.state),
        Some(DeliveryState::Pending)
    );
}

#[test]
fn expired_before_deposit_is_not_delivered() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "lost".into()).unwrap();
    expire_queue(&da);
    let m = &alice.messages_with(fb).unwrap()[0];
    let d = m.delivery.as_ref().unwrap();
    assert_eq!(d.state, DeliveryState::NotDelivered);
    assert_eq!(d.expired_at, Some(1));
    // Never deposited: told apart from a verdict by `deposited_at`.
    assert_eq!(d.deposited_at, None);
    assert_eq!(d.devices_pending, 0);
}

#[test]
fn deliveries_of_tells_removed_from_no_summary() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "one".into()).unwrap();
    alice.send_text(fb.clone(), "two".into()).unwrap();
    let (one, two) = (id_of(&alice, &fb, "one"), id_of(&alice, &fb, "two"));
    alice.delete_message(one).unwrap();
    let u = alice.deliveries_of(vec![two, one, 9_999]).unwrap();
    assert_eq!(u.len(), 3);
    assert_eq!(u[0].message_id, two);
    assert!(!u[0].removed);
    assert_eq!(
        u[0].delivery.as_ref().unwrap().state,
        DeliveryState::Pending
    );
    for gone in &u[1..] {
        assert!(gone.removed, "{gone:?}");
        assert!(gone.delivery.is_none());
    }
    assert_eq!((u[1].message_id, u[2].message_id), (one, 9_999));
}

#[test]
fn message_delivery_lists_contact_devices() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "hello".into()).unwrap();
    let id = id_of(&alice, &fb, "hello");
    let detail = alice.message_delivery(id).unwrap().unwrap();
    assert_eq!(detail.message_id, id);
    assert_eq!(detail.delivery.state, DeliveryState::Pending);
    assert_eq!(detail.devices.len(), 1);
    let dev = &detail.devices[0];
    assert_eq!(dev.device.len(), 32);
    assert!(dev.device.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(dev.name, "Bob-phone");
    assert_eq!(dev.state, DeliveryState::Pending);
    assert_eq!((dev.deposited_at, dev.node.as_deref()), (None, None));
    assert!(detail.relays.is_empty());
    assert_eq!(detail.own_copies.total, 0);
    assert!(alice.message_delivery(9_999).unwrap().is_none());
}

#[test]
fn counts_and_pages_per_state() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "old".into()).unwrap();
    expire_queue(&da);
    alice.send_text(fb.clone(), "a".into()).unwrap();
    alice.send_text(fb.clone(), "b".into()).unwrap();
    let c = alice.delivery_counts(fb.clone()).unwrap();
    assert_eq!(
        (c.pending, c.on_network, c.received, c.not_delivered),
        (2, 0, 0, 1)
    );
    // Newest first, 1 per page.
    let p1 = alice
        .delivery_page(fb.clone(), DeliveryState::Pending, 1, 0)
        .unwrap();
    let p2 = alice
        .delivery_page(fb.clone(), DeliveryState::Pending, 1, 1)
        .unwrap();
    assert_eq!((p1.len(), p2.len()), (1, 1));
    assert_eq!((p1[0].body.as_str(), p2[0].body.as_str()), ("b", "a"));
    assert_eq!(p1[0].message_id, id_of(&alice, &fb, "b"));
    assert!(p1[0].at > 0);
    assert_eq!(p1[0].delivery.state, DeliveryState::Pending);
    let failed = alice
        .delivery_page(fb.clone(), DeliveryState::NotDelivered, 50, 0)
        .unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].body, "old");
    assert!(matches!(
        alice.delivery_counts("nobody".into()),
        Err(BarkingError::NotFound)
    ));
}

#[test]
fn delete_message_cancels_and_reports() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "oops".into()).unwrap();
    let id = id_of(&alice, &fb, "oops");
    let o = alice.delete_message(id).unwrap();
    assert_eq!(
        (o.deleted, o.cancelled, o.partly_cancelled, o.already_left),
        (1, 1, 0, 0)
    );
    assert!(o.still_receiving.is_empty());
    assert!(!o.own_copies_kept);
    // One message: its contact devices, none of them left (spec §6.7).
    assert_eq!((o.devices_left, o.devices_total), (0, 1));
    assert_eq!(o.changes.len(), 1);
    assert_eq!(
        (o.changes[0].contact.as_str(), o.changes[0].message_id),
        (fb.as_str(), id)
    );
    assert!(alice.messages_with(fb).unwrap().is_empty());
}

#[test]
fn delete_messages_and_cancel_all() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    for body in ["a", "b", "c"] {
        alice.send_text(fb.clone(), body.into()).unwrap();
    }
    let ids = vec![id_of(&alice, &fb, "a"), id_of(&alice, &fb, "b")];
    let o = alice.delete_messages(ids).unwrap();
    assert_eq!((o.deleted, o.cancelled), (2, 2));
    // Several messages: no per-message device count.
    assert_eq!((o.devices_left, o.devices_total), (0, 0));
    assert_eq!(o.changes.len(), 2);
    let o = alice.cancel_all_pending().unwrap();
    assert_eq!((o.deleted, o.cancelled), (1, 1));
    assert!(alice.messages_with(fb.clone()).unwrap().is_empty());
    assert_eq!(alice.pending_packets().unwrap().messages.len(), 0);
}

#[test]
fn retry_message_and_retry_all() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "one".into()).unwrap();
    let one = id_of(&alice, &fb, "one");
    // Still pending: nothing to retry, its own error for the app.
    assert!(matches!(
        alice.retry_message(one),
        Err(BarkingError::NothingToRetry)
    ));
    alice.send_text(fb.clone(), "two".into()).unwrap();
    expire_queue(&da);
    alice.retry_message(one).unwrap();
    let state = |body: &str| {
        alice
            .messages_with(fb.clone())
            .unwrap()
            .into_iter()
            .find(|m| m.body == body)
            .unwrap()
            .delivery
            .unwrap()
            .state
    };
    assert_eq!(state("one"), DeliveryState::Pending);
    assert_eq!(state("two"), DeliveryState::NotDelivered);
    assert_eq!(alice.retry_all(fb.clone()).unwrap(), 1);
    assert_eq!(state("two"), DeliveryState::Pending);
    assert_eq!(alice.retry_all(fb.clone()).unwrap(), 0);
}

#[test]
fn pending_packets_and_count() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, fb) = alice_with_bob(&da, &db);
    alice.send_text(fb.clone(), "waiting".into()).unwrap();
    let p = alice.pending_packets().unwrap();
    assert_eq!(p.messages.len(), 1);
    let m = &p.messages[0];
    assert_eq!(m.message_id, id_of(&alice, &fb, "waiting"));
    assert_eq!((m.contact.as_str(), m.name.as_str()), (fb.as_str(), "Bob"));
    assert_eq!(m.body, "waiting");
    assert!(m.sealed_at > 0 && m.expires_at > m.sealed_at);
    assert_eq!(
        (m.packets, m.devices, m.devices_left, m.devices_tried),
        (1, 1, 0, 0)
    );
    let sync: u32 = p.sync.iter().map(|s| s.packets).sum();
    assert_eq!(p.packets, m.packets + sync);
    assert_eq!(alice.pending_count().unwrap(), p.packets);
    expire_queue(&da);
    assert_eq!(alice.pending_count().unwrap(), 0);
}
