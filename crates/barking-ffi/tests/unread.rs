//! Unread marks and key changes, over a local test network.

mod common;

use barking_node::testing::{network, stop_all};
use common::device;

#[tokio::test(flavor = "multi_thread")]
async fn unread_counts_and_mark_read() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let db_path = db.path().join("barking.db");
    tokio::task::spawn_blocking(move || {
        let alice = device(&da, 1, "Alice");
        let bob = device(&db, 2, "Bob");
        let fb = alice
            .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
            .unwrap();
        let fa = bob
            .add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
            .unwrap();
        for d in [&alice, &bob] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        bob.sync(30_000).unwrap();
        for t in ["one", "two", "three"] {
            alice.send_text(fb.clone(), t.into()).unwrap();
        }
        let s = alice.sync(30_000).unwrap();
        assert!(s.sent >= 1, "{s:?}");
        bob.sync(30_000).unwrap();
        let counts = bob.unread_counts().unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(
            (counts[0].contact.as_str(), counts[0].count),
            (fa.as_str(), 3)
        );
        let msgs = bob.messages_with(fa.clone()).unwrap();
        let second = msgs.iter().filter(|m| !m.outgoing).nth(1).unwrap().id;
        bob.mark_read(fa.clone(), second).unwrap();
        assert_eq!(bob.unread_counts().unwrap()[0].count, 1);
        // The marks survive a reopen.
        drop(bob);
        let bob = barking_ffi::Device::open(common::config(&db, 2)).unwrap();
        assert_eq!(bob.unread_counts().unwrap()[0].count, 1);
        // No contact fingerprint in clear in the database file.
        let raw = std::fs::read(&db_path).unwrap();
        let fp_text = fa.replace('-', "");
        assert!(!String::from_utf8_lossy(&raw).contains(&fp_text));
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}
