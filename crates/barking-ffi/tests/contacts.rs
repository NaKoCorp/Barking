//! Contacts: card bytes, own card, verification, alias, removal, safety code.

mod common;

use barking_ffi::{BarkingError, inspect_card, inspect_card_text};
use common::device;

#[test]
fn card_bytes_roundtrip_and_preview() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let bytes = alice.contact_card_bytes().unwrap();
    let preview = inspect_card(bytes.clone()).unwrap();
    assert_eq!(preview.fingerprint, alice.fingerprint().unwrap());
    assert_eq!(preview.display_name, "Alice");
    assert_eq!(
        bob.add_contact_bytes(bytes, None).unwrap(),
        alice.fingerprint().unwrap()
    );
    let text = alice.contact_card("Alice".into()).unwrap();
    assert_eq!(
        inspect_card_text(text).unwrap().fingerprint,
        alice.fingerprint().unwrap()
    );
}

#[test]
fn foreign_bytes_are_not_a_card() {
    assert!(matches!(
        inspect_card(b"https://example.org".to_vec()),
        Err(BarkingError::InvalidInput { .. })
    ));
    let da = tempfile::tempdir().unwrap();
    let alice = device(&da, 1, "Alice");
    let mut cut = alice.contact_card_bytes().unwrap();
    cut.truncate(100);
    assert!(matches!(
        inspect_card(cut),
        Err(BarkingError::InvalidInput { .. })
    ));
}

#[test]
fn own_card_is_refused() {
    let da = tempfile::tempdir().unwrap();
    let alice = device(&da, 1, "Alice");
    let own = alice.contact_card_bytes().unwrap();
    match alice.add_contact_bytes(own, None) {
        Err(BarkingError::InvalidInput { detail }) => assert_eq!(detail, "own card"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn verify_unverify_alias_remove() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), Some("bob".into()))
        .unwrap();
    alice.mark_verified(fb.clone()).unwrap();
    assert!(alice.contacts().unwrap()[0].verified);
    alice.unmark_verified(fb.clone()).unwrap();
    assert!(!alice.contacts().unwrap()[0].verified);
    alice.set_alias(fb.clone(), "bobby".into()).unwrap();
    assert_eq!(alice.contacts().unwrap()[0].alias.as_deref(), Some("bobby"));
    alice.remove_contact(fb).unwrap();
    assert!(alice.contacts().unwrap().is_empty());
}

#[test]
fn safety_number_is_12_groups_of_5() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    let fa = bob
        .add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
        .unwrap();
    let a = alice.safety_number(fb).unwrap();
    assert_eq!(a.len(), 12);
    assert!(
        a.iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit()))
    );
    assert_eq!(a, bob.safety_number(fa).unwrap());
}

#[test]
fn messages_have_ids() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    alice.send_text(fb.clone(), "one".into(), None).unwrap();
    alice.send_text(fb.clone(), "two".into(), None).unwrap();
    let m = alice.messages_with(fb).unwrap();
    assert!(m[0].id < m[1].id);
    assert!(m[0].delivery.is_some());
}

#[test]
fn chat_summaries_in_one_call() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), Some("bob".into()))
        .unwrap();
    alice.send_text(fb.clone(), "first".into(), None).unwrap();
    alice.send_text(fb.clone(), "last".into(), None).unwrap();
    let s = alice.chat_summaries().unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].contact.fingerprint, fb);
    let last = s[0].last.as_ref().unwrap();
    assert_eq!((last.body.as_str(), last.outgoing), ("last", true));
    assert_eq!(s[0].unread, 0);
}

#[test]
fn block_hides_the_contact_and_unblock_restores_it() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let card = bob.contact_card_bytes().unwrap();
    let fb = alice
        .add_contact_bytes(card.clone(), Some("bob".into()))
        .unwrap();
    alice.send_text(fb.clone(), "hi".into(), None).unwrap();
    alice.block_contact(fb.clone()).unwrap();
    assert!(alice.contacts().unwrap().is_empty());
    assert!(alice.chat_summaries().unwrap().is_empty());
    let blocked = alice.blocked_contacts().unwrap();
    assert_eq!(blocked.len(), 1);
    assert!(blocked[0].blocked && blocked[0].fingerprint == fb);
    assert!(matches!(
        alice.send_text(fb.clone(), "no".into(), None),
        Err(BarkingError::ContactBlocked)
    ));
    // The history stays stored.
    assert_eq!(alice.messages_with(fb.clone()).unwrap().len(), 1);
    alice.unblock_contact(fb.clone()).unwrap();
    assert!(alice.blocked_contacts().unwrap().is_empty());
    assert_eq!(alice.chat_summaries().unwrap().len(), 1);
    assert!(!alice.contacts().unwrap()[0].blocked);
}

#[test]
fn a_blocked_card_is_not_added_again() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let card = bob.contact_card_bytes().unwrap();
    let fb = alice.add_contact_bytes(card.clone(), None).unwrap();
    alice.block_contact(fb).unwrap();
    assert!(matches!(
        alice.add_contact_bytes(card, None),
        Err(BarkingError::ContactBlocked)
    ));
}

#[test]
fn draft_roundtrip() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    assert_eq!(alice.draft(fb.clone()).unwrap(), None);
    alice.set_draft(fb.clone(), "hi".into()).unwrap();
    assert_eq!(alice.draft(fb.clone()).unwrap(), Some("hi".to_string()));
    alice.set_draft(fb.clone(), "".into()).unwrap();
    assert_eq!(alice.draft(fb).unwrap(), None);
}
