//! Contact requests and invites through the FFI: the list of requests and
//! its flags, accepting, refusing and blocking, the invite state and its
//! 24-hour cap.

mod common;

use std::path::Path;
use std::sync::Arc;

use barking_core::{Core, parse_fingerprint};
use barking_ffi::{BarkingError, ContactRequestInfo, Device, InviteStatus};
use common::{config, device};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn open(dir: &tempfile::TempDir, key_byte: u8) -> Core {
    let cfg = config(dir, key_byte);
    Core::open(Path::new(&cfg.db_path), &[key_byte; 32], now()).unwrap()
}

/// Hands every packet of `from`'s send queue to `to`, behind the devices'
/// backs (no network).
fn deliver(from: (&tempfile::TempDir, u8), to: (&tempfile::TempDir, u8)) {
    let packets = open(from.0, from.1).pending_outbox(now()).unwrap();
    let mut core = open(to.0, to.1);
    for p in packets {
        core.receive(&p, "t", now(), &mut rand::rng()).unwrap();
    }
}

/// `inviter` (key `key_byte`, in `dir`) adds Bob's card and invites him;
/// Bob (key 2, in `db`) receives the invite. Returns the inviter's
/// fingerprint, as Bob reads it in his requests.
fn invited_by(
    dir: &tempfile::TempDir,
    key_byte: u8,
    inviter: &Device,
    db: &tempfile::TempDir,
    bob: &Device,
) -> String {
    let fb = inviter
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    inviter.invite(fb).unwrap();
    deliver((dir, key_byte), (db, 2));
    inviter.fingerprint().unwrap()
}

struct Setup {
    dirs: (tempfile::TempDir, tempfile::TempDir),
    alice: Arc<Device>,
    bob: Arc<Device>,
    /// Alice's fingerprint.
    fa: String,
}

/// Alice invited Bob, who received it.
fn alice_invited_bob() -> Setup {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fa = invited_by(&da, 1, &alice, &db, &bob);
    Setup {
        dirs: (da, db),
        alice,
        bob,
        fa,
    }
}

fn only_request(bob: &Device) -> ContactRequestInfo {
    let mut list = bob.requests().unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    list.remove(0)
}

#[test]
fn invite_then_request_listed() {
    let s = alice_invited_bob();
    let r = only_request(&s.bob);
    assert_eq!(r.fingerprint, s.fa);
    assert_eq!(r.display_name, "Alice");
    assert_eq!(r.invite_count, 1);
    assert_eq!(r.pending_messages, 0);
    assert!(!r.hidden);
    assert!(r.unseen);
    assert!(!r.name_clash);
}

#[test]
fn invite_twice_is_too_soon() {
    let s = alice_invited_bob();
    let fb = s.bob.fingerprint().unwrap();
    match s.alice.invite(fb) {
        Err(BarkingError::TooSoon { retry_at }) => assert!(retry_at > now()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn invite_status_sent() {
    let s = alice_invited_bob();
    let fb = s.bob.fingerprint().unwrap();
    assert!(matches!(
        s.alice.invite_status(fb).unwrap(),
        InviteStatus::Sent { .. }
    ));
}

#[test]
fn request_safety_number_is_12_groups() {
    let s = alice_invited_bob();
    let code = s.bob.request_safety_number(s.fa.clone()).unwrap();
    assert_eq!(code.len(), 12);
    s.bob.accept_request(s.fa.clone(), None).unwrap();
    assert_eq!(code, s.bob.safety_number(s.fa).unwrap());
}

#[test]
fn accept_returns_contact_and_clears_request() {
    let s = alice_invited_bob();
    assert_eq!(s.bob.accept_request(s.fa.clone(), None).unwrap(), s.fa);
    assert!(s.bob.requests().unwrap().is_empty());
    let contacts = s.bob.contacts().unwrap();
    let alice = contacts.iter().find(|c| c.fingerprint == s.fa).unwrap();
    assert_eq!(alice.display_name, "Alice");
    assert!(!alice.verified);
}

#[test]
fn accept_with_taken_alias_is_invalid_input() {
    let s = alice_invited_bob();
    let dl = tempfile::tempdir().unwrap();
    let lea = device(&dl, 3, "Léa");
    s.bob
        .add_contact_bytes(lea.contact_card_bytes().unwrap(), Some("lea".into()))
        .unwrap();
    match s.bob.accept_request(s.fa.clone(), Some("lea".into())) {
        Err(BarkingError::InvalidInput { detail }) => assert_eq!(detail, "alias taken"),
        other => panic!("unexpected {other:?}"),
    }
    // Nothing written: the request is still there.
    assert_eq!(only_request(&s.bob).fingerprint, s.fa);
}

#[test]
fn refuse_and_block_clear_request() {
    let s = alice_invited_bob();
    s.bob.refuse_request(s.fa.clone()).unwrap();
    assert!(s.bob.requests().unwrap().is_empty());

    let t = alice_invited_bob();
    t.bob.block_request(t.fa.clone()).unwrap();
    assert!(t.bob.requests().unwrap().is_empty());
    // Blocked: a new invite from Alice, a day later (past her 24-hour cap),
    // is dropped and opens no request.
    let (da, db) = &t.dirs;
    let later = now() + 86_400 + 60;
    let fb = parse_fingerprint(&t.bob.fingerprint().unwrap()).unwrap();
    let again = open(da, 1).invite(&fb, later, &mut rand::rng()).unwrap();
    assert!(!again.is_empty());
    let mut bob = open(db, 2);
    for p in &again {
        bob.receive(&p.encode(), "t", later, &mut rand::rng())
            .unwrap();
    }
    assert!(t.bob.requests().unwrap().is_empty());
}

#[test]
fn hide_and_seen_flags() {
    let s = alice_invited_bob();
    s.bob.set_request_hidden(s.fa.clone(), true).unwrap();
    assert!(only_request(&s.bob).hidden);
    s.bob.mark_requests_seen().unwrap();
    assert!(!only_request(&s.bob).unseen);
}

#[test]
fn name_clash_flag() {
    let (da, db, dx) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let real = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    bob.add_contact_bytes(real.contact_card_bytes().unwrap(), None)
        .unwrap();
    // Another identity, named "alice".
    let other = device(&dx, 3, "alice");
    let fx = invited_by(&dx, 3, &other, &db, &bob);
    let r = only_request(&bob);
    assert_eq!(r.fingerprint, fx);
    assert!(r.name_clash);
}

#[test]
fn bad_fingerprint_is_invalid_input() {
    let s = alice_invited_bob();
    match s.bob.refuse_request("zz".into()) {
        Err(BarkingError::InvalidInput { detail }) => assert_eq!(detail, "fingerprint"),
        other => panic!("unexpected {other:?}"),
    }
}
