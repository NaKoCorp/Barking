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

/// Alice, known to Bob, recovers her identity on a new device (§7.7) and
/// invites him: her card replaces the old device by the new one, which
/// `device_changes` reports. Bob's other contact links a second device
/// (an addition only): not reported.
#[test]
fn device_changes_lists_replaced_device() {
    let (da, dr, db) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let bob = device(&db, 2, "Bob");
    // The original device, a while ago: the recovered list is newer.
    let before = now() - 100;
    let mut rng = rand::rng();
    let (a, phrase) = Core::create(
        &da.path().join("a.db"),
        &[1; 32],
        "a-phone",
        before,
        &mut rng,
    )
    .unwrap();
    let fa = bob
        .add_contact_bytes(a.contact_card("Alice").unwrap().encode(), None)
        .unwrap();
    assert!(bob.device_changes(0).unwrap().is_empty());
    drop(a);
    let r = barking_ffi::recover_device(
        common::config(&dr, 3),
        phrase.as_str().to_owned(),
        "r-phone".into(),
    )
    .unwrap();
    r.set_display_name("Alice".into()).unwrap();
    let fb = r
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    r.invite(fb).unwrap();
    deliver((&dr, 3), (&db, 2));
    let changes = bob.device_changes(0).unwrap();
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].contact, fa);
    assert!(changes[0].at >= before);
    // Nothing after the change.
    assert!(bob.device_changes(changes[0].at + 1).unwrap().is_empty());

    // Carol links a tablet: her card gains a device, loses none.
    let (dc, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let carol = device(&dc, 4, "Carol");
    let fc = bob
        .add_contact_bytes(carol.contact_card_bytes().unwrap(), None)
        .unwrap();
    carol
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    let pending = barking_ffi::begin_link(
        common::config(&dt, 5),
        carol.link_offer().unwrap(),
        "t".into(),
    )
    .unwrap();
    pending
        .device
        .finish_link(carol.link_device(pending.request, false).unwrap())
        .unwrap();
    drop(pending.device);
    let packets = open(&dc, 4).pending_outbox(now()).unwrap();
    let mut b = open(&db, 2);
    for p in packets {
        // Packets for Carol's tablet are not Bob's to read.
        let _ = b.receive(&p, "t", now(), &mut rand::rng());
    }
    drop(b);
    let carol_card = bob.contact_devices(fc.clone()).unwrap();
    assert_eq!(carol_card.len(), 2, "Carol's card update reached Bob");
    let changes = bob.device_changes(0).unwrap();
    assert!(changes.iter().all(|c| c.contact != fc), "{changes:?}");
    assert_eq!(changes.len(), 1);
}

/// Hands `from`'s send queue to `to` like `deliver`, ignoring the packets
/// `to` cannot read (those for another device).
fn deliver_any(from: (&tempfile::TempDir, u8), to: (&tempfile::TempDir, u8)) {
    let packets = open(from.0, from.1).pending_outbox(now()).unwrap();
    let mut core = open(to.0, to.1);
    for p in packets {
        let _ = core.receive(&p, "t", now(), &mut rand::rng());
    }
}

/// Spec §7.2: a message held for a hidden request, seen before, moves it
/// (a reload, the indicator lit again) without any new invitation. The
/// sync reports it in `request_contacts`, not in `new_requests`.
#[test]
fn held_message_moves_request_in_sync() {
    let s = alice_invited_bob();
    // No node: the syncs reach no one; the first one sees the request.
    assert_eq!(
        s.bob.sync(1_000).unwrap().request_contacts,
        Vec::<String>::new()
    );
    s.bob.set_request_hidden(s.fa.clone(), true).unwrap();
    s.bob.mark_requests_seen().unwrap();
    let fb = s.bob.fingerprint().unwrap();
    s.alice.send_text(fb, "un".into(), None, None).unwrap();
    let (da, db) = &s.dirs;
    deliver_any((da, 1), (db, 2));
    let sum = s.bob.sync(1_000).unwrap();
    assert_eq!(sum.request_contacts, vec![s.fa.clone()]);
    assert!(sum.new_requests.is_empty());
    let r = only_request(&s.bob);
    assert!(r.hidden && r.unseen, "{r:?}");
    assert_eq!(r.pending_messages, 1);
    // Nothing moved since: nothing reported.
    assert!(s.bob.sync(1_000).unwrap().request_contacts.is_empty());
}

/// A request refused on my other device leaves this one's list: the next
/// sync reports it, so that the list and an open request page reload.
#[test]
fn refusal_from_my_other_device_moves_request_in_sync() {
    let (da, db, dt) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let pending =
        barking_ffi::begin_link(config(&dt, 3), bob.link_offer().unwrap(), "t".into()).unwrap();
    pending
        .device
        .finish_link(bob.link_device(pending.request, false).unwrap())
        .unwrap();
    let tablet = pending.device;
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    alice.invite(fb).unwrap();
    let fa = alice.fingerprint().unwrap();
    deliver_any((&da, 1), (&db, 2));
    deliver_any((&da, 1), (&dt, 3));
    assert_eq!(only_request(&tablet).fingerprint, fa);
    tablet.sync(1_000).unwrap();
    bob.refuse_request(fa.clone()).unwrap();
    deliver_any((&db, 2), (&dt, 3));
    assert!(tablet.requests().unwrap().is_empty());
    assert_eq!(tablet.sync(1_000).unwrap().request_contacts, vec![fa]);
}

/// A blocked requester is no contact, yet Settings lists it by fingerprint
/// (`blocked_fingerprints`) and unblocks it (`unblock_contact` takes a
/// bare fingerprint): a later invitation opens a request again.
#[test]
fn blocked_requester_listed_and_unblocked() {
    let t = alice_invited_bob();
    t.bob.block_request(t.fa.clone()).unwrap();
    assert!(t.bob.blocked_contacts().unwrap().is_empty());
    assert_eq!(t.bob.blocked_fingerprints().unwrap(), vec![t.fa.clone()]);
    t.bob.unblock_contact(t.fa.clone()).unwrap();
    assert!(t.bob.blocked_fingerprints().unwrap().is_empty());
    // Sealed after the unblock (and past Alice's 24-hour cap): kept.
    let (da, db) = &t.dirs;
    let later = now() + 86_400 + 60;
    let fb = parse_fingerprint(&t.bob.fingerprint().unwrap()).unwrap();
    let again = open(da, 1).invite(&fb, later, &mut rand::rng()).unwrap();
    let mut bob = open(db, 2);
    for p in &again {
        bob.receive(&p.encode(), "t", later, &mut rand::rng())
            .unwrap();
    }
    drop(bob);
    assert_eq!(only_request(&t.bob).fingerprint, t.fa);
}

/// A blocked contact is listed by `blocked_contacts`, not twice.
#[test]
fn blocked_contact_is_not_a_blocked_fingerprint() {
    let s = alice_invited_bob();
    s.bob.accept_request(s.fa.clone(), None).unwrap();
    s.bob.block_contact(s.fa.clone()).unwrap();
    assert_eq!(s.bob.blocked_contacts().unwrap().len(), 1);
    assert!(s.bob.blocked_fingerprints().unwrap().is_empty());
}
