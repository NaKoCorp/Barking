//! Device linking: offer, request, package, finish; typed refusals.

mod common;

use barking_core::Core;
use barking_ffi::{BarkingError, LinkReason, begin_link, inspect_link_request};
use common::{config, device};

fn refused(r: Result<impl std::fmt::Debug, BarkingError>) -> LinkReason {
    match r {
        Err(BarkingError::LinkRefused { reason }) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn link_two_devices_with_history() {
    let (da, db, dt) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), Some("bob".into()))
        .unwrap();
    alice.send_text(fb.clone(), "hello".into()).unwrap();
    let offer = alice.link_offer().unwrap();
    assert!(offer.len() < 100);
    let pending = begin_link(config(&dt, 3), offer, "tablet".into()).unwrap();
    assert!(pending.device.is_pending_link().unwrap());
    assert_eq!(
        inspect_link_request(pending.request.clone()).unwrap(),
        "tablet"
    );
    let package = alice.link_device(pending.request, true).unwrap();
    assert_eq!(&package[..4], b"BKLK");
    pending.device.finish_link(package).unwrap();
    let t = pending.device;
    assert!(!t.is_pending_link().unwrap());
    assert_eq!(t.fingerprint().unwrap(), alice.fingerprint().unwrap());
    assert_eq!(t.contacts().unwrap().len(), 1);
    assert_eq!(t.messages_with(fb).unwrap()[0].body, "hello");
    assert_eq!(t.my_devices().unwrap().len(), 2);
}

#[test]
fn expired_offer_is_expired() {
    let (dold, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut rng = rand::rng();
    // An offer made an hour ago (valid 10 minutes).
    let past = barking_ffi_now() - 3600;
    let (mut core, _) =
        Core::create(&dold.path().join("db"), &[7; 32], "old", past, &mut rng).unwrap();
    let offer = core.link_offer(past, &mut rng).unwrap().to_bytes().to_vec();
    assert_eq!(
        refused(begin_link(config(&dt, 3), offer, "t".into())),
        LinkReason::Expired
    );
}

#[test]
fn offer_used_twice_is_used() {
    let (da, dt, du) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let alice = device(&da, 1, "Alice");
    let offer = alice.link_offer().unwrap();
    let p1 = begin_link(config(&dt, 3), offer.clone(), "t".into()).unwrap();
    let p2 = begin_link(config(&du, 4), offer, "u".into()).unwrap();
    alice.link_device(p1.request, false).unwrap();
    assert_eq!(
        refused(alice.link_device(p2.request, false)),
        LinkReason::Used
    );
}

#[test]
fn garbage_package_is_unreadable() {
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let p = begin_link(config(&dt, 3), alice.link_offer().unwrap(), "t".into()).unwrap();
    assert_eq!(
        refused(p.device.finish_link(vec![1, 2, 3])),
        LinkReason::Unreadable
    );
}

#[test]
fn linked_device_cannot_offer() {
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let p = begin_link(config(&dt, 3), alice.link_offer().unwrap(), "t".into()).unwrap();
    p.device
        .finish_link(alice.link_device(p.request, false).unwrap())
        .unwrap();
    assert_eq!(refused(p.device.link_offer()), LinkReason::NotAdmin);
}

fn barking_ffi_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
