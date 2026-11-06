//! Paged transparency log and the devices of a contact.

mod common;

use common::device;

#[test]
fn transparency_log_pages_and_filters() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    for i in 0..3 {
        alice.send_text(fb.clone(), format!("hello {i}")).unwrap();
    }
    let all = alice.transparency_log(100, None, false).unwrap();
    assert!(all.len() >= 4, "{all:?}");
    // Newest first.
    assert!(all.windows(2).all(|w| w[0].at >= w[1].at));
    let keys = barking_ffi::log_keys();
    assert!(all.iter().all(|e| keys.contains(&e.key)));
    // Paging continues where the page before stopped.
    let first = alice.transparency_log(2, None, false).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].id, all[0].id);
    // An event arrives between the pages: the next page neither repeats nor
    // skips an entry.
    alice.send_text(fb.clone(), "one more".into()).unwrap();
    let second = alice.transparency_log(2, Some(first[1].id), false).unwrap();
    assert_eq!(second[0].id, all[2].id);
    assert!(second.iter().all(|e| e.id < first[1].id));
    // Security only: the session, named by the contact's alias or name.
    let sec = alice.transparency_log(100, None, true).unwrap();
    assert!(!sec.is_empty() && sec.len() < all.len());
    assert!(sec.iter().all(|e| e.security));
    let session = sec
        .iter()
        .find(|e| e.key == "log.session_established")
        .expect("session logged");
    assert_eq!(session.args[0], "Bob");
}

#[test]
fn contact_devices_come_from_the_card() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = device(&da, 1, "Alice");
    let bob = device(&db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    let devices = alice.contact_devices(fb).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "Bob-phone");
    assert!(!devices[0].this_device && !devices[0].admin);
    assert_eq!(devices[0].id.len(), 32);
    assert!(devices[0].issued_at > 0);
    assert!(alice.contact_devices("nobody".into()).is_err());
}
