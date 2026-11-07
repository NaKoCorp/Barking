//! `Device`: identity, contacts and messages, one lock per call.

use std::os::fd::AsRawFd;

use barking_ffi::{BarkingError, Device, DeviceConfig};

fn config(dir: &tempfile::TempDir, key_byte: u8) -> DeviceConfig {
    DeviceConfig {
        db_path: dir.path().join("barking.db").display().to_string(),
        lock_path: dir.path().join("barking.lock").display().to_string(),
        db_key: vec![key_byte; 32],
        lock_timeout_ms: 1_000,
        allow_private: false,
    }
}

#[test]
fn create_then_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let created = Device::create(config(&dir, 7), "iphone".into()).unwrap();
    assert_eq!(created.recovery_phrase.split(' ').count(), 24);
    let fp = created.device.fingerprint().unwrap();
    drop(created);
    assert_eq!(
        Device::open(config(&dir, 7))
            .unwrap()
            .fingerprint()
            .unwrap(),
        fp
    );
}

#[test]
fn open_missing_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!barking_ffi::device_exists(config(&dir, 7)));
    assert!(matches!(
        Device::open(config(&dir, 7)),
        Err(BarkingError::NotFound)
    ));
}

#[test]
fn wrong_key_is_storage_error() {
    let dir = tempfile::tempdir().unwrap();
    Device::create(config(&dir, 7), "iphone".into()).unwrap();
    assert!(barking_ffi::device_exists(config(&dir, 8)));
    assert!(matches!(
        Device::open(config(&dir, 8)),
        Err(BarkingError::Storage { .. })
    ));
}

#[test]
fn create_on_existing_db_fails_and_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let fp = Device::create(config(&dir, 7), "iphone".into())
        .unwrap()
        .device
        .fingerprint()
        .unwrap();
    assert!(matches!(
        Device::create(config(&dir, 7), "again".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
    assert_eq!(
        Device::open(config(&dir, 7))
            .unwrap()
            .fingerprint()
            .unwrap(),
        fp
    );
}

#[test]
fn short_key_is_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir, 7);
    c.db_key.truncate(16);
    assert!(matches!(
        Device::create(c, "x".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
}

#[test]
fn cards_contacts_and_outgoing_message() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = Device::create(config(&da, 1), "a".into()).unwrap().device;
    let bob = Device::create(config(&db, 2), "b".into()).unwrap().device;
    let fp_b = alice
        .add_contact(bob.contact_card("Bob".into()).unwrap(), Some("bob".into()))
        .unwrap();
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].display_name, "Bob");
    assert_eq!(contacts[0].fingerprint, fp_b);
    alice.send_text("bob".into(), "salut".into()).unwrap();
    let msgs = alice.messages_with(fp_b).unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].outgoing);
    assert_eq!(msgs[0].body, "salut");
    // Not deposited on any node yet.
    assert_eq!(msgs[0].status, "queued");
}

#[test]
fn unknown_contact_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    assert!(matches!(
        alice.send_text("nobody".into(), "x".into()),
        Err(BarkingError::NotFound)
    ));
}

#[test]
fn invalid_card_is_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Device::create(config(&dir, 1), "a".into()).unwrap().device;
    assert!(matches!(
        alice.add_contact("not a card".into(), None),
        Err(BarkingError::InvalidInput { .. })
    ));
}

#[test]
fn call_waits_for_lock_then_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir, 1);
    c.lock_timeout_ms = 200;
    let dev = Device::create(c.clone(), "a".into()).unwrap().device;
    let held = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&c.lock_path)
        .unwrap();
    // SAFETY: `flock` on a descriptor owned by `held`, alive until the end.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(matches!(dev.fingerprint(), Err(BarkingError::Locked)));
}

#[test]
fn failed_create_leaves_no_database() {
    let dir = tempfile::tempdir().unwrap();
    // Too long a name fails after the database file is written.
    let long = "x".repeat(10_000);
    assert!(matches!(
        Device::create(config(&dir, 7), long),
        Err(BarkingError::InvalidInput { .. })
    ));
    assert!(!barking_ffi::device_exists(config(&dir, 7)));
    assert!(Device::create(config(&dir, 7), "iphone".into()).is_ok());
}

#[test]
fn at_takes_no_lock_and_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir, 1);
    c.lock_timeout_ms = 200;
    let fp = Device::create(c.clone(), "a".into())
        .unwrap()
        .device
        .fingerprint()
        .unwrap();
    let held = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&c.lock_path)
        .unwrap();
    // SAFETY: `flock` on a descriptor owned by `held`.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    let dev = Device::at(c.clone()).unwrap();
    assert!(matches!(dev.fingerprint(), Err(BarkingError::Locked)));
    drop(held);
    assert_eq!(dev.fingerprint().unwrap(), fp);
}

#[test]
fn at_without_database_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Device::at(config(&dir, 1)),
        Err(BarkingError::NotFound)
    ));
}
