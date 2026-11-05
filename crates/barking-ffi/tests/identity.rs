//! Identity: recovery, display name, my devices, the BIP-39 list.

mod common;

use barking_ffi::{BarkingError, Device, bip39_words, recover_device};
use common::{config, device};

#[test]
fn recover_restores_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let created = Device::create(config(&dir, 3), "first".into()).unwrap();
    let fp = created.device.fingerprint().unwrap();
    let phrase = created.recovery_phrase.clone();
    drop(created);
    std::fs::remove_file(dir.path().join("barking.db")).unwrap();
    let again = recover_device(config(&dir, 3), phrase, "second".into()).unwrap();
    assert_eq!(again.fingerprint().unwrap(), fp);
}

#[test]
fn recover_rejects_bad_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let words = bip39_words();
    let phrase = words[..23].join(" ");
    assert!(matches!(
        recover_device(config(&dir, 3), phrase, "x".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
    assert!(!barking_ffi::device_exists(config(&dir, 3)));
}

#[test]
fn bip39_words_has_2048() {
    let w = bip39_words();
    assert_eq!(w.len(), 2048);
    assert_eq!(w[0], "abandon");
    assert_eq!(w[2047], "zoo");
}

#[test]
fn display_name_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let d = device(&dir, 1, "Alice");
    assert_eq!(d.display_name().unwrap(), "Alice");
    assert!(matches!(
        d.set_display_name("x".repeat(65)),
        Err(BarkingError::InvalidInput { .. })
    ));
}

#[test]
fn my_devices_has_this_device() {
    let dir = tempfile::tempdir().unwrap();
    let d = device(&dir, 1, "Alice");
    let devs = d.my_devices().unwrap();
    assert_eq!(devs.len(), 1);
    assert!(devs[0].this_device && devs[0].admin);
    assert_eq!(devs[0].name, "Alice-phone");
}
