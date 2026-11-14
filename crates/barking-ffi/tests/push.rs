//! Notification preferences and wake status through `Device`.

mod common;

use barking_ffi::{NotificationPrefs, PushPreview, PushSettings};

fn valid_settings() -> PushSettings {
    // A relay id is 52 base32 characters: take a real one from a node id.
    let id = barking_proto::NodeId([3; 32]).to_string();
    PushSettings {
        relay_host: "relay.example.org".into(),
        relay_port: 443,
        relay_id: id,
        seal_key_id: 1,
        seal_public: vec![7; 32],
        apns_token: vec![9; 32],
        sandbox: true,
    }
}

#[test]
fn prefs_default_then_set() {
    let dir = tempfile::tempdir().unwrap();
    let d = common::device(&dir, 1, "alice");
    let p = d.notification_prefs().unwrap();
    assert!(p.instant);
    assert_eq!(p.preview, PushPreview::NameAndText);
    assert_eq!(p.last_wake, None);
    d.set_instant(false).unwrap();
    d.set_preview(PushPreview::Generic).unwrap();
    d.note_wake(1_763_100_000).unwrap();
    let p = d.notification_prefs().unwrap();
    assert_eq!(
        p,
        NotificationPrefs {
            instant: false,
            preview: PushPreview::Generic,
            last_wake: Some(1_763_100_000),
        }
    );
}

#[test]
fn set_instant_keeps_push_config() {
    let dir = tempfile::tempdir().unwrap();
    let d = common::device(&dir, 1, "alice");
    d.set_push(Some(valid_settings())).unwrap();
    d.set_instant(false).unwrap();
    d.set_instant(true).unwrap();
    assert!(d.wake_status().unwrap().config_set);
}

#[test]
fn wake_status_empty() {
    let dir = tempfile::tempdir().unwrap();
    let d = common::device(&dir, 1, "alice");
    let s = d.wake_status().unwrap();
    assert!(!s.config_set);
    assert!(s.nodes.is_empty());
}
