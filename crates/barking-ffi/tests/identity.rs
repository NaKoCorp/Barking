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

#[tokio::test(flavor = "multi_thread")]
async fn admin_transfer_over_the_network() {
    use barking_node::testing::{network, stop_all};
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let a = device(&da, 1, "a");
        let pending =
            barking_ffi::begin_link(config(&dt, 2), a.link_offer().unwrap(), "t".into()).unwrap();
        pending
            .device
            .finish_link(a.link_device(pending.request, false).unwrap())
            .unwrap();
        let t = pending.device;
        for d in [&a, &t] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        let t_id = a
            .my_devices()
            .unwrap()
            .into_iter()
            .find(|d| d.name == "t")
            .unwrap()
            .id;
        assert_eq!(t_id.len(), 32);
        assert!(matches!(
            a.transfer_admin("zz".into()),
            Err(BarkingError::InvalidInput { .. })
        ));
        assert_eq!(a.admin_transfer_pending().unwrap(), None);
        a.transfer_admin(t_id.clone()).unwrap();
        assert_eq!(a.admin_transfer_pending().unwrap(), Some(t_id.clone()));
        assert!(matches!(
            a.link_offer(),
            Err(BarkingError::AdminTransferPending)
        ));
        // The ack may take more than one round over the test network.
        for _ in 0..5 {
            a.sync(30_000).unwrap();
            t.sync(30_000).unwrap();
            a.sync(30_000).unwrap();
            if a.admin_transfer_pending().unwrap().is_none() {
                break;
            }
        }
        assert_eq!(a.admin_transfer_pending().unwrap(), None);
        let admin = |d: &Device| -> Vec<String> {
            d.my_devices()
                .unwrap()
                .into_iter()
                .filter(|x| x.admin)
                .map(|x| x.name)
                .collect()
        };
        assert_eq!(admin(&a), vec!["t".to_owned()]);
        assert_eq!(admin(&t), vec!["t".to_owned()]);
        assert!(t.link_offer().is_ok());
        assert_eq!(a.removed().unwrap(), None);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[test]
fn leave_on_admin_is_is_admin_error() {
    let dir = tempfile::tempdir().unwrap();
    let a = device(&dir, 1, "a");
    assert!(matches!(a.leave(), Err(BarkingError::IsAdmin)));
    assert!(!a.leave_ready().unwrap());
    // Removing itself goes through `transfer_and_leave`, never `remove_device`.
    let me = a.my_devices().unwrap()[0].id.clone();
    assert!(matches!(
        a.remove_device(me),
        Err(BarkingError::InvalidInput { .. })
    ));
    assert!(matches!(
        a.remove_device("zz".into()),
        Err(BarkingError::InvalidInput { .. })
    ));
}

/// The administrator `a` and a linked device `t`, both on the test network.
fn linked_pair(
    da: &tempfile::TempDir,
    dt: &tempfile::TempDir,
    id: &str,
    addr: &str,
) -> (std::sync::Arc<Device>, std::sync::Arc<Device>, String) {
    let a = device(da, 1, "a");
    let pending =
        barking_ffi::begin_link(config(dt, 2), a.link_offer().unwrap(), "t".into()).unwrap();
    pending
        .device
        .finish_link(a.link_device(pending.request, false).unwrap())
        .unwrap();
    let t = pending.device;
    for d in [&a, &t] {
        d.add_node(id.to_owned(), addr.to_owned()).unwrap();
    }
    let t_id = a
        .my_devices()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "t")
        .unwrap()
        .id;
    (a, t, t_id)
}

/// Syncs `a` then `t` until `done`, a few rounds at most.
fn sync_until(a: &Device, t: &Device, done: impl Fn() -> bool) {
    for _ in 0..6 {
        a.sync(30_000).unwrap();
        t.sync(30_000).unwrap();
        if done() {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_device_via_ffi() {
    use barking_node::testing::{network, stop_all};
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (a, t, t_id) = linked_pair(&da, &dt, &id, &addr);
        // Only the administrator removes.
        let a_id = a.my_devices().unwrap()[0].id.clone();
        assert!(t.remove_device(a_id).is_err());
        assert_eq!(t.removed().unwrap(), None);
        a.remove_device(t_id).unwrap();
        assert_eq!(a.my_devices().unwrap().len(), 1);
        sync_until(&a, &t, || t.removed().unwrap().is_some());
        assert!(t.removed().unwrap().is_some());
        assert!(matches!(
            t.send_text("x".into(), "y".into()),
            Err(BarkingError::DeviceRemoved | BarkingError::NotFound)
        ));
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn linked_device_leaves_via_ffi() {
    use barking_node::testing::{network, stop_all};
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (a, t, _) = linked_pair(&da, &dt, &id, &addr);
        assert!(!t.leave_ready().unwrap());
        assert!(!t.leave_sent().unwrap());
        t.leave().unwrap();
        assert!(t.leave_ready().unwrap());
        // Queued, not yet deposited: no wipe yet.
        assert!(!t.leave_sent().unwrap());
        t.sync(30_000).unwrap();
        assert!(t.leave_sent().unwrap());
        sync_until(&t, &a, || a.my_devices().unwrap().len() == 1);
        assert_eq!(a.my_devices().unwrap().len(), 1);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_transfers_and_leaves_via_ffi() {
    use barking_node::testing::{network, stop_all};
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, dt) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let (a, t, t_id) = linked_pair(&da, &dt, &id, &addr);
        assert!(matches!(
            a.transfer_and_leave("zz".into()),
            Err(BarkingError::InvalidInput { .. })
        ));
        a.transfer_and_leave(t_id.clone()).unwrap();
        assert_eq!(a.admin_transfer_pending().unwrap(), Some(t_id));
        assert!(!a.leave_ready().unwrap());
        assert!(!a.leave_sent().unwrap());
        sync_until(&a, &t, || a.leave_sent().unwrap());
        assert!(a.leave_ready().unwrap());
        assert!(a.leave_sent().unwrap());
        // The `RemoveMe` queued at the ack reaches the new administrator.
        sync_until(&a, &t, || t.my_devices().unwrap().len() == 1);
        let left = t.my_devices().unwrap();
        assert_eq!(left.len(), 1);
        assert!(left[0].this_device && left[0].admin);
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}
