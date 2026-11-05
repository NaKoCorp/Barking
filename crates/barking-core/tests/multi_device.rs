//! Multi-device: linking a new device (offer, request,
//! acceptance, completion), with two and three parties.

use std::path::{Path, PathBuf};

use barking_core::core::{HistoryArchive, LinkBundle, LinkOffer};
use barking_core::identity::Fingerprint;
use barking_core::identity::device_list::MAX_DEVICES;
use barking_core::packet::{Kind, Packet};
use barking_core::store::{Direction, MessageStatus};
use barking_core::transparency::{SyncKind, TransparencyEvent};
use barking_core::{Core, CoreError, LinkRequest, ReceiveOutcome};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000;
const T: &str = "file";

struct Dev {
    core: Core,
    path: PathBuf,
    key: [u8; 32],
}

/// One temporary directory per test, several databases inside.
fn dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn create(d: &Path, file: &str, seed: u8, rng: &mut StdRng) -> Dev {
    let path = d.join(file);
    let key = [seed; 32];
    let (core, _) = Core::create(&path, &key, file, NOW, rng).unwrap();
    Dev { core, path, key }
}

fn begin(
    d: &Path,
    file: &str,
    seed: u8,
    offer: &LinkOffer,
    rng: &mut StdRng,
) -> (Dev, LinkRequest) {
    let path = d.join(file);
    let key = [seed; 32];
    let (core, req) = Core::begin_link(&path, &key, offer, file, NOW, rng).unwrap();
    (Dev { core, path, key }, req)
}

fn events(core: &Core) -> Vec<TransparencyEvent> {
    core.transparency_log(10_000)
        .unwrap()
        .into_iter()
        .map(|(_, e)| e)
        .collect()
}

fn link_err(r: Result<impl Sized, CoreError>) -> &'static str {
    match r {
        Err(CoreError::Link(reason)) => reason,
        Err(e) => panic!("CoreError::Link expected, got {e:?}"),
        Ok(_) => panic!("CoreError::Link expected, got Ok"),
    }
}

/// A (administrator) with two contacts, Alice and Bob; Bob verified.
fn admin_with_contacts(d: &Path, rng: &mut StdRng) -> (Dev, Dev, Dev) {
    let mut a = create(d, "a", 1, rng);
    let alice = create(d, "alice", 2, rng);
    let bob = create(d, "bob", 3, rng);
    a.core
        .add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            rng,
        )
        .unwrap();
    let bob_fp = a
        .core
        .add_contact(&bob.core.contact_card("Bob").unwrap(), None, NOW, rng)
        .unwrap();
    a.core.mark_verified(&bob_fp, NOW, rng).unwrap();
    (a, alice, bob)
}

#[test]
fn link_full_flow() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(1);
    let (mut a, alice, bob) = admin_with_contacts(d.path(), &mut rng);
    let version = a.core.contact_card("A").unwrap().devices.version;

    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    assert_eq!(offer.expires_at, NOW + 600);
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    assert_eq!(t.core.fingerprint(), a.core.fingerprint());
    let out = a.core.link_device(&req, false, NOW + 1, &mut rng).unwrap();
    assert!(out.history.is_none());
    // A card update for Alice and one for Bob (one device each).
    assert_eq!(out.packets.len(), 2);
    // Going through bytes, as in the CLI.
    let bundle = LinkBundle::from_bytes(&out.bundle.to_bytes()).unwrap();
    t.core.finish_link(&bundle, None, NOW + 2).unwrap();

    assert_eq!(t.core.fingerprint(), a.core.fingerprint());
    let card = a.core.contact_card("A").unwrap();
    assert_eq!(card.devices.version, version + 1);
    assert_eq!(card.devices.certs.len(), 2);
    assert!(card.devices.certs.iter().any(|c| c.name == "t"));
    assert_eq!(a.core.contacts().unwrap(), t.core.contacts().unwrap());
    let tc = t.core.contacts().unwrap();
    let al = tc
        .iter()
        .find(|c| c.fingerprint == alice.core.fingerprint())
        .unwrap();
    assert_eq!((al.alias.as_deref(), al.verified), (Some("alice"), false));
    let bo = tc
        .iter()
        .find(|c| c.fingerprint == bob.core.fingerprint())
        .unwrap();
    assert_eq!((bo.alias.as_deref(), bo.verified), (None, true));
    assert_eq!(t.core.contact_card("T"), Err(CoreError::NotAdmin));
    assert!(matches!(
        t.core.link_offer(NOW, &mut rng),
        Err(CoreError::NotAdmin)
    ));

    // Log on each side.
    assert!(events(&a.core).iter().any(|e| matches!(
        e,
        TransparencyEvent::DeviceLinked { name, .. } if name == "t"
    )));
    assert!(events(&t.core).iter().any(|e| matches!(
        e,
        TransparencyEvent::LinkFinished {
            device_count: 2,
            contacts: 2
        }
    )));

    // T reopened: linked, no longer pending.
    drop(t.core);
    let mut t2 = Core::open(&t.path, &t.key, NOW + 3).unwrap();
    assert_eq!(t2.fingerprint(), a.core.fingerprint());
    assert_eq!(t2.contacts().unwrap().len(), 2);
    // T can write to Alice (one packet per Alice device), plus a
    // `SyncSent` copy for A.
    let pkts = t2
        .send_text(
            &alice.core.fingerprint(),
            "from the tablet",
            NOW + 3,
            &mut rng,
        )
        .unwrap();
    assert_eq!(pkts.len(), 2);
    // A second link completion is refused.
    assert_eq!(
        link_err(t2.finish_link(&bundle, None, NOW + 4)),
        "no pending link"
    );
    let _ = (a.path, a.key);
}

#[test]
fn linked_device_receives_from_contact() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(2);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let mut alice = create(d.path(), "alice", 2, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    let me = alice
        .core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, &mut rng)
        .unwrap();
    t.core
        .add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let pkts = alice.core.send_text(&me, "to both", NOW, &mut rng).unwrap();
    assert_eq!(pkts.len(), 2);
    let opened = pkts
        .iter()
        .filter(|p| {
            matches!(
                t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { ref text, .. } if text == "to both"
            )
        })
        .count();
    assert_eq!(opened, 1);
}

#[test]
fn pending_device_cannot_send_or_receive() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(3);
    let (mut a, alice, _bob) = admin_with_contacts(d.path(), &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, _req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let alice_fp = alice.core.fingerprint();
    assert!(matches!(
        t.core.send_text(&alice_fp, "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert!(matches!(
        t.core.receive(&[0u8; 64], T, NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert!(matches!(
        t.core.receive_frame(&[0u8; 64], T, NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert_eq!(
        t.core.add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            None,
            NOW,
            &mut rng
        ),
        Err(CoreError::LinkPending)
    );
    assert_eq!(t.core.contact_card("T"), Err(CoreError::LinkPending));
    assert!(matches!(
        t.core.link_offer(NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert!(t.core.watched_mailboxes(NOW).unwrap().is_empty());

    // Still pending after reopening.
    drop(t.core);
    let mut t2 = Core::open(&t.path, &t.key, NOW).unwrap();
    assert_eq!(t2.fingerprint(), a.core.fingerprint());
    assert!(matches!(
        t2.send_text(&alice_fp, "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    // The link bundle of another device (other offer) is refused.
    let offer2 = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t4, req) = begin(d.path(), "t4", 11, &offer2, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    assert_eq!(
        link_err(t2.finish_link(&out.bundle, None, NOW)),
        "invalid link bundle"
    );
    assert!(matches!(
        t2.send_text(&alice_fp, "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
}

#[test]
fn pending_device_finishes_after_reopen() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(4);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    drop(t.core);
    let mut t2 = Core::open(&t.path, &t.key, NOW).unwrap();
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t2.finish_link(&out.bundle, None, NOW).unwrap();
    assert_eq!(t2.contact_card("T"), Err(CoreError::NotAdmin));
}

#[test]
fn link_request_replay_refused() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(5);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    let card = a.core.contact_card("A").unwrap();
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW, &mut rng)),
        "offer missing or already used"
    );
    assert_eq!(a.core.contact_card("A").unwrap(), card);
    // Without any offer at all.
    let mut b = create(d.path(), "b", 2, &mut rng);
    assert_eq!(
        link_err(b.core.link_device(&req, false, NOW, &mut rng)),
        "offer missing or already used"
    );
    // A new offer replaces the old one: the request tied to the old one
    // fails (MAC), the one tied to the new one goes through.
    let o1 = a.core.link_offer(NOW, &mut rng).unwrap();
    let o2 = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t1, r1) = begin(d.path(), "t1", 10, &o1, &mut rng);
    let (_t2, r2) = begin(d.path(), "t2", 11, &o2, &mut rng);
    assert_eq!(
        link_err(a.core.link_device(&r1, false, NOW, &mut rng)),
        "invalid MAC"
    );
    a.core.link_device(&r2, false, NOW, &mut rng).unwrap();
}

#[test]
fn link_rejects_bad_mac_expired_wrong_root() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(6);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let mut b = create(d.path(), "b", 2, &mut rng);
    let card = a.core.contact_card("A").unwrap();
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);

    // MAC modified, or field modified under the original MAC.
    for tamper in 0..4 {
        let mut bad = req.clone();
        match tamper {
            0 => bad.mac[0] ^= 1,
            1 => bad.name = "other".into(),
            2 => bad.issued_at += 1,
            _ => bad.device_sig[0] ^= 1,
        }
        assert_eq!(
            link_err(a.core.link_device(&bad, false, NOW, &mut rng)),
            "invalid MAC",
            "falsification {tamper}"
        );
    }
    // No state modified: same card, and the offer is still valid.
    assert_eq!(a.core.contact_card("A").unwrap(), card);

    // Link bundle from another identity: refused, T stays pending.
    let offer_b = b.core.link_offer(NOW, &mut rng).unwrap();
    let (_tb, req_b) = begin(d.path(), "tb", 12, &offer_b, &mut rng);
    let other = b.core.link_device(&req_b, false, NOW, &mut rng).unwrap();
    assert_eq!(
        link_err(t.core.finish_link(&other.bundle, None, NOW)),
        "invalid link bundle"
    );
    // Truncated or modified bundle.
    let good = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    let bytes = good.bundle.to_bytes();
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        link_err(
            t.core
                .finish_link(&LinkBundle::from_bytes(&flipped).unwrap(), None, NOW)
        ),
        "invalid link bundle"
    );
    assert_eq!(
        link_err(LinkBundle::from_bytes(&bytes[..3])),
        "unreadable link file"
    );
    assert!(matches!(
        t.core.send_text(&b.core.fingerprint(), "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert!(events(&t.core).is_empty());
    // The right bundle then goes through.
    t.core.finish_link(&good.bundle, None, NOW).unwrap();

    // Expired offer (11 minutes later): refused, then erased.
    let card = a.core.contact_card("A").unwrap();
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t3, req) = begin(d.path(), "t3", 13, &offer, &mut rng);
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW + 11 * 60, &mut rng)),
        "offer expired"
    );
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW, &mut rng)),
        "offer missing or already used"
    );
    assert_eq!(a.core.contact_card("A").unwrap(), card);
}

#[test]
fn begin_link_refuses_expired_offer() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(7);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let path = d.path().join("t");
    assert_eq!(
        link_err(Core::begin_link(
            &path,
            &[9; 32],
            &offer,
            "t",
            NOW + 601,
            &mut rng
        )),
        "offer expired"
    );
}

#[test]
fn link_files_roundtrip_and_garbage() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(8);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let back = LinkOffer::from_bytes(&offer.to_bytes()).unwrap();
    assert_eq!(back.root, offer.root);
    assert_eq!(*back.secret, *offer.secret);
    assert_eq!(back.expires_at, offer.expires_at);
    let (_t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    assert_eq!(LinkRequest::from_bytes(&req.to_bytes()).unwrap(), req);
    for garbage in [&[][..], &[0xff; 7][..], &[1, 2, 3][..]] {
        assert_eq!(
            link_err(LinkOffer::from_bytes(garbage)),
            "unreadable link file"
        );
        assert_eq!(
            link_err(LinkRequest::from_bytes(garbage)),
            "unreadable link file"
        );
    }
    // Extra bytes refused.
    let mut long = offer.to_bytes().to_vec();
    long.push(0);
    assert_eq!(
        link_err(LinkOffer::from_bytes(&long)),
        "unreadable link file"
    );
}

#[test]
fn link_secret_not_in_debug_or_log() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(9);
    let (mut a, ..) = admin_with_contacts(d.path(), &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let hex: String = offer.secret.iter().map(|b| format!("{b:02x}")).collect();
    let dbg = format!("{offer:?}");
    assert!(!dbg.contains(&hex), "{dbg}");
    assert!(!dbg.contains(&format!("{:?}", &offer.secret[..4])), "{dbg}");
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    assert!(!format!("{:?}", out.bundle).contains(&hex));
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    for core in [&a.core, &t.core] {
        for (_, e) in core.transparency_log(10_000).unwrap() {
            let text = format!("{e:?} {}", e.describe());
            assert!(!text.contains(&hex), "{text}");
            assert!(
                !text.contains(&format!("{:?}", &offer.secret[..4])),
                "{text}"
            );
        }
    }
}

#[test]
fn link_refuses_device_beyond_cap() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(10);
    let mut a = create(d.path(), "a", 1, &mut rng);
    for i in 1..MAX_DEVICES {
        let offer = a.core.link_offer(NOW, &mut rng).unwrap();
        let (_t, req) = begin(d.path(), &format!("t{i}"), 20 + i as u8, &offer, &mut rng);
        a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    }
    assert_eq!(
        a.core.contact_card("A").unwrap().devices.certs.len(),
        MAX_DEVICES
    );
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t, req) = begin(d.path(), "too-many", 99, &offer, &mut rng);
    assert_eq!(
        a.core.link_device(&req, false, NOW, &mut rng).err(),
        Some(CoreError::TooLarge)
    );
    assert_eq!(
        a.core.contact_card("A").unwrap().devices.certs.len(),
        MAX_DEVICES
    );
}

/// A linked to T, without contacts.
fn admin_and_tablet(d: &Path, rng: &mut StdRng) -> (Dev, Dev) {
    let mut a = create(d, "a", 1, rng);
    let offer = a.core.link_offer(NOW, rng).unwrap();
    let (mut t, req) = begin(d, "t", 9, &offer, rng);
    let out = a.core.link_device(&req, false, NOW, rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    (a, t)
}

/// Delivers to `to` every packet of `from`'s send queue, then hands back
/// to `from` the acks of `to`. Returns the syncs applied.
fn sync_round(from: &mut Dev, to: &mut Dev, rng: &mut StdRng) -> Vec<SyncKind> {
    let mut applied = Vec::new();
    for bytes in from.core.pending_outbox(NOW).unwrap() {
        if let ReceiveOutcome::Synced { kind } = to.core.receive(&bytes, T, NOW, rng).unwrap() {
            applied.push(kind);
        }
    }
    for bytes in to.core.pending_outbox(NOW).unwrap() {
        from.core.receive(&bytes, T, NOW, rng).unwrap();
    }
    applied
}

fn contact_state(core: &Core) -> Vec<(Fingerprint, Option<String>, bool)> {
    core.contacts()
        .unwrap()
        .into_iter()
        .map(|c| (c.fingerprint, c.alias, c.verified))
        .collect()
}

#[test]
fn sent_on_a_appears_on_t() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(20);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let mut bob = create(d.path(), "bob", 3, &mut rng);
    bob.core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, &mut rng)
        .unwrap();
    let bob_fp = a
        .core
        .add_contact(
            &bob.core.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());

    // One packet for Bob, one `SyncSent` for T, the same identifier.
    let pkts = a.core.send_text(&bob_fp, "hello", NOW, &mut rng).unwrap();
    assert_eq!(pkts.len(), 2);
    let sent = a.core.messages_with(&bob_fp).unwrap();
    assert_eq!(sent.len(), 1);
    let mut on_t = Vec::new();
    for p in &pkts {
        match t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
            ReceiveOutcome::Synced { kind } => on_t.push((kind, p.id)),
            ReceiveOutcome::NotForUs => {}
            other => panic!("unexpected : {other:?}"),
        }
    }
    assert_eq!(on_t.len(), 1);
    assert_eq!(on_t[0].0, SyncKind::Sent);
    let rows = t.core.messages_with(&bob_fp).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].direction,
            rows[0].body.as_str(),
            rows[0].message_id,
            rows[0].at
        ),
        (Direction::Out, "hello", sent[0].message_id, NOW)
    );
    assert!(events(&t.core).contains(&TransparencyEvent::SyncApplied {
        kind: SyncKind::Sent
    }));
    // Received twice: still one row.
    for p in &pkts {
        let r = t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap();
        assert!(matches!(
            r,
            ReceiveOutcome::Duplicate | ReceiveOutcome::NotForUs
        ));
    }
    assert_eq!(t.core.messages_with(&bob_fp).unwrap().len(), 1);

    // T's ack removes the `SyncSent` from A's queue, but the message
    // for Bob is not delivered for all that.
    let sync_id = on_t[0].1;
    let mut acked = Vec::new();
    for bytes in t.core.pending_outbox(NOW).unwrap() {
        if let ReceiveOutcome::AckReceived { packet_id } =
            a.core.receive(&bytes, T, NOW, &mut rng).unwrap()
        {
            acked.push(packet_id);
        }
    }
    assert_eq!(acked, vec![sync_id]);
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 1);
    assert_eq!(
        a.core.messages_with(&bob_fp).unwrap()[0].status,
        MessageStatus::Sent
    );
    // Bob's ack, on the other hand, marks it delivered.
    let to_bob = pkts.iter().find(|p| p.id != sync_id).unwrap();
    assert!(matches!(
        bob.core
            .receive(&to_bob.encode(), T, NOW, &mut rng)
            .unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    for bytes in bob.core.pending_outbox(NOW).unwrap() {
        a.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    assert_eq!(
        a.core.messages_with(&bob_fp).unwrap()[0].status,
        MessageStatus::Delivered
    );
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());
}

#[test]
fn sent_on_t_reaches_bob_and_a() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(23);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let mut bob = create(d.path(), "bob", 3, &mut rng);
    let alice_fp = bob
        .core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, &mut rng)
        .unwrap();
    let bob_fp = a
        .core
        .add_contact(
            &bob.core.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    sync_round(&mut a, &mut t, &mut rng);

    // T writes to Bob: one packet for Bob, a `SyncSent` copy for A.
    let pkts = t
        .core
        .send_text(&bob_fp, "from the tablet", NOW, &mut rng)
        .unwrap();
    assert_eq!(pkts.len(), 2);
    let sent = t.core.messages_with(&bob_fp).unwrap();
    assert_eq!(sent.len(), 1);
    let (mut at_bob, mut at_a) = (0, 0);
    for p in &pkts {
        match bob.core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
            ReceiveOutcome::Message { from, text, .. } => {
                assert_eq!((from, text.as_str()), (alice_fp, "from the tablet"));
                at_bob += 1;
            }
            ReceiveOutcome::NotForUs => {}
            o => panic!("unexpected at Bob : {o:?}"),
        }
        match a.core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
            ReceiveOutcome::Synced { kind } => {
                assert_eq!(kind, SyncKind::Sent);
                at_a += 1;
            }
            ReceiveOutcome::NotForUs => {}
            o => panic!("unexpected at A : {o:?}"),
        }
    }
    assert_eq!((at_bob, at_a), (1, 1));
    let on_a = a.core.messages_with(&bob_fp).unwrap();
    assert_eq!(on_a.len(), 1);
    assert_eq!(
        (on_a[0].direction, on_a[0].body.as_str(), on_a[0].message_id),
        (Direction::Out, "from the tablet", sent[0].message_id)
    );

    // Bob's reply arrives on T (and on A).
    let reply = bob
        .core
        .send_text(&alice_fp, "received", NOW, &mut rng)
        .unwrap();
    assert_eq!(reply.len(), 2);
    for dev in [&mut t, &mut a] {
        let opened = reply
            .iter()
            .filter(|p| {
                matches!(
                    dev.core.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                    ReceiveOutcome::Message { ref text, .. } if text == "received"
                )
            })
            .count();
        assert_eq!(opened, 1);
    }

    // The acks empty all the queues; T's message is delivered.
    deliver_all(&mut [&mut a, &mut t, &mut bob], &mut rng);
    for dev in [&mut a, &mut t, &mut bob] {
        assert_eq!(unacked(dev), 0);
    }
    assert_eq!(
        t.core.messages_with(&bob_fp).unwrap()[0].status,
        MessageStatus::Delivered
    );
    // On A, the copy stays "sent": only T receives Bob's ack.
    assert_eq!(on_a[0].status, MessageStatus::Sent);
}

#[test]
fn contact_ops_sync() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(21);
    // Without another device: no sync queued.
    let mut solo = create(d.path(), "solo", 4, &mut rng);
    let x = create(d.path(), "x", 5, &mut rng);
    solo.core
        .add_contact(&x.core.contact_card("X").unwrap(), Some("x"), NOW, &mut rng)
        .unwrap();
    assert!(solo.core.pending_outbox(NOW).unwrap().is_empty());

    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let carol = create(d.path(), "carol", 6, &mut rng);
    let card = carol.core.contact_card("Carol").unwrap();
    let carol_fp = a
        .core
        .add_contact(&card, Some("carol"), NOW, &mut rng)
        .unwrap();
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert_eq!(
        contact_state(&t.core),
        vec![(carol_fp, Some("carol".to_owned()), false)]
    );
    a.core.set_alias(&carol_fp, "caro", NOW, &mut rng).unwrap();
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert_eq!(
        contact_state(&t.core),
        vec![(carol_fp, Some("caro".to_owned()), false)]
    );
    a.core.mark_verified(&carol_fp, NOW, &mut rng).unwrap();
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert_eq!(
        contact_state(&t.core),
        vec![(carol_fp, Some("caro".to_owned()), true)]
    );
    assert_eq!(contact_state(&t.core), contact_state(&a.core));
    a.core.remove_contact(&carol_fp, NOW, &mut rng).unwrap();
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert!(contact_state(&t.core).is_empty());
    // Each ack from T emptied A's queue.
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());

    // The other way: an operation on T arrives on A.
    t.core.add_contact(&card, None, NOW, &mut rng).unwrap();
    t.core.set_alias(&carol_fp, "c", NOW, &mut rng).unwrap();
    assert_eq!(
        sync_round(&mut t, &mut a, &mut rng),
        vec![SyncKind::Contact, SyncKind::Contact]
    );
    assert_eq!(
        contact_state(&a.core),
        vec![(carol_fp, Some("c".to_owned()), false)]
    );
    // `set_alias`: unknown contact, alias too long.
    assert_eq!(
        a.core.set_alias(&Fingerprint([9; 32]), "z", NOW, &mut rng),
        Err(CoreError::UnknownContact)
    );
    assert_eq!(
        a.core.set_alias(&carol_fp, &"z".repeat(65), NOW, &mut rng),
        Err(CoreError::TooLarge)
    );
}

/// Packets of `dev`'s queue produced by `op`.
fn produced(dev: &mut Dev, op: impl FnOnce(&mut Core)) -> Vec<Vec<u8>> {
    let before = dev.core.pending_outbox(NOW).unwrap();
    op(&mut dev.core);
    dev.core
        .pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .filter(|b| !before.contains(b))
        .collect()
}

fn deliver(to: &mut Dev, bytes: &[u8], rng: &mut StdRng) -> ReceiveOutcome {
    to.core.receive(bytes, T, NOW, rng).unwrap()
}

#[test]
fn contact_sync_is_order_independent() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(22);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let carol = create(d.path(), "carol", 6, &mut rng)
        .core
        .contact_card("Carol")
        .unwrap();
    let dave = create(d.path(), "dave", 7, &mut rng)
        .core
        .contact_card("Dave")
        .unwrap();
    let carol_fp = carol.fingerprint();
    let dave_fp = dave.fingerprint();
    let mut r2 = StdRng::seed_from_u64(1);

    // Add then delete, delivered in reverse: deleting an unknown contact
    // is applied (and acked), the older add changes nothing.
    let add = produced(&mut a, |c| {
        c.add_contact(&carol, Some("carol"), NOW, &mut r2).unwrap();
    });
    let rm = produced(&mut a, |c| {
        c.remove_contact(&carol_fp, NOW + 1, &mut r2).unwrap()
    });
    assert_eq!((add.len(), rm.len()), (1, 1));
    for p in rm.iter().chain(&add) {
        assert!(matches!(
            deliver(&mut t, p, &mut rng),
            ReceiveOutcome::Synced {
                kind: SyncKind::Contact
            }
        ));
    }
    assert!(contact_state(&t.core).is_empty());
    // The same packet a second time: duplicate, nothing changes.
    assert!(matches!(
        deliver(&mut t, &add[0], &mut rng),
        ReceiveOutcome::Duplicate
    ));
    assert!(contact_state(&t.core).is_empty());

    // Verified state delivered before the add: the contact is verified, the
    // older add does not un-verify it.
    let add = produced(&mut a, |c| {
        c.add_contact(&dave, Some("dave"), NOW + 2, &mut r2)
            .unwrap();
    });
    let ver = produced(&mut a, |c| {
        c.mark_verified(&dave_fp, NOW + 3, &mut r2).unwrap()
    });
    for p in ver.iter().chain(&add) {
        deliver(&mut t, p, &mut rng);
    }
    assert_eq!(
        contact_state(&t.core),
        vec![(dave_fp, Some("dave".to_owned()), true)]
    );
    // The same operation redone (new packet): same state.
    let again = produced(&mut a, |c| {
        c.mark_verified(&dave_fp, NOW + 4, &mut r2).unwrap()
    });
    deliver(&mut t, &again[0], &mut rng);
    assert_eq!(contact_state(&t.core), contact_state(&a.core));

    // An add more recent than the deletion brings the contact back.
    let re = produced(&mut a, |c| {
        c.add_contact(&carol, Some("carol"), NOW + 5, &mut r2)
            .unwrap();
    });
    deliver(&mut t, &re[0], &mut rng);
    assert_eq!(contact_state(&t.core), contact_state(&a.core));
    assert_eq!(contact_state(&t.core).len(), 2);

    // Local operations: a deletion on T (more recent) wins
    // over an older alias change on A, delivered afterwards.
    let late = produced(&mut a, |c| {
        c.set_alias(&carol_fp, "c", NOW + 6, &mut r2).unwrap()
    });
    t.core.remove_contact(&carol_fp, NOW + 7, &mut r2).unwrap();
    deliver(&mut t, &late[0], &mut rng);
    assert_eq!(
        contact_state(&t.core),
        vec![(dave_fp, Some("dave".to_owned()), true)]
    );

    // All of T's acks empty A's queue: only the ack of the
    // deletion done on T remains.
    for bytes in t.core.pending_outbox(NOW).unwrap() {
        a.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    let left = a.core.pending_outbox(NOW).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(Packet::decode(&left[0]).unwrap().kind, Kind::Ack);
}

/// A and T, with Carol and Dave known to both (added on A at `NOW`, copied
/// to T).
fn pair_with_two_contacts(d: &Path, rng: &mut StdRng) -> (Dev, Dev, Fingerprint, Fingerprint) {
    let (mut a, mut t) = admin_and_tablet(d, rng);
    let carol = create(d, "carol", 6, rng)
        .core
        .contact_card("Carol")
        .unwrap();
    let dave = create(d, "dave", 7, rng).core.contact_card("Dave").unwrap();
    let carol_fp = a.core.add_contact(&carol, Some("carol"), NOW, rng).unwrap();
    let dave_fp = a.core.add_contact(&dave, Some("dave"), NOW, rng).unwrap();
    sync_round(&mut a, &mut t, rng);
    assert_eq!(contact_state(&a.core), contact_state(&t.core));
    (a, t, carol_fp, dave_fp)
}

#[test]
fn alias_replacement_warns_other_devices() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(33);
    let (mut a, mut t, carol, dave) = pair_with_two_contacts(d.path(), &mut rng);
    // On A, a new card takes Carol's alias: Carol is replaced.
    let eve_card = create(d.path(), "eve", 8, &mut rng)
        .core
        .contact_card("Eve")
        .unwrap();
    let eve = a
        .core
        .add_contact(&eve_card, Some("carol"), NOW + 5, &mut rng)
        .unwrap();
    let changed = TransparencyEvent::ContactKeyChanged {
        alias: "carol".into(),
        old: carol,
        new: eve,
    };
    assert!(events(&a.core).contains(&changed));
    sync_round(&mut a, &mut t, &mut rng);
    // T sees the same warning, and the same state.
    assert!(events(&t.core).contains(&changed));
    assert!(changed.is_security());
    let mut sa = contact_state(&a.core);
    let mut st = contact_state(&t.core);
    sa.sort_by_key(|c| c.0.0);
    st.sort_by_key(|c| c.0.0);
    assert_eq!(sa, st);
    assert!(sa.iter().all(|c| c.0 != carol));
    assert!(sa.iter().any(|c| c.0 == dave));
}

#[test]
fn same_second_edits_converge() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(30);
    let (mut a, mut t, carol, _) = pair_with_two_contacts(d.path(), &mut rng);
    // Same second, two devices, two different aliases for Carol.
    let mut r2 = StdRng::seed_from_u64(2);
    let from_a = produced(&mut a, |c| {
        c.set_alias(&carol, "x", NOW + 10, &mut r2).unwrap()
    });
    let from_t = produced(&mut t, |c| {
        c.set_alias(&carol, "y", NOW + 10, &mut r2).unwrap()
    });
    assert_eq!((from_a.len(), from_t.len()), (1, 1));
    deliver(&mut t, &from_a[0], &mut rng);
    deliver(&mut a, &from_t[0], &mut rng);
    assert_eq!(contact_state(&a.core), contact_state(&t.core));
}

#[test]
fn concurrent_alias_move_converges() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(31);
    let (mut a, mut t, carol, dave) = pair_with_two_contacts(d.path(), &mut rng);
    let mut r2 = StdRng::seed_from_u64(3);
    // A gives "z" to Carol; T, later, gives "z" to Dave.
    let from_a = produced(&mut a, |c| {
        c.set_alias(&carol, "z", NOW + 10, &mut r2).unwrap()
    });
    let from_t = produced(&mut t, |c| {
        c.set_alias(&dave, "z", NOW + 20, &mut r2).unwrap()
    });
    deliver(&mut t, &from_a[0], &mut rng);
    deliver(&mut a, &from_t[0], &mut rng);
    // The most recent operation keeps the alias, everywhere. On A, the alias
    // moves to another fingerprint: warning, as for a local add.
    let moved = TransparencyEvent::ContactKeyChanged {
        alias: "z".into(),
        old: carol,
        new: dave,
    };
    assert!(events(&a.core).contains(&moved));
    assert!(
        !events(&t.core)
            .iter()
            .any(|e| matches!(e, TransparencyEvent::ContactKeyChanged { .. }))
    );
    let expected = vec![(carol, None, false), (dave, Some("z".to_owned()), false)];
    let mut sa = contact_state(&a.core);
    let mut st = contact_state(&t.core);
    let mut expected = expected;
    for v in [&mut sa, &mut st, &mut expected] {
        v.sort_by_key(|c| c.0.0);
    }
    assert_eq!(sa, expected);
    assert_eq!(st, expected);
}

#[test]
fn bumped_clock_only_moves_envelope_date() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(32);
    let (mut a, _t, carol, _) = pair_with_two_contacts(d.path(), &mut rng);
    let mut r2 = StdRng::seed_from_u64(4);
    // Several operations in the same second: the contact clock advances
    // (NOW + 1, NOW + 2...), but the packet expiry follows the wall clock.
    for alias in ["a", "b", "c"] {
        let p = produced(&mut a, |c| {
            c.set_alias(&carol, alias, NOW, &mut r2).unwrap()
        });
        let packet = Packet::decode(&p[0]).unwrap();
        assert_eq!(
            u64::from(packet.expires_at),
            NOW + barking_core::packet::DEFAULT_TTL_SECS
        );
    }
}

#[test]
fn bob_reaches_new_tablet() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(40);
    let mut alice = create(d.path(), "alice", 1, &mut rng);
    let mut bob = create(d.path(), "bob", 3, &mut rng);
    let alice_fp = bob
        .core
        .add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .core
        .add_contact(
            &bob.core.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let before = bob
        .core
        .send_text(&alice_fp, "before", NOW, &mut rng)
        .unwrap()
        .len();
    assert_eq!(before, 1);

    let offer = alice.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = alice.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    // A card update for Bob's device; no device of mine other than T,
    // which received everything through the link bundle.
    assert_eq!(out.packets.len(), 1);
    let card_update = out.packets[0].encode();
    assert!(
        alice
            .core
            .pending_outbox(NOW)
            .unwrap()
            .contains(&card_update)
    );
    match bob.core.receive(&card_update, T, NOW, &mut rng).unwrap() {
        ReceiveOutcome::CardUpdated { from, alias } => {
            assert_eq!(from, alice_fp);
            assert_eq!(alias.as_deref(), Some("alice"));
        }
        o => panic!("CardUpdated expected, got {o:?}"),
    }
    // Alice's display name is kept in the new card.
    let c = bob.core.contacts().unwrap();
    assert_eq!(c[0].display_name, "Alice");
    let updated = TransparencyEvent::ContactCardUpdated {
        contact: alice_fp,
        alias: "alice".into(),
        added: 1,
        removed: 0,
    };
    assert!(events(&bob.core).contains(&updated));
    assert!(updated.is_security());

    // Bob now also encrypts for T.
    let pkts = bob
        .core
        .send_text(&alice_fp, "to both", NOW, &mut rng)
        .unwrap();
    assert_eq!(pkts.len(), before + 1);
    let opened = pkts
        .iter()
        .filter(|p| {
            matches!(
                t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { ref text, .. } if text == "to both"
            )
        })
        .count();
    assert_eq!(opened, 1);
    // Bob's ack removes the update from Alice's queue.
    for bytes in bob.core.pending_outbox(NOW).unwrap() {
        alice.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    assert!(
        !alice
            .core
            .pending_outbox(NOW)
            .unwrap()
            .contains(&card_update)
    );
}

#[test]
fn removing_contact_drops_its_card_updates() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(41);
    let mut alice = create(d.path(), "alice", 1, &mut rng);
    let bob = create(d.path(), "bob", 3, &mut rng);
    let mut carol = create(d.path(), "carol", 5, &mut rng);
    let bob_fp = alice
        .core
        .add_contact(
            &bob.core.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .core
        .add_contact(
            &carol.core.contact_card("Carol").unwrap(),
            Some("carol"),
            NOW,
            &mut rng,
        )
        .unwrap();
    carol
        .core
        .add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let offer = alice.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = alice.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    // One card update per contact (one device each).
    assert_eq!(out.packets.len(), 2);
    let updates: Vec<Vec<u8>> = out.packets.iter().map(Packet::encode).collect();
    let queued = alice.core.pending_outbox(NOW).unwrap();
    assert!(updates.iter().all(|u| queued.contains(u)));

    alice.core.remove_contact(&bob_fp, NOW, &mut rng).unwrap();
    let queued = alice.core.pending_outbox(NOW).unwrap();
    let left: Vec<&Vec<u8>> = updates.iter().filter(|u| queued.contains(u)).collect();
    // Only Carol's update remains.
    assert_eq!(left.len(), 1);
    assert!(matches!(
        carol.core.receive(left[0], T, NOW, &mut rng).unwrap(),
        ReceiveOutcome::CardUpdated { .. }
    ));
}

#[test]
fn second_link_sends_devices_to_first_tablet() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(41);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t2, req) = begin(d.path(), "t2", 10, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    // A `SyncDevices` for T, nothing for T2 (nor contact).
    assert_eq!(out.packets.len(), 1);
    assert!(matches!(
        t.core
            .receive(&out.packets[0].encode(), T, NOW, &mut rng)
            .unwrap(),
        ReceiveOutcome::Synced {
            kind: SyncKind::Devices
        }
    ));
    t2.core.finish_link(&out.bundle, None, NOW).unwrap();
    // On T, the change to my list is a security entry.
    let updated = TransparencyEvent::OwnDevicesUpdated {
        added: 1,
        removed: 0,
    };
    assert!(events(&t.core).contains(&updated));
    assert!(updated.is_security());
    // T knows T2: an operation on a contact goes to A and T2.
    let carol = create(d.path(), "carol", 6, &mut rng)
        .core
        .contact_card("Carol")
        .unwrap();
    let produced = produced(&mut t, |c| {
        c.add_contact(&carol, None, NOW, &mut StdRng::seed_from_u64(5))
            .unwrap();
    });
    assert_eq!(produced.len(), 2);
}

#[test]
fn card_updates_in_reverse_order_converge() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(42);
    let mut alice = create(d.path(), "alice", 1, &mut rng);
    let mut bob = create(d.path(), "bob", 3, &mut rng);
    let alice_fp = bob
        .core
        .add_contact(
            &alice.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .core
        .add_contact(&bob.core.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let mut updates = Vec::new();
    for (i, file) in ["t1", "t2"].into_iter().enumerate() {
        let offer = alice.core.link_offer(NOW, &mut rng).unwrap();
        let (mut t, req) = begin(d.path(), file, 20 + i as u8, &offer, &mut rng);
        let out = alice.core.link_device(&req, false, NOW, &mut rng).unwrap();
        t.core.finish_link(&out.bundle, None, NOW).unwrap();
        updates.push(out.packets);
    }
    // The most recent (3 devices) first, then the old one (2 devices).
    let mut outcomes = Vec::new();
    for packets in updates.iter().rev() {
        for p in packets {
            match bob.core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
                ReceiveOutcome::NotForUs => {}
                o => outcomes.push(o),
            }
        }
    }
    assert_eq!(outcomes.len(), 2);
    assert!(matches!(outcomes[0], ReceiveOutcome::CardUpdated { .. }));
    assert!(matches!(outcomes[1], ReceiveOutcome::Duplicate));
    // Bob encrypts for Alice's 3 devices.
    assert_eq!(
        bob.core
            .send_text(&alice_fp, "x", NOW, &mut rng)
            .unwrap()
            .len(),
        3
    );
    // Both updates are acked: they leave Alice's queue.
    for bytes in bob.core.pending_outbox(NOW).unwrap() {
        alice.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    // Only the `SyncDevices` for T1 (not relayed here) remains.
    let left = alice.core.pending_outbox(NOW).unwrap();
    let card_updates_left = updates
        .iter()
        .flatten()
        .filter(|p| left.contains(&p.encode()))
        .count();
    assert_eq!(card_updates_left, 1, "only the SyncDevices for T1 remains");
}

/// Comparable view of a conversation: identifier, direction, text, status, date.
type MsgView = Vec<([u8; 16], Direction, String, MessageStatus, u64)>;

fn conversation(core: &Core, fp: &Fingerprint) -> MsgView {
    core.messages_with(fp)
        .unwrap()
        .into_iter()
        .map(|m| (m.message_id.0, m.direction, m.body, m.status, m.at))
        .collect()
}

/// A with three conversations (Alice, Bob, Carol), including a received message and
/// a delivered message, and enough text for several 64 KiB chunks.
/// Returns A, T pending, the archive and the link bundle.
fn history_setup(
    d: &Path,
    rng: &mut StdRng,
) -> (Dev, Dev, LinkBundle, HistoryArchive, Vec<Fingerprint>) {
    let (mut a, mut alice, bob) = admin_with_contacts(d, rng);
    let carol = create(d, "carol", 4, rng);
    let carol_fp = a
        .core
        .add_contact(
            &carol.core.contact_card("Carol").unwrap(),
            Some("carol"),
            NOW,
            rng,
        )
        .unwrap();
    let alice_fp = alice.core.fingerprint();
    let bob_fp = bob.core.fingerprint();
    // Alice writes to A; A replies, Alice acks.
    let a_fp = alice
        .core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, rng)
        .unwrap();
    for p in alice.core.send_text(&a_fp, "hello A", NOW, rng).unwrap() {
        a.core.receive(&p.encode(), T, NOW, rng).unwrap();
    }
    for p in a
        .core
        .send_text(&alice_fp, "hello Alice", NOW + 1, rng)
        .unwrap()
    {
        alice.core.receive(&p.encode(), T, NOW + 1, rng).unwrap();
    }
    for bytes in alice.core.pending_outbox(NOW + 1).unwrap() {
        a.core.receive(&bytes, T, NOW + 1, rng).unwrap();
    }
    // Lots of text to Bob and Carol: several chunks.
    for i in 0..20u64 {
        let text = format!("{i:02}{}", "x".repeat(3900));
        a.core.send_text(&bob_fp, &text, NOW + 2 + i, rng).unwrap();
        a.core
            .send_text(&carol_fp, &text, NOW + 2 + i, rng)
            .unwrap();
    }
    let alice_view = conversation(&a.core, &alice_fp);
    assert!(alice_view.iter().any(|m| m.1 == Direction::In));
    assert!(alice_view.iter().any(|m| m.3 == MessageStatus::Delivered));

    let offer = a.core.link_offer(NOW, rng).unwrap();
    let (t, req) = begin(d, "t", 9, &offer, rng);
    let out = a.core.link_device(&req, true, NOW + 30, rng).unwrap();
    // Going through bytes, as in the CLI.
    let archive = HistoryArchive::from_bytes(&out.history.unwrap().to_bytes()).unwrap();
    assert!(archive.chunks.len() >= 2, "{} chunks", archive.chunks.len());
    (a, t, out.bundle, archive, vec![alice_fp, bob_fp, carol_fp])
}

/// T still pending: no contact, no message, no event.
fn assert_still_pending(t: &mut Dev, fps: &[Fingerprint], rng: &mut StdRng) {
    assert!(t.core.contacts().unwrap().is_empty());
    for fp in fps {
        assert!(t.core.messages_with(fp).unwrap().is_empty());
    }
    assert!(events(&t.core).is_empty());
    assert!(matches!(
        t.core.send_text(&fps[0], "x", NOW, rng),
        Err(CoreError::LinkPending)
    ));
}

#[test]
fn history_round_trip() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(40);
    let (a, mut t, bundle, archive, fps) = history_setup(d.path(), &mut rng);
    t.core
        .finish_link(&bundle, Some(&archive), NOW + 31)
        .unwrap();
    let mut total = 0;
    for fp in &fps {
        let on_a = conversation(&a.core, fp);
        assert!(!on_a.is_empty());
        assert_eq!(conversation(&t.core, fp), on_a);
        total += on_a.len();
    }
    assert_eq!(total, 42);
    // Last event: the import, after the link completion.
    let ev = events(&t.core);
    assert_eq!(
        ev.last(),
        Some(&TransparencyEvent::HistoryImported { count: 42 })
    );
    assert!(matches!(
        ev[ev.len() - 2],
        TransparencyEvent::LinkFinished { .. }
    ));
    // Reopened: the history is still there.
    drop(t.core);
    let t2 = Core::open(&t.path, &t.key, NOW + 32).unwrap();
    for fp in &fps {
        assert_eq!(conversation(&t2, fp), conversation(&a.core, fp));
    }
}

#[test]
fn history_truncated_refused() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(41);
    let (_a, mut t, bundle, archive, fps) = history_setup(d.path(), &mut rng);
    for cut in [0, 1, archive.chunks.len() - 1] {
        let mut bad = archive.clone();
        if cut == 0 {
            bad.chunks.pop();
        } else {
            bad.chunks.truncate(cut);
        }
        assert_eq!(
            link_err(t.core.finish_link(&bundle, Some(&bad), NOW + 31)),
            "invalid history",
            "cut {cut}"
        );
        assert_still_pending(&mut t, &fps, &mut rng);
    }
    let empty = HistoryArchive { chunks: Vec::new() };
    assert_eq!(
        link_err(t.core.finish_link(&bundle, Some(&empty), NOW + 31)),
        "invalid history"
    );
    assert_still_pending(&mut t, &fps, &mut rng);
    // The right archive then goes through.
    t.core
        .finish_link(&bundle, Some(&archive), NOW + 31)
        .unwrap();
}

#[test]
fn history_duplicate_chunk_refused() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(42);
    let (_a, mut t, bundle, archive, fps) = history_setup(d.path(), &mut rng);
    // Chunk added twice, chunk replaced by another, reversed order.
    let mut added = archive.clone();
    added.chunks.insert(1, archive.chunks[1].clone());
    let mut replaced = archive.clone();
    replaced.chunks[1] = archive.chunks[0].clone();
    let mut swapped = archive.clone();
    swapped.chunks.swap(0, 1);
    for bad in [added, replaced, swapped] {
        assert_eq!(
            link_err(t.core.finish_link(&bundle, Some(&bad), NOW + 31)),
            "invalid history"
        );
        assert_still_pending(&mut t, &fps, &mut rng);
    }
    t.core
        .finish_link(&bundle, Some(&archive), NOW + 31)
        .unwrap();
}

#[test]
fn history_tampered_refused() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(43);
    let (mut a, mut t, bundle, archive, fps) = history_setup(d.path(), &mut rng);
    for (chunk, at) in [(0, 0), (1, 30), (archive.chunks.len() - 1, usize::MAX)] {
        let mut bad = archive.clone();
        let c = &mut bad.chunks[chunk];
        let i = at.min(c.len() - 1);
        c[i] ^= 1;
        assert_eq!(
            link_err(t.core.finish_link(&bundle, Some(&bad), NOW + 31)),
            "invalid history"
        );
        assert_still_pending(&mut t, &fps, &mut rng);
    }
    // Archive from another link (other secret): refused.
    let offer = a.core.link_offer(NOW + 40, &mut rng).unwrap();
    let (_t2, req) = begin(d.path(), "t2", 10, &offer, &mut rng);
    let other = a.core.link_device(&req, true, NOW + 41, &mut rng).unwrap();
    assert_eq!(
        link_err(
            t.core
                .finish_link(&bundle, other.history.as_ref(), NOW + 31)
        ),
        "invalid history"
    );
    assert_still_pending(&mut t, &fps, &mut rng);
    t.core
        .finish_link(&bundle, Some(&archive), NOW + 31)
        .unwrap();
}

#[test]
fn history_empty_and_without_history() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(44);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = a.core.link_device(&req, true, NOW, &mut rng).unwrap();
    let archive = out.history.unwrap();
    assert_eq!(archive.chunks.len(), 1);
    t.core
        .finish_link(&out.bundle, Some(&archive), NOW)
        .unwrap();
    assert_eq!(
        events(&t.core).last(),
        Some(&TransparencyEvent::HistoryImported { count: 0 })
    );
}

/// Delivers every queued packet of every device to all the others, in
/// rounds, until a round produces nothing new (messages,
/// cards, syncs, first acks). Refused packets
/// (sender still unknown) stay queued and are replayed next round.
/// A quarantine panics: none is expected, and it must never go unseen.
fn deliver_all(devs: &mut [&mut Dev], rng: &mut StdRng) {
    for _ in 0..12 {
        let mut progress = false;
        let outboxes: Vec<Vec<Vec<u8>>> = devs
            .iter_mut()
            .map(|d| d.core.pending_outbox(NOW).unwrap())
            .collect();
        for (from, out) in outboxes.iter().enumerate() {
            for bytes in out {
                for (to, dev) in devs.iter_mut().enumerate() {
                    if to == from {
                        continue;
                    }
                    match dev.core.receive(bytes, T, NOW, rng).unwrap() {
                        ReceiveOutcome::Quarantined { reason } => {
                            panic!("unexpected quarantine: {reason}")
                        }
                        ReceiveOutcome::Duplicate | ReceiveOutcome::NotForUs => {}
                        _ => progress = true,
                    }
                }
            }
        }
        if !progress {
            return;
        }
    }
    panic!("delivery does not converge");
}

/// Message-type packets still queued (acks wait for nothing).
fn unacked(dev: &mut Dev) -> usize {
    dev.core
        .pending_outbox(NOW)
        .unwrap()
        .iter()
        .filter(|b| Packet::decode(b).unwrap().kind == Kind::Message)
        .count()
}

/// Number of devices (among `to`) that decrypt `text` in `pkts`.
fn opened_by(pkts: &[Packet], to: &mut [&mut Dev], text: &str, rng: &mut StdRng) -> usize {
    let mut n = 0;
    for dev in to.iter_mut() {
        for p in pkts {
            if let ReceiveOutcome::Message { text: got, .. } =
                dev.core.receive(&p.encode(), T, NOW, rng).unwrap()
            {
                assert_eq!(got, text);
                n += 1;
            }
        }
    }
    n
}

#[test]
fn crossing_links_converge_to_full_mesh() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(43);
    let mut a = create(d.path(), "a", 1, &mut rng);
    let mut b1 = create(d.path(), "b1", 3, &mut rng);
    let alice_fp = b1
        .core
        .add_contact(
            &a.core.contact_card("Alice").unwrap(),
            Some("alice"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let bob_fp = a
        .core
        .add_contact(
            &b1.core.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();

    // Bob links B2; his card update for A stays queued (delayed).
    let offer = b1.core.link_offer(NOW, &mut rng).unwrap();
    let (mut b2, req) = begin(d.path(), "b2", 4, &offer, &mut rng);
    let out = b1.core.link_device(&req, false, NOW, &mut rng).unwrap();
    b2.core.finish_link(&out.bundle, None, NOW).unwrap();
    // Alice links T: her snapshot carries Bob's old card (B1 only),
    // and Alice's update only goes to B1.
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    assert_eq!(out.packets.len(), 1);
    t.core.finish_link(&out.bundle, None, NOW).unwrap();

    deliver_all(&mut [&mut a, &mut t, &mut b1, &mut b2], &mut rng);

    // Each Alice device encrypts for both of Bob's devices (plus
    // a copy for her other device), and vice versa.
    for (i, text) in ["from A", "from T"].into_iter().enumerate() {
        let from = if i == 0 { &mut a } else { &mut t };
        let pkts = from.core.send_text(&bob_fp, text, NOW, &mut rng).unwrap();
        assert_eq!(pkts.len(), 3, "{text}");
        assert_eq!(
            opened_by(&pkts, &mut [&mut b1, &mut b2], text, &mut rng),
            2,
            "{text}"
        );
    }
    for (i, text) in ["from B1", "from B2"].into_iter().enumerate() {
        let from = if i == 0 { &mut b1 } else { &mut b2 };
        let pkts = from.core.send_text(&alice_fp, text, NOW, &mut rng).unwrap();
        assert_eq!(pkts.len(), 3, "{text}");
        assert_eq!(
            opened_by(&pkts, &mut [&mut a, &mut t], text, &mut rng),
            2,
            "{text}"
        );
    }
    // Everything is acked: no more messages queued.
    deliver_all(&mut [&mut a, &mut t, &mut b1, &mut b2], &mut rng);
    for dev in [&mut a, &mut t, &mut b1, &mut b2] {
        assert_eq!(unacked(dev), 0);
    }
}

#[test]
fn unmark_verified_syncs() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(22);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let carol = create(d.path(), "carol", 6, &mut rng);
    let card = carol.core.contact_card("Carol").unwrap();
    let carol_fp = a
        .core
        .add_contact(&card, Some("carol"), NOW, &mut rng)
        .unwrap();
    a.core.mark_verified(&carol_fp, NOW, &mut rng).unwrap();
    sync_round(&mut a, &mut t, &mut rng);
    assert_eq!(
        contact_state(&t.core),
        vec![(carol_fp, Some("carol".to_owned()), true)]
    );
    a.core
        .unmark_verified(&carol_fp, NOW + 1, &mut rng)
        .unwrap();
    assert_eq!(
        contact_state(&a.core),
        vec![(carol_fp, Some("carol".to_owned()), false)]
    );
    assert_eq!(
        sync_round(&mut a, &mut t, &mut rng),
        vec![SyncKind::Contact]
    );
    assert_eq!(
        contact_state(&t.core),
        vec![(carol_fp, Some("carol".to_owned()), false)]
    );
}

#[test]
fn unmark_unknown_contact_is_unknown() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(23);
    let mut a = create(d.path(), "a", 1, &mut rng);
    assert!(matches!(
        a.core.unmark_verified(&Fingerprint([9; 32]), NOW, &mut rng),
        Err(CoreError::UnknownContact)
    ));
}

#[test]
fn my_devices_lists_certificates() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(24);
    let (a, t) = admin_and_tablet(d.path(), &mut rng);
    let on_a = a.core.my_devices();
    assert_eq!(on_a.len(), 2);
    assert_eq!(on_a.iter().filter(|x| x.this_device).count(), 1);
    assert!(on_a.iter().all(|x| x.admin == x.this_device));
    let on_t = t.core.my_devices();
    assert_eq!(on_t.len(), 2);
    assert_eq!(on_t.iter().filter(|x| x.this_device).count(), 1);
    assert!(on_t.iter().all(|x| !x.admin));
    assert!(on_t.iter().any(|x| x.this_device && x.name == "t"));
}

/// A device that has not synced yet renames a contact after the other one
/// verified it: the verification survives (its own register, review I1).
#[test]
fn stale_device_does_not_erase_verification() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(25);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let carol = create(d.path(), "carol", 6, &mut rng);
    let card = carol.core.contact_card("Carol").unwrap();
    let carol_fp = a
        .core
        .add_contact(&card, Some("carol"), NOW, &mut rng)
        .unwrap();
    sync_round(&mut a, &mut t, &mut rng);
    // A verifies; T does not know yet and renames later.
    a.core.mark_verified(&carol_fp, NOW + 10, &mut rng).unwrap();
    t.core
        .set_alias(&carol_fp, "caro", NOW + 20, &mut rng)
        .unwrap();
    sync_round(&mut t, &mut a, &mut rng);
    sync_round(&mut a, &mut t, &mut rng);
    assert_eq!(
        contact_state(&a.core),
        vec![(carol_fp, Some("caro".to_owned()), true)]
    );
    assert_eq!(contact_state(&t.core), contact_state(&a.core));
}

/// A verification made on a device behind on the contact's other changes
/// is still applied everywhere.
#[test]
fn verification_from_a_stale_device_is_kept() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(26);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let carol = create(d.path(), "carol", 6, &mut rng);
    let card = carol.core.contact_card("Carol").unwrap();
    let carol_fp = a
        .core
        .add_contact(&card, Some("carol"), NOW, &mut rng)
        .unwrap();
    sync_round(&mut a, &mut t, &mut rng);
    a.core
        .set_alias(&carol_fp, "caro", NOW + 20, &mut rng)
        .unwrap();
    t.core.mark_verified(&carol_fp, NOW + 10, &mut rng).unwrap();
    sync_round(&mut a, &mut t, &mut rng);
    sync_round(&mut t, &mut a, &mut rng);
    assert_eq!(
        contact_state(&a.core),
        vec![(carol_fp, Some("caro".to_owned()), true)]
    );
    assert_eq!(contact_state(&t.core), contact_state(&a.core));
}

fn device_id(core: &Core, name: &str) -> barking_core::identity::DeviceId {
    core.my_devices()
        .into_iter()
        .find(|d| d.name == name)
        .unwrap()
        .id
}

fn admins(core: &Core) -> Vec<String> {
    core.my_devices()
        .into_iter()
        .filter(|d| d.admin)
        .map(|d| d.name)
        .collect()
}

#[test]
fn admin_transfer_moves_root() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(40);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let t_id = device_id(&a.core, "t");

    a.core.transfer_admin(t_id, NOW, &mut rng).unwrap();
    // Root kept until T acknowledges, but no linking meanwhile.
    assert_eq!(a.core.admin_transfer_pending(NOW).unwrap(), Some(t_id));
    assert!(matches!(
        a.core.link_offer(NOW, &mut rng),
        Err(CoreError::AdminTransferPending)
    ));
    assert_eq!(admins(&a.core), vec!["a".to_owned()]);

    assert_eq!(sync_round(&mut a, &mut t, &mut rng), vec![SyncKind::Admin]);
    assert_eq!(a.core.admin_transfer_pending(NOW).unwrap(), None);
    assert!(matches!(
        a.core.link_offer(NOW, &mut rng),
        Err(CoreError::NotAdmin)
    ));
    assert_eq!(admins(&a.core), vec!["t".to_owned()]);
    assert_eq!(admins(&t.core), vec!["t".to_owned()]);
    assert!(
        events(&a.core).iter().any(
            |e| matches!(e, TransparencyEvent::AdminTransferred { device } if *device == t_id)
        )
    );
    assert!(events(&t.core).contains(&TransparencyEvent::AdminReceived));

    // Erased for good: still not admin after reopening.
    drop(a.core);
    a.core = Core::open(&a.path, &a.key, NOW).unwrap();
    assert!(matches!(
        a.core.link_offer(NOW, &mut rng),
        Err(CoreError::NotAdmin)
    ));

    // T links a third device; A learns the new list.
    let offer = t.core.link_offer(NOW, &mut rng).unwrap();
    let (mut u, req) = begin(d.path(), "u", 11, &offer, &mut rng);
    let out = t.core.link_device(&req, false, NOW, &mut rng).unwrap();
    u.core.finish_link(&out.bundle, None, NOW).unwrap();
    assert_eq!(
        sync_round(&mut t, &mut a, &mut rng),
        vec![SyncKind::Devices]
    );
    assert_eq!(a.core.my_devices().len(), 3);
    assert_eq!(u.core.my_devices().len(), 3);
}

#[test]
fn admin_transfer_expires_keeps_root() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(41);
    let (mut a, _t) = admin_and_tablet(d.path(), &mut rng);
    let t_id = device_id(&a.core, "t");
    a.core.transfer_admin(t_id, NOW, &mut rng).unwrap();
    let later = NOW + 8 * 86_400;
    assert!(a.core.pending_outbox(later).unwrap().is_empty());
    assert_eq!(a.core.admin_transfer_pending(later).unwrap(), None);
    a.core.link_offer(later, &mut rng).unwrap();
    assert_eq!(admins(&a.core), vec!["a".to_owned()]);
    // Also after reopening.
    drop(a.core);
    a.core = Core::open(&a.path, &a.key, later).unwrap();
    assert_eq!(a.core.admin_transfer_pending(later).unwrap(), None);
}

#[test]
fn admin_transfer_refusals() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(42);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let a_id = device_id(&a.core, "a");
    let t_id = device_id(&a.core, "t");
    assert!(matches!(
        a.core.transfer_admin(a_id, NOW, &mut rng),
        Err(CoreError::Malformed(_))
    ));
    let unknown = barking_core::identity::DeviceId([7; 16]);
    assert!(matches!(
        a.core.transfer_admin(unknown, NOW, &mut rng),
        Err(CoreError::Malformed(_))
    ));
    assert!(matches!(
        t.core.transfer_admin(a_id, NOW, &mut rng),
        Err(CoreError::NotAdmin)
    ));
    a.core.transfer_admin(t_id, NOW, &mut rng).unwrap();
    assert!(matches!(
        a.core.transfer_admin(t_id, NOW, &mut rng),
        Err(CoreError::AdminTransferPending)
    ));
}

#[test]
fn admin_transfer_ack_twice() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(43);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let t_id = device_id(&a.core, "t");
    a.core.transfer_admin(t_id, NOW, &mut rng).unwrap();
    for bytes in a.core.pending_outbox(NOW).unwrap() {
        t.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    let acks = t.core.pending_outbox(NOW).unwrap();
    assert_eq!(acks.len(), 1);
    assert!(matches!(
        a.core.receive(&acks[0], T, NOW, &mut rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert!(matches!(
        a.core.receive(&acks[0], T, NOW, &mut rng).unwrap(),
        ReceiveOutcome::Duplicate
    ));
    assert_eq!(admins(&a.core), vec!["t".to_owned()]);
}

/// Delivers every queued packet of `from` to `to`, ignoring the outcomes.
fn drain(from: &mut Dev, to: &mut Dev, rng: &mut StdRng) {
    for bytes in from.core.pending_outbox(NOW).unwrap() {
        to.core.receive(&bytes, T, NOW, rng).unwrap();
    }
}

#[test]
fn recovery_removes_old_devices() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(50);
    let a_path = d.path().join("a");
    let (a_core, phrase) = Core::create(&a_path, &[1; 32], "a", NOW, &mut rng).unwrap();
    let mut a = Dev {
        core: a_core,
        path: a_path,
        key: [1; 32],
    };
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    let mut c = create(d.path(), "c", 3, &mut rng);
    let c_fp = c.core.contact_card("C").unwrap().fingerprint();
    a.core
        .add_contact(&c.core.contact_card("C").unwrap(), None, NOW, &mut rng)
        .unwrap();
    sync_round(&mut a, &mut t, &mut rng);
    c.core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, &mut rng)
        .unwrap();
    // Sessions between C and both of my old devices.
    a.core.send_text(&c_fp, "hi", NOW, &mut rng).unwrap();
    drain(&mut a, &mut c, &mut rng);
    c.core
        .send_text(&a.core.fingerprint(), "hello", NOW, &mut rng)
        .unwrap();
    drain(&mut c, &mut t, &mut rng);
    drain(&mut c, &mut a, &mut rng);
    drain(&mut t, &mut c, &mut rng);
    drain(&mut a, &mut c, &mut rng);
    // A message of C sealed before it learns the recovery, delivered late.
    let late = produced(&mut c, |core| {
        core.send_text(&a_fp(core), "late", NOW, &mut StdRng::seed_from_u64(7))
            .unwrap();
    });

    // Recovery on N; C re-adds me with N's card.
    let recovered_at = NOW + 10;
    let n_core = Core::recover(
        &d.path().join("n"),
        &[4; 32],
        phrase.as_str(),
        "n",
        recovered_at,
        &mut rng,
    )
    .unwrap();
    let n_card = n_core.contact_card("A").unwrap();
    c.core.add_contact(&n_card, None, NOW, &mut rng).unwrap();

    // Only A gets C's relay; T learns it from A.
    let queued = c.core.pending_outbox(NOW).unwrap();
    let outcomes: Vec<_> = queued
        .iter()
        .filter(|b| !late.contains(b))
        .map(|b| a.core.receive(b, T, NOW, &mut rng).unwrap())
        .collect();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Removed))
    );
    sync_round(&mut a, &mut t, &mut rng);
    for dev in [&a, &t] {
        let removed = dev.core.removed().unwrap().unwrap();
        assert_eq!(removed.version, recovered_at);
        assert!(
            events(&dev.core).contains(&TransparencyEvent::DeviceRemoved {
                version: recovered_at
            })
        );
    }
    assert!(matches!(
        a.core.link_offer(NOW, &mut rng),
        Err(CoreError::DeviceRemoved)
    ));
    assert!(matches!(
        t.core.send_text(&c_fp, "x", NOW, &mut rng),
        Err(CoreError::DeviceRemoved)
    ));
    // The late message is still shown on the removed device.
    let shown = late
        .iter()
        .map(|b| a.core.receive(b, T, NOW, &mut rng).unwrap())
        .any(|o| matches!(o, ReceiveOutcome::Message { text, .. } if text == "late"));
    assert!(shown);
    // Root erased for good.
    drop(a.core);
    a.core = Core::open(&a.path, &a.key, NOW).unwrap();
    assert!(admins(&a.core).is_empty());
    assert!(matches!(
        a.core.contact_card("A"),
        Err(CoreError::DeviceRemoved)
    ));
}

/// Fingerprint of the only contact of `core`.
fn a_fp(core: &Core) -> Fingerprint {
    core.contacts().unwrap()[0].fingerprint
}

#[test]
fn admin_transfer_refused_by_a_target_behind_on_the_list() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(44);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    // A links U; T never gets the new list.
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut u, req) = begin(d.path(), "u", 12, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    u.core.finish_link(&out.bundle, None, NOW).unwrap();
    let t_id = device_id(&a.core, "t");
    let transfer = produced(&mut a, |core| {
        core.transfer_admin(t_id, NOW, &mut StdRng::seed_from_u64(8))
            .unwrap();
    });
    let transfer_to_t: Vec<_> = transfer
        .iter()
        .map(|b| t.core.receive(b, T, NOW, &mut rng).unwrap())
        .collect();
    assert!(
        transfer_to_t
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Quarantined { .. })),
        "{transfer_to_t:?}"
    );
    assert!(admins(&t.core).is_empty());
    // No ack: A keeps the root.
    for bytes in t.core.pending_outbox(NOW).unwrap() {
        a.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    assert_eq!(admins(&a.core), vec!["a".to_owned()]);
}

#[test]
fn contacts_other_device_relays_the_removal() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(51);
    let a_path = d.path().join("a");
    let (a_core, phrase) = Core::create(&a_path, &[1; 32], "a", NOW, &mut rng).unwrap();
    let mut a = Dev {
        core: a_core,
        path: a_path,
        key: [1; 32],
    };
    // Contact C on two devices, C1 and C2.
    let mut c1 = create(d.path(), "c1", 3, &mut rng);
    let offer = c1.core.link_offer(NOW, &mut rng).unwrap();
    let (mut c2, req) = begin(d.path(), "c2", 5, &offer, &mut rng);
    let out = c1.core.link_device(&req, false, NOW, &mut rng).unwrap();
    c2.core.finish_link(&out.bundle, None, NOW).unwrap();
    c1.core
        .add_contact(&a.core.contact_card("A").unwrap(), None, NOW, &mut rng)
        .unwrap();
    sync_round(&mut c1, &mut c2, &mut rng);
    a.core
        .add_contact(&c1.core.contact_card("C").unwrap(), None, NOW, &mut rng)
        .unwrap();
    // Only C2 has a session with A.
    let a_fp = a.core.fingerprint();
    c2.core.send_text(&a_fp, "hi", NOW, &mut rng).unwrap();
    for bytes in c2.core.pending_outbox(NOW).unwrap() {
        a.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }

    // Recovery on N; C1 re-adds me, C2 learns it by contact sync.
    let n_core = Core::recover(
        &d.path().join("n"),
        &[4; 32],
        phrase.as_str(),
        "n",
        NOW + 10,
        &mut rng,
    )
    .unwrap();
    c1.core
        .add_contact(&n_core.contact_card("A").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let before = c2.core.pending_outbox(NOW).unwrap();
    sync_round(&mut c1, &mut c2, &mut rng);
    let relayed: Vec<_> = c2
        .core
        .pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .filter(|b| !before.contains(b))
        .collect();
    let outcomes: Vec<_> = relayed
        .iter()
        .map(|b| a.core.receive(b, T, NOW, &mut rng).unwrap())
        .collect();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Removed)),
        "{outcomes:?}"
    );
    assert_eq!(a.core.removed().unwrap().map(|r| r.version), Some(NOW + 10));
}
