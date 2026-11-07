//! End-to-end scenario: two (or three) people, each with their own database.

use std::cell::RefCell;
use std::path::PathBuf;

use barking_core::contact::ContactCard;
use barking_core::envelope::{Wire, parse_wire};
use barking_core::identity::{DeviceCertificate, DeviceList, Fingerprint, RootIdentity};
use barking_core::mailbox::{MailboxId, day_of, intro_mailbox};
use barking_core::packet::{DEFAULT_TTL_SECS, Kind, Packet, PacketId, Tier};
use barking_core::store::{Direction, MessageStatus};
use barking_core::transparency::TransparencyEvent;
use barking_core::{Core, CoreError, ReceiveOutcome};
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
/// A delivery late but still before the 24-hour expiry.
const LATE: u64 = DAY - 3_600;
const T: &str = "file";

struct Party {
    core: Core,
    path: PathBuf,
    key: [u8; 32],
    _dir: TempDir,
}

impl Party {
    fn new(name: &str, seed: u8) -> Party {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.db");
        let key = [seed; 32];
        let mut rng = StdRng::seed_from_u64(u64::from(seed));
        let (core, phrase) = Core::create(&path, &key, name, NOW, &mut rng).unwrap();
        assert_eq!(phrase.as_str().split(' ').count(), 24);
        Party {
            core,
            path,
            key,
            _dir: dir,
        }
    }

    fn fp(&self) -> Fingerprint {
        self.core.fingerprint()
    }

    fn card(&self, name: &str) -> ContactCard {
        self.core.contact_card(name).unwrap()
    }

    fn reopen(&mut self) {
        // The old connection is closed before reopening.
        let placeholder = Core::open(&self.path, &self.key, NOW).unwrap();
        let old = std::mem::replace(&mut self.core, placeholder);
        drop(old);
        self.core = Core::open(&self.path, &self.key, NOW).unwrap();
    }

    fn send(&mut self, to: &Fingerprint, text: &str, now: u64, rng: &mut StdRng) -> Vec<Packet> {
        self.core.send_text(to, text, now, rng).unwrap()
    }

    fn recv(&mut self, p: &Packet, now: u64, rng: &mut StdRng) -> ReceiveOutcome {
        self.core.receive(&p.encode(), T, now, rng).unwrap()
    }

    fn events(&self) -> Vec<TransparencyEvent> {
        self.core
            .transparency_log(10_000)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .collect()
    }
}

/// Alice and Bob, each in their own temporary database, have exchanged cards.
fn pair() -> (Party, Party, StdRng) {
    let mut a = Party::new("tel-alice", 1);
    let mut b = Party::new("tel-bob", 2);
    let ca = a.card("Alice");
    let cb = b.card("Bob");
    assert_eq!(
        a.core
            .add_contact(&cb, Some("bob"), NOW, &mut StdRng::seed_from_u64(0))
            .unwrap(),
        b.fp()
    );
    assert_eq!(
        b.core
            .add_contact(&ca, Some("alice"), NOW, &mut StdRng::seed_from_u64(0))
            .unwrap(),
        a.fp()
    );
    (a, b, StdRng::seed_from_u64(99))
}

/// Links a new device `name` (database `path`) to the administrator `admin`,
/// through the full flow: offer, request, acceptance, completion.
fn link_new(
    admin: &mut Core,
    path: &std::path::Path,
    key: [u8; 32],
    name: &str,
    rng: &mut StdRng,
) -> Core {
    let offer = admin.link_offer(NOW, rng).unwrap();
    let (mut t, req) = Core::begin_link(path, &key, &offer, name, NOW, rng).unwrap();
    let out = admin.link_device(&req, false, NOW, rng).unwrap();
    t.finish_link(&out.bundle, None, NOW).unwrap();
    t
}

/// Unwraps a `Message`, otherwise fails.
fn expect_msg(o: ReceiveOutcome) -> (Fingerprint, Option<String>, String, Packet) {
    match o {
        ReceiveOutcome::Message {
            from,
            alias,
            text,
            ack,
        } => (from, alias, text, ack),
        other => panic!("Message expected, got {other:?}"),
    }
}

fn one(mut v: Vec<Packet>) -> Packet {
    assert_eq!(v.len(), 1, "exactly one packet expected");
    v.remove(0)
}

fn is_initial(p: &Packet) -> bool {
    matches!(parse_wire(&p.payload).unwrap(), Wire::Initial { .. })
}

#[test]
fn alice_to_bob_and_back() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "Hi Bob! 🐕", NOW, &mut rng));
    assert_eq!(p1.kind, Kind::Message);
    assert!(is_initial(&p1));
    assert_ne!(p1.tier, Tier::S, "never a session opening in tier S");

    let (from, alias, text, _) = expect_msg(b.recv(&p1, NOW, &mut rng));
    assert_eq!(from, a.fp());
    assert_eq!(alias.as_deref(), Some("alice"));
    assert_eq!(text, "Hi Bob! 🐕");

    // Bob replies in the session opened by Alice: no Initial.
    let p2 = one(b.send(&a.fp(), "Hi Alice", NOW + 5, &mut rng));
    assert!(!is_initial(&p2));
    assert_eq!(p2.tier, Tier::S);
    let (from, alias, text, _) = expect_msg(a.recv(&p2, NOW + 5, &mut rng));
    assert_eq!(from, b.fp());
    assert_eq!(alias.as_deref(), Some("bob"));
    assert_eq!(text, "Hi Alice");

    // After Bob's reply, Alice no longer sends an Initial.
    let p3 = one(a.send(&b.fp(), "works for me", NOW + 10, &mut rng));
    assert!(!is_initial(&p3));
    let (_, _, text, _) = expect_msg(b.recv(&p3, NOW + 10, &mut rng));
    assert_eq!(text, "works for me");

    let hist = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(hist.len(), 3);
    assert_eq!(hist[1].direction, Direction::In);
    assert_eq!(hist[1].body, "Hi Alice");
}

#[test]
fn initial_resent_until_first_reply() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "one", NOW, &mut rng));
    let p2 = one(a.send(&b.fp(), "two", NOW + 1, &mut rng));
    assert!(is_initial(&p1) && is_initial(&p2));
    // Reversed order: the second Initial opens the session, the first reuses it.
    assert_eq!(expect_msg(b.recv(&p2, NOW + 2, &mut rng)).2, "two");
    assert_eq!(expect_msg(b.recv(&p1, NOW + 3, &mut rng)).2, "one");
}

#[test]
fn ack_marks_delivered() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "ack-me", NOW, &mut rng));
    let sent = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(sent[0].status, MessageStatus::Sent);
    assert_eq!(sent.len(), 1);

    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(ack.kind, Kind::Ack);
    assert_eq!(ack.tier, Tier::S);
    match a.recv(&ack, NOW + 1, &mut rng) {
        ReceiveOutcome::AckReceived { packet_id } => assert_eq!(packet_id, p.id),
        other => panic!("AckReceived expected, got {other:?}"),
    }
    let after = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(after[0].status, MessageStatus::Delivered);
    assert!(a.events().iter().any(
        |e| matches!(e, TransparencyEvent::AckVerified { for_packet } if *for_packet == p.id)
    ));
    // The same ack a second time is not counted twice.
    assert!(matches!(
        a.recv(&ack, NOW + 2, &mut rng),
        ReceiveOutcome::Duplicate
    ));
}

#[test]
fn forged_or_malformed_acks_are_not_for_us() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));

    // Wrong secret.
    let mut bad = ack.clone();
    bad.payload[20] ^= 1;
    assert!(matches!(
        a.recv(&bad, NOW, &mut rng),
        ReceiveOutcome::NotForUs
    ));
    // Ack payload of the wrong length (31 and 33 bytes).
    for len in [31usize, 33] {
        let mut odd = ack.clone();
        odd.payload.resize(len, 0);
        if len == 33 {
            odd.payload[32] = 1;
        }
        assert!(matches!(
            a.recv(&odd, NOW, &mut rng),
            ReceiveOutcome::NotForUs
        ));
    }
    // Valid ack for a packet I did not send (Bob's packet to me).
    let q = one(b.send(&a.fp(), "y", NOW, &mut rng));
    let (_, _, _, ack_q) = expect_msg(a.recv(&q, NOW, &mut rng));
    assert!(matches!(
        a.recv(&ack_q, NOW, &mut rng),
        ReceiveOutcome::NotForUs
    ));
    assert_eq!(
        a.core.messages_with(&b.fp()).unwrap()[0].status,
        MessageStatus::Sent
    );
}

#[test]
fn duplicate_shown_once() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "once", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    assert!(matches!(
        b.recv(&p, NOW + 1, &mut rng),
        ReceiveOutcome::Duplicate
    ));
    // Also for a normal message (after the session is opened).
    let q = one(b.send(&a.fp(), "back", NOW + 2, &mut rng));
    expect_msg(a.recv(&q, NOW + 2, &mut rng));
    assert!(matches!(
        a.recv(&q, NOW + 3, &mut rng),
        ReceiveOutcome::Duplicate
    ));
    assert!(
        b.events()
            .iter()
            .any(|e| matches!(e, TransparencyEvent::DuplicateIgnored { .. }))
    );
    assert_eq!(b.core.messages_with(&a.fp()).unwrap().len(), 2);
}

#[test]
fn expired_packet() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "old", NOW, &mut rng));
    let late = u64::from(p.expires_at) + 1;
    assert!(matches!(
        b.recv(&p, late, &mut rng),
        ReceiveOutcome::Expired
    ));
}

#[test]
fn late_delivery_within_freshness_window() {
    let (mut a, mut b, mut rng) = pair();
    // Initial delivered 23 hours after sending: intro mailbox of the sending day.
    let p1 = one(a.send(&b.fp(), "one day late", NOW, &mut rng));
    assert_eq!(
        expect_msg(b.recv(&p1, NOW + LATE, &mut rng)).2,
        "one day late"
    );
    // Session established in both directions.
    let r = one(b.send(&a.fp(), "received", NOW + LATE, &mut rng));
    expect_msg(a.recv(&r, NOW + LATE, &mut rng));
    // Normal message (session mailbox) delivered 23 hours after sending.
    let t = NOW + LATE + 10;
    let p2 = one(a.send(&b.fp(), "normal but late", t, &mut rng));
    assert!(!is_initial(&p2));
    assert_eq!(
        expect_msg(b.recv(&p2, t + LATE, &mut rng)).2,
        "normal but late"
    );
    // Beyond the freshness window: expired.
    let p3 = one(a.send(&b.fp(), "too late", t + 1, &mut rng));
    assert!(matches!(
        b.recv(&p3, t + 1 + DEFAULT_TTL_SECS + DAY + 1, &mut rng),
        ReceiveOutcome::Expired
    ));
    // Even with an expiry rewritten by a relay: the sending-day mailbox
    // is outside the accepted window.
    let p4 = one(a.send(&b.fp(), "rewritten", t + 2, &mut rng));
    let later = t + 2 + DEFAULT_TTL_SECS + 2 * DAY;
    let mut rewritten = p4.clone();
    rewritten.expires_at = u32::try_from(later + DEFAULT_TTL_SECS).unwrap();
    assert!(matches!(
        b.recv(&rewritten, later, &mut rng),
        ReceiveOutcome::NotForUs
    ));
}

#[test]
fn clock_skew_one_day_ok() {
    let (mut a, mut b, mut rng) = pair();
    // Bob's clock is one day ahead.
    let p1 = one(a.send(&b.fp(), "one day off", NOW, &mut rng));
    assert_eq!(
        expect_msg(b.recv(&p1, NOW + DAY, &mut rng)).2,
        "one day off"
    );
    // Bob's clock is one day ahead: Alice reads the next-day mailbox.
    let p3 = one(b.send(&a.fp(), "back", NOW + DAY, &mut rng));
    assert_eq!(expect_msg(a.recv(&p3, NOW, &mut rng)).2, "back");
    // Sender two days ahead: mailbox outside the window.
    let p4 = one(b.send(&a.fp(), "too far ahead", NOW + 3 * DAY, &mut rng));
    assert!(matches!(
        a.recv(&p4, NOW, &mut rng),
        ReceiveOutcome::NotForUs
    ));
}

#[test]
fn simultaneous_first_messages() {
    let (mut a, mut b, mut rng) = pair();
    let pa = one(a.send(&b.fp(), "from A", NOW, &mut rng));
    let pb = one(b.send(&a.fp(), "from B", NOW, &mut rng));
    assert!(is_initial(&pa) && is_initial(&pb));
    assert_eq!(expect_msg(b.recv(&pa, NOW + 1, &mut rng)).2, "from A");
    assert_eq!(expect_msg(a.recv(&pb, NOW + 1, &mut rng)).2, "from B");

    let mut t = NOW + 10;
    for i in 0..3 {
        let x = one(a.send(&b.fp(), &format!("A{i}"), t, &mut rng));
        assert!(!is_initial(&x), "no more Initial after a reception");
        assert_eq!(expect_msg(b.recv(&x, t, &mut rng)).2, format!("A{i}"));
        t += 1;
        let y = one(b.send(&a.fp(), &format!("B{i}"), t, &mut rng));
        assert!(!is_initial(&y));
        assert_eq!(expect_msg(a.recv(&y, t, &mut rng)).2, format!("B{i}"));
        t += 1;
    }
}

#[test]
fn garbage_and_truncated_never_panic() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "real message", NOW, &mut rng));
    let good = p.encode();

    let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xff; 245], vec![0; 1024]];
    for cut in [1usize, 41, 42, 100, good.len() - 1] {
        inputs.push(good[..cut].to_vec());
    }
    // Lying tier: announces S but length M, and the reverse.
    let mut liar = good.clone();
    liar[3] = Tier::S as u8;
    inputs.push(liar);
    let mut liar2 = good[..245].to_vec();
    liar2[3] = Tier::L as u8;
    inputs.push(liar2);
    // Tampered payload, lying payload length.
    let mut flipped = good.clone();
    flipped[60] ^= 0x55;
    inputs.push(flipped);
    let mut badlen = good.clone();
    badlen[40] = 0xff;
    badlen[41] = 0xff;
    inputs.push(badlen);
    let mut rnd = StdRng::seed_from_u64(5);
    for len in [245usize, 1024, 16384, 3000] {
        let mut v = vec![0u8; len];
        rand::RngExt::fill(&mut rnd, &mut v[..]);
        inputs.push(v);
    }

    for input in &inputs {
        let out = b.core.receive(input, T, NOW, &mut rng);
        match out {
            Ok(ReceiveOutcome::NotForUs) | Ok(ReceiveOutcome::Quarantined { .. }) => {}
            other => panic!("NotForUs or Quarantined expected, got {other:?}"),
        }
    }
    // The real message still gets through.
    assert_eq!(expect_msg(b.recv(&p, NOW, &mut rng)).2, "real message");
}

#[test]
fn tampered_body_quarantined_then_original_ok() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "intact", NOW, &mut rng));
    let mut bad = p.clone();
    let n = bad.payload.len();
    bad.payload[n - 3] ^= 1;
    match b.recv(&bad, NOW, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => {
            assert_eq!(reason, "decryption impossible");
        }
        other => panic!("Quarantined expected, got {other:?}"),
    }
    assert!(
        b.events()
            .iter()
            .any(|e| matches!(e, TransparencyEvent::DecryptFailed { .. }))
    );
    // The forged packet does not block the original (same identifier).
    assert_eq!(expect_msg(b.recv(&p, NOW, &mut rng)).2, "intact");
}

#[test]
fn unknown_sender_quarantined() {
    let (_a, mut b, mut rng) = pair();
    let mut carol = Party::new("tel-carol", 3);
    carol
        .core
        .add_contact(&b.card("Bob"), Some("bob"), NOW, &mut rng)
        .unwrap();
    let p = one(carol.send(&b.fp(), "hi, it's Carol", NOW, &mut rng));
    match b.recv(&p, NOW, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("unknown"), "{reason}"),
        other => panic!("Quarantined expected, got {other:?}"),
    }
    assert!(
        b.core
            .contacts()
            .unwrap()
            .iter()
            .all(|c| c.fingerprint != carol.fp())
    );
}

#[test]
fn stale_initial_replayed_into_today_mailbox_quarantined() {
    // A relay replays an old Initial by rewriting the header (day mailbox,
    // expiry): the authenticated timestamp of the envelope gives it away.
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "old", NOW, &mut rng));
    let later = NOW + 10 * DAY;
    let bob_dev = b.card("Bob").devices.certs[0].device;
    let mut replay = p.clone();
    replay.mailbox = intro_mailbox(&bob_dev, day_of(later));
    replay.expires_at = u32::try_from(later + DEFAULT_TTL_SECS).unwrap();
    match b.recv(&replay, later, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("too old"), "{reason}"),
        other => panic!("Quarantined expected, got {other:?}"),
    }
    // The session that this old Initial would have opened is not created.
    assert_eq!(b.core.watched_mailboxes(later).unwrap().len(), 3);
    assert!(b.core.messages_with(&a.fp()).unwrap().is_empty());
}

#[test]
fn persists_across_reopen() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "before", NOW, &mut rng));
    a.reopen();
    b.reopen();
    assert_eq!(expect_msg(b.recv(&p1, NOW, &mut rng)).2, "before");
    b.reopen();
    let p2 = one(b.send(&a.fp(), "reply", NOW + 1, &mut rng));
    a.reopen();
    let (from, alias, text, ack) = expect_msg(a.recv(&p2, NOW + 1, &mut rng));
    assert_eq!(
        (from, alias.as_deref(), text.as_str()),
        (b.fp(), Some("bob"), "reply")
    );
    b.reopen();
    assert!(matches!(
        b.recv(&ack, NOW + 2, &mut rng),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert!(matches!(
        b.recv(&p1, NOW + 2, &mut rng),
        ReceiveOutcome::Duplicate
    ));
    let p3 = one(a.send(&b.fp(), "after", NOW + 3, &mut rng));
    assert!(!is_initial(&p3));
    assert_eq!(expect_msg(b.recv(&p3, NOW + 3, &mut rng)).2, "after");
    assert_eq!(a.core.fingerprint(), a.fp());
    assert_eq!(a.core.contacts().unwrap().len(), 1);
}

#[test]
fn send_state_persisted_before_return() {
    // A reopen between two sends must never reuse a message key.
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "one", NOW, &mut rng));
    expect_msg(b.recv(&p1, NOW, &mut rng));
    let p2 = one(b.send(&a.fp(), "r", NOW, &mut rng));
    expect_msg(a.recv(&p2, NOW, &mut rng));
    let p3 = one(a.send(&b.fp(), "two", NOW, &mut rng));
    a.reopen();
    let p4 = one(a.send(&b.fp(), "three", NOW, &mut rng));
    assert_ne!(p3.payload, p4.payload);
    assert_eq!(expect_msg(b.recv(&p4, NOW, &mut rng)).2, "three");
    assert_eq!(expect_msg(b.recv(&p3, NOW, &mut rng)).2, "two");
}

#[test]
fn multi_device_fanout() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let p1 = dir.path().join("bob1.db");
    let (mut bob1, _) = Core::create(&p1, &[2; 32], "tel-bob", NOW, &mut rng).unwrap();
    let p2 = dir.path().join("bob2.db");
    let mut bob2 = link_new(&mut bob1, &p2, [3; 32], "pc-bob", &mut rng);
    assert_eq!(bob1.fingerprint(), bob2.fingerprint());
    let card = bob1.contact_card("Bob").unwrap();
    // Initial list signed at version `NOW`, then `version + 1` on linking.
    assert_eq!(card.devices.version, NOW + 1);
    assert_eq!(card.devices.certs.len(), 2);
    assert_eq!(card.bundles.len(), 2);
    card.verify().unwrap();

    let bob_fp = a
        .core
        .add_contact(&card, Some("bob"), NOW, &mut rng)
        .unwrap();
    let alice_card = a.card("Alice");
    bob1.add_contact(&alice_card, Some("alice"), NOW, &mut rng)
        .unwrap();
    bob2.add_contact(&alice_card, Some("alice"), NOW, &mut rng)
        .unwrap();

    let pkts = a.send(&bob_fp, "to all your devices", NOW, &mut rng);
    assert_eq!(pkts.len(), 2);
    assert_ne!(pkts[0].id, pkts[1].id);
    for core in [&mut bob1, &mut bob2] {
        let mut opened = 0;
        for p in &pkts {
            match core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
                ReceiveOutcome::Message { text, .. } => {
                    assert_eq!(text, "to all your devices");
                    opened += 1;
                }
                ReceiveOutcome::NotForUs => {}
                other => panic!("unexpected : {other:?}"),
            }
        }
        assert_eq!(opened, 1, "each device decrypts exactly one packet");
    }
}

#[test]
fn send_to_multi_device_contact_is_one_message() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let (mut bob1, _) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let mut bob2 = link_new(&mut bob1, &dir.path().join("b2"), [3; 32], "b2", &mut rng);
    let card = bob1.contact_card("Bob").unwrap();
    let bob = a
        .core
        .add_contact(&card, Some("bob"), NOW, &mut rng)
        .unwrap();
    let alice_card = a.card("Alice");
    bob1.add_contact(&alice_card, Some("alice"), NOW, &mut rng)
        .unwrap();
    bob2.add_contact(&alice_card, Some("alice"), NOW, &mut rng)
        .unwrap();

    let pkts = a.send(&bob, "a single message", NOW, &mut rng);
    assert_eq!(pkts.len(), 2);
    let rows = a.core.messages_with(&bob).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, MessageStatus::Sent);
    for core in [&mut bob1, &mut bob2] {
        let mut ack = None;
        for p in &pkts {
            if let ReceiveOutcome::Message { ack: k, .. } =
                core.receive(&p.encode(), T, NOW, &mut rng).unwrap()
            {
                ack = Some(k);
            }
        }
        let ack = ack.expect("each device opens a packet");
        let out = a.core.receive(&ack.encode(), T, NOW + 1, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::AckReceived { .. }), "{out:?}");
        let rows = a.core.messages_with(&bob).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, MessageStatus::Delivered);
    }
}

#[test]
fn device_list_rollback_refused() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(8);
    let (mut bob1, _) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let old_card = bob1.contact_card("Bob").unwrap();
    let _bob2 = link_new(&mut bob1, &dir.path().join("b2"), [3; 32], "b2", &mut rng);
    let new_card = bob1.contact_card("Bob").unwrap();
    a.core
        .add_contact(&new_card, Some("bob"), NOW, &mut rng)
        .unwrap();
    // A card with an older list is refused.
    assert!(
        a.core
            .add_contact(&old_card, Some("bob"), NOW, &mut rng)
            .is_err()
    );
    let pkts = a.send(&bob1.fingerprint(), "x", NOW, &mut rng);
    assert_eq!(pkts.len(), 2);
}

#[test]
fn contact_key_change_flagged() {
    let (mut a, b, _rng) = pair();
    a.core
        .mark_verified(&b.fp(), NOW, &mut StdRng::seed_from_u64(0))
        .unwrap();
    assert!(a.core.contacts().unwrap()[0].verified);
    assert_eq!(
        a.core.safety_number(&b.fp()).unwrap(),
        b.core.safety_number(&a.fp()).unwrap()
    );

    let mallory = Party::new("tel-mallory", 4);
    let new_fp = a
        .core
        .add_contact(
            &mallory.card("Bob"),
            Some("bob"),
            NOW,
            &mut StdRng::seed_from_u64(0),
        )
        .unwrap();
    assert_eq!(new_fp, mallory.fp());
    let contacts = a.core.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].fingerprint, mallory.fp());
    assert_eq!(contacts[0].alias.as_deref(), Some("bob"));
    assert_eq!(contacts[0].display_name, "Bob");
    assert!(!contacts[0].verified);
    assert!(a.events().iter().any(|e| matches!(
        e,
        TransparencyEvent::ContactKeyChanged { alias, old, new }
            if alias == "bob" && *old == b.fp() && *new == mallory.fp()
    )));
    assert_eq!(a.core.resolve("bob").unwrap(), mallory.fp());
}

#[test]
fn resolve_by_alias_or_fingerprint() {
    let (a, b, _) = pair();
    assert_eq!(a.core.resolve("bob").unwrap(), b.fp());
    assert_eq!(a.core.resolve(&b.fp().to_string()).unwrap(), b.fp());
    assert_eq!(a.core.resolve("carol"), Err(CoreError::UnknownContact));
    let stranger = Party::new("x", 9);
    assert_eq!(
        a.core.resolve(&stranger.fp().to_string()),
        Err(CoreError::UnknownContact)
    );
    let mut a = a;
    let mut rng = StdRng::seed_from_u64(1);
    assert_eq!(
        a.core.send_text(&stranger.fp(), "x", NOW, &mut rng).err(),
        Some(CoreError::UnknownContact)
    );
}

#[test]
fn own_card_and_tampered_card_refused() {
    let (mut a, b, _) = pair();
    assert!(
        a.core
            .add_contact(
                &a.card("Alice"),
                Some("me"),
                NOW,
                &mut StdRng::seed_from_u64(0)
            )
            .is_err()
    );
    let mut card = b.card("Bob");
    card.display_name = "Bobby".into();
    assert!(
        a.core
            .add_contact(&card, Some("bob2"), NOW, &mut StdRng::seed_from_u64(0))
            .is_err()
    );
}

#[test]
fn transparency_has_no_plaintext() {
    let (mut a, mut b, mut rng) = pair();
    let secret = "very-secret-text-42";
    let p = one(a.send(&b.fp(), secret, NOW, &mut rng));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    a.recv(&ack, NOW, &mut rng);
    let q = one(b.send(&a.fp(), secret, NOW, &mut rng));
    expect_msg(a.recv(&q, NOW, &mut rng));
    b.recv(&q, NOW, &mut rng);
    for party in [&a, &b] {
        let events = party.events();
        assert!(events.len() >= 4);
        for e in events {
            let d = e.describe();
            assert!(!d.contains(secret), "{d}");
            assert!(!format!("{e:?}").contains(secret));
        }
    }
    // The first contact does not claim to hide the recipient.
    for e in a.events().into_iter().chain(b.events()) {
        let first = matches!(
            e,
            TransparencyEvent::PacketSealed {
                first_contact: true,
                ..
            } | TransparencyEvent::PacketOpened {
                first_contact: true,
                ..
            }
        );
        if first {
            let d = e.describe();
            assert!(!d.contains("whom you are writing to"), "{d}");
            assert!(d.contains("contact card"), "{d}");
        }
    }
    assert!(a.events().iter().any(|e| matches!(
        e,
        TransparencyEvent::PacketSealed {
            first_contact: true,
            ..
        }
    )));
    assert!(b.events().iter().any(|e| matches!(
        e,
        TransparencyEvent::PacketOpened {
            first_contact: true,
            ..
        }
    )));
}

#[test]
fn transparency_log_returns_most_recent() {
    let (mut a, mut b, mut rng) = pair();
    for i in 0..5u64 {
        let p = one(a.send(&b.fp(), "x", NOW + i, &mut rng));
        expect_msg(b.recv(&p, NOW + i, &mut rng));
    }
    let all = a.core.transparency_log(1000).unwrap();
    let last2 = a.core.transparency_log(2).unwrap();
    assert_eq!(last2.len(), 2);
    assert_eq!(&all[all.len() - 2..], &last2[..]);
    assert_eq!(last2[1].0, NOW + 4);
}

#[test]
fn debug_hides_secrets_and_text() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "hush-hush", NOW, &mut rng));
    let out = b.recv(&p, NOW, &mut rng);
    assert!(!format!("{out:?}").contains("hush-hush"));
    let dbg = format!("{:?}", a.core);
    assert!(dbg.starts_with("Core"), "{dbg}");
    assert!(!dbg.contains("signing") && !dbg.contains("spk"));
}

#[test]
fn open_wrong_key_and_double_create() {
    let a = Party::new("tel-alice", 1);
    let path = a.path.clone();
    let key = a.key;
    drop(a.core);
    assert_eq!(
        Core::open(&path, &[0xee; 32], NOW).err(),
        Some(CoreError::StoreLocked)
    );
    let mut rng = StdRng::seed_from_u64(1);
    assert!(Core::create(&path, &key, "again", NOW, &mut rng).is_err());
    assert!(Core::open(&path, &key, NOW).is_ok());
    let dir = tempfile::tempdir().unwrap();
    assert!(Core::open(&dir.path().join("empty.db"), &key, NOW).is_err());
    assert!(
        !dir.path().join("empty.db").exists(),
        "open does not create a database"
    );
    assert_eq!(
        Core::recover(
            &dir.path().join("r.db"),
            &key,
            "not a phrase",
            "x",
            NOW,
            &mut rng
        )
        .err(),
        Some(CoreError::InvalidPhrase)
    );
}

#[test]
fn watched_mailboxes_cover_three_days() {
    let (mut a, mut b, mut rng) = pair();
    // Without a session: 3 intro mailboxes.
    assert_eq!(b.core.watched_mailboxes(NOW).unwrap().len(), 3);
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    assert!(b.core.watched_mailboxes(NOW).unwrap().contains(&p.mailbox));
    assert!(
        b.core
            .watched_mailboxes(NOW + DAY)
            .unwrap()
            .contains(&p.mailbox)
    );
    assert!(
        !b.core
            .watched_mailboxes(NOW + 2 * DAY)
            .unwrap()
            .contains(&p.mailbox)
    );
    expect_msg(b.recv(&p, NOW, &mut rng));
    // With a session: 3 more mailboxes.
    assert_eq!(b.core.watched_mailboxes(NOW).unwrap().len(), 6);
}

#[test]
fn offline_five_days_still_watches_missed_days() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    b.core.mark_polled(NOW).unwrap();
    let later = NOW + 5 * DAY;
    let watched = b.core.watched_mailboxes(later).unwrap();
    // Alice writes every day: the packet's mailbox is Bob's for that day.
    for d in day_of(NOW)..=day_of(later) + 1 {
        let t = u64::from(d) * DAY;
        let q = one(a.send(&b.fp(), "day", t, &mut rng));
        assert!(watched.contains(&q.mailbox), "day {d} not watched");
    }
}

#[test]
fn polling_window_capped_at_nine_days() {
    let (_a, mut b, _rng) = pair();
    let bob_dev = b.card("Bob").devices.certs[0].device;
    b.core.mark_polled(NOW).unwrap();
    let later = NOW + 20 * DAY;
    let watched = b.core.watched_mailboxes(later).unwrap();
    // 7 days back, the same day and the next day.
    assert_eq!(watched.len(), 9);
    let last = day_of(later) + 1;
    for d in last - 8..=last {
        assert!(watched.contains(&intro_mailbox(&bob_dev, d)), "day {d}");
    }
}

#[test]
fn polled_in_future_falls_back() {
    let (_a, mut b, _rng) = pair();
    let reference = b.core.watched_mailboxes(NOW).unwrap();
    b.core.mark_polled(NOW + 10 * DAY).unwrap();
    assert_eq!(b.core.watched_mailboxes(NOW).unwrap(), reference);
}

fn arb_packet_bytes(watched: Vec<MailboxId>) -> impl Strategy<Value = Vec<u8>> {
    let n = watched.len();
    prop_oneof![
        // Arbitrary bytes.
        proptest::collection::vec(any::<u8>(), 0..2048),
        // Well-formed packets to a watched mailbox, arbitrary payload.
        (
            0usize..n,
            prop_oneof![Just(Tier::S), Just(Tier::M)],
            any::<bool>(),
            any::<[u8; 16]>(),
            proptest::collection::vec(any::<u8>(), 0..900),
        )
            .prop_map(move |(i, tier, ack, id, mut payload)| {
                payload.truncate(tier.size() - 42);
                Packet {
                    kind: if ack { Kind::Ack } else { Kind::Message },
                    hops: 8,
                    tier,
                    id: PacketId(id),
                    expires_at: u32::MAX,
                    mailbox: watched[i],
                    payload,
                }
                .encode()
            }),
    ]
}

#[test]
fn receive_arbitrary_bytes_always_ok() {
    let (mut a, mut b, mut rng) = pair();
    // A session exists, so that session mailboxes are reached too.
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    let watched = b.core.watched_mailboxes(NOW).unwrap();
    let state = RefCell::new((b, rng));
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
    runner
        .run(&arb_packet_bytes(watched), |bytes| {
            let (b, rng) = &mut *state.borrow_mut();
            let out = b.core.receive(&bytes, T, NOW, rng);
            prop_assert!(out.is_ok(), "{out:?}");
            let shown = matches!(out, Ok(ReceiveOutcome::Message { .. }));
            prop_assert!(!shown, "no message must come out of random bytes");
            Ok(())
        })
        .unwrap();
}

#[test]
fn link_request_tampering_is_refused() {
    // Any tampering with the request is refused (by the MAC; the proof
    // of possession under a valid MAC is tested in `core/link.rs`), and
    // the intact request then goes through: a refusal does not consume the offer.
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(12);
    let (mut bob1, _) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let offer = bob1.link_offer(NOW, &mut rng).unwrap();
    let (_bob2, good) = Core::begin_link(
        &dir.path().join("b2"),
        &[3; 32],
        &offer,
        "b2",
        NOW,
        &mut rng,
    )
    .unwrap();
    for tamper in 0..3 {
        let mut req = good.clone();
        match tamper {
            0 => req.device_sig[0] ^= 1,
            1 => req.name = "other".into(),
            _ => req.issued_at += 1,
        }
        assert!(
            bob1.link_device(&req, false, NOW, &mut rng).is_err(),
            "tampering {tamper}"
        );
    }
    bob1.link_device(&good, false, NOW, &mut rng).unwrap();
}

#[test]
fn card_claiming_another_contacts_device_rejected() {
    // Mallory wants to claim Alice's device under her own root.
    let (_a, mut b, mut rng) = pair();
    let alice_card = _a.card("Alice");
    let alice_cert = alice_card.devices.certs[0].clone();
    let dir = tempfile::tempdir().unwrap();
    let (mallory, phrase) =
        Core::create(&dir.path().join("m"), &[5; 32], "m", NOW, &mut rng).unwrap();
    let mroot = RootIdentity::from_phrase(phrase.as_str()).unwrap();
    // 1. Alice's proof of possession is bound to her root.
    assert_eq!(
        DeviceCertificate::issue_with_proof(
            &mroot,
            alice_cert.device,
            &alice_cert.name,
            alice_cert.issued_at,
            alice_cert.device_sig,
        )
        .err(),
        Some(CoreError::InvalidSignature)
    );
    // 2. Alice's certificate as is cannot enter Mallory's list.
    let mut forged = mallory.contact_card("Alice").unwrap();
    assert!(DeviceList::sign(&mroot, 2, vec![alice_cert.clone()]).is_err());
    forged.devices.certs.push(alice_cert);
    assert!(
        b.core
            .add_contact(&forged, Some("alice2"), NOW, &mut rng)
            .is_err()
    );
    // 3. Alice's messages stay attributed to Alice.
    let mut a = _a;
    let p = one(a.send(&b.fp(), "it's Alice", NOW, &mut rng));
    let (from, alias, ..) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!((from, alias.as_deref()), (a.fp(), Some("alice")));
}

#[test]
fn revoked_device_refused_for_normal_and_initial() {
    let mut alice = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(13);
    let (mut bob1, phrase) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let mut bob2 = link_new(&mut bob1, &dir.path().join("b2"), [3; 32], "b2", &mut rng);
    let v2 = bob1.contact_card("Bob").unwrap();
    let bob_fp = alice
        .core
        .add_contact(&v2, Some("bob"), NOW, &mut rng)
        .unwrap();
    let alice_card = alice.card("Alice");
    bob2.add_contact(&alice_card, Some("alice"), NOW, &mut rng)
        .unwrap();

    // Bob2 opens the session (two Initials), Alice receives one and replies.
    let i1 = bob2
        .send_text(&alice.fp(), "i1", NOW, &mut rng)
        .unwrap()
        .remove(0);
    let i2 = bob2
        .send_text(&alice.fp(), "i2", NOW, &mut rng)
        .unwrap()
        .remove(0);
    assert!(is_initial(&i1) && is_initial(&i2));
    assert_eq!(expect_msg(alice.recv(&i1, NOW, &mut rng)).2, "i1");
    // One packet per Bob device; Bob2 decrypts its own (its session
    // is no longer pending: it will send normal messages from now on).
    let replies = alice.send(&bob_fp, "r", NOW, &mut rng);
    let opened = replies
        .iter()
        .filter(|p| {
            matches!(
                bob2.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { .. }
            )
        })
        .count();
    assert_eq!(opened, 1);
    let n0 = bob2
        .send_text(&alice.fp(), "n0", NOW, &mut rng)
        .unwrap()
        .remove(0);
    let n1 = bob2
        .send_text(&alice.fp(), "n1", NOW, &mut rng)
        .unwrap()
        .remove(0);
    assert!(!is_initial(&n0) && !is_initial(&n1));
    // Before revocation, a normal message from Bob2 gets through.
    assert_eq!(expect_msg(alice.recv(&n0, NOW, &mut rng)).2, "n0");

    // Bob revokes Bob2: next list without it.
    let root = RootIdentity::from_phrase(phrase.as_str()).unwrap();
    let bob1_cert = v2.devices.certs[0].clone();
    let bob1_bundle = v2
        .bundles
        .iter()
        .find(|b| b.device == bob1_cert.device)
        .unwrap()
        .clone();
    let v3 = DeviceList::sign(&root, v2.devices.version + 1, vec![bob1_cert]).unwrap();
    let card3 = ContactCard::sign(&root, "Bob", v3, vec![bob1_bundle], Vec::new()).unwrap();
    alice
        .core
        .add_contact(&card3, Some("bob"), NOW, &mut rng)
        .unwrap();

    // Neither Bob2's normal message nor its Initial get through once revoked.
    let normal = alice.recv(&n1, NOW, &mut rng);
    assert!(
        matches!(
            normal,
            ReceiveOutcome::NotForUs | ReceiveOutcome::Quarantined { .. }
        ),
        "{normal:?}"
    );
    match alice.recv(&i2, NOW, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("unknown"), "{reason}"),
        other => panic!("Quarantined expected, got {other:?}"),
    }
    let texts: Vec<String> = alice
        .core
        .messages_with(&bob_fp)
        .unwrap()
        .into_iter()
        .filter(|m| m.direction == Direction::In)
        .map(|m| m.body)
        .collect();
    assert_eq!(texts, vec!["i1", "n0"]);
}

#[test]
fn outbox_survives_reopen() {
    let (mut a, b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "don't lose me", NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![p.encode()]);
    a.reopen();
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![p.encode()]);
}

#[test]
fn ack_clears_outbox() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "ack-me", NOW, &mut rng));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 1);
    assert!(matches!(
        a.recv(&ack, NOW + 1, &mut rng),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert!(a.core.pending_outbox(NOW + 1).unwrap().is_empty());
}

#[test]
fn expired_leaves_outbox() {
    let (mut a, b, mut rng) = pair();
    one(a.send(&b.fp(), "too late", NOW, &mut rng));
    assert_eq!(
        a.core.pending_outbox(NOW + DEFAULT_TTL_SECS).unwrap().len(),
        1
    );
    assert!(
        a.core
            .pending_outbox(NOW + DEFAULT_TTL_SECS + 1)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn emitted_ack_is_queued() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "hi", NOW, &mut rng));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(b.core.pending_outbox(NOW).unwrap(), vec![ack.encode()]);
}

#[test]
fn send_rollback_leaves_no_outbox_row() {
    let (mut a, b, mut rng) = pair();
    let too_long = "x".repeat(100_000);
    assert!(a.core.send_text(&b.fp(), &too_long, NOW, &mut rng).is_err());
    let stranger = Fingerprint([9; 32]);
    assert_eq!(
        a.core.send_text(&stranger, "?", NOW, &mut rng).unwrap_err(),
        CoreError::UnknownContact
    );
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());
}

#[test]
fn recovered_identity_reachable_by_existing_contact() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(21);
    let (mut bob1, phrase) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let bob_fp = bob1.fingerprint();
    a.core
        .add_contact(
            &bob1.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    bob1.add_contact(&a.card("Alice"), Some("alice"), NOW, &mut rng)
        .unwrap();
    let p = one(a.send(&bob_fp, "before", NOW, &mut rng));
    expect_msg(bob1.receive(&p.encode(), T, NOW, &mut rng).unwrap());

    // Bob loses his phone and recovers his identity later.
    let later = NOW + 30 * DAY;
    let mut bob2 = Core::recover(
        &dir.path().join("b2"),
        &[3; 32],
        phrase.as_str(),
        "b2",
        later,
        &mut rng,
    )
    .unwrap();
    assert_eq!(bob2.fingerprint(), bob_fp);
    // Alice adds the new card without removing the old one.
    assert_eq!(
        a.core
            .add_contact(
                &bob2.contact_card("Bob").unwrap(),
                Some("bob"),
                NOW,
                &mut rng
            )
            .unwrap(),
        bob_fp
    );
    bob2.add_contact(&a.card("Alice"), Some("alice"), NOW, &mut rng)
        .unwrap();

    let p = one(a.send(&bob_fp, "after", later, &mut rng));
    let (from, _, text, _) = expect_msg(bob2.receive(&p.encode(), T, later, &mut rng).unwrap());
    assert_eq!((from, text.as_str()), (a.fp(), "after"));
    let r = one(bob2
        .send_text(&a.fp(), "well received", later + 1, &mut rng)
        .unwrap());
    let (from, alias, text, _) = expect_msg(a.recv(&r, later + 1, &mut rng));
    assert_eq!(from, bob_fp);
    assert_eq!(alias.as_deref(), Some("bob"));
    assert_eq!(text, "well received");
}

#[test]
fn skipped_keys_expire_after_seven_days() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "opening", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    let r = one(b.send(&a.fp(), "ok", NOW, &mut rng));
    expect_msg(a.recv(&r, NOW, &mut rng));

    // Alice's clock is one day ahead of Bob's.
    let s = NOW + 100;
    let q0 = one(a.send(&b.fp(), "q0", s, &mut rng));
    let q1 = one(a.send(&b.fp(), "q1", s, &mut rng));
    let p2 = one(a.send(&b.fp(), "p2", s + 1, &mut rng));
    assert!(!is_initial(&q0));
    // Bob receives p2 first: the keys of q0 and q1 are skipped up to `stored`.
    let stored = s + 1 - DAY;
    assert_eq!(expect_msg(b.recv(&p2, stored, &mut rng)).2, "p2");
    // Key skipped for less than 7 days: still usable (the packet, which
    // lives 24 hours, is still unexpired).
    assert_eq!(expect_msg(b.recv(&q1, s + 3_000, &mut rng)).2, "q1");
    // Key skipped for more than 7 days: purged. A packet lives only 24 hours,
    // so a relay rewrites the expiry to make the old packet look fresh.
    let late = stored + 7 * DAY + 1;
    let mut rewritten = q0.clone();
    rewritten.expires_at = u32::try_from(late + DEFAULT_TTL_SECS).unwrap();
    match b.recv(&rewritten, late, &mut rng) {
        ReceiveOutcome::Quarantined { .. } | ReceiveOutcome::NotForUs => {}
        other => panic!("expired skipped key, got {other:?}"),
    }
}

#[test]
fn ack_goes_to_the_original_mailbox_which_the_sender_watches_until_acked() {
    let (mut a, mut b, mut rng) = pair();
    // Ack of an Initial: same mailbox as the message, watched by A as long as
    // the message awaits its ack.
    let p = one(a.send(&b.fp(), "opening", NOW, &mut rng));
    assert!(a.core.watched_mailboxes(NOW).unwrap().contains(&p.mailbox));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(ack.mailbox, p.mailbox);
    // Ack of a normal message, in the other direction.
    let r = one(b.send(&a.fp(), "reply", NOW + 1, &mut rng));
    let (_, _, _, ack_r) = expect_msg(a.recv(&r, NOW + 1, &mut rng));
    assert_eq!(ack_r.mailbox, r.mailbox);
    assert!(
        b.core
            .watched_mailboxes(NOW + 1)
            .unwrap()
            .contains(&ack_r.mailbox)
    );
    // Message delivered almost a day later (the packet lifetime): A still
    // watches its mailbox as long as it awaits the ack.
    let q = one(a.send(&b.fp(), "late", NOW + 2, &mut rng));
    assert!(!is_initial(&q));
    let late = NOW + LATE;
    let (_, _, _, ack_q) = expect_msg(b.recv(&q, late, &mut rng));
    assert_eq!(ack_q.mailbox, q.mailbox);
    assert!(
        a.core
            .watched_mailboxes(late)
            .unwrap()
            .contains(&ack_q.mailbox)
    );
    // Acks are still verified by identifier and secret.
    for (ack, at, id) in [(ack, late, p.id), (ack_q, late, q.id)] {
        match a.recv(&ack, at, &mut rng) {
            ReceiveOutcome::AckReceived { packet_id } => assert_eq!(packet_id, id),
            other => panic!("AckReceived expected, got {other:?}"),
        }
    }
    // Ack received: A no longer watches the late message's mailbox.
    assert!(!a.core.watched_mailboxes(late).unwrap().contains(&q.mailbox));
    assert!(matches!(
        b.recv(&ack_r, NOW + 2, &mut rng),
        ReceiveOutcome::AckReceived { .. }
    ));
}

#[test]
fn removed_or_replaced_contact_leaves_no_outbox_rows() {
    // Deletion: pending messages and acks for Bob disappear.
    let (mut a, mut b, mut rng) = pair();
    one(a.send(&b.fp(), "pending", NOW, &mut rng));
    let q = one(b.send(&a.fp(), "from Bob", NOW, &mut rng));
    expect_msg(a.recv(&q, NOW, &mut rng));
    let carol = Party::new("tel-carol", 5);
    a.core
        .add_contact(&carol.card("Carol"), Some("carol"), NOW, &mut rng)
        .unwrap();
    let c = one(a.send(&carol.fp(), "for Carol", NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 3);
    a.core.remove_contact(&b.fp(), NOW, &mut rng).unwrap();
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![c.encode()]);

    // Replacement by alias: same for the old contact.
    let (mut a, mut b, mut rng) = pair();
    one(a.send(&b.fp(), "pending", NOW, &mut rng));
    let q = one(b.send(&a.fp(), "from Bob", NOW, &mut rng));
    expect_msg(a.recv(&q, NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 2);
    let mallory = Party::new("tel-mallory", 4);
    a.core
        .add_contact(&mallory.card("Bob"), Some("bob"), NOW, &mut rng)
        .unwrap();
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());
}

#[test]
fn large_packet_crosses_lora_mtu() {
    let (mut a, mut b, mut rng) = pair();
    let text = "é".repeat(1900);
    let p = one(a.send(&b.fp(), &text, NOW, &mut rng));
    assert_eq!(p.tier, Tier::L);
    let frames = a.core.frames(&p.encode(), 255).unwrap();
    assert!(frames.len() > 60, "{} frames", frames.len());
    assert!(frames.iter().all(|f| f.len() <= 255));
    let n = frames.len();
    for (i, f) in frames.iter().rev().enumerate() {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        if i + 1 < n {
            assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
        } else {
            let (_, _, got, _) = expect_msg(out);
            assert_eq!(got, text);
        }
    }
}

#[test]
fn tampered_frame_is_rejected_and_logged() {
    let (mut a, mut b, mut rng) = pair();
    let text = "secret-very-private ".repeat(100);
    let p = one(a.send(&b.fp(), &text, NOW, &mut rng));
    let frames = a.core.frames(&p.encode(), 255).unwrap();
    assert!(frames.len() > 1);
    let mut bad = frames.clone();
    let last = bad[1].len() - 1;
    bad[1][last] ^= 0x01;
    let n = bad.len();
    for (i, f) in bad.iter().enumerate() {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        if i + 1 < n {
            assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
        } else {
            assert!(matches!(out, ReceiveOutcome::NotForUs), "{out:?}");
        }
    }
    let rejected: Vec<String> = b
        .events()
        .iter()
        .filter(|e| matches!(e, TransparencyEvent::FrameRejected { .. }))
        .map(|e| e.describe())
        .collect();
    assert_eq!(rejected.len(), 1);
    assert!(rejected[0].contains("bad frame hash"), "{}", rejected[0]);
    assert!(!rejected[0].contains("secret"));
    assert_eq!(
        rejected[0],
        "Frame rejected (bad frame hash): it does not match the announced packet. \
         The packet was not reassembled; the sender will resend it."
    );
    // The original frames succeed.
    let mut done = None;
    for f in &frames {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        if !matches!(out, ReceiveOutcome::Partial) {
            done = Some(out);
        }
    }
    let (_, _, got, _) = expect_msg(done.expect("packet rebuilt"));
    assert_eq!(got, text);
}

#[test]
fn pending_is_bounded_and_expires() {
    let (mut a, mut b, mut rng) = pair();
    let mut firsts = Vec::new();
    for i in 0..100 {
        let text = format!("{i} {}", "x".repeat(900));
        let p = one(a.send(&b.fp(), &text, NOW, &mut rng));
        let frames = a.core.frames(&p.encode(), 255).unwrap();
        assert!(frames.len() > 1);
        let out = b.core.receive_frame(&frames[0], T, NOW, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
        firsts.push(frames);
    }
    assert_eq!(b.core.pending_frames(), 64);
    // The oldest packet was evicted: its remaining frames complete nothing.
    for f in &firsts[0][1..] {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
    }

    // Packet started at NOW, finished after the TTL: does not complete.
    let frames = firsts.last().unwrap();
    let late = NOW + 3601;
    for f in &frames[1..] {
        let out = b.core.receive_frame(f, T, late, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
    }
    // A late frame restarts an entry without crashing; all the
    // frames then rebuild the packet.
    let done = frames
        .iter()
        .map(|f| b.core.receive_frame(f, T, late, &mut rng).unwrap())
        .find(|o| !matches!(o, ReceiveOutcome::Partial));
    expect_msg(done.expect("packet rebuilt"));
}

fn frame_rejections(p: &Party) -> usize {
    p.events()
        .iter()
        .filter(|e| matches!(e, TransparencyEvent::FrameRejected { .. }))
        .count()
}

#[test]
fn junk_frames_are_not_logged() {
    let (_, mut b, mut rng) = pair();
    let before = b.events().len();
    let mut junk = StdRng::seed_from_u64(7);
    for i in 0..1000usize {
        let mut f = vec![0u8; 32];
        junk.fill(&mut f[..]);
        match i % 4 {
            0 => f.truncate(i % 10), // too short
            1 => f[9] = 0,           // zero count
            2 => {
                f[9] = 3;
                f[8] = 3 + (i % 200) as u8; // index out of range
            }
            _ => f.truncate(10), // empty fragment
        }
        let out = b.core.receive_frame(&f, T, NOW, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::NotForUs), "{out:?}");
    }
    assert_eq!(b.events().len(), before);
}

#[test]
fn hash_failures_are_rate_limited() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), &"y".repeat(900), NOW, &mut rng));
    let mut frames = a.core.frames(&p.encode(), 255).unwrap();
    let last = frames.len() - 1;
    let l = frames[last].len() - 1;
    frames[last][l] ^= 1;
    let mut run = |b: &mut Party, at: u64| {
        for f in &frames {
            let out = b.core.receive_frame(f, T, at, &mut rng).unwrap();
            assert!(!matches!(out, ReceiveOutcome::Message { .. }), "{out:?}");
        }
    };
    for i in 0..10 {
        run(&mut b, NOW + i);
    }
    assert_eq!(frame_rejections(&b), 1);
    run(&mut b, NOW + 61);
    assert_eq!(frame_rejections(&b), 2);
}
