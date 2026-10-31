//! Internal tests of the facade: authenticated but refused packets, forged
//! with the real state of a session (impossible from the public API).

use super::*;
use crate::contact::ContactCard;
use crate::envelope::{Body, Envelope, SyncOp, Wire, parse_wire};
use crate::handshake::PrekeyBundle;
use crate::identity::{
    DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic, RootIdentity,
};
use crate::mailbox::day_of;
use crate::packet::{DEFAULT_HOPS, Kind, Tier, ack};
use crate::store::{Direction, MessageId, MessageStatus, SessionRow};
use crate::transparency::SyncKind;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000;

fn party(name: &str, seed: u8) -> (TempDir, Core) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(u64::from(seed));
    let (core, _) = Core::create(&dir.path().join("db"), &[seed; 32], name, NOW, &mut rng).unwrap();
    (dir, core)
}

struct Pair {
    _d: (TempDir, TempDir),
    a: Core,
    b: Core,
    rng: StdRng,
}

/// Alice and Bob with a session established in both directions (no more Initial).
fn pair() -> Pair {
    let (da, mut a) = party("a", 1);
    let (db, mut b) = party("b", 2);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let p = a.send_text(&b.fingerprint(), "x", NOW, &mut rng).unwrap();
    assert!(matches!(
        b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    let q = b.send_text(&a.fingerprint(), "y", NOW, &mut rng).unwrap();
    assert!(matches!(
        a.receive(&q[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    Pair {
        _d: (da, db),
        a,
        b,
        rng,
    }
}

fn best_session(c: &Core) -> SessionRow {
    c.store
        .all_sessions()
        .unwrap()
        .into_iter()
        .max_by_key(|s| (s.last_rx, s.created_at))
        .unwrap()
}

/// Encrypts raw `pt` in the best session of `from` (saved state),
/// wrapped in `Wire::Normal` toward the peer's session mailbox.
fn forge(from: &mut Core, pt: &[u8], id: PacketId, rng: &mut StdRng) -> Packet {
    let mut row = best_session(from);
    assert!(row.pending_initial.is_none());
    let mut ratchet = de_state(&row.state).unwrap();
    let msg = ratchet.encrypt(pt, &row.ad, rng).unwrap();
    row.state = ser_state(&ratchet).unwrap();
    from.store.put_session(&row).unwrap();
    let payload = postcard::to_allocvec(&Wire::Normal { msg }).unwrap();
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::fit(payload.len()).unwrap(),
        id,
        expires_at: u32::MAX,
        mailbox: session_mailbox(&row.mailbox_secret, &row.contact_device, day_of(NOW)),
        payload,
    }
}

fn envelope_bytes(secret: [u8; 16], sent_at: u64, text: &str) -> Vec<u8> {
    postcard::to_allocvec(&Envelope {
        sent_at,
        ack_secret: secret,
        message_id: secret,
        body: Body::Text(text.into()),
    })
    .unwrap()
}

fn reason(o: ReceiveOutcome) -> String {
    match o {
        ReceiveOutcome::Quarantined { reason } => reason,
        other => panic!("Quarantined expected, got {other:?}"),
    }
}

#[test]
fn authenticated_malformed_envelope_keeps_ratchet_and_quarantines() {
    let mut p = pair();
    let before = best_session(&p.b).state.clone();
    let id = PacketId([7; 16]);
    let bad = forge(&mut p.a, &[0xff, 0xff, 0xff], id, &mut p.rng);
    let r = reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap());
    assert_eq!(r, "authenticated but malformed content");
    // The advanced ratchet state is saved: a replay no longer decrypts.
    // (Without an authenticated ack secret, nothing is marked seen.)
    assert_ne!(best_session(&p.b).state, before);
    assert_eq!(
        reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap()),
        "decryption impossible"
    );
    // Nothing appears in the history, and the conversation continues.
    assert_eq!(p.b.messages_with(&p.a.fingerprint()).unwrap().len(), 2);
    let next =
        p.a.send_text(&p.b.fingerprint(), "suite", NOW, &mut p.rng)
            .unwrap();
    match p
        .b
        .receive(&next[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { text, .. } => assert_eq!(text, "suite"),
        other => panic!("{other:?}"),
    }
    // The log contains only fixed reasons.
    for (_, e) in p.b.transparency_log(100).unwrap() {
        if let TransparencyEvent::DecryptFailed { reason, .. } = e {
            assert!(!reason.contains('\u{fffd}'));
        }
    }
}

#[test]
fn packet_id_not_bound_to_ack_secret_quarantined() {
    let mut p = pair();
    let secret = ack::new_secret(&mut p.rng);
    let env = envelope_bytes(secret, NOW, "x");
    let bad = forge(&mut p.a, &env, PacketId([9; 16]), &mut p.rng);
    let r = reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap());
    assert_eq!(r, "inconsistent packet identifier");
}

#[test]
fn contact_reusing_my_packet_id_is_quarantined_not_err() {
    // Bob knows the ack secret of my message: he could forge a
    // message carrying the same identifier (UNIQUE column in the database).
    let mut p = pair();
    let mine =
        p.a.send_text(&p.b.fingerprint(), "to Bob", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let ReceiveOutcome::Message { ack: ack_pkt, .. } =
        p.b.receive(&mine.encode(), "t", NOW, &mut p.rng).unwrap()
    else {
        panic!("Message expected");
    };
    let mut secret = [0u8; 16];
    secret.copy_from_slice(&ack_pkt.payload[16..32]);
    let env = envelope_bytes(secret, NOW, "trap");
    let evil = forge(&mut p.b, &env, mine.id, &mut p.rng);
    let out = p.a.receive(&evil.encode(), "t", NOW, &mut p.rng);
    assert_eq!(reason(out.unwrap()), "packet identifier already used");
}

#[test]
fn stale_or_future_sent_at_quarantined() {
    let mut p = pair();
    for sent_at in [NOW - MAX_AGE_SECS - 1, NOW + MAX_FUTURE_SECS + 1] {
        let secret = ack::new_secret(&mut p.rng);
        let env = envelope_bytes(secret, sent_at, "x");
        let pkt = forge(&mut p.a, &env, ack::packet_id_for(&secret), &mut p.rng);
        let r = reason(p.b.receive(&pkt.encode(), "t", NOW, &mut p.rng).unwrap());
        assert_eq!(r, "message too old or dated in the future");
    }
    // At the exact limits, the message passes.
    for sent_at in [NOW - MAX_AGE_SECS, NOW + MAX_FUTURE_SECS] {
        let secret = ack::new_secret(&mut p.rng);
        let env = envelope_bytes(secret, sent_at, "ok");
        let pkt = forge(&mut p.a, &env, ack::packet_id_for(&secret), &mut p.rng);
        assert!(matches!(
            p.b.receive(&pkt.encode(), "t", NOW, &mut p.rng).unwrap(),
            ReceiveOutcome::Message { .. }
        ));
    }
}

#[test]
fn at_most_two_sessions_per_device() {
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        None,
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        None,
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    let a_dev = a.device.public().id();
    let b_dev = b.device.public().id();
    let mut rng = StdRng::seed_from_u64(3);
    let mut ids = Vec::new();
    for i in 0..3u64 {
        // Alice forgets her sessions: she opens a new one.
        a.store
            .delete_sessions_for_device(b.fingerprint(), b_dev)
            .unwrap();
        let t = NOW + i * 10;
        let p = a.send_text(&b.fingerprint(), "x", t, &mut rng).unwrap();
        ids.push(a.store.sessions_for(b.fingerprint(), b_dev).unwrap()[0].session_id);
        assert!(matches!(
            b.receive(&p[0].encode(), "t", t, &mut rng).unwrap(),
            ReceiveOutcome::Message { .. }
        ));
    }
    let kept: Vec<[u8; 16]> = b
        .store
        .sessions_for(a.fingerprint(), a_dev)
        .unwrap()
        .iter()
        .map(|s| s.session_id)
        .collect();
    assert_eq!(kept.len(), 2);
    assert!(!kept.contains(&ids[0]), "the oldest is deleted");
    assert!(kept.contains(&ids[1]) && kept.contains(&ids[2]));
}

#[test]
fn seen_rows_are_purged_after_retention() {
    let mut p = pair();
    let old = PacketId([1; 16]);
    p.b.store.mark_seen(old, NOW).unwrap();
    let later = NOW + SEEN_RETENTION_SECS + 1;
    // Any packet for a watched mailbox triggers the purge.
    let me = p.b.device.public();
    let junk = Packet {
        kind: Kind::Message,
        hops: 1,
        tier: Tier::S,
        id: PacketId([2; 16]),
        expires_at: u32::MAX,
        mailbox: intro_mailbox(&me, day_of(later)),
        payload: vec![1, 2, 3],
    };
    reason(p.b.receive(&junk.encode(), "t", later, &mut p.rng).unwrap());
    assert!(!p.b.store.is_seen(old).unwrap());
}

#[test]
fn session_id_uses_inner_pqxdh_ek() {
    let (_da, mut a) = party("a", 1);
    let (_db, b) = party("b", 2);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        None,
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(5);
    let p = a.send_text(&b.fingerprint(), "x", NOW, &mut rng).unwrap();
    let row = best_session(&a);
    let init = de_init(row.pending_initial.as_deref().unwrap()).unwrap();
    assert_eq!(row.session_id, session_id(&init.ek));
    let Wire::Initial { ek: seal_ek, .. } = crate::envelope::parse_wire(&p[0].payload).unwrap()
    else {
        panic!("Initial expected");
    };
    assert_ne!(seal_ek, init.ek, "the sealing ephemeral is distinct");
}

#[test]
fn relay_rewritten_id_does_not_suppress_genuine_packet() {
    // A relay copies P2's identifier into P1's header.
    let mut p = pair();
    let p1 =
        p.a.send_text(&p.b.fingerprint(), "one", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let p2 =
        p.a.send_text(&p.b.fingerprint(), "two", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let mut evil = p1.clone();
    evil.id = p2.id;
    assert_eq!(
        reason(p.b.receive(&evil.encode(), "t", NOW, &mut p.rng).unwrap()),
        "inconsistent packet identifier"
    );
    // The authenticated identifier (P1's) is marked seen, not P2's.
    assert!(p.b.store.is_seen(p1.id).unwrap());
    assert!(!p.b.store.is_seen(p2.id).unwrap());
    match p.b.receive(&p2.encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { text, .. } => assert_eq!(text, "two"),
        other => panic!("Message expected, got {other:?}"),
    }
}

/// Mallory's card whose only device pairs HER signing key with a third
/// party's X25519 key `dh`. Certificate and card are valid: the proof
/// of possession covers only the signing key.
fn mixed_card(
    dh_of: &DevicePublic,
    bundle_of: Option<&PrekeyBundle>,
    rng: &mut StdRng,
) -> ContactCard {
    let (mroot, _) = RootIdentity::generate(rng);
    let mkeys = DeviceKeys::generate(rng);
    let device = DevicePublic {
        sig: mkeys.public().sig,
        dh: dh_of.dh,
    };
    let bytes = postcard::to_allocvec(&(mroot.public(), device, "tel", NOW)).unwrap();
    let cert = DeviceCertificate {
        root: mroot.public(),
        device,
        name: "tel".into(),
        issued_at: NOW,
        sig: mroot.sign(crate::crypto::labels::DEVICE_CERT, &bytes),
        device_sig: mkeys.sign(crate::crypto::labels::DEVICE_POSSESSION, &bytes),
    };
    cert.verify().unwrap();
    let list = DeviceList::sign(&mroot, 1, vec![cert]).unwrap();
    let bundles = bundle_of
        .map(|b| {
            let mut b = b.clone();
            b.device = device;
            b.sig = mkeys.sign(crate::crypto::labels::PREKEYS, &b.signed_bytes());
            b.verify().unwrap();
            vec![b]
        })
        .unwrap_or_default();
    let card = ContactCard::sign(&mroot, "Alice", list, bundles, Vec::new()).unwrap();
    card.verify().unwrap();
    card
}

#[test]
fn card_sharing_a_contacts_dh_key_rejected() {
    let mut p = pair();
    let alice_dev = p.a.device.public();
    let card = mixed_card(&alice_dev, None, &mut p.rng);
    assert_eq!(
        p.b.add_contact(&card, Some("mallory"), NOW, &mut p.rng),
        Err(CoreError::Malformed(
            "device already associated with another contact"
        ))
    );
    // Nor under Alice's alias (simulated key change).
    assert!(
        p.b.add_contact(&card, Some("alice"), NOW, &mut p.rng)
            .is_err()
    );
    assert_eq!(p.b.contacts().unwrap().len(), 1);
    // Nor my own key.
    let mine = mixed_card(&p.b.device.public(), None, &mut p.rng);
    assert!(
        p.b.add_contact(&mine, Some("moi"), NOW, &mut p.rng)
            .is_err()
    );
}

#[test]
fn ambiguous_sender_never_misattributed() {
    // Defense in depth: even if Mallory's card had been stored
    // (add verification bypassed), Alice's Initial is not attributed to Mallory.
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("zz-alice"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(31);
    let card = mixed_card(&a.device.public(), None, &mut rng);
    // Alias sorted first: the old code would have chosen it.
    b.store
        .upsert_contact(card.fingerprint(), &card.encode(), "aa-mallory", false)
        .unwrap();
    let p = a
        .send_text(&b.fingerprint(), "from Alice", NOW, &mut rng)
        .unwrap();
    assert_eq!(
        reason(b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap()),
        "ambiguous sender"
    );
    assert!(b.messages_with(&card.fingerprint()).unwrap().is_empty());
}

#[test]
fn session_to_mixed_device_fails_at_its_real_owner() {
    // Carol does not know Alice: she accepts Mallory's "mixed" card
    // (Alice's dh key). Her Initial arrives at Alice, who knows Carol. The
    // device identifiers bound to the associated data make
    // decryption fail: Alice does not take for herself a message meant for Mallory,
    // and cannot reply to it in a session that Carol would attribute to Mallory.
    let (_da, mut alice) = party("a", 1);
    let (_dc, mut carol) = party("c", 3);
    alice
        .add_contact(
            &carol.contact_card("Carol").unwrap(),
            Some("carol"),
            NOW,
            &mut StdRng::seed_from_u64(0),
        )
        .unwrap();
    let mut rng = StdRng::seed_from_u64(32);
    let alice_card = alice.contact_card("Alice").unwrap();
    let card = mixed_card(
        &alice.device.public(),
        Some(&alice_card.bundles[0]),
        &mut rng,
    );
    let mallory = carol
        .add_contact(&card, Some("mallory"), NOW, &mut rng)
        .unwrap();
    let p = carol
        .send_text(&mallory, "for Mallory", NOW, &mut rng)
        .unwrap();
    assert!(alice.watched_mailboxes(NOW).contains(&p[0].mailbox));
    assert_eq!(
        reason(alice.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap()),
        "decryption impossible"
    );
    assert!(
        alice
            .messages_with(&carol.fingerprint())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn remove_contact_deletes_contact_card_and_sessions_but_keeps_history() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    assert!(!p.a.store.all_sessions().unwrap().is_empty());
    assert!(!p.a.messages_with(&bob).unwrap().is_empty());
    p.a.remove_contact(&bob, NOW, &mut p.rng).unwrap();
    assert!(p.a.contacts().unwrap().is_empty());
    assert_eq!(p.a.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(p.a.store.get_contact(bob).unwrap().is_none());
    assert!(p.a.store.all_sessions().unwrap().is_empty());
    assert!(!p.a.messages_with(&bob).unwrap().is_empty());
    // Unknown: error, nothing is broken.
    assert_eq!(
        p.a.remove_contact(&bob, NOW, &mut p.rng),
        Err(CoreError::UnknownContact)
    );
    // It can be added back, then written to (new session).
    p.a.add_contact(
        &p.b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    let out = p.a.send_text(&bob, "retour", NOW, &mut p.rng).unwrap();
    assert!(matches!(
        p.b.receive(&out[0].encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
}

/// Ratchet state copies made by `decrypt` on this thread (per-thread counter,
/// hence insensitive to parallel tests).
fn clones() -> usize {
    crate::ratchet::STATE_CLONES.with(|c| c.get())
}

/// Same packet with the `Wire::Normal` payload modified by `f`.
fn tamper(p: &Packet, f: impl FnOnce(&mut crate::ratchet::RatchetMessage)) -> Packet {
    let Wire::Normal { mut msg } = postcard::from_bytes(&p.payload).unwrap() else {
        panic!("Wire::Normal expected");
    };
    f(&mut msg);
    let payload = postcard::to_allocvec(&Wire::Normal { msg }).unwrap();
    Packet {
        tier: Tier::fit(payload.len()).unwrap(),
        payload,
        ..p.clone()
    }
}

#[test]
fn junk_packet_never_clones_state() {
    use rand_core::Rng;
    let mut p = pair();
    let good = forge(&mut p.a, b"x", PacketId([9; 16]), &mut p.rng);
    for _ in 0..20 {
        let junk = tamper(&good, |m| {
            p.rng.fill_bytes(&mut m.enc_header);
            p.rng.fill_bytes(&mut m.ct);
        });
        let before = clones();
        let out = p.b.receive(&junk.encode(), "t", NOW, &mut p.rng).unwrap();
        assert!(matches!(
            out,
            ReceiveOutcome::Quarantined { .. } | ReceiveOutcome::NotForUs
        ));
        assert_eq!(
            clones(),
            before,
            "a booby-trapped packet does not copy the state"
        );
    }
    let before = clones();
    let next =
        p.a.send_text(&p.b.fingerprint(), "vrai", NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(
        p.b.receive(&next[0].encode(), "t", NOW, &mut p.rng)
            .unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    assert_eq!(clones(), before + 1);
}

#[test]
fn valid_header_bad_body_keeps_session() {
    let mut p = pair();
    let good =
        p.a.send_text(&p.b.fingerprint(), "vrai", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let bad = tamper(&good, |m| m.ct[0] ^= 1);
    let r = reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap());
    assert_eq!(r, "decryption impossible");
    match p.b.receive(&good.encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { text, .. } => assert_eq!(text, "vrai"),
        other => panic!("{other:?}"),
    }
}

/// Bob receives only Alice's 3rd message: 2 skipped keys, dated NOW.
fn bob_with_two_skipped() -> Pair {
    let mut p = pair();
    let mut pkts = Vec::new();
    for t in ["1", "2", "3"] {
        let v =
            p.a.send_text(&p.b.fingerprint(), t, NOW, &mut p.rng)
                .unwrap();
        pkts.push(v.into_iter().next().unwrap());
    }
    let out =
        p.b.receive(&pkts[2].encode(), "t", NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(out, ReceiveOutcome::Message { .. }));
    assert_eq!(skipped_total(&p.b), 2);
    p
}

fn skipped_total(c: &Core) -> usize {
    c.store
        .all_sessions()
        .unwrap()
        .iter()
        .filter_map(|s| de_state(&s.state).ok())
        .map(|st| st.skipped_len())
        .sum()
}

#[test]
fn idle_session_purges_skipped_keys() {
    let mut p = bob_with_two_skipped();
    // Negative control: at 6 days, the keys are still there.
    p.b.pending_outbox(NOW + 6 * 86_400).unwrap();
    assert_eq!(skipped_total(&p.b), 2);
    p.b.pending_outbox(NOW + 8 * 86_400).unwrap();
    assert_eq!(skipped_total(&p.b), 0);
}

#[test]
fn open_purges_skipped_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let key = [2u8; 32];
    let mut rng = StdRng::seed_from_u64(2);
    let (mut b, _) = Core::create(&path, &key, "b", NOW, &mut rng).unwrap();
    let (_da, mut a) = party("a", 1);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"), NOW, &mut rng)
        .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut rng,
    )
    .unwrap();
    let mut pkts = Vec::new();
    for t in ["1", "2", "3"] {
        let v = a.send_text(&b.fingerprint(), t, NOW, &mut rng).unwrap();
        pkts.push(v.into_iter().next().unwrap());
    }
    // Alice's Initial (1st message) establishes the session, then the 2nd is skipped.
    b.receive(&pkts[0].encode(), "t", NOW, &mut rng).unwrap();
    b.receive(&pkts[2].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(skipped_total(&b), 1);
    drop(b);
    let b = Core::open(&path, &key, NOW + 6 * 86_400).unwrap();
    assert_eq!(skipped_total(&b), 1);
    drop(b);
    let b = Core::open(&path, &key, NOW + 8 * 86_400).unwrap();
    assert_eq!(skipped_total(&b), 0);
}

#[test]
fn corrupt_session_row_does_not_block_pending_outbox() {
    let mut p = bob_with_two_skipped();
    // Second session row, unreadable.
    let mut bad = best_session(&p.b);
    bad.session_id = [0xee; 16];
    bad.state = vec![0xff; 7];
    p.b.store.put_session(&bad).unwrap();
    let later = NOW + 8 * 86_400;
    p.b.pending_outbox(later).unwrap();
    assert_eq!(skipped_total(&p.b), 0);
    // The unreadable row is intact and does not prevent reopening.
    assert!(
        p.b.store
            .all_sessions()
            .unwrap()
            .iter()
            .any(|s| s.state == vec![0xff; 7])
    );
}

#[test]
fn corrupt_session_row_does_not_block_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let key = [2u8; 32];
    let mut rng = StdRng::seed_from_u64(2);
    let (mut b, _) = Core::create(&path, &key, "b", NOW, &mut rng).unwrap();
    let (_da, mut a) = party("a", 1);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"), NOW, &mut rng)
        .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut rng,
    )
    .unwrap();
    let mut pkts = Vec::new();
    for t in ["1", "2", "3"] {
        let v = a.send_text(&b.fingerprint(), t, NOW, &mut rng).unwrap();
        pkts.push(v.into_iter().next().unwrap());
    }
    b.receive(&pkts[0].encode(), "t", NOW, &mut rng).unwrap();
    b.receive(&pkts[2].encode(), "t", NOW, &mut rng).unwrap();
    let mut bad = best_session(&b);
    bad.session_id = [0xee; 16];
    bad.state = vec![0xff; 7];
    b.store.put_session(&bad).unwrap();
    drop(b);
    let b = Core::open(&path, &key, NOW + 8 * 86_400).unwrap();
    assert_eq!(skipped_total(&b), 0);
}

/// Noise packet in the introduction mailbox of `to` on the day of `now`.
fn junk_to_intro(to: &Core, n: u32, now: u64) -> Vec<u8> {
    let mut id = [0u8; 16];
    id[..4].copy_from_slice(&n.to_be_bytes());
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId(id),
        expires_at: u32::MAX,
        mailbox: intro_mailbox(&to.device.public(), day_of(now)),
        payload: vec![0xa5; 40],
    }
    .encode()
}

fn count_events(c: &Core, f: impl Fn(&TransparencyEvent) -> bool) -> usize {
    c.transparency_log(100_000)
        .unwrap()
        .iter()
        .filter(|(_, e)| f(e))
        .count()
}

/// Bob with an established session and a changed contact key in the log.
fn bob_with_security_events() -> Pair {
    let mut p = pair();
    let (_dc, c) = party("c", 3);
    let (_dd, d) = party("d", 4);
    p.b.add_contact(
        &c.contact_card("Carol").unwrap(),
        Some("carol"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    p.b.add_contact(
        &d.contact_card("Dave").unwrap(),
        Some("carol"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    assert_eq!(
        count_events(&p.b, |e| matches!(
            e,
            TransparencyEvent::SessionEstablished { .. }
                | TransparencyEvent::ContactKeyChanged { .. }
        )),
        2
    );
    p
}

#[test]
fn junk_to_intro_mailbox_is_coalesced_and_keeps_security_events() {
    let mut p = bob_with_security_events();
    for i in 0..10_050u32 {
        let now = NOW + u64::from(i) / 100;
        let o =
            p.b.receive(&junk_to_intro(&p.b, i, now), "t", now, &mut p.rng)
                .unwrap();
        assert!(matches!(o, ReceiveOutcome::Quarantined { .. }), "{o:?}");
    }
    assert_eq!(
        count_events(&p.b, |e| matches!(
            e,
            TransparencyEvent::SessionEstablished { .. }
        )),
        1
    );
    assert_eq!(
        count_events(&p.b, |e| matches!(
            e,
            TransparencyEvent::ContactKeyChanged { .. }
        )),
        1
    );
    // 100 s of noise: at most one entry per minute.
    let failed = count_events(&p.b, |e| {
        matches!(e, TransparencyEvent::DecryptFailed { .. })
    });
    assert!((1..=2).contains(&failed), "{failed}");
}

#[test]
fn spaced_junk_fills_log_but_never_evicts_security_events() {
    let mut p = bob_with_security_events();
    // One minute between two packets: nothing is grouped, the cap applies.
    for i in 0..10_050u32 {
        let now = NOW + 60 * u64::from(i + 1);
        p.b.receive(&junk_to_intro(&p.b, i, now), "t", now, &mut p.rng)
            .unwrap();
    }
    let failed = count_events(&p.b, |e| {
        matches!(e, TransparencyEvent::DecryptFailed { .. })
    });
    assert_eq!(failed, crate::store::LOG_MAX_ROWS as usize);
    assert_eq!(
        count_events(&p.b, |e| matches!(
            e,
            TransparencyEvent::SessionEstablished { .. }
                | TransparencyEvent::ContactKeyChanged { .. }
        )),
        2
    );
}

#[test]
fn replayed_packets_and_acks_are_coalesced() {
    let mut p = pair();
    let m =
        p.a.send_text(&p.b.fingerprint(), "z", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let ack = match p.b.receive(&m.encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    assert!(matches!(
        p.a.receive(&ack.encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    let dup = |c: &Core| {
        count_events(c, |e| {
            matches!(e, TransparencyEvent::DuplicateIgnored { .. })
        })
    };
    for i in 0..500u64 {
        let now = NOW + i / 10;
        assert!(matches!(
            p.b.receive(&m.encode(), "t", now, &mut p.rng).unwrap(),
            ReceiveOutcome::Duplicate
        ));
        assert!(matches!(
            p.a.receive(&ack.encode(), "t", now, &mut p.rng).unwrap(),
            ReceiveOutcome::Duplicate
        ));
    }
    assert_eq!(dup(&p.b), 1);
    assert_eq!(dup(&p.a), 1);
    // After the interval, a new entry.
    let later = NOW + FRAME_REJECT_LOG_INTERVAL_SECS + 60;
    p.b.receive(&m.encode(), "t", later, &mut p.rng).unwrap();
    assert_eq!(dup(&p.b), 2);
}

#[test]
fn corrupt_session_row_does_not_abort_receive() {
    let mut p = pair();
    // Unreadable session row, same mailbox, tried first.
    let mut bad = best_session(&p.b);
    bad.session_id = [0xee; 16];
    bad.state = vec![0xff; 7];
    bad.last_rx = NOW + 1_000;
    p.b.store.put_session(&bad).unwrap();
    let m =
        p.a.send_text(&p.b.fingerprint(), "still here", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    assert!(matches!(
        p.b.receive(&m.encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
}

#[test]
fn corrupt_session_row_quarantines_resent_initial() {
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let p1 = a.send_text(&b.fingerprint(), "1", NOW, &mut rng).unwrap();
    let p2 = a.send_text(&b.fingerprint(), "2", NOW, &mut rng).unwrap();
    b.receive(&p1[0].encode(), "t", NOW, &mut rng).unwrap();
    // The session opened by the first Initial becomes unreadable.
    let mut row = best_session(&b);
    row.state = vec![0xff; 7];
    b.store.put_session(&row).unwrap();
    assert!(matches!(
        b.receive(&p2[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Quarantined { .. }
    ));
}

// --- Batch 1B, task 3: message identifier, sessions between my devices.

/// A (admin) and T, linked to A.
fn linked() -> (TempDir, Core, Core, StdRng) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(77);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t.finish_link(&out.bundle, None, NOW).unwrap();
    (dir, a, t, rng)
}

/// Seals `body` for `target` from `from`, in one transaction.
fn seal_body(
    from: &mut Core,
    target: &send::Target,
    body: &Body,
    message_id: MessageId,
    rng: &mut StdRng,
) -> Vec<(Packet, DeviceId)> {
    let Core { store, device, .. } = from;
    store
        .transaction(|tx| {
            send::seal_for(
                tx,
                device,
                target,
                body,
                message_id,
                send::SealTime::at(NOW),
                rng,
            )
        })
        .unwrap()
}

#[test]
fn own_devices_open_sessions() {
    let (_d, mut a, mut t, mut rng) = linked();
    let me = a.fingerprint();
    let body = Body::Text("interne".into());
    // A → T: a session opened with my other device, filed under my fingerprint.
    let out = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &body,
        MessageId([1; 16]),
        &mut rng,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1, t.device.public().id());
    let sessions = a.store.all_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].contact_fp, me);
    // T opens it and recognizes the sender (me): a text coming from me is
    // unexpected, but it was indeed authenticated and attributed.
    assert!(t.watched_mailboxes(NOW).contains(&out[0].0.mailbox));
    let r = t.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(r), "unexpected content for this mailbox");
    // T → A, in the other direction.
    let back = seal_body(
        &mut t,
        &send::Target::OwnDevices,
        &body,
        MessageId([2; 16]),
        &mut rng,
    );
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].1, a.device.public().id());
    let r = a.receive(&back[0].0.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(r), "unexpected content for this mailbox");
    assert!(t.messages_with(&me).unwrap().is_empty());
    assert!(a.messages_with(&me).unwrap().is_empty());
}

#[test]
fn contact_claiming_own_device_refused() {
    let (_d, mut a, mut t, mut rng) = linked();
    let t_dev = t.device.public();
    let a_dev = a.device.public();
    // Read from the database: true on A as on T.
    assert!(contacts::claimed_by_other(&a.store, None, &[t_dev]).unwrap());
    assert!(contacts::claimed_by_other(&t.store, None, &[a_dev]).unwrap());
    let card = mixed_card(&t_dev, None, &mut rng);
    assert!(a.add_contact(&card, Some("faux"), NOW, &mut rng).is_err());
    let card = mixed_card(&a_dev, None, &mut rng);
    assert!(t.add_contact(&card, Some("faux"), NOW, &mut rng).is_err());
    assert!(a.contacts().unwrap().is_empty());
    assert!(t.contacts().unwrap().is_empty());
}

#[test]
fn message_id_dedups_resend() {
    let mut p = pair();
    let b_fp = p.b.fingerprint();
    let a_fp = p.a.fingerprint();
    p.a.send_text(&b_fp, "once", NOW, &mut p.rng).unwrap();
    // A's last message to B: resent, same identifier, new packet.
    let first =
        p.a.send_text(&b_fp, "unique", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    assert!(matches!(
        p.b.receive(&first.encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    let mid = p.a.messages_with(&b_fp).unwrap().last().unwrap().message_id;
    let before = p.b.messages_with(&a_fp).unwrap().len();
    let again = seal_body(
        &mut p.a,
        &send::Target::Contact(b_fp),
        &Body::Text("unique".into()),
        mid,
        &mut p.rng,
    )
    .remove(0)
    .0;
    assert_ne!(again.id, first.id);
    assert!(matches!(
        p.b.receive(&again.encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Duplicate
    ));
    assert_eq!(p.b.messages_with(&a_fp).unwrap().len(), before);
    // The duplicate is still acked: the sender stops resending it.
    let acks: Vec<Packet> =
        p.b.pending_outbox(NOW)
            .unwrap()
            .iter()
            .map(|b| Packet::decode(b).unwrap())
            .filter(|q| q.kind == Kind::Ack && q.payload[..16] == again.id.0)
            .collect();
    assert_eq!(acks.len(), 1);
}

#[test]
fn message_ids_scoped_to_sender() {
    // A contact freely chooses the identifier of its messages: it can
    // neither erase nor overwrite a message of another contact, nor one of mine.
    let mut p = pair();
    let (_dc, mut c) = party("c", 3);
    let b_fp = p.b.fingerprint();
    let a_fp = p.a.fingerprint();
    p.b.add_contact(
        &c.contact_card("Carol").unwrap(),
        Some("carol"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    c.add_contact(
        &p.b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    // Identifier of a message received by Bob (from Alice), and of a message from Bob.
    let from_a = p.b.messages_with(&a_fp).unwrap();
    let in_id = from_a
        .iter()
        .find(|m| m.direction == Direction::In)
        .unwrap();
    let out_id = from_a
        .iter()
        .find(|m| m.direction == Direction::Out)
        .unwrap();
    let a_mid = p.a.messages_with(&b_fp).unwrap()[0].message_id;
    for (i, mid) in [a_mid, in_id.message_id, out_id.message_id]
        .into_iter()
        .enumerate()
    {
        let pk = seal_body(
            &mut c,
            &send::Target::Contact(b_fp),
            &Body::Text(format!("carol {i}")),
            mid,
            &mut p.rng,
        )
        .remove(0)
        .0;
        assert!(matches!(
            p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap(),
            ReceiveOutcome::Message { .. }
        ));
    }
    assert_eq!(p.b.messages_with(&a_fp).unwrap(), from_a);
    assert_eq!(p.b.messages_with(&c.fingerprint()).unwrap().len(), 3);
}

/// Quarantine reason of a synchronization coming from somewhere other than my devices.
const NOT_MINE: &str = "synchronization from a device that is not mine";

#[test]
fn sync_from_contact_quarantined() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let card = p.b.contact_card("Bob").unwrap();
    let bodies = [
        Body::SyncSent {
            to: b_fp,
            text: "faux".into(),
        },
        Body::SyncContact(SyncOp::Remove(b_fp)),
        Body::SyncContact(SyncOp::Upsert {
            card: Box::new(card.clone()),
            alias: "x".into(),
            verified: true,
        }),
        Body::SyncDevices {
            card: Box::new(card),
        },
    ];
    let before = p.a.messages_with(&b_fp).unwrap().len();
    for (i, body) in bodies.iter().enumerate() {
        let id = MessageId([i as u8 + 1; 16]);
        let out = seal_body(&mut p.b, &send::Target::Contact(a_fp), body, id, &mut p.rng);
        let r =
            p.a.receive(&out[0].0.encode(), "t", NOW, &mut p.rng)
                .unwrap();
        assert_eq!(reason(r), NOT_MINE, "case {i}");
    }
    assert_eq!(p.a.messages_with(&b_fp).unwrap().len(), before);
    let c = p.a.contacts().unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].fingerprint, c[0].alias.as_deref(), c[0].verified),
        (b_fp, Some("bob"), false)
    );
}

/// A linked to T1 then to T2; T1 only knows the list from its link.
fn linked_twice() -> (TempDir, Core, Core, Core, StdRng) {
    let (dir, mut a, t1, mut rng) = linked();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t2, req) = Core::begin_link(
        &dir.path().join("t2"),
        &[3; 32],
        &offer,
        "t2",
        NOW,
        &mut rng,
    )
    .unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t2.finish_link(&out.bundle, None, NOW).unwrap();
    (dir, a, t1, t2, rng)
}

/// `SyncDevices` sealed by A for `to` (one of its other devices).
fn devices_packet(a: &mut Core, to: &Core, card: ContactCard, id: u8, rng: &mut StdRng) -> Packet {
    let body = Body::SyncDevices {
        card: Box::new(card),
    };
    let to_id = to.device.public().id();
    seal_body(
        a,
        &send::Target::OwnDevices,
        &body,
        MessageId([id; 16]),
        rng,
    )
    .into_iter()
    .find(|(_, d)| *d == to_id)
    .unwrap()
    .0
}

/// Card of `root` for `list`, with the key packets (among `all`) of the
/// devices in the list, except `skip`.
fn card_for(
    root: &RootIdentity,
    list: DeviceList,
    all: &[PrekeyBundle],
    skip: Option<&DevicePublic>,
) -> ContactCard {
    let bundles = all
        .iter()
        .filter(|b| list.certs.iter().any(|c| c.device == b.device))
        .filter(|b| Some(&b.device) != skip)
        .cloned()
        .collect();
    ContactCard::sign(root, "", list, bundles, Vec::new()).unwrap()
}

/// Key packets of all of A's devices.
fn all_bundles(a: &Core) -> Vec<PrekeyBundle> {
    let mut all = vec![a.prekeys.bundle(&a.device, false)];
    all.extend(a.linked_bundles.iter().cloned());
    all
}

#[test]
fn sync_devices_requires_newer_signed_list() {
    let (_d, mut a, mut t1, mut t2, mut rng) = linked_twice();
    let me = a.fingerprint();
    let t1_before = t1.devices.clone();
    let stored = |c: &Core| {
        c.store
            .get_meta::<DeviceList>(META_DEVICE_LIST)
            .unwrap()
            .unwrap()
    };
    assert_eq!(stored(&t1), t1_before);
    assert_eq!(t1_before.certs.len(), 2);
    let all = all_bundles(&a);
    let root = a.root.take().unwrap();
    let t1_dev = t1.device.public();
    let certs = a.devices.certs.clone();
    let v = a.devices.version;
    let mut cases = Vec::new();
    // Version equal to T1's, signed by my root.
    let same = DeviceList::sign(&root, t1_before.version, certs.clone()).unwrap();
    cases.push(card_for(&root, same, &all, None));
    // Higher version that does not contain T1.
    let without: Vec<_> = certs
        .iter()
        .filter(|c| c.device != t1_dev)
        .cloned()
        .collect();
    let list = DeviceList::sign(&root, v + 1, without).unwrap();
    cases.push(card_for(&root, list, &all, None));
    // Invalid list signature (rewritten version).
    let mut forged = a.devices.clone();
    forged.version += 10;
    cases.push(card_for(&root, forged, &all, None));
    // Card of another root.
    let (other, _) = RootIdentity::generate(&mut rng);
    let oc = DeviceCertificate::issue(&other, &t1.device, "t1", NOW).unwrap();
    let ol = DeviceList::sign(&other, v + 5, vec![oc]).unwrap();
    cases.push(card_for(&other, ol, &all, None));
    // Valid and newer list, but no key packet for T1.
    let list = DeviceList::sign(&root, v + 1, certs.clone()).unwrap();
    cases.push(card_for(&root, list, &all, Some(&t1_dev)));
    a.root = Some(root);
    for (i, card) in cases.into_iter().enumerate() {
        let pkt = devices_packet(&mut a, &t1, card, 10 + i as u8, &mut rng);
        let r = t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap();
        assert_eq!(reason(r), "device list refused", "case {i}");
        assert_eq!(t1.devices, t1_before, "case {i}");
        assert_eq!(stored(&t1), t1_before, "case {i}");
    }

    // The real card, newer: applied, T1 can reach T2.
    let card = a.contact_card("").unwrap();
    let pkt = devices_packet(&mut a, &t1, card, 30, &mut rng);
    match t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap() {
        ReceiveOutcome::Synced { kind } => assert_eq!(kind, SyncKind::Devices),
        other => panic!("Synced expected, got {other:?}"),
    }
    assert_eq!(t1.devices, a.devices);
    assert_eq!(stored(&t1), a.devices);
    // The key packets of my other devices come from the card, without mine.
    assert_eq!(t1.linked_bundles.len(), 2);
    assert!(t1.linked_bundles.iter().all(|b| b.device != t1_dev));
    let out = seal_body(
        &mut t1,
        &send::Target::OwnDevices,
        &Body::Text("x".into()),
        MessageId([40; 16]),
        &mut rng,
    );
    assert_eq!(out.len(), 2);
    let t2_id = t2.device.public().id();
    assert!(out.iter().any(|(_, d)| *d == t2_id));
    assert!(!t1.store.sessions_for(me, t2_id).unwrap().is_empty());

    // A newer card that removes T2: T1's sessions with T2 disappear.
    let shrunk = {
        let root = a.root.as_ref().unwrap();
        let certs = a
            .devices
            .certs
            .iter()
            .filter(|c| c.device != t2.device.public())
            .cloned()
            .collect();
        let list = DeviceList::sign(root, a.devices.version + 1, certs).unwrap();
        card_for(root, list, &all, None)
    };
    let pkt = devices_packet(&mut a, &t1, shrunk.clone(), 50, &mut rng);
    assert!(matches!(
        t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced { .. }
    ));
    assert_eq!(t1.devices, shrunk.devices);
    assert!(t1.store.sessions_for(me, t2_id).unwrap().is_empty());
    assert!(
        !t1.store
            .sessions_for(me, a.device.public().id())
            .unwrap()
            .is_empty()
    );

    // T2, removed, still sends a synchronization to T1: refused.
    let op = Body::SyncContact(SyncOp::Remove(Fingerprint([9; 32])));
    let out = seal_body(
        &mut t2,
        &send::Target::OwnDevices,
        &op,
        MessageId([60; 16]),
        &mut rng,
    );
    let t1_id = t1.device.public().id();
    let to_t1 = &out.iter().find(|(_, d)| *d == t1_id).unwrap().0;
    let r = t1.receive(&to_t1.encode(), "t", NOW, &mut rng).unwrap();
    assert!(
        matches!(
            r,
            ReceiveOutcome::NotForUs | ReceiveOutcome::Quarantined { .. }
        ),
        "{r:?}"
    );
    assert!(
        t1.store
            .contact_clock(Fingerprint([9; 32]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn older_valid_sync_devices_is_acked_duplicate() {
    // T1 applied list v3 (T2 linked); v2 (the one from its link),
    // authentic and containing it, arrives late: duplicate acked,
    // no quarantine, nothing changed.
    let (dir, mut a, mut t1, mut rng) = linked();
    let v2 = a
        .store
        .get_meta::<ContactCard>(link::META_OWN_CARD)
        .unwrap()
        .unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (_t2, req) = Core::begin_link(
        &dir.path().join("t2"),
        &[3; 32],
        &offer,
        "t2",
        NOW,
        &mut rng,
    )
    .unwrap();
    a.link_device(&req, false, NOW, &mut rng).unwrap();
    let v3 = a.contact_card("").unwrap();
    let pkt = devices_packet(&mut a, &t1, v3, 1, &mut rng);
    assert!(matches!(
        t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced {
            kind: SyncKind::Devices
        }
    ));
    let current = t1.devices.clone();
    let acks_before = t1.pending_outbox(NOW).unwrap().len();
    let late = devices_packet(&mut a, &t1, v2, 2, &mut rng);
    let r = t1.receive(&late.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
    assert_eq!(t1.devices, current);
    // Ack emitted for this packet: A stops resending the old list.
    let acks = t1.pending_outbox(NOW).unwrap();
    assert_eq!(acks.len(), acks_before + 1);
    assert!(acks.iter().any(|b| {
        let p = Packet::decode(b).unwrap();
        p.kind == Kind::Ack && p.payload[..16] == late.id.0
    }));
}

#[test]
fn sync_from_removed_device_with_session_refused() {
    // Session T1 ↔ T2 established, then T2 removed from T1's list without
    // the session being purged (state from before the purge): the synchronization
    // is still refused, because T2 is no longer in my list.
    let (_d, mut a, mut t1, mut t2, mut rng) = linked_twice();
    let card = a.contact_card("").unwrap();
    let pkt = devices_packet(&mut a, &t1, card, 1, &mut rng);
    t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap();
    let t1_id = t1.device.public().id();
    let op = |fp: u8| Body::SyncContact(SyncOp::Remove(Fingerprint([fp; 32])));
    let out = seal_body(
        &mut t2,
        &send::Target::OwnDevices,
        &op(1),
        MessageId([2; 16]),
        &mut rng,
    );
    let p = &out.iter().find(|(_, d)| *d == t1_id).unwrap().0;
    assert!(matches!(
        t1.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced { .. }
    ));
    // T1's reply: T2's session no longer awaits an Initial.
    let t2_id = t2.device.public().id();
    let back = seal_body(
        &mut t1,
        &send::Target::OwnDevices,
        &op(5),
        MessageId([6; 16]),
        &mut rng,
    );
    let p = &back.iter().find(|(_, d)| *d == t2_id).unwrap().0;
    assert!(matches!(
        t2.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced { .. }
    ));
    // List rewritten in the database without T2 (sessions kept).
    let root = a.root.as_ref().unwrap();
    let certs = a
        .devices
        .certs
        .iter()
        .filter(|c| c.device != t2.device.public())
        .cloned()
        .collect();
    let list = DeviceList::sign(root, a.devices.version + 1, certs).unwrap();
    t1.store.put_meta(META_DEVICE_LIST, &list).unwrap();
    let out = seal_body(
        &mut t2,
        &send::Target::OwnDevices,
        &op(3),
        MessageId([4; 16]),
        &mut rng,
    );
    let p = &out.iter().find(|(_, d)| *d == t1_id).unwrap().0;
    assert_eq!(
        reason(t1.receive(&p.encode(), "t", NOW, &mut rng).unwrap()),
        NOT_MINE
    );
    assert!(
        t1.store
            .contact_clock(Fingerprint([3; 32]))
            .unwrap()
            .is_none()
    );
}

/// Card of `n` devices with maximum-size names and maximum node hints.
fn max_card(n: usize, rng: &mut StdRng) -> ContactCard {
    let (root, _) = RootIdentity::generate(rng);
    let mut certs = Vec::new();
    let mut bundles = Vec::new();
    for i in 0..n {
        let d = DeviceKeys::generate(rng);
        let name = format!("{i:0>64}");
        certs.push(DeviceCertificate::issue(&root, &d, &name, u64::MAX).unwrap());
        bundles.push(crate::handshake::PrekeySecrets::generate(rng, 0).bundle(&d, false));
    }
    let list = DeviceList::sign(&root, u64::MAX, certs).unwrap();
    let nodes =
        vec![vec![0xab; crate::contact::MAX_NODE_HINT_BYTES]; crate::contact::MAX_CARD_NODES];
    ContactCard::sign(&root, &"x".repeat(64), list, bundles, nodes).unwrap()
}

/// Heaviest contents that carry a card. A contact's card
/// update (`CardUpdate`) has the size of `SyncDevices`: a
/// label and the card.
fn card_bodies(card: &ContactCard) -> [Body; 3] {
    [
        Body::SyncContact(SyncOp::Upsert {
            card: Box::new(card.clone()),
            alias: "a".repeat(crate::core::contacts::MAX_ALIAS_LEN),
            verified: true,
        }),
        Body::SyncDevices {
            card: Box::new(card.clone()),
        },
        Body::CardUpdate(Box::new(card.clone())),
    ]
}

#[test]
fn device_cap_fits_one_packet() {
    use crate::identity::device_list::MAX_DEVICES;
    let mut rng = StdRng::seed_from_u64(5);
    let card = max_card(MAX_DEVICES, &mut rng);
    for body in card_bodies(&card) {
        assert!(crate::envelope::fits_in_packet(&body), "{body:?}");
    }
    // One more device would not fit: the list is refused at signing.
    let mut bigger = card.clone();
    let extra = max_card(1, &mut rng);
    bigger.devices.certs.push(extra.devices.certs[0].clone());
    bigger.bundles.push(extra.bundles[0].clone());
    for body in card_bodies(&bigger) {
        assert!(!crate::envelope::fits_in_packet(&body), "{body:?}");
    }
    let (root, _) = RootIdentity::generate(&mut rng);
    let certs = (0..=MAX_DEVICES)
        .map(|_| {
            DeviceCertificate::issue(&root, &DeviceKeys::generate(&mut rng), "d", NOW).unwrap()
        })
        .collect();
    assert_eq!(
        DeviceList::sign(&root, 1, certs).err(),
        Some(CoreError::TooLarge)
    );
}

#[test]
fn wire_overhead_bound_holds() {
    // Session opening (Wire::Initial, the heaviest) with the largest card.
    let (_d, mut a, _t, mut rng) = linked();
    let card = max_card(crate::identity::device_list::MAX_DEVICES, &mut rng);
    for body in card_bodies(&card) {
        let out = seal_body(
            &mut a,
            &send::Target::OwnDevices,
            &body,
            MessageId([1; 16]),
            &mut rng,
        );
        let env = Envelope {
            sent_at: NOW,
            ack_secret: [0; 16],
            message_id: [1; 16],
            body,
        };
        let env_len = postcard::to_allocvec(&env).unwrap().len();
        let packet = &out[0].0;
        assert!(matches!(
            parse_wire(&packet.payload).unwrap(),
            Wire::Initial { .. }
        ));
        assert!(
            packet.payload.len() <= env_len + crate::envelope::MAX_WIRE_OVERHEAD,
            "{} > {} + {}",
            packet.payload.len(),
            env_len,
            crate::envelope::MAX_WIRE_OVERHEAD
        );
        // Session opened: a new one is made for the next content.
        for s in a.store.all_sessions().unwrap() {
            a.store
                .delete_session(s.contact_fp, s.contact_device, &s.session_id)
                .unwrap();
        }
    }
}

#[test]
fn oversized_sync_is_skipped_not_fatal() {
    let (_d, mut a, _t, mut rng) = linked();
    let before = a.pending_outbox(NOW).unwrap().len();
    // Card that does not fit in a packet (not signable as is:
    // forged for the size computation only).
    let mut big = max_card(crate::identity::device_list::MAX_DEVICES, &mut rng);
    let extra = max_card(1, &mut rng);
    big.devices.certs.push(extra.devices.certs[0].clone());
    big.bundles.push(extra.bundles[0].clone());
    let op = SyncOp::Upsert {
        card: Box::new(big),
        alias: String::new(),
        verified: false,
    };
    let sessions = a.store.all_sessions().unwrap().len();
    let Core { store, device, .. } = &mut a;
    store
        .transaction(|tx| sync::send_op(tx, device, op, send::SealTime::at(NOW), &mut rng))
        .unwrap();
    // Nothing sealed, no session opened, the event is logged.
    assert_eq!(a.pending_outbox(NOW).unwrap().len(), before);
    assert_eq!(a.store.all_sessions().unwrap().len(), sessions);
    let events: Vec<_> = a
        .transparency_log(100)
        .unwrap()
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    assert!(events.contains(&TransparencyEvent::SyncSkipped {
        kind: SyncKind::Contact
    }));
    assert!(!events.iter().any(|e| matches!(
        e,
        TransparencyEvent::SessionEstablished { .. } | TransparencyEvent::PacketSealed { .. }
    )));
}

// --- Batch 1B, task 5: new card sent to contacts.

/// Alice (A, admin, linked to T) and Bob, contacts of each other. Bob
/// applied Alice's card update (A and T). Also returns Alice's card
/// from before the link.
fn alice_tablet_bob() -> (TempDir, Core, Core, Core, ContactCard, StdRng) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(78);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let (mut b, _) = Core::create(&dir.path().join("b"), &[4; 32], "b", NOW, &mut rng).unwrap();
    let v1 = a.contact_card("Alice").unwrap();
    b.add_contact(&v1, Some("alice"), NOW, &mut rng).unwrap();
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"), NOW, &mut rng)
        .unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t.finish_link(&out.bundle, None, NOW).unwrap();
    assert_eq!(out.packets.len(), 1);
    assert!(matches!(
        b.receive(&out.packets[0].encode(), "t", NOW, &mut rng)
            .unwrap(),
        ReceiveOutcome::CardUpdated { .. }
    ));
    (dir, a, t, b, v1, rng)
}

fn stored_card(c: &Core, fp: Fingerprint) -> ContactCard {
    load_card(&c.store.get_contact(fp).unwrap().unwrap().card).unwrap()
}

fn card_update(from: &mut Core, to: Fingerprint, card: ContactCard, rng: &mut StdRng) -> Packet {
    let body = Body::CardUpdate(Box::new(card));
    let mut id = [0u8; 16];
    rand::Rng::fill_bytes(rng, &mut id);
    seal_body(from, &send::Target::Contact(to), &body, MessageId(id), rng)
        .remove(0)
        .0
}

#[test]
fn trapped_card_does_not_block_receive() {
    // Bob signs a card that adds a device whose signed prekey is
    // low-order ([0; 32]). Alice, linked (stored card), would send him her
    // card: sealing fails for this device, which is skipped.
    let (_dir, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let bob_root = b.root.take().unwrap();
    let trap = DeviceKeys::generate(&mut rng);
    let mut bundle = PrekeySecrets::generate(&mut rng, 0).bundle(&trap, false);
    bundle.spk = [0; 32];
    bundle.sig = trap.sign(crate::crypto::labels::PREKEYS, &bundle.signed_bytes());
    let mut certs = b.devices.certs.clone();
    certs.push(DeviceCertificate::issue(&bob_root, &trap, "trap", NOW).unwrap());
    let list = DeviceList::sign(&bob_root, b.devices.version + 1, certs).unwrap();
    let bundles = vec![b.prekeys.bundle(&b.device, false), bundle];
    let card = ContactCard::sign(&bob_root, "Bob", list, bundles, Vec::new()).unwrap();
    b.root = Some(bob_root);
    let a_id = a.device.public().id();
    let body = Body::CardUpdate(Box::new(card));
    let p = seal_body(
        &mut b,
        &send::Target::Contact(alice),
        &body,
        MessageId([90; 16]),
        &mut rng,
    )
    .into_iter()
    .find(|(_, d)| *d == a_id)
    .unwrap()
    .0;
    let r = a.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::CardUpdated { .. }), "{r:?}");
    assert_eq!(stored_card(&a, bob).devices.certs.len(), 2);
    assert!(a.store.is_seen(p.id).unwrap());
    let again = a.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(again, ReceiveOutcome::Duplicate), "{again:?}");
    // Alice writes to Bob again: his valid device receives (the
    // booby-trapped device is skipped), plus the copy for T.
    let pkts = a.send_text(&bob, "still here", NOW, &mut rng).unwrap();
    assert_eq!(pkts.len(), 2);
    let opened = pkts
        .iter()
        .filter(|p| {
            matches!(
                b.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { ref text, .. } if text == "still here"
            )
        })
        .count();
    assert_eq!(opened, 1);
}

#[test]
fn card_update_wrong_root_or_older_ignored() {
    let (dir, mut a, _t, mut b, v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let current = stored_card(&b, alice);
    assert_eq!(current.devices.certs.len(), 2);
    // Other root: quarantine, card unchanged.
    let (c, _) = Core::create(&dir.path().join("c"), &[5; 32], "c", NOW, &mut rng).unwrap();
    let p = card_update(&mut a, bob, c.contact_card("Carol").unwrap(), &mut rng);
    assert_eq!(
        reason(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap()),
        "card update refused"
    );
    assert_eq!(stored_card(&b, alice), current);
    // Lower version, or the same card: superseded, duplicate acked
    // (the sender stops resending it), card unchanged.
    for (card, why) in [(v1, "lower version"), (current.clone(), "same card")] {
        let acks = b.pending_outbox(NOW).unwrap().len();
        let p = card_update(&mut a, bob, card, &mut rng);
        assert!(
            matches!(
                b.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
                ReceiveOutcome::Duplicate
            ),
            "{why}"
        );
        assert_eq!(b.pending_outbox(NOW).unwrap().len(), acks + 1, "{why}");
        assert_eq!(stored_card(&b, alice), current, "{why}");
    }
}

#[test]
fn card_update_refusals() {
    let (dir, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    // Carol, another contact of Bob.
    let (carol, _) = Core::create(&dir.path().join("c"), &[5; 32], "c", NOW, &mut rng).unwrap();
    let carol_card = carol.contact_card("Carol").unwrap();
    b.add_contact(&carol_card, Some("carol"), NOW, &mut rng)
        .unwrap();
    let current = stored_card(&b, alice);
    let root = RootIdentity::from_seed(&Zeroizing::new(
        a.store.get_meta::<[u8; 32]>(META_ROOT).unwrap().unwrap(),
    ));
    // Alice's newer list, with the extra device `extra`.
    let claiming = |extra: &DeviceKeys| {
        let mut certs = current.devices.certs.clone();
        certs.push(DeviceCertificate::issue(&root, extra, "vol", NOW).unwrap());
        let list = DeviceList::sign(&root, current.devices.version + 1, certs).unwrap();
        ContactCard::sign(&root, "Alice", list, current.bundles.clone(), Vec::new()).unwrap()
    };
    let cases = [
        (carol_card.clone(), "card of another contact"),
        (claiming(&b.device), "one of my devices"),
        (claiming(&carol.device), "a device of another contact"),
    ];
    for (card, why) in cases {
        let p = card_update(&mut a, bob, card, &mut rng);
        assert_eq!(
            reason(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap()),
            "card update refused",
            "{why}"
        );
        assert_eq!(stored_card(&b, alice), current, "{why}");
        assert_eq!(stored_card(&b, carol.fingerprint()), carol_card, "{why}");
    }
}

#[test]
fn card_update_removing_sender_device() {
    let (_d, a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let t_id = t.device.public().id();
    // Alice's new list without T, sent by T itself.
    let root = a.root.as_ref().unwrap();
    let certs: Vec<_> = a
        .devices
        .certs
        .iter()
        .filter(|c| c.device.id() != t_id)
        .cloned()
        .collect();
    let list = DeviceList::sign(root, a.devices.version + 1, certs).unwrap();
    let card = ContactCard::sign(
        root,
        "Alice",
        list,
        vec![a.prekeys.bundle(&a.device, false)],
        Vec::new(),
    )
    .unwrap();
    let p = card_update(&mut t, bob, card.clone(), &mut rng);
    assert!(matches!(
        b.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::CardUpdated { .. }
    ));
    assert_eq!(stored_card(&b, alice), card);
    assert!(b.store.sessions_for(alice, t_id).unwrap().is_empty());
    assert!(
        count_events(&b, |e| *e
            == TransparencyEvent::ContactCardUpdated {
                contact: alice,
                alias: "alice".into(),
                added: 0,
                removed: 1
            })
            == 1
    );
    // Bob now writes only to A.
    assert_eq!(b.send_text(&alice, "x", NOW, &mut rng).unwrap().len(), 1);
}

#[test]
fn card_update_from_own_device_quarantined() {
    let (_d, mut a, mut t, _b, _v1, mut rng) = alice_tablet_bob();
    let card = a.contact_card("Alice").unwrap();
    let body = Body::CardUpdate(Box::new(card));
    let out = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &body,
        MessageId([7; 16]),
        &mut rng,
    );
    let r = t.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(r), "unexpected content for this mailbox");
}

#[test]
fn display_name_stored_and_used_for_link() {
    let (_d, mut a, _t, _b, _v1, _rng) = alice_tablet_bob();
    // `contact_card` recorded it; the link's card carries it.
    assert_eq!(
        a.store.get_meta::<String>(META_DISPLAY_NAME).unwrap(),
        Some("Alice".to_owned())
    );
    assert_eq!(
        a.store
            .get_meta::<ContactCard>(link::META_OWN_CARD)
            .unwrap()
            .unwrap()
            .display_name,
        "Alice"
    );
    a.set_display_name("Alicia").unwrap();
    assert_eq!(
        a.store.get_meta::<String>(META_DISPLAY_NAME).unwrap(),
        Some("Alicia".to_owned())
    );
    assert_eq!(
        a.set_display_name(&"x".repeat(65)),
        Err(CoreError::TooLarge)
    );
}

#[test]
fn card_update_same_version_divergent_list_refused() {
    let (_d, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let current = stored_card(&b, alice);
    // Another list signed by Alice's root, at the same version.
    let root = a.root.as_ref().unwrap();
    let a_id = a.device.public().id();
    let certs: Vec<_> = current
        .devices
        .certs
        .iter()
        .filter(|c| c.device.id() == a_id)
        .cloned()
        .collect();
    let list = DeviceList::sign(root, current.devices.version, certs).unwrap();
    let bundles = vec![a.prekeys.bundle(&a.device, false)];
    let divergent = ContactCard::sign(root, "Alice", list, bundles, Vec::new()).unwrap();
    // Superseded but invalid card (altered signature): refused too.
    let mut forged = current.clone();
    forged.sig[0] ^= 1;
    for (card, why) in [(divergent, "divergent list"), (forged, "signature")] {
        let p = card_update(&mut a, bob, card, &mut rng);
        assert_eq!(
            reason(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap()),
            "card update refused",
            "{why}"
        );
        assert_eq!(stored_card(&b, alice), current, "{why}");
    }
}

#[test]
fn sync_sent_matching_imported_history_message_not_duplicated() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let bob_fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let packets = a.send_text(&bob_fp, "hello", NOW + 1, &mut rng).unwrap();
    let sent = a.messages_with(&bob_fp).unwrap();
    assert_eq!(sent.len(), 1);
    // T already has this message (imported with the history), same identifier.
    let inserted = t
        .store
        .insert_message(
            bob_fp,
            Direction::Out,
            "hello",
            MessageStatus::Sent,
            NOW + 1,
            sent[0].message_id,
        )
        .unwrap();
    assert!(inserted);
    let mut synced = 0;
    for p in &packets {
        if let ReceiveOutcome::Synced { .. } =
            t.receive(&p.encode(), "t", NOW + 2, &mut rng).unwrap()
        {
            synced += 1;
        }
    }
    assert_eq!(synced, 1);
    assert_eq!(t.messages_with(&bob_fp).unwrap().len(), 1);
}

#[test]
fn log_transport_event_accepts_only_node_events() {
    let mut p = pair();
    let dep = TransparencyEvent::NodeDeposit {
        node: "ABCDEFGH".into(),
        count: 1,
        refused: 0,
    };
    let fetch = TransparencyEvent::NodeFetch {
        node: "ABCDEFGH".into(),
        mailboxes: 2,
        received: 1,
    };
    p.a.log_transport_event(dep.clone(), NOW).unwrap();
    p.a.log_transport_event(fetch.clone(), NOW).unwrap();
    let log = p.a.transparency_log(10).unwrap();
    assert!(log.iter().any(|(_, e)| *e == dep));
    assert!(log.iter().any(|(_, e)| *e == fetch));
    assert_eq!(
        p.a.log_transport_event(
            TransparencyEvent::AckEmitted {
                for_packet: PacketId([0; 16])
            },
            NOW
        ),
        Err(CoreError::Malformed("transport event"))
    );
}

#[test]
fn watched_mailboxes_split_by_class() {
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    let mut rng = StdRng::seed_from_u64(9);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"), NOW, &mut rng)
        .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut rng,
    )
    .unwrap();
    // First contact: toward Bob's introduction mailbox, ack expected there.
    let p = a.send_text(&b.fingerprint(), "x", NOW, &mut rng).unwrap();
    let g = a.watched_mailbox_groups(NOW);
    let my_intro = intro_mailbox(&a.device.public(), day_of(NOW));
    assert!(g.intro.contains(&my_intro));
    assert!(g.intro.contains(&p[0].mailbox));
    assert!(!g.sessions.contains(&p[0].mailbox));
    assert!(!g.sessions.contains(&my_intro));
    // Session established: the session mailbox and that of the expected ack
    // are in the sessions group.
    b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap();
    let q = b.send_text(&a.fingerprint(), "y", NOW, &mut rng).unwrap();
    a.receive(&q[0].encode(), "t", NOW, &mut rng).unwrap();
    let r = a.send_text(&b.fingerprint(), "z", NOW, &mut rng).unwrap();
    let g = a.watched_mailbox_groups(NOW);
    assert!(g.sessions.contains(&q[0].mailbox));
    assert!(g.sessions.contains(&r[0].mailbox));
    assert!(!g.intro.contains(&r[0].mailbox));
    // Union, without duplicates.
    let all = a.watched_mailboxes(NOW);
    assert_eq!(all.len(), g.intro.len() + g.sessions.len());
    assert!(g.intro.iter().chain(&g.sessions).all(|m| all.contains(m)));
}

#[test]
fn transport_state_roundtrip_and_key_rules() {
    let (d, mut a) = party("a", 1);
    assert_eq!(a.transport_state("netsync").unwrap(), None);
    a.set_transport_state("netsync", b"state").unwrap();
    assert_eq!(
        a.transport_state("netsync").unwrap().as_deref(),
        Some(&b"state"[..])
    );
    a.set_transport_state("netsync", b"").unwrap();
    assert_eq!(
        a.transport_state("netsync").unwrap().as_deref(),
        Some(&b""[..])
    );
    for bad in ["", "a/b", "é", &"x".repeat(65)] {
        assert!(a.transport_state(bad).is_err());
        assert!(a.set_transport_state(bad, b"x").is_err());
    }
    assert!(matches!(
        a.set_transport_state("big", &vec![0; MAX_TRANSPORT_STATE + 1]),
        Err(CoreError::TooLarge)
    ));
    // Kept in the (encrypted) database: reread after reopening.
    a.set_transport_state("netsync", b"persists").unwrap();
    drop(a);
    let a = Core::open(&d.path().join("db"), &[1; 32], NOW).unwrap();
    assert_eq!(
        a.transport_state("netsync").unwrap().as_deref(),
        Some(&b"persists"[..])
    );
}

#[test]
fn contact_card_carries_card_nodes() {
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    let mut rng = StdRng::seed_from_u64(5);
    assert!(a.contact_card("Alice").unwrap().nodes.is_empty());
    let hints = vec![vec![1u8, 2, 3], vec![4u8; 192]];
    a.set_card_nodes(hints.clone()).unwrap();
    let card = a.contact_card("Alice").unwrap();
    assert_eq!(card.nodes, hints);
    card.verify().unwrap();
    assert!(b.contact_node_hints().unwrap().is_empty());
    b.add_contact(&card, Some("alice"), NOW, &mut rng).unwrap();
    assert_eq!(b.contact_node_hints().unwrap(), hints);
    // Another contact sharing a hint: no duplicate.
    let (_dc, mut c) = party("c", 3);
    c.set_card_nodes(vec![vec![4u8; 192], vec![7]]).unwrap();
    b.add_contact(
        &c.contact_card("Carol").unwrap(),
        Some("carol"),
        NOW,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        b.contact_node_hints().unwrap(),
        vec![vec![1u8, 2, 3], vec![4u8; 192], vec![7]]
    );
}

#[test]
fn set_card_nodes_enforces_limits() {
    let (_da, mut a) = party("a", 1);
    assert_eq!(a.set_card_nodes(vec![vec![0]; 4]), Err(CoreError::TooLarge));
    assert_eq!(
        a.set_card_nodes(vec![vec![0; 193]]),
        Err(CoreError::TooLarge)
    );
    a.set_card_nodes(vec![vec![0; 192]; 3]).unwrap();
    a.set_card_nodes(Vec::new()).unwrap();
    assert!(a.contact_card("Alice").unwrap().nodes.is_empty());
}

#[test]
fn invalid_node_hint_is_ignored() {
    // The core never decodes hints: arbitrary bytes do not prevent a card
    // from being accepted.
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.set_card_nodes(vec![
        vec![0xff; 40],
        Vec::new(),
        b"not a node card".to_vec(),
    ])
    .unwrap();
    let card = a.contact_card("Alice").unwrap();
    b.add_contact(&card, Some("alice"), NOW, &mut StdRng::seed_from_u64(0))
        .unwrap();
    assert_eq!(b.contact_node_hints().unwrap(), card.nodes);
}

#[test]
fn log_transport_event_accepts_node_avoided() {
    let mut p = pair();
    let e = TransparencyEvent::NodeAvoided {
        node: "ABCDEFGH".into(),
        reason: crate::transparency::AvoidReason::Unreachable,
    };
    p.a.log_transport_event(e.clone(), NOW).unwrap();
    assert!(
        p.a.transparency_log(10)
            .unwrap()
            .iter()
            .any(|(_, x)| *x == e)
    );
}

#[test]
fn card_nodes_survive_card_update_and_reload() {
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.set_card_nodes(vec![vec![5; 10]]).unwrap();
    let card = a.contact_card("Alice").unwrap();
    b.add_contact(&card, Some("alice"), NOW, &mut StdRng::seed_from_u64(0))
        .unwrap();
    assert_eq!(stored_card(&b, card.fingerprint()), card);
    // Serde form (message bodies, own-card meta) round-trips too.
    let bytes = postcard::to_allocvec(&Body::CardUpdate(Box::new(card.clone()))).unwrap();
    let Body::CardUpdate(back) = postcard::from_bytes(&bytes).unwrap() else {
        panic!("variant");
    };
    assert_eq!(*back, card);
}

#[test]
fn own_card_meta_in_old_form_is_still_read() {
    let (_d, a, _t, _b, _v1, _rng) = alice_tablet_bob();
    let card = a
        .store
        .get_meta::<ContactCard>(link::META_OWN_CARD)
        .unwrap()
        .unwrap();
    let write = |bytes: &[u8]| {
        a.store
            .conn()
            .execute(
                "UPDATE meta SET v = ?1 WHERE k = ?2",
                rusqlite::params![bytes, link::META_OWN_CARD],
            )
            .unwrap();
    };
    // Plain postcard of the card, as written by the previous build.
    write(&card.encode());
    assert!(
        a.store
            .get_meta::<ContactCard>(link::META_OWN_CARD)
            .is_err()
    );
    assert_eq!(sync::own_card(&a.store).unwrap(), Some(card.clone()));
    // Unreadable: treated as absent, never an error.
    write(&[0xff; 9]);
    assert_eq!(sync::own_card(&a.store).unwrap(), None);
}
