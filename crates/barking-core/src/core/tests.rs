//! Internal tests of the facade: authenticated but refused packets, forged
//! with the real state of a session (impossible from the public API).

use super::*;
use crate::contact::ContactCard;
use crate::content::{ExtContent, MessageRef, UnknownPolicy};
use crate::envelope::{Body, Envelope, SyncOp, Wire, parse_wire};
use crate::handshake::PrekeyBundle;
use crate::identity::{
    DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic, RootIdentity,
};
use crate::mailbox::day_of;
use crate::packet::{ACK_GRACE_SECS, DEFAULT_HOPS, DEFAULT_TTL_SECS, Kind, Tier, ack};
use crate::store::{Direction, MessageId, MessageStatus, ReactionRow, SessionRow};
use crate::transparency::{SyncKind, TransparencyEvent};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rusqlite::OptionalExtension;
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
    assert_eq!(p.b.messages_with(&p.a.fingerprint(), NOW).unwrap().len(), 2);
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

/// Alice has added Bob (not the reverse yet: Bob adds her in the tests) and
/// sent him a first text: her session row still carries `pending_initial`.
fn alice_opened_to_bob() -> (TempDir, Core, TempDir, Core, StdRng) {
    let (da, mut a) = party("a", 1);
    let (db, mut b) = party("b", 2);
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
    let mut rng = StdRng::seed_from_u64(6);
    a.send_text(&b.fingerprint(), "x", NOW, &mut rng).unwrap();
    (da, a, db, b, rng)
}

#[test]
fn stored_v1_pending_initial_still_reads() {
    let (_da, mut a, _db, mut b, mut rng) = alice_opened_to_bob();
    let mut row = best_session(&a);
    let stored = row.pending_initial.clone().unwrap();
    let init = de_init(&stored).unwrap();
    assert_eq!(init.sig, Some(a.device.public().sig));
    // A row written by 0.6.0: the same bytes without the trailing `sig`.
    let v1 = stored[..stored.len() - 32].to_vec();
    let old = de_init(&v1).unwrap();
    assert_eq!(old.sig, None);
    assert_eq!(old.ek, init.ek);
    assert_eq!(old.kem_ct, init.kem_ct);
    // The legacy row still sends, and Bob (who knows Alice) opens it.
    row.pending_initial = Some(v1);
    a.store.put_session(&row).unwrap();
    let p = a.send_text(&b.fingerprint(), "y", NOW, &mut rng).unwrap();
    assert!(matches!(
        b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
}

#[test]
fn known_sender_with_wrong_sig_refused() {
    let (_da, mut a, _db, mut b, mut rng) = alice_opened_to_bob();
    // Alice's Initial now names another signing key than the one of her
    // device in Bob's copy of her card.
    let mut row = best_session(&a);
    let mut init = de_init(row.pending_initial.as_deref().unwrap()).unwrap();
    let other = DeviceKeys::generate(&mut rng).public().sig;
    init.sig = Some(other);
    row.pending_initial = Some(ser_init(&init).unwrap());
    a.store.put_session(&row).unwrap();
    let p = a.send_text(&b.fingerprint(), "y", NOW, &mut rng).unwrap();
    assert!(matches!(
        parse_wire(&p[0].payload).unwrap(),
        Wire::Initial { .. }
    ));
    assert_eq!(
        reason(b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap()),
        R_HANDSHAKE
    );
    assert!(b.store.all_sessions().unwrap().is_empty());
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
    assert!(
        b.messages_with(&card.fingerprint(), NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn session_to_mixed_device_fails_at_its_real_owner() {
    // Carol does not know Alice: she accepts Mallory's "mixed" card
    // (Alice's dh key). Her Initial targets Mallory's intro mailbox, which
    // Alice does not watch. Even if it reached her, the device identifiers
    // bound to the associated data make decryption fail: Alice does not take
    // for herself a message meant for Mallory.
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
    // The intro mailbox binds the signing key: Mallory's key puts the Initial
    // in a mailbox Alice does not watch, so she does not even try to open it.
    assert!(
        !alice
            .watched_mailboxes(NOW)
            .unwrap()
            .contains(&p[0].mailbox)
    );
    assert!(matches!(
        alice.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::NotForUs
    ));
    // Relabelled into Alice's own intro mailbox, the Initial reaches the
    // decryption step: the device identifiers bound to the associated data
    // (Mallory's, not Alice's) make it fail there.
    let mut q = p[0].clone();
    q.mailbox = intro_mailbox(&alice.device.public(), day_of(NOW));
    assert!(alice.watched_mailboxes(NOW).unwrap().contains(&q.mailbox));
    assert_eq!(
        reason(alice.receive(&q.encode(), "t", NOW, &mut rng).unwrap()),
        "decryption impossible"
    );
    assert!(
        alice
            .messages_with(&carol.fingerprint(), NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn remove_contact_deletes_contact_card_and_sessions_but_keeps_history() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    assert!(!p.a.store.all_sessions().unwrap().is_empty());
    assert!(!p.a.messages_with(&bob, NOW).unwrap().is_empty());
    p.a.remove_contact(&bob, NOW, &mut p.rng).unwrap();
    assert!(p.a.contacts().unwrap().is_empty());
    assert_eq!(p.a.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(p.a.store.get_contact(bob).unwrap().is_none());
    assert!(p.a.store.all_sessions().unwrap().is_empty());
    assert!(!p.a.messages_with(&bob, NOW).unwrap().is_empty());
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
    // Negative control: at 8 days (the retention), the keys are still there.
    p.b.pending_outbox(NOW + 8 * 86_400).unwrap();
    assert_eq!(skipped_total(&p.b), 2);
    p.b.pending_outbox(NOW + 9 * 86_400).unwrap();
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
    let b = Core::open(&path, &key, NOW + 8 * 86_400).unwrap();
    assert_eq!(skipped_total(&b), 1);
    drop(b);
    let b = Core::open(&path, &key, NOW + 9 * 86_400).unwrap();
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
    let later = NOW + 9 * 86_400;
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
    let b = Core::open(&path, &key, NOW + 9 * 86_400).unwrap();
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
            ReceiveOutcome::DuplicateMessage
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
    assert!(
        t.watched_mailboxes(NOW)
            .unwrap()
            .contains(&out[0].0.mailbox)
    );
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
    assert!(t.messages_with(&me, NOW).unwrap().is_empty());
    assert!(a.messages_with(&me, NOW).unwrap().is_empty());
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
    let mid =
        p.a.messages_with(&b_fp, NOW)
            .unwrap()
            .last()
            .unwrap()
            .message_id;
    let before = p.b.messages_with(&a_fp, NOW).unwrap().len();
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
        ReceiveOutcome::DuplicateMessage
    ));
    assert_eq!(p.b.messages_with(&a_fp, NOW).unwrap().len(), before);
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
    let from_a = p.b.messages_with(&a_fp, NOW).unwrap();
    let in_id = from_a
        .iter()
        .find(|m| m.direction == Direction::In)
        .unwrap();
    let out_id = from_a
        .iter()
        .find(|m| m.direction == Direction::Out)
        .unwrap();
    let a_mid = p.a.messages_with(&b_fp, NOW).unwrap()[0].message_id;
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
    assert_eq!(p.b.messages_with(&a_fp, NOW).unwrap(), from_a);
    assert_eq!(p.b.messages_with(&c.fingerprint(), NOW).unwrap().len(), 3);
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
        Body::SyncContact(SyncOp::Avatar {
            contact: b_fp,
            avatar: None,
            at: NOW,
        }),
        Body::SyncContact(SyncOp::Upsert {
            card: Box::new(card.clone()),
            alias: "x".into(),
            verified: true,
        }),
        Body::SyncDevices {
            card: Box::new(card),
        },
    ];
    let before = p.a.messages_with(&b_fp, NOW).unwrap().len();
    for (i, body) in bodies.iter().enumerate() {
        let id = MessageId([i as u8 + 1; 16]);
        let out = seal_body(&mut p.b, &send::Target::Contact(a_fp), body, id, &mut p.rng);
        let r =
            p.a.receive(&out[0].0.encode(), "t", NOW, &mut p.rng)
                .unwrap();
        assert_eq!(reason(r), NOT_MINE, "case {i}");
    }
    assert_eq!(p.a.messages_with(&b_fp, NOW).unwrap().len(), before);
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
    // (A higher version that does not contain T1 removes it: see
    // `sync_devices_without_me_removes_me`.)
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
        ReceiveOutcome::Synced { kind, .. } => assert_eq!(kind, SyncKind::Devices),
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
            kind: SyncKind::Devices,
            ..
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
fn max_card_invitation_fits_one_packet() {
    use crate::identity::device_list::MAX_DEVICES;
    let mut rng = StdRng::seed_from_u64(5);
    let card = max_card(MAX_DEVICES, &mut rng);
    let body = ExtContent::ContactRequest {
        card: Box::new(card),
    }
    .to_body();
    assert!(crate::envelope::fits_in_packet(&body));
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
        let Wire::Initial { msg, .. } = parse_wire(&packet.payload).unwrap() else {
            panic!("Initial expected");
        };
        // The payload fills its tier (issue #82): the overhead is what the
        // wire adds to the padded plaintext, `ct` minus its tag.
        let padded_pt = msg.ct.len() - crate::ratchet::BODY_TAG_LEN;
        assert!(padded_pt >= env_len);
        let overhead = packet.payload.len() - padded_pt;
        assert!(
            overhead <= crate::envelope::MAX_WIRE_OVERHEAD,
            "{overhead} > {}",
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

/// Unusable keys of a booby-trapped device in a contact's card.
#[derive(Clone, Copy, Debug)]
enum Trap {
    /// Low-order signed prekey ([0; 32]).
    LowOrderSpk,
    /// Low-order device identity key ([0; 32]), certified by the root.
    LowOrderIdentity,
    /// ML-KEM key of the right size that does not decode.
    BadPqKey,
}

/// Bob's new card: his device plus a device with `trap` keys, every
/// signature valid. Returns the card and the trapped device's id.
fn trapped_card(b: &mut Core, trap: Trap, rng: &mut StdRng) -> (ContactCard, DeviceId) {
    use crate::crypto::labels;
    let bob_root = b.root.take().unwrap();
    let keys = DeviceKeys::generate(rng);
    let mut bundle = PrekeySecrets::generate(rng, 0).bundle(&keys, false);
    let cert = match trap {
        Trap::LowOrderSpk => {
            bundle.spk = [0; 32];
            DeviceCertificate::issue(&bob_root, &keys, "trap", NOW).unwrap()
        }
        Trap::LowOrderIdentity => {
            let mut device = keys.public();
            device.dh = [0; 32];
            bundle.device = device;
            let bytes = postcard::to_allocvec(&(bob_root.public(), device, "trap", NOW)).unwrap();
            let proof = keys.sign(labels::DEVICE_POSSESSION, &bytes);
            DeviceCertificate::issue_with_proof(&bob_root, device, "trap", NOW, proof).unwrap()
        }
        Trap::BadPqKey => {
            bundle.pq_ek = vec![0xff; bundle.pq_ek.len()];
            DeviceCertificate::issue(&bob_root, &keys, "trap", NOW).unwrap()
        }
    };
    let trap_id = cert.device.id();
    bundle.sig = keys.sign(labels::PREKEYS, &bundle.signed_bytes());
    let mut certs = b.devices.certs.clone();
    certs.push(cert);
    let list = DeviceList::sign(&bob_root, b.devices.version + 1, certs).unwrap();
    let bundles = vec![b.prekeys.bundle(&b.device, false), bundle];
    let card = ContactCard::sign(&bob_root, "Bob", list, bundles, Vec::new()).unwrap();
    b.root = Some(bob_root);
    (card, trap_id)
}

/// Bob sends `card` to Alice, who applies it.
fn apply_card(a: &mut Core, b: &mut Core, card: ContactCard, rng: &mut StdRng) {
    let a_id = a.device.public().id();
    let body = Body::CardUpdate(Box::new(card));
    let p = seal_body(
        b,
        &send::Target::Contact(a.fingerprint()),
        &body,
        MessageId([91; 16]),
        rng,
    )
    .into_iter()
    .find(|(_, d)| *d == a_id)
    .unwrap()
    .0;
    let r = a.receive(&p.encode(), "t", NOW, rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::CardUpdated { .. }), "{r:?}");
}

/// `SealSkipped` entries of `c`'s log for `device`.
fn seal_skipped(c: &Core, contact: Fingerprint, device: DeviceId) -> usize {
    c.transparency_log(1000)
        .unwrap()
        .into_iter()
        .filter(|(_, e)| *e == TransparencyEvent::SealSkipped { contact, device })
        .count()
}

/// Packets among `pkts` that Bob opens as `text`.
fn opened_text(b: &mut Core, pkts: &[Packet], text: &str, rng: &mut StdRng) -> usize {
    pkts.iter()
        .filter(|p| {
            matches!(
                b.receive(&p.encode(), "t", NOW, rng).unwrap(),
                ReceiveOutcome::Message { text: ref t, .. } if t == text
            )
        })
        .count()
}

#[test]
fn trapped_card_does_not_block_receive() {
    // Bob signs a card that adds a device whose signed prekey is
    // low-order ([0; 32]). Alice, linked (stored card), would send him her
    // card: sealing fails for this device, which is skipped.
    let (_dir, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let (card, trap_id) = trapped_card(&mut b, Trap::LowOrderSpk, &mut rng);
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
    assert_eq!(opened_text(&mut b, &pkts, "still here", &mut rng), 1);
    // The skipped device is in the transparency log, described.
    assert!(seal_skipped(&a, bob, trap_id) >= 1);
    let skipped = TransparencyEvent::SealSkipped {
        contact: bob,
        device: trap_id,
    };
    assert!(!skipped.is_security());
    assert!(skipped.describe().contains(&bob.to_string()));
}

#[test]
fn bad_device_keys_are_skipped_when_sealing() {
    for trap in [Trap::LowOrderIdentity, Trap::BadPqKey] {
        let (_dir, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
        let bob = b.fingerprint();
        let (card, trap_id) = trapped_card(&mut b, trap, &mut rng);
        apply_card(&mut a, &mut b, card, &mut rng);
        assert_eq!(stored_card(&a, bob).devices.certs.len(), 2, "{trap:?}");
        // Bob's valid device and the copy for T; nothing for the trap.
        let before = seal_skipped(&a, bob, trap_id);
        let pkts = a.send_text(&bob, "hi", NOW, &mut rng).unwrap();
        assert_eq!(pkts.len(), 2, "{trap:?}");
        assert_eq!(opened_text(&mut b, &pkts, "hi", &mut rng), 1, "{trap:?}");
        assert_eq!(seal_skipped(&a, bob, trap_id), before + 1, "{trap:?}");
    }
}

#[test]
fn link_skips_trapped_contact_device() {
    let (dir, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let (card, trap_id) = trapped_card(&mut b, Trap::BadPqKey, &mut rng);
    apply_card(&mut a, &mut b, card, &mut rng);
    // Linking a second tablet sends the new card to Bob's devices: the
    // link succeeds and only his valid device gets it.
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
    let before = seal_skipped(&a, bob, trap_id);
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t2.finish_link(&out.bundle, None, NOW).unwrap();
    let updated = out
        .packets
        .iter()
        .filter(|p| {
            matches!(
                b.receive(&p.encode(), "t", NOW, &mut rng).unwrap(),
                ReceiveOutcome::CardUpdated { .. }
            )
        })
        .count();
    assert_eq!(updated, 1);
    assert_eq!(seal_skipped(&a, bob, trap_id), before + 1);
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
    let sent = a.messages_with(&bob_fp, NOW).unwrap();
    assert_eq!(sent.len(), 1);
    // T already has this message (imported with the history), same identifier.
    let inserted = t
        .store
        .insert_message(
            bob_fp,
            Direction::Out,
            "hello",
            MessageStatus::OnNetwork,
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
    assert_eq!(t.messages_with(&bob_fp, NOW).unwrap().len(), 1);
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
    let g = a.watched_mailbox_groups(NOW).unwrap();
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
    let g = a.watched_mailbox_groups(NOW).unwrap();
    assert!(g.sessions.contains(&q[0].mailbox));
    assert!(g.sessions.contains(&r[0].mailbox));
    assert!(!g.intro.contains(&r[0].mailbox));
    // Union, without duplicates.
    let all = a.watched_mailboxes(NOW).unwrap();
    assert_eq!(all.len(), g.intro.len() + g.sessions.len());
    assert!(g.intro.iter().chain(&g.sessions).all(|m| all.contains(m)));
}

#[test]
fn watched_mailboxes_surface_store_errors() {
    let (_d, a) = party("a", 1);
    a.store
        .conn()
        .execute_batch("ALTER TABLE sessions RENAME TO sessions_gone;")
        .unwrap();
    // A partial list would let a poll move the window past unread days.
    assert!(a.watched_mailbox_groups(NOW).is_err());
    assert!(a.watched_mailboxes(NOW).is_err());
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

// --- Push: own mailboxes.

#[test]
fn sign_intro_ownership_for_own_mailbox() {
    use ed25519_dalek::{Signature, VerifyingKey};
    let p = pair();
    let me = p.a.device.public();
    let day = day_of(NOW);
    let hash = [0x5Au8; 32];
    let s =
        p.a.sign_intro_ownership(&intro_mailbox(&me, day), day, &hash)
            .expect("own intro mailbox");
    assert_eq!(s.sig, me.sig);
    assert_eq!(s.dh, me.dh);
    // Core signs the derived owner message, never the hash itself.
    let msg = barking_packet::owner_message(&hash, day);
    VerifyingKey::from_bytes(&s.sig)
        .unwrap()
        .verify_strict(&msg, &Signature::from_bytes(&s.signature))
        .unwrap();
    assert!(
        VerifyingKey::from_bytes(&s.sig)
            .unwrap()
            .verify_strict(&hash, &Signature::from_bytes(&s.signature))
            .is_err()
    );
}

#[test]
fn sign_intro_ownership_refuses_other_mailbox() {
    let p = pair();
    let me = p.a.device.public();
    let day = day_of(NOW);
    let hash = [0x5Au8; 32];
    // The mailbox of another day.
    assert!(
        p.a.sign_intro_ownership(&intro_mailbox(&me, day + 1), day, &hash)
            .is_none()
    );
    // Another device's introduction mailbox.
    let other = p.b.device.public();
    assert!(
        p.a.sign_intro_ownership(&intro_mailbox(&other, day), day, &hash)
            .is_none()
    );
    // A session mailbox.
    let sess =
        p.a.store
            .all_sessions()
            .unwrap()
            .into_iter()
            .next()
            .expect("pair() establishes a session");
    let m = session_mailbox(&sess.mailbox_secret, &me.id(), day);
    assert!(p.a.sign_intro_ownership(&m, day, &hash).is_none());
}

#[test]
fn sign_intro_ownership_refused_while_awaiting_link() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(6);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (t, _req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let day = day_of(NOW);
    let mine = intro_mailbox(&t.device.public(), day);
    assert!(t.sign_intro_ownership(&mine, day, &[0x5A; 32]).is_none());
}

#[test]
fn own_mailboxes_cover_sessions_and_intro_per_day() {
    let mut p = pair();
    let (_dc, mut c) = party("c", 3);
    p.a.add_contact(
        &c.contact_card("Carol").unwrap(),
        Some("carol"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    c.add_contact(
        &p.a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    // A message to Carol queues a packet awaiting its ack.
    p.a.send_text(&c.fingerprint(), "hi", NOW, &mut p.rng)
        .unwrap();
    let d = day_of(NOW);
    let own = p.a.own_mailboxes(&[d, d + 1]).unwrap();
    assert_eq!(own.len(), 6);
    assert_eq!(own.iter().filter(|(_, x)| *x == d).count(), 3);
    assert_eq!(own.iter().filter(|(_, x)| *x == d + 1).count(), 3);
    // The ack mailboxes (send mailboxes of my sessions) are not mine.
    let me = p.a.device.public();
    let my_id = me.id();
    let expected: Vec<MailboxId> = [d, d + 1]
        .iter()
        .flat_map(|&day| {
            let mut v = vec![intro_mailbox(&me, day)];
            for s in p.a.store.all_sessions().unwrap() {
                v.push(session_mailbox(&s.mailbox_secret, &my_id, day));
            }
            v
        })
        .collect();
    assert_eq!(own.iter().map(|(m, _)| *m).collect::<Vec<_>>(), expected);
    for s in p.a.store.all_sessions().unwrap() {
        for day in [d, d + 1] {
            let sent = session_mailbox(&s.mailbox_secret, &s.contact_device, day);
            assert!(!own.iter().any(|(m, _)| *m == sent));
        }
    }
    // The introduction part, in the order of the days.
    assert_eq!(
        p.a.own_intro_mailboxes(&[d, d + 1, d]),
        vec![intro_mailbox(&me, d), intro_mailbox(&me, d + 1)]
    );
}

#[test]
fn own_mailboxes_empty_while_awaiting_link() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(5);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (t, _req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    assert!(t.own_mailboxes(&[day_of(NOW)]).unwrap().is_empty());
    assert_eq!(a.own_mailboxes(&[day_of(NOW)]).unwrap().len(), 1);
}

/// A card of `c`'s identity, version `version`, with only a new device.
fn card_without(c: &Core, version: u64, rng: &mut StdRng) -> ContactCard {
    let root = c.root.as_ref().unwrap();
    let other = DeviceKeys::generate(rng);
    let cert = DeviceCertificate::issue(root, &other, "n", NOW).unwrap();
    let list = DeviceList::sign(root, version, vec![cert]).unwrap();
    ContactCard::sign(root, "", list, Vec::new(), Vec::new()).unwrap()
}

/// `from` seals `body` for every device of contact `to` (as a relay would).
fn seal_to_contact(from: &mut Core, to: Fingerprint, body: &Body, rng: &mut StdRng) -> Vec<u8> {
    let Core { store, device, .. } = from;
    store
        .transaction(|tx| {
            let id = MessageId([5; 16]);
            let target = send::Target::Contact(to);
            let time = send::SealTime::at(NOW);
            send::seal_for(tx, device, &target, body, id, time, rng)
        })
        .unwrap()
        .remove(0)
        .0
        .encode()
}

#[test]
fn removed_device_blocks_outgoing() {
    let Pair {
        _d,
        mut a,
        mut b,
        mut rng,
    } = pair();
    let card = card_without(&a, NOW + 10, &mut rng);
    let body = Body::CardUpdate(Box::new(card));
    let relayed = seal_to_contact(&mut b, a.fingerprint(), &body, &mut rng);
    assert!(matches!(
        a.receive(&relayed, "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Removed
    ));
    let gone = Some(removed::Removed {
        version: NOW + 10,
        at: NOW,
    });
    assert_eq!(a.removed().unwrap(), gone);
    assert!(a.root.is_none());
    let bob = b.fingerprint();
    let removed = |r: Result<()>| assert_eq!(r, Err(CoreError::DeviceRemoved));
    removed(a.send_text(&bob, "x", NOW, &mut rng).map(|_| ()));
    removed(
        a.add_contact(&b.contact_card("B").unwrap(), None, NOW, &mut rng)
            .map(|_| ()),
    );
    removed(a.mark_verified(&bob, NOW, &mut rng));
    removed(a.unmark_verified(&bob, NOW, &mut rng));
    removed(a.set_alias(&bob, "x", NOW, &mut rng).map(|_| ()));
    removed(a.remove_contact(&bob, NOW, &mut rng));
    removed(a.contact_card("A").map(|_| ()));
    removed(a.link_offer(NOW, &mut rng).map(|_| ()));
    let me = a.device.public().id();
    removed(a.transfer_admin(me, NOW, &mut rng));
    // Still receives.
    let p = b
        .send_text(&a.fingerprint(), "still here", NOW, &mut rng)
        .unwrap();
    assert!(matches!(
        a.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
    // A second relay of the same removal: duplicate.
    let again = seal_to_contact(&mut b, a.fingerprint(), &body, &mut rng);
    assert!(matches!(
        a.receive(&again, "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Duplicate
    ));
}

#[test]
fn removed_state_survives_reopen() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let mut rng = StdRng::seed_from_u64(9);
    let (mut a, _) = Core::create(&path, &[9; 32], "a", NOW, &mut rng).unwrap();
    let card = card_without(&a, NOW + 10, &mut rng);
    let Core { store, device, .. } = &mut a;
    store
        .transaction(|tx| removed::enter(tx, device, &card, NOW, &mut rng))
        .unwrap();
    drop(a);
    let mut a = Core::open(&path, &[9; 32], NOW).unwrap();
    assert!(a.root.is_none());
    assert_eq!(a.removed().unwrap().map(|r| r.version), Some(NOW + 10));
    assert_eq!(
        a.link_offer(NOW, &mut rng).map(|_| ()),
        Err(CoreError::DeviceRemoved)
    );
}

#[test]
fn stale_or_including_own_card_is_ignored() {
    let Pair {
        _d,
        mut a,
        mut b,
        mut rng,
    } = pair();
    // Older than my list: replayed, no effect.
    let old = card_without(&a, 1, &mut rng);
    // Newer but still containing me: not a removal.
    let root = a.root.as_ref().unwrap();
    let mine = a.devices.certs.clone();
    let list = DeviceList::sign(root, NOW + 20, mine).unwrap();
    let with_me = ContactCard::sign(root, "", list, Vec::new(), Vec::new()).unwrap();
    for card in [old, with_me] {
        let body = Body::CardUpdate(Box::new(card));
        let relayed = seal_to_contact(&mut b, a.fingerprint(), &body, &mut rng);
        assert!(matches!(
            a.receive(&relayed, "t", NOW, &mut rng).unwrap(),
            ReceiveOutcome::Duplicate
        ));
    }
    // Forged (version changed after signing): quarantine.
    let mut forged = card_without(&a, NOW + 30, &mut rng);
    forged.devices.version += 1;
    let body = Body::CardUpdate(Box::new(forged));
    let relayed = seal_to_contact(&mut b, a.fingerprint(), &body, &mut rng);
    assert!(matches!(
        a.receive(&relayed, "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Quarantined { .. }
    ));
    assert_eq!(a.removed().unwrap(), None);
    assert!(a.root.is_some());
}

#[test]
fn sync_devices_without_me_removes_me() {
    let (_d, mut a, mut t1, t2, mut rng) = linked_twice();
    let t1_dev = t1.device.public();
    let root = a.root.take().unwrap();
    let without: Vec<_> = a
        .devices
        .certs
        .iter()
        .filter(|c| c.device != t1_dev)
        .cloned()
        .collect();
    let list = DeviceList::sign(&root, a.devices.version + 1, without).unwrap();
    let card = card_for(&root, list, &all_bundles(&a), None);
    a.root = Some(root);
    let pkt = devices_packet(&mut a, &t1, card, 50, &mut rng);
    assert!(matches!(
        t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced {
            kind: SyncKind::Devices,
            ..
        }
    ));
    let version = a.devices.version + 1;
    assert_eq!(t1.removed().unwrap().map(|r| r.version), Some(version));
    assert_eq!(
        t1.send_text(&t2.fingerprint(), "x", NOW, &mut rng)
            .map(|_| ()),
        Err(CoreError::DeviceRemoved)
    );
    // T1 forwards the card to the siblings it knows (here A, which signed
    // it but never stored it): A, still listed, adopts it.
    let forwarded = t1.pending_outbox(NOW).unwrap();
    assert!(!forwarded.is_empty());
    for bytes in forwarded {
        a.receive(&bytes, "t", NOW, &mut rng).unwrap();
    }
    assert_eq!(a.devices.version, version);
    assert_eq!(a.removed().unwrap(), None);
    assert_eq!(t2.removed().unwrap(), None);
}

#[test]
fn card_update_relays_to_revoked() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, mut b) = party("b", 5);
    let a_fp = a.fingerprint();
    b.add_contact(&a.contact_card("A").unwrap(), None, NOW, &mut rng)
        .unwrap();
    a.add_contact(&b.contact_card("B").unwrap(), None, NOW, &mut rng)
        .unwrap();
    // T learns B through A's contact sync.
    for p in a.pending_outbox(NOW).unwrap() {
        t.receive(&p, "t", NOW, &mut rng).unwrap();
    }
    // B opens sessions with A and T.
    b.send_text(&a_fp, "hi", NOW, &mut rng).unwrap();
    let t_id = t.device.public().id();
    assert!(!b.store.sessions_for(a_fp, t_id).unwrap().is_empty());
    let before = b.pending_outbox(NOW).unwrap();

    // A's newer card without T, sent to B as a card update.
    let root = a.root.take().unwrap();
    let mine = a.device.public();
    let kept: Vec<_> = a
        .devices
        .certs
        .iter()
        .filter(|c| c.device == mine)
        .cloned()
        .collect();
    let list = DeviceList::sign(&root, a.devices.version + 1, kept).unwrap();
    let card = card_for(&root, list, &all_bundles(&a), None);
    a.root = Some(root);
    let update = seal_body(
        &mut a,
        &send::Target::Contact(b.fingerprint()),
        &Body::CardUpdate(Box::new(card)),
        MessageId([60; 16]),
        &mut rng,
    );
    assert!(matches!(
        b.receive(&update[0].0.encode(), "t", NOW, &mut rng)
            .unwrap(),
        ReceiveOutcome::CardUpdated { .. }
    ));
    // B told T before deleting its sessions with it.
    assert!(b.store.sessions_for(a_fp, t_id).unwrap().is_empty());
    let relayed: Vec<_> = b
        .pending_outbox(NOW)
        .unwrap()
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    let outcomes: Vec<_> = relayed
        .iter()
        .map(|p| t.receive(p, "t", NOW, &mut rng).unwrap())
        .collect();
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Removed)),
        "{outcomes:?}"
    );
    assert!(t.removed().unwrap().is_some());
}

/// A failure in the write step of a removal requested by `RemoveMe` is never
/// swallowed: the receive fails and its transaction rolls back whole.
#[test]
fn remove_me_write_failure_aborts_receive() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    // A session A -> T first (the `SyncSent` copy): T's `RemoveMe` then
    // needs no sender lookup among the contacts.
    for p in a.send_text(&b.fingerprint(), "hi", NOW, &mut rng).unwrap() {
        t.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    }
    let packets = t.leave(NOW, &mut rng).unwrap();
    assert_eq!(packets.len(), 1);
    // B's stored card unreadable: `CardUpdate`, sealed last, fails.
    a.store
        .conn()
        .execute(
            "UPDATE contacts SET card = ?1 WHERE fp = ?2",
            rusqlite::params![&[0xff_u8; 9][..], &b.fingerprint().0[..]],
        )
        .unwrap();
    let before = a.store.get_meta::<DeviceList>(META_DEVICE_LIST).unwrap();
    assert!(a.receive(&packets[0].encode(), "t", NOW, &mut rng).is_err());
    assert_eq!(
        a.store.get_meta::<DeviceList>(META_DEVICE_LIST).unwrap(),
        before
    );
    assert_eq!(a.my_devices().len(), 2);
    let removed = a
        .transparency_log(10_000)
        .unwrap()
        .into_iter()
        .any(|(_, e)| {
            matches!(
                e,
                crate::transparency::TransparencyEvent::DeviceRemoved { .. }
                    | crate::transparency::TransparencyEvent::RemoveRequested { .. }
            )
        });
    assert!(!removed);
}

// --- Block 2b, task 5: route of a message.

const ROUTE_NODE: &str = "K7QX2M4A";

fn this_device(c: &Core) -> DeviceId {
    c.my_devices()
        .into_iter()
        .find(|d| d.this_device)
        .unwrap()
        .id
}

#[test]
fn route_of_sent_and_received_message() {
    // B (admin) with B2 linked; A knows B's card listing both devices.
    let (_dir, mut b, b2, mut rng) = linked();
    let (_da, mut a) = party("a", 9);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"), NOW, &mut rng)
        .unwrap();
    b.add_contact(
        &a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut rng,
    )
    .unwrap();
    let (b_id, b2_id, a_id) = (this_device(&b), this_device(&b2), this_device(&a));

    let packets = a.send_text(&b.fingerprint(), "hi", NOW, &mut rng).unwrap();
    assert_eq!(packets.len(), 2);
    for p in &packets {
        a.record_route(p.id, RouteStep::Deposited, ROUTE_NODE, NOW + 1)
            .unwrap();
    }
    let mut acks = Vec::new();
    for p in &packets {
        if let ReceiveOutcome::Message { ack, .. } =
            b.receive(&p.encode(), "t", NOW + 2, &mut rng).unwrap()
        {
            acks.push(ack);
        }
    }
    assert_eq!(acks.len(), 1);
    assert!(matches!(
        a.receive(&acks[0].encode(), "t", NOW + 3, &mut rng)
            .unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));

    // Sender: Sealed towards B and B2, Deposited on the node, AckVerified.
    let row = a.messages_with(&b.fingerprint(), NOW).unwrap()[0].id;
    let route = a.message_route(row).unwrap();
    let steps: Vec<RouteStep> = route.iter().map(|e| e.step).collect();
    assert_eq!(
        steps,
        [
            RouteStep::Sealed,
            RouteStep::Sealed,
            RouteStep::Deposited,
            RouteStep::Deposited,
            RouteStep::AckVerified
        ]
    );
    let sealed_to: std::collections::HashSet<DeviceId> =
        route[..2].iter().map(|e| e.device.unwrap()).collect();
    assert_eq!(sealed_to, std::collections::HashSet::from([b_id, b2_id]));
    for e in &route[..2] {
        assert!(e.size.unwrap() > 0);
        assert_eq!(e.node, None);
        assert!(!e.own);
        assert_eq!(e.at, NOW);
    }
    for e in &route[2..4] {
        assert_eq!(e.node.as_deref(), Some(ROUTE_NODE));
        assert_eq!(e.at, NOW + 1);
    }
    assert_eq!(route[4].device, Some(b_id));
    assert_eq!(route[4].at, NOW + 3);

    // Recipient: Opened.
    let row = b.messages_with(&a.fingerprint(), NOW).unwrap()[0].id;
    let route = b.message_route(row).unwrap();
    assert_eq!(route.len(), 1);
    assert_eq!(route[0].step, RouteStep::Opened);
    assert_eq!(route[0].at, NOW + 2);
    assert_eq!(route[0].device, None);

    // B's reply: Sealed towards A, and its OwnCopy towards B2.
    b.send_text(&a.fingerprint(), "re", NOW + 4, &mut rng)
        .unwrap();
    let reply = b
        .messages_with(&a.fingerprint(), NOW)
        .unwrap()
        .into_iter()
        .find(|m| m.direction == Direction::Out)
        .unwrap();
    let route = b.message_route(reply.id).unwrap();
    assert_eq!(route.len(), 2);
    assert_eq!(route[0].step, RouteStep::Sealed);
    assert_eq!(route[0].device, Some(a_id));
    assert!(!route[0].own);
    assert_eq!(route[1].step, RouteStep::OwnCopy);
    assert_eq!(route[1].device, Some(b2_id));
    assert!(route[1].own);

    // An unknown message has no route.
    assert!(a.message_route(i64::MAX).unwrap().is_empty());
}

#[test]
fn record_route_rejects_internal_steps() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "z", NOW, &mut p.rng)
            .unwrap();
    let id = sent[0].id;
    for step in [
        RouteStep::Sealed,
        RouteStep::Opened,
        RouteStep::AckVerified,
        RouteStep::OwnCopy,
    ] {
        assert!(matches!(
            p.a.record_route(id, step, ROUTE_NODE, NOW),
            Err(CoreError::Malformed(_))
        ));
    }
    // A node is its short identifier, never an address.
    for node in ["", "127.0.0.1:4433", "K7QX2M4AK7QX2M4A"] {
        assert!(matches!(
            p.a.record_route(id, RouteStep::Deposited, node, NOW),
            Err(CoreError::Malformed(_))
        ));
    }
    p.a.record_route(id, RouteStep::Fetched, ROUTE_NODE, NOW)
        .unwrap();
}

#[test]
fn route_steps_purged_after_30_days() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "z", NOW, &mut p.rng)
            .unwrap();
    let row =
        p.a.messages_with(&p.b.fingerprint(), NOW)
            .unwrap()
            .into_iter()
            .rfind(|m| m.direction == Direction::Out)
            .unwrap()
            .id;
    let id = sent[0].id;
    p.a.record_route(id, RouteStep::Deposited, ROUTE_NODE, NOW)
        .unwrap();
    assert_eq!(p.a.message_route(row).unwrap().len(), 2);
    let fetch = |t: u64| TransparencyEvent::NodeFetch {
        node: format!("{t}"),
        mailboxes: 1,
        received: 0,
    };
    // The log's purge clock advances by at most two days per write.
    for day in 1..=30 {
        p.a.log_transport_event(fetch(day), NOW + day * 86_400)
            .unwrap();
    }
    assert_eq!(p.a.message_route(row).unwrap().len(), 2);
    p.a.log_transport_event(fetch(31), NOW + 30 * 86_400 + 1)
        .unwrap();
    assert!(p.a.message_route(row).unwrap().is_empty());
}

#[test]
fn repeated_transport_steps_are_recorded_once_per_node() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "z", NOW, &mut p.rng)
            .unwrap();
    let id = sent[0].id;
    for pk in &sent {
        p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    }
    let transport =
        |c: &Core, contact: &crate::identity::root::Fingerprint| -> Vec<(RouteStep, String, u64)> {
            // The last message of the conversation: "z".
            let row = c.messages_with(contact, NOW).unwrap().last().unwrap().id;
            c.message_route(row)
                .unwrap()
                .into_iter()
                .filter_map(|e| Some((e.step, e.node?, e.at)))
                .collect()
        };
    // A redeposit, a refetch and a cross-check of the same packet on the
    // same node add nothing; another node keeps its own step.
    for t in [NOW, NOW + 60, NOW + 120] {
        p.a.record_route(id, RouteStep::Deposited, ROUTE_NODE, t)
            .unwrap();
        p.b.record_route(id, RouteStep::Fetched, ROUTE_NODE, t)
            .unwrap();
    }
    p.a.record_route(id, RouteStep::Deposited, "ZZZZ9999", NOW + 5)
        .unwrap();
    p.b.record_route(id, RouteStep::Fetched, "ZZZZ9999", NOW + 5)
        .unwrap();
    // The sender fetching back its own packet (an audit) and the recipient
    // depositing a received one are not steps of the route.
    p.a.record_route(id, RouteStep::Fetched, ROUTE_NODE, NOW + 9)
        .unwrap();
    p.b.record_route(id, RouteStep::Deposited, ROUTE_NODE, NOW + 9)
        .unwrap();
    let (fa, fb) = (p.a.fingerprint(), p.b.fingerprint());
    assert_eq!(
        transport(&p.a, &fb),
        [
            (RouteStep::Deposited, ROUTE_NODE.to_owned(), NOW),
            (RouteStep::Deposited, "ZZZZ9999".to_owned(), NOW + 5),
        ]
    );
    assert_eq!(
        transport(&p.b, &fa),
        [
            (RouteStep::Fetched, ROUTE_NODE.to_owned(), NOW),
            (RouteStep::Fetched, "ZZZZ9999".to_owned(), NOW + 5),
        ]
    );
}

#[test]
fn awaited_ack_mailboxes_lists_contact_messages_only() {
    let (_d, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    // The card update queued for Bob by the link is no message: not listed.
    assert!(a.awaited_ack_mailboxes(NOW).unwrap().is_empty());
    let at = NOW + 86_400;
    let packets = a
        .send_text(&b.fingerprint(), "hello", at, &mut rng)
        .unwrap();
    // Bob's device first, then the `SyncSent` copy for my tablet.
    assert_eq!(packets.len(), 2);
    assert_ne!(packets[1].mailbox, packets[0].mailbox);
    assert_eq!(
        a.awaited_ack_mailboxes(at).unwrap(),
        vec![(packets[0].mailbox, day_of(at))]
    );
    // A second message to the same mailbox: still listed once.
    let more = a
        .send_text(&b.fingerprint(), "again", at, &mut rng)
        .unwrap();
    assert_eq!(more[0].mailbox, packets[0].mailbox);
    assert_eq!(
        a.awaited_ack_mailboxes(at).unwrap(),
        vec![(packets[0].mailbox, day_of(at))]
    );
    // Bob's queue holds only his receipts: nothing awaited there.
    let mut acks = Vec::new();
    for p in [&packets[0], &more[0]] {
        match b.receive(&p.encode(), "t", at, &mut rng).unwrap() {
            ReceiveOutcome::Message { ack, .. } => acks.push(ack),
            o => panic!("{o:?}"),
        }
    }
    assert!(
        b.pending_outbox(at)
            .unwrap()
            .iter()
            .any(|p| Packet::decode(p).unwrap().kind == Kind::Ack)
    );
    assert!(b.awaited_ack_mailboxes(at).unwrap().is_empty());
    // One receipt: the other message still awaits its own.
    assert!(matches!(
        a.receive(&acks[0].encode(), "t", at, &mut rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert_eq!(a.awaited_ack_mailboxes(at).unwrap().len(), 1);
    assert!(matches!(
        a.receive(&acks[1].encode(), "t", at, &mut rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert!(a.awaited_ack_mailboxes(at).unwrap().is_empty());
    // An expired message is no longer awaited.
    let late = a.send_text(&b.fingerprint(), "late", at, &mut rng).unwrap();
    assert_eq!(a.awaited_ack_mailboxes(at).unwrap().len(), 1);
    let expiry = u64::from(late[0].expires_at);
    assert_eq!(a.awaited_ack_mailboxes(expiry).unwrap().len(), 1);
    assert!(a.awaited_ack_mailboxes(expiry + 1).unwrap().is_empty());
}

// --- Lot M, task 1: delivery states and times.

/// `(status, sealed_at, size, acked_at)` of the delivery carrying `packet`.
fn delivery_of(c: &Core, packet: PacketId) -> (i64, i64, Option<i64>, Option<i64>) {
    c.store
        .conn()
        .query_row(
            "SELECT status, sealed_at, size, acked_at FROM deliveries WHERE packet_id = ?1",
            rusqlite::params![packet.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

#[test]
fn send_is_pending_until_deposit() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "pending", NOW + 10, &mut p.rng)
            .unwrap();
    let rows = p.a.messages_with(&p.b.fingerprint(), NOW).unwrap();
    let row = rows.iter().find(|m| m.body == "pending").unwrap();
    assert_eq!(row.status, MessageStatus::Pending);
    let size = i64::try_from(sent[0].tier.size()).unwrap();
    assert!(size > 0);
    let now = i64::try_from(NOW + 10).unwrap();
    assert_eq!(delivery_of(&p.a, sent[0].id), (0, now, Some(size), None));
}

#[test]
fn ack_sets_received_and_acked_at() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "ack-me", NOW, &mut p.rng)
            .unwrap();
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    assert!(matches!(
        p.a.receive(&ack.encode(), "t", NOW + 7, &mut p.rng)
            .unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    let rows = p.a.messages_with(&p.b.fingerprint(), NOW).unwrap();
    let row = rows.iter().find(|m| m.body == "ack-me").unwrap();
    assert_eq!(row.status, MessageStatus::Received);
    let (status, _, _, acked_at) = delivery_of(&p.a, sent[0].id);
    assert_eq!(
        (status, acked_at),
        (3, Some(i64::try_from(NOW + 7).unwrap()))
    );
}

#[test]
fn own_copy_ack_does_not_make_received() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let sent = a
        .send_text(&b.fingerprint(), "copy", NOW, &mut rng)
        .unwrap();
    // Bob's device first, then the `SyncSent` copy for my tablet.
    assert_eq!(sent.len(), 2);
    let copy = &sent[1];
    assert_eq!(delivery_of(&a, copy.id).1, i64::try_from(NOW).unwrap());
    assert!(matches!(
        t.receive(&copy.encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced { .. }
    ));
    let ack = t
        .pending_outbox(NOW)
        .unwrap()
        .iter()
        .map(|bytes| Packet::decode(bytes).unwrap())
        .find(|p| p.kind == Kind::Ack)
        .unwrap();
    assert!(matches!(
        a.receive(&ack.encode(), "t", NOW + 3, &mut rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert_eq!(delivery_of(&a, copy.id).0, 3);
    let rows = a.messages_with(&b.fingerprint(), NOW).unwrap();
    assert_eq!(rows[0].status, MessageStatus::Pending);
}

#[test]
fn emitted_ack_keeps_its_reference() {
    let mut p = pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "ref", NOW, &mut p.rng)
            .unwrap();
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    let reference: Option<Vec<u8>> =
        p.b.store
            .conn()
            .query_row(
                "SELECT ref FROM outbox WHERE packet_id = ?1",
                rusqlite::params![ack.id.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(reference, Some(sent[0].id.0.to_vec()));
}

// --- Lot M, task 2: deposits, expiry and the failure verdict.

/// Short id of a test node.
const NODE: &str = "K7QX2M4A";

/// `(status, deposited_at, node, expired_at)` of the delivery carrying `packet`.
fn delivery_state(c: &Core, packet: PacketId) -> (i64, Option<i64>, Option<String>, Option<i64>) {
    c.store
        .conn()
        .query_row(
            "SELECT status, deposited_at, node, expired_at FROM deliveries WHERE packet_id = ?1",
            rusqlite::params![packet.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

/// `Some(deposited_at)` of `packet` in the send queue; `None` if it left it.
fn outbox_row(c: &Core, packet: PacketId) -> Option<Option<i64>> {
    c.store
        .conn()
        .query_row(
            "SELECT deposited_at FROM outbox WHERE packet_id = ?1",
            rusqlite::params![packet.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
}

/// `Deposited` steps of `packet`.
fn deposited_steps(c: &Core, packet: PacketId) -> Vec<(i64, Option<String>)> {
    let mut stmt = c
        .store
        .conn()
        .prepare("SELECT at, node FROM route_steps WHERE packet_id = ?1 AND step = 1")
        .unwrap();
    stmt.query_map(rusqlite::params![packet.0.as_slice()], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

fn status_of(c: &Core, contact: &Fingerprint, body: &str) -> MessageStatus {
    c.messages_with(contact, NOW)
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
        .status
}

fn row_of(c: &Core, contact: &Fingerprint, body: &str) -> i64 {
    c.messages_with(contact, NOW)
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
        .id
}

fn i(v: u64) -> i64 {
    i64::try_from(v).unwrap()
}

/// `pair`, with Alice's first message acknowledged: nothing of hers awaits.
fn settled_pair() -> Pair {
    let mut p = pair();
    for bytes in p.b.pending_outbox(NOW).unwrap() {
        let packet = Packet::decode(&bytes).unwrap();
        if packet.kind == Kind::Ack {
            p.a.receive(&bytes, "t", NOW, &mut p.rng).unwrap();
        }
    }
    assert!(p.a.awaited_ack_mailboxes(NOW).unwrap().is_empty());
    p
}

#[test]
fn record_deposit_is_idempotent_and_sets_on_network() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "dep", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    p.a.record_deposit(id, NODE, NOW + 5).unwrap();
    p.a.record_deposit(id, NODE, NOW + 9).unwrap();
    assert_eq!(
        delivery_state(&p.a, id),
        (1, Some(i(NOW + 5)), Some(NODE.to_string()), None)
    );
    assert_eq!(outbox_row(&p.a, id), Some(Some(i(NOW + 5))));
    assert_eq!(
        deposited_steps(&p.a, id),
        vec![(i(NOW + 5), Some(NODE.to_string()))]
    );
    assert_eq!(status_of(&p.a, &bob, "dep"), MessageStatus::OnNetwork);
    // A second node: one more step, the first deposit stays.
    p.a.record_deposit(id, "ZZZZZZZZ", NOW + 12).unwrap();
    assert_eq!(deposited_steps(&p.a, id).len(), 2);
    assert_eq!(delivery_state(&p.a, id).1, Some(i(NOW + 5)));
    // A malformed node id is refused; an unknown packet is ignored.
    assert!(p.a.record_deposit(id, "short", NOW).is_err());
    p.a.record_deposit(PacketId([9; 16]), NODE, NOW).unwrap();
}

#[test]
fn record_route_deposited_delegates_to_record_deposit() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "route-dep", NOW, &mut p.rng).unwrap();
    p.a.record_route(sent[0].id, RouteStep::Deposited, NODE, NOW + 3)
        .unwrap();
    assert_eq!(delivery_state(&p.a, sent[0].id).0, 1);
    assert_eq!(outbox_row(&p.a, sent[0].id), Some(Some(i(NOW + 3))));
    assert_eq!(status_of(&p.a, &bob, "route-dep"), MessageStatus::OnNetwork);
}

#[test]
fn deposited_ack_sets_outbox_deposited_at() {
    let mut p = settled_pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "acked", NOW, &mut p.rng)
            .unwrap();
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    assert_eq!(outbox_row(&p.b, ack.id), Some(None));
    p.b.record_deposit(ack.id, NODE, NOW + 2).unwrap();
    assert_eq!(outbox_row(&p.b, ack.id), Some(Some(i(NOW + 2))));
    // A receipt has no delivery and no route.
    assert!(deposited_steps(&p.b, ack.id).is_empty());
}

#[test]
fn expiry_without_deposit_is_not_delivered() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "lost", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.expire_due(expiry).unwrap();
    assert_eq!(delivery_state(&p.a, id).0, 0, "not expired at its expiry");
    p.a.expire_due(expiry + 1).unwrap();
    assert_eq!(delivery_state(&p.a, id), (5, None, None, Some(i(expiry))));
    assert_eq!(status_of(&p.a, &bob, "lost"), MessageStatus::NotDelivered);
    assert_eq!(outbox_row(&p.a, id), None, "purged");
    let row = row_of(&p.a, &bob, "lost");
    assert_eq!(p.a.take_failed_notices(), vec![(bob, row)]);
    assert!(p.a.take_failed_notices().is_empty());
    // Idempotent.
    p.a.expire_due(expiry + 2).unwrap();
    assert!(p.a.take_failed_notices().is_empty());
}

#[test]
fn pending_outbox_expires_before_purging() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "late", NOW, &mut p.rng).unwrap();
    let expiry = u64::from(sent[0].expires_at);
    p.a.pending_outbox(expiry + 1).unwrap();
    assert_eq!(delivery_state(&p.a, sent[0].id).0, 5);
    assert_eq!(status_of(&p.a, &bob, "late"), MessageStatus::NotDelivered);
}

#[test]
fn expiry_after_deposit_waits_for_the_verdict() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "wait", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.record_deposit(id, NODE, NOW + 1).unwrap();
    p.a.expire_due(expiry + 1).unwrap();
    assert_eq!(delivery_state(&p.a, id).0, 1);
    assert_eq!(status_of(&p.a, &bob, "wait"), MessageStatus::OnNetwork);
    assert!(outbox_row(&p.a, id).is_some(), "still queued");
    assert!(p.a.take_failed_notices().is_empty());
    // Awaiting the verdict from its expiry on, with its mailbox.
    assert!(p.a.awaiting_verdict(expiry - 1).unwrap().is_empty());
    assert_eq!(
        p.a.awaiting_verdict(expiry).unwrap(),
        vec![(id, sent[0].mailbox)]
    );
    assert_eq!(
        p.a.awaiting_verdict(expiry + 1).unwrap(),
        vec![(id, sent[0].mailbox)]
    );
    // Never redeposited once expired.
    assert!(p.a.pending_outbox(expiry + 1).unwrap().is_empty());
}

#[test]
fn verdict_never_given_ends_past_the_ack_grace_on_the_network() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "unconfirmed", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.record_deposit(id, NODE, NOW + 1).unwrap();
    let row = row_of(&p.a, &bob, "unconfirmed");
    let summary = |a: &mut Core, at: u64| a.deliveries_of(&[row], at).unwrap()[0].1.unwrap();
    assert!(summary(&mut p.a, NOW + 2).awaiting_verdict);
    // Up to the end of the nodes' ack grace, it still awaits its verdict.
    let last = expiry + ACK_GRACE_SECS;
    assert!(summary(&mut p.a, last).awaiting_verdict);
    assert_eq!(
        p.a.awaiting_verdict(last).unwrap(),
        vec![(id, sent[0].mailbox)]
    );
    assert!(outbox_row(&p.a, id).is_some());
    // Past it, no node can hold its ack any more: it leaves the queue and
    // the awaited set, unconfirmed, and stays on the network.
    assert!(p.a.awaiting_verdict(last + 1).unwrap().is_empty());
    let s = summary(&mut p.a, last + 1);
    assert!(!s.awaiting_verdict);
    assert_eq!(s.state, MessageStatus::OnNetwork);
    assert_eq!(delivery_state(&p.a, id).0, 1);
    assert_eq!(
        status_of(&p.a, &bob, "unconfirmed"),
        MessageStatus::OnNetwork
    );
    assert_eq!(outbox_row(&p.a, id), None, "dropped from the queue");
    assert!(p.a.pending_outbox(last + 1).unwrap().is_empty());
    assert!(p.a.take_failed_notices().is_empty(), "no failure notice");
    // A late verdict call can no longer fail it.
    assert!(!p.a.confirm_expired(id, last + 2).unwrap());
    assert_eq!(
        status_of(&p.a, &bob, "unconfirmed"),
        MessageStatus::OnNetwork
    );
}

#[test]
fn awaiting_verdict_skips_pending_and_received() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let queued = p.a.send_text(&bob, "queued", NOW, &mut p.rng).unwrap();
    let acked = p.a.send_text(&bob, "acked", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(acked[0].id, NODE, NOW).unwrap();
    let ack = match p
        .b
        .receive(&acked[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    p.a.receive(&ack.encode(), "t", NOW, &mut p.rng).unwrap();
    let expiry = u64::from(queued[0].expires_at);
    assert!(p.a.awaiting_verdict(expiry + 1).unwrap().is_empty());
}

#[test]
fn confirm_expired_marks_not_delivered_and_keeps_deposited_at() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "gone", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.record_deposit(id, NODE, NOW + 1).unwrap();
    // Not before its expiry.
    assert!(!p.a.confirm_expired(id, expiry - 1).unwrap());
    assert_eq!(delivery_state(&p.a, id).0, 1);
    assert!(p.a.confirm_expired(id, expiry + 30).unwrap());
    assert_eq!(
        delivery_state(&p.a, id),
        (5, Some(i(NOW + 1)), Some(NODE.to_string()), Some(i(expiry)))
    );
    assert_eq!(status_of(&p.a, &bob, "gone"), MessageStatus::NotDelivered);
    assert_eq!(outbox_row(&p.a, id), None);
    assert!(p.a.awaiting_verdict(expiry + 30).unwrap().is_empty());
    assert!(p.a.awaited_ack_mailboxes(NOW).unwrap().is_empty());
    let row = row_of(&p.a, &bob, "gone");
    assert_eq!(p.a.take_failed_notices(), vec![(bob, row)]);
    // Idempotent.
    assert!(!p.a.confirm_expired(id, expiry + 40).unwrap());
    assert!(p.a.take_failed_notices().is_empty());
}

#[test]
fn confirm_expired_leaves_received_alone() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "got", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.record_deposit(id, NODE, NOW).unwrap();
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    p.a.receive(&ack.encode(), "t", NOW + 1, &mut p.rng)
        .unwrap();
    assert!(!p.a.confirm_expired(id, expiry + 1).unwrap());
    assert_eq!(delivery_state(&p.a, id).0, 3);
    assert_eq!(status_of(&p.a, &bob, "got"), MessageStatus::Received);
    assert!(p.a.take_failed_notices().is_empty());
}

#[test]
fn not_delivered_on_one_device_keeps_the_message_on_the_network() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "split", NOW, &mut rng).unwrap();
    // Bob's device first, then the copy for my tablet.
    let expiry = u64::from(sent[0].expires_at);
    a.record_deposit(sent[1].id, NODE, NOW).unwrap();
    // The contact's only delivery expires undeposited: the message failed,
    // whatever became of my own copy.
    a.expire_due(expiry + 1).unwrap();
    assert_eq!(status_of(&a, &bob, "split"), MessageStatus::NotDelivered);
    // The deposited copy for my tablet awaits its own verdict.
    assert_eq!(delivery_state(&a, sent[1].id).0, 1);
    assert_eq!(
        a.awaiting_verdict(expiry + 1).unwrap(),
        vec![(sent[1].id, sent[1].mailbox)]
    );
    assert!(a.confirm_expired(sent[1].id, expiry + 1).unwrap());
    assert_eq!(delivery_state(&a, sent[1].id).0, 5);
    // One notice for the message: the copy's verdict changes nothing.
    assert_eq!(a.take_failed_notices().len(), 1);
}

#[test]
fn local_purge_spares_deposited_packets_without_verdict() {
    let mut p = settled_pair();
    let sent =
        p.a.send_text(&p.b.fingerprint(), "spared", NOW, &mut p.rng)
            .unwrap();
    let id = sent[0].id;
    let expiry = u64::from(sent[0].expires_at);
    p.a.record_deposit(id, NODE, NOW).unwrap();
    // A deposited receipt has no verdict to wait for: purged at its expiry.
    let msg =
        p.b.send_text(&p.a.fingerprint(), "to-ack", NOW, &mut p.rng)
            .unwrap();
    let ack = match p.a.receive(&msg[0].encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    p.a.record_deposit(ack.id, NODE, NOW).unwrap();
    let later = expiry.max(u64::from(ack.expires_at)) + 1;
    p.a.pending_outbox(later).unwrap();
    assert!(outbox_row(&p.a, id).is_some(), "awaits its verdict");
    assert_eq!(outbox_row(&p.a, ack.id), None);
    // After the verdict, nothing is left.
    assert!(p.a.confirm_expired(id, later).unwrap());
    p.a.pending_outbox(later).unwrap();
    assert_eq!(outbox_row(&p.a, id), None);
}

#[test]
fn dropped_packet_is_not_delivered() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "refused", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    assert!(p.a.drop_outbox_packet(&sent[0].encode(), NOW + 4).unwrap());
    assert_eq!(delivery_state(&p.a, id), (5, None, None, Some(i(NOW + 4))));
    assert_eq!(
        status_of(&p.a, &bob, "refused"),
        MessageStatus::NotDelivered
    );
    assert_eq!(outbox_row(&p.a, id), None);
    let row = row_of(&p.a, &bob, "refused");
    assert_eq!(p.a.take_failed_notices(), vec![(bob, row)]);
}

#[test]
fn dropped_packet_already_on_the_network_awaits_its_verdict() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "legacy", NOW, &mut p.rng).unwrap();
    let id = sent[0].id;
    p.a.record_deposit(id, NODE, NOW).unwrap();
    // A node accepted it earlier: only `confirm_expired` may fail it.
    assert!(!p.a.drop_outbox_packet(&sent[0].encode(), NOW + 4).unwrap());
    assert_eq!(delivery_state(&p.a, id).0, 1);
    assert!(outbox_row(&p.a, id).is_some());
    assert!(p.a.take_failed_notices().is_empty());
}

/// Rewrites the deliveries of the message `body` with hand-written
/// `(own, status)` rows and recomputes its status.
fn recompute_with(p: &mut Pair, body: &str, rows: &[(i64, i64)]) -> MessageStatus {
    let bob = p.b.fingerprint();
    let mid =
        p.a.messages_with(&bob, NOW)
            .unwrap()
            .into_iter()
            .find(|m| m.body == body)
            .unwrap()
            .message_id;
    let conn = p.a.store.conn();
    conn.execute(
        "DELETE FROM deliveries WHERE message_id = ?1",
        rusqlite::params![mid.0.as_slice()],
    )
    .unwrap();
    for (n, (own, status)) in rows.iter().enumerate() {
        conn.execute(
            "INSERT INTO deliveries(message_id, packet_id, device, status, own) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                mid.0.as_slice(),
                [u8::try_from(n).unwrap(); 16].as_slice(),
                [7u8; 32].as_slice(),
                status,
                own
            ],
        )
        .unwrap();
    }
    delivery::recompute_message_status(&p.a.store, mid).unwrap();
    status_of(&p.a, &bob, body)
}

#[test]
fn recompute_precedence_of_contact_deliveries() {
    let mut p = settled_pair();
    p.a.send_text(&p.b.fingerprint(), "mix", NOW, &mut p.rng)
        .unwrap();
    let cases: [(&[(i64, i64)], MessageStatus); 6] = [
        (&[(0, 3), (0, 1)], MessageStatus::Received),
        (&[(0, 1), (0, 0)], MessageStatus::OnNetwork),
        (&[(0, 1), (0, 5)], MessageStatus::OnNetwork),
        (&[(0, 0), (0, 5)], MessageStatus::Pending),
        (&[(0, 5), (0, 5)], MessageStatus::NotDelivered),
        // My own copy received never makes the message received.
        (&[(1, 3), (0, 5)], MessageStatus::NotDelivered),
    ];
    for (rows, want) in cases {
        assert_eq!(recompute_with(&mut p, "mix", rows), want, "{rows:?}");
    }
}

#[test]
fn ack_is_taken_a_day_past_its_expiry() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "late-ack", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(sent[0].id, NODE, NOW).unwrap();
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    let ack_expiry = u64::from(ack.expires_at);
    // Beyond the grace: expired.
    let mut q = settled_pair();
    let other =
        q.a.send_text(&q.b.fingerprint(), "too-late", NOW, &mut q.rng)
            .unwrap();
    let late = match q
        .b
        .receive(&other[0].encode(), "t", NOW, &mut q.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    let late_expiry = u64::from(late.expires_at);
    assert!(matches!(
        q.a.receive(
            &late.encode(),
            "t",
            late_expiry + ACK_GRACE_SECS + 1,
            &mut q.rng
        )
        .unwrap(),
        ReceiveOutcome::Expired
    ));
    // Within the grace: the delivery is proven.
    assert!(matches!(
        p.a.receive(
            &ack.encode(),
            "t",
            ack_expiry + ACK_GRACE_SECS - 3_600,
            &mut p.rng
        )
        .unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert_eq!(status_of(&p.a, &bob, "late-ack"), MessageStatus::Received);
}

#[test]
fn ack_with_an_early_expiry_is_bounded_by_the_message() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "early-ack", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(sent[0].id, NODE, NOW).unwrap();
    let message_expiry = u64::from(sent[0].expires_at);
    // Bob's clock is 10 hours behind: his receipt expires well before the
    // message.
    let ack = match p
        .b
        .receive(&sent[0].encode(), "t", NOW - 10 * 3_600, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    assert!(u64::from(ack.expires_at) + 9 * 3_600 < message_expiry);
    // Past the receipt's own expiry plus the grace, within the message's:
    // the nodes still serve it, and it still proves the delivery.
    let at = message_expiry + ACK_GRACE_SECS - 3_600;
    assert!(u64::from(ack.expires_at) + ACK_GRACE_SECS < at);
    let mut q_rng = StdRng::seed_from_u64(5);
    // Beyond the message's expiry plus the grace: expired.
    assert!(matches!(
        p.a.receive(
            &ack.encode(),
            "t",
            message_expiry + ACK_GRACE_SECS + 1,
            &mut q_rng
        )
        .unwrap(),
        ReceiveOutcome::Expired
    ));
    assert!(matches!(
        p.a.receive(&ack.encode(), "t", at, &mut q_rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert_eq!(status_of(&p.a, &bob, "early-ack"), MessageStatus::Received);
}

// --- Lot M, task 3: deletion, tombstones.

/// Deliveries of the message `message_id`, as `(own, status)`, own last.
fn deliveries_of(c: &Core, message_id: MessageId) -> Vec<(i64, i64)> {
    let mut stmt = c
        .store
        .conn()
        .prepare("SELECT own, status FROM deliveries WHERE message_id = ?1 ORDER BY own, status")
        .unwrap();
    stmt.query_map(rusqlite::params![message_id.0.as_slice()], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

fn message_id_of(c: &Core, contact: &Fingerprint, body: &str) -> MessageId {
    c.messages_with(contact, NOW)
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
        .message_id
}

fn has_message(c: &Core, contact: &Fingerprint, body: &str) -> bool {
    c.messages_with(contact, NOW)
        .unwrap()
        .iter()
        .any(|m| m.body == body)
}

fn tombstones(c: &Core) -> i64 {
    c.store
        .conn()
        .query_row("SELECT count(*) FROM deleted_messages", [], |r| r.get(0))
        .unwrap()
}

fn route_steps_of(c: &Core, packet: PacketId) -> i64 {
    c.store
        .conn()
        .query_row(
            "SELECT count(*) FROM route_steps WHERE packet_id = ?1",
            rusqlite::params![packet.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn delete_pending_cancels_and_drops_own_copies() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "never", NOW, &mut rng).unwrap();
    // Bob's device first, then the copy for my tablet.
    assert_eq!(sent.len(), 2);
    let mid = message_id_of(&a, &bob, "never");
    let row = row_of(&a, &bob, "never");
    assert_eq!(route_steps_of(&a, sent[0].id), 1);
    let outcome = a.delete_message(row, NOW + 5, &mut rng).unwrap().0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            cancelled: 1,
            // Bob's one device; the copy for my tablet is not counted.
            devices_left: 0,
            devices_total: 1,
            ..DeleteOutcome::default()
        }
    );
    assert!(!has_message(&a, &bob, "never"));
    // Nobody receives it: neither Bob nor my tablet.
    assert!(deliveries_of(&a, mid).is_empty());
    for p in &sent {
        assert_eq!(outbox_row(&a, p.id), None);
        assert_eq!(route_steps_of(&a, p.id), 0);
    }
    assert!(a.awaited_ack_mailboxes(NOW + 5).unwrap().is_empty());
    assert_eq!(tombstones(&a), 1);
}

#[test]
fn delete_after_deposit_reports_already_left() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "gone", NOW, &mut rng).unwrap();
    let mid = message_id_of(&a, &bob, "gone");
    a.record_deposit(sent[0].id, NODE, NOW + 1).unwrap();
    let outcome = a
        .delete_message(row_of(&a, &bob, "gone"), NOW + 5, &mut rng)
        .unwrap()
        .0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            already_left: 1,
            still_receiving: vec![bob],
            own_copies_kept: true,
            devices_left: 1,
            devices_total: 1,
            ..DeleteOutcome::default()
        }
    );
    assert!(!has_message(&a, &bob, "gone"));
    // Bob receives it all the same: its packet stays queued (redeposited
    // if lost) and the copy for my tablet keeps going.
    assert_eq!(outbox_row(&a, sent[0].id), Some(Some(i(NOW + 1))));
    assert_eq!(outbox_row(&a, sent[1].id), Some(None));
    assert_eq!(deliveries_of(&a, mid), vec![(0, 1), (1, 0)]);
    // No ack subscription is left for a message that is gone.
    assert!(a.awaited_ack_mailboxes(NOW + 5).unwrap().is_empty());
}

#[test]
fn kept_delivery_of_a_deleted_message_settles() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let acked = p.a.send_text(&bob, "acked", NOW, &mut p.rng).unwrap();
    let lost = p.a.send_text(&bob, "lost", NOW, &mut p.rng).unwrap();
    for s in [&acked, &lost] {
        p.a.record_deposit(s[0].id, NODE, NOW).unwrap();
    }
    let rows = [row_of(&p.a, &bob, "acked"), row_of(&p.a, &bob, "lost")];
    assert_eq!(
        p.a.delete_messages(&rows, NOW + 1, &mut p.rng)
            .unwrap()
            .0
            .already_left,
        2
    );
    // The ack still clears its packet from the queue.
    let ack = match p
        .b
        .receive(&acked[0].encode(), "t", NOW, &mut p.rng)
        .unwrap()
    {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    assert!(matches!(
        p.a.receive(&ack.encode(), "t", NOW + 2, &mut p.rng)
            .unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    assert_eq!(outbox_row(&p.a, acked[0].id), None);
    assert_eq!(delivery_state(&p.a, acked[0].id).0, 3);
    // The other still gets its verdict, without a failure notice for a
    // message that no longer exists.
    let expiry = u64::from(lost[0].expires_at);
    assert_eq!(
        p.a.awaiting_verdict(expiry).unwrap(),
        vec![(lost[0].id, lost[0].mailbox)]
    );
    assert!(p.a.confirm_expired(lost[0].id, expiry + 1).unwrap());
    assert_eq!(outbox_row(&p.a, lost[0].id), None);
    assert!(p.a.awaiting_verdict(expiry + 1).unwrap().is_empty());
    assert!(p.a.take_failed_notices().is_empty());
}

#[test]
fn delete_mixed_devices_is_partly_cancelled() {
    let (_d, a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    // Alice has two devices: one packet each.
    let sent = b.send_text(&alice, "half", NOW, &mut rng).unwrap();
    assert_eq!(sent.len(), 2);
    let mid = message_id_of(&b, &alice, "half");
    b.record_deposit(sent[0].id, NODE, NOW).unwrap();
    let outcome = b
        .delete_message(row_of(&b, &alice, "half"), NOW + 5, &mut rng)
        .unwrap()
        .0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            partly_cancelled: 1,
            still_receiving: vec![alice],
            devices_left: 1,
            devices_total: 2,
            ..DeleteOutcome::default()
        }
    );
    assert_eq!(deliveries_of(&b, mid), vec![(0, 1)]);
    assert!(outbox_row(&b, sent[0].id).is_some());
    assert_eq!(outbox_row(&b, sent[1].id), None);
}

#[test]
fn delete_not_delivered_drops_its_deliveries() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "late", NOW, &mut p.rng).unwrap();
    let mid = message_id_of(&p.a, &bob, "late");
    p.a.expire_due(u64::from(sent[0].expires_at) + 1).unwrap();
    assert_eq!(status_of(&p.a, &bob, "late"), MessageStatus::NotDelivered);
    let row = row_of(&p.a, &bob, "late");
    let outcome =
        p.a.delete_message(row, NOW + DAY_SECS, &mut p.rng)
            .unwrap()
            .0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            ..DeleteOutcome::default()
        }
    );
    assert!(deliveries_of(&p.a, mid).is_empty());
    // Gone already: nothing more.
    assert_eq!(
        p.a.delete_message(row, NOW + DAY_SECS, &mut p.rng)
            .unwrap()
            .0,
        DeleteOutcome::default()
    );
}

const DAY_SECS: u64 = 86_400;

#[test]
fn delete_received_message_keeps_inbound() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let first =
        p.a.send_text(&b_fp, "read-me", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let ack = match p.b.receive(&first.encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    let row = row_of(&p.b, &a_fp, "read-me");
    let outcome = p.b.delete_message(row, NOW + 1, &mut p.rng).unwrap().0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            ..DeleteOutcome::default()
        }
    );
    assert!(!has_message(&p.b, &a_fp, "read-me"));
    // The pending ack still leaves; the packet stays known.
    assert!(outbox_row(&p.b, ack.id).is_some());
    let inbound: i64 =
        p.b.store
            .conn()
            .query_row(
                "SELECT count(*) FROM inbound WHERE packet_id = ?1",
                rusqlite::params![first.id.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(inbound, 1);
    // The contact resends it (same identifier, new packet): it stays gone,
    // and is acked.
    let mid = message_id_of(&p.a, &b_fp, "read-me");
    let again = seal_body(
        &mut p.a,
        &send::Target::Contact(b_fp),
        &Body::Text("read-me".into()),
        mid,
        &mut p.rng,
    )
    .remove(0)
    .0;
    assert!(matches!(
        p.b.receive(&again.encode(), "t", NOW + 2, &mut p.rng)
            .unwrap(),
        ReceiveOutcome::Duplicate
    ));
    assert!(!has_message(&p.b, &a_fp, "read-me"));
}

#[test]
fn cancel_all_pending_touches_only_pending_messages() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    p.a.send_text(&bob, "p1", NOW, &mut p.rng).unwrap();
    p.a.send_text(&bob, "p2", NOW, &mut p.rng).unwrap();
    let dep = p.a.send_text(&bob, "dep", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(dep[0].id, NODE, NOW).unwrap();
    let got = p.a.send_text(&bob, "got", NOW, &mut p.rng).unwrap();
    let ack = match p.b.receive(&got[0].encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { ack, .. } => ack,
        o => panic!("{o:?}"),
    };
    p.a.receive(&ack.encode(), "t", NOW, &mut p.rng).unwrap();
    let before = p.a.messages_with(&bob, NOW).unwrap().len();
    let outcome = p.a.cancel_all_pending(NOW + 10, &mut p.rng).unwrap().0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 2,
            cancelled: 2,
            ..DeleteOutcome::default()
        }
    );
    let left: Vec<String> =
        p.a.messages_with(&bob, NOW)
            .unwrap()
            .into_iter()
            .map(|m| m.body)
            .collect();
    assert_eq!(left.len(), before - 2);
    assert!(!left.contains(&"p1".to_string()) && !left.contains(&"p2".to_string()));
    for body in ["x", "y", "dep", "got"] {
        assert!(left.contains(&body.to_string()), "{body}");
    }
    // Nothing more to cancel.
    assert_eq!(
        p.a.cancel_all_pending(NOW + 10, &mut p.rng).unwrap().0,
        DeleteOutcome::default()
    );
}

#[test]
fn tombstones_kept_for_good() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let first =
        p.a.send_text(&b_fp, "brief", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    p.b.receive(&first.encode(), "t", NOW, &mut p.rng).unwrap();
    p.b.delete_message(row_of(&p.b, &a_fp, "brief"), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(tombstones(&p.b), 1);
    // Weeks of log activity (the log's purge clock advances by two days
    // at most per entry): the tombstone stays, a retry may come any time.
    for k in 0..30 {
        p.b.send_text(&a_fp, "later", NOW + k * DAY_SECS, &mut p.rng)
            .unwrap();
    }
    assert_eq!(tombstones(&p.b), 1);
}

#[test]
fn delete_after_unconfirmed_deposit_reports_already_left() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "maybe", NOW, &mut rng).unwrap();
    let mid = message_id_of(&a, &bob, "maybe");
    // A deposit request left for Bob's packet; its answer never came: a
    // node may hold it.
    a.record_deposit_tried(sent[0].id, NOW + 1).unwrap();
    a.record_deposit_tried(sent[0].id, NOW + 2).unwrap();
    let tried: Option<i64> = a
        .store
        .conn()
        .query_row(
            "SELECT deposit_tried_at FROM outbox WHERE packet_id = ?1",
            rusqlite::params![sent[0].id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tried, Some(i(NOW + 1)));
    assert_eq!(delivery_state(&a, sent[0].id).0, 0);
    let outcome = a
        .delete_message(row_of(&a, &bob, "maybe"), NOW + 5, &mut rng)
        .unwrap()
        .0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            already_left: 1,
            still_receiving: vec![bob],
            own_copies_kept: true,
            // A tried deposit may have reached a node: it counts as left.
            devices_left: 1,
            devices_total: 1,
            ..DeleteOutcome::default()
        }
    );
    // Its packet keeps going, and so does the copy for my tablet.
    assert!(outbox_row(&a, sent[0].id).is_some());
    assert!(outbox_row(&a, sent[1].id).is_some());
    assert_eq!(deliveries_of(&a, mid), vec![(0, 0), (1, 0)]);
    // An unknown packet is ignored.
    a.record_deposit_tried(PacketId([9; 16]), NOW).unwrap();
}

#[test]
fn tried_own_copy_is_kept_when_nobody_receives() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "copy tried", NOW, &mut rng).unwrap();
    a.record_deposit_tried(sent[1].id, NOW + 1).unwrap();
    let outcome = a
        .delete_message(row_of(&a, &bob, "copy tried"), NOW + 5, &mut rng)
        .unwrap()
        .0;
    assert_eq!(
        outcome,
        DeleteOutcome {
            deleted: 1,
            cancelled: 1,
            own_copies_kept: true,
            devices_left: 0,
            devices_total: 1,
            ..DeleteOutcome::default()
        }
    );
    assert_eq!(outbox_row(&a, sent[0].id), None);
    assert!(outbox_row(&a, sent[1].id).is_some());
}

#[test]
fn a_tried_deposit_counts_in_devices_tried() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "tried", NOW, &mut rng).unwrap();
    let row = row_of(&a, &bob, "tried");
    let summary = |a: &mut Core| a.deliveries_of(&[row], NOW + 3).unwrap()[0].1.unwrap();
    assert_eq!(summary(&mut a).devices_tried, 0);
    // The request was sent, its answer lost: the packet may be on a node.
    a.record_deposit_tried(sent[0].id, NOW + 1).unwrap();
    let s = summary(&mut a);
    assert_eq!(
        (s.devices_tried, s.devices_left, s.devices_pending),
        (1, 0, 1)
    );
    assert_eq!(s.state, MessageStatus::Pending, "the state stays Pending");
    let detail = a.message_delivery(row, NOW + 3).unwrap().unwrap();
    assert_eq!(detail.summary.devices_tried, 1);
    let rows = a.messages_with_delivery(&bob, NOW + 3).unwrap();
    assert_eq!(rows[0].1.unwrap().devices_tried, 1);
    let pending = a.pending_packets(NOW + 3).unwrap();
    assert_eq!(pending.messages[0].devices_tried, 1);
    assert_eq!(pending.messages[0].devices_left, 0);
}

#[test]
fn delete_event_has_no_content() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    p.a.send_text(&bob, "secret words", NOW, &mut p.rng)
        .unwrap();
    let dep = p.a.send_text(&bob, "other words", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(dep[0].id, NODE, NOW).unwrap();
    let rows = [
        row_of(&p.a, &bob, "secret words"),
        row_of(&p.a, &bob, "other words"),
    ];
    p.a.delete_messages(&rows, NOW + 1, &mut p.rng).unwrap();
    let (_, last) = p.a.transparency_log(1).unwrap().remove(0);
    assert_eq!(
        last,
        TransparencyEvent::MessagesDeleted {
            count: 2,
            cancelled: 1,
            already_left: 1,
            from_other_device: false,
        }
    );
    assert!(!last.is_security());
    let text = last.describe();
    assert!(!text.contains("words") && !text.contains("bob"), "{text}");
    let bytes: Vec<u8> =
        p.a.store
            .conn()
            .query_row(
                "SELECT event FROM transparency ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(!bytes.windows(5).any(|w| w == b"words"));
    assert!(!bytes.windows(32).any(|w| w == bob.0.as_slice()));
    // Nothing deleted, nothing logged.
    let n = p.a.transparency_log(10_000).unwrap().len();
    p.a.delete_messages(&rows, NOW + 2, &mut p.rng).unwrap();
    assert_eq!(p.a.transparency_log(10_000).unwrap().len(), n);
}

#[test]
fn tombstone_blocks_history_import() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(31);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let (c, _) = Core::create(&dir.path().join("c"), &[3; 32], "c", NOW, &mut rng).unwrap();
    let c_fp = a
        .add_contact(&c.contact_card("C").unwrap(), Some("c"), NOW, &mut rng)
        .unwrap();
    a.send_text(&c_fp, "kept", NOW, &mut rng).unwrap();
    a.send_text(&c_fp, "deleted", NOW, &mut rng).unwrap();
    let deleted = message_id_of(&a, &c_fp, "deleted");
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, true, NOW, &mut rng).unwrap();
    // T already deleted that message (its tombstone is there): the
    // archive does not bring it back.
    t.store
        .conn()
        .execute(
            "INSERT INTO deleted_messages(message_id, at) VALUES (?1, ?2)",
            rusqlite::params![deleted.0.as_slice(), i(NOW)],
        )
        .unwrap();
    t.finish_link(&out.bundle, out.history.as_ref(), NOW + 1)
        .unwrap();
    assert!(has_message(&t, &c_fp, "kept"));
    assert!(!has_message(&t, &c_fp, "deleted"));
    assert!(
        t.transparency_log(10)
            .unwrap()
            .iter()
            .any(|(_, e)| *e == TransparencyEvent::HistoryImported { count: 1 })
    );
}

// --- Lot M, task 4: delivery queries, pending packets, noted changes.

use crate::store::{
    DeliverySummary, DeviceDeliveryRow, OwnCopies, PendingKind, PendingMessage, PendingPackets,
    PendingSync, RelayHop,
};

/// The receipt `to` emits on receiving `packet`, if it opens it.
fn ack_from(to: &mut Core, packet: &Packet, rng: &mut StdRng) -> Option<Packet> {
    ack_at(to, packet, NOW, rng)
}

/// `ack_from`, received at `now`.
fn ack_at(to: &mut Core, packet: &Packet, now: u64, rng: &mut StdRng) -> Option<Packet> {
    match to.receive(&packet.encode(), "t", now, rng).unwrap() {
        ReceiveOutcome::Message { ack, .. } => Some(ack),
        _ => None,
    }
}

/// The packet a receipt acknowledges.
fn acked_by(ack: &Packet) -> PacketId {
    PacketId(ack.payload[..16].try_into().unwrap())
}

fn tier_size(p: &Packet) -> u32 {
    u32::try_from(p.tier.size()).unwrap()
}

#[test]
fn summary_counts_devices_per_state() {
    let (_d, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    // Alice has two devices: one packet each.
    let sent = b.send_text(&alice, "two", NOW, &mut rng).unwrap();
    assert_eq!(sent.len(), 2);
    let ack = sent
        .iter()
        .find_map(|p| ack_from(&mut a, p, &mut rng))
        .unwrap();
    let other = sent.iter().find(|p| p.id != acked_by(&ack)).unwrap();
    assert!(matches!(
        b.receive(&ack.encode(), "t", NOW + 4, &mut rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    let row = row_of(&b, &alice, "two");
    let received = DeliverySummary {
        state: MessageStatus::Received,
        sealed_at: NOW,
        deposited_at: None,
        received_at: Some(NOW + 4),
        expired_at: None,
        devices: 2,
        devices_received: 1,
        devices_left: 1,
        devices_tried: 0,
        devices_pending: 1,
        awaiting_verdict: false,
    };
    let rows = b.messages_with_delivery(&alice, NOW + 5).unwrap();
    let (m, summary) = rows.iter().find(|(m, _)| m.id == row).unwrap();
    assert_eq!(m.body, "two");
    assert_eq!(*summary, Some(received));
    assert_eq!(
        b.deliveries_of(&[row, 9_999], NOW + 5).unwrap(),
        vec![(row, Some(received))],
        "an unknown or deleted row is left out"
    );
    // The other device's packet reaches a node.
    b.record_deposit(other.id, NODE, NOW + 6).unwrap();
    let detail = b.message_delivery(row, NOW + 7).unwrap().unwrap();
    assert_eq!(detail.row_id, row);
    assert_eq!(detail.contact, alice);
    assert_eq!(
        detail.summary,
        DeliverySummary {
            deposited_at: Some(NOW + 6),
            devices_left: 2,
            devices_pending: 0,
            awaiting_verdict: true,
            ..received
        }
    );
    assert_eq!(detail.deliveries.len(), 2);
    assert!(detail.deliveries.iter().all(|d| !d.own));
    let deposited: Vec<&DeviceDeliveryRow> = detail
        .deliveries
        .iter()
        .filter(|d| d.state == MessageStatus::OnNetwork)
        .collect();
    assert_eq!(deposited.len(), 1);
    assert_eq!(deposited[0].node.as_deref(), Some(NODE));
    assert_eq!(deposited[0].deposited_at, Some(NOW + 6));
    assert_eq!(deposited[0].size, Some(tier_size(other)));
    assert_eq!(
        detail.relays,
        vec![RelayHop {
            node: NODE.into(),
            at: NOW + 6,
            size: tier_size(other),
        }]
    );
    // Bob has no other device: no copy.
    assert_eq!(detail.own_copies, OwnCopies::default());
}

#[test]
fn detail_counts_own_copies_and_falls_back_to_delivery_nodes() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "copied", NOW, &mut rng).unwrap();
    // Bob's device first, then the copy for my tablet.
    a.record_deposit(sent[0].id, NODE, NOW + 1).unwrap();
    a.record_deposit(sent[0].id, "B2C4D6F8", NOW + 2).unwrap();
    let row = row_of(&a, &bob, "copied");
    let detail = a.message_delivery(row, NOW + 3).unwrap().unwrap();
    assert_eq!(
        detail.own_copies,
        OwnCopies {
            total: 1,
            left: 0,
            waiting: 1
        }
    );
    assert_eq!(
        detail.deliveries.iter().map(|d| d.own).collect::<Vec<_>>(),
        vec![false, true]
    );
    // Two relays from the route, in order.
    let nodes: Vec<String> = detail.relays.iter().map(|r| r.node.clone()).collect();
    assert_eq!(nodes, vec![NODE.to_string(), "B2C4D6F8".to_string()]);
    // Route steps purged (30 days): the delivery's first node remains.
    a.store
        .conn()
        .execute("DELETE FROM route_steps", [])
        .unwrap();
    let detail = a.message_delivery(row, NOW + 3).unwrap().unwrap();
    assert_eq!(
        detail.relays,
        vec![RelayHop {
            node: NODE.into(),
            at: NOW + 1,
            size: tier_size(&sent[0]),
        }]
    );
}

#[test]
fn message_from_another_device_has_no_summary() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "elsewhere", NOW, &mut rng).unwrap();
    // The sender knows its delivery.
    let a_row = row_of(&a, &bob, "elsewhere");
    assert!(a.deliveries_of(&[a_row], NOW).unwrap()[0].1.is_some());
    // My tablet gets the copy: sent from another device, no delivery known.
    assert!(matches!(
        t.receive(&sent[1].encode(), "t", NOW, &mut rng).unwrap(),
        ReceiveOutcome::Synced { .. }
    ));
    let row = row_of(&t, &bob, "elsewhere");
    let rows = t.messages_with_delivery(&bob, NOW).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0.id, row);
    assert_eq!(rows[0].1, None);
    assert_eq!(t.deliveries_of(&[row], NOW).unwrap(), vec![(row, None)]);
    assert_eq!(t.message_delivery(row, NOW).unwrap(), None);
    assert_eq!(t.delivery_counts(&bob, NOW).unwrap(), [0; 4]);
    // A received message has none either.
    assert!(ack_from(&mut b, &sent[0], &mut rng).is_some());
    let b_row = row_of(&b, &alice, "elsewhere");
    let rows = b.messages_with_delivery(&alice, NOW).unwrap();
    assert_eq!(rows.iter().find(|(m, _)| m.id == b_row).unwrap().1, None);
    assert_eq!(b.message_delivery(b_row, NOW).unwrap(), None);
}

fn bodies(page: &[(MessageRow, DeliverySummary)]) -> Vec<&str> {
    page.iter().map(|(m, _)| m.body.as_str()).collect()
}

#[test]
fn counts_and_pages_ignore_messages_without_contact_delivery() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    // "x" (received by Bob) and "y" (from Bob) come from `pair`. A sent
    // message without any delivery to Bob (imported, or sent from another
    // of my devices) is stored `OnNetwork`.
    p.a.store
        .insert_message(
            bob,
            Direction::Out,
            "imported",
            MessageStatus::OnNetwork,
            NOW + 1,
            MessageId([9; 16]),
        )
        .unwrap();
    for (n, body) in ["p1", "p2", "p3"].into_iter().enumerate() {
        let at = NOW + 10 + u64::try_from(n).unwrap();
        p.a.send_text(&bob, body, at, &mut p.rng).unwrap();
    }
    let dep = p.a.send_text(&bob, "dep", NOW + 20, &mut p.rng).unwrap();
    p.a.record_deposit(dep[0].id, NODE, NOW + 21).unwrap();
    assert_eq!(p.a.delivery_counts(&bob, NOW + 30).unwrap(), [3, 1, 1, 0]);
    let page =
        p.a.delivery_page(&bob, MessageStatus::OnNetwork, 50, 0, NOW + 30)
            .unwrap();
    assert_eq!(bodies(&page), vec!["dep"]);
    assert_eq!(page[0].1.deposited_at, Some(NOW + 21));
    let page =
        p.a.delivery_page(&bob, MessageStatus::Received, 50, 0, NOW + 30)
            .unwrap();
    assert_eq!(bodies(&page), vec!["x"]);
    // Newest first, by pages.
    let first =
        p.a.delivery_page(&bob, MessageStatus::Pending, 2, 0, NOW + 30)
            .unwrap();
    assert_eq!(bodies(&first), vec!["p3", "p2"]);
    assert!(first.iter().all(|(_, s)| s.devices == 1));
    let second =
        p.a.delivery_page(&bob, MessageStatus::Pending, 2, 2, NOW + 30)
            .unwrap();
    assert_eq!(bodies(&second), vec!["p1"]);
    assert!(
        p.a.delivery_page(&bob, MessageStatus::NotDelivered, 50, 0, NOW + 30)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reads_expire_due_packets_first() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "slept", NOW, &mut p.rng).unwrap();
    let later = u64::from(sent[0].expires_at) + 1;
    // The app slept past the expiry: no sync ran, the read is right.
    let rows = p.a.messages_with_delivery(&bob, later).unwrap();
    let (m, summary) = rows.iter().find(|(m, _)| m.body == "slept").unwrap();
    assert_eq!(m.status, MessageStatus::NotDelivered);
    let summary = summary.unwrap();
    assert_eq!(summary.state, MessageStatus::NotDelivered);
    assert_eq!(summary.expired_at, Some(u64::from(sent[0].expires_at)));
    assert_eq!(summary.devices_pending, 0);
    assert_eq!(p.a.delivery_counts(&bob, later).unwrap(), [0, 0, 1, 1]);
}

/// Alice (with a tablet) and Bob, with one pending packet of each sort on
/// Alice's side, plus packets that are not pending. Returns the Bob
/// message's packets.
fn pending_scene() -> (TempDir, Core, Fingerprint, Vec<Packet>, StdRng) {
    let (d, mut a, _t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    // An ack for a message from Bob (its reference leads to Bob).
    let from_bob = b.send_text(&alice, "hi", NOW, &mut rng).unwrap();
    assert!(
        from_bob
            .iter()
            .filter_map(|p| ack_from(&mut a, p, &mut rng))
            .count()
            == 1
    );
    // An ack queued before the migration: no reference.
    let old_ack = Packet {
        kind: Kind::Ack,
        hops: DEFAULT_HOPS,
        tier: Tier::fit(32).unwrap(),
        id: PacketId([0xAB; 16]),
        expires_at: u32::try_from(NOW + DAY_SECS).unwrap(),
        mailbox: from_bob[0].mailbox,
        payload: vec![0; 32],
    };
    a.store
        .outbox_put(
            old_ack.id,
            &old_ack.encode(),
            Kind::Ack,
            NOW + DAY_SECS,
            NOW,
            None,
        )
        .unwrap();
    // A message: Bob's packet and the copy for my tablet.
    let sent = a.send_text(&bob, "m", NOW, &mut rng).unwrap();
    assert_eq!(sent.len(), 2);
    // Synchronisation for my tablet without a message.
    a.mark_verified(&bob, NOW, &mut rng).unwrap();
    // Not pending: a message already deposited.
    let dep = a.send_text(&bob, "dep", NOW, &mut rng).unwrap();
    a.record_deposit(dep[0].id, NODE, NOW).unwrap();
    a.record_deposit(dep[1].id, NODE, NOW).unwrap();
    // A message deleted after its packet to Bob left: its copy for my
    // tablet keeps going, without a row.
    let kept = a.send_text(&bob, "kept", NOW, &mut rng).unwrap();
    a.record_deposit(kept[0].id, NODE, NOW).unwrap();
    let row = row_of(&a, &bob, "kept");
    assert!(
        a.delete_message(row, NOW, &mut rng)
            .unwrap()
            .0
            .own_copies_kept
    );
    (d, a, bob, sent, rng)
}

#[test]
fn pending_kinds_are_classified() {
    let (_d, mut a, bob, sent, _rng) = pending_scene();
    let pending = a.pending_packets(NOW + 1).unwrap();
    assert_eq!(
        pending.messages,
        vec![PendingMessage {
            row_id: row_of(&a, &bob, "m"),
            contact: bob,
            body: "m".into(),
            gif: false,
            sealed_at: NOW,
            expires_at: u64::from(sent[0].expires_at),
            packets: 1,
            devices: 1,
            devices_left: 0,
            devices_tried: 0,
        }]
    );
    assert_eq!(
        pending.sync,
        vec![
            // With and without a reference.
            PendingSync {
                kind: PendingKind::Ack,
                packets: 2,
                contacts: vec![bob],
            },
            // The copy of "m" and that of the deleted "kept".
            PendingSync {
                kind: PendingKind::OwnCopy,
                packets: 2,
                contacts: vec![bob],
            },
            // The verification, and the deletion of "kept" for my tablet.
            PendingSync {
                kind: PendingKind::DeviceSync,
                packets: 2,
                contacts: vec![],
            },
            // The card update sent to Bob when the tablet was linked.
            PendingSync {
                kind: PendingKind::CardUpdate,
                packets: 1,
                contacts: vec![bob],
            },
        ]
    );
    assert_eq!(pending.packets, 8);
}

#[test]
fn pending_count_equals_screen_total() {
    let (_d, mut a, _bob, sent, _rng) = pending_scene();
    let total = |p: &PendingPackets| -> u32 {
        p.messages.iter().map(|m| m.packets).sum::<u32>()
            + p.sync.iter().map(|s| s.packets).sum::<u32>()
    };
    let pending = a.pending_packets(NOW + 1).unwrap();
    assert!(pending.packets > 0);
    assert_eq!(total(&pending), pending.packets);
    assert_eq!(a.pending_count(NOW + 1).unwrap(), pending.packets);
    // Past every expiry, the deposited packets still await their verdict
    // in the queue, yet nothing is pending.
    let later = u64::from(sent[0].expires_at) + DAY_SECS;
    let pending = a.pending_packets(later).unwrap();
    assert_eq!(pending, PendingPackets::default());
    assert_eq!(a.pending_count(later).unwrap(), 0);
    assert!(!a.awaiting_verdict(later).unwrap().is_empty());
}

#[test]
fn deposited_packets_and_deposited_acks_are_not_pending() {
    let mut p = pair();
    let alice = p.a.fingerprint();
    let bob = p.b.fingerprint();
    // Everything Bob queued while setting up reaches a node.
    for bytes in p.b.pending_outbox(NOW).unwrap() {
        let id = Packet::decode(&bytes).unwrap().id;
        p.b.record_deposit(id, NODE, NOW).unwrap();
    }
    assert_eq!(p.b.pending_count(NOW).unwrap(), 0);
    let sent = p.b.send_text(&alice, "out", NOW, &mut p.rng).unwrap();
    let from_alice = p.a.send_text(&bob, "in", NOW, &mut p.rng).unwrap();
    let ack = ack_from(&mut p.b, &from_alice[0], &mut p.rng).unwrap();
    let before = p.b.pending_packets(NOW).unwrap();
    assert_eq!(before.messages.len(), 1);
    assert_eq!(before.sync.len(), 1);
    assert_eq!(before.sync[0].kind, PendingKind::Ack);
    assert_eq!(p.b.pending_count(NOW).unwrap(), 2);
    p.b.record_deposit(ack.id, NODE, NOW).unwrap();
    let after = p.b.pending_packets(NOW).unwrap();
    assert!(after.sync.is_empty());
    assert_eq!(after.messages.len(), 1);
    p.b.record_deposit(sent[0].id, NODE, NOW).unwrap();
    assert_eq!(p.b.pending_packets(NOW).unwrap(), PendingPackets::default());
    assert_eq!(p.b.pending_count(NOW).unwrap(), 0);
}

#[test]
fn every_state_change_is_noted_once() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    p.a.take_delivery_changes();
    // A new message is not a state change.
    let s1 = p.a.send_text(&bob, "s1", NOW, &mut p.rng).unwrap();
    let r1 = row_of(&p.a, &bob, "s1");
    assert!(p.a.take_delivery_changes().is_empty());
    // Deposit, once.
    p.a.record_deposit(s1[0].id, NODE, NOW + 1).unwrap();
    p.a.record_deposit(s1[0].id, NODE, NOW + 2).unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r1)]);
    assert!(p.a.take_delivery_changes().is_empty());
    // Ack.
    let ack = ack_from(&mut p.b, &s1[0], &mut p.rng).unwrap();
    p.a.receive(&ack.encode(), "t", NOW + 3, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r1)]);
    // A replayed ack changes nothing.
    p.a.receive(&ack.encode(), "t", NOW + 4, &mut p.rng)
        .unwrap();
    assert!(p.a.take_delivery_changes().is_empty());
    // Expiry before deposit, then the retry.
    let s2 = p.a.send_text(&bob, "s2", NOW, &mut p.rng).unwrap();
    let r2 = row_of(&p.a, &bob, "s2");
    let e2 = u64::from(s2[0].expires_at) + 1;
    p.a.expire_due(e2).unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r2)]);
    p.a.retry_message(r2, e2, &mut p.rng).unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r2)]);
    // Confirmed failure after a deposit.
    let s3 = p.a.send_text(&bob, "s3", e2, &mut p.rng).unwrap();
    let r3 = row_of(&p.a, &bob, "s3");
    p.a.record_deposit(s3[0].id, NODE, e2).unwrap();
    p.a.take_delivery_changes();
    let e3 = u64::from(s3[0].expires_at) + 1;
    assert!(p.a.confirm_expired(s3[0].id, e3).unwrap());
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r3)]);
    // Undeliverable packet.
    let s4 = p.a.send_text(&bob, "s4", e2, &mut p.rng).unwrap();
    let r4 = row_of(&p.a, &bob, "s4");
    assert!(p.a.drop_outbox_packet(&s4[0].encode(), e2).unwrap());
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r4)]);
    // Deletions: one change per deleted message.
    p.a.delete_messages(&[r1, r2, r4], e2, &mut p.rng).unwrap();
    assert_eq!(
        p.a.take_delivery_changes(),
        vec![(bob, r1), (bob, r2), (bob, r4)]
    );
    // Several changes of one message between two takes: noted once.
    let s5 = p.a.send_text(&bob, "s5", e2, &mut p.rng).unwrap();
    let r5 = row_of(&p.a, &bob, "s5");
    p.a.record_deposit(s5[0].id, NODE, e2).unwrap();
    let ack = ack_at(&mut p.b, &s5[0], e2, &mut p.rng).unwrap();
    p.a.receive(&ack.encode(), "t", e2, &mut p.rng).unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r5)]);
    // An expiry found by a read, outside any sync.
    let s6 = p.a.send_text(&bob, "s6", e2, &mut p.rng).unwrap();
    let r6 = row_of(&p.a, &bob, "s6");
    let e6 = u64::from(s6[0].expires_at) + 1;
    p.a.delivery_counts(&bob, e6).unwrap();
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r6)]);
    assert!(p.a.take_delivery_changes().is_empty());
    // Kept packets of deleted messages settle without a change: no row.
    let s7 = p.a.send_text(&bob, "s7", e6, &mut p.rng).unwrap();
    let s8 = p.a.send_text(&bob, "s8", e6, &mut p.rng).unwrap();
    for s in [&s7, &s8] {
        p.a.record_deposit(s[0].id, NODE, e6).unwrap();
    }
    let rows = [row_of(&p.a, &bob, "s7"), row_of(&p.a, &bob, "s8")];
    p.a.delete_messages(&rows, e6, &mut p.rng).unwrap();
    assert_eq!(
        p.a.take_delivery_changes(),
        vec![(bob, rows[0]), (bob, rows[1])]
    );
    let ack = ack_at(&mut p.b, &s7[0], e6, &mut p.rng).unwrap();
    assert!(matches!(
        p.a.receive(&ack.encode(), "t", e6, &mut p.rng).unwrap(),
        ReceiveOutcome::AckReceived { .. }
    ));
    let e8 = u64::from(s8[0].expires_at) + 1;
    assert!(p.a.confirm_expired(s8[0].id, e8).unwrap());
    assert!(p.a.take_delivery_changes().is_empty());
}

#[test]
fn own_copy_of_a_deleted_message_notes_nothing() {
    let (_d, mut a, _t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "kept", NOW, &mut rng).unwrap();
    a.record_deposit(sent[0].id, NODE, NOW).unwrap();
    let row = row_of(&a, &bob, "kept");
    assert!(
        a.delete_message(row, NOW, &mut rng)
            .unwrap()
            .0
            .own_copies_kept
    );
    assert_eq!(a.take_delivery_changes(), vec![(bob, row)]);
    // The copy for my tablet expires undeposited: no row, no change.
    a.expire_due(u64::from(sent[1].expires_at) + 1).unwrap();
    assert_eq!(delivery_state(&a, sent[1].id).0, 5);
    assert!(a.take_delivery_changes().is_empty());
}

#[test]
fn change_lists_are_bounded() {
    let fp = Fingerprint([3; 32]);
    let mut list = delivery::ChangeList::default();
    let extra = 5;
    let last = i64::try_from(MAX_NOTED_CHANGES + extra).unwrap();
    for row in 1..=last {
        list.push((fp, row));
    }
    // Already listed: neither added again nor moved.
    list.push((fp, last - 1));
    let taken = list.take();
    // The oldest are dropped, each kept once.
    assert_eq!(taken.len(), MAX_NOTED_CHANGES);
    assert_eq!(taken[0], (fp, i64::try_from(extra).unwrap() + 1));
    assert_eq!(taken[MAX_NOTED_CHANGES - 1], (fp, last));
    assert!(list.take().is_empty());
    // Taken entries may be noted again.
    list.push((fp, 1));
    list.retain(|(_, row)| *row != 1);
    list.push((fp, 2));
    assert_eq!(list.take(), vec![(fp, 2)]);
}

#[test]
fn removed_contact_leaves_true_states() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let pend = p.a.send_text(&bob, "pend", NOW, &mut p.rng).unwrap();
    let dep = p.a.send_text(&bob, "dep", NOW, &mut p.rng).unwrap();
    p.a.record_deposit(dep[0].id, NODE, NOW).unwrap();
    // A deposit was tried, its answer lost: a node may hold it.
    let tried = p.a.send_text(&bob, "tried", NOW, &mut p.rng).unwrap();
    p.a.record_deposit_tried(tried[0].id, NOW).unwrap();
    let r_pend = row_of(&p.a, &bob, "pend");
    let r_dep = row_of(&p.a, &bob, "dep");
    p.a.take_delivery_changes();
    p.a.remove_contact(&bob, NOW + 1, &mut p.rng).unwrap();
    // "x" (from `pair`) was received.
    assert_eq!(p.a.delivery_counts(&bob, NOW + 1).unwrap(), [1, 1, 1, 1]);
    assert_eq!(status_of(&p.a, &bob, "pend"), MessageStatus::NotDelivered);
    assert_eq!(delivery_state(&p.a, pend[0].id).3, Some(i(NOW + 1)));
    assert_eq!(p.a.take_delivery_changes(), vec![(bob, r_pend)]);
    assert!(p.a.take_failed_notices().is_empty());
    assert_eq!(outbox_row(&p.a, pend[0].id), None);
    assert_eq!(outbox_row(&p.a, dep[0].id), Some(Some(i(NOW))));
    assert!(outbox_row(&p.a, tried[0].id).is_some());
    let pending = p.a.pending_packets(NOW + 1).unwrap();
    assert_eq!(p.a.pending_count(NOW + 1).unwrap(), pending.packets);
    // The deposited one still gets its verdict.
    let expiry = u64::from(dep[0].expires_at);
    assert!(
        p.a.awaiting_verdict(expiry)
            .unwrap()
            .contains(&(dep[0].id, dep[0].mailbox))
    );
    assert!(p.a.confirm_expired(dep[0].id, expiry + 1).unwrap());
    assert_eq!(status_of(&p.a, &bob, "dep"), MessageStatus::NotDelivered);
    assert!(p.a.take_delivery_changes().contains(&(bob, r_dep)));
    // No notification for a removed contact.
    assert!(p.a.take_failed_notices().is_empty());
}

/// Spec §13: under 50 ms on 10 000 messages, as the app is built
/// (optimized). Meant for a release run:
/// `cargo nextest run -p barking-core --cargo-profile release --run-ignored only
/// -E 'test(summary_query_under_50ms_on_10k_messages)'`. A debug build runs
/// SQLCipher unoptimized (about 3 times slower): the bound is scaled there.
#[test]
#[ignore = "performance check (spec §13), run by hand with --cargo-profile release"]
fn summary_query_under_50ms_on_10k_messages() {
    use std::time::{Duration, Instant};
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    // 10 000 sent messages with two contact deliveries each, written
    // directly (sealing them would take minutes).
    p.a.store
        .transaction(|tx| {
            for n in 0..10_000u32 {
                let mut mid = [0xEE; 16];
                mid[..4].copy_from_slice(&n.to_le_bytes());
                let mid = MessageId(mid);
                tx.insert_message(
                    bob,
                    Direction::Out,
                    "perf",
                    MessageStatus::Pending,
                    NOW + u64::from(n),
                    mid,
                )?;
                for dev in 0..2u8 {
                    let mut pid = [0xEF; 16];
                    pid[..4].copy_from_slice(&n.to_le_bytes());
                    pid[4] = dev;
                    tx.add_delivery(mid, PacketId(pid), DeviceId([dev; 16]), false, NOW, 1024)?;
                }
            }
            Ok(())
        })
        .unwrap();
    let mut times = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let rows = p.a.messages_with_delivery(&bob, NOW).unwrap();
        times.push(start.elapsed());
        assert!(rows.len() > 10_000);
    }
    eprintln!("messages_with_delivery on 10 000 messages: {times:?}");
    let best = *times.iter().min().unwrap();
    let bound = if cfg!(debug_assertions) { 150 } else { 50 };
    assert!(best < Duration::from_millis(bound), "{best:?}");
}

#[test]
fn draft_roundtrip_and_clear() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    assert_eq!(p.a.draft(&bob).unwrap(), None);
    p.a.set_draft(&bob, "hello", NOW).unwrap();
    assert_eq!(p.a.draft(&bob).unwrap().as_deref(), Some("hello"));
    p.a.set_draft(&bob, "hello again", NOW + 1).unwrap();
    assert_eq!(p.a.draft(&bob).unwrap().as_deref(), Some("hello again"));
    p.a.set_draft(&bob, "  \n", NOW + 2).unwrap();
    assert_eq!(p.a.draft(&bob).unwrap(), None);
}

#[test]
fn draft_survives_reopen() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let mut rng = StdRng::seed_from_u64(9);
    let (mut a, _) = Core::create(&path, &[9; 32], "a", NOW, &mut rng).unwrap();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    a.set_draft(&fp, "later", NOW).unwrap();
    drop(a);
    let a = Core::open(&path, &[9; 32], NOW).unwrap();
    assert_eq!(a.draft(&fp).unwrap().as_deref(), Some("later"));
}

#[test]
fn draft_refuses_oversize_and_unknown() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    p.a.set_draft(&bob, "keep", NOW).unwrap();
    // The same error `send_text` gives for an oversize text.
    assert_eq!(
        p.a.set_draft(&bob, &"a".repeat(4001), NOW),
        p.a.send_text(&bob, &"a".repeat(4001), NOW, &mut p.rng)
            .map(|_| ())
    );
    assert_eq!(
        p.a.set_draft(&bob, &"a".repeat(4001), NOW),
        Err(CoreError::TooLarge)
    );
    assert_eq!(p.a.draft(&bob).unwrap().as_deref(), Some("keep"));
    p.a.set_draft(&bob, &"a".repeat(4000), NOW).unwrap();
    assert_eq!(
        p.a.set_draft(&Fingerprint([7; 32]), "x", NOW),
        Err(CoreError::UnknownContact)
    );
}

#[test]
fn draft_erased_with_contact() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    p.a.set_draft(&bob, "hello", NOW).unwrap();
    p.a.remove_contact(&bob, NOW, &mut p.rng).unwrap();
    assert_eq!(p.a.draft(&bob).unwrap(), None);
    p.a.add_contact(
        &p.b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    assert_eq!(p.a.draft(&bob).unwrap(), None);
}

#[test]
fn draft_erased_when_blocked() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    p.a.set_draft(&bob, "hello", NOW).unwrap();
    p.a.block_contact(&bob, NOW, &mut p.rng).unwrap();
    assert_eq!(p.a.draft(&bob).unwrap(), None);
}

/// Delivers every packet queued by `from` to `to`, ignoring what is not for it.
fn deliver_all(from: &mut Core, to: &mut Core, rng: &mut StdRng) {
    for b in from.pending_outbox(NOW + 9).unwrap() {
        let _ = to.receive(&b, "t", NOW + 9, rng);
    }
}

#[test]
fn draft_erased_when_contact_removed_by_sync() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert!(t.resolve("bob").is_ok());
    t.set_draft(&fp, "typing", NOW).unwrap();
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(t.resolve("bob"), Err(CoreError::UnknownContact));
    assert_eq!(t.draft(&fp).unwrap(), None);
}

#[test]
fn draft_erased_when_blocked_by_sync() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    t.set_draft(&fp, "typing", NOW).unwrap();
    a.block_contact(&fp, NOW + 5, &mut rng).unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert!(t.store.block_state(fp).unwrap().blocked);
    assert_eq!(t.draft(&fp).unwrap(), None);
    // The conversation still open on `t` saves again: nothing is kept.
    t.set_draft(&fp, "typing more", NOW + 10).unwrap();
    assert_eq!(t.draft(&fp).unwrap(), None);
}

#[test]
fn watched_days_cover_the_whole_lifetime() {
    let mut p = pair();
    let day = 86_400;
    let later = NOW + day;
    // Polled yesterday: the full window still starts 8 days back.
    p.b.mark_polled(NOW).unwrap();
    let watched = p.b.watched_mailboxes(later).unwrap();
    let b_id = p.b.device.public().id();
    let s = best_session(&p.b);
    let oldest = session_mailbox(&s.mailbox_secret, &b_id, day_of(later) - 8);
    assert!(watched.contains(&oldest));
    // A packet Alice sealed 5 days ago (offline, deposited late) sits in the
    // mailbox of its seal day: still polled.
    let target = send::Target::Contact(p.b.fingerprint());
    let body = Body::Text("late".into());
    let Core { store, device, .. } = &mut p.a;
    let sealed = store
        .transaction(|tx| {
            send::seal_for(
                tx,
                device,
                &target,
                &body,
                MessageId([6; 16]),
                send::SealTime::at(NOW - 5 * day),
                &mut p.rng,
            )
        })
        .unwrap();
    let (late, _) = &sealed[0];
    assert!(watched.contains(&late.mailbox));
}

// --- Lot 2, task 2: Ext envelope, unknown kinds, sender x kind matrix.

fn ext(kind: u16, unknown: UnknownPolicy) -> Body {
    Body::Ext {
        kind,
        unknown,
        data: vec![1, 2, 3],
    }
}

fn some_ref() -> MessageRef {
    MessageRef {
        id: [9; 16],
        by_sender: true,
    }
}

fn acks_for(c: &mut Core, packet: &Packet) -> usize {
    c.pending_outbox(NOW)
        .unwrap()
        .iter()
        .map(|b| Packet::decode(b).unwrap())
        .filter(|q| q.kind == Kind::Ack && q.payload[..16] == packet.id.0)
        .count()
}

fn seal_to_b(p: &mut Pair, body: &Body, mid: u8) -> Packet {
    let target = send::Target::Contact(p.b.fingerprint());
    seal_body(&mut p.a, &target, body, MessageId([mid; 16]), &mut p.rng)
        .remove(0)
        .0
}

#[test]
fn unknown_ignore_kind_is_acked_and_invisible() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let before = p.b.messages_with(&a_fp, NOW).unwrap().len();
    let pk = seal_to_b(&mut p, &ext(999, UnknownPolicy::Ignore), 0x31);
    let r = p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::Ignored), "{r:?}");
    assert_eq!(acks_for(&mut p.b, &pk), 1);
    assert_eq!(p.b.messages_with(&a_fp, NOW).unwrap().len(), before);
    let logged =
        p.b.transparency_log(100)
            .unwrap()
            .into_iter()
            .filter(|(_, e)| matches!(e, TransparencyEvent::UnknownContent { kind: 999, .. }))
            .count();
    assert_eq!(logged, 1);
    // The same content again, in a new packet: a duplicate (still acked).
    let again = seal_to_b(&mut p, &ext(999, UnknownPolicy::Ignore), 0x31);
    let r = p.b.receive(&again.encode(), "t", NOW, &mut p.rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
    assert_eq!(acks_for(&mut p.b, &again), 1);
}

#[test]
fn unknown_show_update_kind_adds_placeholder_row() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let before = p.b.messages_with(&a_fp, NOW).unwrap().len();
    let pk = seal_to_b(&mut p, &ext(999, UnknownPolicy::ShowUpdate), 0x32);
    let r = p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    match r {
        ReceiveOutcome::NeedsUpdate { from, .. } => assert_eq!(from, a_fp),
        other => panic!("NeedsUpdate expected, got {other:?}"),
    }
    let rows = p.b.messages_with(&a_fp, NOW).unwrap();
    assert_eq!(rows.len(), before + 1);
    let row = rows.last().unwrap();
    assert!(row.placeholder);
    assert_eq!(row.body, "");
    assert_eq!(row.direction, Direction::In);
    assert_eq!(row.wire_id, Some([0x32; 16]));
    assert_eq!(acks_for(&mut p.b, &pk), 1);
    // A resend of it is a duplicate, not a second placeholder.
    let again = seal_to_b(&mut p, &ext(999, UnknownPolicy::ShowUpdate), 0x32);
    let r = p.b.receive(&again.encode(), "t", NOW, &mut p.rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::DuplicateMessage), "{r:?}");
    assert_eq!(p.b.messages_with(&a_fp, NOW).unwrap().len(), before + 1);
}

#[test]
fn unknown_kind_from_blocked_contact_refused() {
    let mut p = pair();
    let a = p.b.resolve("alice").unwrap();
    p.b.block_contact(&a, NOW, &mut p.rng).unwrap();
    let pk = seal_to_b(&mut p, &ext(999, UnknownPolicy::ShowUpdate), 0x33);
    let r = p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(r), "blocked contact");
    assert_eq!(acks_for(&mut p.b, &pk), 0);
}

#[test]
fn known_kind_malformed_is_quarantined() {
    let mut p = pair();
    // Sealing refuses a malformed known kind: forged with the session state.
    let secret = [0x34; 16];
    let pt = postcard::to_allocvec(&Envelope {
        sent_at: NOW,
        ack_secret: secret,
        message_id: secret,
        body: Body::Ext {
            kind: 3,
            unknown: UnknownPolicy::Ignore,
            data: vec![0xff],
        },
    })
    .unwrap();
    let pk = forge(&mut p.a, &pt, ack::packet_id_for(&secret), &mut p.rng);
    let r = p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(r), "authenticated but malformed content");
}

#[test]
fn received_text_keeps_wire_id() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let pk =
        p.a.send_text(&b_fp, "hello", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    let sent = p.a.messages_with(&b_fp, NOW).unwrap().pop().unwrap();
    let got = p.b.messages_with(&a_fp, NOW).unwrap().pop().unwrap();
    assert_eq!(got.body, "hello");
    assert_eq!(got.wire_id, Some(sent.message_id.0));
    // Sent rows keep no wire id.
    assert_eq!(sent.wire_id, None);
}

#[test]
fn sync_ext_from_contact_quarantined() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let bodies = [
        ExtContent::SyncReply {
            to: a_fp,
            text: "faux".into(),
            reply_to: some_ref(),
        }
        .to_body(),
        ExtContent::SyncReaction {
            to: a_fp,
            target: some_ref(),
            emojis: vec!["👍".into()],
        }
        .to_body(),
    ];
    let before = p.a.messages_with(&b_fp, NOW).unwrap().len();
    for (i, body) in bodies.iter().enumerate() {
        let id = MessageId([0x40 + i as u8; 16]);
        let out = seal_body(&mut p.b, &send::Target::Contact(a_fp), body, id, &mut p.rng);
        let r =
            p.a.receive(&out[0].0.encode(), "t", NOW, &mut p.rng)
                .unwrap();
        assert_eq!(reason(r), NOT_MINE, "case {i}");
    }
    assert_eq!(p.a.messages_with(&b_fp, NOW).unwrap().len(), before);
    let reactions: i64 =
        p.a.store
            .conn()
            .query_row("SELECT count(*) FROM reactions", [], |r| r.get(0))
            .unwrap();
    assert_eq!(reactions, 0);
}

#[test]
fn contact_ext_from_my_device_refused() {
    let (_d, mut a, mut t, mut rng) = linked();
    let bodies = [
        ExtContent::Reply {
            text: "x".into(),
            reply_to: some_ref(),
        }
        .to_body(),
        ExtContent::Reaction {
            target: some_ref(),
            emojis: vec!["👍".into()],
        }
        .to_body(),
    ];
    for (i, body) in bodies.iter().enumerate() {
        let out = seal_body(
            &mut a,
            &send::Target::OwnDevices,
            body,
            MessageId([0x50 + i as u8; 16]),
            &mut rng,
        );
        let r = t.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
        assert_eq!(reason(r), "unexpected content for this mailbox", "case {i}");
    }
}

#[test]
fn unknown_kind_from_unlisted_own_device_refused() {
    let (_d, mut a, mut t1, mut t2, mut rng) = linked_twice();
    let card = a.contact_card("").unwrap();
    let pkt = devices_packet(&mut a, &t1, card, 1, &mut rng);
    t1.receive(&pkt.encode(), "t", NOW, &mut rng).unwrap();
    let t1_id = t1.device.public().id();
    let body = ext(999, UnknownPolicy::Ignore);
    // Listed: accepted and set aside (this also opens the session).
    let out = seal_body(
        &mut t2,
        &send::Target::OwnDevices,
        &body,
        MessageId([0x61; 16]),
        &mut rng,
    );
    let p = &out.iter().find(|(_, d)| *d == t1_id).unwrap().0;
    let r = t1.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::Ignored), "{r:?}");
    // T1's reply: T2's session no longer awaits an Initial.
    let t2_id = t2.device.public().id();
    let back = seal_body(
        &mut t1,
        &send::Target::OwnDevices,
        &body,
        MessageId([0x63; 16]),
        &mut rng,
    );
    let p = &back.iter().find(|(_, d)| *d == t2_id).unwrap().0;
    let r = t2.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::Ignored), "{r:?}");
    // T2 leaves the list (session kept): refused.
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
        &body,
        MessageId([0x62; 16]),
        &mut rng,
    );
    let p = &out.iter().find(|(_, d)| *d == t1_id).unwrap().0;
    assert_eq!(
        reason(t1.receive(&p.encode(), "t", NOW, &mut rng).unwrap()),
        NOT_MINE
    );
}

// --- Lot 2, task 3: replies.

/// The whole row of the message with this body.
fn full_row(c: &Core, contact: &Fingerprint, body: &str) -> crate::store::MessageRow {
    c.messages_with(contact, NOW)
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
}

/// The envelope of `p` as `to` would read it, without touching `to`.
fn peek_envelope(to: &Core, p: &Packet) -> Envelope {
    let row = best_session(to);
    let mut ratchet = de_state(&row.state).unwrap();
    let Wire::Normal { msg } = parse_wire(&p.payload).unwrap() else {
        panic!("Wire::Normal expected");
    };
    let pt = ratchet.decrypt(&msg, &row.ad, NOW).unwrap();
    crate::envelope::decode(&pt).unwrap()
}

fn deliver(to: &mut Core, p: &Packet, rng: &mut StdRng) -> ReceiveOutcome {
    to.receive(&p.encode(), "t", NOW, rng).unwrap()
}

/// `pair` plus Carol, a contact of Alice (and Alice of hers).
fn with_carol() -> (Pair, TempDir, Core) {
    let mut p = pair();
    let (dc, mut c) = party("c", 3);
    let mut rng = StdRng::seed_from_u64(0);
    p.a.add_contact(
        &c.contact_card("Carol").unwrap(),
        Some("carol"),
        NOW,
        &mut rng,
    )
    .unwrap();
    c.add_contact(
        &p.a.contact_card("Alice").unwrap(),
        Some("alice"),
        NOW,
        &mut rng,
    )
    .unwrap();
    (p, dc, c)
}

#[test]
fn reply_to_received_message() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let pk = p.a.send_text(&b, "18 h ?", NOW, &mut p.rng).unwrap();
    deliver(&mut p.b, &pk[0], &mut p.rng);
    let quoted = full_row(&p.b, &a, "18 h ?");
    let out =
        p.b.send_message(&a, "oui", Some(quoted.id), None, NOW, &mut p.rng)
            .unwrap();
    // The sender's row keeps the local id and the reference.
    let mine = full_row(&p.b, &a, "oui");
    let wire = quoted.wire_id.unwrap();
    assert_eq!(mine.reply_to, Some(quoted.message_id));
    assert_eq!(
        mine.reply_ref,
        Some(MessageRef {
            id: wire,
            by_sender: false
        })
    );
    assert!(matches!(
        deliver(&mut p.a, &out[0], &mut p.rng),
        ReceiveOutcome::Message { .. }
    ));
    let original = full_row(&p.a, &b, "18 h ?");
    let got = full_row(&p.a, &b, "oui");
    assert_eq!(got.reply_to, Some(original.message_id));
    assert_eq!(got.reply_ref, mine.reply_ref);
    assert!(got.wire_id.is_some());
    let quote =
        p.a.message_in(&b, got.reply_to.unwrap(), NOW)
            .unwrap()
            .unwrap();
    assert_eq!(quote.body, "18 h ?");
    // The rows survive a reopening.
    assert_eq!(
        p.a.messages_with(&b, NOW)
            .unwrap()
            .last()
            .unwrap()
            .reply_ref,
        got.reply_ref
    );
}

#[test]
fn reply_to_sent_message() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let pk = p.b.send_text(&a, "mine", NOW, &mut p.rng).unwrap();
    deliver(&mut p.a, &pk[0], &mut p.rng);
    let own = full_row(&p.b, &a, "mine");
    let out =
        p.b.send_message(&a, "re", Some(own.id), None, NOW, &mut p.rng)
            .unwrap();
    assert_eq!(
        full_row(&p.b, &a, "re").reply_ref,
        Some(MessageRef {
            id: own.message_id.0,
            by_sender: true
        })
    );
    deliver(&mut p.a, &out[0], &mut p.rng);
    let received = full_row(&p.a, &b, "mine");
    let got = full_row(&p.a, &b, "re");
    assert_eq!(got.reply_to, Some(received.message_id));
    assert_eq!(
        p.a.message_in(&b, got.reply_to.unwrap(), NOW)
            .unwrap()
            .unwrap()
            .body,
        "mine"
    );
}

#[test]
fn reply_without_original_resolves_later() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let original = p.b.send_text(&a, "orig", NOW, &mut p.rng).unwrap();
    let row = full_row(&p.b, &a, "orig");
    let reply =
        p.b.send_message(&a, "re", Some(row.id), None, NOW, &mut p.rng)
            .unwrap();
    // The reply first.
    deliver(&mut p.a, &reply[0], &mut p.rng);
    let id = full_row(&p.a, &b, "re").reply_to.unwrap();
    assert!(p.a.message_in(&b, id, NOW).unwrap().is_none());
    deliver(&mut p.a, &original[0], &mut p.rng);
    let found = p.a.message_in(&b, id, NOW).unwrap().unwrap();
    assert_eq!((found.body.as_str(), found.message_id), ("orig", id));
}

#[test]
fn deleted_original_reads_unavailable() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let original = p.b.send_text(&a, "orig", NOW, &mut p.rng).unwrap();
    deliver(&mut p.a, &original[0], &mut p.rng);
    let id = full_row(&p.a, &b, "orig");
    p.a.delete_message(id.id, NOW, &mut p.rng).unwrap();
    let row = full_row(&p.b, &a, "orig");
    let reply =
        p.b.send_message(&a, "re", Some(row.id), None, NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &reply[0], &mut p.rng);
    let got = full_row(&p.a, &b, "re");
    assert_eq!(got.reply_to, Some(id.message_id));
    assert!(p.a.message_in(&b, id.message_id, NOW).unwrap().is_none());
    // A resend of the original does not bring it back.
    deliver(&mut p.a, &original[0], &mut p.rng);
    assert!(p.a.message_in(&b, id.message_id, NOW).unwrap().is_none());
    assert!(
        p.a.messages_with(&b, NOW)
            .unwrap()
            .iter()
            .all(|m| m.body != "orig")
    );
}

#[test]
fn reply_to_other_conversation_is_unavailable() {
    let (mut p, _dc, mut c) = with_carol();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let c_fp = c.fingerprint();
    let to_bob = full_row(&p.a, &b, "x");
    // Carol forges a quote of Alice's message to Bob.
    let forged = ExtContent::Reply {
        text: "snoop".into(),
        reply_to: MessageRef {
            id: to_bob.message_id.0,
            by_sender: false,
        },
    }
    .to_body();
    let out = seal_body(
        &mut c,
        &send::Target::Contact(a),
        &forged,
        MessageId([0x70; 16]),
        &mut p.rng,
    );
    assert!(matches!(
        deliver(&mut p.a, &out[0].0, &mut p.rng),
        ReceiveOutcome::Message { .. }
    ));
    let got = full_row(&p.a, &c_fp, "snoop");
    let resolved = got.reply_to.unwrap();
    assert_eq!(resolved, to_bob.message_id);
    assert!(p.a.message_in(&c_fp, resolved, NOW).unwrap().is_none());
    assert!(p.a.message_in(&b, resolved, NOW).unwrap().is_some());
}

#[test]
fn reply_refuses_bad_target() {
    let (mut p, _dc, c) = with_carol();
    let b = p.b.fingerprint();
    let c_fp = c.fingerprint();
    let b_row = full_row(&p.a, &b, "x").id;
    // A received row of this device without a wire identifier.
    p.a.store
        .insert_message(
            b,
            Direction::In,
            "bare",
            MessageStatus::Received,
            NOW,
            MessageId([0x71; 16]),
        )
        .unwrap();
    let bare = full_row(&p.a, &b, "bare").id;
    let outbox = p.a.pending_outbox(NOW).unwrap().len();
    let rows = p.a.messages_with(&b, NOW).unwrap().len();
    for (to, id) in [(b, -1), (b, 9_999), (c_fp, b_row), (b, bare)] {
        assert_eq!(
            p.a.send_message(&to, "nope", Some(id), None, NOW, &mut p.rng),
            Err(CoreError::MessageNotFound),
            "{id}"
        );
    }
    assert_eq!(p.a.messages_with(&b, NOW).unwrap().len(), rows);
    assert!(p.a.messages_with(&c_fp, NOW).unwrap().is_empty());
    assert_eq!(p.a.pending_outbox(NOW).unwrap().len(), outbox);
}

#[test]
fn retried_reply_keeps_its_ref() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let original = p.b.send_text(&a, "orig", NOW, &mut p.rng).unwrap();
    deliver(&mut p.a, &original[0], &mut p.rng);
    let orig = full_row(&p.a, &b, "orig");
    let sent =
        p.a.send_message(&b, "re", Some(orig.id), None, NOW, &mut p.rng)
            .unwrap();
    let before = full_row(&p.a, &b, "re");
    // The delivery fails, the original goes away, the reply is retried.
    let late = u64::from(sent[0].expires_at) + 1;
    p.a.expire_due(late).unwrap();
    assert_eq!(before.status, MessageStatus::Pending);
    assert_eq!(full_row(&p.a, &b, "re").status, MessageStatus::NotDelivered);
    p.a.delete_message(orig.id, late, &mut p.rng).unwrap();
    let again = p.a.retry_message(before.id, late, &mut p.rng).unwrap();
    let after = full_row(&p.a, &b, "re");
    assert_eq!(
        (after.reply_to, after.reply_ref),
        (before.reply_to, before.reply_ref)
    );
    assert!(after.reply_ref.is_some());
    let r =
        p.b.receive(&again[0].encode(), "t", late, &mut p.rng)
            .unwrap();
    assert!(matches!(r, ReceiveOutcome::Message { .. }), "{r:?}");
    let got = full_row(&p.b, &a, "re");
    let theirs = full_row(&p.b, &a, "orig");
    assert_eq!(got.reply_to, Some(theirs.message_id));
    assert!(got.reply_ref.is_some());
}

#[test]
fn reply_body_never_contains_quoted_text() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let secret = "quoted-text-that-must-not-travel";
    let original = p.b.send_text(&a, secret, NOW, &mut p.rng).unwrap();
    deliver(&mut p.a, &original[0], &mut p.rng);
    let row = full_row(&p.a, &b, secret);
    let out =
        p.a.send_message(&b, "short", Some(row.id), None, NOW, &mut p.rng)
            .unwrap();
    let env = peek_envelope(&p.b, &out[0]);
    let Body::Ext { kind, data, .. } = &env.body else {
        panic!("Ext expected, got {:?}", env.body);
    };
    assert_eq!(*kind, crate::content::KIND_REPLY);
    let bytes = postcard::to_allocvec(&env).unwrap();
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!find(&bytes, secret.as_bytes()));
    assert!(find(data, b"short"));
    // Without a quote the body is still a plain text.
    let plain =
        p.a.send_message(&b, "plain", None, None, NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(peek_envelope(&p.b, &plain[0]).body, Body::Text(_)));
}

// --- Lot 2, task 4: reactions.

fn emo(list: &[&str]) -> Vec<String> {
    list.iter().map(|e| (*e).to_owned()).collect()
}

/// Chips as `(emoji, count)`: `mine` differs between the two sides.
fn counts(c: &Core, contact: &Fingerprint, message: MessageId) -> Vec<(String, u32)> {
    c.reaction_chips(contact, message)
        .unwrap()
        .into_iter()
        .map(|chip| (chip.emoji, chip.count))
        .collect()
}

fn reaction_rows(c: &Core) -> i64 {
    c.store
        .conn()
        .query_row("SELECT count(*) FROM reactions", [], |r| r.get(0))
        .unwrap()
}

fn added_of(o: ReceiveOutcome) -> Vec<String> {
    match o {
        ReceiveOutcome::Reaction { added, .. } => added,
        other => panic!("Reaction expected, got {other:?}"),
    }
}

/// Alice reacts on her message "x" to Bob; returns the packet for Bob.
fn react_x(p: &mut Pair, set: &[&str], now: u64) -> Packet {
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "x");
    let mut out = p.a.set_reactions(row, &emo(set), now, &mut p.rng).unwrap();
    assert_eq!(out.len(), 1, "one packet for Bob's only device");
    out.remove(0)
}

#[test]
fn reaction_add_remove_replace() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let on_a = message_id_of(&p.a, &b, "x");
    let on_b = message_id_of(&p.b, &a, "x");
    for (i, set) in [&["👍"][..], &["👍", "😂"], &[]].iter().enumerate() {
        let pk = react_x(&mut p, set, NOW + i as u64);
        deliver(&mut p.b, &pk, &mut p.rng);
        let mine = p.a.reaction_chips(&b, on_a).unwrap();
        assert!(mine.iter().all(|c| c.mine && c.count == 1));
        assert_eq!(counts(&p.b, &a, on_b), counts(&p.a, &b, on_a), "step {i}");
        assert_eq!(counts(&p.b, &a, on_b).len(), set.len());
    }
    assert!(counts(&p.a, &b, on_a).is_empty());
    assert!(counts(&p.b, &a, on_b).is_empty());
}

#[test]
fn reaction_out_of_order_and_duplicate_converge() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let on_b = message_id_of(&p.b, &a, "x");
    let p1 = react_x(&mut p, &["👍"], NOW);
    let p2 = react_x(&mut p, &["👍", "❤️"], NOW + 1);
    let p3 = react_x(&mut p, &["🎉"], NOW + 2);
    assert_eq!(added_of(deliver(&mut p.b, &p3, &mut p.rng)), emo(&["🎉"]));
    assert!(added_of(deliver(&mut p.b, &p2, &mut p.rng)).is_empty());
    assert!(added_of(deliver(&mut p.b, &p1, &mut p.rng)).is_empty());
    assert!(matches!(
        deliver(&mut p.b, &p1, &mut p.rng),
        ReceiveOutcome::Duplicate
    ));
    assert_eq!(counts(&p.b, &a, on_b), vec![("🎉".to_owned(), 1)]);
}

#[test]
fn reaction_clock_tie_breaks_on_message_id() {
    let body = |set: &[&str], p: &Pair| {
        ExtContent::Reaction {
            target: MessageRef {
                id: message_id_of(&p.a, &p.b.fingerprint(), "x").0,
                by_sender: true,
            },
            emojis: emo(set),
        }
        .to_body()
    };
    for reverse in [false, true] {
        // `pair` is seeded: each run gives the same fresh Bob.
        let mut p = pair();
        let a = p.a.fingerprint();
        let low = body(&["👍"], &p);
        let high = body(&["❤️"], &p);
        let low = seal_to_b(&mut p, &low, 0x10);
        let high = seal_to_b(&mut p, &high, 0x20);
        let order = if reverse {
            [&high, &low]
        } else {
            [&low, &high]
        };
        for pk in order {
            assert!(matches!(
                deliver(&mut p.b, pk, &mut p.rng),
                ReceiveOutcome::Reaction { .. }
            ));
        }
        let on_b = message_id_of(&p.b, &a, "x");
        assert_eq!(
            counts(&p.b, &a, on_b),
            vec![("❤️".to_owned(), 1)],
            "reverse: {reverse}"
        );
    }
}

#[test]
fn same_second_toggles_keep_their_order() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let on = react_x(&mut p, &["👍"], NOW);
    let off = react_x(&mut p, &[], NOW);
    let mine =
        p.a.store
            .reaction(message_id_of(&p.a, &b, "x"), ME_REACTOR)
            .unwrap()
            .unwrap();
    assert_eq!(mine.clock, NOW + 1);
    assert!(mine.emojis.is_empty());
    assert_eq!(peek_envelope(&p.b, &off).sent_at, NOW + 1);
    deliver(&mut p.b, &off, &mut p.rng);
    deliver(&mut p.b, &on, &mut p.rng);
    assert!(counts(&p.b, &a, message_id_of(&p.b, &a, "x")).is_empty());
}

#[test]
fn reaction_limits() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "x");
    let many: Vec<String> = "😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗😙😚🙂🤗🤩"
        .chars()
        .map(String::from)
        .collect();
    assert_eq!(many.len(), 21);
    let outbox = p.a.pending_outbox(NOW).unwrap().len();
    let cases: [(i64, Vec<String>, CoreError); 3] = [
        (row, many, CoreError::TooManyEmoji),
        (row, emo(&["a"]), CoreError::InvalidEmoji),
        (-1, emo(&["👍"]), CoreError::MessageNotFound),
    ];
    for (id, set, err) in cases {
        assert_eq!(p.a.set_reactions(id, &set, NOW, &mut p.rng), Err(err));
    }
    p.a.block_contact(&b, NOW, &mut p.rng).unwrap();
    let outbox_blocked = p.a.pending_outbox(NOW).unwrap().len();
    assert_eq!(
        p.a.set_reactions(row, &emo(&["👍"]), NOW, &mut p.rng),
        Err(CoreError::ContactBlocked)
    );
    assert_eq!(reaction_rows(&p.a), 0);
    assert_eq!(outbox_blocked, outbox);
    assert_eq!(p.a.pending_outbox(NOW).unwrap().len(), outbox);
}

#[test]
fn reaction_from_blocked_contact_refused() {
    let mut p = pair();
    let a = p.a.fingerprint();
    p.b.block_contact(&a, NOW, &mut p.rng).unwrap();
    let pk = react_x(&mut p, &["👍"], NOW + 1);
    assert_eq!(
        reason(deliver(&mut p.b, &pk, &mut p.rng)),
        "blocked contact"
    );
    assert_eq!(reaction_rows(&p.b), 0);
    assert_eq!(acks_for(&mut p.b, &pk), 0);
}

#[test]
fn reaction_on_deleted_message_ignored() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let row = row_of(&p.b, &a, "x");
    p.b.delete_message(row, NOW, &mut p.rng).unwrap();
    let pk = react_x(&mut p, &["👍"], NOW);
    assert!(matches!(
        deliver(&mut p.b, &pk, &mut p.rng),
        ReceiveOutcome::Ignored
    ));
    assert_eq!(reaction_rows(&p.b), 0);
    assert_eq!(acks_for(&mut p.b, &pk), 1);
}

#[test]
fn reaction_before_its_message_shows_on_arrival() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let late = p.a.send_text(&b, "late", NOW, &mut p.rng).unwrap();
    let row = row_of(&p.a, &b, "late");
    let r =
        p.a.set_reactions(row, &emo(&["👀"]), NOW, &mut p.rng)
            .unwrap();
    assert_eq!(added_of(deliver(&mut p.b, &r[0], &mut p.rng)), emo(&["👀"]));
    assert!(!has_message(&p.b, &a, "late"));
    deliver(&mut p.b, &late[0], &mut p.rng);
    let on_b = message_id_of(&p.b, &a, "late");
    assert_eq!(counts(&p.b, &a, on_b), vec![("👀".to_owned(), 1)]);
}

#[test]
fn reaction_cannot_reach_another_conversation() {
    let (mut p, _dc, mut c) = with_carol();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let to_bob = full_row(&p.a, &b, "x");
    let forged = ExtContent::Reaction {
        target: MessageRef {
            id: to_bob.message_id.0,
            by_sender: false,
        },
        emojis: emo(&["💩"]),
    }
    .to_body();
    let out = seal_body(
        &mut c,
        &send::Target::Contact(a),
        &forged,
        MessageId([0x72; 16]),
        &mut p.rng,
    );
    assert!(matches!(
        deliver(&mut p.a, &out[0].0, &mut p.rng),
        ReceiveOutcome::Ignored
    ));
    assert!(
        p.a.reaction_chips(&b, to_bob.message_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(reaction_rows(&p.a), 0);
}

/// Alice holds her reaction on "x" and Bob's on "y".
fn both_react(p: &mut Pair) {
    let a = p.a.fingerprint();
    react_x(p, &["👍"], NOW);
    let y = row_of(&p.b, &a, "y");
    let pk =
        p.b.set_reactions(y, &emo(&["❤️"]), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &pk[0], &mut p.rng);
    assert_eq!(reaction_rows(&p.a), 2);
}

#[test]
fn reactions_erased_with_message_contact_and_block() {
    // Deleting a message erases its reactions only.
    let mut p = pair();
    let b = p.b.fingerprint();
    both_react(&mut p);
    let x = message_id_of(&p.a, &b, "x");
    p.a.delete_message(row_of(&p.a, &b, "x"), NOW, &mut p.rng)
        .unwrap();
    assert!(p.a.store.reaction(x, ME_REACTOR).unwrap().is_none());
    assert_eq!(reaction_rows(&p.a), 1);
    // Removing the contact erases every row of the conversation.
    p.a.remove_contact(&b, NOW, &mut p.rng).unwrap();
    assert_eq!(reaction_rows(&p.a), 0);
    // Blocking does too, mine included.
    let mut p = pair();
    let b = p.b.fingerprint();
    both_react(&mut p);
    p.a.block_contact(&b, NOW, &mut p.rng).unwrap();
    assert_eq!(reaction_rows(&p.a), 0);

    // The same, received from my other device.
    for block in [false, true] {
        let (_d, mut a, mut t, mut rng) = linked();
        let (_db, bob) = party("bob", 5);
        let fp = a
            .add_contact(
                &bob.contact_card("Bob").unwrap(),
                Some("bob"),
                NOW,
                &mut rng,
            )
            .unwrap();
        deliver_all(&mut a, &mut t, &mut rng);
        t.store
            .insert_message(
                fp,
                Direction::Out,
                "m",
                MessageStatus::OnNetwork,
                NOW,
                MessageId([0x61; 16]),
            )
            .unwrap();
        let row = row_of(&t, &fp, "m");
        t.set_reactions(row, &emo(&["👍"]), NOW, &mut rng).unwrap();
        assert_eq!(reaction_rows(&t), 1);
        if block {
            a.block_contact(&fp, NOW + 5, &mut rng).unwrap();
        } else {
            a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
        }
        deliver_all(&mut a, &mut t, &mut rng);
        assert_eq!(reaction_rows(&t), 0, "block: {block}");
    }
}

/// What the chat list reads of a conversation: its rows, its last message
/// (with delivery) and the received rows (the unread count's input).
type ConversationView = (
    Vec<MessageRow>,
    Option<(MessageRow, Option<crate::store::DeliverySummary>)>,
    usize,
);

fn conversation_view(c: &mut Core, contact: &Fingerprint) -> ConversationView {
    let rows = c.messages_with(contact, NOW).unwrap();
    let last = c
        .messages_with_delivery(contact, NOW)
        .unwrap()
        .into_iter()
        .last();
    let received = rows.iter().filter(|m| m.direction == Direction::In).count();
    (rows, last, received)
}

#[test]
fn reaction_is_never_a_message() {
    let mut p = settled_pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    // Every receipt of the two messages back home first.
    deliver_all(&mut p.b, &mut p.a, &mut p.rng);
    deliver_all(&mut p.a, &mut p.b, &mut p.rng);
    let before_a = conversation_view(&mut p.a, &b);
    let before_b = conversation_view(&mut p.b, &a);
    let pk = react_x(&mut p, &["👍"], NOW);
    deliver(&mut p.b, &pk, &mut p.rng);
    let y = row_of(&p.b, &a, "y");
    let back =
        p.b.set_reactions(y, &emo(&["🎉"]), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &back[0], &mut p.rng);
    // The receipts go back too.
    deliver_all(&mut p.b, &mut p.a, &mut p.rng);
    deliver_all(&mut p.a, &mut p.b, &mut p.rng);
    assert_eq!(reaction_rows(&p.a), 2);
    assert_eq!(reaction_rows(&p.b), 2);
    assert_eq!(conversation_view(&mut p.a, &b), before_a);
    assert_eq!(conversation_view(&mut p.b, &a), before_b);
    assert_eq!(before_a.0.len(), 2);
    assert_eq!(before_a.2, 1);
}

#[test]
fn reaction_outcome_lists_added_only() {
    let mut p = pair();
    let steps: [(&[&str], &[&str]); 3] =
        [(&["👍"], &["👍"]), (&["👍", "❤️"], &["❤️"]), (&["❤️"], &[])];
    for (i, (set, added)) in steps.into_iter().enumerate() {
        let pk = react_x(&mut p, set, NOW + i as u64);
        assert_eq!(added_of(deliver(&mut p.b, &pk, &mut p.rng)), emo(added));
    }
}

#[test]
fn reaction_leaves_target_delivery_alone() {
    let mut p = settled_pair();
    let b = p.b.fingerprint();
    let x = message_id_of(&p.a, &b, "x");
    let row = row_of(&p.a, &b, "x");
    let status = status_of(&p.a, &b, "x");
    assert_eq!(status, MessageStatus::Received);
    let deliveries = deliveries_of(&p.a, x);
    let pk = react_x(&mut p, &["👍"], NOW);
    // The reaction packet has its own delivery, keyed on its own id.
    let tie = p.a.store.reaction(x, ME_REACTOR).unwrap().unwrap().tie;
    assert_eq!(deliveries_of(&p.a, MessageId(tie)), vec![(0, 0)]);
    assert_eq!(deliveries_of(&p.a, x), deliveries);
    // It expires undeposited: the target is not touched.
    let late = u64::from(pk.expires_at) + 1;
    p.a.expire_due(late).unwrap();
    assert_eq!(deliveries_of(&p.a, MessageId(tie)), vec![(0, 5)]);
    assert_eq!(status_of(&p.a, &b, "x"), status);
    assert_eq!(deliveries_of(&p.a, x), deliveries);
    assert!(p.a.take_failed_notices().is_empty());
    assert_eq!(
        p.a.retry_message(row, late, &mut p.rng),
        Err(CoreError::NothingToRetry)
    );
    assert_eq!(p.a.retry_all(&b, late, &mut p.rng), Ok(0));
    assert!(
        p.a.store
            .messages_with(b, NOW)
            .unwrap()
            .iter()
            .all(|m| m.message_id.0 != tie)
    );
}

#[test]
fn reaction_chips_keep_first_seen_order() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let pk = react_x(&mut p, &["👍"], NOW);
    deliver(&mut p.b, &pk, &mut p.rng);
    let x_on_b = row_of(&p.b, &a, "x");
    let back =
        p.b.set_reactions(x_on_b, &emo(&["❤️"]), NOW + 1, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &back[0], &mut p.rng);
    // Alice updates hers last: her chips stay first.
    let pk = react_x(&mut p, &["👍", "😂"], NOW + 2);
    deliver(&mut p.b, &pk, &mut p.rng);
    let order = |c: &Core, contact: &Fingerprint, body: &str| -> Vec<String> {
        c.reaction_chips(contact, message_id_of(c, contact, body))
            .unwrap()
            .into_iter()
            .map(|chip| chip.emoji)
            .collect()
    };
    assert_eq!(order(&p.a, &b, "x"), emo(&["👍", "😂", "❤️"]));
    assert_eq!(order(&p.b, &a, "x"), emo(&["👍", "😂", "❤️"]));
    // Alice drops 👍 and adds it back: it goes to the end of her list.
    let pk = react_x(&mut p, &["😂"], NOW + 3);
    deliver(&mut p.b, &pk, &mut p.rng);
    let pk = react_x(&mut p, &["😂", "👍"], NOW + 4);
    deliver(&mut p.b, &pk, &mut p.rng);
    assert_eq!(order(&p.b, &a, "x"), emo(&["😂", "👍", "❤️"]));
    let mine =
        p.a.reaction_chips(&b, message_id_of(&p.a, &b, "x"))
            .unwrap();
    assert_eq!(
        mine.iter().map(|c| c.mine).collect::<Vec<_>>(),
        [true, true, false]
    );
}

#[test]
fn reaction_sync_crossing_a_block_is_dropped() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    t.store
        .insert_message(
            fp,
            Direction::Out,
            "m",
            MessageStatus::OnNetwork,
            NOW,
            MessageId([0x62; 16]),
        )
        .unwrap();
    a.store
        .insert_message(
            fp,
            Direction::Out,
            "m",
            MessageStatus::OnNetwork,
            NOW,
            MessageId([0x62; 16]),
        )
        .unwrap();
    // T reacts; its copy is held back while A blocks Bob.
    let row = row_of(&t, &fp, "m");
    let pkts = t.set_reactions(row, &emo(&["👍"]), NOW, &mut rng).unwrap();
    a.block_contact(&fp, NOW + 1, &mut rng).unwrap();
    let mut seen = 0;
    for p in &pkts {
        match a.receive(&p.encode(), "t", NOW, &mut rng).unwrap() {
            ReceiveOutcome::NotForUs => {}
            o => {
                assert!(matches!(o, ReceiveOutcome::Duplicate), "{o:?}");
                assert_eq!(acks_for(&mut a, p), 1);
                seen += 1;
            }
        }
    }
    assert_eq!(seen, 1);
    assert_eq!(reaction_rows(&a), 0);
}

#[test]
fn reaction_sync_after_a_removal_does_not_resurrect() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    t.store
        .insert_message(
            fp,
            Direction::Out,
            "m",
            MessageStatus::OnNetwork,
            NOW,
            MessageId([0x63; 16]),
        )
        .unwrap();
    let row = row_of(&t, &fp, "m");
    // Sealed at NOW, held back while A removes Bob at NOW + 5.
    let early = t.set_reactions(row, &emo(&["👍"]), NOW, &mut rng).unwrap();
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    for p in &early {
        let _ = a.receive(&p.encode(), "t", NOW + 9, &mut rng).unwrap();
    }
    assert_eq!(reaction_rows(&a), 0);
    // A copy sealed after the removal still applies (last writer wins).
    let late = t
        .set_reactions(row, &emo(&["🎉"]), NOW + 6, &mut rng)
        .unwrap();
    for p in &late {
        let _ = a.receive(&p.encode(), "t", NOW + 9, &mut rng).unwrap();
    }
    assert_eq!(reaction_rows(&a), 1);
}

#[test]
fn reaction_chips_same_order_on_both_phones() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    // Both react in the same second, each before seeing the other's.
    let from_a = react_x(&mut p, &["👍"], NOW);
    let x_on_b = row_of(&p.b, &a, "x");
    let from_b =
        p.b.set_reactions(x_on_b, &emo(&["❤️"]), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.b, &from_a, &mut p.rng);
    deliver(&mut p.a, &from_b[0], &mut p.rng);
    let order = |c: &Core, contact: &Fingerprint| -> Vec<String> {
        c.reaction_chips(contact, message_id_of(c, contact, "x"))
            .unwrap()
            .into_iter()
            .map(|chip| chip.emoji)
            .collect()
    };
    assert_eq!(order(&p.a, &b).len(), 2);
    assert_eq!(order(&p.a, &b), order(&p.b, &a));
}

// --- Lot 2, task 5: reaction packets tracked and resent after expiry.

#[test]
fn expired_reaction_waits_for_a_manual_resend() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "x");
    let first = react_x(&mut p, &["👍"], NOW);
    let last = react_x(&mut p, &["👍", "❤️"], NOW + 1);
    // Both packets expire undeposited: the full sync resends neither.
    let late = u64::from(last.expires_at) + 1;
    for now in [late, late + 1] {
        assert_eq!(
            p.a.resend_reactions(now, &mut p.rng).map(|r| r.resent),
            Ok(0)
        );
        assert!(p.a.pending_outbox(now).unwrap().is_empty());
    }
    // Only the last send is tracked, and it failed.
    assert!(gone(&p.a, first.id));
    assert_eq!(contact_tie(&p.a, b, target), Some(tie_of(&p.a, last.id)));
    assert_eq!(
        tie_states(&p.a, tie_of(&p.a, last.id), false),
        vec![MessageStatus::NotDelivered as i64]
    );
}

#[test]
fn expired_reaction_resent_to_my_other_devices_only() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, _fp, target, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
    assert_eq!(a.resend_reactions(late, &mut rng).map(|r| r.resent), Ok(1));
    let queued = a.pending_outbox(late).unwrap();
    assert_eq!(queued.len(), 1, "for T only");
    // My row carries the new clock.
    let mine = a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    assert_eq!(mine.clock, late);
    for bytes in &queued {
        let _ = t.receive(bytes, "t", late, &mut rng).unwrap();
    }
    let on_t = t.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    assert_eq!((on_t.clock, on_t.emojis), (late, emo(&["👍"])));
}

#[test]
fn deposited_reaction_not_resent() {
    let mut p = pair();
    let pk = react_x(&mut p, &["👍"], NOW);
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    let late = u64::from(pk.expires_at) + 1;
    assert_eq!(
        p.a.resend_reactions(late, &mut p.rng).map(|r| r.resent),
        Ok(0)
    );
}

#[test]
fn expired_reaction_without_my_row_is_dropped_not_resent() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let pk = react_x(&mut p, &["👍"], NOW);
    // The message goes (its reactions with it) before the packet expires.
    p.a.delete_message(row_of(&p.a, &b, "x"), NOW + 1, &mut p.rng)
        .unwrap();
    let late = u64::from(pk.expires_at) + 1;
    assert_eq!(
        p.a.resend_reactions(late, &mut p.rng).map(|r| r.resent),
        Ok(0)
    );
    assert!(p.a.pending_outbox(late).unwrap().is_empty());
    let left: i64 =
        p.a.store
            .conn()
            .query_row("SELECT count(*) FROM reaction_sends", [], |r| r.get(0))
            .unwrap();
    assert_eq!(left, 0);
}

#[test]
fn removed_set_is_resent_as_empty() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, _, _) = react_linked(&mut a, &mut t, &mut rng);
    let row = row_of(&a, &fp, "m");
    let last = a.set_reactions(row, &[], NOW + 1, &mut rng).unwrap();
    let late = last.iter().map(|p| u64::from(p.expires_at)).max().unwrap() + 1;
    assert_eq!(a.resend_reactions(late, &mut rng).map(|r| r.resent), Ok(1));
    let queued = a.pending_outbox(late).unwrap();
    assert_eq!(queued.len(), 1);
    let _ = t.receive(&queued[0], "t", late, &mut rng).unwrap();
    assert!(t.reaction_chips(&fp, target).unwrap().is_empty());
    assert!(a.reaction_chips(&fp, target).unwrap().is_empty());
}

#[test]
fn pending_reaction_listed_as_reaction() {
    let mut p = pair();
    let b = p.b.fingerprint();
    react_x(&mut p, &["👍"], NOW);
    let pending = p.a.pending_packets(NOW + 1).unwrap();
    let reactions: Vec<_> = pending
        .sync
        .iter()
        .filter(|s| s.kind == PendingKind::Reaction)
        .collect();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0].packets, 1);
    assert_eq!(reactions[0].contacts, vec![b]);
    assert!(
        pending
            .sync
            .iter()
            .all(|s| s.kind != PendingKind::CardUpdate)
    );
}

fn sends_where(c: &Core, clause: &str) -> i64 {
    c.store
        .conn()
        .query_row(
            &format!("SELECT count(*) FROM reaction_sends WHERE {clause}"),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn deleting_the_message_drops_its_reaction_sends() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let pk = react_x(&mut p, &["👍"], NOW);
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    assert_eq!(sends_where(&p.a, "1"), 1);
    p.a.delete_message(row_of(&p.a, &b, "x"), NOW + 2, &mut p.rng)
        .unwrap();
    assert_eq!(sends_where(&p.a, "1"), 0, "no link to the deleted message");
}

#[test]
fn rows_of_packets_that_left_the_queue_are_kept() {
    let mut p = pair();
    let pk = react_x(&mut p, &["👍"], NOW);
    p.a.store.outbox_remove(pk.id).unwrap();
    assert_eq!(
        p.a.resend_reactions(NOW + 1, &mut p.rng).map(|r| r.resent),
        Ok(0)
    );
    assert_eq!(packet_rows(&p.a, "reaction_sends", pk.id), 1);
    assert_eq!(packet_rows(&p.a, "deliveries", pk.id), 1);
}

#[test]
fn a_failing_group_does_not_block_the_others() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let (_dc, carol) = party("carol", 6);
    let mut fps = Vec::new();
    for (card, alias) in [
        (bob.contact_card("Bob").unwrap(), "bob"),
        (carol.contact_card("Carol").unwrap(), "carol"),
    ] {
        fps.push(a.add_contact(&card, Some(alias), NOW, &mut rng).unwrap());
    }
    deliver_all(&mut a, &mut t, &mut rng);
    // Bob's group is first, then Carol's.
    let mut sent = Vec::new();
    for (i, fp) in fps.iter().enumerate() {
        let id = MessageId([0x75 + i as u8; 16]);
        for c in [&mut a, &mut t] {
            c.store
                .insert_message(*fp, Direction::Out, "m", MessageStatus::OnNetwork, NOW, id)
                .unwrap();
        }
        let row = row_of(&a, fp, "m");
        sent.extend(a.set_reactions(row, &emo(&["👍"]), NOW, &mut rng).unwrap());
    }
    let late = sent.iter().map(|p| u64::from(p.expires_at)).max().unwrap() + 1;
    // Bob's stored contact row became unreadable: his group fails.
    a.store
        .conn()
        .execute(
            "UPDATE contacts SET verified = 'x' WHERE fp = ?1",
            [fps[0].0.as_slice()],
        )
        .unwrap();
    assert_eq!(
        a.resend_reactions(late, &mut rng),
        Ok(ReactionResend {
            resent: 1,
            failed: 1
        })
    );
    assert_eq!(
        sends_where(&a, "expired = 1 AND own = 1"),
        1,
        "Bob's stays flagged"
    );
    assert_eq!(a.pending_outbox(late).unwrap().len(), 1, "Carol's went");
}

#[test]
fn blocked_or_unknown_contact_audience_is_skipped() {
    for block in [true, false] {
        let (_d, mut a, mut t, mut rng) = linked();
        let (_db, fp, _, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
        if block {
            a.block_contact(&fp, NOW + 1, &mut rng).unwrap();
        } else {
            a.store
                .conn()
                .execute("DELETE FROM contacts WHERE fp = ?1", [fp.0.as_slice()])
                .unwrap();
        }
        let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
        assert_eq!(
            a.resend_reactions(late, &mut rng).map(|r| r.resent),
            Ok(0),
            "block {block}"
        );
        // My copies are dropped, nothing new is sealed.
        assert_eq!(sends_where(&a, "own = 1"), 0, "block {block}");
        assert_eq!(sends_where(&a, "expired = 0"), 0, "block {block}");
    }
}

#[test]
fn reaction_lost_after_deposit_stays_not_delivered() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "x");
    let pk = react_x(&mut p, &["👍"], NOW);
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    let expiry = u64::from(pk.expires_at);
    // The network confirms it gone: the full sync does not resend it.
    assert_eq!(p.a.confirm_expired(pk.id, expiry + 1), Ok(true));
    assert_eq!(
        p.a.resend_reactions(expiry + 2, &mut p.rng)
            .map(|r| r.resent),
        Ok(0)
    );
    assert!(p.a.pending_outbox(expiry + 2).unwrap().is_empty());
    let tie = contact_tie(&p.a, b, target).expect("still tracked");
    assert_eq!(
        tie_states(&p.a, tie, false),
        vec![MessageStatus::NotDelivered as i64]
    );
}

#[test]
fn removing_a_contact_drops_its_reaction_sends() {
    let mut p = pair();
    let b = p.b.fingerprint();
    react_x(&mut p, &["👍"], NOW);
    p.a.remove_contact(&b, NOW + 1, &mut p.rng).unwrap();
    let left: i64 =
        p.a.store
            .conn()
            .query_row("SELECT count(*) FROM reaction_sends", [], |r| r.get(0))
            .unwrap();
    assert_eq!(left, 0);
}

// --- Final review: a repeat of a visible message is told apart.

#[test]
fn repeat_of_a_stored_message_is_a_visible_duplicate() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let b = p.b.fingerprint();
    let m =
        p.a.send_text(&b, "seen", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    assert!(matches!(
        deliver(&mut p.b, &m, &mut p.rng),
        ReceiveOutcome::Message { .. }
    ));
    // The same packet again (another node serves it): already seen.
    let r = deliver(&mut p.b, &m, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::DuplicateMessage), "{r:?}");
    // The same message in a new packet (a resend).
    let mid =
        p.a.messages_with(&b, NOW)
            .unwrap()
            .last()
            .unwrap()
            .message_id;
    let again = seal_body(
        &mut p.a,
        &send::Target::Contact(b),
        &Body::Text("seen".into()),
        mid,
        &mut p.rng,
    )
    .remove(0)
    .0;
    let r = deliver(&mut p.b, &again, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::DuplicateMessage), "{r:?}");
    // An update placeholder received again is visible too.
    let pk = seal_to_b(&mut p, &ext(999, UnknownPolicy::ShowUpdate), 0x41);
    assert!(matches!(
        deliver(&mut p.b, &pk, &mut p.rng),
        ReceiveOutcome::NeedsUpdate { .. }
    ));
    let r = deliver(&mut p.b, &pk, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::DuplicateMessage), "{r:?}");
    let pk2 = seal_to_b(&mut p, &ext(999, UnknownPolicy::ShowUpdate), 0x41);
    let r = deliver(&mut p.b, &pk2, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::DuplicateMessage), "{r:?}");

    // Deleted here since: nothing of it shows, a plain duplicate.
    let row = row_of(&p.b, &a, "seen");
    p.b.delete_message(row, NOW, &mut p.rng).unwrap();
    for pk in [&m, &again] {
        let r = deliver(&mut p.b, pk, &mut p.rng);
        assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
    }
    // A reaction received twice, an ignored kind, an ack: plain duplicates.
    let rx = react_x(&mut p, &["👍"], NOW);
    deliver(&mut p.b, &rx, &mut p.rng);
    let r = deliver(&mut p.b, &rx, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
    let ig = seal_to_b(&mut p, &ext(999, UnknownPolicy::Ignore), 0x42);
    deliver(&mut p.b, &ig, &mut p.rng);
    let r = deliver(&mut p.b, &ig, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
    let n =
        p.a.send_text(&b, "acked", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let ReceiveOutcome::Message { ack, .. } = deliver(&mut p.b, &n, &mut p.rng) else {
        panic!("message expected");
    };
    deliver(&mut p.a, &ack, &mut p.rng);
    let r = deliver(&mut p.a, &ack, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::Duplicate), "{r:?}");
}

// --- Final review: a policy this version does not know.

/// The plaintext of an `Ext` of unknown kind whose policy byte is `policy`,
/// found as the one byte that differs between the two known policies.
fn ext_with_policy_byte(secret: [u8; 16], policy: u8) -> Vec<u8> {
    let pt = |unknown| {
        postcard::to_allocvec(&Envelope {
            sent_at: NOW,
            ack_secret: secret,
            message_id: secret,
            body: ext(999, unknown),
        })
        .unwrap()
    };
    let (ignore, show) = (pt(UnknownPolicy::Ignore), pt(UnknownPolicy::ShowUpdate));
    let diff: Vec<usize> = (0..ignore.len())
        .filter(|&i| ignore[i] != show[i])
        .collect();
    assert_eq!(diff.len(), 1, "one policy byte");
    assert_eq!((ignore[diff[0]], show[diff[0]]), (0, 1));
    let mut out = ignore;
    out[diff[0]] = policy;
    out
}

#[test]
fn future_policy_shows_an_update_placeholder() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let secret = [0x51; 16];
    let pt = ext_with_policy_byte(secret, 7);
    let pk = forge(&mut p.a, &pt, ack::packet_id_for(&secret), &mut p.rng);
    let before = p.b.messages_with(&a_fp, NOW).unwrap().len();
    let r = p.b.receive(&pk.encode(), "t", NOW, &mut p.rng).unwrap();
    assert!(matches!(r, ReceiveOutcome::NeedsUpdate { .. }), "{r:?}");
    assert_eq!(acks_for(&mut p.b, &pk), 1);
    let rows = p.b.messages_with(&a_fp, NOW).unwrap();
    assert_eq!(rows.len(), before + 1);
    assert!(rows.last().unwrap().placeholder);
}

// --- Final review: one emoji, one spelling (U+FE0F).

#[test]
fn heart_with_or_without_fe0f_is_one_emoji_on_send() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "x");
    let on_a = message_id_of(&p.a, &b, "x");
    // Both spellings in one set: a duplicate.
    assert_eq!(
        p.a.set_reactions(row, &emo(&["❤", "❤\u{FE0F}"]), NOW, &mut p.rng),
        Err(CoreError::InvalidEmoji)
    );
    // The bare heart is stored and sent fully qualified.
    let sent =
        p.a.set_reactions(row, &emo(&["❤"]), NOW, &mut p.rng)
            .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(counts(&p.a, &b, on_a), vec![("❤\u{FE0F}".to_owned(), 1)]);
    let Body::Ext { kind, data, .. } = peek_envelope(&p.b, &sent[0]).body else {
        panic!("Ext expected");
    };
    let Some(ExtContent::Reaction { emojis, .. }) = ExtContent::decode(kind, &data).unwrap() else {
        panic!("Reaction expected");
    };
    assert_eq!(emojis, emo(&["❤\u{FE0F}"]));
    // The other spelling is the same set: nothing to send.
    assert!(
        p.a.set_reactions(row, &emo(&["❤\u{FE0F}"]), NOW + 1, &mut p.rng)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn heart_with_or_without_fe0f_is_one_emoji_on_receive() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let on_a = message_id_of(&p.a, &b, "x");
    let on_b = message_id_of(&p.b, &a, "x");
    let target = MessageRef {
        id: on_a.0,
        by_sender: true,
    };
    // A peer that sends the bare heart: stored in the canonical spelling.
    let bare = ExtContent::Reaction {
        target,
        emojis: emo(&["❤"]),
    }
    .to_body();
    let pk = seal_to_b(&mut p, &bare, 0x61);
    let added = added_of(deliver(&mut p.b, &pk, &mut p.rng));
    assert_eq!(added, emo(&["❤\u{FE0F}"]));
    assert_eq!(counts(&p.b, &a, on_b), vec![("❤\u{FE0F}".to_owned(), 1)]);
    // Bob's own fully-qualified heart counts with it, as one chip.
    let row = row_of(&p.b, &a, "x");
    p.b.set_reactions(row, &emo(&["❤\u{FE0F}"]), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(counts(&p.b, &a, on_b), vec![("❤\u{FE0F}".to_owned(), 2)]);
    // Both spellings in one received set: a duplicate, refused (sealing
    // refuses it too: forged with the session state).
    let secret = [0x62; 16];
    let pt = postcard::to_allocvec(&Envelope {
        sent_at: NOW,
        ack_secret: secret,
        message_id: secret,
        body: Body::Ext {
            kind: crate::content::KIND_REACTION,
            unknown: UnknownPolicy::Ignore,
            data: postcard::to_allocvec(&(target, emo(&["❤", "❤\u{FE0F}"]))).unwrap(),
        },
    })
    .unwrap();
    let pk = forge(&mut p.a, &pt, ack::packet_id_for(&secret), &mut p.rng);
    let r = deliver(&mut p.b, &pk, &mut p.rng);
    assert!(matches!(r, ReceiveOutcome::Quarantined { .. }), "{r:?}");
}

// --- Final review: no reaction leftovers.

/// Rows of `table` about the packet `id` (`deliveries`, `outbox`).
fn packet_rows(c: &Core, table: &str, id: PacketId) -> i64 {
    c.store
        .conn()
        .query_row(
            &format!("SELECT count(*) FROM {table} WHERE packet_id = ?1"),
            [id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
}

/// Neither queued, nor tracked, nor kept as a delivery.
fn gone(c: &Core, id: PacketId) -> bool {
    packet_rows(c, "outbox", id) == 0
        && packet_rows(c, "deliveries", id) == 0
        && packet_rows(c, "reaction_sends", id) == 0
}

#[test]
fn blocking_drops_queued_reaction_packets() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let pk = react_x(&mut p, &["👍"], NOW);
    assert!(!gone(&p.a, pk.id));
    p.a.block_contact(&b, NOW + 1, &mut p.rng).unwrap();
    assert!(gone(&p.a, pk.id));
}

#[test]
fn block_from_my_other_device_drops_queued_reaction_packets() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    t.store
        .insert_message(
            fp,
            Direction::Out,
            "m",
            MessageStatus::OnNetwork,
            NOW,
            MessageId([0x81; 16]),
        )
        .unwrap();
    let row = row_of(&t, &fp, "m");
    let sent = t.set_reactions(row, &emo(&["👍"]), NOW, &mut rng).unwrap();
    // Only what T sends to Bob, kept apart from the sync for A.
    let to_bob: Vec<PacketId> = sent
        .iter()
        .map(|p| p.id)
        .filter(|id| {
            t.store
                .conn()
                .query_row(
                    "SELECT own = 0 FROM reaction_sends WHERE packet_id = ?1",
                    [id.0.as_slice()],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(to_bob.len(), 1);
    a.block_contact(&fp, NOW + 5, &mut rng).unwrap();
    // A's block reaches T: only the block sync, not T's packets back to A.
    let block: Vec<Vec<u8>> = a.pending_outbox(NOW + 5).unwrap();
    for bytes in &block {
        let _ = t.receive(bytes, "t", NOW + 5, &mut rng);
    }
    assert!(t.store.block_state(fp).unwrap().blocked);
    assert!(gone(&t, to_bob[0]));
}

#[test]
fn deleting_the_message_drops_its_queued_reaction_packets() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let pk = react_x(&mut p, &["👍"], NOW);
    p.a.delete_message(row_of(&p.a, &b, "x"), NOW + 1, &mut p.rng)
        .unwrap();
    assert!(gone(&p.a, pk.id));
    assert!(
        p.a.pending_packets(NOW + 1)
            .unwrap()
            .sync
            .iter()
            .all(|s| s.kind != PendingKind::CardUpdate && s.kind != PendingKind::Reaction)
    );
}

#[test]
fn pruned_reaction_rows_take_their_deliveries() {
    // A copy for my device that expired undeposited and was resent: the old
    // packet's delivery goes with its row.
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, _, _, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
    assert_eq!(a.resend_reactions(late, &mut rng).unwrap().resent, 1);
    assert!(gone(&a, to_t.id));
    // The send to Bob is kept: it waits for the manual resend.
    assert_eq!(packet_rows(&a, "deliveries", to_bob.id), 1);
    assert_eq!(packet_rows(&a, "reaction_sends", to_bob.id), 1);
}

#[test]
fn removing_a_contact_drops_acks_of_its_reactions_and_ignored_content() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let rx = react_x(&mut p, &["👍"], NOW);
    deliver(&mut p.b, &rx, &mut p.rng);
    let ig = seal_to_b(&mut p, &ext(999, UnknownPolicy::Ignore), 0x71);
    assert!(matches!(
        deliver(&mut p.b, &ig, &mut p.rng),
        ReceiveOutcome::Ignored
    ));
    assert_eq!(acks_for(&mut p.b, &rx), 1);
    assert_eq!(acks_for(&mut p.b, &ig), 1);
    p.b.remove_contact(&a, NOW + 1, &mut p.rng).unwrap();
    assert_eq!(acks_for(&mut p.b, &rx), 0);
    assert_eq!(acks_for(&mut p.b, &ig), 0);
}

/// A reaction row on `target`, first seen at `first_seen`.
fn put_reaction(c: &Core, contact: Fingerprint, target: MessageId, first_seen: u64) {
    c.store
        .put_reaction_if_newer(&ReactionRow {
            message_id: target,
            reactor: contact.0,
            contact_fp: contact,
            emojis: emo(&["👍"]),
            clock: first_seen,
            tie: [1; 16],
            first_seen,
            first_tie: [1; 16],
        })
        .unwrap();
}

#[test]
fn orphan_reactions_are_purged_once_their_target_cannot_come() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let stored = message_id_of(&p.a, &b, "x");
    let late = NOW + MAX_AGE_SECS + 10;
    put_reaction(&p.a, b, MessageId([0x91; 16]), NOW); // orphan, too old
    put_reaction(&p.a, b, MessageId([0x92; 16]), late - 5); // orphan, young
    put_reaction(&p.a, b, stored, NOW); // old, on a stored message
    p.a.resend_reactions(late, &mut p.rng).unwrap();
    let left = |id: MessageId| p.a.store.reaction(id, b.0).unwrap().is_some();
    assert!(!left(MessageId([0x91; 16])));
    assert!(left(MessageId([0x92; 16])));
    assert!(left(stored));
}

// --- Lot 2 bis, task 1: the tracking of the current reaction send.

/// Alice reacts on Bob's message "y"; returns the packet for Bob.
fn react_y(p: &mut Pair, set: &[&str], now: u64) -> Packet {
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    let mut out = p.a.set_reactions(row, &emo(set), now, &mut p.rng).unwrap();
    assert_eq!(out.len(), 1, "one packet for Bob's only device");
    out.remove(0)
}

fn contact_tie(c: &Core, contact: Fingerprint, target: MessageId) -> Option<MessageId> {
    reactions::current_contact_tie(&c.store, contact, target).unwrap()
}

/// The states of the `own` deliveries keyed on `tie`.
fn tie_states(c: &Core, tie: MessageId, own: bool) -> Vec<i64> {
    let mut stmt = c
        .store
        .conn()
        .prepare("SELECT status FROM deliveries WHERE message_id = ?1 AND own = ?2")
        .unwrap();
    stmt.query_map(rusqlite::params![tie.0.as_slice(), own], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// The delivery tie of `packet`.
fn tie_of(c: &Core, packet: PacketId) -> MessageId {
    let tie: Vec<u8> = c
        .store
        .conn()
        .query_row(
            "SELECT message_id FROM deliveries WHERE packet_id = ?1",
            [packet.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    MessageId(tie.try_into().unwrap())
}

/// The ack `c` queued for `packet`.
fn ack_bytes(c: &mut Core, packet: &Packet, now: u64) -> Vec<u8> {
    c.pending_outbox(now)
        .unwrap()
        .into_iter()
        .find(|b| {
            let q = Packet::decode(b).unwrap();
            q.kind == Kind::Ack && q.payload[..16] == packet.id.0
        })
        .expect("an ack")
}

/// Leaves `c` with no session with `contact`'s devices and no key packet
/// to open one: a send to the contact seals nothing.
fn no_session_with(c: &Core, contact: Fingerprint) {
    let stored = c.store.get_contact(contact).unwrap().unwrap();
    let mut card = ContactCard::decode(&stored.card).unwrap();
    card.bundles.clear();
    let conn = c.store.conn();
    conn.execute(
        "UPDATE contacts SET card = ?2 WHERE fp = ?1",
        rusqlite::params![contact.0.as_slice(), card.encode()],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM sessions WHERE contact_fp = ?1",
        [contact.0.as_slice()],
    )
    .unwrap();
}

/// A linked to T, with Bob as a contact and an outgoing message "m" to
/// him on both; A reacts on it: `(Bob, target, Bob's packet, T's packet)`.
fn react_linked(
    a: &mut Core,
    t: &mut Core,
    rng: &mut StdRng,
) -> (TempDir, Fingerprint, MessageId, Packet, Packet) {
    let (db, bob) = party("bob", 5);
    let fp = a
        .add_contact(&bob.contact_card("Bob").unwrap(), Some("bob"), NOW, rng)
        .unwrap();
    deliver_all(a, t, rng);
    let target = MessageId([0x73; 16]);
    for c in [&mut *a, &mut *t] {
        c.store
            .insert_message(
                fp,
                Direction::Out,
                "m",
                MessageStatus::OnNetwork,
                NOW,
                target,
            )
            .unwrap();
    }
    let row = row_of(a, &fp, "m");
    let sent = a.set_reactions(row, &emo(&["👍"]), NOW, rng).unwrap();
    assert_eq!(sent.len(), 2, "one for Bob, one for T");
    let own = |p: &Packet| {
        a.store
            .conn()
            .query_row(
                "SELECT own FROM reaction_sends WHERE packet_id = ?1",
                [p.id.0.as_slice()],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
    };
    let (mine, theirs): (Vec<Packet>, Vec<Packet>) = sent.into_iter().partition(own);
    drop(bob);
    (db, fp, target, theirs[0].clone(), mine[0].clone())
}

#[test]
fn reaction_send_tracking_survives_leaving_the_queue() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "y");
    let pk = react_y(&mut p, &["👍"], NOW);
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    // It leaves the send queue (purged past the ack grace, say).
    p.a.store.outbox_remove(pk.id).unwrap();
    p.a.resend_reactions(NOW + 2, &mut p.rng).unwrap();
    deliver(&mut p.b, &pk, &mut p.rng);
    let ack = ack_bytes(&mut p.b, &pk, NOW);
    p.a.receive(&ack, "t", NOW + 3, &mut p.rng).unwrap();
    let tie = contact_tie(&p.a, b, target).expect("tracked");
    assert_eq!(
        tie_states(&p.a, tie, false),
        vec![MessageStatus::Received as i64]
    );
    assert_eq!(packet_rows(&p.a, "reaction_sends", pk.id), 1);
}

#[test]
fn own_copy_ack_does_not_make_the_reaction_received() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, _to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let _ = t.receive(&to_t.encode(), "t", NOW, &mut rng).unwrap();
    let ack = ack_bytes(&mut t, &to_t, NOW);
    a.receive(&ack, "t", NOW + 1, &mut rng).unwrap();
    let tie = contact_tie(&a, fp, target).expect("tracked");
    assert_eq!(
        tie_states(&a, tie, true),
        vec![MessageStatus::Received as i64]
    );
    assert_eq!(
        tie_states(&a, tie, false),
        vec![MessageStatus::Pending as i64]
    );
}

#[test]
fn new_reaction_send_replaces_the_previous_tracking() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "x");
    let first = react_x(&mut p, &["👍"], NOW);
    let second = react_x(&mut p, &["👍", "❤️"], NOW + 1);
    assert_eq!(packet_rows(&p.a, "deliveries", first.id), 0);
    assert_eq!(superseded(&p.a, first.id), Some(true), "kept, untracked");
    assert_eq!(packet_rows(&p.a, "outbox", first.id), 1, "it still leaves");
    assert_eq!(superseded(&p.a, second.id), Some(false));
    assert_eq!(packet_rows(&p.a, "deliveries", second.id), 1);
    assert_eq!(packet_rows(&p.a, "reaction_sends", second.id), 1);
    assert_eq!(contact_tie(&p.a, b, target), Some(tie_of(&p.a, second.id)));
}

#[test]
fn reaction_set_without_contact_session_forgets_the_older_send() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "x");
    react_x(&mut p, &["👍"], NOW);
    assert!(contact_tie(&p.a, b, target).is_some());
    no_session_with(&p.a, b);
    let row = row_of(&p.a, &b, "x");
    let sent =
        p.a.set_reactions(row, &emo(&["❤️"]), NOW + 1, &mut p.rng)
            .unwrap();
    assert!(sent.is_empty(), "no device of Bob to seal for");
    assert_eq!(contact_tie(&p.a, b, target), None);
}

#[test]
fn expired_contact_reaction_stays_not_delivered_after_full_sync() {
    let mut p = pair();
    let b = p.b.fingerprint();
    // On Bob's message: no message packet of its own to change with it.
    let target = message_id_of(&p.a, &b, "y");
    let row = row_of(&p.a, &b, "y");
    let pk = react_y(&mut p, &["👍"], NOW);
    let late = u64::from(pk.expires_at) + 1;
    p.a.take_delivery_changes();
    p.a.expire_due(late).unwrap();
    assert!(
        p.a.take_delivery_changes().contains(&(b, row)),
        "the expiry refreshes the target"
    );
    assert_eq!(
        p.a.resend_reactions(late, &mut p.rng).map(|r| r.resent),
        Ok(0)
    );
    assert!(p.a.pending_outbox(late).unwrap().is_empty());
    let tie = contact_tie(&p.a, b, target).expect("still tracked");
    assert_eq!(tie, tie_of(&p.a, pk.id));
    assert_eq!(
        tie_states(&p.a, tie, false),
        vec![MessageStatus::NotDelivered as i64]
    );
    assert_eq!(packet_rows(&p.a, "reaction_sends", pk.id), 1);
}

#[test]
fn expired_own_copy_is_still_resent() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let before = contact_tie(&a, fp, target).expect("tracked");
    let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
    a.expire_due(late).unwrap();
    assert_eq!(a.resend_reactions(late, &mut rng).map(|r| r.resent), Ok(1));
    // Only the copy for T is resealed.
    let queued = a.pending_outbox(late).unwrap();
    assert_eq!(queued.len(), 1);
    let resent = Packet::decode(&queued[0]).unwrap();
    let own: bool = a
        .store
        .conn()
        .query_row(
            "SELECT own FROM reaction_sends WHERE packet_id = ?1",
            [resent.id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(own);
    assert_eq!(contact_tie(&a, fp, target), Some(before));
    assert_eq!(
        tie_states(&a, before, false),
        vec![MessageStatus::NotDelivered as i64]
    );
    assert_eq!(packet_rows(&a, "reaction_sends", to_t.id), 0, "resent");
}

#[test]
fn reaction_delivery_change_names_the_target_row() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let pk = react_y(&mut p, &["👍"], NOW);
    p.a.take_delivery_changes();
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    assert!(
        p.a.take_delivery_changes()
            .contains(&(b, row_of(&p.a, &b, "y")))
    );
}

/// `reaction_sends.superseded` of `packet`, `None` without a row.
fn superseded(c: &Core, packet: PacketId) -> Option<bool> {
    c.store
        .conn()
        .query_row(
            "SELECT superseded FROM reaction_sends WHERE packet_id = ?1",
            [packet.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
}

#[test]
fn superseded_queued_reaction_still_counts_as_reaction() {
    let mut p = pair();
    let b = p.b.fingerprint();
    // Offline: both sets stay queued.
    react_x(&mut p, &["👍"], NOW);
    react_x(&mut p, &["👍", "❤️"], NOW + 1);
    let pending = p.a.pending_packets(NOW + 2).unwrap();
    let reaction: Vec<_> = pending
        .sync
        .iter()
        .filter(|s| s.kind == PendingKind::Reaction)
        .collect();
    assert_eq!(reaction.len(), 1);
    assert_eq!(
        (reaction[0].packets, reaction[0].contacts.clone()),
        (2, vec![b])
    );
    assert!(
        pending
            .sync
            .iter()
            .all(|s| s.kind != PendingKind::DeviceSync),
        "{pending:?}"
    );
}

#[test]
fn superseded_rows_go_once_the_packet_leaves() {
    let mut p = pair();
    let first = react_x(&mut p, &["👍"], NOW);
    // Sent just before the first expires (expiries are coarse).
    let later = u64::from(first.expires_at) - 10;
    let second = react_x(&mut p, &["👍", "❤️"], later);
    assert_eq!(superseded(&p.a, first.id), Some(true));
    // The first packet expires and leaves the queue; the second is still
    // queued.
    let late = u64::from(first.expires_at) + 1;
    assert!(u64::from(second.expires_at) >= late);
    p.a.resend_reactions(late, &mut p.rng).unwrap();
    assert!(gone(&p.a, first.id));
    assert_eq!(sends_where(&p.a, "superseded = 1"), 0);
    assert_eq!(superseded(&p.a, second.id), Some(false));
}

#[test]
fn acked_superseded_reaction_leaves_the_queue() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "x");
    let first = react_x(&mut p, &["👍"], NOW);
    let second = react_x(&mut p, &["👍", "❤️"], NOW + 1);
    p.a.record_deposit(first.id, NODE, NOW + 2).unwrap();
    deliver(&mut p.b, &first, &mut p.rng);
    let ack = ack_bytes(&mut p.b, &first, NOW);
    p.a.receive(&ack, "t", NOW + 3, &mut p.rng).unwrap();
    assert_eq!(packet_rows(&p.a, "outbox", first.id), 0, "left the queue");
    assert_eq!(superseded(&p.a, first.id), None);
    let pending = p.a.pending_packets(NOW + 3).unwrap();
    let reaction: Vec<_> = pending
        .sync
        .iter()
        .filter(|s| s.kind == PendingKind::Reaction)
        .collect();
    assert_eq!(reaction.len(), 1);
    assert_eq!(reaction[0].packets, 1, "only the current send");
    // The current send is untouched.
    let tie = tie_of(&p.a, second.id);
    assert_eq!(contact_tie(&p.a, b, target), Some(tie));
    assert_eq!(
        tie_states(&p.a, tie, false),
        vec![MessageStatus::Pending as i64]
    );
}

// --- Lot 2 bis, task 2: reaction state, sheet read and manual retry.

#[test]
fn my_reaction_state_follows_the_contact_send() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    let pk = react_y(&mut p, &["👍"], NOW);
    assert_eq!(p.a.my_reaction_state(row), Ok(Some(MessageStatus::Pending)));
    p.a.record_deposit(pk.id, NODE, NOW + 1).unwrap();
    assert_eq!(
        p.a.my_reaction_state(row),
        Ok(Some(MessageStatus::OnNetwork))
    );
    deliver(&mut p.b, &pk, &mut p.rng);
    let ack = ack_bytes(&mut p.b, &pk, NOW);
    p.a.receive(&ack, "t", NOW + 2, &mut p.rng).unwrap();
    assert_eq!(
        p.a.my_reaction_state(row),
        Ok(Some(MessageStatus::Received))
    );
    assert_eq!(p.a.my_reaction_state(row_of(&p.a, &b, "x")), Ok(None));
}

#[test]
fn my_reaction_state_is_none_for_a_synced_reaction() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, _target, _to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let _ = t.receive(&to_t.encode(), "t", NOW, &mut rng).unwrap();
    let row = row_of(&t, &fp, "m");
    assert!(
        !t.reaction_chips(&fp, MessageId([0x73; 16]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(t.my_reaction_state(row), Ok(None));
}

#[test]
fn reaction_delivery_reports_a_removal() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    react_y(&mut p, &["❤️"], NOW);
    let sent = p.a.set_reactions(row, &[], NOW + 1, &mut p.rng).unwrap();
    assert_eq!(sent.len(), 1);
    let detail =
        p.a.reaction_delivery(row, NOW + 2)
            .unwrap()
            .expect("tracked");
    assert!(detail.emojis.is_empty());
    assert_eq!(detail.summary.state, MessageStatus::Pending);
    assert_eq!((detail.row_id, detail.contact), (row, b));
}

#[test]
fn reaction_delivery_lists_devices_and_relays() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, _target, to_bob, _to_t) = react_linked(&mut a, &mut t, &mut rng);
    a.record_deposit(to_bob.id, "K7QX2M4A", NOW + 1).unwrap();
    let row = row_of(&a, &fp, "m");
    let detail = a.reaction_delivery(row, NOW + 2).unwrap().expect("tracked");
    assert_eq!(detail.emojis, emo(&["👍"]));
    assert_eq!(detail.summary.state, MessageStatus::OnNetwork);
    assert_eq!(detail.relays[0].node, "K7QX2M4A");
    let own: Vec<bool> = detail.deliveries.iter().map(|d| d.own).collect();
    assert_eq!(own, vec![false, true], "contact devices first");
    assert_eq!(detail.own_copies.total, 1);
    assert_eq!(detail.summary.devices, 1);
}

/// Alice reacts 👍 on "y"; the packet expires undeposited: `(row, late,
/// old tie)`.
fn failed_reaction_on_y(p: &mut Pair) -> (i64, u64, MessageId) {
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    let pk = react_y(p, &["👍"], NOW);
    let late = u64::from(pk.expires_at) + 1;
    p.a.expire_due(late).unwrap();
    assert_eq!(
        p.a.my_reaction_state(row),
        Ok(Some(MessageStatus::NotDelivered))
    );
    (row, late, tie_of(&p.a, pk.id))
}

#[test]
fn retry_reactions_reseals_the_current_set() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "y");
    let (row, late, old_tie) = failed_reaction_on_y(&mut p);
    let before = p.a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    p.a.take_delivery_changes();
    let sent = p.a.retry_reactions(row, late, &mut p.rng).unwrap();
    assert_eq!(sent.len(), 1, "one packet for Bob's only device");
    assert_eq!(p.a.my_reaction_state(row), Ok(Some(MessageStatus::Pending)));
    let tie = contact_tie(&p.a, b, target).expect("tracked");
    assert_ne!(tie, old_tie);
    assert_eq!(tie, tie_of(&p.a, sent[0].id));
    let after = p.a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    assert!(after.clock > before.clock);
    assert_eq!(after.emojis, before.emojis);
    assert!(p.a.take_delivery_changes().contains(&(b, row)));
    // Bob gets the set, on his own row of "y".
    let a = p.a.fingerprint();
    let on_b = message_id_of(&p.b, &a, "y");
    let got = p.b.receive(&sent[0].encode(), "t", late, &mut p.rng);
    assert!(
        matches!(got, Ok(ReceiveOutcome::Reaction { .. })),
        "{got:?}"
    );
    assert_eq!(counts(&p.b, &a, on_b), vec![("👍".to_owned(), 1)]);
}

#[test]
fn retry_reactions_refuses_when_not_failed() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    react_y(&mut p, &["👍"], NOW);
    assert_eq!(
        p.a.retry_reactions(row, NOW + 1, &mut p.rng),
        Err(CoreError::NothingToRetry)
    );
    // No reaction of mine at all.
    assert_eq!(
        p.a.retry_reactions(row_of(&p.a, &b, "x"), NOW + 1, &mut p.rng),
        Err(CoreError::NothingToRetry)
    );
    assert_eq!(
        p.a.retry_reactions(i64::MAX, NOW + 1, &mut p.rng),
        Err(CoreError::MessageNotFound)
    );
}

#[test]
fn retry_reactions_without_session_changes_nothing() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let target = message_id_of(&p.a, &b, "y");
    let (row, late, old_tie) = failed_reaction_on_y(&mut p);
    let before = p.a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    no_session_with(&p.a, b);
    assert_eq!(
        p.a.retry_reactions(row, late, &mut p.rng),
        Err(CoreError::NoSession)
    );
    assert_eq!(
        p.a.my_reaction_state(row),
        Ok(Some(MessageStatus::NotDelivered))
    );
    assert_eq!(contact_tie(&p.a, b, target), Some(old_tie));
    assert_eq!(
        tie_states(&p.a, old_tie, false),
        vec![MessageStatus::NotDelivered as i64]
    );
    assert_eq!(
        p.a.store.reaction(target, ME_REACTOR).unwrap(),
        Some(before)
    );
}

#[test]
fn retry_reactions_refuses_a_blocked_contact() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let (row, late, _) = failed_reaction_on_y(&mut p);
    p.a.block_contact(&b, late, &mut p.rng).unwrap();
    assert_eq!(
        p.a.retry_reactions(row, late, &mut p.rng),
        Err(CoreError::ContactBlocked)
    );
}

#[test]
fn retry_reactions_reseals_an_own_copy_that_never_left() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
    a.expire_due(late).unwrap();
    let row = row_of(&a, &fp, "m");
    let sent = a.retry_reactions(row, late, &mut rng).unwrap();
    assert_eq!(sent.len(), 2, "one for Bob, one for T");
    let mine = a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    for p in &sent {
        let _ = t.receive(&p.encode(), "t", late, &mut rng);
    }
    let on_t = t.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    assert_eq!((on_t.clock, on_t.emojis), (mine.clock, emo(&["👍"])));
}

#[test]
fn retry_reactions_leaves_an_own_copy_that_left() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, _target, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    a.record_deposit(to_t.id, NODE, NOW + 1).unwrap();
    let late = u64::from(to_bob.expires_at) + 1;
    a.expire_due(late).unwrap();
    let row = row_of(&a, &fp, "m");
    let sent = a.retry_reactions(row, late, &mut rng).unwrap();
    assert_eq!(sent.len(), 1, "Bob only");
}

#[test]
fn retry_reactions_resends_a_failed_removal() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "y");
    let first = react_y(&mut p, &["❤️"], NOW);
    deliver(&mut p.b, &first, &mut p.rng);
    let removal = p.a.set_reactions(row, &[], NOW + 1, &mut p.rng).unwrap();
    let late = u64::from(removal[0].expires_at) + 1;
    p.a.expire_due(late).unwrap();
    assert_eq!(
        p.a.my_reaction_state(row),
        Ok(Some(MessageStatus::NotDelivered))
    );
    let sent = p.a.retry_reactions(row, late, &mut p.rng).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(p.a.my_reaction_state(row), Ok(Some(MessageStatus::Pending)));
    let detail = p.a.reaction_delivery(row, late).unwrap().expect("tracked");
    assert!(detail.emojis.is_empty());
    let a = p.a.fingerprint();
    let on_b = message_id_of(&p.b, &a, "y");
    assert!(!p.b.reaction_chips(&a, on_b).unwrap().is_empty());
    let _ =
        p.b.receive(&sent[0].encode(), "t", late, &mut p.rng)
            .unwrap();
    assert!(p.b.reaction_chips(&a, on_b).unwrap().is_empty());
}

#[test]
fn synced_newer_set_forgets_the_local_contact_send() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, to_bob, _to_t) = react_linked(&mut a, &mut t, &mut rng);
    a.record_deposit(to_bob.id, NODE, NOW + 1).unwrap();
    let row = row_of(&a, &fp, "m");
    assert_eq!(a.my_reaction_state(row), Ok(Some(MessageStatus::OnNetwork)));
    let t_row = row_of(&t, &fp, "m");
    // T reacts before it saw A's copy, with an older clock: ignored here.
    let older = t
        .set_reactions(t_row, &emo(&["❤️"]), NOW - 10, &mut rng)
        .unwrap();
    for p in &older {
        let _ = a.receive(&p.encode(), "t", NOW + 2, &mut rng).unwrap();
    }
    assert_eq!(
        a.store
            .reaction(target, ME_REACTOR)
            .unwrap()
            .unwrap()
            .emojis,
        emo(&["👍"])
    );
    assert_eq!(a.my_reaction_state(row), Ok(Some(MessageStatus::OnNetwork)));
    assert!(a.reaction_delivery(row, NOW + 2).unwrap().is_some());
    // A newer set from T, the same emoji as A's (it adds nothing here):
    // A's contact send no longer describes my current set.
    let newer = t
        .set_reactions(t_row, &emo(&["👍"]), NOW + 5, &mut rng)
        .unwrap();
    for p in &newer {
        let _ = a.receive(&p.encode(), "t", NOW + 6, &mut rng).unwrap();
    }
    let mine = a.store.reaction(target, ME_REACTOR).unwrap().unwrap();
    assert_eq!(mine.clock, NOW + 5, "T's set applied");
    assert_eq!(a.my_reaction_state(row), Ok(None));
    assert_eq!(a.reaction_delivery(row, NOW + 6), Ok(None));
    assert_eq!(contact_tie(&a, fp, target), None);
}

#[test]
fn retry_reactions_without_contact_session_seals_no_own_copy() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, fp, target, to_bob, to_t) = react_linked(&mut a, &mut t, &mut rng);
    let late = u64::from(to_bob.expires_at.max(to_t.expires_at)) + 1;
    a.expire_due(late).unwrap();
    let row = row_of(&a, &fp, "m");
    let before = a.store.reaction(target, ME_REACTOR).unwrap();
    let rows = |c: &Core| -> i64 {
        c.store
            .conn()
            .query_row("SELECT count(*) FROM reaction_sends", [], |r| r.get(0))
            .unwrap()
    };
    let sends = rows(&a);
    no_session_with(&a, fp);
    // My copy for T never left, but no device of Bob can be sealed for.
    assert_eq!(
        a.retry_reactions(row, late, &mut rng),
        Err(CoreError::NoSession)
    );
    assert_eq!(rows(&a), sends);
    assert_eq!(a.store.reaction(target, ME_REACTOR).unwrap(), before);
    assert_eq!(
        a.my_reaction_state(row),
        Ok(Some(MessageStatus::NotDelivered))
    );
}

// --- Deletion and ephemeral, task 1: `SyncDelete` to my other devices.

/// Gives each packet to each of `cores`, ignoring those not for it.
fn deliver_each(pkts: &[Packet], cores: &mut [&mut Core], rng: &mut StdRng) {
    for p in pkts {
        for c in cores.iter_mut() {
            c.receive(&p.encode(), "t", NOW, rng).unwrap();
        }
    }
}

fn not_acks(c: &mut Core) -> usize {
    c.pending_outbox(NOW)
        .unwrap()
        .iter()
        .filter(|b| Packet::decode(b).unwrap().kind != Kind::Ack)
        .count()
}

fn is_tombstoned(c: &Core, id: MessageId) -> bool {
    c.store
        .conn()
        .query_row(
            "SELECT count(*) FROM deleted_messages WHERE message_id = ?1",
            rusqlite::params![id.0.as_slice()],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        == 1
}

fn synced_delete(o: ReceiveOutcome) {
    assert!(
        matches!(
            o,
            ReceiveOutcome::Synced {
                kind: SyncKind::Delete,
                contact: None
            }
        ),
        "{o:?}"
    );
}

/// `ids` deleted identifiers, as a `SyncDelete` from `from` to its other
/// device (one packet).
fn seal_delete(from: &mut Core, ids: usize, mid: u8, rng: &mut StdRng) -> Packet {
    let ids = (0..ids)
        .map(|i| MessageId([0x80 | u8::try_from(i).unwrap(); 16]))
        .collect();
    let body = ExtContent::SyncDelete { ids }.to_body();
    assert!(crate::envelope::fits_in_packet(&body));
    let mut sealed = seal_body(
        from,
        &send::Target::OwnDevices,
        &body,
        MessageId([mid; 16]),
        rng,
    );
    assert_eq!(sealed.len(), 1);
    sealed.remove(0).0
}

#[test]
fn sync_delete_of_32_ids_fits_tier_m() {
    let (_d, mut a, mut t, _b, _v1, mut rng) = alice_tablet_bob();
    // The session between the phone and the tablet is opened and answered
    // first: an opening packet carries the session keys (tier L whatever
    // it holds).
    let first = seal_delete(&mut a, 1, 0x40, &mut rng);
    synced_delete(deliver(&mut t, &first, &mut rng));
    let answer = seal_delete(&mut t, 1, 0x41, &mut rng);
    synced_delete(deliver(&mut a, &answer, &mut rng));
    let full = seal_delete(&mut a, crate::content::MAX_SYNC_DELETE_IDS, 0x42, &mut rng);
    assert_eq!(full.tier, Tier::M);
}

#[test]
fn delete_on_phone_removes_message_on_tablet() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = b.send_text(&alice, "hi", NOW, &mut rng).unwrap();
    deliver_each(&sent, &mut [&mut a, &mut t], &mut rng);
    let react = b
        .set_reactions(row_of(&b, &alice, "hi"), &emo(&["👍"]), NOW, &mut rng)
        .unwrap();
    deliver_each(&react, &mut [&mut a, &mut t], &mut rng);
    assert_eq!(reaction_rows(&t), 1);
    let id = message_id_of(&t, &bob, "hi");
    let (outcome, pkts) = a
        .delete_message(row_of(&a, &bob, "hi"), NOW + 5, &mut rng)
        .unwrap();
    assert_eq!(outcome.deleted, 1);
    assert_eq!(pkts.len(), 1, "one copy for the tablet");
    synced_delete(deliver(&mut t, &pkts[0], &mut rng));
    assert_eq!(acks_for(&mut t, &pkts[0]), 1);
    assert!(t.messages_with(&bob, NOW).unwrap().is_empty());
    assert!(is_tombstoned(&t, id));
    assert_eq!(reaction_rows(&t), 0);
    // Logged as coming from another of my devices; the phone's own entry
    // is not.
    let deleted = |c: &Core| {
        c.transparency_log(100)
            .unwrap()
            .into_iter()
            .filter_map(|(_, e)| match e {
                TransparencyEvent::MessagesDeleted {
                    count,
                    from_other_device,
                    ..
                } => Some((count, from_other_device)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(deleted(&t), [(1, true)]);
    assert_eq!(deleted(&a), [(1, false)]);
    // The same copy again: a duplicate, nothing more.
    let again = t.receive(&pkts[0].encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(again, ReceiveOutcome::Duplicate), "{again:?}");
}

#[test]
fn sync_delete_before_message_blocks_it_forever() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = b.send_text(&alice, "hi", NOW, &mut rng).unwrap();
    deliver_each(&sent, &mut [&mut a], &mut rng);
    let (_, pkts) = a
        .delete_message(row_of(&a, &bob, "hi"), NOW + 5, &mut rng)
        .unwrap();
    // The tablet gets the deletion first, then Bob's packet.
    synced_delete(deliver(&mut t, &pkts[0], &mut rng));
    deliver_each(&sent, &mut [&mut t], &mut rng);
    assert!(t.messages_with(&bob, NOW).unwrap().is_empty());
    let react = b
        .set_reactions(row_of(&b, &alice, "hi"), &emo(&["👍"]), NOW, &mut rng)
        .unwrap();
    deliver_each(&react, &mut [&mut t], &mut rng);
    assert!(t.messages_with(&bob, NOW).unwrap().is_empty());
    assert_eq!(reaction_rows(&t), 0);
}

/// The phone sends "x" to Bob, the tablet gets its copy and deletes it;
/// `tried`: a deposit of Bob's packet was tried first. Returns the phone,
/// Bob's packet and the message.
fn delete_on_tablet(tried: bool) -> (TempDir, Core, Packet, MessageId) {
    let (d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "x", NOW, &mut rng).unwrap();
    assert_eq!(sent.len(), 2, "Bob's device, then my tablet");
    let mid = message_id_of(&a, &bob, "x");
    deliver(&mut t, &sent[1], &mut rng);
    if tried {
        a.record_deposit_tried(sent[0].id, NOW + 1).unwrap();
    }
    let (_, pkts) = t
        .delete_message(row_of(&t, &bob, "x"), NOW + 5, &mut rng)
        .unwrap();
    assert_eq!(pkts.len(), 1, "one copy for the phone");
    synced_delete(deliver(&mut a, &pkts[0], &mut rng));
    assert!(!has_message(&a, &bob, "x"));
    (d, a, sent[0].clone(), mid)
}

#[test]
fn sync_delete_cancels_untried_pending_packet_on_sealer() {
    let (_d, a, to_bob, mid) = delete_on_tablet(false);
    assert_eq!(outbox_row(&a, to_bob.id), None);
    assert!(deliveries_of(&a, mid).is_empty());
    // Tried: a node may hold it, it is kept.
    let (_d, a, to_bob, mid) = delete_on_tablet(true);
    assert_eq!(outbox_row(&a, to_bob.id), Some(None));
    assert!(
        deliveries_of(&a, mid).contains(&(0, MessageStatus::Pending as i64)),
        "{:?}",
        deliveries_of(&a, mid)
    );
}

#[test]
fn seventy_ids_make_three_sync_packets() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let mut rows = Vec::new();
    for i in 0..70u8 {
        let body = format!("m{i}");
        a.store
            .insert_message(
                bob,
                Direction::Out,
                &body,
                MessageStatus::OnNetwork,
                NOW,
                MessageId([i; 16]),
            )
            .unwrap();
        rows.push(row_of(&a, &bob, &body));
    }
    let (outcome, pkts) = a.delete_messages(&rows, NOW + 5, &mut rng).unwrap();
    assert_eq!(outcome.deleted, 70);
    assert_eq!(pkts.len(), 3, "32 + 32 + 6 ids");
    let before = tombstones(&t);
    for p in &pkts {
        synced_delete(deliver(&mut t, p, &mut rng));
    }
    assert_eq!(tombstones(&t) - before, 70);
}

#[test]
fn received_sync_delete_sends_nothing() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = b.send_text(&alice, "hi", NOW, &mut rng).unwrap();
    deliver_each(&sent, &mut [&mut a, &mut t], &mut rng);
    let (_, pkts) = a
        .delete_message(row_of(&a, &bob, "hi"), NOW + 5, &mut rng)
        .unwrap();
    let before = not_acks(&mut t);
    synced_delete(deliver(&mut t, &pkts[0], &mut rng));
    assert_eq!(not_acks(&mut t), before);
    assert_eq!(acks_for(&mut t, &pkts[0]), 1);
}

#[test]
fn sync_delete_from_contact_is_refused() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let b_fp = p.b.fingerprint();
    let before = p.a.messages_with(&b_fp, NOW).unwrap();
    let ids = before.iter().map(|m| m.message_id).collect();
    let body = ExtContent::SyncDelete { ids }.to_body();
    let out = seal_body(
        &mut p.b,
        &send::Target::Contact(a_fp),
        &body,
        MessageId([0x44; 16]),
        &mut p.rng,
    );
    let r =
        p.a.receive(&out[0].0.encode(), "t", NOW, &mut p.rng)
            .unwrap();
    assert_eq!(reason(r), NOT_MINE);
    assert_eq!(p.a.messages_with(&b_fp, NOW).unwrap(), before);
    assert_eq!(tombstones(&p.a), 0);
}

#[test]
fn sync_delete_for_unknown_contact_only_tombstones() {
    let (_d, mut a, mut t, mut rng) = linked();
    let id = MessageId::incoming(&Fingerprint([7; 32]), &[1; 16]);
    let body = ExtContent::SyncDelete { ids: vec![id] }.to_body();
    let sealed = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &body,
        MessageId([0x45; 16]),
        &mut rng,
    );
    let pkt = &sealed[0].0;
    synced_delete(deliver(&mut t, pkt, &mut rng));
    assert_eq!(acks_for(&mut t, pkt), 1);
    assert!(is_tombstoned(&t, id));
}

#[test]
fn cancel_all_pending_syncs_its_deletions() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    for text in ["one", "two"] {
        let sent = a.send_text(&bob, text, NOW, &mut rng).unwrap();
        deliver(&mut t, &sent[1], &mut rng);
    }
    assert_eq!(t.messages_with(&bob, NOW).unwrap().len(), 2);
    let (outcome, pkts) = a.cancel_all_pending(NOW + 5, &mut rng).unwrap();
    assert_eq!(outcome.deleted, 2);
    assert_eq!(pkts.len(), 1);
    synced_delete(deliver(&mut t, &pkts[0], &mut rng));
    assert!(t.messages_with(&bob, NOW).unwrap().is_empty());
}

#[test]
fn delete_without_another_device_seals_nothing() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let row = row_of(&p.a, &b, "x");
    let (outcome, pkts) = p.a.delete_message(row, NOW + 5, &mut p.rng).unwrap();
    assert_eq!(outcome.deleted, 1);
    assert!(pkts.is_empty());
}

#[test]
fn delete_on_a_removed_device_stays_local() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a.send_text(&bob, "x", NOW, &mut rng).unwrap();
    deliver(&mut t, &sent[1], &mut rng);
    let t_id = t.device.public().id();
    let removal = a.remove_device(t_id, NOW, &mut rng).unwrap();
    deliver_each(&removal, &mut [&mut t], &mut rng);
    assert!(t.removed().unwrap().is_some());
    let before = not_acks(&mut t);
    let (outcome, pkts) = t
        .delete_message(row_of(&t, &bob, "x"), NOW + 5, &mut rng)
        .unwrap();
    assert_eq!(outcome.deleted, 1);
    assert!(pkts.is_empty());
    assert_eq!(not_acks(&mut t), before);
}

// --- Deletion and ephemeral, task 3: sending and receiving an ephemeral.

use crate::content::{KIND_MESSAGE, UNSEEN_CEILING_SECS};

/// `ttl_secs`, `seen_at` and `expire_at` of the row with this body.
fn ephemeral_cols(
    c: &Core,
    contact: &Fingerprint,
    body: &str,
) -> (Option<u32>, Option<u64>, Option<u64>) {
    let row = full_row(c, contact, body);
    (row.ttl_secs, row.seen_at, row.expire_at)
}

#[test]
fn send_rejects_ttl_out_of_bounds() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let outbox = p.a.pending_outbox(NOW).unwrap().len();
    let rows = p.a.messages_with(&b, NOW).unwrap().len();
    for ttl in [0, 59, 604_801, u32::MAX] {
        assert_eq!(
            p.a.send_message(&b, "nope", None, Some(ttl), NOW, &mut p.rng),
            Err(CoreError::InvalidTtl),
            "{ttl}"
        );
    }
    assert_eq!(p.a.messages_with(&b, NOW).unwrap().len(), rows);
    assert_eq!(p.a.pending_outbox(NOW).unwrap().len(), outbox);
}

#[test]
fn ephemeral_text_uses_message_kind_and_plain_uses_text() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let out =
        p.a.send_message(&b, "secret", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    let Body::Ext { kind, data, .. } = peek_envelope(&p.b, &out[0]).body else {
        panic!("Ext expected");
    };
    assert_eq!(kind, KIND_MESSAGE);
    assert_eq!(
        ExtContent::decode(kind, &data).unwrap(),
        Some(ExtContent::Message {
            text: "secret".into(),
            reply_to: None,
            ttl_secs: Some(300),
        })
    );
    let plain =
        p.a.send_message(&b, "plain", None, None, NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(peek_envelope(&p.b, &plain[0]).body, Body::Text(_)));
    assert_eq!(ephemeral_cols(&p.a, &b, "plain"), (None, None, None));
}

#[test]
fn received_ephemeral_has_ceiling() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let out =
        p.b.send_message(&a, "poof", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    // Received later than sent: the ceiling counts from the insertion.
    let r = NOW + 7;
    let got = p.a.receive(&out[0].encode(), "t", r, &mut p.rng).unwrap();
    assert!(
        matches!(got, ReceiveOutcome::Message { ref text, ephemeral: true, .. } if text == "poof"),
        "{got:?}"
    );
    assert_eq!(
        ephemeral_cols(&p.a, &b, "poof"),
        (Some(300), None, Some(r + UNSEEN_CEILING_SECS))
    );
    // A plain text is not ephemeral.
    let plain = p.b.send_text(&a, "stays", NOW, &mut p.rng).unwrap();
    let got = p.a.receive(&plain[0].encode(), "t", r, &mut p.rng).unwrap();
    assert!(
        matches!(
            got,
            ReceiveOutcome::Message {
                ephemeral: false,
                ..
            }
        ),
        "{got:?}"
    );
    assert_eq!(ephemeral_cols(&p.a, &b, "stays"), (None, None, None));
}

#[test]
fn received_message_without_ttl_is_a_plain_text() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let body = ExtContent::Message {
        text: "v2".into(),
        reply_to: None,
        ttl_secs: None,
    }
    .to_body();
    let out = seal_body(
        &mut p.b,
        &send::Target::Contact(a),
        &body,
        MessageId([0x61; 16]),
        &mut p.rng,
    );
    let got = deliver(&mut p.a, &out[0].0, &mut p.rng);
    assert!(
        matches!(
            got,
            ReceiveOutcome::Message {
                ephemeral: false,
                ..
            }
        ),
        "{got:?}"
    );
    assert_eq!(ephemeral_cols(&p.a, &b, "v2"), (None, None, None));
}

#[test]
fn sent_ephemeral_is_seen_at_send() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let now = NOW + 3;
    p.a.send_message(&b, "mine", None, Some(300), now, &mut p.rng)
        .unwrap();
    assert_eq!(
        ephemeral_cols(&p.a, &b, "mine"),
        (Some(300), Some(now), Some(now + 300))
    );
}

#[test]
fn ephemeral_reply_carries_reference() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let pk = p.a.send_text(&b, "18 h ?", NOW, &mut p.rng).unwrap();
    deliver(&mut p.b, &pk[0], &mut p.rng);
    let quoted = full_row(&p.b, &a, "18 h ?");
    let out =
        p.b.send_message(&a, "oui", Some(quoted.id), Some(60), NOW, &mut p.rng)
            .unwrap();
    let mine = full_row(&p.b, &a, "oui");
    assert_eq!(mine.reply_to, Some(quoted.message_id));
    assert_eq!(
        mine.reply_ref,
        Some(MessageRef {
            id: quoted.wire_id.unwrap(),
            by_sender: false
        })
    );
    assert_eq!(mine.ttl_secs, Some(60));
    let got = deliver(&mut p.a, &out[0], &mut p.rng);
    assert!(
        matches!(
            got,
            ReceiveOutcome::Message {
                ephemeral: true,
                ..
            }
        ),
        "{got:?}"
    );
    let original = full_row(&p.a, &b, "18 h ?");
    let reply = full_row(&p.a, &b, "oui");
    assert_eq!(reply.reply_to, Some(original.message_id));
    assert_eq!(reply.reply_ref, mine.reply_ref);
    assert_eq!(reply.ttl_secs, Some(60));
    assert_eq!(
        p.a.message_in(&b, reply.reply_to.unwrap(), NOW)
            .unwrap()
            .unwrap()
            .body,
        "18 h ?"
    );
}

#[test]
fn tablet_gets_sync_message_with_ttl() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = b.send_text(&alice, "q", NOW, &mut rng).unwrap();
    deliver_each(&first, &mut [&mut a, &mut t], &mut rng);
    let quoted = full_row(&a, &bob, "q");
    let sent = a
        .send_message(&bob, "e", Some(quoted.id), Some(300), NOW, &mut rng)
        .unwrap();
    assert_eq!(
        sent.len(),
        3,
        "one for Bob, one copy and its \"seen\" for the tablet"
    );
    let r = NOW + 9;
    let got = t.receive(&sent[1].encode(), "t", r, &mut rng).unwrap();
    assert!(
        matches!(
            got,
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                contact: Some(c)
            } if c == bob
        ),
        "{got:?}"
    );
    let row = full_row(&t, &bob, "e");
    assert_eq!(row.direction, Direction::Out);
    assert_eq!(row.at, NOW);
    assert_eq!(
        (row.ttl_secs, row.seen_at, row.expire_at),
        (Some(300), None, Some(r + UNSEEN_CEILING_SECS))
    );
    assert_eq!(row.reply_to, Some(full_row(&t, &bob, "q").message_id));
    assert_eq!(row.reply_ref, full_row(&a, &bob, "e").reply_ref);
    // Bob's side: an ephemeral from Alice.
    let at_bob = deliver(&mut b, &sent[0], &mut rng);
    assert!(
        matches!(
            at_bob,
            ReceiveOutcome::Message {
                ephemeral: true,
                ..
            }
        ),
        "{at_bob:?}"
    );
}

#[test]
fn sync_message_from_contact_and_message_from_my_device_refused() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let body = ExtContent::SyncMessage {
        to: a,
        text: "faux".into(),
        reply_to: None,
        ttl_secs: Some(300),
    }
    .to_body();
    let out = seal_body(
        &mut p.b,
        &send::Target::Contact(a),
        &body,
        MessageId([0x62; 16]),
        &mut p.rng,
    );
    assert_eq!(reason(deliver(&mut p.a, &out[0].0, &mut p.rng)), NOT_MINE);

    let (_d, mut a, mut t, mut rng) = linked();
    let body = ExtContent::Message {
        text: "x".into(),
        reply_to: None,
        ttl_secs: Some(300),
    }
    .to_body();
    let out = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &body,
        MessageId([0x63; 16]),
        &mut rng,
    );
    let r = t.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(r), "unexpected content for this mailbox");
}

#[test]
fn ephemeral_from_blocked_contact_dropped() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let bob = p.a.resolve("bob").unwrap();
    let out =
        p.b.send_message(&a, "blocked", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    p.a.block_contact(&bob, NOW, &mut p.rng).unwrap();
    let r = p.a.receive(&out[0].encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(r), "blocked contact");
    assert_eq!(acks_for(&mut p.a, &out[0]), 0);
    assert!(
        p.a.messages_with(&bob, NOW)
            .unwrap()
            .iter()
            .all(|m| m.body != "blocked")
    );
}

#[test]
fn resend_of_not_delivered_ephemeral_keeps_ttl() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let sent =
        p.a.send_message(&b, "again", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    let before = full_row(&p.a, &b, "again");
    // Refused by a node: not delivered while the message is still shown
    // here (a resend needs its text, erased at `NOW + 300`).
    let late = NOW + 4;
    assert!(p.a.drop_outbox_packet(&sent[0].encode(), late).unwrap());
    assert_eq!(
        full_row(&p.a, &b, "again").status,
        MessageStatus::NotDelivered
    );
    let again = p.a.retry_message(before.id, late, &mut p.rng).unwrap();
    let after = full_row(&p.a, &b, "again");
    assert_eq!(
        (after.ttl_secs, after.seen_at, after.expire_at),
        (before.ttl_secs, before.seen_at, before.expire_at)
    );
    let r =
        p.b.receive(&again[0].encode(), "t", late, &mut p.rng)
            .unwrap();
    assert!(
        matches!(
            r,
            ReceiveOutcome::Message {
                ephemeral: true,
                ..
            }
        ),
        "{r:?}"
    );
    assert_eq!(
        ephemeral_cols(&p.b, &a, "again"),
        (Some(300), None, Some(late + UNSEEN_CEILING_SECS))
    );
}

// --- Deletion and ephemeral, task 4: seen, `SyncSeen`, expiry, erasure.

use crate::content::{KIND_SYNC_SEEN, MAX_SYNC_SEEN, SeenEntry};

/// `entries` as a `SyncSeen` from `from` to its other device (one packet).
fn seal_seen_pkt(from: &mut Core, entries: Vec<SeenEntry>, mid: u8, rng: &mut StdRng) -> Packet {
    let body = ExtContent::SyncSeen { seen: entries }.to_body();
    let mut sealed = seal_body(
        from,
        &send::Target::OwnDevices,
        &body,
        MessageId([mid; 16]),
        rng,
    );
    assert_eq!(sealed.len(), 1);
    sealed.remove(0).0
}

fn synced_seen(o: &ReceiveOutcome) {
    assert!(
        matches!(
            o,
            ReceiveOutcome::Synced {
                kind: SyncKind::Seen,
                contact: None
            }
        ),
        "{o:?}"
    );
}

/// The phone–tablet session opened and answered: their packets are no
/// longer openings (tier L whatever they hold).
fn answer_own_session(a: &mut Core, t: &mut Core, rng: &mut StdRng) {
    let first = seal_delete(a, 1, 0x40, rng);
    synced_delete(deliver(t, &first, rng));
    let answer = seal_delete(t, 1, 0x41, rng);
    synced_delete(deliver(a, &answer, rng));
}

/// `(seen_at, expire_at)` of the row with this body, read at `now`.
fn seen_cols(c: &Core, contact: &Fingerprint, body: &str) -> (Option<u64>, Option<u64>) {
    let row = full_row(c, contact, body);
    (row.seen_at, row.expire_at)
}

/// Rows stored with this body, shown or not.
fn stored_rows(c: &Core, body: &str) -> i64 {
    c.store
        .conn()
        .query_row(
            "SELECT count(*) FROM messages WHERE body = ?1",
            rusqlite::params![body],
            |r| r.get(0),
        )
        .unwrap()
}

fn pending_seen_rows(c: &Core) -> i64 {
    c.store
        .conn()
        .query_row("SELECT count(*) FROM pending_seen", [], |r| r.get(0))
        .unwrap()
}

/// Alice's phone and tablet, and Bob; Bob's ephemeral "e" (`ttl`)
/// received by both of Alice's devices at `NOW`.
fn ephemeral_on_both(ttl: u32) -> (TempDir, Core, Core, Core, StdRng) {
    let (d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let alice = a.fingerprint();
    let sent = b
        .send_message(&alice, "e", None, Some(ttl), NOW, &mut rng)
        .unwrap();
    deliver_each(&sent, &mut [&mut a, &mut t], &mut rng);
    (d, a, t, b, rng)
}

#[test]
fn sync_seen_cap_fits_tier_m() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    answer_own_session(&mut a, &mut t, &mut rng);
    let entries = |n: usize, at: u64| -> Vec<SeenEntry> {
        (0..n)
            .map(|i| SeenEntry {
                id: MessageId([0x90 | u8::try_from(i).unwrap(); 16]),
                contact: b.fingerprint(),
                at,
            })
            .collect()
    };
    // A realistic date and the longest one (`u64::MAX`, ten bytes).
    for (mid, at) in [(0x50, NOW), (0x51, u64::MAX)] {
        let full = seal_seen_pkt(&mut a, entries(MAX_SYNC_SEEN, at), mid, &mut rng);
        assert_eq!(full.tier, Tier::M, "{MAX_SYNC_SEEN} entries dated {at}");
    }
    // One more is refused on decode.
    let raw: Vec<([u8; 16], Fingerprint, u64)> = entries(MAX_SYNC_SEEN + 1, NOW)
        .iter()
        .map(|e| (e.id.0, e.contact, e.at))
        .collect();
    let data = postcard::to_allocvec(&raw).unwrap();
    assert!(matches!(
        ExtContent::decode(KIND_SYNC_SEEN, &data),
        Err(CoreError::Malformed(_))
    ));
    let empty = postcard::to_allocvec(&Vec::<([u8; 16], Fingerprint, u64)>::new()).unwrap();
    assert!(matches!(
        ExtContent::decode(KIND_SYNC_SEEN, &empty),
        Err(CoreError::Malformed(_))
    ));
}

#[test]
fn gif_with_reply_and_ttl_fits_tier_m() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    answer_own_session(&mut a, &mut t, &mut rng);
    let content = ExtContent::SyncGif {
        to: b.fingerprint(),
        gif: crate::gif::GifRef {
            provider: u8::MAX,
            id: "-".repeat(crate::gif::MAX_GIF_ID_LEN),
            width: u16::MAX,
            height: u16::MAX,
        },
        reply_to: Some(MessageRef {
            id: [0xff; 16],
            by_sender: true,
        }),
        // The longest delay `seal` accepts (`u32::MAX` is refused as out of
        // bounds).
        ttl_secs: Some(crate::content::MAX_TTL_SECS),
    };
    let mut sealed = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &content.to_body(),
        MessageId([0x52; 16]),
        &mut rng,
    );
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed.remove(0).0.tier, Tier::M);
}

#[test]
fn sync_seen_round_trips() {
    let seen = vec![SeenEntry {
        id: MessageId([1; 16]),
        contact: Fingerprint([2; 32]),
        at: NOW,
    }];
    let content = ExtContent::SyncSeen { seen };
    let Body::Ext {
        kind,
        unknown,
        data,
    } = content.to_body()
    else {
        panic!("Ext expected");
    };
    assert_eq!((kind, unknown), (KIND_SYNC_SEEN, UnknownPolicy::Ignore));
    assert_eq!(ExtContent::decode(kind, &data).unwrap(), Some(content));
    let mut trailing = data;
    trailing.push(0);
    assert!(ExtContent::decode(kind, &trailing).is_err());
}

#[test]
fn seen_on_phone_expires_on_tablet_at_same_time() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    let seen_at = NOW + 10;
    let row = row_of(&a, &bob, "e");
    let pkts = a.mark_seen(&[row], seen_at, &mut rng).unwrap();
    assert_eq!(pkts.len(), 1, "one SyncSeen for the tablet");
    for p in &pkts {
        let got = t.receive(&p.encode(), "t", seen_at, &mut rng).unwrap();
        synced_seen(&got);
    }
    for c in [&a, &t] {
        assert_eq!(
            seen_cols(c, &bob, "e"),
            (Some(seen_at), Some(seen_at + 300))
        );
        assert_eq!(c.next_expiry().unwrap(), Some(seen_at + 300));
    }
    for c in [&mut a, &mut t] {
        assert!(c.expire_ephemeral(seen_at + 299).unwrap().is_empty());
        assert_eq!(stored_rows(c, "e"), 1);
    }
    let on_t = row_of(&t, &bob, "e");
    assert_eq!(a.expire_ephemeral(seen_at + 300).unwrap(), [row]);
    assert_eq!(t.expire_ephemeral(seen_at + 300).unwrap(), [on_t]);
    for c in [&a, &t] {
        assert_eq!(stored_rows(c, "e"), 0);
        assert_eq!(c.next_expiry().unwrap(), None);
    }
}

#[test]
fn earliest_seen_wins() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    let id = message_id_of(&t, &bob, "e");
    let entry = |at| {
        vec![SeenEntry {
            id,
            contact: bob,
            at,
        }]
    };
    let late = seal_seen_pkt(&mut a, entry(NOW + 100), 0x52, &mut rng);
    let early = seal_seen_pkt(&mut a, entry(NOW + 50), 0x53, &mut rng);
    let later_again = seal_seen_pkt(&mut a, entry(NOW + 70), 0x54, &mut rng);
    for p in [&late, &early, &later_again] {
        synced_seen(&t.receive(&p.encode(), "t", NOW + 200, &mut rng).unwrap());
    }
    assert_eq!(seen_cols(&t, &bob, "e"), (Some(NOW + 50), Some(NOW + 350)));
}

#[test]
fn future_seen_is_clamped_to_now() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    let id = message_id_of(&t, &bob, "e");
    let ahead = seal_seen_pkt(
        &mut a,
        vec![SeenEntry {
            id,
            contact: bob,
            at: NOW + 3600,
        }],
        0x55,
        &mut rng,
    );
    synced_seen(&deliver(&mut t, &ahead, &mut rng));
    assert_eq!(seen_cols(&t, &bob, "e"), (Some(NOW), Some(NOW + 300)));
}

/// A "seen" dated in the past is honoured: an ephemeral whose delay is
/// already over is hidden at once and erased by the next sweep.
#[test]
fn past_seen_expires_at_once() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    let id = message_id_of(&t, &bob, "e");
    let past = seal_seen_pkt(
        &mut a,
        vec![SeenEntry {
            id,
            contact: bob,
            at: NOW - 1000,
        }],
        0x56,
        &mut rng,
    );
    synced_seen(&deliver(&mut t, &past, &mut rng));
    assert!(!has_message(&t, &bob, "e"));
    assert_eq!(stored_rows(&t, "e"), 1, "hidden, not erased yet");
    assert_eq!(t.expire_ephemeral(NOW).unwrap().len(), 1);
    assert_eq!(stored_rows(&t, "e"), 0);
}

#[test]
fn seen_before_message_is_applied_on_arrival() {
    // A received ephemeral: the phone shows it, the tablet gets the "seen"
    // before Bob's packet.
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = b
        .send_message(&alice, "e", None, Some(300), NOW, &mut rng)
        .unwrap();
    deliver_each(&sent, &mut [&mut a], &mut rng);
    let seen_at = NOW + 20;
    let pkts = a
        .mark_seen(&[row_of(&a, &bob, "e")], seen_at, &mut rng)
        .unwrap();
    for p in &pkts {
        synced_seen(&t.receive(&p.encode(), "t", seen_at, &mut rng).unwrap());
    }
    assert_eq!(pending_seen_rows(&t), 1);
    for p in &sent {
        t.receive(&p.encode(), "t", seen_at + 5, &mut rng).unwrap();
    }
    assert_eq!(
        seen_cols(&t, &bob, "e"),
        (Some(seen_at), Some(seen_at + 300))
    );
    assert_eq!(pending_seen_rows(&t), 0);

    // One I send: its "seen" leaves with it, and reaches the tablet first.
    let mine = a
        .send_message(&bob, "m", None, Some(120), NOW + 30, &mut rng)
        .unwrap();
    assert_eq!(mine.len(), 3, "Bob, the copy, its \"seen\"");
    synced_seen(
        &t.receive(&mine[2].encode(), "t", NOW + 31, &mut rng)
            .unwrap(),
    );
    assert_eq!(pending_seen_rows(&t), 1);
    t.receive(&mine[1].encode(), "t", NOW + 32, &mut rng)
        .unwrap();
    assert_eq!(seen_cols(&t, &bob, "m"), (Some(NOW + 30), Some(NOW + 150)));
    assert_eq!(seen_cols(&a, &bob, "m"), (Some(NOW + 30), Some(NOW + 150)));
    assert_eq!(pending_seen_rows(&t), 0);
}

/// A "seen" for an unknown message of Bob's, given to the tablet at `NOW`.
fn pending_for_bob(a: &mut Core, t: &mut Core, bob: Fingerprint, mid: u8, rng: &mut StdRng) {
    let p = seal_seen_pkt(
        a,
        vec![SeenEntry {
            id: MessageId([mid; 16]),
            contact: bob,
            at: NOW,
        }],
        mid,
        rng,
    );
    synced_seen(&deliver(t, &p, rng));
}

#[test]
fn pending_seen_purged_after_8_days() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    pending_for_bob(&mut a, &mut t, b.fingerprint(), 0x57, &mut rng);
    assert_eq!(pending_seen_rows(&t), 1);
    let days8 = crate::core::ephemeral::PENDING_SEEN_RETENTION_SECS;
    assert_eq!(days8, 8 * 86_400);
    t.expire_ephemeral(NOW + days8).unwrap();
    assert_eq!(pending_seen_rows(&t), 1);
    t.expire_ephemeral(NOW + days8 + 1).unwrap();
    assert_eq!(pending_seen_rows(&t), 0);
}

#[test]
fn pending_seen_dropped_on_block_and_delete() {
    // On the tablet itself: a block, then a removal.
    for remove in [false, true] {
        let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
        let bob = b.fingerprint();
        pending_for_bob(&mut a, &mut t, bob, 0x58, &mut rng);
        assert_eq!(pending_seen_rows(&t), 1);
        if remove {
            t.remove_contact(&bob, NOW + 1, &mut rng).unwrap();
        } else {
            t.block_contact(&bob, NOW + 1, &mut rng).unwrap();
        }
        assert_eq!(pending_seen_rows(&t), 0, "local, remove: {remove}");
        // A late "seen" for that contact is not kept either.
        pending_for_bob(&mut a, &mut t, bob, 0x59, &mut rng);
        assert_eq!(pending_seen_rows(&t), 0, "late, remove: {remove}");
    }
    // From the phone, through `SyncContact`.
    for remove in [false, true] {
        let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
        let bob = b.fingerprint();
        pending_for_bob(&mut a, &mut t, bob, 0x5a, &mut rng);
        assert_eq!(pending_seen_rows(&t), 1);
        if remove {
            a.remove_contact(&bob, NOW + 5, &mut rng).unwrap();
        } else {
            a.block_contact(&bob, NOW + 5, &mut rng).unwrap();
        }
        deliver_all(&mut a, &mut t, &mut rng);
        assert_eq!(pending_seen_rows(&t), 0, "synced, remove: {remove}");
    }
}

#[test]
fn never_seen_ephemeral_expires_after_7_days() {
    let (_d, mut a, mut t, b, _rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    for c in [&mut a, &mut t] {
        assert_eq!(seen_cols(c, &bob, "e"), (None, Some(NOW + 604_800)));
        assert!(c.expire_ephemeral(NOW + 604_800 - 1).unwrap().is_empty());
        assert_eq!(c.expire_ephemeral(NOW + 604_800).unwrap().len(), 1);
        assert_eq!(stored_rows(c, "e"), 0);
    }
}

#[test]
fn expired_row_is_hidden_before_sweep() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let kept = p.b.send_text(&a, "kept", NOW, &mut p.rng).unwrap();
    deliver(&mut p.a, &kept[0], &mut p.rng);
    let gone =
        p.b.send_message(&a, "gone", None, Some(60), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &gone[0], &mut p.rng);
    let row = row_of(&p.a, &b, "gone");
    let id = message_id_of(&p.a, &b, "gone");
    p.a.mark_seen(&[row], NOW, &mut p.rng).unwrap();
    // Bob quotes it while it is still shown on his side.
    let bob_row = full_row(&p.b, &a, "gone").id;
    let reply =
        p.b.send_message(&a, "re", Some(bob_row), None, NOW, &mut p.rng)
            .unwrap();
    let due = NOW + 60;
    // Still shown one second before.
    assert!(
        p.a.messages_with(&b, due - 1)
            .unwrap()
            .iter()
            .any(|m| m.id == row)
    );
    assert!(p.a.message_in(&b, id, due - 1).unwrap().is_some());
    // Due, never swept: the row is stored but no read returns it.
    assert!(
        p.a.messages_with(&b, due)
            .unwrap()
            .iter()
            .all(|m| m.id != row)
    );
    let with_delivery = p.a.messages_with_delivery(&b, due).unwrap();
    assert!(with_delivery.iter().all(|(m, _)| m.id != row));
    // The chat list's last message is the one before.
    assert_eq!(with_delivery.last().unwrap().0.body, "kept");
    assert!(p.a.deliveries_of(&[row], due).unwrap().is_empty());
    assert!(p.a.message_in(&b, id, due).unwrap().is_none());
    // A reply quoting it shows the original as unavailable.
    p.a.receive(&reply[0].encode(), "t", due, &mut p.rng)
        .unwrap();
    let re =
        p.a.messages_with(&b, due)
            .unwrap()
            .into_iter()
            .find(|m| m.body == "re")
            .unwrap();
    assert_eq!(re.reply_to, Some(id));
    assert!(p.a.message_in(&b, id, due).unwrap().is_none());
    // Nor can it be quoted or reacted to any more.
    assert_eq!(
        p.a.send_message(&b, "late", Some(row), None, due, &mut p.rng),
        Err(CoreError::MessageNotFound)
    );
    assert_eq!(
        p.a.set_reactions(row, &emo(&["👍"]), due, &mut p.rng),
        Err(CoreError::MessageNotFound)
    );
    assert_eq!(stored_rows(&p.a, "gone"), 1);
}

/// A due ephemeral of mine is left out of the delivery screens too.
#[test]
fn expired_send_is_hidden_from_delivery_screens() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent =
        p.a.send_message(&bob, "brief", None, Some(60), NOW, &mut p.rng)
            .unwrap();
    let row = row_of(&p.a, &bob, "brief");
    let due = NOW + 60;
    let listed = |c: &mut Core, now: u64| {
        c.pending_packets(now)
            .unwrap()
            .messages
            .iter()
            .any(|m| m.row_id == row)
    };
    assert!(listed(&mut p.a, due - 1));
    assert!(!listed(&mut p.a, due));
    // "x", Alice's first message, stays counted as received.
    assert_eq!(p.a.delivery_counts(&bob, due - 1).unwrap(), [1, 0, 1, 0]);
    assert_eq!(p.a.delivery_counts(&bob, due).unwrap(), [0, 0, 1, 0]);
    assert!(p.a.message_delivery(row, due - 1).unwrap().is_some());
    assert!(p.a.message_delivery(row, due).unwrap().is_none());
    assert!(
        p.a.delivery_page(&bob, MessageStatus::Pending, 10, 0, due)
            .unwrap()
            .is_empty()
    );
    // The packet itself still waits to leave.
    assert!(outbox_row(&p.a, sent[0].id).is_some());
}

#[test]
fn expiry_keeps_the_send_going() {
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent =
        p.a.send_message(&bob, "brief", None, Some(60), NOW, &mut p.rng)
            .unwrap();
    let packet = sent[0].clone();
    let row = row_of(&p.a, &bob, "brief");
    let mid = message_id_of(&p.a, &bob, "brief");
    let later = NOW + 61;
    assert_eq!(p.a.expire_ephemeral(later).unwrap(), [row]);
    assert_eq!(stored_rows(&p.a, "brief"), 0);
    assert!(is_tombstoned(&p.a, mid));
    // The packet is still queued, its delivery `Pending`.
    assert_eq!(outbox_row(&p.a, packet.id), Some(None));
    assert_eq!(
        delivery_state(&p.a, packet.id).0,
        MessageStatus::Pending as i64
    );
    // The Pending screen and its count read it without the row.
    let pending = p.a.pending_packets(later).unwrap();
    assert!(pending.messages.iter().all(|m| m.row_id != row));
    assert_eq!(pending.packets, p.a.pending_count(later).unwrap());
    assert!(pending.packets >= 1);
    assert!(
        p.a.pending_outbox(later)
            .unwrap()
            .iter()
            .any(|b| Packet::decode(b).unwrap().id == packet.id)
    );
    // It leaves, Bob gets the whole delay, and the ack settles it.
    p.a.record_deposit(packet.id, NODE, later + 1).unwrap();
    assert_eq!(
        delivery_state(&p.a, packet.id).0,
        MessageStatus::OnNetwork as i64
    );
    let ack = match p.b.receive(&packet.encode(), "t", later + 2, &mut p.rng) {
        Ok(ReceiveOutcome::Message {
            ack,
            ephemeral: true,
            ..
        }) => ack,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        ephemeral_cols(&p.b, &p.a.fingerprint(), "brief"),
        (Some(60), None, Some(later + 2 + UNSEEN_CEILING_SECS))
    );
    let r =
        p.a.receive(&ack.encode(), "t", later + 3, &mut p.rng)
            .unwrap();
    assert!(matches!(r, ReceiveOutcome::AckReceived { .. }), "{r:?}");
    assert_eq!(
        delivery_state(&p.a, packet.id).0,
        MessageStatus::Received as i64
    );
    assert_eq!(outbox_row(&p.a, packet.id), None);
    assert!(p.a.deliveries_of(&[row], later + 3).unwrap().is_empty());
    assert!(p.a.message_delivery(row, later + 3).unwrap().is_none());
    p.a.take_delivery_changes();
    assert!(p.a.take_failed_notices().is_empty());
    assert_eq!(stored_rows(&p.a, "brief"), 0);
}

#[test]
fn expiry_erases_reactions_and_tombstones() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = a
        .send_message(&bob, "e", None, Some(60), NOW, &mut rng)
        .unwrap();
    // The tablet gets the copy, not the "seen": shown there, it is seen.
    t.receive(&sent[1].encode(), "t", NOW, &mut rng).unwrap();
    let on_t = row_of(&t, &bob, "e");
    t.mark_seen(&[on_t], NOW, &mut rng).unwrap();
    deliver(&mut b, &sent[0], &mut rng);
    let react = b
        .set_reactions(row_of(&b, &alice, "e"), &emo(&["👍"]), NOW, &mut rng)
        .unwrap();
    deliver_each(&react, &mut [&mut a, &mut t], &mut rng);
    assert_eq!(reaction_rows(&a), 1);
    assert_eq!(reaction_rows(&t), 1);
    let id = message_id_of(&t, &bob, "e");
    for c in [&mut a, &mut t] {
        assert_eq!(c.expire_ephemeral(NOW + 60).unwrap().len(), 1);
        assert_eq!(reaction_rows(c), 0);
        assert!(is_tombstoned(c, id));
    }
    // A late copy of it (a new packet, same message, from the tablet: the
    // phone never received it, only the tombstone can refuse it).
    let copy = ExtContent::SyncMessage {
        to: bob,
        text: "e".into(),
        reply_to: None,
        ttl_secs: Some(60),
    }
    .to_body();
    let late = seal_body(&mut t, &send::Target::OwnDevices, &copy, id, &mut rng);
    let got = a
        .receive(&late[0].0.encode(), "t", NOW + 61, &mut rng)
        .unwrap();
    assert!(
        matches!(
            got,
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                ..
            }
        ),
        "{got:?}"
    );
    assert_eq!(stored_rows(&a, "e"), 0);
    // So is a late "seen" for it: nothing waits for it.
    let seen = seal_seen_pkt(
        &mut a,
        vec![SeenEntry {
            id,
            contact: bob,
            at: NOW,
        }],
        0x5b,
        &mut rng,
    );
    synced_seen(&t.receive(&seen.encode(), "t", NOW + 61, &mut rng).unwrap());
    assert_eq!(pending_seen_rows(&t), 0);
}

#[test]
fn expiry_sends_nothing() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    a.mark_seen(&[row_of(&a, &bob, "e")], NOW, &mut rng)
        .unwrap();
    let queued = |c: &mut Core| c.pending_outbox(NOW).unwrap().len();
    let (before_a, before_t) = (queued(&mut a), queued(&mut t));
    assert_eq!(a.expire_ephemeral(NOW + 300).unwrap().len(), 1);
    assert_eq!(t.expire_ephemeral(NOW + 604_800).unwrap().len(), 1);
    assert_eq!(queued(&mut a), before_a);
    assert_eq!(queued(&mut t), before_t);
    let deleted = |c: &Core| {
        count_events(c, |e| {
            matches!(
                e,
                TransparencyEvent::MessagesDeleted { .. } | TransparencyEvent::SyncSkipped { .. }
            )
        })
    };
    assert_eq!(deleted(&a), 0);
    assert_eq!(deleted(&t), 0);
}

#[test]
fn mark_seen_ignores_plain_and_already_seen() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let plain = b.send_text(&alice, "plain", NOW, &mut rng).unwrap();
    let eph = b
        .send_message(&alice, "e", None, Some(300), NOW, &mut rng)
        .unwrap();
    deliver_each(&plain, &mut [&mut a], &mut rng);
    deliver_each(&eph, &mut [&mut a], &mut rng);
    let (p_row, e_row) = (row_of(&a, &bob, "plain"), row_of(&a, &bob, "e"));
    assert!(
        a.mark_seen(&[p_row, 9_999], NOW, &mut rng)
            .unwrap()
            .is_empty()
    );
    assert_eq!(seen_cols(&a, &bob, "plain"), (None, None));
    let first = a.mark_seen(&[e_row, e_row], NOW + 1, &mut rng).unwrap();
    assert_eq!(first.len(), 1, "one entry, one packet");
    synced_seen(
        &t.receive(&first[0].encode(), "t", NOW + 1, &mut rng)
            .unwrap(),
    );
    // The tablet stores it for the message to come.
    assert_eq!(pending_seen_rows(&t), 1);
    // Already seen: nothing changes, nothing is sent.
    assert!(
        a.mark_seen(&[e_row], NOW + 50, &mut rng)
            .unwrap()
            .is_empty()
    );
    assert_eq!(seen_cols(&a, &bob, "e"), (Some(NOW + 1), Some(NOW + 301)));
    // Never shown and due (its ceiling passed): not marked.
    let unseen = b
        .send_message(&alice, "unseen", None, Some(300), NOW, &mut rng)
        .unwrap();
    deliver_each(&unseen, &mut [&mut a], &mut rng);
    let u_row = row_of(&a, &bob, "unseen");
    let ceiling = NOW + UNSEEN_CEILING_SECS;
    assert!(a.mark_seen(&[u_row], ceiling, &mut rng).unwrap().is_empty());
    assert_eq!(seen_cols(&a, &bob, "unseen"), (None, Some(ceiling)));
}

#[test]
fn mark_seen_without_another_device_stays_local() {
    let mut p = pair();
    let b = p.b.fingerprint();
    let a = p.a.fingerprint();
    let out =
        p.b.send_message(&a, "e", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &out[0], &mut p.rng);
    let row = row_of(&p.a, &b, "e");
    assert!(
        p.a.mark_seen(&[row], NOW + 3, &mut p.rng)
            .unwrap()
            .is_empty()
    );
    assert_eq!(seen_cols(&p.a, &b, "e"), (Some(NOW + 3), Some(NOW + 303)));
}

#[test]
fn next_expiry_is_the_earliest() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    assert_eq!(p.a.next_expiry().unwrap(), None);
    for (body, ttl) in [("e1", 300), ("e2", 60)] {
        let out =
            p.b.send_message(&a, body, None, Some(ttl), NOW, &mut p.rng)
                .unwrap();
        deliver(&mut p.a, &out[0], &mut p.rng);
    }
    assert_eq!(p.a.next_expiry().unwrap(), Some(NOW + 604_800));
    p.a.mark_seen(&[row_of(&p.a, &b, "e1")], NOW + 5, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.next_expiry().unwrap(), Some(NOW + 305));
    p.a.mark_seen(&[row_of(&p.a, &b, "e2")], NOW + 10, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.next_expiry().unwrap(), Some(NOW + 70));
    p.a.send_message(&b, "mine", None, Some(120), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.next_expiry().unwrap(), Some(NOW + 70));
    p.a.expire_ephemeral(NOW + 70).unwrap();
    assert_eq!(p.a.next_expiry().unwrap(), Some(NOW + 120));
}

#[test]
fn expired_ephemeral_is_not_resent() {
    let mut p = settled_pair();
    let b = p.b.fingerprint();
    let sent =
        p.a.send_message(&b, "short", None, Some(60), NOW, &mut p.rng)
            .unwrap();
    assert!(p.a.drop_outbox_packet(&sent[0].encode(), NOW + 1).unwrap());
    let row = row_of(&p.a, &b, "short");
    assert_eq!(status_of(&p.a, &b, "short"), MessageStatus::NotDelivered);
    let outbox = p.a.pending_outbox(NOW + 60).unwrap().len();
    // Due, not swept yet: nothing is sealed again.
    assert_eq!(
        p.a.retry_message(row, NOW + 60, &mut p.rng),
        Err(CoreError::NothingToRetry)
    );
    assert_eq!(p.a.retry_all(&b, NOW + 60, &mut p.rng), Ok(0));
    assert_eq!(p.a.pending_outbox(NOW + 60).unwrap().len(), outbox);
    // Swept: the row is gone.
    p.a.expire_ephemeral(NOW + 60).unwrap();
    assert_eq!(
        p.a.retry_message(row, NOW + 60, &mut p.rng),
        Err(CoreError::NothingToRetry)
    );
    // Before it is due, the resend works.
    let other =
        p.a.send_message(&b, "other", None, Some(60), NOW + 100, &mut p.rng)
            .unwrap();
    assert!(
        p.a.drop_outbox_packet(&other[0].encode(), NOW + 101)
            .unwrap()
    );
    let again =
        p.a.retry_message(row_of(&p.a, &b, "other"), NOW + 102, &mut p.rng)
            .unwrap();
    assert!(!again.is_empty());
}

#[test]
fn sync_seen_from_contact_is_refused() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let body = ExtContent::SyncSeen {
        seen: vec![SeenEntry {
            id: MessageId([1; 16]),
            contact: a,
            at: NOW,
        }],
    }
    .to_body();
    let out = seal_body(
        &mut p.b,
        &send::Target::Contact(a),
        &body,
        MessageId([0x64; 16]),
        &mut p.rng,
    );
    assert_eq!(reason(deliver(&mut p.a, &out[0].0, &mut p.rng)), NOT_MINE);
    assert_eq!(pending_seen_rows(&p.a), 0);
}

#[test]
fn history_export_skips_ephemerals() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let eph =
        p.b.send_message(&a, "eph", None, Some(300), NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &eph[0], &mut p.rng);
    p.a.send_message(&b, "mine", None, Some(300), NOW, &mut p.rng)
        .unwrap();
    p.a.set_reactions(row_of(&p.a, &b, "eph"), &emo(&["👍"]), NOW, &mut p.rng)
        .unwrap();
    p.a.set_reactions(row_of(&p.a, &b, "y"), &emo(&["👍"]), NOW, &mut p.rng)
        .unwrap();
    let contacts = std::collections::HashSet::from([b]);
    let out = history::export(&p.a.store, &contacts).unwrap();
    let bodies: Vec<String> = out.entries.iter().map(|e| format!("{e:?}")).collect();
    // "x" (sent) and "y" (received): the plain messages only.
    assert_eq!(out.entries.len(), 2, "{bodies:?}");
    let eph_id = message_id_of(&p.a, &b, "eph");
    let y_id = message_id_of(&p.a, &b, "y");
    assert!(bodies.iter().all(|e| !e.contains(&format!("{eph_id:?}"))));
    assert_eq!(out.reactions.len(), 1);
    assert_eq!(out.reactions[0].target(), y_id);
}

// --- Task 4, fix 1: an erased message on the Pending screen.

/// The sorts of the "Synchronisation" section but receipts (Alice still
/// owes Bob one for "y"), with their packets and contacts, read at `now`.
fn sync_sorts(c: &mut Core, now: u64) -> Vec<(PendingKind, u32, Vec<Fingerprint>)> {
    c.pending_packets(now)
        .unwrap()
        .sync
        .into_iter()
        .filter(|s| s.kind != PendingKind::Ack)
        .map(|s| (s.kind, s.packets, s.contacts))
        .collect()
}

#[test]
fn erased_messages_are_pending_as_such() {
    // An ephemeral that is due (then erased) before it leaves.
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    p.a.send_message(&bob, "brief", None, Some(60), NOW, &mut p.rng)
        .unwrap();
    let erased = vec![(PendingKind::ErasedMessage, 1, vec![bob])];
    for (now, sweep) in [(NOW + 60, false), (NOW + 61, true)] {
        if sweep {
            assert_eq!(p.a.expire_ephemeral(now).unwrap().len(), 1);
        }
        let pending = p.a.pending_packets(now).unwrap();
        assert!(pending.messages.is_empty(), "no row, no text");
        assert_eq!(sync_sorts(&mut p.a, now), erased, "swept: {sweep}");
        assert_eq!(pending.packets, p.a.pending_count(now).unwrap());
    }

    // A plain message deleted after a deposit was tried: it may still go.
    let mut p = settled_pair();
    let bob = p.b.fingerprint();
    let sent = p.a.send_text(&bob, "tried", NOW, &mut p.rng).unwrap();
    p.a.record_deposit_tried(sent[0].id, NOW + 1).unwrap();
    p.a.delete_message(row_of(&p.a, &bob, "tried"), NOW + 2, &mut p.rng)
        .unwrap();
    assert!(outbox_row(&p.a, sent[0].id).is_some());
    let pending = p.a.pending_packets(NOW + 3).unwrap();
    assert!(pending.messages.is_empty());
    assert_eq!(sync_sorts(&mut p.a, NOW + 3), erased);
}

// --- Final review fixes: a "seen" from another device, a message born due.

/// A "seen" from another of my devices changes the countdown of a row this
/// device shows: the row is noted (`take_delivery_changes`) so the open
/// conversation reloads. A repeat that lowers nothing notes nothing.
#[test]
fn sync_seen_notes_the_row_it_changes() {
    let (_d, mut a, mut t, b, mut rng) = ephemeral_on_both(300);
    let bob = b.fingerprint();
    let on_t = row_of(&t, &bob, "e");
    t.take_delivery_changes();
    let pkts = a
        .mark_seen(&[row_of(&a, &bob, "e")], NOW + 10, &mut rng)
        .unwrap();
    for p in &pkts {
        synced_seen(&t.receive(&p.encode(), "t", NOW + 10, &mut rng).unwrap());
    }
    assert_eq!(t.take_delivery_changes(), vec![(bob, on_t)]);

    // The same date again (or a later one) lowers nothing.
    let id = message_id_of(&t, &bob, "e");
    let again = seal_seen_pkt(
        &mut a,
        vec![SeenEntry {
            id,
            contact: bob,
            at: NOW + 40,
        }],
        0x57,
        &mut rng,
    );
    synced_seen(&t.receive(&again.encode(), "t", NOW + 50, &mut rng).unwrap());
    assert!(t.take_delivery_changes().is_empty());
}

/// An ephemeral whose earlier "seen" (from another of my devices) already
/// ran out when it arrives is never shown nor notified: acked, erased and
/// tombstoned at once, as the sweep would.
#[test]
fn message_born_due_is_not_surfaced() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let sent = b
        .send_message(&alice, "gone", None, Some(60), NOW, &mut rng)
        .unwrap();
    deliver_each(&sent, &mut [&mut a], &mut rng);
    let pkts = a
        .mark_seen(&[row_of(&a, &bob, "gone")], NOW + 1, &mut rng)
        .unwrap();
    for p in &pkts {
        synced_seen(&t.receive(&p.encode(), "t", NOW + 1, &mut rng).unwrap());
    }
    assert_eq!(pending_seen_rows(&t), 1);
    let id = message_id_of(&a, &bob, "gone");
    let mut opened = 0;
    for p in &sent {
        let got = t.receive(&p.encode(), "t", NOW + 100, &mut rng).unwrap();
        if matches!(got, ReceiveOutcome::NotForUs) {
            continue;
        }
        assert!(matches!(got, ReceiveOutcome::Ignored), "born due: {got:?}");
        assert_eq!(acks_for(&mut t, p), 1, "acked all the same");
        opened += 1;
    }
    assert_eq!(opened, 1);
    assert_eq!(stored_rows(&t, "gone"), 0, "erased at once");
    assert!(is_tombstoned(&t, id));
    assert_eq!(pending_seen_rows(&t), 0);
    assert!(t.expire_ephemeral(NOW + 100).unwrap().is_empty());
    // A resend is a plain duplicate: nothing to wake for.
    for p in &sent {
        let again = t.receive(&p.encode(), "t", NOW + 101, &mut rng).unwrap();
        assert!(
            matches!(again, ReceiveOutcome::Duplicate | ReceiveOutcome::NotForUs),
            "{again:?}"
        );
    }
}

// --- Contact requests, task 3: sending and resending an invite.

/// Bob (admin, linked to his tablet) and Alice, who added Bob's card (two
/// devices) without inviting him yet.
fn alice_and_bob_with_tablet() -> (TempDir, TempDir, Core, Core, Core, StdRng) {
    let (db, b, bt, rng) = linked();
    let (da, mut a) = party("a", 9);
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut StdRng::seed_from_u64(3),
    )
    .unwrap();
    (da, db, a, b, bt, rng)
}

fn count_table(c: &Core, table: &str) -> i64 {
    c.store
        .conn()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn invite_seals_one_initial_per_device_in_tier_l() {
    let (_da, _db, mut a, b, bt, mut rng) = alice_and_bob_with_tablet();
    let bob = b.fingerprint();
    let messages_before = count_table(&a, "messages");
    let out = a.invite(&bob, NOW, &mut rng).unwrap();
    // Alice has no other device: only Bob's two devices.
    assert_eq!(out.len(), 2);
    let intros: Vec<_> = [&b, &bt]
        .iter()
        .map(|c| intro_mailbox(&c.device.public(), day_of(NOW)))
        .collect();
    for p in &out {
        assert_eq!(p.kind, Kind::Message);
        assert_eq!(p.tier, Tier::L);
        assert!(matches!(
            parse_wire(&p.payload).unwrap(),
            Wire::Initial { .. }
        ));
        assert!(intros.contains(&p.mailbox));
        // A delivery (its ack is recognised) and an invite packet row.
        assert!(a.store.is_my_packet(p.id).unwrap());
        assert_eq!(
            requests::invite_packet_fp(&a.store, p.id).unwrap(),
            Some(bob)
        );
    }
    assert_ne!(out[0].mailbox, out[1].mailbox);
    // No conversation row for an invite.
    assert_eq!(count_table(&a, "messages"), messages_before);
    assert_eq!(
        requests::get_invite(&a.store, bob).unwrap(),
        Some(requests::InviteRow {
            at: NOW,
            accepted_at: None
        })
    );
    assert_eq!(
        count_events(&a, |e| matches!(
            e,
            TransparencyEvent::InviteSent { contact } if *contact == bob
        )),
        1
    );
}

#[test]
fn invite_refuses_an_unknown_or_blocked_contact() {
    let (_da, _db, mut a, b, _bt, mut rng) = alice_and_bob_with_tablet();
    let stranger = Fingerprint([9; 32]);
    assert!(matches!(
        a.invite(&stranger, NOW, &mut rng),
        Err(CoreError::UnknownContact)
    ));
    a.block_contact(&b.fingerprint(), NOW, &mut rng).unwrap();
    assert!(matches!(
        a.invite(&b.fingerprint(), NOW, &mut rng),
        Err(CoreError::ContactBlocked)
    ));
    assert_eq!(count_table(&a, "invites"), 0);
    assert_eq!(count_table(&a, "invite_packets"), 0);
}

#[test]
fn invite_twice_within_24h_is_too_soon() {
    let (_da, _db, mut a, b, _bt, mut rng) = alice_and_bob_with_tablet();
    let bob = b.fingerprint();
    assert_eq!(a.invite(&bob, NOW, &mut rng).unwrap().len(), 2);
    let packets = count_table(&a, "invite_packets");
    assert!(matches!(
        a.invite(&bob, NOW + 86_399, &mut rng),
        Err(CoreError::TooSoon { retry_at }) if retry_at == NOW + 86_400
    ));
    // Nothing written by the refused resend.
    assert_eq!(count_table(&a, "invite_packets"), packets);
    // A resend in the same pending sessions: one more Initial per device.
    let again = a.invite(&bob, NOW + 86_400, &mut rng).unwrap();
    assert_eq!(again.len(), 2);
    for p in &again {
        assert!(matches!(
            parse_wire(&p.payload).unwrap(),
            Wire::Initial { .. }
        ));
    }
    assert_eq!(
        requests::get_invite(&a.store, bob).unwrap().unwrap().at,
        NOW + 86_400
    );
    assert_eq!(a.store.all_sessions().unwrap().len(), 2);
}

#[test]
fn invite_cap_survives_remove_and_readd() {
    let (_da, _db, mut a, b, _bt, mut rng) = alice_and_bob_with_tablet();
    let bob = b.fingerprint();
    a.invite(&bob, NOW, &mut rng).unwrap();
    a.remove_contact(&bob, NOW + 5, &mut rng).unwrap();
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW + 6,
        &mut rng,
    )
    .unwrap();
    assert!(matches!(
        a.invite(&bob, NOW + 10, &mut rng),
        Err(CoreError::TooSoon { retry_at }) if retry_at == NOW + 86_400
    ));
}

#[test]
fn invite_cap_is_shared_by_my_devices() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, b) = party("b", 9);
    let card = b.contact_card("Bob").unwrap();
    a.add_contact(&card, Some("bob"), NOW, &mut rng).unwrap();
    t.add_contact(&card, Some("bob"), NOW, &mut rng).unwrap();
    let out = a.invite(&b.fingerprint(), NOW, &mut rng).unwrap();
    // Bob's device, then the `SyncInvite` for the tablet.
    assert_eq!(out.len(), 2);
    assert_eq!(
        out[0].mailbox,
        intro_mailbox(&b.device.public(), day_of(NOW))
    );
    let got = t.receive(&out[1].encode(), "t", NOW, &mut rng).unwrap();
    assert!(
        !matches!(got, ReceiveOutcome::Quarantined { .. }),
        "{got:?}"
    );
    assert_eq!(
        count_events(&t, |e| matches!(
            e,
            TransparencyEvent::SyncApplied {
                kind: SyncKind::Contact
            }
        )),
        1
    );
    assert_eq!(
        requests::get_invite(&t.store, b.fingerprint())
            .unwrap()
            .unwrap()
            .at,
        NOW
    );
    assert!(matches!(
        t.invite(&b.fingerprint(), NOW + 10, &mut rng),
        Err(CoreError::TooSoon { retry_at }) if retry_at == NOW + 86_400
    ));
}

#[test]
fn sync_invite_keeps_the_latest_date() {
    let (_d, mut a, mut t, mut rng) = linked();
    let bob = Fingerprint([5; 32]);
    let seal = |a: &mut Core, at: u64, id: u8, rng: &mut StdRng| {
        let body = ExtContent::SyncInvite { to: bob, at }.to_body();
        seal_body(
            a,
            &send::Target::OwnDevices,
            &body,
            MessageId([id; 16]),
            rng,
        )
        .remove(0)
        .0
    };
    let newer = seal(&mut a, NOW + 50, 1, &mut rng);
    let older = seal(&mut a, NOW + 20, 2, &mut rng);
    t.receive(&newer.encode(), "t", NOW, &mut rng).unwrap();
    t.receive(&older.encode(), "t", NOW, &mut rng).unwrap();
    // No contact needed: the cap outlives the contact.
    assert_eq!(
        requests::get_invite(&t.store, bob).unwrap().unwrap().at,
        NOW + 50
    );
}

#[test]
fn sync_invite_from_a_contact_is_not_mine() {
    let mut p = pair();
    let body = ExtContent::SyncInvite {
        to: Fingerprint([5; 32]),
        at: NOW,
    }
    .to_body();
    let bob = p.b.fingerprint();
    let pkt = seal_body(
        &mut p.a,
        &send::Target::Contact(bob),
        &body,
        MessageId([3; 16]),
        &mut p.rng,
    )
    .remove(0)
    .0;
    let got = p.b.receive(&pkt.encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(got), sync::R_NOT_MINE);
    assert_eq!(count_table(&p.b, "invites"), 0);
}

/// Bob, who still has Alice as a contact, invites her after she removed him:
/// every device answered long ago, so the invite opens a new session with each
/// (a fresh Initial, the only kind she can still read).
fn bob_reinvites_after_removal(p: &mut Pair, at: u64) -> Packet {
    let alice = p.a.fingerprint();
    p.a.remove_contact(&p.b.fingerprint(), NOW + 1, &mut p.rng)
        .unwrap();
    let mut out = p.b.invite(&alice, at, &mut p.rng).unwrap();
    assert_eq!(out.len(), 1);
    let invite = out.remove(0);
    assert!(matches!(
        parse_wire(&invite.payload).unwrap(),
        Wire::Initial { .. }
    ));
    assert_eq!(
        invite.mailbox,
        intro_mailbox(&p.a.device.public(), day_of(at))
    );
    invite
}

#[test]
fn reinvite_after_removal_reaches_the_remover_as_a_request() {
    let mut p = pair();
    let (alice, bob) = (p.a.fingerprint(), p.b.fingerprint());
    let at = NOW + 10;
    let invite = bob_reinvites_after_removal(&mut p, at);
    assert_eq!(
        p.b.invite_state(&alice, at).unwrap(),
        InviteState::Sent { at }
    );
    let got = p.a.receive(&invite.encode(), "t", at, &mut p.rng).unwrap();
    assert_eq!(request_outcome(got).0, bob);
    // Written before she accepts: it rides the new session too, and waits
    // with the request.
    let early = p.b.send_text(&alice, "early", at + 1, &mut p.rng).unwrap();
    assert_eq!(early.len(), 1);
    assert_eq!(
        reason(
            p.a.receive(&early[0].encode(), "t", at + 1, &mut p.rng)
                .unwrap()
        ),
        R_PENDING_REQUEST
    );
    let accepted = p.a.accept_request(&bob, None, at + 20, &mut p.rng).unwrap();
    assert!(
        accepted
            .replayed
            .iter()
            .any(|o| matches!(o, ReceiveOutcome::Message { .. })),
        "{:?}",
        accepted.replayed
    );
    for pkt in &accepted.packets {
        p.b.receive(&pkt.encode(), "t", at + 30, &mut p.rng)
            .unwrap();
    }
    assert_eq!(
        p.b.invite_state(&alice, at + 30).unwrap(),
        InviteState::Accepted { at: at + 30 }
    );
    // From then on Bob writes in the new session, answered.
    let next = p.b.send_text(&alice, "again", at + 40, &mut p.rng).unwrap();
    assert!(matches!(
        parse_wire(&next[0].payload).unwrap(),
        Wire::Normal { .. }
    ));
    let got =
        p.a.receive(&next[0].encode(), "t", at + 40, &mut p.rng)
            .unwrap();
    assert!(matches!(got, ReceiveOutcome::Message { .. }), "{got:?}");
}

#[test]
fn reinvite_after_removal_works_from_the_first_inviter() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    let accepted = b.accept_request(&alice, None, NOW + 10, &mut rng).unwrap();
    a.receive(&accepted.packets[0].encode(), "t", NOW + 10, &mut rng)
        .unwrap();
    b.remove_contact(&alice, NOW + 20, &mut rng).unwrap();
    // Within 24 hours of her first invite: refused, nothing written.
    let packets = count_table(&a, "invite_packets");
    assert!(matches!(
        a.invite(&bob, NOW + 30, &mut rng),
        Err(CoreError::TooSoon { retry_at }) if retry_at == NOW + 86_400
    ));
    assert_eq!(count_table(&a, "invite_packets"), packets);
    assert_eq!(
        a.invite_state(&bob, NOW + 30).unwrap(),
        InviteState::Accepted { at: NOW + 10 }
    );
    // A second Initial on the same key packet of Bob's card.
    let later = NOW + 86_400;
    let again = invite_one(&mut a, bob, later, &mut rng);
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Sent { at: later }
    );
    let got = b.receive(&again.encode(), "t", later, &mut rng).unwrap();
    assert_eq!(request_outcome(got).0, alice);
}

#[test]
fn reinvite_after_removal_keeps_the_24h_cap() {
    let mut p = pair();
    let alice = p.a.fingerprint();
    let at = NOW + 10;
    bob_reinvites_after_removal(&mut p, at);
    let sessions = p.b.store.all_sessions().unwrap().len();
    assert!(matches!(
        p.b.invite(&alice, at + 86_399, &mut p.rng),
        Err(CoreError::TooSoon { retry_at }) if retry_at == at + 86_400
    ));
    // The resend is the next message of the new pending session.
    let again = p.b.invite(&alice, at + 86_400, &mut p.rng).unwrap();
    assert_eq!(again.len(), 1);
    assert!(matches!(
        parse_wire(&again[0].payload).unwrap(),
        Wire::Initial { .. }
    ));
    assert_eq!(p.b.store.all_sessions().unwrap().len(), sessions);
}

#[test]
fn reinvite_cycles_keep_the_session_cap() {
    let mut p = pair();
    let (alice, bob) = (p.a.fingerprint(), p.b.fingerprint());
    for (i, at) in [NOW + 10, NOW + 10 + 86_400].into_iter().enumerate() {
        if i > 0 {
            p.a.remove_contact(&bob, at - 5, &mut p.rng).unwrap();
        }
        let out = if i == 0 {
            vec![bob_reinvites_after_removal(&mut p, at)]
        } else {
            p.b.invite(&alice, at, &mut p.rng).unwrap()
        };
        assert_eq!(out.len(), 1);
        let got = p.a.receive(&out[0].encode(), "t", at, &mut p.rng).unwrap();
        assert_eq!(request_outcome(got).0, bob);
        let accepted = p.a.accept_request(&bob, None, at + 20, &mut p.rng).unwrap();
        for pkt in &accepted.packets {
            p.b.receive(&pkt.encode(), "t", at + 30, &mut p.rng)
                .unwrap();
        }
        let text = p.b.send_text(&alice, "hi", at + 40, &mut p.rng).unwrap();
        let got =
            p.a.receive(&text[0].encode(), "t", at + 40, &mut p.rng)
                .unwrap();
        assert!(matches!(got, ReceiveOutcome::Message { .. }), "{got:?}");
        // Bob keeps at most two sessions with her device.
        assert_eq!(p.b.store.all_sessions().unwrap().len(), 2);
    }
}

#[test]
fn reinvite_of_a_contact_who_kept_me_is_harmless() {
    let mut p = pair();
    let (alice, bob) = (p.a.fingerprint(), p.b.fingerprint());
    let at = NOW + 10;
    let out = p.b.invite(&alice, at, &mut p.rng).unwrap();
    assert_eq!(out.len(), 1);
    let got = p.a.receive(&out[0].encode(), "t", at, &mut p.rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(requests::get_request(&p.a.store, bob).unwrap().is_none());
    // Her ack tells Bob she knows him.
    let acks = acks_of(&mut p.a, at);
    let ack = acks.iter().find(|k| k.mailbox == out[0].mailbox).unwrap();
    p.b.receive(&ack.encode(), "t", at + 5, &mut p.rng).unwrap();
    assert_eq!(
        p.b.invite_state(&alice, at + 5).unwrap(),
        InviteState::Accepted { at: at + 5 }
    );
    // Both ways still work.
    let to_a = p.b.send_text(&alice, "b", at + 6, &mut p.rng).unwrap();
    let got =
        p.a.receive(&to_a[0].encode(), "t", at + 6, &mut p.rng)
            .unwrap();
    assert!(matches!(got, ReceiveOutcome::Message { .. }), "{got:?}");
    let to_b = p.a.send_text(&bob, "a", at + 7, &mut p.rng).unwrap();
    let got =
        p.b.receive(&to_b[0].encode(), "t", at + 7, &mut p.rng)
            .unwrap();
    assert!(matches!(got, ReceiveOutcome::Message { .. }), "{got:?}");
}

// --- Contact requests, task 5: receiving an invite from an unknown sender.

/// Alice (display name "Alice") added Bob; Bob does not know her.
fn alice_knows_bob() -> (TempDir, Core, TempDir, Core, StdRng) {
    let (da, mut a) = party("a", 1);
    let (db, b) = party("b", 2);
    a.contact_card("Alice").unwrap();
    a.add_contact(
        &b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut StdRng::seed_from_u64(0),
    )
    .unwrap();
    (da, a, db, b, StdRng::seed_from_u64(8))
}

/// The one packet of an invite for Bob's single device.
fn invite_one(a: &mut Core, bob: Fingerprint, at: u64, rng: &mut StdRng) -> Packet {
    let mut out = a.invite(&bob, at, rng).unwrap();
    assert_eq!(out.len(), 1);
    out.remove(0)
}

/// A `ContactRequest` carrying `card`, sealed by `from` for `to` under
/// `message_id` (no 24-hour cap: forged below the public API).
fn sealed_invite(
    from: &mut Core,
    to: Fingerprint,
    card: ContactCard,
    message_id: u8,
    rng: &mut StdRng,
) -> Packet {
    let body = ExtContent::ContactRequest {
        card: Box::new(card),
    }
    .to_body();
    seal_body(
        from,
        &send::Target::Contact(to),
        &body,
        MessageId([message_id; 16]),
        rng,
    )
    .remove(0)
    .0
}

fn request_outcome(o: ReceiveOutcome) -> (Fingerprint, bool, bool) {
    match o {
        ReceiveOutcome::ContactRequest {
            contact,
            resent,
            notify,
        } => (contact, resent, notify),
        other => panic!("ContactRequest expected, got {other:?}"),
    }
}

fn held_messages(c: &Core, fp: Fingerprint) -> usize {
    requests::list_pending_by_fp(&c.store, fp)
        .unwrap()
        .iter()
        .filter(|p| !p.invite)
        .count()
}

#[test]
fn invitation_creates_request_without_session_or_ack() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let outbox_before = b.pending_outbox(NOW).unwrap().len();
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, false, true));
    let list = requests::list_requests(&b.store).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].fingerprint, alice);
    assert_eq!(list[0].display_name, "Alice");
    assert_eq!(list[0].invite_count, 1);
    assert_eq!(list[0].pending_messages, 0);
    assert!(list[0].unseen);
    // The packet is held, not accepted: no session, no ack, not seen.
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].invite);
    assert_eq!(held[0].packet_id, p.id);
    assert!(b.store.all_sessions().unwrap().is_empty());
    assert_eq!(b.pending_outbox(NOW).unwrap().len(), outbox_before);
    assert_eq!(count_table(&b, "seen"), 0);
    assert!(b.contacts().unwrap().is_empty());
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestReceived { contact } if *contact == alice
        )),
        1
    );
}

#[test]
fn forged_invitation_creates_no_request() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    // Carol's real card, sealed by Alice's device: it does not list it.
    let (_dc, c) = party("c", 3);
    let carol = c.contact_card("Carol").unwrap();
    let p = sealed_invite(&mut a, b.fingerprint(), carol, 1, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_REQUEST_FORGED);
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn message_before_invitation_joins_request() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let text = a.send_text(&bob, "un", NOW, &mut rng).unwrap();
    let got = b.receive(&text[0].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 1);
    let p = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    let list = requests::list_requests(&b.store).unwrap();
    assert_eq!(list[0].pending_messages, 1);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    // A later message of the same sender joins the request directly.
    let more = a.send_text(&bob, "deux", NOW, &mut rng).unwrap();
    let got = b.receive(&more[0].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_PENDING_REQUEST);
    assert_eq!(held_messages(&b, alice), 2);
    assert!(b.store.all_sessions().unwrap().is_empty());
}

#[test]
fn resend_updates_single_request_and_counts() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = invite_one(&mut a, bob, NOW, &mut rng);
    b.receive(&first.encode(), "t", NOW, &mut rng).unwrap();
    let later = NOW + 86_400;
    let second = invite_one(&mut a, bob, later, &mut rng);
    let got = b.receive(&second.encode(), "t", later, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, true, true));
    let list = requests::list_requests(&b.store).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].invite_count, 2);
    assert_eq!(list[0].last_seen, later);
    // The resend replaced the stored invite.
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].packet_id, second.id);
    // The same packet again, or the replaced one redelivered (never acked,
    // nodes keep it): nothing changes.
    for p in [&second, &first] {
        let got = b.receive(&p.encode(), "t", later, &mut rng).unwrap();
        assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
    }
    assert_eq!(
        requests::list_requests(&b.store).unwrap()[0].invite_count,
        2
    );
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].packet_id, second.id);
}

#[test]
fn notification_at_most_once_per_24h() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let card = a.contact_card("Alice").unwrap();
    let one = sealed_invite(&mut a, bob, card.clone(), 1, &mut rng);
    let two = sealed_invite(&mut a, bob, card, 2, &mut rng);
    let got = b.receive(&one.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, false, true));
    let got = b
        .receive(&two.encode(), "t", NOW + 3_600, &mut rng)
        .unwrap();
    assert_eq!(request_outcome(got), (alice, true, false));
    let row = requests::get_request(&b.store, alice).unwrap().unwrap();
    assert_eq!(row.invite_count, 2);
    assert_eq!(row.last_notified, Some(NOW));
}

#[test]
fn caps_drop_newest() {
    // A full list of requests: a new sender is dropped.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    for n in 0..requests::MAX_PENDING_REQUESTS {
        let mut fp = [0xee; 32];
        fp[..4].copy_from_slice(&n.to_be_bytes());
        requests::upsert_request(
            &b.store,
            &requests::RequestRow {
                fp: Fingerprint(fp),
                card: vec![1],
                display_name: format!("r{n}"),
                first_seen: NOW,
                last_seen: NOW,
                invite_count: 1,
                hidden: false,
                unseen: true,
                last_notified: None,
            },
        )
        .unwrap();
    }
    let p = invite_one(&mut a, bob, NOW, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert_eq!(requests::count_requests(&b.store).unwrap(), 50);
    assert!(requests::get_request(&b.store, alice).unwrap().is_none());
    assert_eq!(count_table(&b, "pending_initials"), 0);

    // A request holds its newest invite and 3 messages: the 4th is dropped.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let p = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    for i in 0..4 {
        let text = a.send_text(&bob, &format!("m{i}"), NOW, &mut rng).unwrap();
        let got = b.receive(&text[0].encode(), "t", NOW, &mut rng).unwrap();
        assert_eq!(reason(got), R_PENDING_REQUEST);
    }
    assert_eq!(held_messages(&b, alice), 3);
    assert_eq!(
        requests::count_pending_for_fp(&b.store, alice).unwrap(),
        requests::MAX_PACKETS_PER_REQUEST
    );

    // The queue of unknown senders holds 16 packets: the 17th is dropped.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    for i in 0..=requests::MAX_UNKNOWN_INITIALS {
        let text = a.send_text(&bob, &format!("u{i}"), NOW, &mut rng).unwrap();
        let got = b.receive(&text[0].encode(), "t", NOW, &mut rng).unwrap();
        assert_eq!(reason(got), R_UNKNOWN_SENDER);
    }
    assert_eq!(
        requests::count_unknown(&b.store).unwrap(),
        requests::MAX_UNKNOWN_INITIALS
    );
    // Attached to the request when the invite comes: within its cap, the
    // others are dropped.
    let p = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    assert_eq!(held_messages(&b, alice), 3);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn blocked_fingerprint_invitation_is_dropped() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    // Bob blocked Alice, then removed her: the block outlives the contact.
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    b.block_contact(&alice, NOW, &mut rng).unwrap();
    b.remove_contact(&alice, NOW, &mut rng).unwrap();
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn refused_fingerprint_older_invitation_is_dropped() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    requests::put_refusal(&b.store, alice, NOW).unwrap();
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    // Sealed after the refusal: a request again.
    let later = NOW + 86_400;
    let p = invite_one(&mut a, b.fingerprint(), later, &mut rng);
    let got = b.receive(&p.encode(), "t", later, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, false, true));
}

#[test]
fn resend_from_another_session_replaces_its_packets() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let p = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    let text = a.send_text(&bob, "old", NOW, &mut rng).unwrap();
    b.receive(&text[0].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(held_messages(&b, alice), 1);
    // Alice drops her session (removed and added Bob again): her next
    // invite opens another one.
    a.remove_contact(&bob, NOW, &mut rng).unwrap();
    a.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let later = NOW + 86_400;
    let again = invite_one(&mut a, bob, later, &mut rng);
    let got = b.receive(&again.encode(), "t", later, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, true, true));
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].packet_id, again.id);
    // The replaced message, redelivered, does not come back.
    let got = b.receive(&text[0].encode(), "t", later, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
    assert_eq!(held_messages(&b, alice), 0);
}

/// A text in Alice's pending session to Bob, sealed with an Initial without
/// her signing key (as 0.6.0 wrote it).
fn unsigned_initial(a: &Core, b: &Core, rng: &mut StdRng) -> Packet {
    unsigned_initial_as(a, b, a.device.public().dh, 4, rng)
}

/// As `unsigned_initial`, with the Initial naming the identity key `ik`
/// (another device's to forge it) and the envelope secret `[secret; 16]`.
fn unsigned_initial_as(a: &Core, b: &Core, ik: [u8; 32], secret: u8, rng: &mut StdRng) -> Packet {
    let row = best_session(a);
    let mut init = de_init(row.pending_initial.as_deref().unwrap()).unwrap();
    init.sig = None;
    init.ik = ik;
    let mut ratchet = de_state(&row.state).unwrap();
    let env = Envelope {
        sent_at: NOW,
        ack_secret: [secret; 16],
        message_id: [secret; 16],
        body: Body::Text("old".into()),
    };
    let peer = b.device.public();
    crate::envelope::seal(
        &env,
        &mut ratchet,
        &row.ad,
        Some((&init, &peer.dh)),
        intro_mailbox(&peer, day_of(NOW)),
        NOW,
        rng,
    )
    .unwrap()
}

#[test]
fn unsigned_initial_is_held_without_trial() {
    // An Initial without the signing key (written by 0.6.0): held as it is,
    // in the queue of unknown senders, with no envelope read.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    a.send_text(&bob, "x", NOW, &mut rng).unwrap();
    let p = unsigned_initial(&a, &b, &mut rng);
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    let held = requests::list_pending_by_ik(&b.store, &a.device.public().dh).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].message_id, None);
    // Held once.
    let got = b.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
}

#[test]
fn unsigned_initial_does_not_squat_a_packet_id() {
    // An unauthenticated packet carrying the id of a real invite, received
    // first, does not make the invite pass for a duplicate.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let invite = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    let mut squat = unsigned_initial(&a, &b, &mut rng);
    squat.id = invite.id;
    let got = b.receive(&squat.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    let got = b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, false, true));
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].invite);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn legacy_pending_initial_is_sealed_with_my_signing_key() {
    let (_da, mut a, _db, b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    a.send_text(&bob, "x", NOW, &mut rng).unwrap();
    // The row as 0.6.0 stored it: no signing key.
    let mut row = best_session(&a);
    let stored = row.pending_initial.clone().unwrap();
    row.pending_initial = Some(stored[..stored.len() - 32].to_vec());
    a.store.put_session(&row).unwrap();
    let p = a.send_text(&bob, "y", NOW, &mut rng).unwrap();
    let Wire::Initial {
        ek, sealed_init, ..
    } = parse_wire(&p[0].payload).unwrap()
    else {
        panic!("Initial expected");
    };
    let init = crate::envelope::open_initial(&b.device, &ek, &sealed_init).unwrap();
    assert_eq!(init.sig, Some(a.device.public().sig));
}

#[test]
fn known_contact_new_device_invitation_updates_card() {
    // Bob knows Alice with one device; she links a tablet whose card never
    // reached Bob. The tablet writes to him, then invites him.
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(77);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let (db, mut b) = party("b", 9);
    let alice = a.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t.finish_link(&out.bundle, None, NOW).unwrap();
    t.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let to_bob = |pkts: Vec<Packet>| {
        pkts.into_iter()
            .find(|p| p.mailbox == intro_mailbox(&b.device.public(), day_of(NOW)))
            .unwrap()
    };
    let text = to_bob(
        t.send_text(&b.fingerprint(), "tablette", NOW, &mut rng)
            .unwrap(),
    );
    let invite = to_bob(t.invite(&b.fingerprint(), NOW, &mut rng).unwrap());
    let got = b.receive(&text.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    let got = b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_PENDING_REQUEST);
    // No request: the card of a known contact is updated instead, and the
    // tablet's packets are replayed at once.
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    assert_eq!(stored_card(&b, alice).devices.certs.len(), 2);
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(texts_with(&b, alice, NOW), ["tablette"]);
    let tablet = t.device.public().id();
    assert!(
        b.store
            .all_sessions()
            .unwrap()
            .iter()
            .any(|s| s.contact_device == tablet)
    );
    drop(db);
}

/// Bob knows Alice (her card signed at NOW) and has a session with her;
/// Alice then recovers her identity from her phrase on a new device at
/// `recovered_at` (a new device, a list of version `recovered_at`), adds Bob
/// again and invites him. Returns the recovered device, Bob, Alice's
/// fingerprint and the invite.
fn recovered_alice_invites(recovered_at: u64) -> (TempDir, Core, Core, Fingerprint, Packet) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(31);
    let (mut a, phrase) =
        Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let (mut b, _) = Core::create(&dir.path().join("b"), &[2; 32], "b", NOW, &mut rng).unwrap();
    let alice = a.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    a.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let p = a
        .send_text(&b.fingerprint(), "before", NOW, &mut rng)
        .unwrap();
    b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(b.store.all_sessions().unwrap().len(), 1);
    let mut r = Core::recover(
        &dir.path().join("r"),
        &[3; 32],
        phrase.as_str(),
        "r",
        recovered_at,
        &mut rng,
    )
    .unwrap();
    assert_eq!(r.fingerprint(), alice);
    r.contact_card("Alice").unwrap();
    r.add_contact(
        &b.contact_card("Bob").unwrap(),
        None,
        recovered_at,
        &mut rng,
    )
    .unwrap();
    let invite = invite_one(&mut r, b.fingerprint(), recovered_at, &mut rng);
    (dir, r, b, alice, invite)
}

#[test]
fn recovered_identity_invitation_updates_card() {
    let (_d, r, mut b, alice, invite) = recovered_alice_invites(NOW + 100);
    let old = stored_card(&b, alice);
    let mut rng = StdRng::seed_from_u64(32);
    let got = b
        .receive(&invite.encode(), "t", NOW + 100, &mut rng)
        .unwrap();
    assert_eq!(reason(got), R_PENDING_REQUEST);
    // No request: a card update, applied; the old device's session goes.
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    let card = stored_card(&b, alice);
    assert!(card.devices.supersedes(&old.devices));
    assert_eq!(card.devices.certs.len(), 1);
    assert_ne!(card.devices.certs[0].device, old.devices.certs[0].device);
    // The old device's session went; the replayed invite opened one with
    // the new device.
    let sessions = b.store.all_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].contact_device, r.device.public().id());
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactCardUpdated { contact, .. } if *contact == alice
        )),
        1
    );
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactKeyChanged { .. }
        )),
        0
    );
    // Held with Alice's fingerprint, then replayed: nothing left.
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn recovered_identity_older_list_refused() {
    // Recovered with a clock behind: its list is older than the known one.
    let (_d, _r, mut b, alice, invite) = recovered_alice_invites(NOW - 100);
    let old = stored_card(&b, alice);
    let mut rng = StdRng::seed_from_u64(32);
    let got = b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), contacts::R_CARD_REFUSED);
    assert_eq!(stored_card(&b, alice), old);
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(b.store.all_sessions().unwrap().len(), 1);
}

/// Mallory, who added Bob, and a pending session of hers toward him: her
/// Initials can name Alice's identity key, but not prove it.
fn mallory_toward(b: &Core, rng: &mut StdRng) -> (TempDir, Core) {
    let (dm, mut m) = party("m", 5);
    m.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, rng)
        .unwrap();
    m.send_text(&b.fingerprint(), "m", NOW, rng).unwrap();
    (dm, m)
}

#[test]
fn forged_unsigned_initial_cannot_join_a_request() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    let mut row = requests::get_request(&b.store, alice).unwrap().unwrap();
    row.unseen = false;
    requests::upsert_request(&b.store, &row).unwrap();
    let (_dm, m) = mallory_toward(&b, &mut rng);
    let alice_ik = a.device.public().dh;
    for secret in 1..=4 {
        let forged = unsigned_initial_as(&m, &b, alice_ik, secret, &mut rng);
        let got = b
            .receive(&forged.encode(), "t", NOW + 60, &mut rng)
            .unwrap();
        let r = reason(got);
        assert_ne!(r, R_PENDING_REQUEST);
        assert_ne!(r, R_UNKNOWN_SENDER);
    }
    // No slot taken, the request untouched.
    assert_eq!(held_messages(&b, alice), 0);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    assert_eq!(
        requests::get_request(&b.store, alice).unwrap().unwrap(),
        row
    );
}

#[test]
fn forged_queued_initial_is_not_attached() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    // Before any invite: no card to check them against, both are queued.
    let (_dm, m) = mallory_toward(&b, &mut rng);
    let forged = unsigned_initial_as(&m, &b, a.device.public().dh, 1, &mut rng);
    let got = b.receive(&forged.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    let genuine = unsigned_initial_as(&a, &b, a.device.public().dh, 2, &mut rng);
    let got = b.receive(&genuine.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 2);
    // The invite comes: only the genuine one joins the request.
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    let messages: Vec<_> = held.iter().filter(|h| !h.invite).collect();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].packet_id, genuine.id);
    assert_eq!(messages[0].message_id, Some(MessageId([2; 16])));
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn unsigned_message_from_the_requester_is_held() {
    // A 0.6.0-style Initial (no signing key) from the requester's device:
    // authenticated as the device its card lists, then held.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let p = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    let genuine = unsigned_initial(&a, &b, &mut rng);
    let got = b
        .receive(&genuine.encode(), "t", NOW + 60, &mut rng)
        .unwrap();
    assert_eq!(reason(got), R_PENDING_REQUEST);
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    let message = held.iter().find(|h| !h.invite).unwrap();
    assert_eq!(message.packet_id, genuine.id);
    assert_eq!(message.message_id, Some(MessageId([4; 16])));
    assert_eq!(
        requests::get_request(&b.store, alice)
            .unwrap()
            .unwrap()
            .last_seen,
        NOW + 60
    );
    let got = b
        .receive(&genuine.encode(), "t", NOW + 60, &mut rng)
        .unwrap();
    assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
}

// --- Contact requests, task 6: accepting, replaying, resolving by an add.

/// The texts of my conversation with `fp`, oldest first.
fn texts_with(c: &Core, fp: Fingerprint, now: u64) -> Vec<String> {
    c.messages_with(&fp, now)
        .unwrap()
        .into_iter()
        .map(|m| m.body)
        .collect()
}

/// The texts of the `Message` outcomes, in order.
fn replayed_texts(outcomes: &[ReceiveOutcome]) -> Vec<String> {
    outcomes
        .iter()
        .filter_map(|o| match o {
            ReceiveOutcome::Message { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Packets of `kind` in `c`'s send queue at `now`.
fn outbox_of(c: &mut Core, kind: Kind, now: u64) -> usize {
    c.pending_outbox(now)
        .unwrap()
        .iter()
        .filter(|b| Packet::decode(b).unwrap().kind == kind)
        .count()
}

/// Alice invites Bob, then writes "un" and "deux"; Bob receives the three
/// packets at `at`: a request holding the invite and two messages.
fn bob_with_request(at: u64) -> (TempDir, Core, TempDir, Core, StdRng) {
    let (da, mut a, db, mut b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let un = a.send_text(&bob, "un", NOW, &mut rng).unwrap();
    let deux = a.send_text(&bob, "deux", NOW, &mut rng).unwrap();
    request_outcome(b.receive(&invite.encode(), "t", at, &mut rng).unwrap());
    for p in [&un[0], &deux[0]] {
        assert_eq!(
            reason(b.receive(&p.encode(), "t", at, &mut rng).unwrap()),
            R_PENDING_REQUEST
        );
    }
    (da, a, db, b, rng)
}

#[test]
fn accept_replays_messages_in_order() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    let accepted = b.accept_request(&alice, None, NOW, &mut rng).unwrap();
    assert_eq!(accepted.contact, alice);
    assert_eq!(replayed_texts(&accepted.replayed), ["un", "deux"]);
    assert_eq!(texts_with(&b, alice, NOW), ["un", "deux"]);
    // REQUEST_ACCEPTED, sealed for Alice.
    assert!(!accepted.packets.is_empty());
    assert!(requests::get_request(&b.store, alice).unwrap().is_none());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                contact,
                how: RequestResolution::Accepted,
            } if *contact == alice
        )),
        1
    );
    // Accepted without an alias: the declared name stays the card's.
    assert_eq!(b.store.get_contact(alice).unwrap().unwrap().alias, "");
}

#[test]
fn accept_never_replaces_contact_with_same_name() {
    let (_dx, mut x, _db, mut b, mut rng) = alice_knows_bob();
    let (_dl, l) = party("l", 6);
    let lea = l.fingerprint();
    b.add_contact(&l.contact_card("Léa").unwrap(), Some("léa"), NOW, &mut rng)
        .unwrap();
    // An unknown X declares "Léa".
    let xfp = x.fingerprint();
    x.contact_card("Léa").unwrap();
    let card = x.contact_card("Léa").unwrap();
    let p = sealed_invite(&mut x, b.fingerprint(), card, 1, &mut rng);
    request_outcome(b.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    // An explicit alias already taken: refused, nothing written.
    let got = b.accept_request(&xfp, Some("léa"), NOW, &mut rng);
    assert!(matches!(got, Err(CoreError::Malformed(_))), "{got:?}");
    assert_eq!(b.store.get_contact(lea).unwrap().unwrap().alias, "léa");
    assert!(b.store.get_contact(xfp).unwrap().is_none());
    assert!(requests::get_request(&b.store, xfp).unwrap().is_some());
    assert_eq!(
        requests::list_pending_by_fp(&b.store, xfp).unwrap().len(),
        1
    );
    // Accepted without an alias: Léa stays, X is added without one.
    b.accept_request(&xfp, None, NOW, &mut rng).unwrap();
    assert_eq!(b.store.get_contact(lea).unwrap().unwrap().alias, "léa");
    assert_eq!(b.store.get_contact(xfp).unwrap().unwrap().alias, "");
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactKeyChanged { .. }
        )),
        0
    );
}

#[test]
fn request_safety_number_matches_after_accept() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    // No request yet.
    assert!(matches!(
        b.request_safety_number(&alice),
        Err(CoreError::UnknownContact)
    ));
    let invite = invite_one(&mut a, b.fingerprint(), NOW, &mut rng);
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    let before = b.request_safety_number(&alice).unwrap();
    b.accept_request(&alice, None, NOW, &mut rng).unwrap();
    assert_eq!(before, b.safety_number(&alice).unwrap());
}

#[test]
fn accept_on_day_20_replays_without_acks() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    let day_20 = NOW + 20 * 86_400;
    let accepted = b.accept_request(&alice, None, day_20, &mut rng).unwrap();
    assert_eq!(replayed_texts(&accepted.replayed), ["un", "deux"]);
    assert_eq!(texts_with(&b, alice, day_20), ["un", "deux"]);
    assert_eq!(outbox_of(&mut b, Kind::Ack, day_20), 0);
    assert_eq!(
        count_events(&b, |e| matches!(e, TransparencyEvent::AckEmitted { .. })),
        0
    );
}

#[test]
fn accept_within_grace_acks_replayed_packets() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    let later = NOW + 3_600;
    b.accept_request(&alice, None, later, &mut rng).unwrap();
    // The invite and both messages.
    assert_eq!(outbox_of(&mut b, Kind::Ack, later), 3);
}

#[test]
fn replay_is_resumable() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    // Accepted (step 1), then a crash after the first packet's replay.
    let row = requests::get_request(&b.store, alice).unwrap().unwrap();
    let card = load_card(&row.card).unwrap();
    {
        let Core { store, device, .. } = &mut b;
        store
            .transaction(|tx| {
                contacts::add_in(tx, device, &card, None, NOW, &mut rng)?;
                requests::delete_request_row(tx, alice)
            })
            .unwrap();
    }
    let held = requests::list_pending_by_fp(&b.store, alice).unwrap();
    assert_eq!(held.len(), 3);
    requests::replay_held(&mut b, &held[0], NOW, &mut rng).unwrap();
    assert_eq!(
        requests::list_pending_by_fp(&b.store, alice).unwrap().len(),
        2
    );
    // Resumed: the rest only, nothing twice.
    let rest = requests::replay_pending(&mut b, alice, NOW, &mut rng).unwrap();
    assert_eq!(rest.len(), 2);
    assert_eq!(texts_with(&b, alice, NOW), ["un", "deux"]);
    assert!(
        requests::replay_pending(&mut b, alice, NOW, &mut rng)
            .unwrap()
            .is_empty()
    );
    assert_eq!(texts_with(&b, alice, NOW), ["un", "deux"]);
}

#[test]
fn adding_requester_resolves_request() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    assert!(requests::get_request(&b.store, alice).unwrap().is_none());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(texts_with(&b, alice, NOW), ["un", "deux"]);
    // No REQUEST_ACCEPTED: nothing but the acks (Bob has no other device).
    assert_eq!(outbox_of(&mut b, Kind::Message, NOW), 0);
    assert_eq!(outbox_of(&mut b, Kind::Ack, NOW), 3);
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::AddedDirectly,
                ..
            }
        )),
        1
    );
}

#[test]
fn recovered_identity_invitation_switches_contact_to_new_device() {
    // Alice (here the one who recovers) and Bob know each other; Alice
    // recovers from her phrase, adds Bob again, invites him and writes.
    let at = NOW + 100;
    let (_d, mut r, mut b, alice, invite) = recovered_alice_invites(at);
    let mut rng = StdRng::seed_from_u64(33);
    let bob = b.fingerprint();
    let text = r.send_text(&bob, "back", at, &mut rng).unwrap();
    // The message first: its device is not in Alice's card yet.
    let got = b.receive(&text[0].encode(), "t", at, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    b.receive(&invite.encode(), "t", at, &mut rng).unwrap();
    // No request; the card lists the new device only; the message replayed.
    assert!(requests::list_requests(&b.store).unwrap().is_empty());
    let card = stored_card(&b, alice);
    assert_eq!(card.devices.certs.len(), 1);
    assert_eq!(card.devices.certs[0].device, r.device.public());
    let new_id = r.device.public().id();
    let sessions = b.store.all_sessions().unwrap();
    assert!(!sessions.is_empty());
    assert!(sessions.iter().all(|s| s.contact_device == new_id));
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(texts_with(&b, alice, at), ["before", "back"]);
    // Bob answers; the recovered device reads it.
    let reply = b.send_text(&alice, "ok", at, &mut rng).unwrap();
    assert_eq!(reply.len(), 1);
    match r.receive(&reply[0].encode(), "t", at, &mut rng).unwrap() {
        ReceiveOutcome::Message { text, .. } => assert_eq!(text, "ok"),
        other => panic!("Message expected, got {other:?}"),
    }
}

#[test]
fn accept_on_one_device_resolves_on_the_other() {
    // Bob has two devices, each received its invite.
    let (_d, mut b1, mut b2, mut rng) = linked();
    let (_da, mut a) = party("alice", 7);
    let alice = a.fingerprint();
    a.contact_card("Alice").unwrap();
    a.add_contact(&b1.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let packets = a.invite(&b1.fingerprint(), NOW, &mut rng).unwrap();
    assert_eq!(packets.len(), 2);
    for bob in [&mut b1, &mut b2] {
        let mailbox = intro_mailbox(&bob.device.public(), day_of(NOW));
        let p = packets.iter().find(|p| p.mailbox == mailbox).unwrap();
        request_outcome(bob.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    }
    b1.accept_request(&alice, None, NOW, &mut rng).unwrap();
    // The SyncContact reaches B2: its packets replayed, its request gone.
    for bytes in b1.pending_outbox(NOW).unwrap() {
        b2.receive(&bytes, "t", NOW, &mut rng).unwrap();
    }
    assert!(b2.store.get_contact(alice).unwrap().is_some());
    assert!(requests::get_request(&b2.store, alice).unwrap().is_none());
    assert_eq!(count_table(&b2, "pending_initials"), 0);
    assert!(
        b2.store
            .all_sessions()
            .unwrap()
            .iter()
            .any(|s| s.contact_fp == alice)
    );
    assert_eq!(
        count_events(&b2, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::AddedDirectly,
                ..
            }
        )),
        1
    );
}

#[test]
fn adding_a_card_replays_its_queued_packets() {
    // Spec §7.3, step 3: the queue of unknown senders for the card's keys is
    // replayed too. Alice writes without an invite; Bob adds her card.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let text = a
        .send_text(&b.fingerprint(), "sans invitation", NOW, &mut rng)
        .unwrap();
    let got = b.receive(&text[0].encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(got), R_UNKNOWN_SENDER);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 1);
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(texts_with(&b, alice, NOW), ["sans invitation"]);
}

// --- Contact requests, task 7: the invite's state on the inviting side.

/// The `Kind::Ack` packets in `c`'s send queue at `now`.
fn acks_of(c: &mut Core, now: u64) -> Vec<Packet> {
    c.pending_outbox(now)
        .unwrap()
        .iter()
        .map(|b| Packet::decode(b).unwrap())
        .filter(|p| p.kind == Kind::Ack)
        .collect()
}

/// The status of my outgoing message `text` to `fp`.
fn sent_status(c: &Core, fp: Fingerprint, text: &str, now: u64) -> MessageStatus {
    c.messages_with(&fp, now)
        .unwrap()
        .into_iter()
        .find(|m| m.body == text && m.direction == Direction::Out)
        .unwrap()
        .status
}

#[test]
fn invite_state_moves_from_sent_to_unanswered() {
    let (_da, mut a, _db, b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    assert_eq!(a.invite_state(&bob, NOW).unwrap(), InviteState::None);
    invite_one(&mut a, bob, NOW, &mut rng);
    assert_eq!(
        a.invite_state(&bob, NOW + 1).unwrap(),
        InviteState::Sent { at: NOW }
    );
    assert_eq!(
        a.invite_state(&bob, NOW + 604_799).unwrap(),
        InviteState::Sent { at: NOW }
    );
    assert_eq!(
        a.invite_state(&bob, NOW + 604_800).unwrap(),
        InviteState::Unanswered { at: NOW }
    );
}

#[test]
fn request_accepted_marks_state_and_replayed_messages() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let salut = a.send_text(&bob, "salut", NOW, &mut rng).unwrap();
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    assert_eq!(
        reason(b.receive(&salut[0].encode(), "t", NOW, &mut rng).unwrap()),
        R_PENDING_REQUEST
    );
    // Never deposited: the delivery expires at Alice's.
    let expired = NOW + DEFAULT_TTL_SECS + 1;
    a.expire_due(expired).unwrap();
    assert_eq!(
        sent_status(&a, bob, "salut", expired),
        MessageStatus::NotDelivered
    );
    let day_20 = NOW + 20 * 86_400;
    let accepted = b.accept_request(&alice, None, day_20, &mut rng).unwrap();
    assert_eq!(accepted.packets.len(), 1);
    let got = a
        .receive(&accepted.packets[0].encode(), "t", day_20, &mut rng)
        .unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert_eq!(
        a.invite_state(&bob, day_20).unwrap(),
        InviteState::Accepted { at: day_20 }
    );
    assert_eq!(
        sent_status(&a, bob, "salut", day_20),
        MessageStatus::Received
    );
    // Acked like any message, so Bob stops resending it.
    assert_eq!(acks_of(&mut a, day_20).len(), 1);
    // The first date stays.
    let later = day_20 + 3_600;
    let text = b.send_text(&alice, "plus tard", later, &mut rng).unwrap();
    a.receive(&text[0].encode(), "t", later, &mut rng).unwrap();
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Accepted { at: day_20 }
    );
}

#[test]
fn request_accepted_ignores_other_messages() {
    // The list names only my outgoing messages to the sender.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    let (_dc, c) = party("c", 7);
    a.add_contact(&c.contact_card("Carol").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let carol = c.fingerprint();
    a.send_text(&carol, "pour carol", NOW, &mut rng).unwrap();
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    let expired = NOW + DEFAULT_TTL_SECS + 1;
    a.expire_due(expired).unwrap();
    b.accept_request(&alice, None, expired, &mut rng).unwrap();
    // A forged list naming Alice's message to Carol, sealed by Bob.
    let carol_id = a
        .messages_with(&carol, expired)
        .unwrap()
        .into_iter()
        .find(|m| m.body == "pour carol")
        .unwrap()
        .message_id;
    let body = ExtContent::RequestAccepted {
        replayed: vec![carol_id],
    }
    .to_body();
    let forged = seal_body(
        &mut b,
        &send::Target::Contact(alice),
        &body,
        MessageId([9; 16]),
        &mut rng,
    )
    .remove(0)
    .0;
    a.receive(&forged.encode(), "t", expired, &mut rng).unwrap();
    assert_eq!(
        sent_status(&a, carol, "pour carol", expired),
        MessageStatus::NotDelivered
    );
}

#[test]
fn request_accepted_from_my_own_device_is_refused() {
    let (_dir, mut a, mut tablet, mut rng) = linked();
    let (_db, b) = party("b", 2);
    let bob = b.fingerprint();
    a.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    a.invite(&bob, NOW, &mut rng).unwrap();
    let body = ExtContent::RequestAccepted { replayed: vec![] }.to_body();
    let p = seal_body(
        &mut tablet,
        &send::Target::OwnDevices,
        &body,
        MessageId([4; 16]),
        &mut rng,
    )
    .remove(0)
    .0;
    let got = a.receive(&p.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Quarantined { .. }), "{got:?}");
    assert_eq!(
        a.invite_state(&bob, NOW).unwrap(),
        InviteState::Sent { at: NOW }
    );
}

#[test]
fn invitation_to_known_contact_is_acked_and_ignored() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let at = NOW + 60;
    let got = b.receive(&invite.encode(), "t", at, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(requests::get_request(&b.store, alice).unwrap().is_none());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    let acks = acks_of(&mut b, at);
    assert_eq!(acks.len(), 1);
    let later = at + 60;
    let got = a.receive(&acks[0].encode(), "t", later, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::AckReceived { .. }), "{got:?}");
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Accepted { at: later }
    );
}

#[test]
fn any_message_from_the_invited_marks_the_invite_accepted() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    let bob = b.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    invite_one(&mut a, bob, NOW, &mut rng);
    let text = b.send_text(&alice, "coucou", NOW + 5, &mut rng).unwrap();
    a.receive(&text[0].encode(), "t", NOW + 10, &mut rng)
        .unwrap();
    assert_eq!(
        a.invite_state(&bob, NOW + 10).unwrap(),
        InviteState::Accepted { at: NOW + 10 }
    );
}

// --- Contact requests, task 8: refusing, blocking, hiding, listing, purging.

fn unknown_packet(id: u8, received_at: u64) -> requests::PendingInitial {
    requests::PendingInitial {
        packet_id: PacketId([id; 16]),
        ik: [id; 32],
        fp: None,
        session_id: [id; 16],
        message_id: Some(MessageId([id; 16])),
        bytes: vec![id; 5],
        received_at,
        invite: false,
    }
}

/// Alice invites Bob and his tablet; each device holds a request.
fn both_devices_have_request() -> (TempDir, TempDir, Core, Core, Core, StdRng) {
    let (da, db, mut a, mut b, mut bt, mut rng) = alice_and_bob_with_tablet();
    let bob = b.fingerprint();
    let out = a.invite(&bob, NOW, &mut rng).unwrap();
    for p in &out {
        let target = if p.mailbox == intro_mailbox(&b.device.public(), day_of(NOW)) {
            &mut b
        } else {
            &mut bt
        };
        request_outcome(target.receive(&p.encode(), "t", NOW, &mut rng).unwrap());
    }
    (da, db, a, b, bt, rng)
}

#[test]
fn refuse_sends_nothing_to_requester() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    let queued = b.pending_outbox(NOW).unwrap().len();
    let out = b.refuse_request(&alice, NOW + 1, &mut rng).unwrap();
    // No other device of mine: no `SyncRefused` either.
    assert!(out.is_empty());
    assert_eq!(b.pending_outbox(NOW + 1).unwrap().len(), queued);
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(
        requests::get_refusal(&b.store, alice).unwrap(),
        Some(NOW + 1)
    );
    assert!(matches!(
        b.refuse_request(&alice, NOW + 2, &mut rng),
        Err(CoreError::UnknownContact)
    ));
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::Refused,
                ..
            }
        )),
        1
    );
}

#[test]
fn invitation_sealed_before_refusal_is_dropped() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = invite_one(&mut a, bob, NOW, &mut rng);
    let card = a.contact_card("Alice").unwrap();
    let opening = sealed_invite(&mut a, bob, card, 7, &mut rng);
    request_outcome(b.receive(&opening.encode(), "t", NOW, &mut rng).unwrap());
    b.refuse_request(&alice, NOW + 1, &mut rng).unwrap();
    // Sealed at NOW, fetched only at NOW + 5.
    let got = b.receive(&first.encode(), "t", NOW + 5, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(b.requests().unwrap().is_empty());
    // A resend sealed a day later is a new request, notified.
    let later = NOW + 86_400;
    let resend = invite_one(&mut a, bob, later, &mut rng);
    let got = b.receive(&resend.encode(), "t", later, &mut rng).unwrap();
    assert_eq!(request_outcome(got), (alice, false, true));
}

#[test]
fn refusal_syncs_to_my_other_devices() {
    let (_da, _db, a, mut b, mut bt, mut rng) = both_devices_have_request();
    let alice = a.fingerprint();
    assert_eq!(bt.requests().unwrap().len(), 1);
    let out = b.refuse_request(&alice, NOW + 1, &mut rng).unwrap();
    assert_eq!(out.len(), 1);
    // Also in the send queue: `barking outbox` rewrites it.
    assert!(
        b.pending_outbox(NOW + 1)
            .unwrap()
            .contains(&out[0].encode())
    );
    let got = bt
        .receive(&out[0].encode(), "t", NOW + 1, &mut rng)
        .unwrap();
    assert!(
        !matches!(got, ReceiveOutcome::Quarantined { .. }),
        "{got:?}"
    );
    assert!(bt.requests().unwrap().is_empty());
    assert_eq!(count_table(&bt, "pending_initials"), 0);
    assert_eq!(
        requests::get_refusal(&bt.store, alice).unwrap(),
        Some(NOW + 1)
    );
    // Last writer wins: an older refusal does not move the date back.
    let older = ExtContent::SyncRefused { fp: alice, at: NOW }.to_body();
    let pkt = seal_body(
        &mut b,
        &send::Target::OwnDevices,
        &older,
        MessageId([9; 16]),
        &mut rng,
    )
    .remove(0)
    .0;
    bt.receive(&pkt.encode(), "t", NOW + 2, &mut rng).unwrap();
    assert_eq!(
        requests::get_refusal(&bt.store, alice).unwrap(),
        Some(NOW + 1)
    );
}

#[test]
fn block_request_drops_later_invitations() {
    let (_da, _db, mut a, mut b, mut bt, mut rng) = both_devices_have_request();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let out = b.block_request(&alice, NOW + 1, &mut rng).unwrap();
    assert_eq!(out.len(), 1);
    assert!(
        b.pending_outbox(NOW + 1)
            .unwrap()
            .contains(&out[0].encode())
    );
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert!(b.store.block_state(alice).unwrap().blocked);
    // `SyncOp::Block` closes the request on the tablet too.
    bt.receive(&out[0].encode(), "t", NOW + 1, &mut rng)
        .unwrap();
    assert!(bt.store.block_state(alice).unwrap().blocked);
    assert!(bt.requests().unwrap().is_empty());
    let later = NOW + 86_400;
    let resend = a.invite(&bob, later, &mut rng).unwrap();
    let mine = intro_mailbox(&b.device.public(), day_of(later));
    let resend = resend.iter().find(|p| p.mailbox == mine).unwrap();
    let got = b.receive(&resend.encode(), "t", later, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::Blocked,
                ..
            }
        )),
        1
    );
}

#[test]
fn hidden_request_stays_listed_and_lights_indicator() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = invite_one(&mut a, bob, NOW, &mut rng);
    b.receive(&first.encode(), "t", NOW, &mut rng).unwrap();
    assert!(b.requests().unwrap()[0].unseen);
    b.set_request_hidden(&alice, true).unwrap();
    // Hiding touches neither `unseen` nor the other devices.
    let list = b.requests().unwrap();
    assert!(list[0].hidden && list[0].unseen);
    assert_eq!(count_table(&b, "outbox"), 0);
    b.mark_requests_seen().unwrap();
    assert!(!b.requests().unwrap()[0].unseen);
    let later = NOW + 86_400;
    let resend = invite_one(&mut a, bob, later, &mut rng);
    b.receive(&resend.encode(), "t", later, &mut rng).unwrap();
    let list = b.requests().unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].hidden && list[0].unseen);
    b.set_request_hidden(&alice, false).unwrap();
    assert!(!b.requests().unwrap()[0].hidden);
    assert!(matches!(
        b.set_request_hidden(&Fingerprint([9; 32]), true),
        Err(CoreError::UnknownContact)
    ));
}

/// Spec §7.2: a message held for a hidden request, already seen, lights
/// the indicator again; the request stays hidden.
#[test]
fn held_message_relights_hidden_request() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&first.encode(), "t", NOW, &mut rng).unwrap());
    b.set_request_hidden(&alice, true).unwrap();
    b.mark_requests_seen().unwrap();
    assert!(!b.requests().unwrap()[0].unseen);
    let text = a.send_text(&bob, "un", NOW + 60, &mut rng).unwrap();
    let got = b
        .receive(&text[0].encode(), "t", NOW + 60, &mut rng)
        .unwrap();
    assert_eq!(reason(got), R_PENDING_REQUEST);
    let list = b.requests().unwrap();
    assert!(list[0].hidden && list[0].unseen);
    assert_eq!(list[0].pending_messages, 1);
    assert_eq!(list[0].last_seen, NOW + 60);
}

/// A blocked requester is no contact: `blocked_strangers` lists it, so
/// that it can be unblocked; a blocked contact is not listed there.
#[test]
fn blocked_strangers_lists_blocked_non_contacts() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let (_dc, c) = party("c", 3);
    let carol_card = c.contact_card("Carol").unwrap();
    let carol = c.fingerprint();
    b.add_contact(&carol_card, Some("carol"), NOW, &mut rng)
        .unwrap();
    b.block_contact(&carol, NOW, &mut rng).unwrap();
    assert!(b.blocked_strangers().unwrap().is_empty());
    let first = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&first.encode(), "t", NOW, &mut rng).unwrap());
    b.block_request(&alice, NOW + 1, &mut rng).unwrap();
    assert_eq!(b.blocked_strangers().unwrap(), vec![alice]);
    b.unblock_contact(&alice, NOW + 2, &mut rng).unwrap();
    assert!(b.blocked_strangers().unwrap().is_empty());
    drop(c);
}

#[test]
fn requests_are_listed_most_recent_first() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (_dc, mut c) = party("c", 3);
    c.contact_card("Carol").unwrap();
    c.add_contact(&b.contact_card("Bob").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let bob = b.fingerprint();
    let pa = invite_one(&mut a, bob, NOW, &mut rng);
    let pc = invite_one(&mut c, bob, NOW + 10, &mut rng);
    b.receive(&pc.encode(), "t", NOW + 10, &mut rng).unwrap();
    b.receive(&pa.encode(), "t", NOW + 20, &mut rng).unwrap();
    let list = b.requests().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].fingerprint, a.fingerprint());
    assert_eq!(list[1].fingerprint, c.fingerprint());
}

#[test]
fn purge_expires_requests_queue_and_refusals() {
    let (_da, a, _db, b, _rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    let (day, week) = (86_400, requests::UNKNOWN_RETENTION_SECS);
    requests::insert_pending_initial(&b.store, &unknown_packet(200, NOW)).unwrap();
    requests::put_refusal(&b.store, Fingerprint([8; 32]), NOW).unwrap();
    // Exactly at the limit nothing goes.
    requests::purge_requests(&b.store, NOW + week).unwrap();
    assert_eq!(count_table(&b, "pending_initials") as usize, 4);
    assert_eq!(count_table(&b, "refused_requests"), 1);
    requests::purge_requests(&b.store, NOW + week + 1).unwrap();
    assert_eq!(count_table(&b, "refused_requests"), 0);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    // The request itself keeps its 30 days.
    assert_eq!(b.requests().unwrap().len(), 1);
    assert_eq!(held_messages(&b, alice), 2);
    requests::purge_requests(&b.store, NOW + 30 * day).unwrap();
    assert_eq!(b.requests().unwrap().len(), 1);
    requests::purge_requests(&b.store, NOW + 30 * day + 1).unwrap();
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::Expired,
                ..
            }
        )),
        1
    );
}

#[test]
fn purge_drops_old_packets_held_for_a_contact() {
    let p = pair();
    let alice = p.a.fingerprint();
    let mut old = unknown_packet(1, NOW);
    old.fp = Some(alice);
    let mut recent = unknown_packet(2, NOW + 100);
    recent.fp = Some(alice);
    requests::insert_pending_initial(&p.b.store, &old).unwrap();
    requests::insert_pending_initial(&p.b.store, &recent).unwrap();
    let limit = NOW + requests::UNKNOWN_RETENTION_SECS;
    requests::purge_requests(&p.b.store, limit + 1).unwrap();
    let left = requests::list_pending_by_fp(&p.b.store, alice).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].packet_id, recent.packet_id);
}

#[test]
fn polling_purges_expired_requests() {
    let (_da, _a, _db, mut b, _rng) = bob_with_request(NOW);
    b.mark_polled(NOW + 30 * 86_400 + 1).unwrap();
    assert!(b.requests().unwrap().is_empty());
}

// --- Contact requests, whole-branch review fixes.

/// Alice invites Bob and writes "un" to him; Bob holds a request with that
/// message. Returns the invite and the message packets.
fn bob_holds_invite_and_message(a: &mut Core, b: &mut Core, rng: &mut StdRng) -> (Packet, Packet) {
    let bob = b.fingerprint();
    let invite = invite_one(a, bob, NOW, rng);
    let un = a.send_text(&bob, "un", NOW, rng).unwrap().remove(0);
    request_outcome(b.receive(&invite.encode(), "t", NOW, rng).unwrap());
    assert_eq!(
        reason(b.receive(&un.encode(), "t", NOW, rng).unwrap()),
        R_PENDING_REQUEST
    );
    (invite, un)
}

#[test]
fn refused_requester_packets_do_not_come_back() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    let alice = a.fingerprint();
    let (invite, un) = bob_holds_invite_and_message(&mut a, &mut b, &mut rng);
    b.refuse_request(&alice, NOW + 1, &mut rng).unwrap();
    // Nodes keep the packets (never acked): the next poll fetches them
    // again. They do not land in the queue of unknown senders.
    for p in [&invite, &un] {
        let got = b.receive(&p.encode(), "t", NOW + 2, &mut rng).unwrap();
        assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
    }
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    // A fresh resend opens a new request without the refused message,
    // even when that message is fetched again afterwards.
    let later = NOW + 86_400;
    let resend = invite_one(&mut a, bob, later, &mut rng);
    request_outcome(b.receive(&resend.encode(), "t", later, &mut rng).unwrap());
    b.receive(&un.encode(), "t", later, &mut rng).unwrap();
    let list = b.requests().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].pending_messages, 0);
}

#[test]
fn blocked_requester_packets_do_not_come_back() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    let alice = a.fingerprint();
    let (invite, un) = bob_holds_invite_and_message(&mut a, &mut b, &mut rng);
    b.block_request(&alice, NOW + 1, &mut rng).unwrap();
    for p in [&invite, &un] {
        let got = b.receive(&p.encode(), "t", NOW + 2, &mut rng).unwrap();
        assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
    }
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    // Unblocked, then invited again: the message blocked stays out.
    b.unblock_contact(&alice, NOW + 3, &mut rng).unwrap();
    let later = NOW + 86_400;
    let resend = invite_one(&mut a, bob, later, &mut rng);
    request_outcome(b.receive(&resend.encode(), "t", later, &mut rng).unwrap());
    b.receive(&un.encode(), "t", later, &mut rng).unwrap();
    let list = b.requests().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].pending_messages, 0);
}

#[test]
fn blocked_sender_invitation_empties_its_queued_messages() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    b.block_contact(&alice, NOW, &mut rng).unwrap();
    b.remove_contact(&alice, NOW, &mut rng).unwrap();
    // A message before the invite: no card yet, it is queued.
    let un = a.send_text(&bob, "un", NOW, &mut rng).unwrap().remove(0);
    assert_eq!(
        reason(b.receive(&un.encode(), "t", NOW, &mut rng).unwrap()),
        R_UNKNOWN_SENDER
    );
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 1);
    // The invite names her devices: her queued packets go, for good.
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let got = b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
    let got = b.receive(&un.encode(), "t", NOW + 1, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Duplicate), "{got:?}");
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn message_of_a_blocked_requester_is_not_held() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    // A block that did not close the request (a crossing it cannot be
    // reproduced with: set below the API).
    let state = crate::store::BlockState {
        blocked: true,
        at: NOW,
        since: NOW,
    };
    b.store.set_block_state(alice, &state).unwrap();
    let un = a.send_text(&bob, "un", NOW, &mut rng).unwrap().remove(0);
    let got = b.receive(&un.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert_eq!(held_messages(&b, alice), 0);
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn invite_after_remove_and_readd_is_not_accepted() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    request_outcome(b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap());
    let accepted = b.accept_request(&alice, None, NOW + 10, &mut rng).unwrap();
    a.receive(&accepted.packets[0].encode(), "t", NOW + 10, &mut rng)
        .unwrap();
    assert_eq!(
        a.invite_state(&bob, NOW + 10).unwrap(),
        InviteState::Accepted { at: NOW + 10 }
    );
    a.remove_contact(&bob, NOW + 20, &mut rng).unwrap();
    a.add_contact(&b.contact_card("Bob").unwrap(), None, NOW + 20, &mut rng)
        .unwrap();
    let later = NOW + 86_400;
    invite_one(&mut a, bob, later, &mut rng);
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Sent { at: later }
    );
}

#[test]
fn invite_to_the_devices_still_waiting_keeps_the_acceptance() {
    let (_da, _db, mut a, mut b, _bt, mut rng) = alice_and_bob_with_tablet();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let out = a.invite(&bob, NOW, &mut rng).unwrap();
    let mine = intro_mailbox(&b.device.public(), day_of(NOW));
    let to_phone = out.iter().find(|p| p.mailbox == mine).unwrap();
    request_outcome(b.receive(&to_phone.encode(), "t", NOW, &mut rng).unwrap());
    let accepted = b.accept_request(&alice, None, NOW + 10, &mut rng).unwrap();
    a.receive(&accepted.packets[0].encode(), "t", NOW + 10, &mut rng)
        .unwrap();
    // The tablet has not answered: the resend goes to it only.
    let later = NOW + 86_400;
    assert_eq!(a.invite(&bob, later, &mut rng).unwrap().len(), 1);
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Accepted { at: NOW + 10 }
    );
}

/// A held row for `fp` that cannot be read back (`ik` of 3 bytes): the
/// replay logs it as failed and deletes it.
fn corrupt_held_row(c: &Core, fp: Fingerprint) {
    c.store
        .conn()
        .execute(
            "INSERT INTO pending_initials
                (packet_id, ik, fp, session_id, message_id, bytes, received_at, invite)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, 0)",
            rusqlite::params![
                vec![0xcc_u8; 16],
                vec![1_u8, 2, 3],
                fp.0.to_vec(),
                vec![0_u8; 16],
                vec![0_u8; 5],
                i64::try_from(NOW).unwrap(),
            ],
        )
        .unwrap();
}

fn replay_failures(c: &Core) -> usize {
    count_events(c, |e| {
        matches!(
            e,
            TransparencyEvent::DecryptFailed { reason, .. } if reason == requests::R_REPLAY_FAILED
        )
    })
}

#[test]
fn failed_replay_does_not_fail_a_committed_receive() {
    let mut p = pair();
    let alice = p.a.fingerprint();
    corrupt_held_row(&p.b, alice);
    let text =
        p.a.send_text(&p.b.fingerprint(), "ok", NOW, &mut p.rng)
            .unwrap();
    let got =
        p.b.receive(&text[0].encode(), "t", NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(got, ReceiveOutcome::Message { .. }), "{got:?}");
    assert!(texts_with(&p.b, alice, NOW).contains(&"ok".to_owned()));
    assert_eq!(replay_failures(&p.b), 1);
}

#[test]
fn failed_replay_does_not_fail_a_committed_add() {
    let (_da, a, _db, mut b, mut rng) = alice_knows_bob();
    let alice = a.fingerprint();
    corrupt_held_row(&b, alice);
    let added = b
        .add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    assert_eq!(added, alice);
    assert!(b.store.get_contact(alice).unwrap().is_some());
    assert_eq!(replay_failures(&b), 1);
}

#[test]
fn block_contact_on_a_requester_closes_the_request() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    b.block_contact(&alice, NOW + 1, &mut rng).unwrap();
    assert!(b.store.block_state(alice).unwrap().blocked);
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(
        count_events(&b, |e| matches!(
            e,
            TransparencyEvent::ContactRequestResolved {
                how: RequestResolution::Blocked,
                ..
            }
        )),
        1
    );
    // Still refused for a fingerprint that is neither a contact nor a
    // requester.
    assert!(matches!(
        b.block_contact(&Fingerprint([9; 32]), NOW + 2, &mut rng),
        Err(CoreError::UnknownContact)
    ));
}

#[test]
fn acceptance_learned_from_an_ack_survives_a_resend() {
    // Bob already knew Alice: he acks her invite without writing, so her
    // session with him still waits for a first answer.
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let bob = b.fingerprint();
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let at = NOW + 60;
    b.receive(&invite.encode(), "t", at, &mut rng).unwrap();
    let acks = acks_of(&mut b, at);
    a.receive(&acks[0].encode(), "t", at + 60, &mut rng)
        .unwrap();
    assert_eq!(
        a.invite_state(&bob, at + 60).unwrap(),
        InviteState::Accepted { at: at + 60 }
    );
    let later = NOW + 86_400;
    a.invite(&bob, later, &mut rng).unwrap();
    assert_eq!(
        a.invite_state(&bob, later).unwrap(),
        InviteState::Accepted { at: at + 60 }
    );
}

// --- Contact requests, fix pass 2: unreadable held rows.

/// A row of the queue of unknown senders with the identity key `ik` that
/// cannot be read back (`session_id` of 3 bytes), its content read
/// (`message_id` set).
fn corrupt_queued_row(c: &Core, ik: [u8; 32]) {
    c.store
        .conn()
        .execute(
            "INSERT INTO pending_initials
                (packet_id, ik, fp, session_id, message_id, bytes, received_at, invite)
             VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, 0)",
            rusqlite::params![
                vec![0xdd_u8; 16],
                ik.to_vec(),
                vec![1_u8, 2, 3],
                vec![0xee_u8; 16],
                vec![0_u8; 5],
                i64::try_from(NOW).unwrap(),
            ],
        )
        .unwrap();
}

/// Bob holds a request of Alice with unreadable rows: one held for her
/// fingerprint, one queued under her device key.
fn bob_with_unreadable_rows() -> (TempDir, Core, TempDir, Core, StdRng) {
    let (da, a, db, b, rng) = bob_with_request(NOW);
    corrupt_held_row(&b, a.fingerprint());
    corrupt_queued_row(&b, a.device.public().dh);
    (da, a, db, b, rng)
}

const REQUEST_EXPIRED: u64 = NOW + requests::REQUEST_RETENTION_SECS + 1;

#[test]
fn open_closes_an_expired_request_with_unreadable_rows() {
    let (_da, _a, db, b, _rng) = bob_with_unreadable_rows();
    drop(b);
    let b = Core::open(&db.path().join("db"), &[2; 32], REQUEST_EXPIRED).unwrap();
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn polling_closes_an_expired_request_with_unreadable_rows() {
    let (_da, _a, _db, mut b, _rng) = bob_with_unreadable_rows();
    b.mark_polled(REQUEST_EXPIRED).unwrap();
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn refuse_closes_a_request_with_unreadable_rows() {
    let (_da, a, _db, mut b, mut rng) = bob_with_unreadable_rows();
    b.refuse_request(&a.fingerprint(), NOW + 1, &mut rng)
        .unwrap();
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn block_closes_a_request_with_unreadable_rows() {
    let (_da, a, _db, mut b, mut rng) = bob_with_unreadable_rows();
    b.block_request(&a.fingerprint(), NOW + 1, &mut rng)
        .unwrap();
    assert!(b.requests().unwrap().is_empty());
    assert_eq!(count_table(&b, "pending_initials"), 0);
}

#[test]
fn blocked_sender_invitation_drops_an_unreadable_queued_row() {
    let (_da, mut a, _db, mut b, mut rng) = alice_knows_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW, &mut rng)
        .unwrap();
    b.block_contact(&alice, NOW, &mut rng).unwrap();
    b.remove_contact(&alice, NOW, &mut rng).unwrap();
    corrupt_queued_row(&b, a.device.public().dh);
    let invite = invite_one(&mut a, bob, NOW, &mut rng);
    let got = b.receive(&invite.encode(), "t", NOW, &mut rng).unwrap();
    assert!(matches!(got, ReceiveOutcome::Ignored), "{got:?}");
    assert_eq!(requests::count_unknown(&b.store).unwrap(), 0);
}

#[test]
fn accept_skips_an_unreadable_row_and_replays_the_next() {
    // The genuine packets arrive after the unreadable row (held at NOW).
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW + 1);
    let alice = a.fingerprint();
    corrupt_held_row(&b, alice);
    let accepted = b.accept_request(&alice, None, NOW + 2, &mut rng).unwrap();
    assert_eq!(replayed_texts(&accepted.replayed), ["un", "deux"]);
    assert_eq!(texts_with(&b, alice, NOW + 2), ["un", "deux"]);
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(replay_failures(&b), 1);
}

#[test]
fn committed_replay_skips_an_unreadable_row_and_replays_the_next() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW + 1);
    let alice = a.fingerprint();
    corrupt_held_row(&b, alice);
    b.add_contact(&a.contact_card("Alice").unwrap(), None, NOW + 2, &mut rng)
        .unwrap();
    assert_eq!(texts_with(&b, alice, NOW + 2), ["un", "deux"]);
    assert_eq!(count_table(&b, "pending_initials"), 0);
    assert_eq!(replay_failures(&b), 1);
}

// --- Contact requests, fix pass 2: late-ack cutoff from the sending time.

/// Rewrites the header expiry of every packet held for `fp` to `u32::MAX`,
/// as a malicious node could serve them (not covered by the packet id nor
/// the AEAD).
fn rewrite_held_expiry(c: &Core, fp: Fingerprint) {
    for held in requests::list_pending_by_fp(&c.store, fp).unwrap() {
        let mut packet = Packet::decode(&held.bytes).unwrap();
        packet.expires_at = u32::MAX;
        c.store
            .conn()
            .execute(
                "UPDATE pending_initials SET bytes = ?2 WHERE packet_id = ?1",
                rusqlite::params![held.packet_id.0.to_vec(), packet.encode()],
            )
            .unwrap();
    }
}

#[test]
fn accept_on_day_20_ignores_a_rewritten_header_expiry() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    rewrite_held_expiry(&b, alice);
    let day_20 = NOW + 20 * 86_400;
    let accepted = b.accept_request(&alice, None, day_20, &mut rng).unwrap();
    assert_eq!(replayed_texts(&accepted.replayed), ["un", "deux"]);
    assert_eq!(outbox_of(&mut b, Kind::Ack, day_20), 0);
    assert_eq!(
        count_events(&b, |e| matches!(e, TransparencyEvent::AckEmitted { .. })),
        0
    );
}

#[test]
fn accept_within_grace_acks_despite_a_rewritten_header_expiry() {
    let (_da, a, _db, mut b, mut rng) = bob_with_request(NOW);
    let alice = a.fingerprint();
    rewrite_held_expiry(&b, alice);
    let later = NOW + 3_600;
    b.accept_request(&alice, None, later, &mut rng).unwrap();
    assert_eq!(outbox_of(&mut b, Kind::Ack, later), 3);
}

// Contact avatars: a register synchronized between my devices (last writer
// wins), copied by a link, never logged nor sent to the contact.

use crate::core::{ContactAvatar, MAX_AVATAR_PHOTO_LEN};
use crate::store::{AvatarKind, AvatarRegister};

/// A tiny byte string that starts like a JPEG (SOI marker).
fn jpeg(len: usize) -> Vec<u8> {
    let mut v = vec![0xAB; len];
    v[0] = 0xFF;
    v[1] = 0xD8;
    v
}

fn dog() -> ContactAvatar {
    ContactAvatar::Emoji("\u{1F436}".into())
}

fn cat() -> ContactAvatar {
    ContactAvatar::Emoji("\u{1F431}".into())
}

fn avatar_of(core: &Core, fp: &Fingerprint) -> Option<ContactAvatar> {
    core.contact_avatars()
        .unwrap()
        .into_iter()
        .find(|(f, _)| f == fp)
        .map(|(_, a)| a)
}

fn outbox_count(core: &Core) -> i64 {
    core.store
        .conn()
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap()
}

/// Deliveries addressed to a contact (not to one of my devices).
fn contact_deliveries(core: &Core) -> i64 {
    core.store
        .conn()
        .query_row("SELECT count(*) FROM deliveries WHERE own = 0", [], |r| {
            r.get(0)
        })
        .unwrap()
}

/// A (admin) linked to T, both knowing Bob (added on A, synchronized).
fn linked_with_bob() -> (TempDir, TempDir, Core, Core, Fingerprint, StdRng) {
    let (d, mut a, mut t, mut rng) = linked();
    let (db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert!(t.resolve("bob").is_ok());
    (d, db, a, t, fp, rng)
}

/// The packets `c` queued since `before` (a previous `pending_outbox`).
fn queued_since(c: &mut Core, before: &[Vec<u8>]) -> Vec<Vec<u8>> {
    c.pending_outbox(NOW + 9)
        .unwrap()
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect()
}

fn deliver_bytes(to: &mut Core, packets: &[Vec<u8>], rng: &mut StdRng) {
    for p in packets {
        let _ = to.receive(p, "t", NOW + 9, rng);
    }
}

#[test]
fn avatar_emoji_roundtrip() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    assert!(p.a.contact_avatars().unwrap().is_empty());
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
    let avatar = ContactAvatar::Emoji(family.into());
    p.a.set_contact_avatar(&bob, Some(&avatar), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.contact_avatars().unwrap(), vec![(bob, avatar)]);
}

#[test]
fn avatar_photo_roundtrip_and_replace() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    let photo = ContactAvatar::Photo(jpeg(MAX_AVATAR_PHOTO_LEN));
    p.a.set_contact_avatar(&bob, Some(&photo), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(avatar_of(&p.a, &bob), Some(photo));
    p.a.set_contact_avatar(&bob, Some(&dog()), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(p.a.contact_avatars().unwrap(), vec![(bob, dog())]);
}

#[test]
fn avatar_clear() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    // Clearing without an avatar is no error, and writes nothing.
    p.a.set_contact_avatar(&bob, None, NOW, &mut p.rng).unwrap();
    assert_eq!(p.a.store.contact_avatar(bob).unwrap(), None);
    p.a.set_contact_avatar(&bob, Some(&dog()), NOW, &mut p.rng)
        .unwrap();
    p.a.set_contact_avatar(&bob, None, NOW, &mut p.rng).unwrap();
    assert!(p.a.contact_avatars().unwrap().is_empty());
    // A tombstone, dated after the set (same second: one more).
    assert_eq!(
        p.a.store.contact_avatar(bob).unwrap(),
        Some(AvatarRegister {
            at: NOW + 1,
            value: None
        })
    );
}

#[test]
fn avatar_unknown_contact_refused() {
    let mut p = pair();
    assert_eq!(
        p.a.set_contact_avatar(&Fingerprint([7; 32]), Some(&dog()), NOW, &mut p.rng),
        Err(CoreError::UnknownContact)
    );
    assert_eq!(
        p.a.set_contact_avatar(&Fingerprint([7; 32]), None, NOW, &mut p.rng),
        Err(CoreError::UnknownContact)
    );
}

#[test]
fn avatar_photo_refused_when_oversize_or_not_jpeg() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    p.a.set_contact_avatar(&bob, Some(&dog()), NOW, &mut p.rng)
        .unwrap();
    assert_eq!(MAX_AVATAR_PHOTO_LEN, 12 * 1024);
    assert_eq!(
        p.a.set_contact_avatar(
            &bob,
            Some(&ContactAvatar::Photo(jpeg(MAX_AVATAR_PHOTO_LEN + 1))),
            NOW,
            &mut p.rng
        ),
        Err(CoreError::TooLarge)
    );
    for bad in [
        Vec::new(),
        vec![0xFF],
        b"\x89PNG\r\n\x1a\n".to_vec(),
        vec![0xD8, 0xFF, 0x00],
    ] {
        assert!(
            matches!(
                p.a.set_contact_avatar(&bob, Some(&ContactAvatar::Photo(bad)), NOW, &mut p.rng),
                Err(CoreError::Malformed(_))
            ),
            "accepted"
        );
    }
    // The previous avatar is kept.
    assert_eq!(avatar_of(&p.a, &bob), Some(dog()));
}

#[test]
fn avatar_emoji_refused_when_empty_too_long_or_control() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    // 16 four-byte emoji: 64 bytes, the limit.
    let max = "\u{1F436}".repeat(16);
    p.a.set_contact_avatar(
        &bob,
        Some(&ContactAvatar::Emoji(max.clone())),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    assert_eq!(
        p.a.set_contact_avatar(
            &bob,
            Some(&ContactAvatar::Emoji(format!("{max}a"))),
            NOW,
            &mut p.rng
        ),
        Err(CoreError::TooLarge)
    );
    for bad in ["", "   ", "\u{1F436}\n", "\u{1F436}\u{7}", "\t"] {
        assert!(
            matches!(
                p.a.set_contact_avatar(
                    &bob,
                    Some(&ContactAvatar::Emoji(bad.into())),
                    NOW,
                    &mut p.rng
                ),
                Err(CoreError::Malformed(_))
            ),
            "{bad:?} accepted"
        );
    }
    assert_eq!(avatar_of(&p.a, &bob), Some(ContactAvatar::Emoji(max)));
}

#[test]
fn avatar_removed_with_contact() {
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    p.a.set_contact_avatar(&bob, Some(&ContactAvatar::Photo(jpeg(10))), NOW, &mut p.rng)
        .unwrap();
    p.a.remove_contact(&bob, NOW, &mut p.rng).unwrap();
    assert!(p.a.contact_avatars().unwrap().is_empty());
    assert_eq!(p.a.store.contact_avatar(bob).unwrap(), None);
    // Added again: no avatar.
    p.a.add_contact(
        &p.b.contact_card("Bob").unwrap(),
        Some("bob"),
        NOW,
        &mut p.rng,
    )
    .unwrap();
    assert!(p.a.contact_avatars().unwrap().is_empty());
}

#[test]
fn avatar_survives_reopen() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let mut rng = StdRng::seed_from_u64(9);
    let (mut a, _) = Core::create(&path, &[9; 32], "a", NOW, &mut rng).unwrap();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    a.set_contact_avatar(&fp, Some(&ContactAvatar::Photo(jpeg(100))), NOW, &mut rng)
        .unwrap();
    drop(a);
    let a = Core::open(&path, &[9; 32], NOW).unwrap();
    assert_eq!(avatar_of(&a, &fp), Some(ContactAvatar::Photo(jpeg(100))));
}

#[test]
fn avatar_alone_neither_logged_nor_queued() {
    // Without another device of mine: nothing to synchronize.
    let mut p = pair();
    let bob = p.a.resolve("bob").unwrap();
    let events = p.a.store.recent_events(10_000).unwrap().len();
    let queued = outbox_count(&p.a);
    p.a.set_contact_avatar(&bob, Some(&dog()), NOW, &mut p.rng)
        .unwrap();
    p.a.set_contact_avatar(&bob, None, NOW, &mut p.rng).unwrap();
    assert_eq!(p.a.store.recent_events(10_000).unwrap().len(), events);
    assert_eq!(outbox_count(&p.a), queued);
}

#[test]
fn avatar_never_sent_to_the_contact() {
    let (_d, _db, mut a, _t, fp, mut rng) = linked_with_bob();
    let to_contacts = contact_deliveries(&a);
    let queued = outbox_count(&a);
    a.set_contact_avatar(&fp, Some(&ContactAvatar::Photo(jpeg(50))), NOW, &mut rng)
        .unwrap();
    // One copy, for T only.
    assert_eq!(outbox_count(&a), queued + 1);
    assert_eq!(contact_deliveries(&a), to_contacts);
}

#[test]
fn avatar_emoji_synchronized_to_linked_device() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(t.contact_avatars().unwrap(), vec![(fp, dog())]);
    // The other way too.
    t.set_contact_avatar(&fp, Some(&cat()), NOW + 2, &mut rng)
        .unwrap();
    deliver_all(&mut t, &mut a, &mut rng);
    assert_eq!(a.contact_avatars().unwrap(), vec![(fp, cat())]);
}

#[test]
fn avatar_max_photo_synchronized_to_linked_device() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    let photo = ContactAvatar::Photo(jpeg(MAX_AVATAR_PHOTO_LEN));
    a.set_contact_avatar(&fp, Some(&photo), NOW + 1, &mut rng)
        .unwrap();
    // Sealed, not skipped for its size.
    let skipped = a
        .transparency_log(1_000)
        .unwrap()
        .into_iter()
        .any(|(_, e)| matches!(e, TransparencyEvent::SyncSkipped { .. }));
    assert!(!skipped);
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(avatar_of(&t, &fp), Some(photo));
    assert_eq!(
        t.store.contact_avatar(fp).unwrap().map(|r| r.at),
        a.store.contact_avatar(fp).unwrap().map(|r| r.at)
    );
}

#[test]
fn avatar_clear_synchronized() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(avatar_of(&t, &fp), Some(dog()));
    a.set_contact_avatar(&fp, None, NOW + 2, &mut rng).unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert!(t.contact_avatars().unwrap().is_empty());
    assert_eq!(
        t.store.contact_avatar(fp).unwrap(),
        Some(AvatarRegister {
            at: NOW + 2,
            value: None
        })
    );
}

#[test]
fn avatar_older_op_arriving_late_is_ignored() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    let before = a.pending_outbox(NOW + 9).unwrap();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 5, &mut rng)
        .unwrap();
    let old = queued_since(&mut a, &before);
    let mut seen = before.clone();
    seen.extend(old.iter().cloned());
    a.set_contact_avatar(&fp, Some(&cat()), NOW + 10, &mut rng)
        .unwrap();
    let new = queued_since(&mut a, &seen);
    assert_eq!((old.len(), new.len()), (1, 1));
    // The newer op first, then the older one: the newer stays.
    deliver_bytes(&mut t, &new, &mut rng);
    deliver_bytes(&mut t, &old, &mut rng);
    assert_eq!(avatar_of(&t, &fp), Some(cat()));
    // A clear is a tombstone: an older set arriving after it stays out.
    let mut seen = a.pending_outbox(NOW + 9).unwrap();
    a.set_contact_avatar(&fp, None, NOW + 20, &mut rng).unwrap();
    let clear = queued_since(&mut a, &seen);
    seen.extend(clear.iter().cloned());
    deliver_bytes(&mut t, &clear, &mut rng);
    deliver_bytes(&mut t, &new, &mut rng);
    assert!(t.contact_avatars().unwrap().is_empty());
}

#[test]
fn avatar_concurrent_changes_converge() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    // T's change is older than A's: A's wins on both.
    t.set_contact_avatar(&fp, Some(&cat()), NOW + 7, &mut rng)
        .unwrap();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 10, &mut rng)
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    deliver_all(&mut t, &mut a, &mut rng);
    assert_eq!(avatar_of(&a, &fp), Some(dog()));
    assert_eq!(avatar_of(&t, &fp), Some(dog()));
    // Same date on both: the same value wins on both.
    a.set_contact_avatar(&fp, Some(&cat()), NOW + 20, &mut rng)
        .unwrap();
    t.set_contact_avatar(
        &fp,
        Some(&ContactAvatar::Photo(jpeg(40))),
        NOW + 20,
        &mut rng,
    )
    .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    deliver_all(&mut t, &mut a, &mut rng);
    assert_eq!(avatar_of(&a, &fp), avatar_of(&t, &fp));
    assert_eq!(avatar_of(&a, &fp), Some(ContactAvatar::Photo(jpeg(40))));
}

#[test]
fn avatar_op_before_contact_shows_once_contact_arrives() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let before = a.pending_outbox(NOW + 9).unwrap();
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let contact = queued_since(&mut a, &before);
    let mut seen = before.clone();
    seen.extend(contact.iter().cloned());
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    let avatar = queued_since(&mut a, &seen);
    deliver_bytes(&mut t, &avatar, &mut rng);
    // Kept, not shown: no such contact yet.
    assert!(t.contact_avatars().unwrap().is_empty());
    assert!(t.store.contact_avatar(fp).unwrap().is_some());
    deliver_bytes(&mut t, &contact, &mut rng);
    assert!(t.resolve("bob").is_ok());
    assert_eq!(t.contact_avatars().unwrap(), vec![(fp, dog())]);
}

#[test]
fn avatar_removed_on_both_devices_with_the_contact() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(avatar_of(&t, &fp), Some(dog()));
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(t.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(a.contact_avatars().unwrap().is_empty());
    assert!(t.contact_avatars().unwrap().is_empty());
    assert_eq!(t.store.contact_avatar(fp).unwrap(), None);
}

#[test]
fn avatar_set_before_a_removal_arriving_after_it_stays_out() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    let before = a.pending_outbox(NOW + 9).unwrap();
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    let set = queued_since(&mut a, &before);
    let mut seen = before.clone();
    seen.extend(set.iter().cloned());
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    let removal = queued_since(&mut a, &seen);
    // The removal first, then the older set: no orphan left behind, so
    // adding the contact again on T shows no avatar.
    deliver_bytes(&mut t, &removal, &mut rng);
    assert_eq!(t.resolve("bob"), Err(CoreError::UnknownContact));
    deliver_bytes(&mut t, &set, &mut rng);
    assert_eq!(t.store.contact_avatar(fp).unwrap(), None);
}

#[test]
fn avatar_received_before_the_contact_goes_with_its_removal() {
    let (_d, mut a, mut t, mut rng) = linked();
    let (_db, bob) = party("bob", 5);
    let before = a.pending_outbox(NOW + 9).unwrap();
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    let contact = queued_since(&mut a, &before);
    let mut seen = before.clone();
    seen.extend(contact.iter().cloned());
    a.set_contact_avatar(&fp, Some(&dog()), NOW + 1, &mut rng)
        .unwrap();
    let avatar = queued_since(&mut a, &seen);
    seen.extend(avatar.iter().cloned());
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    let removal = queued_since(&mut a, &seen);
    // T never sees the contact: the avatar, then the removal.
    deliver_bytes(&mut t, &avatar, &mut rng);
    assert!(t.store.contact_avatar(fp).unwrap().is_some());
    deliver_bytes(&mut t, &removal, &mut rng);
    assert_eq!(t.store.contact_avatar(fp).unwrap(), None);
    // The late Upsert (older than the removal) changes nothing.
    deliver_bytes(&mut t, &contact, &mut rng);
    assert_eq!(t.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(t.contact_avatars().unwrap().is_empty());
}

#[test]
fn avatar_removed_when_contact_removed_by_sync() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    t.set_contact_avatar(&fp, Some(&dog()), NOW, &mut rng)
        .unwrap();
    a.remove_contact(&fp, NOW + 5, &mut rng).unwrap();
    deliver_all(&mut a, &mut t, &mut rng);
    assert_eq!(t.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(t.contact_avatars().unwrap().is_empty());
}

#[test]
fn avatar_copied_to_a_newly_linked_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(77);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let mut fps = Vec::new();
    for (i, name) in ["bob", "carol", "dan"].iter().enumerate() {
        let (_dc, c) = party(name, 10 + i as u8);
        fps.push(
            a.add_contact(&c.contact_card(name).unwrap(), Some(name), NOW, &mut rng)
                .unwrap(),
        );
    }
    let photo = ContactAvatar::Photo(jpeg(MAX_AVATAR_PHOTO_LEN));
    a.set_contact_avatar(&fps[0], Some(&photo), NOW + 1, &mut rng)
        .unwrap();
    a.set_contact_avatar(&fps[1], Some(&dog()), NOW + 2, &mut rng)
        .unwrap();
    a.set_contact_avatar(&fps[2], Some(&cat()), NOW + 3, &mut rng)
        .unwrap();
    a.set_contact_avatar(&fps[2], None, NOW + 4, &mut rng)
        .unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW + 5, &mut rng).unwrap();
    t.finish_link(&out.bundle, None, NOW + 5).unwrap();
    // On T as soon as the link is finished, with A's dates.
    let mut want = vec![(fps[0], photo), (fps[1], dog())];
    want.sort_by_key(|(fp, _)| fp.0);
    assert_eq!(t.contact_avatars().unwrap(), want);
    for fp in &fps {
        assert_eq!(
            t.store.contact_avatar(*fp).unwrap(),
            a.store.contact_avatar(*fp).unwrap()
        );
    }
}

#[test]
fn max_avatar_op_fits_one_packet() {
    let op = |len: usize| {
        Body::SyncContact(SyncOp::Avatar {
            contact: Fingerprint([0xFF; 32]),
            avatar: Some(ContactAvatar::Photo(jpeg(len))),
            at: u64::MAX,
        })
    };
    assert!(crate::envelope::fits_in_packet(&op(MAX_AVATAR_PHOTO_LEN)));
    // With margin: the limit is not the edge.
    assert!(crate::envelope::fits_in_packet(&op(
        MAX_AVATAR_PHOTO_LEN + 1024
    )));
    assert!(!crate::envelope::fits_in_packet(&op(16 * 1024)));
}

#[test]
fn legacy_oversize_avatar_kept_locally_but_not_synchronized() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(77);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    let (_db, bob) = party("bob", 5);
    let fp = a
        .add_contact(
            &bob.contact_card("Bob").unwrap(),
            Some("bob"),
            NOW,
            &mut rng,
        )
        .unwrap();
    // Stored by the local-only build (64 KiB limit), migrated with date 0.
    let legacy = jpeg(64 * 1024);
    a.store
        .put_contact_avatar(fp, Some((AvatarKind::Photo, &legacy)), 0)
        .unwrap();
    assert_eq!(
        avatar_of(&a, &fp),
        Some(ContactAvatar::Photo(legacy.clone()))
    );
    // The link neither fails nor copies it.
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) =
        Core::begin_link(&dir.path().join("t"), &[2; 32], &offer, "t", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    t.finish_link(&out.bundle, None, NOW).unwrap();
    assert!(t.contact_avatars().unwrap().is_empty());
    assert_eq!(t.store.contact_avatar(fp).unwrap(), None);
    // Nor does a sync of it: nothing queued, no error.
    let queued = outbox_count(&a);
    let Core { store, device, .. } = &mut a;
    store
        .transaction(|tx| {
            sync::send_avatar(
                tx,
                device,
                fp,
                Some(&ContactAvatar::Photo(legacy.clone())),
                1,
                send::SealTime::at(NOW),
                &mut rng,
            )
        })
        .unwrap();
    assert_eq!(outbox_count(&a), queued);
    // Still shown here.
    assert_eq!(avatar_of(&a, &fp), Some(ContactAvatar::Photo(legacy)));
}

#[test]
fn invalid_avatar_op_from_my_device_refused() {
    let (_d, _db, mut a, mut t, fp, mut rng) = linked_with_bob();
    a.set_contact_avatar(&fp, Some(&dog()), NOW, &mut rng)
        .unwrap();
    for (i, avatar) in [
        ContactAvatar::Photo(jpeg(MAX_AVATAR_PHOTO_LEN + 1)),
        ContactAvatar::Photo(vec![1, 2, 3]),
        ContactAvatar::Emoji("\n".into()),
    ]
    .into_iter()
    .enumerate()
    {
        let body = Body::SyncContact(SyncOp::Avatar {
            contact: fp,
            avatar: Some(avatar),
            at: NOW + 100,
        });
        let id = MessageId([i as u8 + 50; 16]);
        let out = seal_body(&mut t, &send::Target::OwnDevices, &body, id, &mut rng);
        let r = a.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
        assert_eq!(reason(r), "synchronization refused", "case {i}");
    }
    assert_eq!(avatar_of(&a, &fp), Some(dog()));
}

// --- GIF, task 2: send, receive and store.

use crate::gif::GifRef;

fn hello_gif() -> GifRef {
    GifRef {
        provider: 1,
        id: "hello-hi-662".into(),
        width: 480,
        height: 270,
    }
}

/// The newest row of the conversation with `contact`, shown at `NOW`.
fn last_row(c: &Core, contact: &Fingerprint) -> crate::store::MessageRow {
    c.messages_with(contact, NOW).unwrap().pop().unwrap()
}

/// Rows of the conversation with `contact` that carry a GIF.
fn gif_rows(c: &Core, contact: &Fingerprint) -> usize {
    c.messages_with(contact, NOW)
        .unwrap()
        .iter()
        .filter(|m| m.gif.is_some())
        .count()
}

#[test]
fn gif_send_receive_round_trip() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let out =
        p.a.send_gif(&b, hello_gif(), None, None, NOW, &mut p.rng)
            .unwrap();
    assert_eq!(out.len(), 1);
    let mine = last_row(&p.a, &b);
    assert_eq!(mine.direction, Direction::Out);
    assert_eq!(mine.gif, Some(hello_gif()));
    assert_eq!(mine.body, "");
    assert!(!mine.placeholder);
    // The contact reads a GIF kind, never a text.
    assert!(matches!(
        peek_envelope(&p.b, &out[0]).body,
        Body::Ext {
            kind: crate::content::KIND_GIF,
            ..
        }
    ));
    let r = deliver(&mut p.b, &out[0], &mut p.rng);
    assert!(
        matches!(
            &r,
            ReceiveOutcome::Message {
                text,
                ephemeral: false,
                ..
            } if text == "GIF"
        ),
        "{r:?}"
    );
    let got = last_row(&p.b, &a);
    assert_eq!(got.direction, Direction::In);
    assert_eq!(got.gif, Some(hello_gif()));
    assert_eq!(got.body, "");
    assert!(!got.placeholder);
    assert!(got.wire_id.is_some());
    // Only the sender counts a send; receiving counts nothing.
    let day = |sent| {
        [GifUsageDay {
            day: (NOW / 86_400) as u32,
            searches: 0,
            shown: 0,
            sent,
            previews: 0,
        }]
    };
    assert_eq!(p.a.gif_usage(7).unwrap(), day(1));
    assert!(p.b.gif_usage(7).unwrap().is_empty());
    // A repeat adds nothing and shows as a stored message.
    assert!(matches!(
        deliver(&mut p.b, &out[0], &mut p.rng),
        ReceiveOutcome::DuplicateMessage
    ));
    assert_eq!(gif_rows(&p.b, &a), 1);
}

#[test]
fn gif_copy_reaches_my_other_device() {
    let (_d, mut a, mut t, mut b, _v1, mut rng) = alice_tablet_bob();
    let (alice, bob) = (a.fingerprint(), b.fingerprint());
    let first = b.send_text(&alice, "q", NOW, &mut rng).unwrap();
    deliver_each(&first, &mut [&mut a, &mut t], &mut rng);
    let sent = a
        .send_gif(&bob, hello_gif(), None, None, NOW, &mut rng)
        .unwrap();
    assert_eq!(sent.len(), 2, "one for Bob, one copy for the tablet");
    let got = t.receive(&sent[1].encode(), "t", NOW, &mut rng).unwrap();
    assert!(
        matches!(
            got,
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                contact: Some(c)
            } if c == bob
        ),
        "{got:?}"
    );
    let row = last_row(&t, &bob);
    let mine = last_row(&a, &bob);
    assert_eq!(row.direction, Direction::Out);
    assert_eq!(row.gif, Some(hello_gif()));
    assert_eq!(row.body, "");
    assert_eq!(row.message_id, mine.message_id);
    assert_eq!(row.at, NOW);
    assert!(matches!(
        deliver(&mut b, &sent[0], &mut rng),
        ReceiveOutcome::Message { .. }
    ));
    assert_eq!(last_row(&b, &alice).gif, Some(hello_gif()));
}

#[test]
fn gif_ephemeral_copy_is_seen_on_my_other_device() {
    let (_d, mut a, mut t, b, _v1, mut rng) = alice_tablet_bob();
    let bob = b.fingerprint();
    let sent = a
        .send_gif(&bob, hello_gif(), None, Some(300), NOW, &mut rng)
        .unwrap();
    assert_eq!(
        sent.len(),
        3,
        "one for Bob, one copy and its \"seen\" for the tablet"
    );
    let mine = last_row(&a, &bob);
    assert_eq!(
        (mine.ttl_secs, mine.seen_at, mine.expire_at),
        (Some(300), Some(NOW), Some(NOW + 300))
    );
    let r = NOW + 9;
    t.receive(&sent[1].encode(), "t", r, &mut rng).unwrap();
    let row = last_row(&t, &bob);
    assert_eq!(row.gif, Some(hello_gif()));
    assert_eq!(
        (row.ttl_secs, row.seen_at, row.expire_at),
        (Some(300), None, Some(r + UNSEEN_CEILING_SECS))
    );
}

#[test]
fn gif_unknown_provider_is_kept() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let other = GifRef {
        provider: 2,
        id: "x".into(),
        width: 1,
        height: 1,
    };
    let out =
        p.a.send_gif(&b, other.clone(), None, None, NOW, &mut p.rng)
            .unwrap();
    assert!(matches!(
        deliver(&mut p.b, &out[0], &mut p.rng),
        ReceiveOutcome::Message { .. }
    ));
    let got = last_row(&p.b, &a);
    assert_eq!(got.gif.as_ref().map(|g| g.provider), Some(2));
    assert_eq!(got.gif, Some(other));
    assert!(!got.placeholder);
}

#[test]
fn gif_invalid_reference_is_refused_on_send() {
    let mut p = pair();
    let b = p.b.fingerprint();
    for gif in [
        GifRef {
            provider: 0,
            id: "x".into(),
            width: 1,
            height: 1,
        },
        GifRef {
            provider: 1,
            id: "Not-Klipy".into(),
            width: 1,
            height: 1,
        },
        GifRef {
            provider: 1,
            id: String::new(),
            width: 1,
            height: 1,
        },
    ] {
        assert!(matches!(
            p.a.send_gif(&b, gif, None, None, NOW, &mut p.rng),
            Err(CoreError::Malformed(_))
        ));
    }
    assert!(matches!(
        p.a.send_gif(&b, hello_gif(), None, Some(1), NOW, &mut p.rng),
        Err(CoreError::InvalidTtl)
    ));
    assert_eq!(gif_rows(&p.a, &b), 0);
}

#[test]
fn sync_gif_from_contact_is_rejected() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let b = p.b.fingerprint();
    let body = ExtContent::SyncGif {
        to: a,
        gif: hello_gif(),
        reply_to: None,
        ttl_secs: None,
    }
    .to_body();
    let out = seal_body(
        &mut p.b,
        &send::Target::Contact(a),
        &body,
        MessageId([0x70; 16]),
        &mut p.rng,
    );
    assert_eq!(reason(deliver(&mut p.a, &out[0].0, &mut p.rng)), NOT_MINE);
    assert_eq!(gif_rows(&p.a, &b), 0);

    // A `Gif` from one of my own devices is not a copy: refused too.
    let (_d, mut a, mut t, mut rng) = linked();
    let body = ExtContent::Gif {
        gif: hello_gif(),
        reply_to: None,
        ttl_secs: None,
    }
    .to_body();
    let out = seal_body(
        &mut a,
        &send::Target::OwnDevices,
        &body,
        MessageId([0x71; 16]),
        &mut rng,
    );
    let r = t.receive(&out[0].0.encode(), "t", NOW, &mut rng).unwrap();
    assert_eq!(reason(r), "unexpected content for this mailbox");
}

#[test]
fn gif_from_blocked_contact_is_dropped() {
    let mut p = pair();
    let a = p.a.fingerprint();
    let bob = p.a.resolve("bob").unwrap();
    let out =
        p.b.send_gif(&a, hello_gif(), None, None, NOW, &mut p.rng)
            .unwrap();
    p.a.block_contact(&bob, NOW, &mut p.rng).unwrap();
    let r = p.a.receive(&out[0].encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(r), "blocked contact");
    assert_eq!(acks_for(&mut p.a, &out[0]), 0);
    assert_eq!(gif_rows(&p.a, &bob), 0);
}

#[test]
fn gif_reply_and_ttl_preserved() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let pk = p.a.send_text(&b, "18 h ?", NOW, &mut p.rng).unwrap();
    deliver(&mut p.b, &pk[0], &mut p.rng);
    let quoted = full_row(&p.b, &a, "18 h ?");
    let out =
        p.b.send_gif(&a, hello_gif(), Some(quoted.id), Some(300), NOW, &mut p.rng)
            .unwrap();
    let mine = last_row(&p.b, &a);
    assert_eq!(mine.reply_to, Some(quoted.message_id));
    assert_eq!(
        mine.reply_ref,
        Some(MessageRef {
            id: quoted.wire_id.unwrap(),
            by_sender: false
        })
    );
    assert_eq!(
        (mine.ttl_secs, mine.seen_at, mine.expire_at),
        (Some(300), Some(NOW), Some(NOW + 300))
    );
    let r = deliver(&mut p.a, &out[0], &mut p.rng);
    assert!(
        matches!(
            r,
            ReceiveOutcome::Message {
                ephemeral: true,
                ..
            }
        ),
        "{r:?}"
    );
    let original = full_row(&p.a, &b, "18 h ?");
    let got = last_row(&p.a, &b);
    assert_eq!(got.gif, Some(hello_gif()));
    assert_eq!(got.reply_to, Some(original.message_id));
    assert_eq!(got.reply_ref, mine.reply_ref);
    assert_eq!(
        (got.ttl_secs, got.seen_at, got.expire_at),
        (Some(300), None, Some(NOW + UNSEEN_CEILING_SECS))
    );
    // A text replying to the GIF resolves its quote on both sides.
    let back =
        p.a.send_message(&b, "yes", Some(got.id), None, NOW, &mut p.rng)
            .unwrap();
    assert_eq!(full_row(&p.a, &b, "yes").reply_to, Some(got.message_id));
    deliver(&mut p.b, &back[0], &mut p.rng);
    assert_eq!(full_row(&p.b, &a, "yes").reply_to, Some(mine.message_id));
    // A missing quote writes nothing.
    assert!(matches!(
        p.b.send_gif(&a, hello_gif(), Some(i64::MAX), None, NOW, &mut p.rng),
        Err(CoreError::MessageNotFound)
    ));
}

#[test]
fn gif_retry_sends_the_gif_again() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let sent =
        p.a.send_gif(&b, hello_gif(), None, None, NOW, &mut p.rng)
            .unwrap();
    let row = last_row(&p.a, &b);
    let late = NOW + 4;
    assert!(p.a.drop_outbox_packet(&sent[0].encode(), late).unwrap());
    assert_eq!(last_row(&p.a, &b).status, MessageStatus::NotDelivered);
    let again = p.a.retry_message(row.id, late, &mut p.rng).unwrap();
    assert!(matches!(
        peek_envelope(&p.b, &again[0]).body,
        Body::Ext {
            kind: crate::content::KIND_GIF,
            ..
        }
    ));
    p.b.receive(&again[0].encode(), "t", late, &mut p.rng)
        .unwrap();
    let got = last_row(&p.b, &a);
    assert_eq!(got.gif, Some(hello_gif()));
    assert_eq!(got.body, "");
}

#[test]
fn gif_survives_history_export() {
    let mut p = pair();
    let (a, b) = (p.a.fingerprint(), p.b.fingerprint());
    let out =
        p.b.send_gif(&a, hello_gif(), None, None, NOW, &mut p.rng)
            .unwrap();
    deliver(&mut p.a, &out[0], &mut p.rng);
    p.a.send_gif(&b, hello_gif(), None, None, NOW, &mut p.rng)
        .unwrap();
    let contacts = std::collections::HashSet::from([b]);
    let history = history::export(&p.a.store, &contacts).unwrap();
    // Through the wire form, as a linked device reads it.
    let bytes = postcard::to_allocvec(&history).unwrap();
    let history: history::History = postcard::from_bytes(&bytes).unwrap();
    let (_dt, t) = party("t", 9);
    assert_eq!(history::import(&t.store, &history).unwrap(), 4);
    let gifs: Vec<_> = t
        .store
        .all_messages()
        .unwrap()
        .into_iter()
        .filter_map(|m| m.gif.map(|g| (m.direction, g)))
        .collect();
    assert_eq!(
        gifs,
        [(Direction::In, hello_gif()), (Direction::Out, hello_gif())]
    );
}

// --- GIF, task 3: consent and synced settings.

/// Delivers every packet queued by `from` to `to` at `now`.
fn deliver_all_at(from: &mut Core, to: &mut Core, now: u64, rng: &mut StdRng) {
    for b in from.pending_outbox(now).unwrap() {
        to.receive(&b, "t", now, rng)
            .expect("a queued packet is delivered");
    }
}

/// A consent with every field set.
fn consent(device: DeviceId, at: u64) -> crate::gif::GifConsent {
    crate::gif::GifConsent {
        warning_version: 1,
        device,
        at,
    }
}

#[test]
fn gif_disabled_by_default() {
    let (_d, a) = party("a", 1);
    let s = a.gif_settings().unwrap();
    assert!(s.enabled.is_empty());
    assert!(!s.auto_load);
    assert!(!a.gif_allowed(1).unwrap());
}

#[test]
fn enable_records_device_and_date() {
    let (_d, mut a) = party("a", 1);
    let mut rng = StdRng::seed_from_u64(1);
    a.enable_gif_provider(1, 1, 1000, &mut rng).unwrap();
    let s = a.gif_settings().unwrap();
    assert_eq!(s.enabled.get(&1), Some(&consent(this_device(&a), 1000)));
    assert!(a.gif_allowed(1).unwrap());
    // Provider 0 is refused, and so is a provider this client does not know.
    assert!(matches!(
        a.enable_gif_provider(0, 1, 1001, &mut rng),
        Err(CoreError::Malformed(_))
    ));
    assert!(matches!(
        a.enable_gif_provider(7, 1, 1001, &mut rng),
        Err(CoreError::Malformed(_))
    ));
    a.disable_gif_provider(1, 1002, &mut rng).unwrap();
    assert!(!a.gif_allowed(1).unwrap());
    assert!(a.gif_settings().unwrap().enabled.is_empty());
}

#[test]
fn stale_warning_version_is_not_allowed() {
    let (_d, mut a) = party("a", 1);
    let mut rng = StdRng::seed_from_u64(1);
    a.enable_gif_provider(1, 0, NOW, &mut rng).unwrap();
    assert!(!a.gif_allowed(1).unwrap());
    a.enable_gif_provider(1, crate::gif::MIN_GIF_WARNING_VERSION, NOW + 1, &mut rng)
        .unwrap();
    assert!(a.gif_allowed(1).unwrap());
}

#[test]
fn gif_settings_sync_to_other_device() {
    let (_d, mut a, mut t, mut rng) = linked();
    a.enable_gif_provider(1, 1, NOW + 10, &mut rng).unwrap();
    a.set_gif_auto_load(true, NOW + 11, &mut rng).unwrap();
    deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
    assert!(t.gif_allowed(1).unwrap());
    let s = t.gif_settings().unwrap();
    assert_eq!(s, a.gif_settings().unwrap());
    assert_eq!(s.enabled[&1].device, this_device(&a));
    assert!(s.auto_load);
    // And back: a change on T reaches A.
    t.disable_gif_provider(1, NOW + 40, &mut rng).unwrap();
    deliver_all_at(&mut t, &mut a, NOW + 50, &mut rng);
    assert!(!a.gif_allowed(1).unwrap());
    assert!(a.gif_settings().unwrap().auto_load, "kept when disabled");
}

#[test]
fn gif_settings_last_writer_wins() {
    for a_first in [true, false] {
        let (_d, mut a, mut t, mut rng) = linked();
        a.enable_gif_provider(1, 1, NOW + 10, &mut rng).unwrap();
        // Disabling a provider T never had is still a change, dated later.
        t.disable_gif_provider(1, NOW + 20, &mut rng).unwrap();
        if a_first {
            deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
            deliver_all_at(&mut t, &mut a, NOW + 30, &mut rng);
        } else {
            deliver_all_at(&mut t, &mut a, NOW + 30, &mut rng);
            deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
        }
        assert!(!a.gif_allowed(1).unwrap(), "A, a_first {a_first}");
        assert!(!t.gif_allowed(1).unwrap(), "T, a_first {a_first}");
        assert_eq!(a.gif_settings().unwrap(), t.gif_settings().unwrap());
    }
}

#[test]
fn gif_settings_tie_breaks_on_device_id() {
    let (_d, mut a, mut t, mut rng) = linked();
    a.enable_gif_provider(1, 1, NOW + 10, &mut rng).unwrap();
    t.set_gif_auto_load(true, NOW + 10, &mut rng).unwrap();
    let winner = if this_device(&a) > this_device(&t) {
        a.gif_settings().unwrap()
    } else {
        t.gif_settings().unwrap()
    };
    deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
    deliver_all_at(&mut t, &mut a, NOW + 30, &mut rng);
    assert_eq!(a.gif_settings().unwrap(), winner);
    assert_eq!(t.gif_settings().unwrap(), winner);
}

/// `SyncGifSettings` carrying `settings` dated `at`, sealed by `from` for
/// `target`.
fn gif_settings_packet(
    from: &mut Core,
    target: &send::Target,
    settings: crate::gif::GifSettings,
    at: u64,
    id: u8,
    rng: &mut StdRng,
) -> Packet {
    let body = ExtContent::SyncGifSettings { settings, at }.to_body();
    seal_body(from, target, &body, MessageId([id; 16]), rng)
        .remove(0)
        .0
}

#[test]
fn gif_settings_from_contact_rejected() {
    let mut p = pair();
    let a_fp = p.a.fingerprint();
    let settings = crate::gif::GifSettings {
        enabled: [(1, consent(this_device(&p.b), NOW))].into(),
        auto_load: true,
    };
    let pkt = gif_settings_packet(
        &mut p.b,
        &send::Target::Contact(a_fp),
        settings,
        NOW,
        1,
        &mut p.rng,
    );
    let r = p.a.receive(&pkt.encode(), "t", NOW, &mut p.rng).unwrap();
    assert_eq!(reason(r), NOT_MINE);
    assert_eq!(
        p.a.gif_settings().unwrap(),
        crate::gif::GifSettings::default()
    );
    assert!(!p.a.gif_allowed(1).unwrap());
}

#[test]
fn gif_settings_unknown_provider_kept() {
    let (_d, mut a, mut t, mut rng) = linked();
    let td = this_device(&t);
    let settings = crate::gif::GifSettings {
        enabled: [(1, consent(td, NOW)), (7, consent(td, NOW))].into(),
        auto_load: false,
    };
    let pkt = gif_settings_packet(
        &mut t,
        &send::Target::OwnDevices,
        settings.clone(),
        NOW + 5,
        1,
        &mut rng,
    );
    assert!(matches!(
        a.receive(&pkt.encode(), "t", NOW + 5, &mut rng).unwrap(),
        ReceiveOutcome::Synced {
            kind: SyncKind::GifSettings,
            ..
        }
    ));
    assert_eq!(a.gif_settings().unwrap(), settings);
    assert!(a.gif_allowed(1).unwrap());
    assert!(!a.gif_allowed(7).unwrap());
    // The next change on A sends provider 7 on, untouched.
    a.set_gif_auto_load(true, NOW + 6, &mut rng).unwrap();
    deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
    let got = t.gif_settings().unwrap();
    assert_eq!(got.enabled, settings.enabled);
    assert!(got.auto_load);
}

#[test]
fn newly_linked_device_gets_gif_settings() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(77);
    let (mut a, _) = Core::create(&dir.path().join("a"), &[1; 32], "a", NOW, &mut rng).unwrap();
    a.enable_gif_provider(1, 1, NOW, &mut rng).unwrap();
    let offer = a.link_offer(NOW, &mut rng).unwrap();
    let (mut c, req) =
        Core::begin_link(&dir.path().join("c"), &[2; 32], &offer, "c", NOW, &mut rng).unwrap();
    let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
    c.finish_link(&out.bundle, None, NOW).unwrap();
    assert!(!c.gif_allowed(1).unwrap());
    deliver_all_at(&mut a, &mut c, NOW + 1, &mut rng);
    assert!(c.gif_allowed(1).unwrap());
    assert_eq!(c.gif_settings().unwrap(), a.gif_settings().unwrap());
}

#[test]
fn gif_consent_is_logged() {
    let (_d, mut a, mut t, mut rng) = linked();
    let consent_event = |enabled, remote| TransparencyEvent::GifConsent {
        provider: 1,
        enabled,
        remote,
    };
    a.enable_gif_provider(1, 1, NOW + 10, &mut rng).unwrap();
    assert_eq!(count_events(&a, |e| *e == consent_event(true, false)), 1);
    deliver_all_at(&mut a, &mut t, NOW + 30, &mut rng);
    assert_eq!(count_events(&t, |e| *e == consent_event(true, true)), 1);
    assert_eq!(
        count_events(&t, |e| *e
            == TransparencyEvent::SyncApplied {
                kind: SyncKind::GifSettings
            }),
        1
    );
    // A change that leaves the provider as it was logs no consent.
    a.set_gif_auto_load(true, NOW + 31, &mut rng).unwrap();
    deliver_all_at(&mut a, &mut t, NOW + 40, &mut rng);
    assert_eq!(
        count_events(&t, |e| matches!(e, TransparencyEvent::GifConsent { .. })),
        1
    );
    a.disable_gif_provider(1, NOW + 41, &mut rng).unwrap();
    assert_eq!(count_events(&a, |e| *e == consent_event(false, false)), 1);
    deliver_all_at(&mut a, &mut t, NOW + 50, &mut rng);
    assert_eq!(count_events(&t, |e| *e == consent_event(false, true)), 1);
}

#[test]
fn gif_settings_fit_tier_m() {
    let (_d, mut a, mut t, mut rng) = linked();
    answer_own_session(&mut a, &mut t, &mut rng);
    let wide = crate::gif::GifConsent {
        warning_version: u16::MAX,
        device: DeviceId([0xff; 16]),
        at: u64::MAX,
    };
    let settings = crate::gif::GifSettings {
        enabled: (1..=8).map(|p| (p, wide.clone())).collect(),
        auto_load: true,
    };
    let pkt = gif_settings_packet(
        &mut a,
        &send::Target::OwnDevices,
        settings,
        u64::MAX,
        1,
        &mut rng,
    );
    assert_eq!(pkt.tier, Tier::M);
}

#[test]
fn stale_consent_logs_no_enabled_event() {
    let (_d, mut a, _t, mut rng) = linked();
    let on =
        |e: &TransparencyEvent| matches!(e, TransparencyEvent::GifConsent { enabled: true, .. });
    // A warning below the minimum does not make Klipy reachable: no claim.
    a.enable_gif_provider(1, 0, NOW, &mut rng).unwrap();
    assert!(!a.gif_allowed(1).unwrap());
    assert_eq!(
        count_events(&a, |e| matches!(e, TransparencyEvent::GifConsent { .. })),
        0
    );
    a.enable_gif_provider(1, crate::gif::MIN_GIF_WARNING_VERSION, NOW + 1, &mut rng)
        .unwrap();
    assert_eq!(count_events(&a, on), 1);
    // Back to a stale version: effectively off, logged as such.
    a.enable_gif_provider(1, 0, NOW + 2, &mut rng).unwrap();
    assert_eq!(count_events(&a, on), 1);
    assert_eq!(
        count_events(&a, |e| matches!(
            e,
            TransparencyEvent::GifConsent { enabled: false, .. }
        )),
        1
    );
}

#[test]
fn unknown_provider_by_sync_logs_no_consent() {
    let (_d, mut a, mut t, mut rng) = linked();
    let settings = crate::gif::GifSettings {
        enabled: [(7, consent(this_device(&t), NOW))].into(),
        auto_load: false,
    };
    let pkt = gif_settings_packet(
        &mut t,
        &send::Target::OwnDevices,
        settings,
        NOW + 5,
        1,
        &mut rng,
    );
    a.receive(&pkt.encode(), "t", NOW + 5, &mut rng).unwrap();
    assert!(a.gif_settings().unwrap().enabled.contains_key(&7));
    assert_eq!(
        count_events(&a, |e| matches!(e, TransparencyEvent::GifConsent { .. })),
        0
    );
}

#[test]
fn gif_settings_from_far_future_ignored() {
    let (_d, mut a, mut t, mut rng) = linked();
    let settings = crate::gif::GifSettings {
        enabled: [(1, consent(this_device(&t), NOW))].into(),
        auto_load: true,
    };
    let now = NOW + 5;
    let too_far = now + super::MAX_FUTURE_SECS + 1;
    let pkt = gif_settings_packet(
        &mut t,
        &send::Target::OwnDevices,
        settings.clone(),
        too_far,
        1,
        &mut rng,
    );
    let r = a.receive(&pkt.encode(), "t", now, &mut rng).unwrap();
    assert!(!matches!(r, ReceiveOutcome::Synced { .. }), "{r:?}");
    assert_eq!(
        a.gif_settings().unwrap(),
        crate::gif::GifSettings::default()
    );
    // At the tolerance it is still applied.
    let pkt = gif_settings_packet(
        &mut t,
        &send::Target::OwnDevices,
        settings.clone(),
        now + super::MAX_FUTURE_SECS,
        2,
        &mut rng,
    );
    a.receive(&pkt.encode(), "t", now, &mut rng).unwrap();
    assert_eq!(a.gif_settings().unwrap(), settings);
}

// --- GIF, task 4: daily usage counters.

fn usage_day(day: u32, searches: u32, shown: u32, sent: u32) -> GifUsageDay {
    GifUsageDay {
        day,
        searches,
        shown,
        sent,
        previews: 0,
    }
}

#[test]
fn gif_usage_counts_per_day() {
    let (_d, mut a) = party("a", 1);
    assert!(a.gif_usage(7).unwrap().is_empty());
    a.record_gif_use(GifUse::Search, 10).unwrap();
    a.record_gif_use(GifUse::Search, 20).unwrap();
    a.record_gif_use(GifUse::Shown, 30).unwrap();
    a.record_gif_use(GifUse::Sent, 86_400 + 5).unwrap();
    assert_eq!(
        a.gif_usage(7).unwrap(),
        [usage_day(1, 0, 0, 1), usage_day(0, 2, 1, 0)]
    );
    assert_eq!(a.gif_usage(1).unwrap(), [usage_day(1, 0, 0, 1)]);
    assert!(a.gif_usage(0).unwrap().is_empty());
    // An earlier day recorded late (clock moved back) lands in its place.
    a.record_gif_use(GifUse::Shown, 40).unwrap();
    assert_eq!(
        a.gif_usage(7).unwrap(),
        [usage_day(1, 0, 0, 1), usage_day(0, 2, 2, 0)]
    );
}

#[test]
fn gif_usage_keeps_30_days() {
    let (_d, mut a) = party("a", 1);
    for day in 0..40u64 {
        a.record_gif_use(GifUse::Search, day * 86_400).unwrap();
    }
    let rows = a.gif_usage(255).unwrap();
    assert_eq!(rows.len(), 30);
    assert_eq!(rows[0].day, 39);
    assert_eq!(rows[29].day, 10);
}

#[test]
fn gif_usage_saturates() {
    let (_d, mut a) = party("a", 1);
    a.store
        .put_meta(META_GIF_USAGE_V2, &vec![usage_day(0, u32::MAX, 0, 0)])
        .unwrap();
    a.record_gif_use(GifUse::Search, 1).unwrap();
    assert_eq!(a.gif_usage(1).unwrap(), [usage_day(0, u32::MAX, 0, 0)]);
}

#[test]
fn gif_usage_never_stores_content() {
    // A row holds five numbers and nothing else.
    let (_d, mut a) = party("a", 1);
    a.record_gif_use(GifUse::Search, 1).unwrap();
    let raw: Vec<GifUsageDay> = a.store.get_meta(META_GIF_USAGE_V2).unwrap().unwrap();
    assert_eq!(postcard::to_allocvec(&raw).unwrap().len(), 6);
}

#[test]
fn gif_usage_counts_previews() {
    let (_d, mut a) = party("a", 1);
    a.record_gif_use(GifUse::Preview, 10).unwrap();
    a.record_gif_use(GifUse::Preview, 20).unwrap();
    a.record_gif_use(GifUse::Search, 30).unwrap();
    let rows = a.gif_usage(1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].searches, rows[0].previews), (1, 2));
}

/// Rows stored before previews were counted (four counters, the first
/// key) still read, with no previews, and are carried over at the next
/// count.
#[test]
fn gif_usage_reads_rows_of_the_first_format() {
    #[derive(serde::Serialize)]
    struct Old {
        day: u32,
        searches: u32,
        shown: u32,
        sent: u32,
    }
    let (_d, mut a) = party("a", 1);
    let old = vec![
        Old {
            day: 3,
            searches: 4,
            shown: 5,
            sent: 6,
        },
        Old {
            day: 1,
            searches: 1,
            shown: 0,
            sent: 2,
        },
    ];
    a.store.put_meta(META_GIF_USAGE, &old).unwrap();
    assert_eq!(
        a.gif_usage(7).unwrap(),
        [usage_day(3, 4, 5, 6), usage_day(1, 1, 0, 2)]
    );
    a.record_gif_use(GifUse::Preview, 3 * 86_400 + 1).unwrap();
    let mut today = usage_day(3, 4, 5, 6);
    today.previews = 1;
    assert_eq!(a.gif_usage(7).unwrap(), [today, usage_day(1, 1, 0, 2)]);
    assert!(a.store.get_meta_raw(META_GIF_USAGE).unwrap().is_none());
}
