//! Scénario de bout en bout : deux (ou trois) personnes, chacune avec sa base.

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
const T: &str = "fichier";

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
        // L'ancienne connexion est fermée avant la réouverture.
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

/// Alice et Bob, chacun dans sa base temporaire, ont échangé leurs cartes.
fn pair() -> (Party, Party, StdRng) {
    let mut a = Party::new("tel-alice", 1);
    let mut b = Party::new("tel-bob", 2);
    let ca = a.card("Alice");
    let cb = b.card("Bob");
    assert_eq!(a.core.add_contact(&cb, Some("bob")).unwrap(), b.fp());
    assert_eq!(b.core.add_contact(&ca, Some("alice")).unwrap(), a.fp());
    (a, b, StdRng::seed_from_u64(99))
}

/// Déballe un `Message`, sinon échoue.
fn expect_msg(o: ReceiveOutcome) -> (Fingerprint, Option<String>, String, Packet) {
    match o {
        ReceiveOutcome::Message {
            from,
            alias,
            text,
            ack,
        } => (from, alias, text, ack),
        other => panic!("Message attendu, obtenu {other:?}"),
    }
}

fn one(mut v: Vec<Packet>) -> Packet {
    assert_eq!(v.len(), 1, "un seul paquet attendu");
    v.remove(0)
}

fn is_initial(p: &Packet) -> bool {
    matches!(parse_wire(&p.payload).unwrap(), Wire::Initial { .. })
}

#[test]
fn alice_to_bob_and_back() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "Salut Bob ! 🐕", NOW, &mut rng));
    assert_eq!(p1.kind, Kind::Message);
    assert!(is_initial(&p1));
    assert_ne!(
        p1.tier,
        Tier::S,
        "jamais d'ouverture de session en palier S"
    );

    let (from, alias, text, _) = expect_msg(b.recv(&p1, NOW, &mut rng));
    assert_eq!(from, a.fp());
    assert_eq!(alias.as_deref(), Some("alice"));
    assert_eq!(text, "Salut Bob ! 🐕");

    // Bob répond dans la session ouverte par Alice : pas d'Initial.
    let p2 = one(b.send(&a.fp(), "Salut Alice", NOW + 5, &mut rng));
    assert!(!is_initial(&p2));
    assert_eq!(p2.tier, Tier::S);
    let (from, alias, text, _) = expect_msg(a.recv(&p2, NOW + 5, &mut rng));
    assert_eq!(from, b.fp());
    assert_eq!(alias.as_deref(), Some("bob"));
    assert_eq!(text, "Salut Alice");

    // Après la réponse de Bob, Alice n'envoie plus d'Initial.
    let p3 = one(a.send(&b.fp(), "ça marche", NOW + 10, &mut rng));
    assert!(!is_initial(&p3));
    let (_, _, text, _) = expect_msg(b.recv(&p3, NOW + 10, &mut rng));
    assert_eq!(text, "ça marche");

    let hist = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(hist.len(), 3);
    assert_eq!(hist[1].direction, Direction::In);
    assert_eq!(hist[1].body, "Salut Alice");
}

#[test]
fn initial_resent_until_first_reply() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "un", NOW, &mut rng));
    let p2 = one(a.send(&b.fp(), "deux", NOW + 1, &mut rng));
    assert!(is_initial(&p1) && is_initial(&p2));
    // Ordre inversé : le second Initial ouvre la session, le premier la réutilise.
    assert_eq!(expect_msg(b.recv(&p2, NOW + 2, &mut rng)).2, "deux");
    assert_eq!(expect_msg(b.recv(&p1, NOW + 3, &mut rng)).2, "un");
}

#[test]
fn ack_marks_delivered() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "accuse-moi", NOW, &mut rng));
    let sent = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(sent[0].status, MessageStatus::Sent);
    assert_eq!(sent.len(), 1);

    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(ack.kind, Kind::Ack);
    assert_eq!(ack.tier, Tier::S);
    match a.recv(&ack, NOW + 1, &mut rng) {
        ReceiveOutcome::AckReceived { packet_id } => assert_eq!(packet_id, p.id),
        other => panic!("AckReceived attendu, obtenu {other:?}"),
    }
    let after = a.core.messages_with(&b.fp()).unwrap();
    assert_eq!(after[0].status, MessageStatus::Delivered);
    assert!(a.events().iter().any(
        |e| matches!(e, TransparencyEvent::AckVerified { for_packet } if *for_packet == p.id)
    ));
    // Le même accusé une seconde fois n'est pas compté deux fois.
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

    // Mauvais secret.
    let mut bad = ack.clone();
    bad.payload[20] ^= 1;
    assert!(matches!(
        a.recv(&bad, NOW, &mut rng),
        ReceiveOutcome::NotForUs
    ));
    // Charge d'accusé de mauvaise longueur (31 et 33 octets).
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
    // Accusé valide pour un paquet que je n'ai pas envoyé (celui de Bob vers moi).
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
    let p = one(a.send(&b.fp(), "une fois", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    assert!(matches!(
        b.recv(&p, NOW + 1, &mut rng),
        ReceiveOutcome::Duplicate
    ));
    // Aussi pour un message normal (après l'ouverture de session).
    let q = one(b.send(&a.fp(), "retour", NOW + 2, &mut rng));
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
    let p = one(a.send(&b.fp(), "vieux", NOW, &mut rng));
    let late = u64::from(p.expires_at) + 1;
    assert!(matches!(
        b.recv(&p, late, &mut rng),
        ReceiveOutcome::Expired
    ));
}

#[test]
fn late_delivery_within_freshness_window() {
    let (mut a, mut b, mut rng) = pair();
    // Initial livré 5 jours après l'envoi : boîte d'introduction du jour d'envoi.
    let p1 = one(a.send(&b.fp(), "cinq jours de retard", NOW, &mut rng));
    assert_eq!(
        expect_msg(b.recv(&p1, NOW + 5 * DAY, &mut rng)).2,
        "cinq jours de retard"
    );
    // Session établie dans les deux sens.
    let r = one(b.send(&a.fp(), "reçu", NOW + 5 * DAY, &mut rng));
    expect_msg(a.recv(&r, NOW + 5 * DAY, &mut rng));
    // Message normal (boîte de session) livré 5 jours après l'envoi.
    let t = NOW + 5 * DAY + 10;
    let p2 = one(a.send(&b.fp(), "normal en retard", t, &mut rng));
    assert!(!is_initial(&p2));
    assert_eq!(
        expect_msg(b.recv(&p2, t + 5 * DAY, &mut rng)).2,
        "normal en retard"
    );
    // Au-delà de la fenêtre de fraîcheur : expiré.
    let p3 = one(a.send(&b.fp(), "trop tard", t + 1, &mut rng));
    assert!(matches!(
        b.recv(&p3, t + 1 + DEFAULT_TTL_SECS + DAY + 1, &mut rng),
        ReceiveOutcome::Expired
    ));
    // Même avec une expiration réécrite par un relais : la boîte du jour
    // d'envoi est hors de la fenêtre acceptée.
    let p4 = one(a.send(&b.fp(), "réécrit", t + 2, &mut rng));
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
    // Horloge de Bob en avance d'un jour.
    let p1 = one(a.send(&b.fp(), "décalé d'un jour", NOW, &mut rng));
    assert_eq!(
        expect_msg(b.recv(&p1, NOW + DAY, &mut rng)).2,
        "décalé d'un jour"
    );
    // Horloge de Bob en retard d'un jour : boîte du lendemain pour Alice.
    let p3 = one(b.send(&a.fp(), "retour", NOW + DAY, &mut rng));
    assert_eq!(expect_msg(a.recv(&p3, NOW, &mut rng)).2, "retour");
    // Deux jours d'avance de l'expéditeur : boîte hors fenêtre.
    let p4 = one(b.send(&a.fp(), "trop en avance", NOW + 3 * DAY, &mut rng));
    assert!(matches!(
        a.recv(&p4, NOW, &mut rng),
        ReceiveOutcome::NotForUs
    ));
}

#[test]
fn simultaneous_first_messages() {
    let (mut a, mut b, mut rng) = pair();
    let pa = one(a.send(&b.fp(), "de A", NOW, &mut rng));
    let pb = one(b.send(&a.fp(), "de B", NOW, &mut rng));
    assert!(is_initial(&pa) && is_initial(&pb));
    assert_eq!(expect_msg(b.recv(&pa, NOW + 1, &mut rng)).2, "de A");
    assert_eq!(expect_msg(a.recv(&pb, NOW + 1, &mut rng)).2, "de B");

    let mut t = NOW + 10;
    for i in 0..3 {
        let x = one(a.send(&b.fp(), &format!("A{i}"), t, &mut rng));
        assert!(!is_initial(&x), "plus d'Initial après une réception");
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
    let p = one(a.send(&b.fp(), "vrai message", NOW, &mut rng));
    let good = p.encode();

    let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xff; 245], vec![0; 1024]];
    for cut in [1usize, 41, 42, 100, good.len() - 1] {
        inputs.push(good[..cut].to_vec());
    }
    // Palier menteur : annonce S mais longueur M, et l'inverse.
    let mut liar = good.clone();
    liar[3] = Tier::S as u8;
    inputs.push(liar);
    let mut liar2 = good[..245].to_vec();
    liar2[3] = Tier::L as u8;
    inputs.push(liar2);
    // Charge altérée, longueur de charge mensongère.
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
            other => panic!("NotForUs ou Quarantined attendu, obtenu {other:?}"),
        }
    }
    // Le vrai message passe toujours.
    assert_eq!(expect_msg(b.recv(&p, NOW, &mut rng)).2, "vrai message");
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
            assert_eq!(reason, "déchiffrement impossible");
        }
        other => panic!("Quarantined attendu, obtenu {other:?}"),
    }
    assert!(
        b.events()
            .iter()
            .any(|e| matches!(e, TransparencyEvent::DecryptFailed { .. }))
    );
    // Le paquet falsifié ne bloque pas l'original (même identifiant).
    assert_eq!(expect_msg(b.recv(&p, NOW, &mut rng)).2, "intact");
}

#[test]
fn unknown_sender_quarantined() {
    let (_a, mut b, mut rng) = pair();
    let mut carol = Party::new("tel-carol", 3);
    carol.core.add_contact(&b.card("Bob"), Some("bob")).unwrap();
    let p = one(carol.send(&b.fp(), "coucou, c'est Carol", NOW, &mut rng));
    match b.recv(&p, NOW, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("inconnu"), "{reason}"),
        other => panic!("Quarantined attendu, obtenu {other:?}"),
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
    // Un relais rejoue un vieil Initial en réécrivant l'en-tête (boîte du jour,
    // expiration) : l'horodatage authentifié de l'enveloppe le trahit.
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "vieux", NOW, &mut rng));
    let later = NOW + 10 * DAY;
    let bob_dev = b.card("Bob").devices.certs[0].device;
    let mut replay = p.clone();
    replay.mailbox = intro_mailbox(&bob_dev, day_of(later));
    replay.expires_at = u32::try_from(later + DEFAULT_TTL_SECS).unwrap();
    match b.recv(&replay, later, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("ancien"), "{reason}"),
        other => panic!("Quarantined attendu, obtenu {other:?}"),
    }
    // La session que ce vieil Initial aurait ouverte n'est pas créée.
    assert_eq!(b.core.watched_mailboxes(later).len(), 3);
    assert!(b.core.messages_with(&a.fp()).unwrap().is_empty());
}

#[test]
fn persists_across_reopen() {
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "avant", NOW, &mut rng));
    a.reopen();
    b.reopen();
    assert_eq!(expect_msg(b.recv(&p1, NOW, &mut rng)).2, "avant");
    b.reopen();
    let p2 = one(b.send(&a.fp(), "réponse", NOW + 1, &mut rng));
    a.reopen();
    let (from, alias, text, ack) = expect_msg(a.recv(&p2, NOW + 1, &mut rng));
    assert_eq!(
        (from, alias.as_deref(), text.as_str()),
        (b.fp(), Some("bob"), "réponse")
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
    let p3 = one(a.send(&b.fp(), "après", NOW + 3, &mut rng));
    assert!(!is_initial(&p3));
    assert_eq!(expect_msg(b.recv(&p3, NOW + 3, &mut rng)).2, "après");
    assert_eq!(a.core.fingerprint(), a.fp());
    assert_eq!(a.core.contacts().unwrap().len(), 1);
}

#[test]
fn send_state_persisted_before_return() {
    // Une réouverture entre deux envois ne doit jamais réutiliser une clé de message.
    let (mut a, mut b, mut rng) = pair();
    let p1 = one(a.send(&b.fp(), "un", NOW, &mut rng));
    expect_msg(b.recv(&p1, NOW, &mut rng));
    let p2 = one(b.send(&a.fp(), "r", NOW, &mut rng));
    expect_msg(a.recv(&p2, NOW, &mut rng));
    let p3 = one(a.send(&b.fp(), "deux", NOW, &mut rng));
    a.reopen();
    let p4 = one(a.send(&b.fp(), "trois", NOW, &mut rng));
    assert_ne!(p3.payload, p4.payload);
    assert_eq!(expect_msg(b.recv(&p4, NOW, &mut rng)).2, "trois");
    assert_eq!(expect_msg(b.recv(&p3, NOW, &mut rng)).2, "deux");
}

#[test]
fn multi_device_fanout() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let p1 = dir.path().join("bob1.db");
    let (mut bob1, phrase) = Core::create(&p1, &[2; 32], "tel-bob", NOW, &mut rng).unwrap();
    let p2 = dir.path().join("bob2.db");
    let mut bob2 = Core::recover(&p2, &[3; 32], phrase.as_str(), "pc-bob", NOW, &mut rng).unwrap();
    assert_eq!(bob1.fingerprint(), bob2.fingerprint());

    let req = bob2.device_link_request("pc-bob", NOW).unwrap();
    bob1.link_device(&req).unwrap();
    let card = bob1.contact_card("Bob").unwrap();
    // Liste initiale signée à la version `NOW`, puis `version + 1` à la liaison.
    assert_eq!(card.devices.version, NOW + 1);
    assert_eq!(card.devices.certs.len(), 2);
    assert_eq!(card.bundles.len(), 2);
    card.verify().unwrap();

    let bob_fp = a.core.add_contact(&card, Some("bob")).unwrap();
    let alice_card = a.card("Alice");
    bob1.add_contact(&alice_card, Some("alice")).unwrap();
    bob2.add_contact(&alice_card, Some("alice")).unwrap();

    let pkts = a.send(&bob_fp, "à tous tes appareils", NOW, &mut rng);
    assert_eq!(pkts.len(), 2);
    assert_ne!(pkts[0].id, pkts[1].id);
    for core in [&mut bob1, &mut bob2] {
        let mut opened = 0;
        for p in &pkts {
            match core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
                ReceiveOutcome::Message { text, .. } => {
                    assert_eq!(text, "à tous tes appareils");
                    opened += 1;
                }
                ReceiveOutcome::NotForUs => {}
                other => panic!("inattendu : {other:?}"),
            }
        }
        assert_eq!(opened, 1, "chaque appareil déchiffre exactement un paquet");
    }
}

#[test]
fn send_to_multi_device_contact_is_one_message() {
    let mut a = Party::new("tel-alice", 1);
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let (mut bob1, phrase) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let mut bob2 = Core::recover(
        &dir.path().join("b2"),
        &[3; 32],
        phrase.as_str(),
        "b2",
        NOW,
        &mut rng,
    )
    .unwrap();
    let req = bob2.device_link_request("b2", NOW).unwrap();
    bob1.link_device(&req).unwrap();
    let card = bob1.contact_card("Bob").unwrap();
    let bob = a.core.add_contact(&card, Some("bob")).unwrap();
    let alice_card = a.card("Alice");
    bob1.add_contact(&alice_card, Some("alice")).unwrap();
    bob2.add_contact(&alice_card, Some("alice")).unwrap();

    let pkts = a.send(&bob, "un seul message", NOW, &mut rng);
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
        let ack = ack.expect("chaque appareil ouvre un paquet");
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
    let (mut bob1, phrase) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let old_card = bob1.contact_card("Bob").unwrap();
    let bob2 = Core::recover(
        &dir.path().join("b2"),
        &[3; 32],
        phrase.as_str(),
        "b2",
        NOW,
        &mut rng,
    )
    .unwrap();
    let req = bob2.device_link_request("b2", NOW).unwrap();
    bob1.link_device(&req).unwrap();
    let new_card = bob1.contact_card("Bob").unwrap();
    a.core.add_contact(&new_card, Some("bob")).unwrap();
    // Une carte avec une liste plus ancienne est refusée.
    assert!(a.core.add_contact(&old_card, Some("bob")).is_err());
    let pkts = a.send(&bob1.fingerprint(), "x", NOW, &mut rng);
    assert_eq!(pkts.len(), 2);
}

#[test]
fn contact_key_change_flagged() {
    let (mut a, b, _rng) = pair();
    a.core.mark_verified(&b.fp()).unwrap();
    assert!(a.core.contacts().unwrap()[0].verified);
    assert_eq!(
        a.core.safety_number(&b.fp()).unwrap(),
        b.core.safety_number(&a.fp()).unwrap()
    );

    let mallory = Party::new("tel-mallory", 4);
    let new_fp = a
        .core
        .add_contact(&mallory.card("Bob"), Some("bob"))
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
    assert!(a.core.add_contact(&a.card("Alice"), Some("moi")).is_err());
    let mut card = b.card("Bob");
    card.display_name = "Bobby".into();
    assert!(a.core.add_contact(&card, Some("bob2")).is_err());
}

#[test]
fn transparency_has_no_plaintext() {
    let (mut a, mut b, mut rng) = pair();
    let secret = "texte-tres-secret-42";
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
    // Le premier contact ne prétend pas cacher le destinataire.
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
            assert!(!d.contains("à qui tu écris"), "{d}");
            assert!(d.contains("carte de contact"), "{d}");
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
    let p = one(a.send(&b.fp(), "chut-chut", NOW, &mut rng));
    let out = b.recv(&p, NOW, &mut rng);
    assert!(!format!("{out:?}").contains("chut-chut"));
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
    assert!(Core::open(&dir.path().join("vide.db"), &key, NOW).is_err());
    assert!(
        !dir.path().join("vide.db").exists(),
        "open ne crée pas de base"
    );
    assert_eq!(
        Core::recover(
            &dir.path().join("r.db"),
            &key,
            "pas une phrase",
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
    // Sans session : 3 boîtes d'introduction.
    assert_eq!(b.core.watched_mailboxes(NOW).len(), 3);
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    assert!(b.core.watched_mailboxes(NOW).contains(&p.mailbox));
    assert!(b.core.watched_mailboxes(NOW + DAY).contains(&p.mailbox));
    assert!(!b.core.watched_mailboxes(NOW + 2 * DAY).contains(&p.mailbox));
    expect_msg(b.recv(&p, NOW, &mut rng));
    // Avec une session : 3 boîtes de plus.
    assert_eq!(b.core.watched_mailboxes(NOW).len(), 6);
}

#[test]
fn offline_five_days_still_watches_missed_days() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    b.core.mark_polled(NOW).unwrap();
    let later = NOW + 5 * DAY;
    let watched = b.core.watched_mailboxes(later);
    // Alice écrit chaque jour : la boîte du paquet est celle de Bob ce jour-là.
    for d in day_of(NOW)..=day_of(later) + 1 {
        let t = u64::from(d) * DAY;
        let q = one(a.send(&b.fp(), "jour", t, &mut rng));
        assert!(watched.contains(&q.mailbox), "jour {d} non relevé");
    }
}

#[test]
fn polling_window_capped_at_nine_days() {
    let (_a, mut b, _rng) = pair();
    let bob_dev = b.card("Bob").devices.certs[0].device;
    b.core.mark_polled(NOW).unwrap();
    let later = NOW + 20 * DAY;
    let watched = b.core.watched_mailboxes(later);
    // 7 jours en arrière, le jour même et le lendemain.
    assert_eq!(watched.len(), 9);
    let last = day_of(later) + 1;
    for d in last - 8..=last {
        assert!(watched.contains(&intro_mailbox(&bob_dev, d)), "jour {d}");
    }
}

#[test]
fn polled_in_future_falls_back() {
    let (_a, mut b, _rng) = pair();
    let reference = b.core.watched_mailboxes(NOW);
    b.core.mark_polled(NOW + 10 * DAY).unwrap();
    assert_eq!(b.core.watched_mailboxes(NOW), reference);
}

fn arb_packet_bytes(watched: Vec<MailboxId>) -> impl Strategy<Value = Vec<u8>> {
    let n = watched.len();
    prop_oneof![
        // Octets quelconques.
        proptest::collection::vec(any::<u8>(), 0..2048),
        // Paquets bien formés vers une boîte surveillée, charge quelconque.
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
    // Une session existe, pour atteindre aussi les boîtes de session.
    let p = one(a.send(&b.fp(), "x", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    let watched = b.core.watched_mailboxes(NOW);
    let state = RefCell::new((b, rng));
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(256));
    runner
        .run(&arb_packet_bytes(watched), |bytes| {
            let (b, rng) = &mut *state.borrow_mut();
            let out = b.core.receive(&bytes, T, NOW, rng);
            prop_assert!(out.is_ok(), "{out:?}");
            let shown = matches!(out, Ok(ReceiveOutcome::Message { .. }));
            prop_assert!(!shown, "aucun message ne doit sortir d'octets aléatoires");
            Ok(())
        })
        .unwrap();
}

#[test]
fn link_request_proof_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(12);
    let (mut bob1, phrase) =
        Core::create(&dir.path().join("b1"), &[2; 32], "b1", NOW, &mut rng).unwrap();
    let bob2 = Core::recover(
        &dir.path().join("b2"),
        &[3; 32],
        phrase.as_str(),
        "b2",
        NOW,
        &mut rng,
    )
    .unwrap();
    let good = bob2.device_link_request("b2", NOW).unwrap();
    for tamper in 0..3 {
        let mut req = good.clone();
        match tamper {
            0 => req.device_sig[0] ^= 1,
            1 => req.name = "autre".into(),
            _ => req.issued_at += 1,
        }
        assert!(bob1.link_device(&req).is_err(), "falsification {tamper}");
    }
    bob1.link_device(&good).unwrap();
}

#[test]
fn card_claiming_another_contacts_device_rejected() {
    // Mallory veut revendiquer l'appareil d'Alice sous sa propre racine.
    let (_a, mut b, mut rng) = pair();
    let alice_card = _a.card("Alice");
    let alice_cert = alice_card.devices.certs[0].clone();
    let dir = tempfile::tempdir().unwrap();
    let (mallory, phrase) =
        Core::create(&dir.path().join("m"), &[5; 32], "m", NOW, &mut rng).unwrap();
    let mroot = RootIdentity::from_phrase(phrase.as_str()).unwrap();
    // 1. La preuve de possession d'Alice est liée à sa racine.
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
    // 2. Le certificat d'Alice tel quel ne peut pas entrer dans la liste de Mallory.
    let mut forged = mallory.contact_card("Alice").unwrap();
    assert!(DeviceList::sign(&mroot, 2, vec![alice_cert.clone()]).is_err());
    forged.devices.certs.push(alice_cert);
    assert!(b.core.add_contact(&forged, Some("alice2")).is_err());
    // 3. Les messages d'Alice restent attribués à Alice.
    let mut a = _a;
    let p = one(a.send(&b.fp(), "c'est Alice", NOW, &mut rng));
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
    let mut bob2 = Core::recover(
        &dir.path().join("b2"),
        &[3; 32],
        phrase.as_str(),
        "b2",
        NOW,
        &mut rng,
    )
    .unwrap();
    bob1.link_device(&bob2.device_link_request("b2", NOW).unwrap())
        .unwrap();
    let v2 = bob1.contact_card("Bob").unwrap();
    let bob_fp = alice.core.add_contact(&v2, Some("bob")).unwrap();
    let alice_card = alice.card("Alice");
    bob2.add_contact(&alice_card, Some("alice")).unwrap();

    // Bob2 ouvre la session (deux Initial), Alice en reçoit un et répond.
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
    // Un paquet par appareil de Bob ; Bob2 déchiffre le sien (sa session
    // n'est plus en attente : il enverra ensuite des messages normaux).
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
    // Avant révocation, un message normal de Bob2 passe.
    assert_eq!(expect_msg(alice.recv(&n0, NOW, &mut rng)).2, "n0");

    // Bob révoque Bob2 : liste suivante sans lui.
    let root = RootIdentity::from_phrase(phrase.as_str()).unwrap();
    let bob1_cert = v2.devices.certs[0].clone();
    let bob1_bundle = v2
        .bundles
        .iter()
        .find(|b| b.device == bob1_cert.device)
        .unwrap()
        .clone();
    let v3 = DeviceList::sign(&root, v2.devices.version + 1, vec![bob1_cert]).unwrap();
    let card3 = ContactCard::sign(&root, "Bob", v3, vec![bob1_bundle]).unwrap();
    alice.core.add_contact(&card3, Some("bob")).unwrap();

    // Ni le message normal, ni l'Initial de l'appareil révoqué ne passent.
    let normal = alice.recv(&n1, NOW, &mut rng);
    assert!(
        matches!(
            normal,
            ReceiveOutcome::NotForUs | ReceiveOutcome::Quarantined { .. }
        ),
        "{normal:?}"
    );
    match alice.recv(&i2, NOW, &mut rng) {
        ReceiveOutcome::Quarantined { reason } => assert!(reason.contains("inconnu"), "{reason}"),
        other => panic!("Quarantined attendu, obtenu {other:?}"),
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
    let p = one(a.send(&b.fp(), "ne me perds pas", NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![p.encode()]);
    a.reopen();
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![p.encode()]);
}

#[test]
fn ack_clears_outbox() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "accuse-moi", NOW, &mut rng));
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
    one(a.send(&b.fp(), "trop tard", NOW, &mut rng));
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
    let p = one(a.send(&b.fp(), "salut", NOW, &mut rng));
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
        .add_contact(&bob1.contact_card("Bob").unwrap(), Some("bob"))
        .unwrap();
    bob1.add_contact(&a.card("Alice"), Some("alice")).unwrap();
    let p = one(a.send(&bob_fp, "avant", NOW, &mut rng));
    expect_msg(bob1.receive(&p.encode(), T, NOW, &mut rng).unwrap());

    // Bob perd son téléphone et retrouve son identité plus tard.
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
    // Alice ajoute la nouvelle carte sans retirer l'ancienne.
    assert_eq!(
        a.core
            .add_contact(&bob2.contact_card("Bob").unwrap(), Some("bob"))
            .unwrap(),
        bob_fp
    );
    bob2.add_contact(&a.card("Alice"), Some("alice")).unwrap();

    let p = one(a.send(&bob_fp, "après", later, &mut rng));
    let (from, _, text, _) = expect_msg(bob2.receive(&p.encode(), T, later, &mut rng).unwrap());
    assert_eq!((from, text.as_str()), (a.fp(), "après"));
    let r = one(bob2
        .send_text(&a.fp(), "bien reçu", later + 1, &mut rng)
        .unwrap());
    let (from, alias, text, _) = expect_msg(a.recv(&r, later + 1, &mut rng));
    assert_eq!(from, bob_fp);
    assert_eq!(alias.as_deref(), Some("bob"));
    assert_eq!(text, "bien reçu");
}

#[test]
fn skipped_keys_expire_after_seven_days() {
    let (mut a, mut b, mut rng) = pair();
    let p = one(a.send(&b.fp(), "ouverture", NOW, &mut rng));
    expect_msg(b.recv(&p, NOW, &mut rng));
    let r = one(b.send(&a.fp(), "ok", NOW, &mut rng));
    expect_msg(a.recv(&r, NOW, &mut rng));

    // L'horloge d'Alice avance d'un jour sur celle de Bob.
    let s = NOW + 100;
    let q0 = one(a.send(&b.fp(), "q0", s, &mut rng));
    let q1 = one(a.send(&b.fp(), "q1", s, &mut rng));
    let p2 = one(a.send(&b.fp(), "p2", s + 1, &mut rng));
    assert!(!is_initial(&q0));
    // Bob reçoit p2 en premier : les clés de q0 et q1 sont sautées à `stored`.
    let stored = s + 1 - DAY;
    assert_eq!(expect_msg(b.recv(&p2, stored, &mut rng)).2, "p2");
    // Clé sautée de moins de 7 jours : encore utilisable.
    assert_eq!(expect_msg(b.recv(&q1, stored + 3 * DAY, &mut rng)).2, "q1");
    // Clé sautée de plus de 7 jours : purgée, alors que le paquet n'est pas
    // encore expiré et que son horodatage reste frais.
    let late = s + DEFAULT_TTL_SECS;
    assert!(late - stored > 7 * DAY);
    assert!(u64::from(q0.expires_at) >= late);
    match b.recv(&q0, late, &mut rng) {
        ReceiveOutcome::Quarantined { .. } | ReceiveOutcome::NotForUs => {}
        other => panic!("clé sautée expirée, obtenu {other:?}"),
    }
}

#[test]
fn ack_goes_to_the_original_mailbox_which_the_sender_watches_until_acked() {
    let (mut a, mut b, mut rng) = pair();
    // Accusé d'un Initial : même boîte que le message, relevée par A tant
    // que le message attend son accusé.
    let p = one(a.send(&b.fp(), "ouverture", NOW, &mut rng));
    assert!(a.core.watched_mailboxes(NOW).contains(&p.mailbox));
    let (_, _, _, ack) = expect_msg(b.recv(&p, NOW, &mut rng));
    assert_eq!(ack.mailbox, p.mailbox);
    // Accusé d'un message normal, dans l'autre sens.
    let r = one(b.send(&a.fp(), "réponse", NOW + 1, &mut rng));
    let (_, _, _, ack_r) = expect_msg(a.recv(&r, NOW + 1, &mut rng));
    assert_eq!(ack_r.mailbox, r.mailbox);
    assert!(b.core.watched_mailboxes(NOW + 1).contains(&ack_r.mailbox));
    // Message livré trois jours plus tard : sa boîte sort de la fenêtre de
    // trois jours, mais A la relève toujours tant qu'il attend l'accusé.
    let q = one(a.send(&b.fp(), "en retard", NOW + 2, &mut rng));
    assert!(!is_initial(&q));
    let late = NOW + 3 * DAY;
    let (_, _, _, ack_q) = expect_msg(b.recv(&q, late, &mut rng));
    assert_eq!(ack_q.mailbox, q.mailbox);
    assert!(a.core.watched_mailboxes(late).contains(&ack_q.mailbox));
    // Les accusés se vérifient toujours par l'identifiant et le secret.
    for (ack, at, id) in [(ack, late, p.id), (ack_q, late, q.id)] {
        match a.recv(&ack, at, &mut rng) {
            ReceiveOutcome::AckReceived { packet_id } => assert_eq!(packet_id, id),
            other => panic!("AckReceived attendu, obtenu {other:?}"),
        }
    }
    // Accusé reçu : A ne relève plus la boîte du message en retard.
    assert!(!a.core.watched_mailboxes(late).contains(&q.mailbox));
    assert!(matches!(
        b.recv(&ack_r, NOW + 2, &mut rng),
        ReceiveOutcome::AckReceived { .. }
    ));
}

#[test]
fn removed_or_replaced_contact_leaves_no_outbox_rows() {
    // Suppression : messages et accusés en attente pour Bob disparaissent.
    let (mut a, mut b, mut rng) = pair();
    one(a.send(&b.fp(), "en attente", NOW, &mut rng));
    let q = one(b.send(&a.fp(), "de Bob", NOW, &mut rng));
    expect_msg(a.recv(&q, NOW, &mut rng));
    let carol = Party::new("tel-carol", 5);
    a.core
        .add_contact(&carol.card("Carol"), Some("carol"))
        .unwrap();
    let c = one(a.send(&carol.fp(), "pour Carol", NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 3);
    a.core.remove_contact(&b.fp()).unwrap();
    assert_eq!(a.core.pending_outbox(NOW).unwrap(), vec![c.encode()]);

    // Remplacement par alias : idem pour l'ancien contact.
    let (mut a, mut b, mut rng) = pair();
    one(a.send(&b.fp(), "en attente", NOW, &mut rng));
    let q = one(b.send(&a.fp(), "de Bob", NOW, &mut rng));
    expect_msg(a.recv(&q, NOW, &mut rng));
    assert_eq!(a.core.pending_outbox(NOW).unwrap().len(), 2);
    let mallory = Party::new("tel-mallory", 4);
    a.core
        .add_contact(&mallory.card("Bob"), Some("bob"))
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
    assert!(frames.len() > 60, "{} trames", frames.len());
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
    let text = "secret-très-privé ".repeat(100);
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
    assert!(
        rejected[0].contains("hash de trame incorrect"),
        "{}",
        rejected[0]
    );
    assert!(!rejected[0].contains("secret"));
    assert_eq!(
        rejected[0],
        "Trame rejetée (hash de trame incorrect) : elle ne correspond pas au paquet annoncé. \
         Le paquet n'a pas été reconstitué ; l'expéditeur le renverra."
    );
    // Les trames d'origine aboutissent.
    let mut done = None;
    for f in &frames {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        if !matches!(out, ReceiveOutcome::Partial) {
            done = Some(out);
        }
    }
    let (_, _, got, _) = expect_msg(done.expect("paquet reconstitué"));
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
    // Le plus ancien paquet a été évincé : ses trames restantes ne complètent rien.
    for f in &firsts[0][1..] {
        let out = b.core.receive_frame(f, T, NOW, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
    }

    // Paquet commencé à NOW, fini après le TTL : ne se complète pas.
    let frames = firsts.last().unwrap();
    let late = NOW + 3601;
    for f in &frames[1..] {
        let out = b.core.receive_frame(f, T, late, &mut rng).unwrap();
        assert!(matches!(out, ReceiveOutcome::Partial), "{out:?}");
    }
    // Une trame tardive redémarre une entrée sans planter ; l'ensemble des
    // trames reconstitue alors le paquet.
    let done = frames
        .iter()
        .map(|f| b.core.receive_frame(f, T, late, &mut rng).unwrap())
        .find(|o| !matches!(o, ReceiveOutcome::Partial));
    expect_msg(done.expect("paquet reconstitué"));
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
            0 => f.truncate(i % 10), // trop courte
            1 => f[9] = 0,           // nombre nul
            2 => {
                f[9] = 3;
                f[8] = 3 + (i % 200) as u8; // index hors limites
            }
            _ => f.truncate(10), // fragment vide
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
