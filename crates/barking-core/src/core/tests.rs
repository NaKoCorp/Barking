//! Tests internes de la façade : paquets authentifiés mais refusés, forgés
//! avec l'état réel d'une session (impossible depuis l'API publique).

use super::*;
use crate::contact::ContactCard;
use crate::envelope::{Body, Envelope, Wire};
use crate::handshake::PrekeyBundle;
use crate::identity::{DeviceCertificate, DeviceKeys, DeviceList, DevicePublic, RootIdentity};
use crate::mailbox::day_of;
use crate::packet::{DEFAULT_HOPS, Kind, Tier, ack};
use crate::store::SessionRow;
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

/// Alice et Bob avec une session établie dans les deux sens (plus d'Initial).
fn pair() -> Pair {
    let (da, mut a) = party("a", 1);
    let (db, mut b) = party("b", 2);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"))
        .unwrap();
    b.add_contact(&a.contact_card("Alice").unwrap(), Some("alice"))
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

/// Chiffre `pt` brut dans la meilleure session de `from` (état sauvegardé),
/// emballé en `Wire::Normal` vers la boîte de session du pair.
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
        body: Body::Text(text.into()),
    })
    .unwrap()
}

fn reason(o: ReceiveOutcome) -> String {
    match o {
        ReceiveOutcome::Quarantined { reason } => reason,
        other => panic!("Quarantined attendu, obtenu {other:?}"),
    }
}

#[test]
fn authenticated_malformed_envelope_keeps_ratchet_and_quarantines() {
    let mut p = pair();
    let before = best_session(&p.b).state.clone();
    let id = PacketId([7; 16]);
    let bad = forge(&mut p.a, &[0xff, 0xff, 0xff], id, &mut p.rng);
    let r = reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap());
    assert_eq!(r, "contenu authentifié mais mal formé");
    // L'état avancé du ratchet est sauvegardé : un rejeu ne se déchiffre plus.
    // (Sans secret d'accusé authentifié, rien n'est marqué vu.)
    assert_ne!(best_session(&p.b).state, before);
    assert_eq!(
        reason(p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap()),
        "déchiffrement impossible"
    );
    // Rien n'apparaît dans l'historique, et la conversation continue.
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
    // Le journal ne contient que des raisons fixes.
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
    assert_eq!(r, "identifiant de paquet incohérent");
}

#[test]
fn contact_reusing_my_packet_id_is_quarantined_not_err() {
    // Bob connaît le secret d'accusé de mon message : il pourrait forger un
    // message portant le même identifiant (colonne UNIQUE en base).
    let mut p = pair();
    let mine =
        p.a.send_text(&p.b.fingerprint(), "à Bob", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let ReceiveOutcome::Message { ack: ack_pkt, .. } =
        p.b.receive(&mine.encode(), "t", NOW, &mut p.rng).unwrap()
    else {
        panic!("Message attendu");
    };
    let mut secret = [0u8; 16];
    secret.copy_from_slice(&ack_pkt.payload[16..32]);
    let env = envelope_bytes(secret, NOW, "piège");
    let evil = forge(&mut p.b, &env, mine.id, &mut p.rng);
    let out = p.a.receive(&evil.encode(), "t", NOW, &mut p.rng);
    assert_eq!(reason(out.unwrap()), "identifiant de paquet déjà utilisé");
}

#[test]
fn stale_or_future_sent_at_quarantined() {
    let mut p = pair();
    for sent_at in [NOW - MAX_AGE_SECS - 1, NOW + MAX_FUTURE_SECS + 1] {
        let secret = ack::new_secret(&mut p.rng);
        let env = envelope_bytes(secret, sent_at, "x");
        let pkt = forge(&mut p.a, &env, ack::packet_id_for(&secret), &mut p.rng);
        let r = reason(p.b.receive(&pkt.encode(), "t", NOW, &mut p.rng).unwrap());
        assert_eq!(r, "message trop ancien ou daté du futur");
    }
    // Aux limites exactes, le message passe.
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
    a.add_contact(&b.contact_card("Bob").unwrap(), None)
        .unwrap();
    b.add_contact(&a.contact_card("Alice").unwrap(), None)
        .unwrap();
    let a_dev = a.device.public().id();
    let b_dev = b.device.public().id();
    let mut rng = StdRng::seed_from_u64(3);
    let mut ids = Vec::new();
    for i in 0..3u64 {
        // Alice oublie ses sessions : elle en rouvre une nouvelle.
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
    assert!(!kept.contains(&ids[0]), "la plus ancienne est supprimée");
    assert!(kept.contains(&ids[1]) && kept.contains(&ids[2]));
}

#[test]
fn seen_rows_are_purged_after_retention() {
    let mut p = pair();
    let old = PacketId([1; 16]);
    p.b.store.mark_seen(old, NOW).unwrap();
    let later = NOW + SEEN_RETENTION_SECS + 1;
    // N'importe quel paquet pour une boîte surveillée déclenche la purge.
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
    a.add_contact(&b.contact_card("Bob").unwrap(), None)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(5);
    let p = a.send_text(&b.fingerprint(), "x", NOW, &mut rng).unwrap();
    let row = best_session(&a);
    let init = de_init(row.pending_initial.as_deref().unwrap()).unwrap();
    assert_eq!(row.session_id, session_id(&init.ek));
    let Wire::Initial { ek: seal_ek, .. } = crate::envelope::parse_wire(&p[0].payload).unwrap()
    else {
        panic!("Initial attendu");
    };
    assert_ne!(seal_ek, init.ek, "l'éphémère de scellement est distincte");
}

#[test]
fn relay_rewritten_id_does_not_suppress_genuine_packet() {
    // Un relais recopie l'identifiant de P2 dans l'en-tête de P1.
    let mut p = pair();
    let p1 =
        p.a.send_text(&p.b.fingerprint(), "un", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let p2 =
        p.a.send_text(&p.b.fingerprint(), "deux", NOW, &mut p.rng)
            .unwrap()
            .remove(0);
    let mut evil = p1.clone();
    evil.id = p2.id;
    assert_eq!(
        reason(p.b.receive(&evil.encode(), "t", NOW, &mut p.rng).unwrap()),
        "identifiant de paquet incohérent"
    );
    // L'identifiant authentifié (celui de P1) est marqué vu, pas celui de P2.
    assert!(p.b.store.is_seen(p1.id).unwrap());
    assert!(!p.b.store.is_seen(p2.id).unwrap());
    match p.b.receive(&p2.encode(), "t", NOW, &mut p.rng).unwrap() {
        ReceiveOutcome::Message { text, .. } => assert_eq!(text, "deux"),
        other => panic!("Message attendu, obtenu {other:?}"),
    }
}

/// Carte de Mallory dont l'unique appareil associe SA clé de signature à la
/// clé X25519 `dh` d'un tiers. Certificat et carte sont valides : la preuve
/// de possession ne couvre que la clé de signature.
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
    let card = ContactCard::sign(&mroot, "Alice", list, bundles).unwrap();
    card.verify().unwrap();
    card
}

#[test]
fn card_sharing_a_contacts_dh_key_rejected() {
    let mut p = pair();
    let alice_dev = p.a.device.public();
    let card = mixed_card(&alice_dev, None, &mut p.rng);
    assert_eq!(
        p.b.add_contact(&card, Some("mallory")),
        Err(CoreError::Malformed(
            "appareil déjà associé à un autre contact"
        ))
    );
    // Ni sous l'alias d'Alice (changement de clé simulé).
    assert!(p.b.add_contact(&card, Some("alice")).is_err());
    assert_eq!(p.b.contacts().unwrap().len(), 1);
    // Ma propre clé non plus.
    let mine = mixed_card(&p.b.device.public(), None, &mut p.rng);
    assert!(p.b.add_contact(&mine, Some("moi")).is_err());
}

#[test]
fn ambiguous_sender_never_misattributed() {
    // Défense en profondeur : même si la carte de Mallory avait été stockée
    // (vérification d'ajout contournée), l'Initial d'Alice n'est pas attribué à Mallory.
    let (_da, mut a) = party("a", 1);
    let (_db, mut b) = party("b", 2);
    a.add_contact(&b.contact_card("Bob").unwrap(), Some("bob"))
        .unwrap();
    b.add_contact(&a.contact_card("Alice").unwrap(), Some("zz-alice"))
        .unwrap();
    let mut rng = StdRng::seed_from_u64(31);
    let card = mixed_card(&a.device.public(), None, &mut rng);
    // Alias trié en premier : l'ancien code l'aurait choisi.
    b.store
        .upsert_contact(
            card.fingerprint(),
            &postcard::to_allocvec(&card).unwrap(),
            "aa-mallory",
            false,
        )
        .unwrap();
    let p = a
        .send_text(&b.fingerprint(), "de la part d'Alice", NOW, &mut rng)
        .unwrap();
    assert_eq!(
        reason(b.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap()),
        "expéditeur ambigu"
    );
    assert!(b.messages_with(&card.fingerprint()).unwrap().is_empty());
}

#[test]
fn session_to_mixed_device_fails_at_its_real_owner() {
    // Carol ne connaît pas Alice : elle accepte la carte « mixte » de Mallory
    // (clé dh d'Alice). Son Initial arrive chez Alice, qui connaît Carol. Les
    // identifiants d'appareil liés aux données associées font échouer le
    // déchiffrement : Alice ne prend pas pour elle un message destiné à Mallory,
    // et ne peut pas y répondre dans une session que Carol attribuerait à Mallory.
    let (_da, mut alice) = party("a", 1);
    let (_dc, mut carol) = party("c", 3);
    alice
        .add_contact(&carol.contact_card("Carol").unwrap(), Some("carol"))
        .unwrap();
    let mut rng = StdRng::seed_from_u64(32);
    let alice_card = alice.contact_card("Alice").unwrap();
    let card = mixed_card(
        &alice.device.public(),
        Some(&alice_card.bundles[0]),
        &mut rng,
    );
    let mallory = carol.add_contact(&card, Some("mallory")).unwrap();
    let p = carol
        .send_text(&mallory, "pour Mallory", NOW, &mut rng)
        .unwrap();
    assert!(alice.watched_mailboxes(NOW).contains(&p[0].mailbox));
    assert_eq!(
        reason(alice.receive(&p[0].encode(), "t", NOW, &mut rng).unwrap()),
        "déchiffrement impossible"
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
    p.a.remove_contact(&bob).unwrap();
    assert!(p.a.contacts().unwrap().is_empty());
    assert_eq!(p.a.resolve("bob"), Err(CoreError::UnknownContact));
    assert!(p.a.store.get_contact(bob).unwrap().is_none());
    assert!(p.a.store.all_sessions().unwrap().is_empty());
    assert!(!p.a.messages_with(&bob).unwrap().is_empty());
    // Inconnu : erreur, rien n'est cassé.
    assert_eq!(p.a.remove_contact(&bob), Err(CoreError::UnknownContact));
    // On peut le rajouter, puis lui écrire (nouvelle session).
    p.a.add_contact(&p.b.contact_card("Bob").unwrap(), Some("bob"))
        .unwrap();
    let out = p.a.send_text(&bob, "retour", NOW, &mut p.rng).unwrap();
    assert!(matches!(
        p.b.receive(&out[0].encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Message { .. }
    ));
}
