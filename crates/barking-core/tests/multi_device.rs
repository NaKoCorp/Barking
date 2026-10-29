//! Multi-appareils : liaison d'un nouvel appareil (offre, demande,
//! acceptation, fin), à deux et trois parties.

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
const T: &str = "fichier";

struct Dev {
    core: Core,
    path: PathBuf,
    key: [u8; 32],
}

/// Un dossier temporaire par test, plusieurs bases dedans.
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
        Err(e) => panic!("CoreError::Link attendue, obtenu {e:?}"),
        Ok(_) => panic!("CoreError::Link attendue, obtenu Ok"),
    }
}

/// A (administrateur) avec deux contacts, Alice et Bob ; Bob vérifié.
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
    // Une mise à jour de carte pour Alice et une pour Bob (un appareil chacun).
    assert_eq!(out.packets.len(), 2);
    // Passage par les octets, comme dans le CLI.
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

    // Journal de chaque côté.
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

    // T rouvert : lié, plus en attente.
    drop(t.core);
    let mut t2 = Core::open(&t.path, &t.key, NOW + 3).unwrap();
    assert_eq!(t2.fingerprint(), a.core.fingerprint());
    assert_eq!(t2.contacts().unwrap().len(), 2);
    // T peut écrire à Alice (un paquet par appareil d'Alice), plus une copie
    // `SyncSent` pour A.
    let pkts = t2
        .send_text(
            &alice.core.fingerprint(),
            "depuis la tablette",
            NOW + 3,
            &mut rng,
        )
        .unwrap();
    assert_eq!(pkts.len(), 2);
    // Une seconde fin de liaison est refusée.
    assert_eq!(
        link_err(t2.finish_link(&bundle, None, NOW + 4)),
        "aucune liaison en attente"
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
    let pkts = alice
        .core
        .send_text(&me, "aux deux", NOW, &mut rng)
        .unwrap();
    assert_eq!(pkts.len(), 2);
    let opened = pkts
        .iter()
        .filter(|p| {
            matches!(
                t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { ref text, .. } if text == "aux deux"
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
    assert!(t.core.watched_mailboxes(NOW).is_empty());

    // Toujours en attente après réouverture.
    drop(t.core);
    let mut t2 = Core::open(&t.path, &t.key, NOW).unwrap();
    assert_eq!(t2.fingerprint(), a.core.fingerprint());
    assert!(matches!(
        t2.send_text(&alice_fp, "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    // Le paquet de liaison d'un autre appareil (autre offre) est refusé.
    let offer2 = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t4, req) = begin(d.path(), "t4", 11, &offer2, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    assert_eq!(
        link_err(t2.finish_link(&out.bundle, None, NOW)),
        "paquet de liaison invalide"
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
        "offre absente ou déjà utilisée"
    );
    assert_eq!(a.core.contact_card("A").unwrap(), card);
    // Sans offre du tout.
    let mut b = create(d.path(), "b", 2, &mut rng);
    assert_eq!(
        link_err(b.core.link_device(&req, false, NOW, &mut rng)),
        "offre absente ou déjà utilisée"
    );
    // Une nouvelle offre remplace l'ancienne : la demande liée à l'ancienne
    // échoue (MAC), celle liée à la nouvelle passe.
    let o1 = a.core.link_offer(NOW, &mut rng).unwrap();
    let o2 = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t1, r1) = begin(d.path(), "t1", 10, &o1, &mut rng);
    let (_t2, r2) = begin(d.path(), "t2", 11, &o2, &mut rng);
    assert_eq!(
        link_err(a.core.link_device(&r1, false, NOW, &mut rng)),
        "MAC invalide"
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

    // MAC modifié, ou champ modifié sous le MAC d'origine.
    for tamper in 0..4 {
        let mut bad = req.clone();
        match tamper {
            0 => bad.mac[0] ^= 1,
            1 => bad.name = "autre".into(),
            2 => bad.issued_at += 1,
            _ => bad.device_sig[0] ^= 1,
        }
        assert_eq!(
            link_err(a.core.link_device(&bad, false, NOW, &mut rng)),
            "MAC invalide",
            "falsification {tamper}"
        );
    }
    // Aucun état modifié : même carte, et l'offre est toujours valable.
    assert_eq!(a.core.contact_card("A").unwrap(), card);

    // Paquet de liaison d'une autre identité : refusé, T reste en attente.
    let offer_b = b.core.link_offer(NOW, &mut rng).unwrap();
    let (_tb, req_b) = begin(d.path(), "tb", 12, &offer_b, &mut rng);
    let other = b.core.link_device(&req_b, false, NOW, &mut rng).unwrap();
    assert_eq!(
        link_err(t.core.finish_link(&other.bundle, None, NOW)),
        "paquet de liaison invalide"
    );
    // Paquet tronqué ou modifié.
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
        "paquet de liaison invalide"
    );
    assert_eq!(
        link_err(LinkBundle::from_bytes(&bytes[..3])),
        "fichier de liaison illisible"
    );
    assert!(matches!(
        t.core.send_text(&b.core.fingerprint(), "x", NOW, &mut rng),
        Err(CoreError::LinkPending)
    ));
    assert!(events(&t.core).is_empty());
    // Le bon paquet passe ensuite.
    t.core.finish_link(&good.bundle, None, NOW).unwrap();

    // Offre expirée (11 minutes plus tard) : refusée, puis effacée.
    let card = a.core.contact_card("A").unwrap();
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t3, req) = begin(d.path(), "t3", 13, &offer, &mut rng);
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW + 11 * 60, &mut rng)),
        "offre expirée"
    );
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW, &mut rng)),
        "offre absente ou déjà utilisée"
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
        "offre expirée"
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
            "fichier de liaison illisible"
        );
        assert_eq!(
            link_err(LinkRequest::from_bytes(garbage)),
            "fichier de liaison illisible"
        );
    }
    // Octets en trop refusés.
    let mut long = offer.to_bytes().to_vec();
    long.push(0);
    assert_eq!(
        link_err(LinkOffer::from_bytes(&long)),
        "fichier de liaison illisible"
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
    let (_t, req) = begin(d.path(), "trop", 99, &offer, &mut rng);
    assert_eq!(
        a.core.link_device(&req, false, NOW, &mut rng).err(),
        Some(CoreError::TooLarge)
    );
    assert_eq!(
        a.core.contact_card("A").unwrap().devices.certs.len(),
        MAX_DEVICES
    );
}

/// A lié à T, sans contact.
fn admin_and_tablet(d: &Path, rng: &mut StdRng) -> (Dev, Dev) {
    let mut a = create(d, "a", 1, rng);
    let offer = a.core.link_offer(NOW, rng).unwrap();
    let (mut t, req) = begin(d, "t", 9, &offer, rng);
    let out = a.core.link_device(&req, false, NOW, rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    (a, t)
}

/// Livre à `to` chaque paquet de la file d'envoi de `from`, puis rend à
/// `from` les accusés de `to`. Renvoie les synchronisations appliquées.
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

    // Un paquet pour Bob, un `SyncSent` pour T, le même identifiant.
    let pkts = a.core.send_text(&bob_fp, "bonjour", NOW, &mut rng).unwrap();
    assert_eq!(pkts.len(), 2);
    let sent = a.core.messages_with(&bob_fp).unwrap();
    assert_eq!(sent.len(), 1);
    let mut on_t = Vec::new();
    for p in &pkts {
        match t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap() {
            ReceiveOutcome::Synced { kind } => on_t.push((kind, p.id)),
            ReceiveOutcome::NotForUs => {}
            other => panic!("inattendu : {other:?}"),
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
        (Direction::Out, "bonjour", sent[0].message_id, NOW)
    );
    assert!(events(&t.core).contains(&TransparencyEvent::SyncApplied {
        kind: SyncKind::Sent
    }));
    // Reçu deux fois : toujours une ligne.
    for p in &pkts {
        let r = t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap();
        assert!(matches!(
            r,
            ReceiveOutcome::Duplicate | ReceiveOutcome::NotForUs
        ));
    }
    assert_eq!(t.core.messages_with(&bob_fp).unwrap().len(), 1);

    // L'accusé de T retire le `SyncSent` de la file de A, mais le message
    // pour Bob n'est pas livré pour autant.
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
    // L'accusé de Bob, lui, le marque livré.
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
fn contact_ops_sync() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(21);
    // Sans autre appareil : aucune synchronisation en file.
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
    // Chaque accusé de T a vidé la file de A.
    assert!(a.core.pending_outbox(NOW).unwrap().is_empty());

    // Dans l'autre sens : une opération sur T arrive sur A.
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
    // `set_alias` : contact inconnu, alias trop long.
    assert_eq!(
        a.core.set_alias(&Fingerprint([9; 32]), "z", NOW, &mut rng),
        Err(CoreError::UnknownContact)
    );
    assert_eq!(
        a.core.set_alias(&carol_fp, &"z".repeat(65), NOW, &mut rng),
        Err(CoreError::TooLarge)
    );
}

/// Paquets de la file de `dev` produits par `op`.
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

    // Ajout puis suppression, livrés à l'envers : la suppression d'un contact
    // inconnu est appliquée (et accusée), l'ajout plus ancien n'y change rien.
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
    // Le même paquet une seconde fois : doublon, rien ne change.
    assert!(matches!(
        deliver(&mut t, &add[0], &mut rng),
        ReceiveOutcome::Duplicate
    ));
    assert!(contact_state(&t.core).is_empty());

    // État vérifié livré avant l'ajout : le contact est vérifié, l'ajout
    // plus ancien ne le dé-vérifie pas.
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
    // La même opération refaite (nouveau paquet) : même état.
    let again = produced(&mut a, |c| {
        c.mark_verified(&dave_fp, NOW + 4, &mut r2).unwrap()
    });
    deliver(&mut t, &again[0], &mut rng);
    assert_eq!(contact_state(&t.core), contact_state(&a.core));

    // Un ajout plus récent que la suppression rend le contact.
    let re = produced(&mut a, |c| {
        c.add_contact(&carol, Some("carol"), NOW + 5, &mut r2)
            .unwrap();
    });
    deliver(&mut t, &re[0], &mut rng);
    assert_eq!(contact_state(&t.core), contact_state(&a.core));
    assert_eq!(contact_state(&t.core).len(), 2);

    // Opérations locales : une suppression sur T (plus récente) l'emporte
    // sur un changement d'alias de A plus ancien, livré ensuite.
    let late = produced(&mut a, |c| {
        c.set_alias(&carol_fp, "c", NOW + 6, &mut r2).unwrap()
    });
    t.core.remove_contact(&carol_fp, NOW + 7, &mut r2).unwrap();
    deliver(&mut t, &late[0], &mut rng);
    assert_eq!(
        contact_state(&t.core),
        vec![(dave_fp, Some("dave".to_owned()), true)]
    );

    // Tous les accusés de T vident la file de A : il n'y reste que l'accusé
    // de la suppression faite sur T.
    for bytes in t.core.pending_outbox(NOW).unwrap() {
        a.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    let left = a.core.pending_outbox(NOW).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(Packet::decode(&left[0]).unwrap().kind, Kind::Ack);
}

/// A et T, avec Carol et Dave connus des deux (ajoutés sur A à `NOW`, copiés
/// sur T).
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
fn same_second_edits_converge() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(30);
    let (mut a, mut t, carol, _) = pair_with_two_contacts(d.path(), &mut rng);
    // Même seconde, deux appareils, deux alias différents pour Carol.
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
    // A donne « z » à Carol ; T, plus tard, donne « z » à Dave.
    let from_a = produced(&mut a, |c| {
        c.set_alias(&carol, "z", NOW + 10, &mut r2).unwrap()
    });
    let from_t = produced(&mut t, |c| {
        c.set_alias(&dave, "z", NOW + 20, &mut r2).unwrap()
    });
    deliver(&mut t, &from_a[0], &mut rng);
    deliver(&mut a, &from_t[0], &mut rng);
    // L'opération la plus récente garde l'alias, partout.
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
    // Plusieurs opérations dans la même seconde : l'horloge du contact avance
    // (NOW + 1, NOW + 2…), mais l'expiration du paquet suit l'horloge murale.
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
        .send_text(&alice_fp, "avant", NOW, &mut rng)
        .unwrap()
        .len();
    assert_eq!(before, 1);

    let offer = alice.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t, req) = begin(d.path(), "t", 9, &offer, &mut rng);
    let out = alice.core.link_device(&req, false, NOW, &mut rng).unwrap();
    t.core.finish_link(&out.bundle, None, NOW).unwrap();
    // Une mise à jour de carte pour l'appareil de Bob ; pas d'autre appareil
    // à moi que T, qui a tout reçu par le paquet de liaison.
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
        o => panic!("CardUpdated attendu, obtenu {o:?}"),
    }
    // Le nom affiché d'Alice est conservé dans la nouvelle carte.
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

    // Bob chiffre désormais aussi pour T.
    let pkts = bob
        .core
        .send_text(&alice_fp, "aux deux", NOW, &mut rng)
        .unwrap();
    assert_eq!(pkts.len(), before + 1);
    let opened = pkts
        .iter()
        .filter(|p| {
            matches!(
                t.core.receive(&p.encode(), T, NOW, &mut rng).unwrap(),
                ReceiveOutcome::Message { ref text, .. } if text == "aux deux"
            )
        })
        .count();
    assert_eq!(opened, 1);
    // L'accusé de Bob retire la mise à jour de la file d'Alice.
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
fn second_link_sends_devices_to_first_tablet() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(41);
    let (mut a, mut t) = admin_and_tablet(d.path(), &mut rng);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (mut t2, req) = begin(d.path(), "t2", 10, &offer, &mut rng);
    let out = a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    // Un `SyncDevices` pour T, rien pour T2 (ni contact).
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
    // T connaît T2 : une opération sur un contact part vers A et T2.
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
    // La plus récente (3 appareils) d'abord, puis l'ancienne (2 appareils).
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
    // Bob chiffre pour les 3 appareils d'Alice.
    assert_eq!(
        bob.core
            .send_text(&alice_fp, "x", NOW, &mut rng)
            .unwrap()
            .len(),
        3
    );
    // Les deux mises à jour sont accusées : elles quittent la file d'Alice.
    for bytes in bob.core.pending_outbox(NOW).unwrap() {
        alice.core.receive(&bytes, T, NOW, &mut rng).unwrap();
    }
    // Seul le `SyncDevices` pour T1 (non relayé ici) reste.
    let left = alice.core.pending_outbox(NOW).unwrap();
    let card_updates_left = updates
        .iter()
        .flatten()
        .filter(|p| left.contains(&p.encode()))
        .count();
    assert_eq!(card_updates_left, 1, "seul le SyncDevices pour T1 reste");
}

/// Vue comparable d'une conversation : identifiant, sens, texte, statut, date.
type MsgView = Vec<([u8; 16], Direction, String, MessageStatus, u64)>;

fn conversation(core: &Core, fp: &Fingerprint) -> MsgView {
    core.messages_with(fp)
        .unwrap()
        .into_iter()
        .map(|m| (m.message_id.0, m.direction, m.body, m.status, m.at))
        .collect()
}

/// A avec trois conversations (Alice, Bob, Carol), dont un message reçu et
/// un message livré, et assez de texte pour plusieurs morceaux de 64 Kio.
/// Rend A, T en attente, l'archive et le paquet de liaison.
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
    // Alice écrit à A ; A lui répond, Alice accuse réception.
    let a_fp = alice
        .core
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"), NOW, rng)
        .unwrap();
    for p in alice.core.send_text(&a_fp, "bonjour A", NOW, rng).unwrap() {
        a.core.receive(&p.encode(), T, NOW, rng).unwrap();
    }
    for p in a
        .core
        .send_text(&alice_fp, "bonjour Alice", NOW + 1, rng)
        .unwrap()
    {
        alice.core.receive(&p.encode(), T, NOW + 1, rng).unwrap();
    }
    for bytes in alice.core.pending_outbox(NOW + 1).unwrap() {
        a.core.receive(&bytes, T, NOW + 1, rng).unwrap();
    }
    // Beaucoup de texte vers Bob et Carol : plusieurs morceaux.
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
    // Passage par les octets, comme dans le CLI.
    let archive = HistoryArchive::from_bytes(&out.history.unwrap().to_bytes()).unwrap();
    assert!(
        archive.chunks.len() >= 2,
        "{} morceaux",
        archive.chunks.len()
    );
    (a, t, out.bundle, archive, vec![alice_fp, bob_fp, carol_fp])
}

/// T toujours en attente : aucun contact, aucun message, aucun événement.
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
    // Dernier événement : l'import, après la fin de liaison.
    let ev = events(&t.core);
    assert_eq!(
        ev.last(),
        Some(&TransparencyEvent::HistoryImported { count: 42 })
    );
    assert!(matches!(
        ev[ev.len() - 2],
        TransparencyEvent::LinkFinished { .. }
    ));
    // Rouvert : l'historique est toujours là.
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
            "historique invalide",
            "coupure {cut}"
        );
        assert_still_pending(&mut t, &fps, &mut rng);
    }
    let empty = HistoryArchive { chunks: Vec::new() };
    assert_eq!(
        link_err(t.core.finish_link(&bundle, Some(&empty), NOW + 31)),
        "historique invalide"
    );
    assert_still_pending(&mut t, &fps, &mut rng);
    // La bonne archive passe ensuite.
    t.core
        .finish_link(&bundle, Some(&archive), NOW + 31)
        .unwrap();
}

#[test]
fn history_duplicate_chunk_refused() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(42);
    let (_a, mut t, bundle, archive, fps) = history_setup(d.path(), &mut rng);
    // Morceau en double ajouté, morceau remplacé par un autre, ordre inversé.
    let mut added = archive.clone();
    added.chunks.insert(1, archive.chunks[1].clone());
    let mut replaced = archive.clone();
    replaced.chunks[1] = archive.chunks[0].clone();
    let mut swapped = archive.clone();
    swapped.chunks.swap(0, 1);
    for bad in [added, replaced, swapped] {
        assert_eq!(
            link_err(t.core.finish_link(&bundle, Some(&bad), NOW + 31)),
            "historique invalide"
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
            "historique invalide"
        );
        assert_still_pending(&mut t, &fps, &mut rng);
    }
    // Archive d'une autre liaison (autre secret) : refusée.
    let offer = a.core.link_offer(NOW + 40, &mut rng).unwrap();
    let (_t2, req) = begin(d.path(), "t2", 10, &offer, &mut rng);
    let other = a.core.link_device(&req, true, NOW + 41, &mut rng).unwrap();
    assert_eq!(
        link_err(
            t.core
                .finish_link(&bundle, other.history.as_ref(), NOW + 31)
        ),
        "historique invalide"
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
