//! Multi-appareils : liaison d'un nouvel appareil (offre, demande,
//! acceptation, fin), à deux et trois parties.

use std::path::{Path, PathBuf};

use barking_core::core::{LinkBundle, LinkOffer};
use barking_core::transparency::TransparencyEvent;
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
        .add_contact(&alice.core.contact_card("Alice").unwrap(), Some("alice"))
        .unwrap();
    let bob_fp = a
        .core
        .add_contact(&bob.core.contact_card("Bob").unwrap(), None)
        .unwrap();
    a.core.mark_verified(&bob_fp).unwrap();
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
    assert!(out.packets.is_empty());
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
    // T peut écrire à Alice (un paquet par appareil d'Alice).
    let pkts = t2
        .send_text(
            &alice.core.fingerprint(),
            "depuis la tablette",
            NOW + 3,
            &mut rng,
        )
        .unwrap();
    assert_eq!(pkts.len(), 1);
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
        .add_contact(&a.core.contact_card("A").unwrap(), Some("a"))
        .unwrap();
    t.core
        .add_contact(&alice.core.contact_card("Alice").unwrap(), Some("alice"))
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
        t.core
            .add_contact(&alice.core.contact_card("Alice").unwrap(), None),
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
    // Offre expirée (11 minutes plus tard).
    assert_eq!(
        link_err(a.core.link_device(&req, false, NOW + 11 * 60, &mut rng)),
        "offre expirée"
    );
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
fn link_refuses_seventeenth_device() {
    let d = dir();
    let mut rng = StdRng::seed_from_u64(10);
    let mut a = create(d.path(), "a", 1, &mut rng);
    for i in 0..15u8 {
        let offer = a.core.link_offer(NOW, &mut rng).unwrap();
        let (_t, req) = begin(d.path(), &format!("t{i}"), 20 + i, &offer, &mut rng);
        a.core.link_device(&req, false, NOW, &mut rng).unwrap();
    }
    assert_eq!(a.core.contact_card("A").unwrap().devices.certs.len(), 16);
    let offer = a.core.link_offer(NOW, &mut rng).unwrap();
    let (_t, req) = begin(d.path(), "t16", 99, &offer, &mut rng);
    assert_eq!(
        a.core.link_device(&req, false, NOW, &mut rng).err(),
        Some(CoreError::TooLarge)
    );
    assert_eq!(a.core.contact_card("A").unwrap().devices.certs.len(), 16);
}
