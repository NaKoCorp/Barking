//! Tests internes de la façade : paquets authentifiés mais refusés, forgés
//! avec l'état réel d'une session (impossible depuis l'API publique).

use super::*;
use crate::envelope::{Body, Envelope, Wire};
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
    // L'état avancé du ratchet est sauvegardé, le paquet marqué vu.
    assert_ne!(best_session(&p.b).state, before);
    assert!(matches!(
        p.b.receive(&bad.encode(), "t", NOW, &mut p.rng).unwrap(),
        ReceiveOutcome::Duplicate
    ));
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
        a.store.delete_sessions_for_device(b_dev).unwrap();
        let t = NOW + i * 10;
        let p = a.send_text(&b.fingerprint(), "x", t, &mut rng).unwrap();
        ids.push(a.store.sessions_for(b_dev).unwrap()[0].session_id);
        assert!(matches!(
            b.receive(&p[0].encode(), "t", t, &mut rng).unwrap(),
            ReceiveOutcome::Message { .. }
        ));
    }
    let kept: Vec<[u8; 16]> = b
        .store
        .sessions_for(a_dev)
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
