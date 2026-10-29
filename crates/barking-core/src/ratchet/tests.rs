use super::header::{ENC_HEADER_LEN, Header};
use super::*;
use crate::CoreError;
use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::{Rng, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

const AD: &[u8] = b"IK_A || IK_B";
/// Horloge des tests (secondes Unix).
const T0: u64 = 1_800_000_000;

fn pair(rng: &mut ChaCha20Rng, sk: &[u8; 32]) -> (RatchetState, RatchetState) {
    let mut spk = [0u8; 32];
    rng.fill_bytes(&mut spk);
    let spk = StaticSecret::from(spk);
    let spk_pub = PublicKey::from(&spk).to_bytes();
    let alice = RatchetState::init_initiator(sk, spk_pub, rng).unwrap();
    let bob = RatchetState::init_responder(sk, &spk);
    (alice, bob)
}

fn setup(seed: u64) -> (ChaCha20Rng, RatchetState, RatchetState) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (a, b) = pair(&mut rng, &[42u8; 32]);
    (rng, a, b)
}

fn snapshot(s: &RatchetState) -> Vec<u8> {
    postcard::to_allocvec(s).unwrap()
}

fn msg(i: usize) -> Vec<u8> {
    format!("message {i}").into_bytes()
}

#[test]
fn ping_pong_10_rounds() {
    let (mut rng, mut a, mut b) = setup(1);
    for i in 0..10 {
        let m = a.encrypt(&msg(i), AD, &mut rng).unwrap();
        assert_eq!(b.decrypt(&m, AD, T0).unwrap(), msg(i));
        let m = b.encrypt(&msg(100 + i), AD, &mut rng).unwrap();
        assert_eq!(a.decrypt(&m, AD, T0).unwrap(), msg(100 + i));
    }
}

#[test]
fn out_of_order_within_chain() {
    let (mut rng, mut a, mut b) = setup(2);
    let msgs: Vec<_> = (0..5)
        .map(|i| a.encrypt(&msg(i), AD, &mut rng).unwrap())
        .collect();
    for i in [4, 0, 3, 1, 2] {
        assert_eq!(b.decrypt(&msgs[i], AD, T0).unwrap(), msg(i));
    }
    assert!(b.mkskipped.is_empty());
}

#[test]
fn out_of_order_across_ratchet() {
    let (mut rng, mut a, mut b) = setup(3);
    let m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m0, AD, T0).unwrap(), msg(0));
    let r = b.encrypt(&msg(10), AD, &mut rng).unwrap();
    assert_eq!(a.decrypt(&r, AD, T0).unwrap(), msg(10));
    let m2 = a.encrypt(&msg(2), AD, &mut rng).unwrap();
    // Nouvelle clé DH d'Alice reçue avant l'ancien message m1.
    assert_eq!(b.decrypt(&m2, AD, T0).unwrap(), msg(2));
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), msg(1));
    assert!(b.mkskipped.is_empty());
}

#[test]
fn skip_over_max_rejected() {
    let (mut rng, mut a, mut b) = setup(4);
    let msgs: Vec<_> = (0..=1001)
        .map(|i| a.encrypt(&msg(i), AD, &mut rng).unwrap())
        .collect();
    let before = snapshot(&b);
    assert_eq!(b.decrypt(&msgs[1001], AD, T0), Err(CoreError::TooLarge));
    assert_eq!(snapshot(&b), before);
    // Exactement MAX_SKIP d'avance : accepté.
    assert_eq!(b.decrypt(&msgs[1000], AD, T0).unwrap(), msg(1000));
    assert_eq!(b.mkskipped.len(), MAX_SKIP as usize);
    assert_eq!(b.decrypt(&msgs[0], AD, T0).unwrap(), msg(0));
}

#[test]
fn replay_rejected() {
    let (mut rng, mut a, mut b) = setup(5);
    let m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    let m2 = a.encrypt(&msg(2), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m0, AD, T0).unwrap(), msg(0));
    assert!(b.decrypt(&m0, AD, T0).is_err());
    // Rejeu d'une clé sautée.
    assert_eq!(b.decrypt(&m2, AD, T0).unwrap(), msg(2));
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), msg(1));
    let before = snapshot(&b);
    assert!(b.decrypt(&m1, AD, T0).is_err());
    assert!(b.decrypt(&m2, AD, T0).is_err());
    assert_eq!(snapshot(&b), before);
}

#[test]
fn tamper_header_or_body_rejected_state_unchanged() {
    let (mut rng, mut a, mut b) = setup(6);
    let m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    let before = snapshot(&b);
    for i in 0..m0.enc_header.len() {
        let mut bad = m0.clone();
        bad.enc_header[i] ^= 1;
        assert!(b.decrypt(&bad, AD, T0).is_err());
    }
    for i in 0..m0.ct.len() {
        let mut bad = m0.clone();
        bad.ct[i] ^= 1;
        assert!(b.decrypt(&bad, AD, T0).is_err());
    }
    assert!(b.decrypt(&m0, b"autre AD", T0).is_err());
    // Tailles mal formées : erreur, jamais de panique.
    for len in [
        0,
        1,
        23,
        24,
        40,
        ENC_HEADER_LEN - 1,
        ENC_HEADER_LEN + 1,
        200,
    ] {
        let mut bad = m0.clone();
        bad.enc_header.resize(len, 0);
        assert!(b.decrypt(&bad, AD, T0).is_err());
    }
    for len in [0, 1, 15] {
        let mut bad = m0.clone();
        bad.ct.truncate(len);
        assert!(b.decrypt(&bad, AD, T0).is_err());
    }
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), msg(1));
    assert_eq!(b.decrypt(&m0, AD, T0).unwrap(), msg(0));

    // Altération d'un message sauté : la clé sautée n'est pas consommée.
    let m2 = a.encrypt(&msg(2), AD, &mut rng).unwrap();
    let m3 = a.encrypt(&msg(3), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m3, AD, T0).unwrap(), msg(3));
    let before = snapshot(&b);
    let mut bad = m2.clone();
    let last = bad.ct.len() - 1;
    bad.ct[last] ^= 0x80;
    assert!(b.decrypt(&bad, AD, T0).is_err());
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.decrypt(&m2, AD, T0).unwrap(), msg(2));
}

#[test]
fn regression_vector() {
    // R7 : octets produits par CETTE implémentation, figés pour détecter
    // toute dérive involontaire du format (Signal ne publie aucun vecteur
    // pour le double ratchet). Calculé une fois, puis recopié ici.
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (mut a, mut b) = pair(&mut rng, &[7u8; 32]);
    let m = a.encrypt(b"barking", b"ad", &mut rng).unwrap();
    let mut bytes = m.enc_header.clone();
    bytes.extend_from_slice(&m.ct);
    assert_eq!(
        blake3::hash(&bytes).to_hex().as_str(),
        "30fc2eaef4ccbb6ca205becc20d3750e0eaa0c297ffe6f48f1e714b7558a8889"
    );
    assert_eq!(b.decrypt(&m, b"ad", T0).unwrap(), b"barking");
}

#[test]
fn overhead_bound() {
    let (mut rng, mut a, mut b) = setup(8);
    for len in [0usize, 1, 80, 1000] {
        let pt = vec![0xAB; len];
        let m = a.encrypt(&pt, AD, &mut rng).unwrap();
        assert_eq!(m.enc_header.len(), ENC_HEADER_LEN);
        assert_eq!(m.enc_header.len() + m.ct.len() - pt.len(), 96);
        assert_eq!(b.decrypt(&m, AD, T0).unwrap(), pt);
        let r = b.encrypt(&pt, AD, &mut rng).unwrap();
        assert_eq!(r.enc_header.len() + r.ct.len() - pt.len(), 96);
        assert_eq!(a.decrypt(&r, AD, T0).unwrap(), pt);
    }
}

#[test]
fn responder_cannot_send_first() {
    let (mut rng, _a, mut b) = setup(9);
    assert_eq!(
        b.encrypt(b"x", AD, &mut rng).unwrap_err(),
        CoreError::NoSession
    );
}

#[test]
fn zero_dh_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    assert_eq!(
        RatchetState::init_initiator(&[1u8; 32], [0u8; 32], &mut rng).unwrap_err(),
        CoreError::Crypto
    );
    // En-tête valide (bonne clé d'en-tête) mais clé DH d'ordre faible.
    let (_a, mut b) = pair(&mut rng, &[1u8; 32]);
    let h = Header {
        dh: [0u8; 32],
        pn: 0,
        n: 0,
    };
    let bad = RatchetMessage {
        enc_header: h.seal(&b.nhkr, &mut rng),
        ct: vec![0u8; 16],
    };
    let before = snapshot(&b);
    assert_eq!(b.decrypt(&bad, AD, T0), Err(CoreError::Crypto));
    assert_eq!(snapshot(&b), before);
}

#[test]
fn skipped_total_evicts_oldest() {
    let (mut rng, mut a, mut b) = setup(11);
    let mut firsts = Vec::new();
    for round in 0..3 {
        let msgs: Vec<_> = (0..=MAX_SKIP as usize)
            .map(|i| a.encrypt(&msg(i), AD, &mut rng).unwrap())
            .collect();
        assert_eq!(
            b.decrypt(&msgs[MAX_SKIP as usize], AD, T0).unwrap(),
            msg(MAX_SKIP as usize)
        );
        firsts.push(msgs[0].clone());
        let r = b.encrypt(&msg(round), AD, &mut rng).unwrap();
        assert_eq!(a.decrypt(&r, AD, T0).unwrap(), msg(round));
    }
    assert_eq!(b.mkskipped.len(), MAX_SKIPPED_TOTAL);
    // Chaîne la plus ancienne évincée ; les deux plus récentes restent.
    assert!(b.decrypt(&firsts[0], AD, T0).is_err());
    assert_eq!(b.decrypt(&firsts[1], AD, T0).unwrap(), msg(0));
    assert_eq!(b.decrypt(&firsts[2], AD, T0).unwrap(), msg(0));
}

#[test]
fn skipped_keys_expire_after_seven_days() {
    let (mut rng, mut a, mut b) = setup(13);
    let m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    let m2 = a.encrypt(&msg(2), AD, &mut rng).unwrap();
    // m2 d'abord : les clés de m0 et m1 sont mises de côté à T0.
    assert_eq!(b.decrypt(&m2, AD, T0).unwrap(), msg(2));
    assert_eq!(b.mkskipped.len(), 2);
    // Exactement 7 jours : encore utilisable.
    assert_eq!(
        b.decrypt(&m1, AD, T0 + MAX_SKIPPED_AGE_SECS).unwrap(),
        msg(1)
    );
    // Au-delà : la clé est effacée, le message tardif ne se déchiffre plus,
    // et l'état est inchangé (déchiffrement transactionnel).
    let before = snapshot(&b);
    assert_eq!(
        b.decrypt(&m0, AD, T0 + MAX_SKIPPED_AGE_SECS + 1),
        Err(CoreError::Crypto)
    );
    assert_eq!(snapshot(&b), before);
    // Le prochain déchiffrement réussi enregistre la purge.
    let m3 = a.encrypt(&msg(3), AD, &mut rng).unwrap();
    assert_eq!(
        b.decrypt(&m3, AD, T0 + MAX_SKIPPED_AGE_SECS + 1).unwrap(),
        msg(3)
    );
    assert!(b.mkskipped.is_empty());
    // Une horloge revenue en arrière n'efface rien.
    let m4 = a.encrypt(&msg(4), AD, &mut rng).unwrap();
    let m5 = a.encrypt(&msg(5), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m5, AD, T0 + 30 * 86_400).unwrap(), msg(5));
    assert_eq!(b.decrypt(&m4, AD, T0).unwrap(), msg(4));
}

#[test]
fn state_serde_roundtrip_and_debug_hides_secrets() {
    let (mut rng, mut a, mut b) = setup(12);
    let m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), msg(1));
    let mut b2: RatchetState = postcard::from_bytes(&snapshot(&b)).unwrap();
    assert_eq!(b2.decrypt(&m0, AD, T0).unwrap(), msg(0));
    let r = b2.encrypt(&msg(2), AD, &mut rng).unwrap();
    assert_eq!(a.decrypt(&r, AD, T0).unwrap(), msg(2));
    let dbg = format!("{b2:?}");
    assert_eq!(dbg, "RatchetState { ns: 1, nr: 2, pn: 0, skipped: 0, .. }");
}

/// Messages d'une direction : texte attendu et indicateur « déjà déchiffré ».
struct Flight {
    msgs: Vec<(RatchetMessage, Vec<u8>, usize)>,
    pending: Vec<usize>,
}

impl Flight {
    fn new() -> Self {
        Flight {
            msgs: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn send(&mut self, s: &mut RatchetState, round: usize, rng: &mut ChaCha20Rng) {
        let id = self.msgs.len();
        let pt = format!("msg {id} round {round}").into_bytes();
        let m = s.encrypt(&pt, AD, rng).unwrap();
        self.msgs.push((m, pt, round));
        self.pending.push(id);
    }

    /// Livre un message en attente choisi par `choice` ; renvoie son tour.
    fn deliver(&mut self, to: &mut RatchetState, choice: usize) -> usize {
        let id = self.pending.remove(choice % self.pending.len());
        let (m, pt, round) = &self.msgs[id];
        assert_eq!(&to.decrypt(m, AD, T0).unwrap(), pt);
        *round
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn proptest_any_delivery_order(
        seed in any::<u64>(),
        counts in proptest::collection::vec(1usize..=5, 6),
        choices in proptest::collection::vec(any::<usize>(), 64),
    ) {
        let (mut rng, mut a, mut b) = setup(seed);
        let mut ab = Flight::new();
        let mut ba = Flight::new();
        let mut c = choices.into_iter().cycle();
        for round in 0..3 {
            for _ in 0..counts[2 * round] {
                ab.send(&mut a, round, &mut rng);
            }
            // Bob répond après avoir reçu au moins un message de ce tour.
            while ab.deliver(&mut b, c.next().unwrap()) != round {}
            for _ in 0..counts[2 * round + 1] {
                ba.send(&mut b, round, &mut rng);
            }
            while ba.deliver(&mut a, c.next().unwrap()) != round {}
        }
        while !ab.pending.is_empty() {
            ab.deliver(&mut b, c.next().unwrap());
        }
        while !ba.pending.is_empty() {
            ba.deliver(&mut a, c.next().unwrap());
        }
        // Chaque message a été déchiffré une fois ; un second essai échoue.
        for (m, _, _) in &ab.msgs {
            prop_assert!(b.decrypt(m, AD, T0).is_err());
        }
        for (m, _, _) in &ba.msgs {
            prop_assert!(a.decrypt(m, AD, T0).is_err());
        }
        prop_assert!(a.mkskipped.is_empty());
        prop_assert!(b.mkskipped.is_empty());
    }
}

#[test]
fn could_open_matches_decrypt() {
    let (mut rng, mut a, mut b) = setup(77);
    let m = a.encrypt(b"vrai", AD, &mut rng).unwrap();
    let before = snapshot(&b);
    assert!(b.could_open(&m));
    assert_eq!(snapshot(&b), before, "could_open ne modifie rien");
    for _ in 0..1000 {
        let mut enc_header = vec![0u8; ENC_HEADER_LEN];
        rng.fill_bytes(&mut enc_header);
        let junk = RatchetMessage {
            enc_header,
            ct: vec![1; 40],
        };
        assert!(!b.could_open(&junk));
    }
    assert!(!b.could_open(&RatchetMessage {
        enc_header: vec![0; ENC_HEADER_LEN - 1],
        ct: Vec::new(),
    }));
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.decrypt(&m, AD, T0).unwrap(), b"vrai");
}

#[test]
fn could_open_accepts_skipped_chain_header() {
    let (mut rng, mut a, mut b) = setup(78);
    let m0 = a.encrypt(b"0", AD, &mut rng).unwrap();
    let m1 = a.encrypt(b"1", AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), b"1");
    assert!(b.could_open(&m0));
    assert_eq!(b.decrypt(&m0, AD, T0).unwrap(), b"0");
}

#[test]
fn purge_with_clock_behind() {
    let (mut rng, mut a, mut b) = setup(14);
    let _m0 = a.encrypt(&msg(0), AD, &mut rng).unwrap();
    let m1 = a.encrypt(&msg(1), AD, &mut rng).unwrap();
    assert_eq!(b.decrypt(&m1, AD, T0).unwrap(), msg(1));
    assert_eq!(b.mkskipped.len(), 1);
    // Horloge en retard d'un jour : rien n'est retiré, pas de panique.
    assert!(!b.purge_skipped(T0 - 86_400));
    assert_eq!(b.mkskipped.len(), 1);
    // Exactement 7 jours : conservée ; au-delà : retirée.
    assert!(!b.purge_skipped(T0 + MAX_SKIPPED_AGE_SECS));
    assert!(b.purge_skipped(T0 + MAX_SKIPPED_AGE_SECS + 1));
    assert!(b.mkskipped.is_empty());
}
