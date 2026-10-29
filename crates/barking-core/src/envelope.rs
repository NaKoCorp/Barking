//! Enveloppe à expéditeur caché.
//!
//! Le contenu chiffré ne transporte aucune identité d'expéditeur : le
//! destinataire l'obtient grâce à la session qui déchiffre (`Wire::Normal`) ou
//! grâce à `InitialMessage::ik` (`Wire::Initial`). Le message initial est
//! lui-même scellé pour que les relais ne voient pas la clé `ik` de
//! l'expéditeur.

use core::fmt;

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::labels;
use crate::handshake::pqxdh::InitialMessage;
use crate::identity::DeviceKeys;
use crate::mailbox::MailboxId;
use crate::packet::{DEFAULT_HOPS, Kind, Packet, Tier, ack, default_expiry};
use crate::ratchet::{RatchetMessage, RatchetState};
use crate::{CoreError, Result};

/// Taille maximale d'un texte, en octets.
pub const MAX_TEXT_LEN: usize = 4000;

/// Contenu d'un message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Text(String),
}

/// Contenu chiffré d'un paquet. Aucune identité d'expéditeur.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub sent_at: u64,
    pub ack_secret: [u8; 16],
    /// Identifiant logique du message, choisi par l'expéditeur : le même pour
    /// chaque paquet (un par appareil destinataire) et pour chaque renvoi.
    pub message_id: [u8; 16],
    pub body: Body,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Text(t) => write!(f, "Text(<{} octets>)", t.len()),
        }
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("sent_at", &self.sent_at)
            .field(
                "message_id",
                &data_encoding::HEXLOWER.encode(&self.message_id[..4]),
            )
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// Charge utile d'un paquet de message.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Wire {
    Initial {
        ek: [u8; 32],
        sealed_init: Vec<u8>,
        msg: RatchetMessage,
    },
    Normal {
        msg: RatchetMessage,
    },
}

impl Body {
    /// Refuse un texte de plus de [`MAX_TEXT_LEN`] octets.
    fn check(&self) -> Result<()> {
        match self {
            Body::Text(t) if t.len() > MAX_TEXT_LEN => Err(CoreError::TooLarge),
            Body::Text(_) => Ok(()),
        }
    }
}

/// Sortie X25519 non nulle (sinon point d'ordre faible : échange non contributif).
fn nonzero_dh(dh: [u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let dh = Zeroizing::new(dh);
    if dh.iter().fold(0u8, |acc, b| acc | b) == 0 {
        return Err(CoreError::Crypto);
    }
    Ok(dh)
}

/// `key(32) || nonce(12) = HKDF(None, dh, INITIAL_SEAL)`.
fn initial_key(dh: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, [u8; 12])> {
    let mut okm = Zeroizing::new([0u8; 44]);
    hkdf_sha256(None, dh, labels::INITIAL_SEAL, okm.as_mut())?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

/// Scelle `init` pour `ik_b` avec une éphémère fraîche ; renvoie `(ek, sealed_init)`.
fn seal_initial(
    init: &InitialMessage,
    ik_b: &[u8; 32],
    rng: &mut impl CryptoRng,
) -> Result<([u8; 32], Vec<u8>)> {
    let mut e_bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(e_bytes.as_mut());
    let e_seal = StaticSecret::from(*e_bytes);
    let ek = PublicKey::from(&e_seal).to_bytes();
    let dh = nonzero_dh(e_seal.diffie_hellman(&PublicKey::from(*ik_b)).to_bytes())?;
    let (key, nonce) = initial_key(&dh)?;
    let pt = postcard::to_allocvec(init).map_err(|_| CoreError::Malformed("message initial"))?;
    // Chaque éphémère est neuve : le couple (clé, nonce) n'est jamais réutilisé.
    Ok((ek, aead::seal(&key, &nonce, &ek, &pt)))
}

/// Chiffre `env` dans la session `ratchet` et l'emballe dans un paquet de message.
///
/// Avec `initial = Some((init, ik_b))`, le paquet est un `Wire::Initial` : le
/// message PQXDH est scellé pour la clé d'identité X25519 `ik_b` du destinataire.
/// En cas d'erreur, `ratchet` n'a pas avancé.
pub fn seal(
    env: &Envelope,
    ratchet: &mut RatchetState,
    ad: &[u8],
    initial: Option<(&InitialMessage, &[u8; 32])>,
    mailbox: MailboxId,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Packet> {
    env.body.check()?;
    let pt =
        Zeroizing::new(postcard::to_allocvec(env).map_err(|_| CoreError::Malformed("enveloppe"))?);
    // Toutes les vérifications faillibles avant de faire avancer le ratchet.
    let sealed = initial
        .map(|(init, ik_b)| seal_initial(init, ik_b, rng))
        .transpose()?;
    let mut next = ratchet.clone();
    let msg = next.encrypt(&pt, ad, rng)?;
    let wire = match sealed {
        Some((ek, sealed_init)) => Wire::Initial {
            ek,
            sealed_init,
            msg,
        },
        None => Wire::Normal { msg },
    };
    let payload = postcard::to_allocvec(&wire).map_err(|_| CoreError::Malformed("charge"))?;
    let mut tier = Tier::fit(payload.len())?;
    if matches!(wire, Wire::Initial { .. }) && tier == Tier::S {
        // Ouverture de session : jamais en palier S (pas en LoRa).
        tier = Tier::M;
    }
    *ratchet = next;
    Ok(Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: ack::packet_id_for(&env.ack_secret),
        expires_at: default_expiry(now),
        mailbox,
        payload,
    })
}

/// Décode la charge d'un paquet de message. Refuse les octets en trop.
pub fn parse_wire(payload: &[u8]) -> Result<Wire> {
    let (wire, rest) =
        postcard::take_from_bytes(payload).map_err(|_| CoreError::Malformed("charge"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("octets en trop dans la charge"));
    }
    Ok(wire)
}

/// Ouvre le message initial scellé pour `me` avec la clé éphémère `ek`.
pub fn open_initial(me: &DeviceKeys, ek: &[u8; 32], sealed_init: &[u8]) -> Result<InitialMessage> {
    let dh = nonzero_dh(me.dh(&PublicKey::from(*ek)))?;
    let (key, nonce) = initial_key(&dh)?;
    let pt = Zeroizing::new(aead::open(&key, &nonce, ek, sealed_init)?);
    let (init, rest) =
        postcard::take_from_bytes(&pt).map_err(|_| CoreError::Malformed("message initial"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed(
            "octets en trop dans le message initial",
        ));
    }
    Ok(init)
}

/// Déchiffre `msg` dans la session `ratchet` et décode l'enveloppe.
///
/// Le déchiffrement est transactionnel ; une fois le message authentifié, le
/// ratchet avance même si l'enveloppe est ensuite refusée (contenu mal formé
/// ou texte trop long), car le message vient bien de l'interlocuteur.
pub fn open(
    msg: &RatchetMessage,
    ratchet: &mut RatchetState,
    ad: &[u8],
    now: u64,
) -> Result<Envelope> {
    let pt = Zeroizing::new(ratchet.decrypt(msg, ad, now)?);
    decode(&pt)
}

/// Décode et valide une enveloppe déjà déchiffrée et authentifiée.
///
/// Séparé de [`open`] pour que l'appelant distingue un échec de déchiffrement
/// (ratchet inchangé) d'un contenu authentifié mais refusé (ratchet avancé).
pub fn decode(pt: &[u8]) -> Result<Envelope> {
    let (env, rest): (Envelope, _) =
        postcard::take_from_bytes(pt).map_err(|_| CoreError::Malformed("enveloppe"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("octets en trop dans l'enveloppe"));
    }
    env.body.check()?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::pqxdh::{SessionSecrets, initiate, respond};
    use crate::handshake::prekeys::PrekeySecrets;
    use crate::identity::RootIdentity;
    use crate::packet::DEFAULT_TTL_SECS;
    use chacha20::ChaCha20Rng;
    use proptest::prelude::*;
    use rand_core::SeedableRng;

    const NOW: u64 = 1_800_000_000;
    const MB: MailboxId = MailboxId([9; 16]);

    struct Setup {
        rng: ChaCha20Rng,
        alice_root: RootIdentity,
        alice: DeviceKeys,
        bob: DeviceKeys,
        a: RatchetState,
        b: RatchetState,
        sa: SessionSecrets,
        init: InitialMessage,
    }

    /// Ouvre une vraie session PQXDH entre Alice et Bob, puis les deux ratchets.
    fn setup(seed: u64) -> Setup {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (alice_root, _) = RootIdentity::generate(&mut rng);
        let alice = DeviceKeys::generate(&mut rng);
        let bob = DeviceKeys::generate(&mut rng);
        let mut pre = PrekeySecrets::generate(&mut rng, 1);
        let bundle = pre.bundle(&bob, true);
        let (sa, init) = initiate(&alice, &bundle, &mut rng).unwrap();
        let sb = respond(&bob, &mut pre, &init).unwrap();
        let a = RatchetState::init_initiator(&sa.sk, bundle.spk, &mut rng).unwrap();
        let b = RatchetState::init_responder(&sb.sk, pre.spk());
        Setup {
            rng,
            alice_root,
            alice,
            bob,
            a,
            b,
            sa,
            init,
        }
    }

    fn env(rng: &mut ChaCha20Rng, text: &str) -> Envelope {
        Envelope {
            sent_at: NOW,
            ack_secret: ack::new_secret(rng),
            message_id: [7; 16],
            body: Body::Text(text.to_owned()),
        }
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Alice envoie l'Initial, Bob le reçoit ; renvoie le paquet.
    fn send_initial(s: &mut Setup, e: &Envelope) -> Packet {
        let ik_b = s.bob.public().dh;
        let ad = s.sa.ad.clone();
        seal(
            e,
            &mut s.a,
            &ad,
            Some((&s.init, &ik_b)),
            MB,
            NOW,
            &mut s.rng,
        )
        .unwrap()
    }

    #[test]
    fn seal_open_roundtrip_normal() {
        let mut s = setup(1);
        // Premier message en Initial, puis réponse et échanges en Normal.
        let e0 = env(&mut s.rng, "bonjour");
        let p0 = send_initial(&mut s, &e0);
        let Wire::Initial { msg, .. } = parse_wire(&p0.payload).unwrap() else {
            panic!("Initial attendu");
        };
        let ad = s.sa.ad.clone();
        assert_eq!(open(&msg, &mut s.b, &ad, NOW).unwrap(), e0);

        for (i, (from_b, text)) in [(true, "salut"), (false, "ça va ?"), (true, "oui")]
            .into_iter()
            .enumerate()
        {
            let e = env(&mut s.rng, text);
            let (snd, rcv) = if from_b {
                (&mut s.b, &mut s.a)
            } else {
                (&mut s.a, &mut s.b)
            };
            let p = seal(&e, snd, &ad, None, MB, NOW + i as u64, &mut s.rng).unwrap();
            assert_eq!(p.kind, Kind::Message);
            assert_eq!(p.hops, DEFAULT_HOPS);
            assert_eq!(p.mailbox, MB);
            assert_eq!(p.expires_at as u64, NOW + i as u64 + DEFAULT_TTL_SECS);
            let decoded = Packet::decode(&p.encode()).unwrap();
            let Wire::Normal { msg } = parse_wire(&decoded.payload).unwrap() else {
                panic!("Normal attendu");
            };
            assert_eq!(open(&msg, rcv, &ad, NOW).unwrap(), e);
        }
    }

    #[test]
    fn seal_open_roundtrip_initial() {
        let mut s = setup(2);
        let e = env(&mut s.rng, "premier message");
        let p = send_initial(&mut s, &e);
        let decoded = Packet::decode(&p.encode()).unwrap();
        let Wire::Initial {
            ek,
            sealed_init,
            msg,
        } = parse_wire(&decoded.payload).unwrap()
        else {
            panic!("Initial attendu");
        };
        // Le scellement utilise une éphémère propre, distincte de celle du PQXDH.
        assert_ne!(ek, s.init.ek);
        let init = open_initial(&s.bob, &ek, &sealed_init).unwrap();
        assert_eq!(init, s.init);
        let ad = s.sa.ad.clone();
        assert_eq!(open(&msg, &mut s.b, &ad, NOW).unwrap(), e);
    }

    #[test]
    fn open_initial_rejects_wrong_key_and_tamper() {
        let mut s = setup(3);
        let e = env(&mut s.rng, "x");
        let p = send_initial(&mut s, &e);
        let Wire::Initial {
            ek, sealed_init, ..
        } = parse_wire(&p.payload).unwrap()
        else {
            panic!("Initial attendu");
        };
        // Mauvais destinataire.
        assert_eq!(
            open_initial(&s.alice, &ek, &sealed_init),
            Err(CoreError::Crypto)
        );
        // Altération du scellé ou de la clé éphémère (données associées).
        let mut bad = sealed_init.clone();
        bad[0] ^= 1;
        assert_eq!(open_initial(&s.bob, &ek, &bad), Err(CoreError::Crypto));
        let mut bad_ek = ek;
        bad_ek[0] ^= 1;
        assert!(open_initial(&s.bob, &bad_ek, &sealed_init).is_err());
        // Point d'ordre faible : sortie DH nulle refusée.
        assert_eq!(
            open_initial(&s.bob, &[0u8; 32], &sealed_init),
            Err(CoreError::Crypto)
        );
        assert_eq!(open_initial(&s.bob, &ek, &[]), Err(CoreError::Crypto));
    }

    #[test]
    fn seal_rejects_low_order_recipient_key() {
        let mut s = setup(4);
        let e = env(&mut s.rng, "x");
        let ad = s.sa.ad.clone();
        let snapshot = postcard::to_allocvec(&s.a).unwrap();
        let r = seal(
            &e,
            &mut s.a,
            &ad,
            Some((&s.init, &[0u8; 32])),
            MB,
            NOW,
            &mut s.rng,
        );
        assert_eq!(r, Err(CoreError::Crypto));
        // Le ratchet n'a pas avancé.
        assert_eq!(postcard::to_allocvec(&s.a).unwrap(), snapshot);
    }

    #[test]
    fn packet_hides_sender() {
        let mut s = setup(5);
        let root = s.alice_root.public().0;
        let dev = s.alice.public();
        let ad = s.sa.ad.clone();
        let e = env(&mut s.rng, "secret");
        let p0 = send_initial(&mut s, &e).encode();
        let Wire::Initial { msg, .. } = parse_wire(&Packet::decode(&p0).unwrap().payload).unwrap()
        else {
            panic!("Initial attendu");
        };
        open(&msg, &mut s.b, &ad, NOW).unwrap();
        let e = env(&mut s.rng, "réponse");
        let p1 = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng)
            .unwrap()
            .encode();
        for bytes in [&p0, &p1] {
            assert!(!contains(bytes, &root));
            assert!(!contains(bytes, &dev.dh));
            assert!(!contains(bytes, &dev.sig));
            // Ni l'éphémère du PQXDH, qui relierait l'Initial à la session.
            assert!(!contains(bytes, &s.init.ek));
        }
    }

    #[test]
    fn packet_id_is_ack_hash() {
        let mut s = setup(6);
        let e = env(&mut s.rng, "accusé");
        let p = send_initial(&mut s, &e);
        assert_eq!(p.id, ack::packet_id_for(&e.ack_secret));
        assert!(ack::verify(&p.id, &e.ack_secret));
    }

    #[test]
    fn initial_goes_to_tier_l() {
        let mut s = setup(7);
        let e = env(&mut s.rng, "x");
        let p = send_initial(&mut s, &e);
        assert_eq!(p.tier, Tier::L);
    }

    #[test]
    fn short_text_tier_s() {
        let mut s = setup(8);
        let ad = s.sa.ad.clone();
        // Normal : Bob répond après avoir reçu l'Initial.
        let e0 = env(&mut s.rng, "x");
        let p0 = send_initial(&mut s, &e0);
        let Wire::Initial { msg, .. } = parse_wire(&p0.payload).unwrap() else {
            panic!("Initial attendu");
        };
        open(&msg, &mut s.b, &ad, NOW).unwrap();
        for (len, tier) in [(60, Tier::S), (120, Tier::M)] {
            let e = env(&mut s.rng, &"a".repeat(len));
            let p = seal(&e, &mut s.b, &ad, None, MB, NOW, &mut s.rng).unwrap();
            assert_eq!(p.tier, tier);
            let decoded = Packet::decode(&p.encode()).unwrap();
            let Wire::Normal { msg } = parse_wire(&decoded.payload).unwrap() else {
                panic!("Normal attendu");
            };
            assert_eq!(open(&msg, &mut s.a, &ad, NOW).unwrap(), e);
        }
    }

    #[test]
    fn text_over_4000_rejected() {
        let mut s = setup(9);
        let ad = s.sa.ad.clone();
        let snapshot = postcard::to_allocvec(&s.a).unwrap();
        let e = env(&mut s.rng, &"a".repeat(MAX_TEXT_LEN + 1));
        assert_eq!(
            seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng),
            Err(CoreError::TooLarge)
        );
        assert_eq!(postcard::to_allocvec(&s.a).unwrap(), snapshot);
        // 4000 octets passent.
        let e = env(&mut s.rng, &"a".repeat(MAX_TEXT_LEN));
        let p = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng).unwrap();
        assert_eq!(p.tier, Tier::L);
    }

    #[test]
    fn expiry_saturates() {
        let mut s = setup(10);
        let ad = s.sa.ad.clone();
        let e = env(&mut s.rng, "x");
        let p = seal(&e, &mut s.a, &ad, None, MB, u64::MAX, &mut s.rng).unwrap();
        assert_eq!(p.expires_at, u32::MAX);
    }

    #[test]
    fn open_rejects_garbage_plaintext_and_wrong_ad() {
        let mut s = setup(11);
        let ad = s.sa.ad.clone();
        // Contenu chiffré authentique mais qui n'est pas une enveloppe.
        let msg = s.a.encrypt(b"\xff\xff\xff", &ad, &mut s.rng).unwrap();
        assert!(matches!(
            open(&msg, &mut s.b, &ad, NOW),
            Err(CoreError::Malformed(_))
        ));
        // Mauvaises données associées.
        let e = env(&mut s.rng, "x");
        let p = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng).unwrap();
        let Wire::Normal { msg } = parse_wire(&p.payload).unwrap() else {
            panic!("Normal attendu");
        };
        assert_eq!(open(&msg, &mut s.b, b"autre", NOW), Err(CoreError::Crypto));
        assert_eq!(open(&msg, &mut s.b, &ad, NOW).unwrap(), e);
    }

    #[test]
    fn open_rejects_oversized_text() {
        let mut s = setup(12);
        let ad = s.sa.ad.clone();
        let e = env(&mut s.rng, &"a".repeat(MAX_TEXT_LEN + 1));
        let pt = postcard::to_allocvec(&e).unwrap();
        let msg = s.a.encrypt(&pt, &ad, &mut s.rng).unwrap();
        assert_eq!(open(&msg, &mut s.b, &ad, NOW), Err(CoreError::TooLarge));
    }

    #[test]
    fn parse_wire_rejects_trailing_and_empty() {
        let mut s = setup(13);
        let ad = s.sa.ad.clone();
        let e = env(&mut s.rng, "x");
        let p = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng).unwrap();
        let mut bytes = p.payload.clone();
        bytes.push(0);
        assert!(matches!(parse_wire(&bytes), Err(CoreError::Malformed(_))));
        assert!(matches!(parse_wire(&[]), Err(CoreError::Malformed(_))));
        assert!(matches!(parse_wire(&[7]), Err(CoreError::Malformed(_))));
    }

    proptest! {
        #[test]
        fn proptest_parse_wire_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let _ = parse_wire(&bytes);
        }

        #[test]
        fn proptest_open_initial_never_panics(
            ek in any::<[u8; 32]>(),
            sealed in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut rng = ChaCha20Rng::seed_from_u64(0);
            let me = DeviceKeys::generate(&mut rng);
            prop_assert!(open_initial(&me, &ek, &sealed).is_err());
        }
    }
}
