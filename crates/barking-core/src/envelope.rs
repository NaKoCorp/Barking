//! Envelope with hidden sender.
//!
//! The encrypted content carries no sender identity: the
//! recipient obtains it from the session that decrypts (`Wire::Normal`) or
//! from `InitialMessage::ik` (`Wire::Initial`). The initial message is
//! itself sealed so that relays cannot see the sender's `ik`
//! key.

use core::fmt;

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::contact::ContactCard;
use crate::crypto::aead;
use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::labels;
use crate::handshake::pqxdh::InitialMessage;
use crate::identity::{DeviceKeys, Fingerprint};
use crate::mailbox::MailboxId;
use crate::packet::{DEFAULT_HOPS, DEFAULT_TTL_SECS, Kind, Packet, Tier, ack};
use crate::ratchet::{RatchetMessage, RatchetState};
use crate::{CoreError, Result};

/// Maximum size of a text, in bytes.
pub const MAX_TEXT_LEN: usize = 4000;

/// Content of a message. New variants: always at the end (postcard
/// format, variant index).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Text(String),
    /// Copy of a message I sent to `to` from another of my
    /// devices. The identifier and date are those of the envelope.
    SyncSent {
        to: Fingerprint,
        text: String,
    },
    /// State of one of my contacts after an operation done on another of
    /// my devices (last writer wins, see `core/sync.rs`).
    SyncContact(SyncOp),
    /// New list of my devices: my card, signed by my root, which
    /// carries the list and one key bundle per device.
    SyncDevices {
        card: Box<ContactCard>,
    },
    /// New card of a contact (new device list), sent to
    /// each of its contacts after a linking. Boxed card (size of
    /// the enum); same postcard format as `CardUpdate(ContactCard)`.
    CardUpdate(Box<ContactCard>),
    /// The root key (32-byte seed), sent to one of my devices only: admin
    /// transfer (`core/admin.rs`), with the version of the sender's device
    /// list (the target refuses it while its own list is older). Added last.
    AdminTransfer {
        seed: [u8; 32],
        version: u64,
    },
    /// Request of one of my devices to leave my account, handled by the
    /// administrator (`core/remove.rs`), ignored elsewhere. Added last.
    RemoveMe,
}

/// State of a contact, replayed on my other devices. Idempotent: the same
/// state applied twice changes nothing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncOp {
    /// Contact present with this card, this alias (empty: none) and this
    /// verified status (merged by "or"). Sent by older versions only (see
    /// `UpsertV2`). Boxed card (size of
    /// the enum); same postcard format.
    Upsert {
        card: Box<ContactCard>,
        alias: String,
        verified: bool,
    },
    /// Contact removed (no effect if unknown).
    Remove(Fingerprint),
    /// `Upsert` with the date of the last verification change: the verified
    /// status is its own register, the most recent change wins whatever the
    /// contact's other operations (a device behind on them neither erases
    /// nor loses a mark). Appended last: older devices still read `Upsert`,
    /// whose status counts as unknown (date 0, merged by "or").
    UpsertV2 {
        card: Box<ContactCard>,
        alias: String,
        verified: bool,
        verified_at: u64,
    },
}

/// Encrypted content of a packet. No sender identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub sent_at: u64,
    pub ack_secret: [u8; 16],
    /// Logical identifier of the message, chosen by the sender: the same for
    /// every packet (one per recipient device) and for every resend.
    pub message_id: [u8; 16],
    pub body: Body,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Text(t) => write!(f, "Text(<{} bytes>)", t.len()),
            Body::SyncSent { text, .. } => write!(f, "SyncSent(<{} bytes>)", text.len()),
            Body::SyncContact(op) => write!(f, "SyncContact({op:?})"),
            Body::SyncDevices { card } => {
                write!(f, "SyncDevices(version {})", card.devices.version)
            }
            Body::CardUpdate(card) => {
                write!(f, "CardUpdate(version {})", card.devices.version)
            }
            Body::AdminTransfer { .. } => f.write_str("AdminTransfer(<secret>)"),
            Body::RemoveMe => f.write_str("RemoveMe"),
        }
    }
}

impl fmt::Debug for SyncOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No card, no alias, no fingerprint: only the operation type.
        f.write_str(match self {
            SyncOp::Upsert { .. } => "Upsert",
            SyncOp::Remove(_) => "Remove",
            SyncOp::UpsertV2 { .. } => "UpsertV2",
        })
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

/// Payload of a message packet.
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
    /// Rejects a text longer than [`MAX_TEXT_LEN`] bytes.
    fn check(&self) -> Result<()> {
        match self {
            Body::Text(t) | Body::SyncSent { text: t, .. } if t.len() > MAX_TEXT_LEN => {
                Err(CoreError::TooLarge)
            }
            _ => Ok(()),
        }
    }
}

/// Upper bound of what the `Wire::Initial` payload (the heaviest) adds to
/// the serialized envelope: tag, `ek` (32), sealed initial message
/// (keys, identifiers, 1088-byte ML-KEM ciphertext, AEAD tag,
/// lengths ≈ 1,190), encrypted header (80) and body tag (16),
/// lengths included. Verified by a test on real packets.
pub const MAX_WIRE_OVERHEAD: usize = 1_340;

/// Does the content fit in a single packet (L tier), whatever the
/// session (opening included)? Computed without writing or advancing anything:
/// to be called before `seal`, which would refuse (`TooLarge`) after the fact.
pub fn fits_in_packet(body: &Body) -> bool {
    // Maximum timestamp: the longest variable-length integer.
    let env = Envelope {
        sent_at: u64::MAX,
        ack_secret: [0; 16],
        message_id: [0; 16],
        body: body.clone(),
    };
    postcard::to_allocvec(&env)
        .ok()
        .and_then(|b| b.len().checked_add(MAX_WIRE_OVERHEAD))
        .is_some_and(|len| Tier::fit(len).is_ok())
}

/// Non-zero X25519 output (otherwise weak-order point: non-contributory exchange).
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

/// Seals `init` for `ik_b` with a fresh ephemeral key; returns `(ek, sealed_init)`.
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
    let pt = postcard::to_allocvec(init).map_err(|_| CoreError::Malformed("initial message"))?;
    // Each ephemeral key is new: the (key, nonce) pair is never reused.
    Ok((ek, aead::seal(&key, &nonce, &ek, &pt)))
}

/// Encrypts `env` in the `ratchet` session and wraps it in a message packet.
///
/// With `initial = Some((init, ik_b))`, the packet is a `Wire::Initial`: the
/// PQXDH message is sealed for the recipient's X25519 identity key `ik_b`.
/// On error, `ratchet` has not advanced.
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
        Zeroizing::new(postcard::to_allocvec(env).map_err(|_| CoreError::Malformed("envelope"))?);
    // All fallible checks before advancing the ratchet.
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
    let payload = postcard::to_allocvec(&wire).map_err(|_| CoreError::Malformed("payload"))?;
    let mut tier = Tier::fit(payload.len())?;
    if matches!(wire, Wire::Initial { .. }) && tier == Tier::S {
        // Session opening: never in tier S (not over LoRa).
        tier = Tier::M;
    }
    *ratchet = next;
    Ok(Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: ack::packet_id_for(&env.ack_secret),
        expires_at: sealed_expiry(now),
        mailbox,
        payload,
    })
}

/// Granularity of the expiry of a packet sealed by the core.
pub const EXPIRY_GRANULARITY_SECS: u64 = 600;

/// Expiry of a packet sealed at `now`: `now` + 24 hours, rounded down
/// to 10 minutes (nodes do not see the second of sealing).
/// Saturated at `u32::MAX`.
pub fn sealed_expiry(now: u64) -> u32 {
    match u32::try_from(now.saturating_add(DEFAULT_TTL_SECS)) {
        Ok(e) => {
            let g = EXPIRY_GRANULARITY_SECS as u32;
            e / g * g
        }
        Err(_) => u32::MAX,
    }
}

/// Decodes the payload of a message packet. Rejects extra bytes.
pub fn parse_wire(payload: &[u8]) -> Result<Wire> {
    let (wire, rest) =
        postcard::take_from_bytes(payload).map_err(|_| CoreError::Malformed("payload"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("extra bytes in the payload"));
    }
    Ok(wire)
}

/// Opens the initial message sealed for `me` with the ephemeral key `ek`.
pub fn open_initial(me: &DeviceKeys, ek: &[u8; 32], sealed_init: &[u8]) -> Result<InitialMessage> {
    let dh = nonzero_dh(me.dh(&PublicKey::from(*ek)))?;
    let (key, nonce) = initial_key(&dh)?;
    let pt = Zeroizing::new(aead::open(&key, &nonce, ek, sealed_init)?);
    let (init, rest) =
        postcard::take_from_bytes(&pt).map_err(|_| CoreError::Malformed("initial message"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("extra bytes in the initial message"));
    }
    Ok(init)
}

/// Decrypts `msg` in the `ratchet` session and decodes the envelope.
///
/// Decryption is transactional; once the message is authenticated, the
/// ratchet advances even if the envelope is subsequently rejected (malformed content
/// or text too long), since the message does come from the correspondent.
pub fn open(
    msg: &RatchetMessage,
    ratchet: &mut RatchetState,
    ad: &[u8],
    now: u64,
) -> Result<Envelope> {
    let pt = Zeroizing::new(ratchet.decrypt(msg, ad, now)?);
    decode(&pt)
}

/// Decodes and validates an envelope that is already decrypted and authenticated.
///
/// Separate from [`open`] so that the caller can tell a decryption failure
/// (ratchet unchanged) from authenticated but rejected content (ratchet advanced).
pub fn decode(pt: &[u8]) -> Result<Envelope> {
    let (env, rest): (Envelope, _) =
        postcard::take_from_bytes(pt).map_err(|_| CoreError::Malformed("envelope"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("extra bytes in the envelope"));
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

    /// Opens a real PQXDH session between Alice and Bob, then the two ratchets.
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

    /// Alice sends the Initial, Bob receives it; returns the packet.
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
        // First message as Initial, then reply and exchanges as Normal.
        let e0 = env(&mut s.rng, "hello");
        let p0 = send_initial(&mut s, &e0);
        let Wire::Initial { msg, .. } = parse_wire(&p0.payload).unwrap() else {
            panic!("Initial expected");
        };
        let ad = s.sa.ad.clone();
        assert_eq!(open(&msg, &mut s.b, &ad, NOW).unwrap(), e0);

        for (i, (from_b, text)) in [(true, "hi"), (false, "how are you?"), (true, "yes")]
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
            assert_eq!(
                p.expires_at as u64,
                (NOW + i as u64 + DEFAULT_TTL_SECS) / 600 * 600
            );
            let decoded = Packet::decode(&p.encode()).unwrap();
            let Wire::Normal { msg } = parse_wire(&decoded.payload).unwrap() else {
                panic!("Normal expected");
            };
            assert_eq!(open(&msg, rcv, &ad, NOW).unwrap(), e);
        }
    }

    #[test]
    fn seal_open_roundtrip_initial() {
        let mut s = setup(2);
        let e = env(&mut s.rng, "first message");
        let p = send_initial(&mut s, &e);
        let decoded = Packet::decode(&p.encode()).unwrap();
        let Wire::Initial {
            ek,
            sealed_init,
            msg,
        } = parse_wire(&decoded.payload).unwrap()
        else {
            panic!("Initial expected");
        };
        // The sealing uses its own ephemeral key, distinct from that of the PQXDH.
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
            panic!("Initial expected");
        };
        // Wrong recipient.
        assert_eq!(
            open_initial(&s.alice, &ek, &sealed_init),
            Err(CoreError::Crypto)
        );
        // Tampering with the seal or the ephemeral key (associated data).
        let mut bad = sealed_init.clone();
        bad[0] ^= 1;
        assert_eq!(open_initial(&s.bob, &ek, &bad), Err(CoreError::Crypto));
        let mut bad_ek = ek;
        bad_ek[0] ^= 1;
        assert!(open_initial(&s.bob, &bad_ek, &sealed_init).is_err());
        // Weak-order point: all-zero DH output rejected.
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
        // The ratchet has not advanced.
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
            panic!("Initial expected");
        };
        open(&msg, &mut s.b, &ad, NOW).unwrap();
        let e = env(&mut s.rng, "reply");
        let p1 = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng)
            .unwrap()
            .encode();
        for bytes in [&p0, &p1] {
            assert!(!contains(bytes, &root));
            assert!(!contains(bytes, &dev.dh));
            assert!(!contains(bytes, &dev.sig));
            // Nor the PQXDH ephemeral key, which would link the Initial to the session.
            assert!(!contains(bytes, &s.init.ek));
        }
    }

    #[test]
    fn packet_id_is_ack_hash() {
        let mut s = setup(6);
        let e = env(&mut s.rng, "ack");
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
        // Normal: Bob replies after having received the Initial.
        let e0 = env(&mut s.rng, "x");
        let p0 = send_initial(&mut s, &e0);
        let Wire::Initial { msg, .. } = parse_wire(&p0.payload).unwrap() else {
            panic!("Initial expected");
        };
        open(&msg, &mut s.b, &ad, NOW).unwrap();
        for (len, tier) in [(60, Tier::S), (120, Tier::M)] {
            let e = env(&mut s.rng, &"a".repeat(len));
            let p = seal(&e, &mut s.b, &ad, None, MB, NOW, &mut s.rng).unwrap();
            assert_eq!(p.tier, tier);
            let decoded = Packet::decode(&p.encode()).unwrap();
            let Wire::Normal { msg } = parse_wire(&decoded.payload).unwrap() else {
                panic!("Normal expected");
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
        // 4000 bytes pass.
        let e = env(&mut s.rng, &"a".repeat(MAX_TEXT_LEN));
        let p = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng).unwrap();
        assert_eq!(p.tier, Tier::L);
    }

    #[test]
    fn expiry_rounded_down_to_ten_minutes() {
        let base = 1_800_000_000u64 / 600 * 600;
        for (now, want) in [
            (base, base + DEFAULT_TTL_SECS),
            (base + 1, base + DEFAULT_TTL_SECS),
            (base + 599, base + DEFAULT_TTL_SECS),
            (base + 600, base + 600 + DEFAULT_TTL_SECS),
        ] {
            assert_eq!(u64::from(sealed_expiry(now)), want);
            // Always accepted by a node: in the future, at 24 h + 1 h at most.
            assert!(want > now && want <= now + 25 * 3_600);
        }
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
        // Authentic encrypted content that is not an envelope.
        let msg = s.a.encrypt(b"\xff\xff\xff", &ad, &mut s.rng).unwrap();
        assert!(matches!(
            open(&msg, &mut s.b, &ad, NOW),
            Err(CoreError::Malformed(_))
        ));
        // Wrong associated data.
        let e = env(&mut s.rng, "x");
        let p = seal(&e, &mut s.a, &ad, None, MB, NOW, &mut s.rng).unwrap();
        let Wire::Normal { msg } = parse_wire(&p.payload).unwrap() else {
            panic!("Normal expected");
        };
        assert_eq!(open(&msg, &mut s.b, b"other", NOW), Err(CoreError::Crypto));
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
