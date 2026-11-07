//! Sealed wake tokens and push subscription types.
//!
//! A client seals its APNs token to a relay's X25519 key: the node that stores
//! the subscription never sees the token, only the relay can open it. Sealed
//! layout (frozen): `[2 (version)] [key_id] [ephemeral public key, 32]
//! [ChaCha20-Poly1305(postcard(WakeToken)), zero nonce]`. The AEAD key is
//! HKDF-SHA256(empty salt, IKM = X25519 shared secret,
//! info = `SEAL_CONTEXT || ephemeral || relay_public`). The key is unique per
//! seal (fresh ephemeral), hence the zero nonce.

use std::net::{IpAddr, SocketAddr};

use barking_packet::MailboxId;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::node_id::NodeId;
use crate::record::routable;

/// Maximum size of a sealed token.
pub const MAX_SEALED: usize = 160;
/// Maximum size of an APNs device token.
pub const MAX_APNS_TOKEN: usize = 64;
/// HKDF context of the sealing key.
pub const SEAL_CONTEXT: &str = "barking/v0/push-seal";
/// BLAKE3 context of the subscription proof of work.
pub const SUBSCRIBE_POW_CONTEXT: &str = "barking/v0/subscribe";
/// Maximum length of a relay host name.
pub const MAX_RELAY_HOST: usize = 253;

const SEAL_VERSION: u8 = 2;
const HEADER_LEN: usize = 2 + 32;

/// Where a relay is reached, and which node identity it must present.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayRef {
    pub host: String,
    pub port: u16,
    pub id: NodeId,
}

impl RelayRef {
    /// Syntax check: non-zero port; an IP literal (bare or bracketed IPv6) must
    /// be routable; otherwise a DNS name of 1 to 253 ASCII letters, digits, `.`
    /// and `-` with no empty label.
    pub fn well_formed(&self) -> bool {
        if self.port == 0 || self.host.is_empty() || self.host.len() > MAX_RELAY_HOST {
            return false;
        }
        let bare = self
            .host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&self.host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return routable(&SocketAddr::new(ip, self.port));
        }
        self.host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && self.host.split('.').all(|label| !label.is_empty())
    }
}

/// APNs environment the device token belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApnsEnv {
    Sandbox,
    Production,
}

/// Why a device is woken. Travels sealed: neither the node nor the relay
/// operator learns it from the subscription.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WakeReason {
    /// A message is waiting for the device.
    Message = 0,
    /// A delivery receipt (or a failure) concerns a message the device sent.
    Receipt = 1,
}

/// What a subscription wakes its mailbox for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubKind {
    /// Wake when a message is deposited in the mailbox.
    Messages = 0,
    /// Wake when an acknowledgement arrives or a packet expires unacked.
    Acks = 1,
}

/// What a relay needs to wake one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeToken {
    pub apns_token: Vec<u8>,
    pub env: ApnsEnv,
    /// Collapse label sent as the APNs collapse identifier.
    pub collapse: [u8; 16],
    pub expires_day: u32,
    pub reason: WakeReason,
}

fn aead(shared: &[u8; 32], ephemeral: &[u8; 32], relay_public: &[u8; 32]) -> ChaCha20Poly1305 {
    let mut info = Vec::with_capacity(SEAL_CONTEXT.len() + 64);
    info.extend_from_slice(SEAL_CONTEXT.as_bytes());
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(relay_public);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    ChaCha20Poly1305::new(&Key::from(key))
}

/// Seals `token` to `relay_public` with a fresh ephemeral key.
///
/// Panics if the APNs token exceeds `MAX_APNS_TOKEN`: a caller bug.
pub fn seal(
    relay_public: &[u8; 32],
    key_id: u8,
    token: &WakeToken,
    rng: &mut impl CryptoRng,
) -> Vec<u8> {
    let mut ephemeral = [0u8; 32];
    rng.fill_bytes(&mut ephemeral);
    seal_with_ephemeral(relay_public, key_id, token, ephemeral)
}

/// Deterministic `seal` (test vectors).
pub fn seal_with_ephemeral(
    relay_public: &[u8; 32],
    key_id: u8,
    token: &WakeToken,
    ephemeral: [u8; 32],
) -> Vec<u8> {
    assert!(
        token.apns_token.len() <= MAX_APNS_TOKEN,
        "APNs token longer than {MAX_APNS_TOKEN} bytes"
    );
    let secret = StaticSecret::from(ephemeral);
    let ephemeral_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(*relay_public));
    let plain = postcard::to_allocvec(token).expect("a wake token always encodes");
    let cipher = aead(shared.as_bytes(), &ephemeral_public, relay_public)
        .encrypt(&Nonce::default(), plain.as_slice())
        .expect("encrypting in memory cannot fail");
    let mut out = Vec::with_capacity(HEADER_LEN + cipher.len());
    out.push(SEAL_VERSION);
    out.push(key_id);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&cipher);
    out
}

/// Opens a sealed token with the relay key published under its `key_id`.
/// `None` for an unknown version or key, an oversized blob, a failed
/// authentication or an APNs token that is too long.
pub fn open(keys: &[(u8, StaticSecret)], sealed: &[u8]) -> Option<WakeToken> {
    if sealed.len() > MAX_SEALED || sealed.len() <= HEADER_LEN || sealed[0] != SEAL_VERSION {
        return None;
    }
    let (_, secret) = keys.iter().find(|(id, _)| *id == sealed[1])?;
    let ephemeral: [u8; 32] = sealed[2..HEADER_LEN].try_into().ok()?;
    let relay_public = PublicKey::from(secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    let plain = aead(shared.as_bytes(), &ephemeral, &relay_public)
        .decrypt(&Nonce::default(), &sealed[HEADER_LEN..])
        .ok()?;
    let token: WakeToken = postcard::from_bytes(&plain).ok()?;
    (token.apns_token.len() <= MAX_APNS_TOKEN).then_some(token)
}

/// A wake subscription stored by a node on behalf of a mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub mailbox: MailboxId,
    pub relay: RelayRef,
    pub sealed: Vec<u8>,
    pub cancel_hash: [u8; 32],
    pub expires_day: u32,
    pub kind: SubKind,
}

/// Content fingerprint of a subscription, to feed `pow::check`.
pub fn subscription_hash(sub: &Subscription) -> [u8; 32] {
    let bytes = postcard::to_allocvec(sub).expect("a subscription always encodes");
    blake3::derive_key(SUBSCRIBE_POW_CONTEXT, &bytes)
}

/// Hash of the cancel secret, stored in the subscription.
pub fn cancel_hash(secret: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(secret).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand::SeedableRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn token() -> WakeToken {
        WakeToken {
            apns_token: vec![0xab; 32],
            env: ApnsEnv::Sandbox,
            collapse: [5; 16],
            expires_day: 20_000,
            reason: WakeReason::Message,
        }
    }

    fn sample_subscription() -> Subscription {
        Subscription {
            mailbox: MailboxId([1; 16]),
            relay: RelayRef {
                host: "push.example.org".into(),
                port: 443,
                id: NodeId([2; 32]),
            },
            sealed: vec![3; 100],
            cancel_hash: [4; 32],
            expires_day: 20_000,
            kind: SubKind::Messages,
        }
    }

    fn keypair(seed: u8) -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::from([seed; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (sk, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let t = token();
        let sealed = seal(&pk, 3, &t, &mut rng);
        assert_eq!(open(&[(3, sk)], &sealed), Some(t));
    }

    #[test]
    fn kind_is_covered_by_the_subscription_hash() {
        let mut s = sample_subscription();
        let a = subscription_hash(&s);
        s.kind = SubKind::Acks;
        assert_ne!(a, subscription_hash(&s));
    }

    #[test]
    fn reason_survives_seal_and_open() {
        let (sk, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(10);
        let mut t = token();
        t.reason = WakeReason::Receipt;
        let sealed = seal(&pk, 3, &t, &mut rng);
        let opened = open(&[(3, sk)], &sealed).expect("opens");
        assert_eq!(opened.reason, WakeReason::Receipt);
        assert_eq!(opened, t);
    }

    #[test]
    fn seal_version_1_is_refused() {
        let (sk, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let mut sealed = seal(&pk, 3, &token(), &mut rng);
        assert_eq!(sealed[0], 2);
        sealed[0] = 1;
        assert_eq!(open(&[(3, sk)], &sealed), None);
    }

    #[test]
    fn sealed_fits_max() {
        let (_, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let mut t = token();
        t.apns_token = vec![0xff; MAX_APNS_TOKEN];
        t.expires_day = u32::MAX;
        t.reason = WakeReason::Receipt;
        assert!(seal(&pk, 1, &t, &mut rng).len() <= MAX_SEALED);
    }

    #[test]
    fn two_seals_differ() {
        let (_, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let t = token();
        assert_ne!(seal(&pk, 1, &t, &mut rng), seal(&pk, 1, &t, &mut rng));
    }

    #[test]
    fn open_rejects_unknown_key_id_and_tamper() {
        let (sk, pk) = keypair(1);
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        let sealed = seal(&pk, 3, &token(), &mut rng);
        let keys = [(3, StaticSecret::from(sk.to_bytes()))];
        assert!(open(&keys, &sealed).is_some());
        assert_eq!(
            open(&[(4, StaticSecret::from(sk.to_bytes()))], &sealed),
            None
        );
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open(&keys, &bad), None);
        let mut bad = sealed.clone();
        bad[2] ^= 1;
        assert_eq!(open(&keys, &bad), None);
        let mut bad = sealed.clone();
        bad[0] = 3;
        assert_eq!(open(&keys, &bad), None);
        let mut long = sealed.clone();
        long.resize(MAX_SEALED + 1, 0);
        assert_eq!(open(&keys, &long), None);
        assert_eq!(open(&keys, &[]), None);
    }

    #[test]
    #[should_panic]
    fn seal_panics_on_oversized_token() {
        let (_, pk) = keypair(1);
        let mut t = token();
        t.apns_token = vec![0; MAX_APNS_TOKEN + 1];
        seal_with_ephemeral(&pk, 1, &t, [7; 32]);
    }

    #[test]
    fn seal_vector_is_frozen() {
        let (_, pk) = keypair(9);
        let sealed = seal_with_ephemeral(&pk, 1, &token(), [7; 32]);
        let frozen: &[u8] = &hex!(
            "020113be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe9"
            "7b6dfe935c5620e0af2515897718e5814b5b0b54e01de72d24e2a1147ed4abbf"
            "08beccf713267b2cd0302b95249af06011443919a6c890b6e55d620c6bb84d95"
            "eb69b5b7f9fe709b"
        );
        assert_eq!(sealed, frozen);
    }

    #[test]
    fn relay_well_formed() {
        let r = |host: &str, port: u16| RelayRef {
            host: host.to_string(),
            port,
            id: NodeId([1; 32]),
        };
        assert!(r("push.example.org", 443).well_formed());
        assert!(r("8.8.8.8", 443).well_formed());
        assert!(r("2606:4700:4700::1111", 443).well_formed());
        assert!(r("[2606:4700:4700::1111]", 443).well_formed());
        assert!(!r("", 443).well_formed());
        assert!(!r(&"a".repeat(300), 443).well_formed());
        assert!(r(&"a".repeat(63), 443).well_formed());
        assert!(!r("push.example.org", 0).well_formed());
        assert!(!r("127.0.0.1", 443).well_formed());
        assert!(!r("::1", 443).well_formed());
        assert!(!r("[::1]", 443).well_formed());
        assert!(!r("10.0.0.1", 443).well_formed());
        assert!(!r("exa mple", 443).well_formed());
        assert!(!r("a..b", 443).well_formed());
        assert!(!r(".a", 443).well_formed());
        assert!(!r("é.org", 443).well_formed());
    }

    #[test]
    fn subscription_hash_changes_with_each_field() {
        let base = Subscription {
            mailbox: MailboxId([1; 16]),
            relay: RelayRef {
                host: "push.example.org".into(),
                port: 443,
                id: NodeId([2; 32]),
            },
            sealed: vec![3; 100],
            cancel_hash: [4; 32],
            expires_day: 20_000,
            kind: SubKind::Messages,
        };
        let h = subscription_hash(&base);
        assert_eq!(h, subscription_hash(&base.clone()));
        let mut variants = Vec::new();
        let mut s = base.clone();
        s.mailbox = MailboxId([9; 16]);
        variants.push(s);
        let mut s = base.clone();
        s.relay.host = "other.example.org".into();
        variants.push(s);
        let mut s = base.clone();
        s.relay.port = 444;
        variants.push(s);
        let mut s = base.clone();
        s.relay.id = NodeId([9; 32]);
        variants.push(s);
        let mut s = base.clone();
        s.sealed[0] ^= 1;
        variants.push(s);
        let mut s = base.clone();
        s.cancel_hash = [9; 32];
        variants.push(s);
        let mut s = base.clone();
        s.expires_day += 1;
        variants.push(s);
        let mut s = base.clone();
        s.kind = SubKind::Acks;
        variants.push(s);
        for v in variants {
            assert_ne!(subscription_hash(&v), h);
        }
        assert_eq!(cancel_hash(&[1; 32]), *blake3::hash(&[1; 32]).as_bytes());
    }
}
