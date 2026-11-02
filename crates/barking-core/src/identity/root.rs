//! Ed25519 root identity, derived from a BIP39 recovery phrase.

use crate::crypto::{kdf::hkdf_sha256, labels};
use crate::{CoreError, Result};
use bip39::{Language, Mnemonic};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Recovery phrase (24 English BIP39 words). Erased on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase(String);

impl RecoveryPhrase {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<secret>)")
    }
}

/// Root secret key (ZeroizeOnDrop via `SigningKey`).
pub struct RootIdentity {
    key: SigningKey,
}

impl fmt::Debug for RootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootIdentity(<secret>)")
    }
}

/// `label || msg`, the message actually signed (root and device keys).
pub(crate) fn labelled(label: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(label.len() + msg.len());
    data.extend_from_slice(label);
    data.extend_from_slice(msg);
    data
}

impl RootIdentity {
    /// Draws 32 bytes of entropy, converts them to a phrase, then derives the key.
    pub fn generate(rng: &mut impl CryptoRng) -> (RootIdentity, RecoveryPhrase) {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let result = Self::from_entropy(&entropy);
        entropy.zeroize();
        result
    }

    fn from_entropy(entropy: &[u8; 32]) -> (RootIdentity, RecoveryPhrase) {
        // Invariant: 32 bytes is a valid BIP39 entropy size (24 words).
        let mnemonic = Mnemonic::from_entropy(entropy).expect("32 bytes of entropy give 24 words");
        let phrase = RecoveryPhrase(mnemonic.to_string());
        (Self::derive(entropy), phrase)
    }

    fn derive(entropy: &[u8; 32]) -> RootIdentity {
        let mut seed = [0u8; 32];
        // Invariant: 32 bytes of HKDF output never exceed the limit.
        hkdf_sha256(None, entropy, labels::ROOT_FROM_ENTROPY, &mut seed)
            .expect("32 bytes of HKDF output");
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        RootIdentity { key }
    }

    /// Restores the identity from a phrase of 24 English words.
    pub fn from_phrase(phrase: &str) -> Result<RootIdentity> {
        let mnemonic =
            Mnemonic::parse_in(Language::English, phrase).map_err(|_| CoreError::InvalidPhrase)?;
        if mnemonic.word_count() != 24 {
            return Err(CoreError::InvalidPhrase);
        }
        let (mut buf, len) = mnemonic.to_entropy_array();
        let mut entropy = [0u8; 32];
        if len != 32 {
            buf.zeroize();
            return Err(CoreError::InvalidPhrase);
        }
        entropy.copy_from_slice(&buf[..32]);
        buf.zeroize();
        let identity = Self::derive(&entropy);
        entropy.zeroize();
        Ok(identity)
    }

    /// Secret seed, for encrypted storage only.
    pub(crate) fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    /// Inverse of [`RootIdentity::to_seed`].
    pub(crate) fn from_seed(seed: &[u8; 32]) -> RootIdentity {
        RootIdentity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn public(&self) -> RootPublic {
        RootPublic(self.key.verifying_key().to_bytes())
    }

    /// Signs `label || msg`.
    pub fn sign(&self, label: &[u8], msg: &[u8]) -> [u8; 64] {
        self.key.sign(&labelled(label, msg)).to_bytes()
    }
}

/// Public root key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct RootPublic(pub [u8; 32]);

impl RootPublic {
    /// Verifies a signature over `label || msg` (strict verification).
    pub fn verify(&self, label: &[u8], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| CoreError::InvalidSignature)?;
        let sig = Signature::from_bytes(sig);
        key.verify_strict(&labelled(label, msg), &sig)
            .map_err(|_| CoreError::InvalidSignature)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(blake3::derive_key(labels::FINGERPRINT_CONTEXT, &self.0))
    }
}

/// Fingerprint of the public root key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl fmt::Display for Fingerprint {
    /// Lowercase base32 without padding, groups of 4 separated by `-`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = data_encoding::BASE32_NOPAD
            .encode(&self.0)
            .to_ascii_lowercase();
        for (i, chunk) in encoded.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            // The bytes are base32 ASCII: valid UTF-8.
            f.write_str(core::str::from_utf8(chunk).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    #[test]
    fn mnemonic_is_zeroized_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<Mnemonic>();
    }

    #[test]
    fn phrase_restores_same_root() {
        let (root, phrase) = RootIdentity::generate(&mut rng());
        assert_eq!(phrase.as_str().split(' ').count(), 24);
        let back = RootIdentity::from_phrase(phrase.as_str()).unwrap();
        assert_eq!(root.public().fingerprint(), back.public().fingerprint());
    }

    #[test]
    fn bad_phrase_rejected() {
        assert!(matches!(
            RootIdentity::from_phrase("abandon abandon"),
            Err(CoreError::InvalidPhrase)
        ));
    }

    #[test]
    fn bad_checksum_and_12_words_rejected() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(matches!(
            RootIdentity::from_phrase(twelve),
            Err(CoreError::InvalidPhrase)
        ));
        let bad = ["abandon"; 24].join(" ");
        assert!(matches!(
            RootIdentity::from_phrase(&bad),
            Err(CoreError::InvalidPhrase)
        ));
    }

    #[test]
    fn signature_label_separation() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let sig = root.sign(b"barking/v0/a", b"msg");
        let public = root.public();
        assert!(public.verify(b"barking/v0/a", b"msg", &sig).is_ok());
        assert_eq!(
            public.verify(b"barking/v0/b", b"msg", &sig),
            Err(CoreError::InvalidSignature)
        );
        assert_eq!(
            public.verify(b"barking/v0/a", b"other", &sig),
            Err(CoreError::InvalidSignature)
        );
    }

    #[test]
    fn invalid_public_key_does_not_panic() {
        // Off-curve point / weak order: must be an error, not a panic.
        let weak = RootPublic([0u8; 32]);
        assert_eq!(
            weak.verify(b"l", b"m", &[0u8; 64]),
            Err(CoreError::InvalidSignature)
        );
    }

    #[test]
    fn fingerprint_display_shape() {
        let fp = RootPublic([9; 32]).fingerprint();
        let s = fp.to_string();
        // 52 base32 characters in 13 groups of 4.
        assert_eq!(s.split('-').count(), 13);
        assert!(s.split('-').all(|g| g.len() == 4));
        assert!(
            s.chars()
                .all(|c| c == '-' || c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let (root, phrase) = RootIdentity::generate(&mut rng());
        assert!(!format!("{root:?}").contains("key"));
        assert!(!format!("{phrase:?}").contains(phrase.as_str()));
    }
}
