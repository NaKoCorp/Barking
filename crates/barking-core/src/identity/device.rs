//! Device keys (Ed25519 signature + X25519 exchange) and certificate signed by the root.

use super::root::{RootIdentity, RootPublic, labelled};
use crate::crypto::{bytes64, labels};
use crate::{CoreError, Result};
use core::fmt;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Maximum size of a device name, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Device identifier: 16 bytes derived from the public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

/// Public keys of a device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct DevicePublic {
    pub sig: [u8; 32],
    pub dh: [u8; 32],
}

impl DevicePublic {
    pub fn id(&self) -> DeviceId {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&self.sig);
        input[32..].copy_from_slice(&self.dh);
        let full = blake3::derive_key(labels::DEVICE_ID_CONTEXT, &input);
        let mut id = [0u8; 16];
        id.copy_from_slice(&full[..16]);
        DeviceId(id)
    }
}

/// Secret keys of a device. Each field is erased on drop
/// (`SigningKey` and `StaticSecret` are `ZeroizeOnDrop`).
pub struct DeviceKeys {
    signing: SigningKey,
    dh: x25519_dalek::StaticSecret,
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKeys(<secret>)")
    }
}

impl DeviceKeys {
    pub fn generate(rng: &mut impl CryptoRng) -> DeviceKeys {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        let keys = DeviceKeys {
            signing: SigningKey::from_bytes(&a),
            dh: x25519_dalek::StaticSecret::from(b),
        };
        a.zeroize();
        b.zeroize();
        keys
    }

    /// Secret keys `signature(32) || dh(32)`, for encrypted storage only.
    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(self.dh.as_bytes());
        out
    }

    /// Inverse of [`DeviceKeys::to_bytes`].
    pub(crate) fn from_bytes(bytes: &[u8; 64]) -> DeviceKeys {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&bytes[..32]);
        b.copy_from_slice(&bytes[32..]);
        let keys = DeviceKeys {
            signing: SigningKey::from_bytes(&a),
            dh: x25519_dalek::StaticSecret::from(b),
        };
        a.zeroize();
        b.zeroize();
        keys
    }

    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            sig: self.signing.verifying_key().to_bytes(),
            dh: x25519_dalek::PublicKey::from(&self.dh).to_bytes(),
        }
    }

    /// Signs `label || msg`.
    pub fn sign(&self, label: &[u8], msg: &[u8]) -> [u8; 64] {
        self.signing.sign(&labelled(label, msg)).to_bytes()
    }

    /// X25519 shared secret with a remote public key.
    pub fn dh(&self, their: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.dh.diffie_hellman(their).to_bytes()
    }
}

/// Certificate: the root attests that a device belongs to it, and
/// the device attests that it belongs to this root (proof of possession
/// of its signing key). Without this second signature, a root could
/// certify the public keys of someone else's device.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub root: RootPublic,
    pub device: DevicePublic,
    pub name: String,
    pub issued_at: u64,
    /// Root signature (label `DEVICE_CERT`).
    #[serde(with = "bytes64")]
    pub sig: [u8; 64],
    /// Device signature (label `DEVICE_POSSESSION`).
    #[serde(with = "bytes64")]
    pub device_sig: [u8; 64],
}

/// Bytes signed by the root and by the device: postcard of
/// `(root, device, name, issued_at)` (the labels differ).
fn cert_bytes(
    root: &RootPublic,
    device: &DevicePublic,
    name: &str,
    issued_at: u64,
) -> Result<Vec<u8>> {
    if name.len() > MAX_NAME_LEN {
        return Err(CoreError::TooLarge);
    }
    postcard::to_allocvec(&(root, device, name, issued_at))
        .map_err(|_| CoreError::Malformed("certificate not serializable"))
}

impl DeviceKeys {
    /// Proof of possession: signature by this device of
    /// `(root, self.public(), name, issued_at)`. Handed to the root so
    /// that it issues the certificate (`DeviceCertificate::issue_with_proof`).
    pub fn possession_proof(
        &self,
        root: &RootPublic,
        name: &str,
        issued_at: u64,
    ) -> Result<[u8; 64]> {
        let bytes = cert_bytes(root, &self.public(), name, issued_at)?;
        Ok(self.sign(labels::DEVICE_POSSESSION, &bytes))
    }
}

/// Verifies the proof of possession of `device` (strict verification).
fn verify_possession(device: &DevicePublic, bytes: &[u8], sig: &[u8; 64]) -> Result<()> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&device.sig)
        .map_err(|_| CoreError::InvalidSignature)?;
    let data = labelled(labels::DEVICE_POSSESSION, bytes);
    key.verify_strict(&data, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| CoreError::InvalidSignature)
}

impl DeviceCertificate {
    /// Certificate for a device whose keys we hold (local device).
    pub fn issue(root: &RootIdentity, device: &DeviceKeys, name: &str, now: u64) -> Result<Self> {
        let proof = device.possession_proof(&root.public(), name, now)?;
        Self::issue_with_proof(root, device.public(), name, now, proof)
    }

    /// Certificate for a remote device (linking): its proof of possession
    /// is verified before the root signs.
    pub fn issue_with_proof(
        root: &RootIdentity,
        device: DevicePublic,
        name: &str,
        issued_at: u64,
        device_sig: [u8; 64],
    ) -> Result<Self> {
        let root_pub = root.public();
        let bytes = cert_bytes(&root_pub, &device, name, issued_at)?;
        verify_possession(&device, &bytes, &device_sig)?;
        Ok(DeviceCertificate {
            root: root_pub,
            device,
            name: name.to_owned(),
            issued_at,
            sig: root.sign(labels::DEVICE_CERT, &bytes),
            device_sig,
        })
    }

    /// Verifies the root signature and the device's proof of possession.
    pub fn verify(&self) -> Result<()> {
        let bytes = cert_bytes(&self.root, &self.device, &self.name, self.issued_at)?;
        self.root.verify(labels::DEVICE_CERT, &bytes, &self.sig)?;
        verify_possession(&self.device, &bytes, &self.device_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::RootIdentity;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// `DeviceKeys` erases itself only through its field types.
    #[test]
    fn device_key_fields_are_zeroized_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SigningKey>();
        assert_zod::<x25519_dalek::StaticSecret>();
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(11)
    }

    #[test]
    fn cert_verifies() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let cert = DeviceCertificate::issue(&root, &dev, "phone", 1000).unwrap();
        assert!(cert.verify().is_ok());
        assert_eq!(cert.root, root.public());
    }

    #[test]
    fn cert_tampered_name_fails() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let mut cert = DeviceCertificate::issue(&root, &dev, "phone", 1000).unwrap();
        cert.name = "evil".into();
        assert_eq!(cert.verify(), Err(crate::CoreError::InvalidSignature));
    }

    #[test]
    fn cert_name_too_long_rejected() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let long = "a".repeat(65);
        assert!(DeviceCertificate::issue(&root, &dev, &long, 1).is_err());
        let ok = "a".repeat(64);
        assert!(DeviceCertificate::issue(&root, &dev, &ok, 1).is_ok());
    }

    #[test]
    fn cert_overlong_name_fails_verify() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let mut cert = DeviceCertificate::issue(&root, &dev, "x", 1).unwrap();
        cert.name = "a".repeat(65);
        assert!(cert.verify().is_err());
    }

    #[test]
    fn cert_missing_or_forged_device_sig_fails() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let good = DeviceCertificate::issue(&root, &dev, "p", 5).unwrap();
        let mut missing = good.clone();
        missing.device_sig = [0u8; 64];
        assert_eq!(missing.verify(), Err(crate::CoreError::InvalidSignature));
        let mut forged = good.clone();
        forged.device_sig[3] ^= 1;
        assert_eq!(forged.verify(), Err(crate::CoreError::InvalidSignature));
        // Proof from another device.
        let other = DeviceKeys::generate(&mut StdRng::seed_from_u64(77));
        let mut swapped = good.clone();
        swapped.device_sig = other.possession_proof(&root.public(), "p", 5).unwrap();
        assert_eq!(swapped.verify(), Err(crate::CoreError::InvalidSignature));
        // The proof cannot be recycled under another date or name.
        assert!(
            DeviceCertificate::issue_with_proof(&root, dev.public(), "p", 6, good.device_sig)
                .is_err()
        );
    }

    #[test]
    fn root_cannot_certify_foreign_device() {
        // Mallory wants to certify Alice's device under her own root.
        let mut r = StdRng::seed_from_u64(21);
        let (alice_root, _) = RootIdentity::generate(&mut r);
        let (mallory_root, _) = RootIdentity::generate(&mut r);
        let alice_dev = DeviceKeys::generate(&mut r);
        let alice_cert = DeviceCertificate::issue(&alice_root, &alice_dev, "tel", 1).unwrap();
        // Alice's proof is bound to her root: rejected under Mallory's.
        assert_eq!(
            DeviceCertificate::issue_with_proof(
                &mallory_root,
                alice_dev.public(),
                "tel",
                1,
                alice_cert.device_sig
            )
            .err(),
            Some(crate::CoreError::InvalidSignature)
        );
        // Hand-crafted certificate: the root signs, the proof does not match.
        let bytes = cert_bytes(&mallory_root.public(), &alice_dev.public(), "tel", 1).unwrap();
        let forged = DeviceCertificate {
            root: mallory_root.public(),
            device: alice_dev.public(),
            name: "tel".into(),
            issued_at: 1,
            sig: mallory_root.sign(labels::DEVICE_CERT, &bytes),
            device_sig: alice_cert.device_sig,
        };
        assert_eq!(forged.verify(), Err(crate::CoreError::InvalidSignature));
    }

    #[test]
    fn device_keys_sign_and_dh() {
        let a = DeviceKeys::generate(&mut rng());
        let mut r2 = StdRng::seed_from_u64(12);
        let b = DeviceKeys::generate(&mut r2);
        let sig = a.sign(b"barking/v0/x", b"m");
        let pubk = a.public();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubk.sig).unwrap();
        let mut data = b"barking/v0/x".to_vec();
        data.extend_from_slice(b"m");
        assert!(
            vk.verify_strict(&data, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );
        let bp = x25519_dalek::PublicKey::from(b.public().dh);
        let ap = x25519_dalek::PublicKey::from(a.public().dh);
        assert_eq!(a.dh(&bp), b.dh(&ap));
        assert_ne!(a.public().id(), b.public().id());
        assert!(!format!("{a:?}").contains("signing"));
    }

    #[test]
    fn cert_postcard_roundtrip() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let cert = DeviceCertificate::issue(&root, &dev, "p", 5).unwrap();
        let bytes = postcard::to_allocvec(&cert).unwrap();
        let back: DeviceCertificate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, cert);
        assert!(back.verify().is_ok());
    }
}
