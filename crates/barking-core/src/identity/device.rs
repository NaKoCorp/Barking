//! Clés d'appareil (signature Ed25519 + échange X25519) et certificat signé par la racine.

use super::root::{RootIdentity, RootPublic};
use crate::crypto::labels;
use crate::{CoreError, Result};
use core::fmt;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Taille maximale du nom d'un appareil, en octets.
pub const MAX_NAME_LEN: usize = 64;

/// Sérialisation serde d'un `[u8; 64]` (serde ne le gère pas nativement) :
/// tuple de 64 octets, soit 64 octets en postcard.
pub(crate) mod sig_bytes {
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(64)?;
        for b in v {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 octets")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(64, V)
    }
}

/// Identifiant d'appareil : 16 octets dérivés des clés publiques.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

/// Clés publiques d'un appareil.
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

/// Clés secrètes d'un appareil. Chaque champ s'efface à la destruction
/// (`SigningKey` et `StaticSecret` sont `ZeroizeOnDrop`).
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

    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            sig: self.signing.verifying_key().to_bytes(),
            dh: x25519_dalek::PublicKey::from(&self.dh).to_bytes(),
        }
    }

    /// Signe `label || msg`.
    pub fn sign(&self, label: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut data = Vec::with_capacity(label.len() + msg.len());
        data.extend_from_slice(label);
        data.extend_from_slice(msg);
        self.signing.sign(&data).to_bytes()
    }

    /// Secret partagé X25519 avec une clé publique distante.
    pub fn dh(&self, their: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.dh.diffie_hellman(their).to_bytes()
    }
}

/// Certificat : la racine atteste qu'un appareil lui appartient.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub root: RootPublic,
    pub device: DevicePublic,
    pub name: String,
    pub issued_at: u64,
    #[serde(with = "sig_bytes")]
    pub sig: [u8; 64],
}

impl DeviceCertificate {
    /// Octets signés : postcard des champs sans `sig`.
    fn signed_bytes(
        root: &RootPublic,
        device: &DevicePublic,
        name: &str,
        issued_at: u64,
    ) -> Result<Vec<u8>> {
        postcard::to_allocvec(&(root, device, name, issued_at))
            .map_err(|_| CoreError::Malformed("certificat non sérialisable"))
    }

    pub fn issue(root: &RootIdentity, device: DevicePublic, name: &str, now: u64) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(CoreError::TooLarge);
        }
        let root_pub = root.public();
        let bytes = Self::signed_bytes(&root_pub, &device, name, now)?;
        Ok(DeviceCertificate {
            root: root_pub,
            device,
            name: name.to_owned(),
            issued_at: now,
            sig: root.sign(labels::DEVICE_CERT, &bytes),
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.name.len() > MAX_NAME_LEN {
            return Err(CoreError::TooLarge);
        }
        let bytes = Self::signed_bytes(&self.root, &self.device, &self.name, self.issued_at)?;
        self.root.verify(labels::DEVICE_CERT, &bytes, &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::RootIdentity;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(11)
    }

    #[test]
    fn cert_verifies() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let cert = DeviceCertificate::issue(&root, dev.public(), "téléphone", 1000).unwrap();
        assert!(cert.verify().is_ok());
        assert_eq!(cert.root, root.public());
    }

    #[test]
    fn cert_tampered_name_fails() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let mut cert = DeviceCertificate::issue(&root, dev.public(), "phone", 1000).unwrap();
        cert.name = "evil".into();
        assert_eq!(cert.verify(), Err(crate::CoreError::InvalidSignature));
    }

    #[test]
    fn cert_name_too_long_rejected() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let long = "a".repeat(65);
        assert!(DeviceCertificate::issue(&root, dev.public(), &long, 1).is_err());
        let ok = "a".repeat(64);
        assert!(DeviceCertificate::issue(&root, dev.public(), &ok, 1).is_ok());
    }

    #[test]
    fn cert_overlong_name_fails_verify() {
        let (root, _) = RootIdentity::generate(&mut rng());
        let dev = DeviceKeys::generate(&mut rng());
        let mut cert = DeviceCertificate::issue(&root, dev.public(), "x", 1).unwrap();
        cert.name = "a".repeat(65);
        assert!(cert.verify().is_err());
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
        let cert = DeviceCertificate::issue(&root, dev.public(), "p", 5).unwrap();
        let bytes = postcard::to_allocvec(&cert).unwrap();
        let back: DeviceCertificate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, cert);
        assert!(back.verify().is_ok());
    }
}
