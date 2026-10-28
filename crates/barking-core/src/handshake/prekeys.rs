//! Paquets de clés (prekeys) : clé signée X25519, clé ML-KEM-768 et clés à usage unique.

use crate::crypto::labels;
use crate::identity::device::sig_bytes;
use crate::identity::{DeviceKeys, DevicePublic};
use crate::{CoreError, Result};
use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use ml_kem::{Generate, KeyExport, MlKem768};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Taille d'une clé d'encapsulation ML-KEM-768 encodée.
pub const PQ_EK_LEN: usize = 1184;
/// Taille d'un chiffré ML-KEM-768.
pub const PQ_CT_LEN: usize = 1088;

pub(crate) type PqDecapsulationKey = ml_kem::DecapsulationKey<MlKem768>;

/// Clés secrètes des paquets de clés d'un appareil.
///
/// Chaque champ secret s'efface lui-même à la destruction : `StaticSecret`
/// (x25519-dalek, feature `zeroize`) et `DecapsulationKey` (ml-kem, feature
/// `zeroize`) sont `ZeroizeOnDrop`, y compris dans la `BTreeMap`.
pub struct PrekeySecrets {
    spk_id: u32,
    spk: StaticSecret,
    pq_id: u32,
    pq_dk: PqDecapsulationKey,
    opks: BTreeMap<u32, StaticSecret>,
}

// Tous les champs secrets sont eux-mêmes `ZeroizeOnDrop` (voir ci-dessus).
impl ZeroizeOnDrop for PrekeySecrets {}

impl fmt::Debug for PrekeySecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrekeySecrets(<secret>)")
    }
}

fn random_static(rng: &mut impl CryptoRng) -> StaticSecret {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    let s = StaticSecret::from(b);
    b.zeroize();
    s
}

impl PrekeySecrets {
    /// Tire une clé signée X25519, une clé ML-KEM-768 et `n_opk` clés à usage
    /// unique, avec des identifiants aléatoires (distincts entre clés à usage unique).
    pub fn generate(rng: &mut impl CryptoRng, n_opk: usize) -> PrekeySecrets {
        let spk_id = rng.next_u32();
        let spk = random_static(rng);
        let pq_id = rng.next_u32();
        let pq_dk = PqDecapsulationKey::generate_from_rng(rng);
        let mut opks = BTreeMap::new();
        while opks.len() < n_opk {
            if let Entry::Vacant(slot) = opks.entry(rng.next_u32()) {
                slot.insert(random_static(rng));
            }
        }
        PrekeySecrets {
            spk_id,
            spk,
            pq_id,
            pq_dk,
            opks,
        }
    }

    /// Paquet de clés publiques signé par l'appareil. Avec `with_opk`, il propose
    /// la clé à usage unique de plus petit identifiant, s'il en reste une.
    pub fn bundle(&self, dev: &DeviceKeys, with_opk: bool) -> PrekeyBundle {
        let opk = if with_opk {
            self.opks
                .iter()
                .next()
                .map(|(id, s)| (*id, PublicKey::from(s).to_bytes()))
        } else {
            None
        };
        let mut bundle = PrekeyBundle {
            device: dev.public(),
            spk_id: self.spk_id,
            spk: PublicKey::from(&self.spk).to_bytes(),
            pq_id: self.pq_id,
            pq_ek: self.pq_dk.encapsulation_key().to_bytes().to_vec(),
            opk,
            sig: [0u8; 64],
        };
        bundle.sig = dev.sign(labels::PREKEYS, &bundle.signed_bytes());
        bundle
    }

    /// Nombre de clés à usage unique restantes.
    pub fn opk_count(&self) -> usize {
        self.opks.len()
    }

    pub(crate) fn spk_id(&self) -> u32 {
        self.spk_id
    }

    pub(crate) fn spk(&self) -> &StaticSecret {
        &self.spk
    }

    pub(crate) fn pq_id(&self) -> u32 {
        self.pq_id
    }

    pub(crate) fn pq_dk(&self) -> &PqDecapsulationKey {
        &self.pq_dk
    }

    pub(crate) fn opk(&self, id: u32) -> Option<&StaticSecret> {
        self.opks.get(&id)
    }

    /// Retire (et détruit) une clé à usage unique.
    pub(crate) fn remove_opk(&mut self, id: u32) {
        self.opks.remove(&id);
    }
}

/// Forme stockée des secrets ; effacée à la destruction.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredPrekeys {
    spk_id: u32,
    spk: [u8; 32],
    pq_id: u32,
    /// Graine de 64 octets (d || z) de la clé ML-KEM.
    #[serde(with = "sig_bytes")]
    pq_seed: [u8; 64],
    opks: Vec<(u32, [u8; 32])>,
}

impl Serialize for PrekeySecrets {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        let mut seed = self
            .pq_dk
            .to_seed()
            .ok_or_else(|| serde::ser::Error::custom("clé ML-KEM sans graine"))?;
        let mut stored = StoredPrekeys {
            spk_id: self.spk_id,
            spk: self.spk.to_bytes(),
            pq_id: self.pq_id,
            pq_seed: [0u8; 64],
            opks: self
                .opks
                .iter()
                .map(|(id, k)| (*id, k.to_bytes()))
                .collect(),
        };
        stored.pq_seed.copy_from_slice(&seed);
        seed.zeroize();
        stored.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PrekeySecrets {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let stored = StoredPrekeys::deserialize(d)?;
        let mut opks = BTreeMap::new();
        for (id, k) in &stored.opks {
            if opks.insert(*id, StaticSecret::from(*k)).is_some() {
                return Err(serde::de::Error::custom("identifiant de clé en double"));
            }
        }
        Ok(PrekeySecrets {
            spk_id: stored.spk_id,
            spk: StaticSecret::from(stored.spk),
            pq_id: stored.pq_id,
            pq_dk: PqDecapsulationKey::from_seed(stored.pq_seed.into()),
            opks,
        })
    }
}

/// Paquet de clés publiques, signé par la clé de signature de l'appareil.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub device: DevicePublic,
    pub spk_id: u32,
    pub spk: [u8; 32],
    pub pq_id: u32,
    /// Clé d'encapsulation ML-KEM-768 (1184 octets).
    pub pq_ek: Vec<u8>,
    pub opk: Option<(u32, [u8; 32])>,
    #[serde(with = "sig_bytes")]
    pub sig: [u8; 64],
}

impl PrekeyBundle {
    /// Octets signés (encodage fixe, sans ambiguïté) :
    /// `device.sig || device.dh || spk_id || spk || pq_id || len(pq_ek) || pq_ek || opk`,
    /// entiers en petit-boutiste sur 4 octets, `opk` = `0` ou `1 || id || clé`.
    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 3 + 4 * 3 + self.pq_ek.len() + 37);
        out.extend_from_slice(&self.device.sig);
        out.extend_from_slice(&self.device.dh);
        out.extend_from_slice(&self.spk_id.to_le_bytes());
        out.extend_from_slice(&self.spk);
        out.extend_from_slice(&self.pq_id.to_le_bytes());
        // Longueur bornée par `verify` ; un `u32` suffit largement sinon.
        let len = u32::try_from(self.pq_ek.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.pq_ek);
        match &self.opk {
            None => out.push(0),
            Some((id, k)) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(k);
            }
        }
        out
    }

    /// Vérifie la taille de `pq_ek` puis la signature de l'appareil (étiquette `PREKEYS`).
    pub fn verify(&self) -> Result<()> {
        if self.pq_ek.len() != PQ_EK_LEN {
            return Err(CoreError::Malformed("taille de clé ML-KEM"));
        }
        let key =
            VerifyingKey::from_bytes(&self.device.sig).map_err(|_| CoreError::InvalidSignature)?;
        let mut data = labels::PREKEYS.to_vec();
        data.extend_from_slice(&self.signed_bytes());
        key.verify_strict(&data, &Signature::from_bytes(&self.sig))
            .map_err(|_| CoreError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn setup() -> (DeviceKeys, PrekeySecrets) {
        let mut rng = StdRng::seed_from_u64(41);
        let dev = DeviceKeys::generate(&mut rng);
        let pre = PrekeySecrets::generate(&mut rng, 3);
        (dev, pre)
    }

    #[test]
    fn bundle_verifies() {
        let (dev, pre) = setup();
        for with_opk in [false, true] {
            let b = pre.bundle(&dev, with_opk);
            assert!(b.verify().is_ok());
            assert_eq!(b.device, dev.public());
            assert_eq!(b.pq_ek.len(), PQ_EK_LEN);
            assert_eq!(b.opk.is_some(), with_opk);
        }
    }

    #[test]
    fn generate_makes_requested_opks() {
        let (_, pre) = setup();
        assert_eq!(pre.opk_count(), 3);
    }

    #[test]
    fn tampered_fields_rejected() {
        let (dev, pre) = setup();
        let good = pre.bundle(&dev, true);

        let mut b = good.clone();
        b.spk[0] ^= 1;
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));

        let mut b = good.clone();
        b.spk_id ^= 1;
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));

        let mut b = good.clone();
        b.pq_ek[10] ^= 1;
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));

        let mut b = good.clone();
        b.opk = None;
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));

        let mut b = good.clone();
        b.sig[0] ^= 1;
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));

        // Signé par un autre appareil.
        let other = DeviceKeys::generate(&mut StdRng::seed_from_u64(99));
        let mut b = good.clone();
        b.device = other.public();
        assert_eq!(b.verify(), Err(CoreError::InvalidSignature));
    }

    #[test]
    fn wrong_pq_ek_size_rejected() {
        let (dev, pre) = setup();
        let mut b = pre.bundle(&dev, false);
        b.pq_ek.pop();
        // Même re-signé, une clé de mauvaise taille est refusée.
        b.sig = dev.sign(crate::crypto::labels::PREKEYS, &b.signed_bytes());
        assert!(matches!(b.verify(), Err(CoreError::Malformed(_))));
    }

    #[test]
    fn secrets_serde_roundtrip() {
        let (dev, pre) = setup();
        let bytes = postcard::to_allocvec(&pre).unwrap();
        let back: PrekeySecrets = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.bundle(&dev, true), pre.bundle(&dev, true));
        assert_eq!(back.opk_count(), 3);
        assert!(postcard::from_bytes::<PrekeySecrets>(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn debug_hides_secrets() {
        let (_, pre) = setup();
        assert_eq!(format!("{pre:?}"), "PrekeySecrets(<secret>)");
    }
}
