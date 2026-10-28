//! Liste signée des appareils d'une identité. Une liste plus récente sans un
//! appareil vaut révocation de cet appareil.

use super::device::{DeviceCertificate, DeviceId, sig_bytes};
use super::root::{RootIdentity, RootPublic};
use crate::crypto::labels;
use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Nombre maximal d'appareils par identité.
pub const MAX_DEVICES: usize = 16;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeviceList {
    pub root: RootPublic,
    pub version: u64,
    pub certs: Vec<DeviceCertificate>,
    #[serde(with = "sig_bytes")]
    pub sig: [u8; 64],
}

impl DeviceList {
    /// Octets signés : postcard des champs sans `sig`.
    fn signed_bytes(
        root: &RootPublic,
        version: u64,
        certs: &[DeviceCertificate],
    ) -> Result<Vec<u8>> {
        postcard::to_allocvec(&(root, version, certs))
            .map_err(|_| CoreError::Malformed("liste non sérialisable"))
    }

    /// Vérifie taille, appartenance à la racine, validité et unicité des appareils.
    fn check_certs(root: &RootPublic, certs: &[DeviceCertificate]) -> Result<()> {
        if certs.len() > MAX_DEVICES {
            return Err(CoreError::TooLarge);
        }
        let mut seen: HashSet<DeviceId> = HashSet::new();
        for cert in certs {
            if cert.root != *root {
                return Err(CoreError::InvalidSignature);
            }
            cert.verify()?;
            if !seen.insert(cert.device.id()) {
                return Err(CoreError::Malformed("appareil en double"));
            }
        }
        Ok(())
    }

    pub fn sign(root: &RootIdentity, version: u64, certs: Vec<DeviceCertificate>) -> Result<Self> {
        let root_pub = root.public();
        Self::check_certs(&root_pub, &certs)?;
        let bytes = Self::signed_bytes(&root_pub, version, &certs)?;
        Ok(DeviceList {
            root: root_pub,
            version,
            sig: root.sign(labels::DEVICE_LIST, &bytes),
            certs,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.certs.len() > MAX_DEVICES {
            return Err(CoreError::TooLarge);
        }
        let bytes = Self::signed_bytes(&self.root, self.version, &self.certs)?;
        self.root.verify(labels::DEVICE_LIST, &bytes, &self.sig)?;
        Self::check_certs(&self.root, &self.certs)
    }

    /// Même racine et version strictement supérieure.
    pub fn supersedes(&self, older: &DeviceList) -> bool {
        self.root == older.root && self.version > older.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use crate::identity::{DeviceCertificate, DeviceKeys, RootIdentity};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn cert(root: &RootIdentity, seed: u64, name: &str) -> DeviceCertificate {
        let dev = DeviceKeys::generate(&mut StdRng::seed_from_u64(seed));
        DeviceCertificate::issue(root, dev.public(), name, 1).unwrap()
    }

    fn root(seed: u64) -> RootIdentity {
        RootIdentity::generate(&mut StdRng::seed_from_u64(seed)).0
    }

    #[test]
    fn list_verifies() {
        let r = root(1);
        let list = DeviceList::sign(&r, 1, vec![cert(&r, 10, "a"), cert(&r, 11, "b")]).unwrap();
        assert!(list.verify().is_ok());
        let bytes = postcard::to_allocvec(&list).unwrap();
        let back: DeviceList = postcard::from_bytes(&bytes).unwrap();
        assert!(back.verify().is_ok());
    }

    #[test]
    fn list_tampered_version_fails() {
        let r = root(1);
        let mut list = DeviceList::sign(&r, 1, vec![cert(&r, 10, "a")]).unwrap();
        list.version = 2;
        assert_eq!(list.verify(), Err(CoreError::InvalidSignature));
    }

    #[test]
    fn list_rejects_cert_from_other_root() {
        let r = root(1);
        let other = root(2);
        let list = DeviceList::sign(&r, 1, vec![cert(&r, 10, "a"), cert(&other, 11, "b")]);
        // Soit refusé à la signature, soit à la vérification.
        match list {
            Err(_) => {}
            Ok(l) => assert!(l.verify().is_err()),
        }
    }

    #[test]
    fn list_rejects_17_devices() {
        let r = root(1);
        let certs: Vec<_> = (0..17).map(|i| cert(&r, 100 + i, "d")).collect();
        assert!(DeviceList::sign(&r, 1, certs).is_err());
        let certs16: Vec<_> = (0..16).map(|i| cert(&r, 100 + i, "d")).collect();
        assert!(DeviceList::sign(&r, 1, certs16).is_ok());
    }

    #[test]
    fn list_rejects_duplicate_device() {
        let r = root(1);
        let c = cert(&r, 10, "a");
        let list = DeviceList::sign(&r, 1, vec![c.clone(), c]);
        match list {
            Err(_) => {}
            Ok(l) => assert!(l.verify().is_err()),
        }
    }

    #[test]
    fn revocation_is_newer_list_without_device() {
        let r = root(1);
        let a = cert(&r, 10, "a");
        let b = cert(&r, 11, "b");
        let v1 = DeviceList::sign(&r, 1, vec![a.clone(), b.clone()]).unwrap();
        let v2 = DeviceList::sign(&r, 2, vec![a]).unwrap();
        assert!(v2.verify().is_ok());
        assert!(v2.supersedes(&v1));
        assert!(!v2.certs.iter().any(|c| c.device.id() == b.device.id()));
        assert!(v1.certs.iter().any(|c| c.device.id() == b.device.id()));
    }

    #[test]
    fn older_version_does_not_supersede() {
        let r = root(1);
        let v1 = DeviceList::sign(&r, 1, vec![]).unwrap();
        let v2 = DeviceList::sign(&r, 2, vec![]).unwrap();
        assert!(!v1.supersedes(&v2));
        assert!(!v1.supersedes(&v1));
        let other = DeviceList::sign(&root(2), 9, vec![]).unwrap();
        assert!(!other.supersedes(&v1));
    }

    /// Liste forgée par un détenteur légitime de la racine, sans passer par `sign`.
    fn forged(r: &RootIdentity, certs: Vec<DeviceCertificate>) -> DeviceList {
        let root = r.public();
        let bytes = DeviceList::signed_bytes(&root, 1, &certs).unwrap();
        DeviceList {
            root,
            version: 1,
            sig: r.sign(crate::crypto::labels::DEVICE_LIST, &bytes),
            certs,
        }
    }

    #[test]
    fn verify_rejects_foreign_cert_and_duplicates_in_forged_list() {
        let r = root(1);
        let foreign = forged(&r, vec![cert(&root(2), 11, "b")]);
        assert_eq!(foreign.verify(), Err(CoreError::InvalidSignature));
        let c = cert(&r, 10, "a");
        assert!(forged(&r, vec![c.clone(), c]).verify().is_err());
        let many: Vec<_> = (0..17).map(|i| cert(&r, 100 + i, "d")).collect();
        assert_eq!(forged(&r, many).verify(), Err(CoreError::TooLarge));
    }
}
