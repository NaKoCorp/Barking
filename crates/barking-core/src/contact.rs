//! Signed contact card: device list and key bundles, shareable as text.

use crate::crypto::labels;
use crate::handshake::PrekeyBundle;
use crate::identity::device::{MAX_NAME_LEN, sig_bytes};
use crate::identity::device_list::MAX_DEVICES;
use crate::identity::{DeviceList, Fingerprint, RootIdentity};
use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Prefix of the text format.
pub const CARD_PREFIX: &str = "barking1:";
/// Maximum size of a decoded card (bytes): that of an L-tier
/// packet (16 KiB). A larger card could not be sent by a card
/// update or a synchronisation. The heaviest possible one
/// (`MAX_DEVICES` devices, names at their maximum size) is about
/// 13.5 KiB (test `max_card_text_roundtrip`).
pub const MAX_CARD_BYTES: usize = 16 * 1024;
/// Maximum size of the text (unpadded base64url of `MAX_CARD_BYTES`,
/// about 22,000 characters), specific to the card: unrelated to the
/// maximum size of a text message.
pub const MAX_TEXT_LEN: usize = CARD_PREFIX.len() + MAX_CARD_BYTES.div_ceil(3) * 4;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ContactCard {
    pub display_name: String,
    pub devices: DeviceList,
    pub bundles: Vec<PrekeyBundle>,
    #[serde(with = "sig_bytes")]
    pub sig: [u8; 64],
}

impl ContactCard {
    /// Signed bytes: postcard of the fields without `sig`.
    fn signed_bytes(name: &str, devices: &DeviceList, bundles: &[PrekeyBundle]) -> Result<Vec<u8>> {
        postcard::to_allocvec(&(name, devices, bundles))
            .map_err(|_| CoreError::Malformed("card not serializable"))
    }

    pub fn sign(
        root: &RootIdentity,
        name: &str,
        devices: DeviceList,
        bundles: Vec<PrekeyBundle>,
    ) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(CoreError::TooLarge);
        }
        let bytes = Self::signed_bytes(name, &devices, &bundles)?;
        let sig = root.sign(labels::CONTACT_CARD, &bytes);
        Ok(ContactCard {
            display_name: name.to_owned(),
            devices,
            bundles,
            sig,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.display_name.len() > MAX_NAME_LEN || self.bundles.len() > MAX_DEVICES {
            return Err(CoreError::TooLarge);
        }
        let bytes = Self::signed_bytes(&self.display_name, &self.devices, &self.bundles)?;
        self.devices
            .root
            .verify(labels::CONTACT_CARD, &bytes, &self.sig)?;
        self.devices.verify()?;
        let known: HashSet<_> = self.devices.certs.iter().map(|c| c.device.id()).collect();
        let mut seen = HashSet::new();
        for b in &self.bundles {
            b.verify()?;
            let id = b.device.id();
            if !known.contains(&id) {
                return Err(CoreError::Malformed("key bundle of an unknown device"));
            }
            if !seen.insert(id) {
                return Err(CoreError::Malformed("duplicate key bundle"));
            }
            if b.opk.is_some() {
                return Err(CoreError::Malformed("one-time key forbidden"));
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.devices.root.fingerprint()
    }

    pub fn to_text(&self) -> String {
        // Serialization of a structure with no invalid state: cannot fail
        // (postcard into a `Vec`).
        let bytes = postcard::to_allocvec(self).unwrap_or_default();
        format!(
            "{CARD_PREFIX}{}",
            data_encoding::BASE64URL_NOPAD.encode(&bytes)
        )
    }

    pub fn from_text(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(CARD_PREFIX)
            .ok_or(CoreError::Malformed("unknown card prefix"))?;
        if CARD_PREFIX.len() + body.len() > MAX_TEXT_LEN {
            return Err(CoreError::TooLarge);
        }
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| CoreError::Malformed("unreadable card"))?;
        let (card, rest): (ContactCard, &[u8]) = postcard::take_from_bytes(&bytes)
            .map_err(|_| CoreError::Malformed("unreadable card"))?;
        if !rest.is_empty() {
            return Err(CoreError::Malformed("extra bytes after the card"));
        }
        card.verify()?;
        Ok(card)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::PrekeySecrets;
    use crate::identity::{DeviceCertificate, DeviceKeys};
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    struct Fixture {
        root: RootIdentity,
        dev: DeviceKeys,
        secrets: PrekeySecrets,
        list: DeviceList,
    }

    fn fixture() -> Fixture {
        let mut rng = StdRng::seed_from_u64(10);
        let (root, _) = RootIdentity::generate(&mut rng);
        let dev = DeviceKeys::generate(&mut rng);
        let secrets = PrekeySecrets::generate(&mut rng, 2);
        let cert = DeviceCertificate::issue(&root, &dev, "tel", 1).unwrap();
        let list = DeviceList::sign(&root, 1, vec![cert]).unwrap();
        Fixture {
            root,
            dev,
            secrets,
            list,
        }
    }

    fn card(f: &Fixture) -> ContactCard {
        let b = f.secrets.bundle(&f.dev, false);
        ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b]).unwrap()
    }

    #[test]
    fn text_roundtrip() {
        let f = fixture();
        let c = card(&f);
        c.verify().unwrap();
        let t = c.to_text();
        assert!(t.starts_with("barking1:"));
        assert_eq!(ContactCard::from_text(&t).unwrap(), c);
        assert_eq!(c.fingerprint(), f.root.public().fingerprint());
    }

    #[test]
    fn wrong_prefix_rejected() {
        let f = fixture();
        let t = card(&f).to_text().replacen("barking1:", "barking2:", 1);
        assert!(ContactCard::from_text(&t).is_err());
    }

    #[test]
    fn bundle_for_unknown_device_rejected() {
        let f = fixture();
        let mut rng = StdRng::seed_from_u64(11);
        let other = DeviceKeys::generate(&mut rng);
        let b = f.secrets.bundle(&other, false);
        let c = ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b]).unwrap();
        assert!(c.verify().is_err());
        assert!(ContactCard::from_text(&c.to_text()).is_err());
    }

    #[test]
    fn card_with_opk_rejected() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, true);
        assert!(b.opk.is_some());
        let c = ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b]).unwrap();
        assert!(c.verify().is_err());
    }

    #[test]
    fn duplicate_bundle_rejected() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, false);
        let c = ContactCard::sign(&f.root, "A", f.list.clone(), vec![b.clone(), b]).unwrap();
        assert!(c.verify().is_err());
    }

    #[test]
    fn tampered_name_rejected() {
        let f = fixture();
        let mut c = card(&f);
        c.display_name = "Mallory".into();
        assert_eq!(c.verify(), Err(CoreError::InvalidSignature));
    }

    #[test]
    fn long_name_rejected() {
        let f = fixture();
        let long = "x".repeat(65);
        assert!(ContactCard::sign(&f.root, &long, f.list.clone(), vec![]).is_err());
        let mut c = card(&f);
        c.display_name = long;
        assert!(c.verify().is_err());
    }

    /// Heaviest card: `MAX_DEVICES` devices, names at their maximum size.
    fn max_card() -> ContactCard {
        let mut rng = StdRng::seed_from_u64(12);
        let (root, _) = RootIdentity::generate(&mut rng);
        let mut certs = Vec::new();
        let mut bundles = Vec::new();
        for i in 0..MAX_DEVICES {
            let d = DeviceKeys::generate(&mut rng);
            let name = format!("{i:0>width$}", width = MAX_NAME_LEN);
            certs.push(DeviceCertificate::issue(&root, &d, &name, u64::MAX).unwrap());
            bundles.push(PrekeySecrets::generate(&mut rng, 0).bundle(&d, false));
        }
        let list = DeviceList::sign(&root, u64::MAX, certs).unwrap();
        ContactCard::sign(&root, &"x".repeat(MAX_NAME_LEN), list, bundles).unwrap()
    }

    #[test]
    fn max_card_text_roundtrip() {
        let c = max_card();
        let t = c.to_text();
        assert!(postcard::to_allocvec(&c).unwrap().len() <= MAX_CARD_BYTES);
        assert!(t.len() <= MAX_TEXT_LEN, "{} > {MAX_TEXT_LEN}", t.len());
        // Well beyond the size of a text message (4,000 bytes).
        assert!(t.len() > crate::envelope::MAX_TEXT_LEN);
        assert_eq!(ContactCard::from_text(&t).unwrap(), c);
        // One character more than the limit: rejected before decoding.
        let over = format!(
            "{CARD_PREFIX}{}",
            "A".repeat(MAX_TEXT_LEN - CARD_PREFIX.len() + 1)
        );
        assert_eq!(ContactCard::from_text(&over), Err(CoreError::TooLarge));
    }

    #[test]
    fn oversized_text_rejected_early() {
        let t = format!("barking1:{}", "A".repeat(200_000));
        assert_eq!(ContactCard::from_text(&t), Err(CoreError::TooLarge));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let f = fixture();
        let c = card(&f);
        let mut bytes = postcard::to_allocvec(&c).unwrap();
        bytes.push(0);
        let t = format!("barking1:{}", data_encoding::BASE64URL_NOPAD.encode(&bytes));
        assert!(ContactCard::from_text(&t).is_err());
    }

    proptest! {
        #[test]
        fn from_text_garbage_never_panics(s in ".*") {
            let _ = ContactCard::from_text(&s);
        }

        #[test]
        fn from_text_prefixed_garbage_never_panics(s in "[A-Za-z0-9_=-]{0,400}") {
            let _ = ContactCard::from_text(&format!("barking1:{s}"));
        }
    }
}
