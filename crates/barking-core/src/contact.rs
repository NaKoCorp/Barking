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
/// (`MAX_DEVICES` devices, names at their maximum size, plus
/// `MAX_CARD_NODES` hints of `MAX_NODE_HINT_BYTES` bytes) is about
/// 15 KiB (test `max_card_text_roundtrip`).
pub const MAX_CARD_BYTES: usize = 16 * 1024;
/// Maximum size of the text (unpadded base64url of `MAX_CARD_BYTES`,
/// about 22,000 characters), specific to the card: unrelated to the
/// maximum size of a text message.
pub const MAX_TEXT_LEN: usize = CARD_PREFIX.len() + MAX_CARD_BYTES.div_ceil(3) * 4;

/// Maximum number of node hints in a card.
pub const MAX_CARD_NODES: usize = 3;
/// Maximum size of one node hint (bytes). Hints are opaque to the core.
pub const MAX_NODE_HINT_BYTES: usize = 512;

/// A contact card. Serialized with serde (inside a message body or the
/// encrypted store) as the length-prefixed bytes of [`ContactCard::encode`],
/// so that every decode goes through [`ContactCard::decode`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactCard {
    pub display_name: String,
    pub devices: DeviceList,
    pub bundles: Vec<PrekeyBundle>,
    pub sig: [u8; 64],
    /// Opaque node hints (at most [`MAX_CARD_NODES`] of at most
    /// [`MAX_NODE_HINT_BYTES`] bytes), covered by the signature. The core
    /// never decodes them.
    pub nodes: Vec<Vec<u8>>,
}

/// Original card format (no `nodes`): also the encoding of a card
/// whose `nodes` is empty.
#[derive(Serialize, Deserialize)]
struct CardV1 {
    display_name: String,
    devices: DeviceList,
    bundles: Vec<PrekeyBundle>,
    #[serde(with = "sig_bytes")]
    sig: [u8; 64],
}

/// Format with node hints, used only when there is at least one.
#[derive(Serialize, Deserialize)]
struct CardV2 {
    display_name: String,
    devices: DeviceList,
    bundles: Vec<PrekeyBundle>,
    #[serde(with = "sig_bytes")]
    sig: [u8; 64],
    nodes: Vec<Vec<u8>>,
}

fn check_nodes(nodes: &[Vec<u8>]) -> Result<()> {
    if nodes.len() > MAX_CARD_NODES || nodes.iter().any(|n| n.len() > MAX_NODE_HINT_BYTES) {
        return Err(CoreError::TooLarge);
    }
    Ok(())
}

impl ContactCard {
    /// Signed bytes: postcard of the fields without `sig`. Without `nodes`,
    /// exactly the original form, so older cards still verify.
    fn signed_bytes(
        name: &str,
        devices: &DeviceList,
        bundles: &[PrekeyBundle],
        nodes: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        let bytes = if nodes.is_empty() {
            postcard::to_allocvec(&(name, devices, bundles))
        } else {
            postcard::to_allocvec(&(name, devices, bundles, nodes))
        };
        bytes.map_err(|_| CoreError::Malformed("card not serializable"))
    }

    pub fn sign(
        root: &RootIdentity,
        name: &str,
        devices: DeviceList,
        bundles: Vec<PrekeyBundle>,
        nodes: Vec<Vec<u8>>,
    ) -> Result<Self> {
        if name.len() > MAX_NAME_LEN {
            return Err(CoreError::TooLarge);
        }
        check_nodes(&nodes)?;
        let bytes = Self::signed_bytes(name, &devices, &bundles, &nodes)?;
        let sig = root.sign(labels::CONTACT_CARD, &bytes);
        Ok(ContactCard {
            display_name: name.to_owned(),
            devices,
            bundles,
            sig,
            nodes,
        })
    }

    /// Binary encoding: the original format when `nodes` is empty (byte for
    /// byte), otherwise the same fields followed by `nodes`.
    pub fn encode(&self) -> Vec<u8> {
        // Serialization of a structure with no invalid state: cannot fail
        // (postcard into a `Vec`).
        if self.nodes.is_empty() {
            postcard::to_allocvec(&CardV1 {
                display_name: self.display_name.clone(),
                devices: self.devices.clone(),
                bundles: self.bundles.clone(),
                sig: self.sig,
            })
        } else {
            postcard::to_allocvec(&CardV2 {
                display_name: self.display_name.clone(),
                devices: self.devices.clone(),
                bundles: self.bundles.clone(),
                sig: self.sig,
                nodes: self.nodes.clone(),
            })
        }
        .unwrap_or_default()
    }

    /// Decodes a card (without verifying it): the full form first, then the
    /// original form without `nodes`. Trailing bytes are an error, and so is
    /// an explicit empty `nodes` (its canonical form omits it).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if let Ok((c, [])) = postcard::take_from_bytes::<CardV2>(bytes) {
            if c.nodes.is_empty() {
                return Err(CoreError::Malformed("non canonical card"));
            }
            return Ok(ContactCard {
                display_name: c.display_name,
                devices: c.devices,
                bundles: c.bundles,
                sig: c.sig,
                nodes: c.nodes,
            });
        }
        match postcard::take_from_bytes::<CardV1>(bytes) {
            Ok((c, [])) => Ok(ContactCard {
                display_name: c.display_name,
                devices: c.devices,
                bundles: c.bundles,
                sig: c.sig,
                nodes: Vec::new(),
            }),
            Ok(_) => Err(CoreError::Malformed("extra bytes after the card")),
            Err(_) => Err(CoreError::Malformed("unreadable card")),
        }
    }

    pub fn verify(&self) -> Result<()> {
        if self.display_name.len() > MAX_NAME_LEN || self.bundles.len() > MAX_DEVICES {
            return Err(CoreError::TooLarge);
        }
        check_nodes(&self.nodes)?;
        let bytes = Self::signed_bytes(
            &self.display_name,
            &self.devices,
            &self.bundles,
            &self.nodes,
        )?;
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
        let bytes = self.encode();
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
        let card = Self::decode(&bytes)?;
        card.verify()?;
        Ok(card)
    }
}

impl Serialize for ContactCard {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.encode())
    }
}

impl<'de> Deserialize<'de> for ContactCard {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = ContactCard;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an encoded contact card")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                if v.len() > MAX_CARD_BYTES {
                    return Err(E::custom("card too large"));
                }
                ContactCard::decode(v).map_err(E::custom)
            }
        }
        d.deserialize_bytes(V)
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
        ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b], Vec::new()).unwrap()
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
        let c = ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b], Vec::new()).unwrap();
        assert!(c.verify().is_err());
        assert!(ContactCard::from_text(&c.to_text()).is_err());
    }

    #[test]
    fn card_with_opk_rejected() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, true);
        assert!(b.opk.is_some());
        let c = ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b], Vec::new()).unwrap();
        assert!(c.verify().is_err());
    }

    #[test]
    fn duplicate_bundle_rejected() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, false);
        let c = ContactCard::sign(&f.root, "A", f.list.clone(), vec![b.clone(), b], Vec::new())
            .unwrap();
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
        assert!(ContactCard::sign(&f.root, &long, f.list.clone(), vec![], Vec::new()).is_err());
        let mut c = card(&f);
        c.display_name = long;
        assert!(c.verify().is_err());
    }

    /// Heaviest card: `MAX_DEVICES` devices, names at their maximum size,
    /// `MAX_CARD_NODES` hints of `MAX_NODE_HINT_BYTES` bytes.
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
        let nodes = (0..MAX_CARD_NODES)
            .map(|i| vec![i as u8; MAX_NODE_HINT_BYTES])
            .collect();
        ContactCard::sign(&root, &"x".repeat(MAX_NAME_LEN), list, bundles, nodes).unwrap()
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
    fn max_card_still_fits() {
        let c = max_card();
        assert_eq!(c.nodes.len(), MAX_CARD_NODES);
        assert!(c.encode().len() <= MAX_CARD_BYTES);
        assert_eq!(ContactCard::decode(&c.encode()).unwrap(), c);
        // Also inside a message body (serde form, length-prefixed).
        let bytes = postcard::to_allocvec(&c).unwrap();
        assert_eq!(postcard::from_bytes::<ContactCard>(&bytes).unwrap(), c);
    }

    /// Text of the card of `fixture()` / `card()` encoded before node hints
    /// existed (captured on the previous format).
    const CARD_V1_TEXT: &str = include_str!("../tests/data/card_v1.txt");

    #[test]
    fn card_without_nodes_is_byte_identical() {
        let f = fixture();
        let c = card(&f);
        assert!(c.nodes.is_empty());
        assert_eq!(c.to_text(), CARD_V1_TEXT.trim());
        // An old card decodes with no nodes and still verifies.
        let old = ContactCard::from_text(CARD_V1_TEXT).unwrap();
        assert!(old.nodes.is_empty());
        old.verify().unwrap();
        assert_eq!(old, c);
    }

    #[test]
    fn card_nodes_roundtrip() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, false);
        let nodes = vec![vec![1, 2, 3], vec![9; 512]];
        let c =
            ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![b], nodes.clone()).unwrap();
        c.verify().unwrap();
        let back = ContactCard::from_text(&c.to_text()).unwrap();
        assert_eq!(back.nodes, nodes);
        assert_eq!(back, c);
    }

    #[test]
    fn card_nodes_are_signed() {
        let f = fixture();
        let b = f.secrets.bundle(&f.dev, false);
        let mut c = ContactCard::sign(
            &f.root,
            "Alice",
            f.list.clone(),
            vec![b],
            vec![vec![1, 2, 3]],
        )
        .unwrap();
        c.nodes[0][1] ^= 1;
        assert_eq!(c.verify(), Err(CoreError::InvalidSignature));
        assert_eq!(
            ContactCard::from_text(&c.to_text()),
            Err(CoreError::InvalidSignature)
        );
        // Removing the hints changes the signed bytes too.
        c.nodes.clear();
        assert_eq!(c.verify(), Err(CoreError::InvalidSignature));
    }

    #[test]
    fn card_nodes_limits() {
        let f = fixture();
        let sign = |nodes: Vec<Vec<u8>>| {
            ContactCard::sign(&f.root, "Alice", f.list.clone(), vec![], nodes)
        };
        assert_eq!(sign(vec![vec![0]; 4]).map(|_| ()), Err(CoreError::TooLarge));
        assert_eq!(
            sign(vec![vec![0; 513]]).map(|_| ()),
            Err(CoreError::TooLarge)
        );
        sign(vec![vec![0; 512]; 3]).unwrap();
        // The same limits apply when decoding a card signed elsewhere.
        for nodes in [vec![vec![0u8]; 4], vec![vec![0u8; 513]]] {
            let mut c = sign(vec![vec![0]]).unwrap();
            c.nodes = nodes;
            assert_eq!(c.verify(), Err(CoreError::TooLarge));
            assert_eq!(
                ContactCard::from_text(&c.to_text()),
                Err(CoreError::TooLarge)
            );
        }
    }

    #[test]
    fn explicit_empty_nodes_rejected() {
        let f = fixture();
        let c = card(&f);
        let mut bytes = c.encode();
        bytes.push(0);
        assert!(ContactCard::decode(&bytes).is_err());
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
