//! Linking a new device in four steps (spec §3.1).
//!
//! 1. **Offer** (A, admin): [`Core::link_offer`] draws a 32-byte link
//!    secret, valid for 10 minutes, kept in `meta`
//!    (`link_offer`); a new offer replaces the previous one.
//! 2. **Request** (T, new device): [`Core::begin_link`] creates T's
//!    database in a "pending" state (`meta` `pending_link` = secret and root)
//!    and returns the request, authenticated by an HMAC-SHA256 whose key is
//!    derived from the secret (`LINK_MAC`).
//! 3. **Acceptance** (A): [`Core::link_device`] verifies the offer (present,
//!    not expired), the MAC (in constant time), the proof of possession, signs
//!    the `version + 1` list and returns the link bundle, encrypted by
//!    XChaCha20-Poly1305 with a key derived from the secret (`LINK_BUNDLE`). The
//!    associated data bind the bundle to the root and to device T. The
//!    plaintext is signed by the root (`LINK_BUNDLE_SIG`, over its BLAKE3 hash),
//!    as is the history archive (`LINK_HISTORY_SIG`): knowing the secret
//!    (compromised link channel) does not allow forging T's contacts or
//!    history.
//!    The offer is consumed (erased) in the same transaction, provided
//!    it is still there and the stored list has not changed. An expired
//!    offer is erased as soon as it is found (here and at open).
//! 4. **Finish** (T): [`Core::finish_link`] decrypts, verifies the signature of
//!    the expected root on the plaintext, then the list (expected root,
//!    T present), the card, the key packets and each contact,
//!    then records everything and erases the secret in a single transaction.
//!    T refuses to finish more than a day after the offer expires
//!    ([`PENDING_LINK_GRACE_SECS`]): a pending link has a bounded
//!    lifetime, beyond which one must start over.
//!
//! Any refusal returns `CoreError::Link(reason)` (or the underlying
//! verification error) without modifying any state. The secret is never displayed
//! (`Debug`) nor logged, and it is wrapped in `Zeroizing`.
//!
//! **Pending device.** Until `finish_link` has succeeded, T has no
//! signed device list. `Core::devices` then holds a dummy list
//! (the offer's root, version 0, no certificate, null signature),
//! never stored, never sent nor verified: it only serves
//! `fingerprint()`. The `Core::pending` flag makes any operation that
//! requires a linked device return `CoreError::LinkPending`.

use std::collections::HashSet;
use std::path::Path;

use rand_core::CryptoRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::contacts::{MAX_ALIAS_LEN, claimed_by_other, overlaps};
use super::history::{self, HistoryArchive};
use super::send::SealTime;
use super::{
    Core, META_DEVICE, META_DEVICE_LIST, META_DEVICE_NAME, META_DISPLAY_NAME, META_LINKED_BUNDLES,
    META_PREKEYS, ensure_empty, log, sync,
};
use crate::contact::ContactCard;
use crate::crypto::aead::{xopen, xseal};
use crate::crypto::bytes64;
use crate::crypto::kdf::{hmac_sha256, hmac_sha256_verify};
use crate::crypto::labels;
use crate::envelope::Body;
use crate::handshake::{PrekeyBundle, PrekeySecrets};
use crate::identity::device_list::MAX_DEVICES;
use crate::identity::root::{Fingerprint, RootIdentity, RootPublic};
use crate::identity::{DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic};
use crate::packet::Packet;
use crate::store::MessageId;
use crate::store::{Queries, Store};
use crate::transparency::SyncKind;
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

/// Validity duration of a link offer: 10 minutes.
pub const LINK_OFFER_TTL_SECS: u64 = 600;

/// Pending offer on A (only one at a time).
pub(super) const META_LINK_OFFER: &str = "link_offer";
/// Pending link on T: secret and expected root.
pub(super) const META_PENDING_LINK: &str = "pending_link";
/// My card signed by the root, as sent to the new device.
pub(super) const META_OWN_CARD: &str = "own_card";

const UNREADABLE: CoreError = CoreError::Link("unreadable link file");
const BAD_BUNDLE: CoreError = CoreError::Link("invalid link bundle");
const BAD_CONTACT: CoreError = CoreError::Link("invalid contact in the link bundle");
const BAD_SIGNATURE: CoreError = CoreError::Link("link bundle not signed by the root");

/// Maximum size of a link offer or request file.
pub const MAX_LINK_FILE_BYTES: usize = 64 * 1024;

/// Maximum size of a link bundle: it carries all my contacts (card,
/// alias), so much more than the offer or the request.
pub const MAX_LINK_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// Link bundle limit lowered by the tests.
    static BUNDLE_MAX_OVERRIDE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Maximum size of a link bundle at generation.
fn bundle_max() -> usize {
    #[cfg(test)]
    if let Some(m) = BUNDLE_MAX_OVERRIDE.with(std::cell::Cell::get) {
        return m;
    }
    MAX_LINK_BUNDLE_BYTES
}

/// Decodes exactly `bytes` (postcard), at most `max` bytes; larger →
/// "link file too large".
fn decode_bounded<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T> {
    if bytes.len() > max {
        return Err(CoreError::Link("link file too large"));
    }
    decode_exact(bytes)
}

/// Decodes exactly `bytes` (postcard): extra or unreadable bytes →
/// "unreadable link file". Never panics.
pub(super) fn decode_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((v, [])) => Ok(v),
        _ => Err(UNREADABLE),
    }
}

/// Link offer (A → T, out of band). `Debug` does not display the secret.
#[derive(Clone)]
pub struct LinkOffer {
    pub root: RootPublic,
    pub secret: Zeroizing<[u8; 32]>,
    pub expires_at: u64,
}

impl core::fmt::Debug for LinkOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkOffer")
            .field("root", &self.root.fingerprint().to_string())
            .field("secret", &"<secret>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Maximum size of the serialized offer: root (32), secret (32), date (varint ≤ 10).
const OFFER_MAX_LEN: usize = 80;

impl LinkOffer {
    /// Bytes of the offer file (postcard). Contains the secret: wiped on
    /// drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new([0u8; OFFER_MAX_LEN]);
        let wire = (&self.root, &*self.secret, self.expires_at);
        // Size bounded above: cannot fail.
        let len = postcard::to_slice(&wire, &mut buf[..])
            .map(|s| s.len())
            .unwrap_or(0);
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&buf[..len]);
        out
    }

    /// Inverse of [`LinkOffer::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (root, mut secret, expires_at): (RootPublic, [u8; 32], u64) =
            decode_bounded(bytes, MAX_LINK_FILE_BYTES)?;
        let offer = LinkOffer {
            root,
            secret: Zeroizing::new(secret),
            expires_at,
        };
        secret.zeroize();
        Ok(offer)
    }
}

/// Link request (T → A, out of band), authenticated by `mac`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LinkRequest {
    pub device: DevicePublic,
    pub bundle: PrekeyBundle,
    pub name: String,
    pub issued_at: u64,
    /// Proof of possession (`DeviceKeys::possession_proof`), bound to the
    /// offer's root.
    #[serde(with = "bytes64")]
    pub device_sig: [u8; 64],
    /// `HMAC-SHA256(derive_key(LINK_MAC, secret), postcard(fields without mac))`.
    pub mac: [u8; 32],
}

/// Request fields covered by the MAC.
#[derive(Serialize)]
struct MacInput<'a> {
    device: &'a DevicePublic,
    bundle: &'a PrekeyBundle,
    name: &'a str,
    issued_at: u64,
    #[serde(with = "bytes64")]
    device_sig: [u8; 64],
}

fn mac_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(labels::LINK_MAC, secret))
}

impl LinkRequest {
    fn mac_input(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&MacInput {
            device: &self.device,
            bundle: &self.bundle,
            name: &self.name,
            issued_at: self.issued_at,
            device_sig: self.device_sig,
        })
        .map_err(|_| CoreError::Malformed("unserializable request"))
    }

    fn compute_mac(&self, secret: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(hmac_sha256(&*mac_key(secret), &self.mac_input()?))
    }

    /// Verifies the MAC in constant time (`Mac::verify_slice`).
    fn mac_ok(&self, secret: &[u8; 32]) -> Result<bool> {
        Ok(hmac_sha256_verify(
            &*mac_key(secret),
            &self.mac_input()?,
            &self.mac,
        ))
    }

    /// Bytes of the request file (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse of [`LinkRequest::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_bounded(bytes, MAX_LINK_FILE_BYTES)
    }
}

/// Link bundle (A → T, out of band): encrypted [`LinkPlain`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBundle(Vec<u8>);

impl core::fmt::Debug for LinkBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LinkBundle(<{} bytes>)", self.0.len())
    }
}

impl LinkBundle {
    /// Bytes of the link file (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse of [`LinkBundle::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_bounded(bytes, MAX_LINK_BUNDLE_BYTES)
    }
}

/// A contact as copied to the new device.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ContactSnapshot {
    pub card: ContactCard,
    pub alias: Option<String>,
    pub verified: bool,
    /// Date of the copy: storage does not keep the real date of addition.
    pub added_at: u64,
}

/// Plaintext of the link bundle.
#[derive(Serialize, Deserialize)]
struct LinkPlain {
    devices: DeviceList,
    card: ContactCard,
    /// Key packets of my other devices (all except T).
    own_bundles: Vec<PrekeyBundle>,
    contacts: Vec<ContactSnapshot>,
}

/// Result of [`Core::link_device`].
#[derive(Debug)]
pub struct LinkOutcome {
    pub bundle: LinkBundle,
    /// History archive (if requested), encrypted with the link
    /// secret: to hand to T out of band along with the link bundle.
    pub history: Option<HistoryArchive>,
    /// Packets to send, already in the send queue: `SyncDevices` (my new
    /// card) for each of my other devices except the new one, then
    /// `CardUpdate` for each reachable device of each contact.
    pub packets: Vec<Packet>,
}

/// Offer stored on A.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredOffer {
    secret: [u8; 32],
    expires_at: u64,
}

/// Pending link stored on T.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PendingLink {
    secret: [u8; 32],
    #[zeroize(skip)]
    root: RootPublic,
    /// Offer expiry (A's clock, copied from the offer).
    expires_at: u64,
}

/// Lifetime of a pending link on T beyond the offer's
/// expiry: one day, to tolerate clock skew between A and T and the
/// file transfer delay. Past that delay, `finish_link` refuses
/// ("offer expired") and T stays pending: its database must be recreated
/// and the process restarted with a new offer.
pub(super) const PENDING_LINK_GRACE_SECS: u64 = 86_400;

/// Erases the pending offer if it has expired at `now` (its secret is no
/// longer useful). Called by `link_device` and at open.
pub(super) fn purge_expired_offer(q: &impl Queries, now: u64) -> Result<()> {
    if q.get_meta::<StoredOffer>(META_LINK_OFFER)?
        .is_some_and(|o| now > o.expires_at)
    {
        q.delete_meta(META_LINK_OFFER)?;
    }
    Ok(())
}

/// Associated data of the link bundle: root and device T.
fn bundle_ad(root: &RootPublic, device: &DeviceId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(48);
    ad.extend_from_slice(&root.0);
    ad.extend_from_slice(&device.0);
    ad
}

fn bundle_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(labels::LINK_BUNDLE, secret))
}

/// Encrypted plaintext of the link bundle: the serialized [`LinkPlain`] and the
/// root's signature over its hash (`LINK_BUNDLE_SIG`). The link
/// secret is therefore not enough to forge a bundle: T verifies the signature
/// with the offer's root before reading anything.
#[derive(Serialize, Deserialize)]
struct SignedPlain {
    plain: Vec<u8>,
    #[serde(with = "bytes64")]
    sig: [u8; 64],
}

impl Drop for SignedPlain {
    fn drop(&mut self) {
        self.plain.zeroize();
    }
}

/// Encrypts the link bundle plaintext for `device`, signed
/// by `signer` (A's root; `root` is its public key, bound to the
/// associated data).
fn seal_bundle(
    secret: &[u8; 32],
    root: &RootPublic,
    signer: &RootIdentity,
    device: &DeviceId,
    plain: &LinkPlain,
    rng: &mut impl CryptoRng,
) -> Result<LinkBundle> {
    let bytes = postcard::to_allocvec(plain).map_err(|_| CoreError::Malformed("link bundle"))?;
    let sig = signer.sign(labels::LINK_BUNDLE_SIG, blake3::hash(&bytes).as_bytes());
    let signed = SignedPlain { plain: bytes, sig };
    let pt = Zeroizing::new(
        postcard::to_allocvec(&signed).map_err(|_| CoreError::Malformed("link bundle"))?,
    );
    let key = bundle_key(secret);
    Ok(LinkBundle(xseal(&key, &bundle_ad(root, device), &pt, rng)))
}

/// Decrypts the link bundle and verifies `root`'s signature over its
/// plaintext, before any decoding of it.
fn open_bundle(
    secret: &[u8; 32],
    root: &RootPublic,
    device: &DeviceId,
    bundle: &LinkBundle,
) -> Result<LinkPlain> {
    let key = bundle_key(secret);
    let pt =
        Zeroizing::new(xopen(&key, &bundle_ad(root, device), &bundle.0).map_err(|_| BAD_BUNDLE)?);
    let signed: SignedPlain = decode_exact(&pt)?;
    root.verify(
        labels::LINK_BUNDLE_SIG,
        blake3::hash(&signed.plain).as_bytes(),
        &signed.sig,
    )
    .map_err(|_| BAD_SIGNATURE)?;
    decode_exact(&signed.plain)
}

/// Dummy list of a pending device (see the module documentation).
pub(super) fn pending_devices(root: RootPublic) -> DeviceList {
    DeviceList {
        root,
        version: 0,
        certs: Vec::new(),
        sig: [0u8; 64],
    }
}

/// Expected root of a pending link, if the database has one.
pub(super) fn pending_root(q: &impl Queries) -> Result<Option<RootPublic>> {
    Ok(q.get_meta::<PendingLink>(META_PENDING_LINK)?
        .map(|p| p.root))
}

impl Core {
    /// Refuses the operation while this device awaits the end of its link.
    pub(super) fn ensure_linked(&self) -> Result<()> {
        if self.pending {
            return Err(CoreError::LinkPending);
        }
        Ok(())
    }

    /// Step 1 (A): new link offer, valid for 10 minutes. It
    /// replaces the previous offer. Admin only.
    pub fn link_offer(&mut self, now: u64, rng: &mut impl CryptoRng) -> Result<LinkOffer> {
        self.ensure_linked()?;
        let root = self.root.as_ref().ok_or(CoreError::NotAdmin)?.public();
        let mut stored = StoredOffer {
            secret: [0u8; 32],
            expires_at: now.saturating_add(LINK_OFFER_TTL_SECS),
        };
        rng.fill_bytes(&mut stored.secret);
        self.store.put_meta(META_LINK_OFFER, &stored)?;
        Ok(LinkOffer {
            root,
            secret: Zeroizing::new(stored.secret),
            expires_at: stored.expires_at,
        })
    }

    /// Step 2 (T): creates T's database (device keys, prekeys) pending
    /// link, and returns the request to hand to A.
    pub fn begin_link(
        path: &Path,
        db_key: &[u8; 32],
        offer: &LinkOffer,
        name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<(Core, LinkRequest)> {
        if now > offer.expires_at {
            return Err(CoreError::Link("offer expired"));
        }
        let device = DeviceKeys::generate(rng);
        let prekeys = PrekeySecrets::generate(rng, 0);
        // Proof of possession bound to the offer's root (error if the name
        // is too long), before any write.
        let device_sig = device.possession_proof(&offer.root, name, now)?;
        let mut req = LinkRequest {
            device: device.public(),
            bundle: prekeys.bundle(&device, false),
            name: name.to_owned(),
            issued_at: now,
            device_sig,
            mac: [0u8; 32],
        };
        req.mac = req.compute_mac(&offer.secret)?;
        let pending = PendingLink {
            secret: *offer.secret,
            root: offer.root,
            expires_at: offer.expires_at,
        };
        let mut store = Store::open(path, db_key)?;
        ensure_empty(&store)?;
        store.transaction(|tx| {
            let dev = Zeroizing::new(device.to_bytes().to_vec());
            tx.put_meta(META_DEVICE, &*dev)?;
            tx.put_meta(META_DEVICE_NAME, &name)?;
            tx.put_meta(META_PREKEYS, &prekeys)?;
            tx.put_meta(META_PENDING_LINK, &pending)
        })?;
        let core = Core::assemble(
            store,
            None,
            device,
            prekeys,
            pending_devices(offer.root),
            Vec::new(),
            true,
        );
        Ok((core, req))
    }

    /// Step 3 (A): accepts a link request. Verifies the pending offer,
    /// the MAC, the proof of possession; signs the `version + 1` list
    /// and returns the encrypted link bundle. If `with_history`, the history
    /// archive (messages of the copied contacts) is produced in the same
    /// transaction, with the same secret (see `history`). An archive of more
    /// than `MAX_HISTORY_CHUNKS` chunks makes the link fail ("history
    /// too large") without writing anything or consuming the offer.
    ///
    /// In the same transaction, my new card (carrying my recorded display
    /// name) is queued: `SyncDevices` for my other devices
    /// except T, `CardUpdate` for each reachable device of each contact
    /// (spec §3.2). These packets are returned in `LinkOutcome::packets`.
    ///
    /// The offer is consumed in the transaction that records the new
    /// list: it must still be present and identical there, and the stored
    /// list must not have changed since it was read (another opening
    /// of the same database may have linked a device in the meantime); otherwise "offer
    /// missing or already used", without writing anything. The only exception to "a
    /// refusal modifies nothing": an offer found expired is erased.
    pub fn link_device(
        &mut self,
        req: &LinkRequest,
        with_history: bool,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<LinkOutcome> {
        self.ensure_linked()?;
        let root = self.root.as_ref().ok_or(CoreError::NotAdmin)?;
        let root_pub = root.public();
        let offer = self
            .store
            .get_meta::<StoredOffer>(META_LINK_OFFER)?
            .ok_or(CoreError::Link("offer missing or already used"))?;
        if now > offer.expires_at {
            purge_expired_offer(&self.store, now)?;
            return Err(CoreError::Link("offer expired"));
        }
        if !req.mac_ok(&offer.secret)? {
            return Err(CoreError::Link("invalid MAC"));
        }
        let device = req.device;
        // No key (identifier, signature, X25519) of one of my devices,
        // myself included: an already linked device is not linked a second time.
        if self
            .devices
            .certs
            .iter()
            .any(|c| overlaps(&c.device, &device))
            || overlaps(&self.device.public(), &device)
        {
            return Err(CoreError::Malformed("device already linked"));
        }
        req.bundle.verify()?;
        if req.bundle.device != device {
            return Err(CoreError::Malformed("key packet of another device"));
        }
        if req.bundle.opk.is_some() {
            return Err(CoreError::Malformed("one-time key forbidden"));
        }
        if claimed_by_other(&self.store, None, &[device])? {
            return Err(CoreError::Malformed(
                "device already associated with a contact",
            ));
        }
        let version = self
            .devices
            .version
            .checked_add(1)
            .ok_or(CoreError::TooLarge)?;
        let cert = DeviceCertificate::issue_with_proof(
            root,
            device,
            &req.name,
            req.issued_at,
            req.device_sig,
        )?;
        let mut certs = self.devices.certs.clone();
        certs.push(cert);
        if certs.len() > MAX_DEVICES {
            return Err(CoreError::TooLarge);
        }
        let devices = DeviceList::sign(root, version, certs)?;
        let mut linked: Vec<PrekeyBundle> = self
            .linked_bundles
            .iter()
            .filter(|b| b.device != device)
            .cloned()
            .collect();
        linked.push(req.bundle.clone());

        // Key packets of all my devices, then those T must keep.
        let mut bundles = vec![self.prekeys.bundle(&self.device, false)];
        bundles.extend(
            linked
                .iter()
                .filter(|b| devices.certs.iter().any(|c| c.device == b.device))
                .cloned(),
        );
        let own_bundles: Vec<PrekeyBundle> = bundles
            .iter()
            .filter(|b| b.device != device)
            .cloned()
            .collect();
        // My recorded display name (`contact_card`, `set_display_name`).
        let display_name = self
            .store
            .get_meta::<String>(META_DISPLAY_NAME)?
            .unwrap_or_default();
        let card = ContactCard::sign(
            root,
            &display_name,
            devices.clone(),
            bundles,
            self.store
                .get_meta::<Vec<Vec<u8>>>(super::META_CARD_NODES)?
                .unwrap_or_default(),
        )?;
        let contacts = self
            .store
            .list_contacts()?
            .into_iter()
            .map(|row| {
                Ok(ContactSnapshot {
                    card: super::load_card(&row.card)?,
                    alias: (!row.alias.is_empty()).then_some(row.alias),
                    verified: row.verified,
                    added_at: now,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let plain = LinkPlain {
            devices: devices.clone(),
            card: card.clone(),
            own_bundles,
            contacts,
        };
        let bundle = seal_bundle(&offer.secret, &root_pub, root, &device.id(), &plain, rng)?;
        // Refused before the transaction: T would refuse this bundle when reading it,
        // and the offer would be lost for nothing. Compared like the reader
        // (`LinkBundle::from_bytes`): on the encoded file, prefix included.
        if bundle.to_bytes().len() > bundle_max() {
            return Err(CoreError::Link("link bundle too large"));
        }
        // The archive carries only the messages of the copied contacts: T refuses
        // an archive that mentions another one.
        let history_contacts: HashSet<Fingerprint> = plain
            .contacts
            .iter()
            .map(|s| s.card.fingerprint())
            .collect();

        let event = TransparencyEvent::DeviceLinked {
            device: device.id(),
            name: req.name.clone(),
        };
        let read_version = self.devices.version;
        let me = &self.device;
        let written = self.store.transaction(|tx| {
            const USED: CoreError = CoreError::Link("offer missing or already used");
            let same_offer = tx
                .get_meta::<StoredOffer>(META_LINK_OFFER)?
                .is_some_and(|o| o.secret == offer.secret && o.expires_at == offer.expires_at);
            let same_list = tx
                .get_meta::<DeviceList>(META_DEVICE_LIST)?
                .is_some_and(|l| l.version == read_version);
            // Offer consumed: the secret disappears from the database.
            if !same_offer || !same_list || !tx.delete_meta(META_LINK_OFFER)? {
                return Err(USED);
            }
            // Archive read inside the transaction: same state as the rest.
            let history = if with_history {
                let entries = history::export(tx, &history_contacts)?;
                Some(history::seal_archive(&offer.secret, root, &entries, rng)?)
            } else {
                None
            };
            // New card for my other devices, sealed before
            // writing the new list: T, which receives everything through the
            // link bundle, is not yet in the stored list.
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            let devices_body = Body::SyncDevices {
                card: Box::new(card.clone()),
            };
            let mut packets = sync::seal_to_own(
                tx,
                me,
                &devices_body,
                SyncKind::Devices,
                MessageId(id),
                SealTime::at(now),
                rng,
            )?;
            tx.put_meta(META_DEVICE_LIST, &devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &linked)?;
            tx.put_meta(META_OWN_CARD, &card)?;
            sync::purge_removed_own_sessions(tx, &devices)?;
            log(tx, now, None, &event)?;
            // And for each of my contacts (spec §3.2).
            packets.extend(sync::send_card_update(tx, me, &card, now, rng)?);
            Ok((packets, history))
        });
        let (packets, history) = match written {
            Ok(written) => written,
            Err(e) => {
                // Stale in-memory list (another opening of the database
                // linked a device): reread, so that a new attempt starts from
                // the right one.
                if matches!(e, CoreError::Link(_)) {
                    self.reload_own_devices()?;
                }
                return Err(e);
            }
        };
        drop(offer);
        self.devices = devices;
        self.linked_bundles = linked;
        Ok(LinkOutcome {
            bundle,
            history,
            packets,
        })
    }

    /// Step 4 (T): finishes the link with A's bundle. Everything is
    /// verified before writing; everything is written in a single transaction.
    /// On failure, T stays pending and nothing is modified.
    ///
    /// With `history`, the archive is fully verified and decrypted before
    /// the transaction (see `history`), then its absent messages are
    /// inserted in the same transaction; `HistoryImported` is logged
    /// last. An invalid archive makes the whole link fail
    /// ("invalid history").
    pub fn finish_link(
        &mut self,
        bundle: &LinkBundle,
        history: Option<&HistoryArchive>,
        now: u64,
    ) -> Result<()> {
        if !self.pending {
            return Err(CoreError::Link("no pending link"));
        }
        let pending = self
            .store
            .get_meta::<PendingLink>(META_PENDING_LINK)?
            .ok_or(CoreError::Link("no pending link"))?;
        if now > pending.expires_at.saturating_add(PENDING_LINK_GRACE_SECS) {
            return Err(CoreError::Link("offer expired"));
        }
        let me = self.device.public();
        let plain = open_bundle(&pending.secret, &pending.root, &me.id(), bundle)?;
        check_plain(&plain, &pending.root, &me)?;
        let entries = match history {
            Some(archive) => {
                let entries = history::open_archive(&pending.secret, &pending.root, archive)?;
                let known: HashSet<Fingerprint> = plain
                    .contacts
                    .iter()
                    .map(|s| s.card.fingerprint())
                    .collect();
                history::check_entries(&entries, &known)?;
                Some(entries)
            }
            None => None,
        };

        let my_fp = pending.root.fingerprint();
        let device_count = u32::try_from(plain.devices.certs.len()).unwrap_or(u32::MAX);
        let contact_count = u32::try_from(plain.contacts.len()).unwrap_or(u32::MAX);
        let event = TransparencyEvent::LinkFinished {
            device_count,
            contacts: contact_count,
        };
        self.store.transaction(|tx| {
            let mut fps = HashSet::new();
            let mut aliases = HashSet::new();
            for snap in &plain.contacts {
                let card = &snap.card;
                let fp = card.fingerprint();
                card.verify().map_err(|_| BAD_CONTACT)?;
                if fp == my_fp || !fps.insert(fp) {
                    return Err(BAD_CONTACT);
                }
                let claimed: Vec<DevicePublic> =
                    card.devices.certs.iter().map(|c| c.device).collect();
                if plain
                    .devices
                    .certs
                    .iter()
                    .any(|mine| claimed.iter().any(|d| overlaps(d, &mine.device)))
                {
                    return Err(BAD_CONTACT);
                }
                // Contacts inserted one by one: also verifies the previous ones.
                if claimed_by_other(tx, Some(fp), &claimed)? {
                    return Err(BAD_CONTACT);
                }
                let alias = snap.alias.as_deref().map(str::trim).unwrap_or("");
                if alias.len() > MAX_ALIAS_LEN
                    || (!alias.is_empty() && !aliases.insert(alias.to_owned()))
                {
                    return Err(BAD_CONTACT);
                }
                let bytes = card.encode();
                tx.upsert_contact(fp, &bytes, alias, snap.verified)?;
            }
            tx.put_meta(META_DEVICE_LIST, &plain.devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &plain.own_bundles)?;
            tx.put_meta(META_OWN_CARD, &plain.card)?;
            sync::purge_removed_own_sessions(tx, &plain.devices)?;
            // Link finished: the secret disappears from the database.
            tx.delete_meta(META_PENDING_LINK)?;
            log(tx, now, None, &event)?;
            if let Some(entries) = &entries {
                let count = history::import(tx, entries)?;
                log(tx, now, None, &TransparencyEvent::HistoryImported { count })?;
            }
            Ok(())
        })?;
        drop(pending);
        self.devices = plain.devices;
        self.linked_bundles = plain.own_bundles;
        self.pending = false;
        Ok(())
    }
}

/// Verifies the link bundle plaintext on T's side: list signed by the expected
/// root and containing T, consistent card, valid key packets of my other
/// devices.
fn check_plain(plain: &LinkPlain, root: &RootPublic, me: &DevicePublic) -> Result<()> {
    if plain.devices.root != *root || plain.card.devices.root != *root {
        return Err(CoreError::Link("unexpected root"));
    }
    plain.devices.verify()?;
    if !plain.devices.certs.iter().any(|c| c.device == *me) {
        return Err(CoreError::Link("device absent from the list"));
    }
    plain.card.verify()?;
    if plain.card.devices != plain.devices {
        return Err(BAD_BUNDLE);
    }
    let mut seen = HashSet::new();
    for b in &plain.own_bundles {
        b.verify()?;
        if b.device == *me
            || b.opk.is_some()
            || !seen.insert(b.device.id())
            || !plain.devices.certs.iter().any(|c| c.device == b.device)
        {
            return Err(BAD_BUNDLE);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn link_files_refuse_oversized_input() {
        let big = vec![0u8; MAX_LINK_FILE_BYTES + 1];
        let too_large = Err(CoreError::Link("link file too large"));
        assert_eq!(LinkOffer::from_bytes(&big).map(|_| ()), too_large);
        assert_eq!(LinkRequest::from_bytes(&big).map(|_| ()), too_large);
        // The link bundle accepts more (all my contacts).
        assert_eq!(
            LinkBundle::from_bytes(&big),
            Err(CoreError::Link("unreadable link file"))
        );
        let huge = vec![0u8; MAX_LINK_BUNDLE_BYTES + 1];
        assert_eq!(LinkBundle::from_bytes(&huge).map(|_| ()), too_large);
    }

    proptest::proptest! {
        #[test]
        fn link_files_garbage_never_panics(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
            let _ = LinkOffer::from_bytes(&bytes);
            let _ = LinkRequest::from_bytes(&bytes);
            let _ = LinkBundle::from_bytes(&bytes);
            let _ = HistoryArchive::from_bytes(&bytes);
        }
    }

    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tempfile::TempDir;

    const NOW: u64 = 1_800_000_000;

    fn admin(d: &TempDir, file: &str, seed: u8, rng: &mut StdRng) -> Core {
        Core::create(&d.path().join(file), &[seed; 32], file, NOW, rng)
            .unwrap()
            .0
    }

    /// Bundle sealed with the right secret for T, but with chosen content.
    fn forged_bundle(
        offer: &LinkOffer,
        t: &Core,
        plain: &LinkPlain,
        signer: &RootIdentity,
        rng: &mut StdRng,
    ) -> LinkBundle {
        let id = t.device.public().id();
        seal_bundle(&offer.secret, &offer.root, signer, &id, plain, rng).unwrap()
    }

    /// Valid plaintext from A for T, obtained by opening the real bundle.
    fn real_plain(offer: &LinkOffer, t: &Core, bundle: &LinkBundle) -> LinkPlain {
        open_bundle(&offer.secret, &offer.root, &t.device.public().id(), bundle).unwrap()
    }

    fn assert_still_pending(t: &mut Core, rng: &mut StdRng) {
        assert!(t.pending);
        assert_eq!(
            t.send_text(&t.fingerprint(), "x", NOW, rng).err(),
            Some(CoreError::LinkPending)
        );
        assert!(t.store.list_contacts().unwrap().is_empty());
        assert!(
            t.store
                .get_meta::<DeviceList>(META_DEVICE_LIST)
                .unwrap()
                .is_none()
        );
        assert!(pending_root(&t.store).unwrap().is_some());
        assert!(t.transparency_log(100).unwrap().is_empty());
    }

    #[test]
    fn finish_rejects_wrong_root_and_missing_device() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let mut a = admin(&d, "a", 1, &mut rng);
        let mut b = admin(&d, "b", 2, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (mut t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
        let good = real_plain(&offer, &t, &out.bundle);

        // List and card of another root (B), sealed with the right secret.
        let offer_b = b.link_offer(NOW, &mut rng).unwrap();
        let (tb, req_b) = Core::begin_link(
            &d.path().join("tb"),
            &[8; 32],
            &offer_b,
            "tb",
            NOW,
            &mut rng,
        )
        .unwrap();
        let out_b = b.link_device(&req_b, false, NOW, &mut rng).unwrap();
        let other = real_plain(&offer_b, &tb, &out_b.bundle);
        let wrong_root = LinkPlain {
            devices: other.devices.clone(),
            card: other.card.clone(),
            own_bundles: Vec::new(),
            contacts: Vec::new(),
        };
        let forged = forged_bundle(&offer, &t, &wrong_root, a.root.as_ref().unwrap(), &mut rng);
        assert_eq!(
            t.finish_link(&forged, None, NOW),
            Err(CoreError::Link("unexpected root"))
        );
        assert_still_pending(&mut t, &mut rng);

        // A's list that does not contain T (before linking).
        let a_root = RootIdentity::from_seed(&Zeroizing::new(
            a.store
                .get_meta::<[u8; 32]>(super::super::META_ROOT)
                .unwrap()
                .unwrap(),
        ));
        let only_a: Vec<_> = good
            .devices
            .certs
            .iter()
            .filter(|c| c.device != t.device.public())
            .cloned()
            .collect();
        let list = DeviceList::sign(&a_root, good.devices.version + 1, only_a).unwrap();
        let card = ContactCard::sign(&a_root, "", list.clone(), Vec::new(), Vec::new()).unwrap();
        let missing = LinkPlain {
            devices: list,
            card,
            own_bundles: Vec::new(),
            contacts: Vec::new(),
        };
        let forged = forged_bundle(&offer, &t, &missing, a.root.as_ref().unwrap(), &mut rng);
        assert_eq!(
            t.finish_link(&forged, None, NOW),
            Err(CoreError::Link("device absent from the list"))
        );
        assert_still_pending(&mut t, &mut rng);

        // An invalid contact (my own card) cancels the whole link.
        let mut bad_contacts = real_plain(&offer, &t, &out.bundle);
        bad_contacts.contacts.push(ContactSnapshot {
            card: good.card.clone(),
            alias: Some("me".into()),
            verified: false,
            added_at: NOW,
        });
        let forged = forged_bundle(
            &offer,
            &t,
            &bad_contacts,
            a.root.as_ref().unwrap(),
            &mut rng,
        );
        assert_eq!(t.finish_link(&forged, None, NOW), Err(BAD_CONTACT));
        assert_still_pending(&mut t, &mut rng);

        // The real bundle passes.
        t.finish_link(&out.bundle, None, NOW).unwrap();
        assert!(!t.pending);
        assert!(pending_root(&t.store).unwrap().is_none());
    }

    /// A with a contact (C1, unverified), T pending, and the real bundle.
    fn link_with_contact(rng: &mut StdRng) -> (TempDir, Core, Core, LinkOffer, LinkBundle) {
        let d = tempfile::tempdir().unwrap();
        let mut a = admin(&d, "a", 1, rng);
        let c1 = admin(&d, "c1", 3, rng);
        a.add_contact(&c1.contact_card("C1").unwrap(), Some("c1"), NOW, rng)
            .unwrap();
        let offer = a.link_offer(NOW, rng).unwrap();
        let (t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, rng).unwrap();
        let out = a.link_device(&req, false, NOW, rng).unwrap();
        (d, a, t, offer, out.bundle)
    }

    #[test]
    fn finish_rejects_bundle_not_signed_by_root() {
        // The secret holder (compromised link channel) reseals the
        // bundle with modified contacts: the root's signature
        // is missing, T refuses without writing anything.
        let mut rng = StdRng::seed_from_u64(13);
        let (_d, _a, mut t, offer, bundle) = link_with_contact(&mut rng);
        let mut plain = real_plain(&offer, &t, &bundle);
        plain.contacts[0].verified = true;
        let (other, _) = RootIdentity::generate(&mut rng);
        let forged = forged_bundle(&offer, &t, &plain, &other, &mut rng);
        assert_eq!(t.finish_link(&forged, None, NOW), Err(BAD_SIGNATURE));
        assert_still_pending(&mut t, &mut rng);
        // The real signature, pasted onto the modified plaintext: refused too.
        let key = bundle_key(&offer.secret);
        let ad = bundle_ad(&offer.root, &t.device.public().id());
        let real: SignedPlain = decode_exact(&xopen(&key, &ad, &bundle.0).unwrap()).unwrap();
        let swapped = SignedPlain {
            plain: postcard::to_allocvec(&plain).unwrap(),
            sig: real.sig,
        };
        let pt = postcard::to_allocvec(&swapped).unwrap();
        let forged = LinkBundle(xseal(&key, &ad, &pt, &mut rng));
        assert_eq!(t.finish_link(&forged, None, NOW), Err(BAD_SIGNATURE));
        assert_still_pending(&mut t, &mut rng);
        t.finish_link(&bundle, None, NOW).unwrap();
        assert!(!t.contacts().unwrap()[0].verified);
    }

    #[test]
    fn finish_rejects_history_not_signed_by_root() {
        // Archive forged with the right secret (invented messages for C1).
        let mut rng = StdRng::seed_from_u64(14);
        let (d, a, mut t, offer, bundle) = link_with_contact(&mut rng);
        let c1 = a.contacts().unwrap()[0].fingerprint;
        let mut fake = Store::open(&d.path().join("fake"), &[5; 32]).unwrap();
        let (other, _) = RootIdentity::generate(&mut rng);
        let archive = fake
            .transaction(|tx| {
                tx.insert_message(
                    c1,
                    crate::store::Direction::In,
                    "invented",
                    crate::store::MessageStatus::Delivered,
                    NOW,
                    MessageId([7; 16]),
                )?;
                let entries = history::export(tx, &HashSet::from([c1]))?;
                history::seal_archive(&offer.secret, &other, &entries, &mut rng)
            })
            .unwrap();
        assert_eq!(
            t.finish_link(&bundle, Some(&archive), NOW),
            Err(CoreError::Link("invalid history"))
        );
        assert_still_pending(&mut t, &mut rng);
        t.finish_link(&bundle, None, NOW).unwrap();
        assert!(t.messages_with(&c1).unwrap().is_empty());
    }

    #[test]
    fn finish_rejects_contacts_sharing_a_device_atomically() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(2);
        let mut a = admin(&d, "a", 1, &mut rng);
        let c1 = admin(&d, "c1", 3, &mut rng);
        a.add_contact(&c1.contact_card("C1").unwrap(), Some("c1"), NOW, &mut rng)
            .unwrap();
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (mut t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
        let mut plain = real_plain(&offer, &t, &out.bundle);
        // The same contact twice, then two identical aliases.
        let dup = plain.contacts[0].clone();
        plain.contacts.push(dup);
        let forged = forged_bundle(&offer, &t, &plain, a.root.as_ref().unwrap(), &mut rng);
        assert_eq!(t.finish_link(&forged, None, NOW), Err(BAD_CONTACT));
        assert_still_pending(&mut t, &mut rng);
    }

    #[test]
    fn link_device_refuses_device_claimed_by_contact() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        let mut a = admin(&d, "a", 1, &mut rng);
        let c = admin(&d, "c", 3, &mut rng);
        a.add_contact(&c.contact_card("C").unwrap(), Some("c"), NOW, &mut rng)
            .unwrap();
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        // Request forged with the keys of C's device (correct MAC:
        // the attacker knows the secret). The proof of possession is valid
        // for A's root, but C already claims this device.
        let mut req = LinkRequest {
            device: c.device.public(),
            bundle: c.prekeys.bundle(&c.device, false),
            name: "t".into(),
            issued_at: NOW,
            device_sig: c.device.possession_proof(&offer.root, "t", NOW).unwrap(),
            mac: [0; 32],
        };
        req.mac = req.compute_mac(&offer.secret).unwrap();
        let before = a.devices.clone();
        assert_eq!(
            a.link_device(&req, false, NOW, &mut rng).err(),
            Some(CoreError::Malformed(
                "device already associated with a contact"
            ))
        );
        assert_eq!(a.devices, before);
        // The offer is not consumed by a refusal.
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn link_device_checks_possession_proof_under_valid_mac() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(5);
        let mut a = admin(&d, "a", 1, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (_t, good) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        let other = DeviceKeys::generate(&mut rng);
        for tamper in 0..4 {
            let mut req = good.clone();
            match tamper {
                0 => req.device_sig[0] ^= 1,
                1 => req.name = "other".into(),
                2 => req.issued_at += 1,
                // Proof from another device for T's keys.
                _ => req.device_sig = other.possession_proof(&offer.root, "t", NOW).unwrap(),
            }
            req.mac = req.compute_mac(&offer.secret).unwrap();
            assert_eq!(
                a.link_device(&req, false, NOW, &mut rng).err(),
                Some(CoreError::InvalidSignature),
                "tampering {tamper}"
            );
        }
        a.link_device(&good, false, NOW, &mut rng).unwrap();
    }

    #[test]
    fn secrets_erased_after_link() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(4);
        let mut a = admin(&d, "a", 1, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (mut t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_some()
        );
        let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_none()
        );
        t.finish_link(&out.bundle, None, NOW).unwrap();
        assert!(
            t.store
                .get_meta::<PendingLink>(META_PENDING_LINK)
                .unwrap()
                .is_none()
        );
    }

    /// Request built by hand for `device` (correct MAC, proof of
    /// possession signed by `signer`).
    fn forged_request(
        offer: &LinkOffer,
        device: DevicePublic,
        signer: &DeviceKeys,
        rng: &mut StdRng,
    ) -> LinkRequest {
        let pre = PrekeySecrets::generate(rng, 0);
        let mut bundle = pre.bundle(signer, false);
        bundle.device = device;
        bundle.sig = signer.sign(labels::PREKEYS, &bundle.signed_bytes());
        let mut req = LinkRequest {
            device,
            bundle,
            name: "t".into(),
            issued_at: NOW,
            device_sig: signer.possession_proof(&offer.root, "t", NOW).unwrap(),
            mac: [0; 32],
        };
        req.mac = req.compute_mac(&offer.secret).unwrap();
        req
    }

    #[test]
    fn expired_offer_is_deleted() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(6);
        let path = d.path().join("a");
        let mut a = Core::create(&path, &[1; 32], "a", NOW, &mut rng).unwrap().0;
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (_t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        assert_eq!(
            a.link_device(&req, false, NOW + LINK_OFFER_TTL_SECS + 1, &mut rng)
                .err(),
            Some(CoreError::Link("offer expired"))
        );
        // The secret is gone: even a clock set back cannot change that.
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            a.link_device(&req, false, NOW, &mut rng).err(),
            Some(CoreError::Link("offer missing or already used"))
        );
        // At open too.
        a.link_offer(NOW, &mut rng).unwrap();
        drop(a);
        let a = Core::open(&path, &[1; 32], NOW + 10).unwrap();
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_some()
        );
        drop(a);
        let a = Core::open(&path, &[1; 32], NOW + LINK_OFFER_TTL_SECS + 1).unwrap();
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pending_link_lifetime_bounded() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let mut a = admin(&d, "a", 1, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (mut t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        let stored = t
            .store
            .get_meta::<PendingLink>(META_PENDING_LINK)
            .unwrap()
            .unwrap();
        assert_eq!(stored.expires_at, offer.expires_at);
        let out = a.link_device(&req, false, NOW, &mut rng).unwrap();
        let late = offer.expires_at + PENDING_LINK_GRACE_SECS + 1;
        assert_eq!(
            t.finish_link(&out.bundle, None, late),
            Err(CoreError::Link("offer expired"))
        );
        assert_still_pending(&mut t, &mut rng);
        // Within the grace period: accepted.
        t.finish_link(&out.bundle, None, late - 1).unwrap();
    }

    #[test]
    fn link_device_refuses_keys_of_my_devices() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(8);
        let mut a = admin(&d, "a", 1, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (t, req) =
            Core::begin_link(&d.path().join("t"), &[9; 32], &offer, "t", NOW, &mut rng).unwrap();
        a.link_device(&req, false, NOW, &mut rng).unwrap();
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let fresh = DeviceKeys::generate(&mut rng);
        let t_dev = t.device.public();
        let a_dev = a.device.public();
        let cases = [
            // T itself (new request, new offer).
            forged_request(&offer, t_dev, &t.device, &mut rng),
            // My X25519 key, with another signing key.
            forged_request(
                &offer,
                DevicePublic {
                    sig: fresh.public().sig,
                    dh: t_dev.dh,
                },
                &fresh,
                &mut rng,
            ),
            forged_request(
                &offer,
                DevicePublic {
                    sig: fresh.public().sig,
                    dh: a_dev.dh,
                },
                &fresh,
                &mut rng,
            ),
            // My signing key, with another X25519 key.
            forged_request(
                &offer,
                DevicePublic {
                    sig: t_dev.sig,
                    dh: fresh.public().dh,
                },
                &t.device,
                &mut rng,
            ),
        ];
        let before = a.devices.clone();
        for (i, req) in cases.iter().enumerate() {
            assert_eq!(
                a.link_device(req, false, NOW, &mut rng).err(),
                Some(CoreError::Malformed("device already linked")),
                "case {i}"
            );
        }
        assert_eq!(a.devices, before);
    }

    #[test]
    fn stale_device_list_does_not_consume_offer() {
        // Two openings of the same database: the second links T1, the first
        // (device list stale in memory) must not overwrite that link.
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        let path = d.path().join("a");
        let mut a1 = Core::create(&path, &[1; 32], "a", NOW, &mut rng).unwrap().0;
        let mut a2 = Core::open(&path, &[1; 32], NOW).unwrap();
        let o1 = a2.link_offer(NOW, &mut rng).unwrap();
        let (_t1, r1) =
            Core::begin_link(&d.path().join("t1"), &[8; 32], &o1, "t1", NOW, &mut rng).unwrap();
        a2.link_device(&r1, false, NOW, &mut rng).unwrap();
        let o2 = a1.link_offer(NOW, &mut rng).unwrap();
        let (_t2, r2) =
            Core::begin_link(&d.path().join("t2"), &[7; 32], &o2, "t2", NOW, &mut rng).unwrap();
        assert_eq!(
            a1.link_device(&r2, false, NOW, &mut rng).err(),
            Some(CoreError::Link("offer missing or already used"))
        );
        // The in-memory list is reread from the database after the refusal.
        assert_eq!(a1.devices, a2.devices);
        assert_eq!(a1.linked_bundles, a2.linked_bundles);
        // Nothing was written: the stored list is a2's, the offer remains.
        let stored = a1
            .store
            .get_meta::<DeviceList>(META_DEVICE_LIST)
            .unwrap()
            .unwrap();
        assert_eq!(stored, a2.devices);
        assert!(
            a1.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_some()
        );
        // Refreshed list: a new attempt with the same offer succeeds.
        a1.link_device(&r2, false, NOW, &mut rng).unwrap();
        assert_eq!(a1.devices.certs.len(), 3);
    }

    #[test]
    fn oversized_bundle_refused_before_consuming_offer() {
        let d = tempfile::tempdir().unwrap();
        let mut rng = StdRng::seed_from_u64(12);
        let mut a = admin(&d, "a", 1, &mut rng);
        let offer = a.link_offer(NOW, &mut rng).unwrap();
        let (_t, req) =
            Core::begin_link(&d.path().join("t"), &[8; 32], &offer, "t", NOW, &mut rng).unwrap();
        BUNDLE_MAX_OVERRIDE.with(|c| c.set(Some(10)));
        let r = a.link_device(&req, false, NOW, &mut rng);
        BUNDLE_MAX_OVERRIDE.with(|c| c.set(None));
        assert_eq!(r.err(), Some(CoreError::Link("link bundle too large")));
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_some()
        );
        assert_eq!(a.devices.certs.len(), 1);
        a.link_device(&req, false, NOW, &mut rng).unwrap();
    }

    #[test]
    fn bundle_limit_applies_to_encoded_file() {
        // Two identical links (same seed): same file size.
        let run = |max: Option<usize>| {
            let d = tempfile::tempdir().unwrap();
            let mut rng = StdRng::seed_from_u64(15);
            let mut a = admin(&d, "a", 1, &mut rng);
            let offer = a.link_offer(NOW, &mut rng).unwrap();
            let (_t, req) =
                Core::begin_link(&d.path().join("t"), &[8; 32], &offer, "t", NOW, &mut rng)
                    .unwrap();
            BUNDLE_MAX_OVERRIDE.with(|c| c.set(max));
            let r = a.link_device(&req, false, NOW, &mut rng);
            BUNDLE_MAX_OVERRIDE.with(|c| c.set(None));
            r.map(|out| out.bundle.to_bytes().len())
        };
        let len = run(None).unwrap();
        // One byte less than the file (length prefix included): refused.
        assert_eq!(
            run(Some(len - 1)).err(),
            Some(CoreError::Link("link bundle too large"))
        );
        assert_eq!(run(Some(len)), Ok(len));
    }
}
