//! Liaison d'un nouvel appareil en quatre temps (spec §3.1).
//!
//! 1. **Offre** (A, administrateur) : [`Core::link_offer`] tire un secret de
//!    liaison de 32 octets, valable 10 minutes, gardé dans `meta`
//!    (`link_offer`) ; une nouvelle offre remplace la précédente.
//! 2. **Demande** (T, nouvel appareil) : [`Core::begin_link`] crée la base de
//!    T dans un état « en attente » (`meta` `pending_link` = secret et racine)
//!    et rend la demande, authentifiée par un HMAC-SHA256 dont la clé est
//!    dérivée du secret (`LINK_MAC`).
//! 3. **Acceptation** (A) : [`Core::link_device`] vérifie l'offre (présente,
//!    non expirée), le MAC (en temps constant), la preuve de possession, signe
//!    la liste `version + 1` et rend le paquet de liaison, chiffré par
//!    XChaCha20-Poly1305 avec une clé dérivée du secret (`LINK_BUNDLE`). Les
//!    données associées lient le paquet à la racine et à l'appareil T.
//!    L'offre est consommée (effacée) dans la même transaction, à condition
//!    d'y être encore et que la liste stockée n'ait pas changé. Une offre
//!    expirée est effacée dès qu'elle est trouvée (ici et à l'ouverture).
//! 4. **Fin** (T) : [`Core::finish_link`] déchiffre, vérifie la liste (racine
//!    attendue, T présent), la carte, les paquets de clés et chaque contact,
//!    puis enregistre tout et efface le secret dans une seule transaction.
//!    T refuse de terminer plus d'un jour après l'expiration de l'offre
//!    ([`PENDING_LINK_GRACE_SECS`]) : la liaison en attente a une durée de vie
//!    bornée, au-delà il faut recommencer.
//!
//! Tout refus rend `CoreError::Link(raison)` (ou l'erreur de vérification
//! sous-jacente) sans modifier aucun état. Le secret n'est jamais affiché
//! (`Debug`), ni journalisé, et il est enveloppé dans `Zeroizing`.
//!
//! **Appareil en attente.** Tant que `finish_link` n'a pas réussi, T n'a pas
//! de liste d'appareils signée. `Core::devices` contient alors une liste
//! factice (racine de l'offre, version 0, aucun certificat, signature nulle),
//! jamais stockée, jamais envoyée ni vérifiée : elle ne sert qu'à
//! `fingerprint()`. Le drapeau `Core::pending` fait renvoyer
//! `CoreError::LinkPending` à toute opération qui exige un appareil lié.

use std::collections::HashSet;
use std::path::Path;

use rand_core::CryptoRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::contacts::{MAX_ALIAS_LEN, claimed_by_other, overlaps};
use super::history::HistoryArchive;
use super::{
    Core, META_DEVICE, META_DEVICE_LIST, META_DEVICE_NAME, META_LINKED_BUNDLES, META_PREKEYS,
    ensure_empty, log, sync,
};
use crate::contact::ContactCard;
use crate::crypto::aead::{xopen, xseal};
use crate::crypto::kdf::{hmac_sha256, hmac_sha256_verify};
use crate::crypto::labels;
use crate::handshake::{PrekeyBundle, PrekeySecrets};
use crate::identity::device::sig_bytes;
use crate::identity::device_list::MAX_DEVICES;
use crate::identity::root::RootPublic;
use crate::identity::{DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic};
use crate::packet::Packet;
use crate::store::{Queries, Store};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

/// Durée de validité d'une offre de liaison : 10 minutes.
pub const LINK_OFFER_TTL_SECS: u64 = 600;

/// Offre en attente sur A (une seule à la fois).
pub(super) const META_LINK_OFFER: &str = "link_offer";
/// Liaison en attente sur T : secret et racine attendue.
pub(super) const META_PENDING_LINK: &str = "pending_link";
/// Ma carte signée par la racine, telle qu'envoyée au nouvel appareil.
pub(super) const META_OWN_CARD: &str = "own_card";

const UNREADABLE: CoreError = CoreError::Link("fichier de liaison illisible");
const BAD_BUNDLE: CoreError = CoreError::Link("paquet de liaison invalide");
const BAD_CONTACT: CoreError = CoreError::Link("contact invalide dans le paquet de liaison");

/// Décode exactement `bytes` (postcard) : octets en trop ou illisibles →
/// « fichier de liaison illisible ». Jamais de panique.
pub(super) fn decode_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((v, [])) => Ok(v),
        _ => Err(UNREADABLE),
    }
}

/// Offre de liaison (A → T, hors réseau). `Debug` n'affiche pas le secret.
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

/// Taille maximale de l'offre sérialisée : racine (32), secret (32), date (varint ≤ 10).
const OFFER_MAX_LEN: usize = 80;

impl LinkOffer {
    /// Octets du fichier d'offre (postcard). Contient le secret : effacés à
    /// la destruction.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new([0u8; OFFER_MAX_LEN]);
        let wire = (&self.root, &*self.secret, self.expires_at);
        // Taille bornée ci-dessus : ne peut pas échouer.
        let len = postcard::to_slice(&wire, &mut buf[..])
            .map(|s| s.len())
            .unwrap_or(0);
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&buf[..len]);
        out
    }

    /// Inverse de [`LinkOffer::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (root, mut secret, expires_at): (RootPublic, [u8; 32], u64) = decode_exact(bytes)?;
        let offer = LinkOffer {
            root,
            secret: Zeroizing::new(secret),
            expires_at,
        };
        secret.zeroize();
        Ok(offer)
    }
}

/// Demande de liaison (T → A, hors réseau), authentifiée par `mac`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LinkRequest {
    pub device: DevicePublic,
    pub bundle: PrekeyBundle,
    pub name: String,
    pub issued_at: u64,
    /// Preuve de possession (`DeviceKeys::possession_proof`), liée à la
    /// racine de l'offre.
    #[serde(with = "sig_bytes")]
    pub device_sig: [u8; 64],
    /// `HMAC-SHA256(derive_key(LINK_MAC, secret), postcard(champs sans mac))`.
    pub mac: [u8; 32],
}

/// Champs de la demande couverts par le MAC.
#[derive(Serialize)]
struct MacInput<'a> {
    device: &'a DevicePublic,
    bundle: &'a PrekeyBundle,
    name: &'a str,
    issued_at: u64,
    #[serde(with = "sig_bytes")]
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
        .map_err(|_| CoreError::Malformed("demande non sérialisable"))
    }

    fn compute_mac(&self, secret: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(hmac_sha256(&*mac_key(secret), &self.mac_input()?))
    }

    /// Vérifie le MAC en temps constant (`Mac::verify_slice`).
    fn mac_ok(&self, secret: &[u8; 32]) -> Result<bool> {
        Ok(hmac_sha256_verify(
            &*mac_key(secret),
            &self.mac_input()?,
            &self.mac,
        ))
    }

    /// Octets du fichier de demande (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse de [`LinkRequest::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes)
    }
}

/// Paquet de liaison (A → T, hors réseau) : [`LinkPlain`] chiffré.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBundle(Vec<u8>);

impl core::fmt::Debug for LinkBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LinkBundle(<{} octets>)", self.0.len())
    }
}

impl LinkBundle {
    /// Octets du fichier de liaison (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse de [`LinkBundle::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes)
    }
}

/// Un contact tel que copié vers le nouvel appareil.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ContactSnapshot {
    pub card: ContactCard,
    pub alias: Option<String>,
    pub verified: bool,
    /// Date de la copie : le stockage ne garde pas la date d'ajout réelle.
    pub added_at: u64,
}

/// Clair du paquet de liaison.
#[derive(Serialize, Deserialize)]
struct LinkPlain {
    devices: DeviceList,
    card: ContactCard,
    /// Paquets de clés de mes autres appareils (tous sauf T).
    own_bundles: Vec<PrekeyBundle>,
    contacts: Vec<ContactSnapshot>,
}

/// Résultat de [`Core::link_device`].
#[derive(Debug)]
pub struct LinkOutcome {
    pub bundle: LinkBundle,
    /// Archive de l'historique (si demandée) ; pas encore produite.
    pub history: Option<HistoryArchive>,
    /// Paquets à envoyer (nouvelle carte aux contacts) ; pas encore produits.
    pub packets: Vec<Packet>,
}

/// Offre stockée sur A.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredOffer {
    secret: [u8; 32],
    expires_at: u64,
}

/// Liaison en attente stockée sur T.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PendingLink {
    secret: [u8; 32],
    #[zeroize(skip)]
    root: RootPublic,
    /// Expiration de l'offre (horloge de A, recopiée de l'offre).
    expires_at: u64,
}

/// Durée de vie d'une liaison en attente sur T au-delà de l'expiration de
/// l'offre : un jour, pour tolérer un décalage d'horloge entre A et T et le
/// délai de transfert des fichiers. Passé ce délai, `finish_link` refuse
/// (« offre expirée ») et T reste en attente : il faut recréer sa base et
/// recommencer avec une nouvelle offre.
pub(super) const PENDING_LINK_GRACE_SECS: u64 = 86_400;

/// Efface l'offre en attente si elle a expiré à `now` (son secret ne sert
/// plus à rien). Appelé par `link_device` et à l'ouverture.
pub(super) fn purge_expired_offer(q: &impl Queries, now: u64) -> Result<()> {
    if q.get_meta::<StoredOffer>(META_LINK_OFFER)?
        .is_some_and(|o| now > o.expires_at)
    {
        q.delete_meta(META_LINK_OFFER)?;
    }
    Ok(())
}

/// Données associées du paquet de liaison : racine et appareil T.
fn bundle_ad(root: &RootPublic, device: &DeviceId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(48);
    ad.extend_from_slice(&root.0);
    ad.extend_from_slice(&device.0);
    ad
}

fn bundle_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(labels::LINK_BUNDLE, secret))
}

/// Chiffre le clair du paquet de liaison pour l'appareil `device`.
fn seal_bundle(
    secret: &[u8; 32],
    root: &RootPublic,
    device: &DeviceId,
    plain: &LinkPlain,
    rng: &mut impl CryptoRng,
) -> Result<LinkBundle> {
    let pt = Zeroizing::new(
        postcard::to_allocvec(plain).map_err(|_| CoreError::Malformed("paquet de liaison"))?,
    );
    let key = bundle_key(secret);
    Ok(LinkBundle(xseal(&key, &bundle_ad(root, device), &pt, rng)))
}

/// Liste factice d'un appareil en attente (voir la documentation du module).
pub(super) fn pending_devices(root: RootPublic) -> DeviceList {
    DeviceList {
        root,
        version: 0,
        certs: Vec::new(),
        sig: [0u8; 64],
    }
}

/// Racine attendue d'une liaison en attente, si la base en a une.
pub(super) fn pending_root(q: &impl Queries) -> Result<Option<RootPublic>> {
    Ok(q.get_meta::<PendingLink>(META_PENDING_LINK)?
        .map(|p| p.root))
}

impl Core {
    /// Refuse l'opération tant que cet appareil attend la fin de sa liaison.
    pub(super) fn ensure_linked(&self) -> Result<()> {
        if self.pending {
            return Err(CoreError::LinkPending);
        }
        Ok(())
    }

    /// Étape 1 (A) : nouvelle offre de liaison, valable 10 minutes. Elle
    /// remplace l'offre précédente. Administrateur seulement.
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

    /// Étape 2 (T) : crée la base de T (clés d'appareil, préclés) en attente
    /// de liaison, et rend la demande à transmettre à A.
    pub fn begin_link(
        path: &Path,
        db_key: &[u8; 32],
        offer: &LinkOffer,
        name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<(Core, LinkRequest)> {
        if now > offer.expires_at {
            return Err(CoreError::Link("offre expirée"));
        }
        let device = DeviceKeys::generate(rng);
        let prekeys = PrekeySecrets::generate(rng, 0);
        // Preuve de possession liée à la racine de l'offre (erreur si le nom
        // est trop long), avant toute écriture.
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

    /// Étape 3 (A) : accepte une demande de liaison. Vérifie l'offre en
    /// attente, le MAC, la preuve de possession ; signe la liste `version + 1`
    /// et rend le paquet de liaison chiffré. `with_history` est encore ignoré
    /// (l'archive viendra plus tard).
    ///
    /// L'offre est consommée dans la transaction qui enregistre la nouvelle
    /// liste : elle doit y être encore présente et identique, et la liste
    /// stockée ne doit pas avoir changé depuis sa lecture (une autre ouverture
    /// de la même base a pu lier un appareil entre-temps) ; sinon « offre
    /// absente ou déjà utilisée », sans rien écrire. Seule exception à « un
    /// refus ne modifie rien » : une offre trouvée expirée est effacée.
    pub fn link_device(
        &mut self,
        req: &LinkRequest,
        with_history: bool,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<LinkOutcome> {
        let _ = with_history;
        self.ensure_linked()?;
        let root = self.root.as_ref().ok_or(CoreError::NotAdmin)?;
        let root_pub = root.public();
        let offer = self
            .store
            .get_meta::<StoredOffer>(META_LINK_OFFER)?
            .ok_or(CoreError::Link("offre absente ou déjà utilisée"))?;
        if now > offer.expires_at {
            purge_expired_offer(&self.store, now)?;
            return Err(CoreError::Link("offre expirée"));
        }
        if !req.mac_ok(&offer.secret)? {
            return Err(CoreError::Link("MAC invalide"));
        }
        let device = req.device;
        // Aucune clé (identifiant, signature, X25519) d'un de mes appareils,
        // moi compris : un appareil déjà lié n'est pas relié une seconde fois.
        if self
            .devices
            .certs
            .iter()
            .any(|c| overlaps(&c.device, &device))
            || overlaps(&self.device.public(), &device)
        {
            return Err(CoreError::Malformed("appareil déjà lié"));
        }
        req.bundle.verify()?;
        if req.bundle.device != device {
            return Err(CoreError::Malformed("paquet de clés d'un autre appareil"));
        }
        if req.bundle.opk.is_some() {
            return Err(CoreError::Malformed("clé à usage unique interdite"));
        }
        if claimed_by_other(&self.store, None, &[device])? {
            return Err(CoreError::Malformed("appareil déjà associé à un contact"));
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

        // Paquets de clés de tous mes appareils, puis ceux que T doit garder.
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
        // Le nom affiché n'est pas stocké : la carte copiée n'en porte pas.
        let card = ContactCard::sign(root, "", devices.clone(), bundles)?;
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
        let bundle = seal_bundle(&offer.secret, &root_pub, &device.id(), &plain, rng)?;

        let event = TransparencyEvent::DeviceLinked {
            device: device.id(),
            name: req.name.clone(),
        };
        let read_version = self.devices.version;
        let written = self.store.transaction(|tx| {
            const USED: CoreError = CoreError::Link("offre absente ou déjà utilisée");
            let same_offer = tx
                .get_meta::<StoredOffer>(META_LINK_OFFER)?
                .is_some_and(|o| o.secret == offer.secret && o.expires_at == offer.expires_at);
            let same_list = tx
                .get_meta::<DeviceList>(META_DEVICE_LIST)?
                .is_some_and(|l| l.version == read_version);
            // Offre consommée : le secret disparaît de la base.
            if !same_offer || !same_list || !tx.delete_meta(META_LINK_OFFER)? {
                return Err(USED);
            }
            tx.put_meta(META_DEVICE_LIST, &devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &linked)?;
            tx.put_meta(META_OWN_CARD, &card)?;
            sync::purge_removed_own_sessions(tx, &devices)?;
            log(tx, now, None, &event)
        });
        if let Err(e) = written {
            // Liste périmée en mémoire (une autre ouverture de la base a lié
            // un appareil) : relue, pour qu'un nouvel essai parte de la bonne.
            if matches!(e, CoreError::Link(_)) {
                self.reload_own_devices()?;
            }
            return Err(e);
        }
        drop(offer);
        self.devices = devices;
        self.linked_bundles = linked;
        Ok(LinkOutcome {
            bundle,
            history: None,
            packets: Vec::new(),
        })
    }

    /// Étape 4 (T) : termine la liaison avec le paquet de A. Tout est
    /// vérifié avant d'écrire ; tout est écrit dans une seule transaction.
    /// En cas d'échec, T reste en attente et rien n'est modifié.
    /// `history` est encore ignoré (l'import viendra plus tard).
    pub fn finish_link(
        &mut self,
        bundle: &LinkBundle,
        history: Option<&HistoryArchive>,
        now: u64,
    ) -> Result<()> {
        let _ = history;
        if !self.pending {
            return Err(CoreError::Link("aucune liaison en attente"));
        }
        let pending = self
            .store
            .get_meta::<PendingLink>(META_PENDING_LINK)?
            .ok_or(CoreError::Link("aucune liaison en attente"))?;
        if now > pending.expires_at.saturating_add(PENDING_LINK_GRACE_SECS) {
            return Err(CoreError::Link("offre expirée"));
        }
        let me = self.device.public();
        let key = bundle_key(&pending.secret);
        let pt = Zeroizing::new(
            xopen(&key, &bundle_ad(&pending.root, &me.id()), &bundle.0).map_err(|_| BAD_BUNDLE)?,
        );
        let plain: LinkPlain = decode_exact(&pt)?;
        check_plain(&plain, &pending.root, &me)?;

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
                // Contacts insérés un par un : vérifie aussi les précédents.
                if claimed_by_other(tx, Some(fp), &claimed)? {
                    return Err(BAD_CONTACT);
                }
                let alias = snap.alias.as_deref().map(str::trim).unwrap_or("");
                if alias.len() > MAX_ALIAS_LEN
                    || (!alias.is_empty() && !aliases.insert(alias.to_owned()))
                {
                    return Err(BAD_CONTACT);
                }
                let bytes =
                    postcard::to_allocvec(card).map_err(|_| CoreError::Malformed("carte"))?;
                tx.upsert_contact(fp, &bytes, alias, snap.verified)?;
            }
            tx.put_meta(META_DEVICE_LIST, &plain.devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &plain.own_bundles)?;
            tx.put_meta(META_OWN_CARD, &plain.card)?;
            sync::purge_removed_own_sessions(tx, &plain.devices)?;
            // Liaison terminée : le secret disparaît de la base.
            tx.delete_meta(META_PENDING_LINK)?;
            log(tx, now, None, &event)
        })?;
        drop(pending);
        self.devices = plain.devices;
        self.linked_bundles = plain.own_bundles;
        self.pending = false;
        Ok(())
    }
}

/// Vérifie le clair du paquet de liaison côté T : liste signée par la racine
/// attendue et contenant T, carte cohérente, paquets de clés de mes autres
/// appareils valides.
fn check_plain(plain: &LinkPlain, root: &RootPublic, me: &DevicePublic) -> Result<()> {
    if plain.devices.root != *root || plain.card.devices.root != *root {
        return Err(CoreError::Link("racine inattendue"));
    }
    plain.devices.verify()?;
    if !plain.devices.certs.iter().any(|c| c.device == *me) {
        return Err(CoreError::Link("appareil absent de la liste"));
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
    use super::*;
    use crate::identity::RootIdentity;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tempfile::TempDir;

    const NOW: u64 = 1_800_000_000;

    fn admin(d: &TempDir, file: &str, seed: u8, rng: &mut StdRng) -> Core {
        Core::create(&d.path().join(file), &[seed; 32], file, NOW, rng)
            .unwrap()
            .0
    }

    /// Paquet scellé avec le bon secret pour T, mais au contenu choisi.
    fn forged_bundle(
        offer: &LinkOffer,
        t: &Core,
        plain: &LinkPlain,
        rng: &mut StdRng,
    ) -> LinkBundle {
        let id = t.device.public().id();
        seal_bundle(&offer.secret, &offer.root, &id, plain, rng).unwrap()
    }

    /// Clair valide de A pour T, obtenu en ouvrant le vrai paquet.
    fn real_plain(offer: &LinkOffer, t: &Core, bundle: &LinkBundle) -> LinkPlain {
        let key = bundle_key(&offer.secret);
        let ad = bundle_ad(&offer.root, &t.device.public().id());
        postcard::from_bytes(&xopen(&key, &ad, &bundle.0).unwrap()).unwrap()
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

        // Liste et carte d'une autre racine (B), scellées avec le bon secret.
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
        let forged = forged_bundle(&offer, &t, &wrong_root, &mut rng);
        assert_eq!(
            t.finish_link(&forged, None, NOW),
            Err(CoreError::Link("racine inattendue"))
        );
        assert_still_pending(&mut t, &mut rng);

        // Liste de A qui ne contient pas T (avant liaison).
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
        let card = ContactCard::sign(&a_root, "", list.clone(), Vec::new()).unwrap();
        let missing = LinkPlain {
            devices: list,
            card,
            own_bundles: Vec::new(),
            contacts: Vec::new(),
        };
        let forged = forged_bundle(&offer, &t, &missing, &mut rng);
        assert_eq!(
            t.finish_link(&forged, None, NOW),
            Err(CoreError::Link("appareil absent de la liste"))
        );
        assert_still_pending(&mut t, &mut rng);

        // Un contact invalide (ma propre carte) annule toute la liaison.
        let mut bad_contacts = real_plain(&offer, &t, &out.bundle);
        bad_contacts.contacts.push(ContactSnapshot {
            card: good.card.clone(),
            alias: Some("moi".into()),
            verified: false,
            added_at: NOW,
        });
        let forged = forged_bundle(&offer, &t, &bad_contacts, &mut rng);
        assert_eq!(t.finish_link(&forged, None, NOW), Err(BAD_CONTACT));
        assert_still_pending(&mut t, &mut rng);

        // Le vrai paquet passe.
        t.finish_link(&out.bundle, None, NOW).unwrap();
        assert!(!t.pending);
        assert!(pending_root(&t.store).unwrap().is_none());
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
        // Le même contact deux fois, puis deux alias identiques.
        let dup = plain.contacts[0].clone();
        plain.contacts.push(dup);
        let forged = forged_bundle(&offer, &t, &plain, &mut rng);
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
        // Demande fabriquée avec les clés de l'appareil de C (MAC correct :
        // l'attaquant connaît le secret). La preuve de possession est valide
        // pour la racine de A, mais C revendique déjà cet appareil.
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
            Some(CoreError::Malformed("appareil déjà associé à un contact"))
        );
        assert_eq!(a.devices, before);
        // L'offre n'est pas consommée par un refus.
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
                1 => req.name = "autre".into(),
                2 => req.issued_at += 1,
                // Preuve d'un autre appareil pour les clés de T.
                _ => req.device_sig = other.possession_proof(&offer.root, "t", NOW).unwrap(),
            }
            req.mac = req.compute_mac(&offer.secret).unwrap();
            assert_eq!(
                a.link_device(&req, false, NOW, &mut rng).err(),
                Some(CoreError::InvalidSignature),
                "falsification {tamper}"
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

    /// Demande construite à la main pour `device` (MAC correct, preuve de
    /// possession signée par `signer`).
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
            Some(CoreError::Link("offre expirée"))
        );
        // Le secret a disparu : même une horloge revenue en arrière n'y peut rien.
        assert!(
            a.store
                .get_meta::<StoredOffer>(META_LINK_OFFER)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            a.link_device(&req, false, NOW, &mut rng).err(),
            Some(CoreError::Link("offre absente ou déjà utilisée"))
        );
        // À l'ouverture aussi.
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
            Err(CoreError::Link("offre expirée"))
        );
        assert_still_pending(&mut t, &mut rng);
        // Dans le délai de grâce : accepté.
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
            // T lui-même (nouvelle demande, nouvelle offre).
            forged_request(&offer, t_dev, &t.device, &mut rng),
            // Ma clé X25519, avec une autre clé de signature.
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
            // Ma clé de signature, avec une autre clé X25519.
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
                Some(CoreError::Malformed("appareil déjà lié")),
                "cas {i}"
            );
        }
        assert_eq!(a.devices, before);
    }

    #[test]
    fn stale_device_list_does_not_consume_offer() {
        // Deux ouvertures de la même base : la seconde lie T1, la première
        // (liste d'appareils périmée en mémoire) ne doit pas écraser ce lien.
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
            Some(CoreError::Link("offre absente ou déjà utilisée"))
        );
        // La liste en mémoire est relue depuis la base après le refus.
        assert_eq!(a1.devices, a2.devices);
        assert_eq!(a1.linked_bundles, a2.linked_bundles);
        // Rien n'a été écrit : la liste stockée est celle de a2, l'offre reste.
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
        // Liste rafraîchie : un nouvel essai avec la même offre aboutit.
        a1.link_device(&r2, false, NOW, &mut rng).unwrap();
        assert_eq!(a1.devices.certs.len(), 3);
    }
}
