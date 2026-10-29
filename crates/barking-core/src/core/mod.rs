//! Façade `Core` : assemble identité, poignée de main, ratchet, boîtes aux
//! lettres, paquets, stockage et journal de transparence.
//!
//! Octets en entrée et en sortie ; l'horloge (`now`, secondes Unix) et le
//! générateur aléatoire sont toujours passés en paramètres. Chaque opération
//! qui écrit (`send_text`, `receive`, `add_contact`, …) le fait dans une seule
//! transaction du stockage.
//!
//! Découpage : `contacts.rs` (cartes, alias, vérification), `send.rs`
//! (`send_text`), `receive.rs` (`receive`), `frames.rs` (fragmentation et
//! réassemblage des trames), `link.rs` (liaison d'un nouvel appareil),
//! `history.rs` (archive de l'historique transférée à la liaison).

mod contacts;
mod frames;
mod history;
mod link;
mod log_limit;
mod receive;
mod send;

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::contact::ContactCard;
use crate::fragment::Reassembler;
use crate::handshake::pqxdh::InitialMessage;
use crate::handshake::{PrekeyBundle, PrekeySecrets};
use crate::identity::{
    DeviceCertificate, DeviceId, DeviceKeys, DeviceList, DevicePublic, Fingerprint, RecoveryPhrase,
    RootIdentity, safety_number,
};
use crate::mailbox::{MailboxId, day_of, intro_mailbox, session_mailbox};
use crate::packet::{DEFAULT_TTL_SECS, Kind, Packet, PacketId};
use crate::ratchet::RatchetState;
use crate::store::{EventClass, MessageRow, Queries, Store};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

pub use contacts::ContactSummary;
pub use frames::{FRAME_REJECT_LOG_INTERVAL_SECS, FRAME_TTL_SECS, MAX_PENDING_FRAMES};
pub use history::HistoryArchive;
pub use link::{
    ContactSnapshot, LINK_OFFER_TTL_SECS, LinkBundle, LinkOffer, LinkOutcome, LinkRequest,
};
pub use log_limit::NOISY_EVENT_LOG_INTERVAL_SECS;

use log_limit::LogLimiter;

const META_ROOT: &str = "root_seed";
const META_DEVICE: &str = "device_keys";
const META_DEVICE_NAME: &str = "device_name";
const META_PREKEYS: &str = "prekeys";
const META_DEVICE_LIST: &str = "device_list";
const META_LINKED_BUNDLES: &str = "linked_bundles";
/// Dernier jour (numéro de jour) où cet appareil a relevé ses boîtes.
const META_LAST_POLLED: &str = "last_polled_day";
/// Fenêtre de relève : 7 jours en arrière, le jour même et le lendemain =
/// 9 jours au plus. Couvre chaque jour de `accepted_days` (réception) qui peut
/// encore contenir un paquet non expiré (durée de vie de 7 jours).
const MAX_POLL_BACK_DAYS: u32 = 7;

/// Âge maximal accepté d'un message (horodatage authentifié de l'enveloppe) :
/// durée de vie d'un paquet plus un jour de décalage d'horloge.
const MAX_AGE_SECS: u64 = DEFAULT_TTL_SECS + 86_400;
/// Avance maximale acceptée de l'horloge de l'expéditeur.
const MAX_FUTURE_SECS: u64 = 86_400;
/// Conservation de la table `seen`. Un paquet vu il y a plus longtemps a un
/// horodatage authentifié `sent_at <= vu + MAX_FUTURE`, donc il est désormais
/// refusé comme trop ancien : la purge ne rouvre pas la porte aux rejeux.
const SEEN_RETENTION_SECS: u64 = MAX_AGE_SECS + MAX_FUTURE_SECS;

/// Résultat de la réception d'octets venus de l'extérieur.
pub enum ReceiveOutcome {
    /// Message déchiffré. `ack` est l'accusé de réception à renvoyer.
    Message {
        from: Fingerprint,
        alias: Option<String>,
        text: String,
        ack: Packet,
    },
    /// Accusé vérifié pour un de mes paquets, désormais `Delivered`.
    AckReceived {
        packet_id: PacketId,
    },
    /// Trame acceptée, mais le paquet qu'elle annonce est encore incomplet.
    Partial,
    Duplicate,
    NotForUs,
    Expired,
    /// Paquet pour moi mais refusé ; son contenu n'est jamais montré.
    Quarantined {
        reason: String,
    },
}

impl fmt::Debug for ReceiveOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message {
                from, alias, text, ..
            } => f
                .debug_struct("Message")
                .field("from", from)
                .field("alias", alias)
                .field("text", &format_args!("<{} octets>", text.len()))
                .finish_non_exhaustive(),
            Self::AckReceived { packet_id } => f
                .debug_struct("AckReceived")
                .field("packet_id", packet_id)
                .finish(),
            Self::Partial => f.write_str("Partial"),
            Self::Duplicate => f.write_str("Duplicate"),
            Self::NotForUs => f.write_str("NotForUs"),
            Self::Expired => f.write_str("Expired"),
            Self::Quarantined { reason } => f
                .debug_struct("Quarantined")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Cœur de la messagerie pour un appareil.
pub struct Core {
    store: Store,
    /// Absente sur un appareil non administrateur.
    root: Option<RootIdentity>,
    device: DeviceKeys,
    prekeys: PrekeySecrets,
    /// Ma liste d'appareils signée (la plus récente que je connais).
    devices: DeviceList,
    /// Paquets de clés de mes autres appareils (`link_device` sur
    /// l'administrateur, paquet de liaison sur un appareil lié).
    linked_bundles: Vec<PrekeyBundle>,
    /// En attente de liaison (`begin_link` sans `finish_link`) : `devices`
    /// est alors une liste factice (voir `link.rs`) et toute opération qui
    /// exige un appareil lié renvoie `CoreError::LinkPending`.
    pending: bool,
    /// Trames reçues d'un paquet encore incomplet (en mémoire, non persisté).
    frames: Reassembler,
    /// Regroupement des événements bruyants au journal (trames rejetées,
    /// paquets indéchiffrables, doublons), en mémoire.
    log_limiter: LogLimiter,
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Core")
            .field("fingerprint", &self.fingerprint().to_string())
            .field("device", &self.device.public().id())
            .field("admin", &self.root.is_some())
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Nouvelle identité : racine, phrase de récupération, appareil, liste
    /// initiale (version `max(1, now)`).
    pub fn create(
        path: &Path,
        db_key: &[u8; 32],
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<(Core, RecoveryPhrase)> {
        let store = Store::open(path, db_key)?;
        ensure_empty(&store)?;
        let (root, phrase) = RootIdentity::generate(rng);
        let core = Self::init(store, root, device_name, now, rng)?;
        Ok((core, phrase))
    }

    /// Nouvel appareil pour une identité existante, à partir de sa phrase.
    /// Les contacts ne sont pas restaurés (v0). La liste d'appareils est
    /// signée avec la version `max(1, now)` : elle remplace chez les contacts
    /// la liste de l'appareil perdu (signée plus tôt).
    pub fn recover(
        path: &Path,
        db_key: &[u8; 32],
        phrase: &str,
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Core> {
        let root = RootIdentity::from_phrase(phrase)?;
        let store = Store::open(path, db_key)?;
        ensure_empty(&store)?;
        Self::init(store, root, device_name, now, rng)
    }

    fn init(
        mut store: Store,
        root: RootIdentity,
        device_name: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Core> {
        let device = DeviceKeys::generate(rng);
        // Pas de clé à usage unique : les cartes sont publiques et réutilisées.
        let prekeys = PrekeySecrets::generate(rng, 0);
        let cert = DeviceCertificate::issue(&root, &device, device_name, now)?;
        // Version = horodatage (au moins 1) : une récupération ultérieure
        // remplace la liste connue des contacts, `link_device` reste monotone.
        let devices = DeviceList::sign(&root, now.max(1), vec![cert])?;
        let linked_bundles: Vec<PrekeyBundle> = Vec::new();
        store.transaction(|tx| {
            tx.put_meta(META_ROOT, &*root.to_seed())?;
            let dev = Zeroizing::new(device.to_bytes().to_vec());
            tx.put_meta(META_DEVICE, &*dev)?;
            tx.put_meta(META_DEVICE_NAME, &device_name)?;
            tx.put_meta(META_PREKEYS, &prekeys)?;
            tx.put_meta(META_DEVICE_LIST, &devices)?;
            tx.put_meta(META_LINKED_BUNDLES, &linked_bundles)
        })?;
        Ok(Core::assemble(
            store,
            Some(root),
            device,
            prekeys,
            devices,
            linked_bundles,
            false,
        ))
    }

    fn assemble(
        store: Store,
        root: Option<RootIdentity>,
        device: DeviceKeys,
        prekeys: PrekeySecrets,
        devices: DeviceList,
        linked_bundles: Vec<PrekeyBundle>,
        pending: bool,
    ) -> Core {
        Core {
            store,
            root,
            device,
            prekeys,
            devices,
            linked_bundles,
            pending,
            frames: Reassembler::new(MAX_PENDING_FRAMES, FRAME_TTL_SECS),
            log_limiter: LogLimiter::default(),
        }
    }

    /// Rouvre une base existante. Mauvaise clé : `StoreLocked`. Les clés
    /// sautées de plus de 7 jours à `now` sont purgées (irréversible, un `now`
    /// très éloigné dans le futur y compris, comme au déchiffrement).
    pub fn open(path: &Path, db_key: &[u8; 32], now: u64) -> Result<Core> {
        // Ne pas créer de base vide en cherchant à en ouvrir une.
        if !path.exists() {
            return Err(CoreError::Store("base absente".into()));
        }
        let mut store = Store::open(path, db_key)?;
        let dev = Zeroizing::new(
            store
                .get_meta::<Vec<u8>>(META_DEVICE)?
                .ok_or_else(|| CoreError::Store("base non initialisée".into()))?,
        );
        let mut dev_bytes = Zeroizing::new([0u8; 64]);
        if dev.len() != 64 {
            return Err(CoreError::Store("clés d'appareil corrompues".into()));
        }
        dev_bytes.copy_from_slice(&dev);
        let device = DeviceKeys::from_bytes(&dev_bytes);
        let root = store
            .get_meta::<[u8; 32]>(META_ROOT)?
            .map(|seed| RootIdentity::from_seed(&Zeroizing::new(seed)));
        let prekeys = store
            .get_meta::<PrekeySecrets>(META_PREKEYS)?
            .ok_or_else(|| CoreError::Store("paquets de clés absents".into()))?;
        // Appareil en attente de liaison : pas encore de liste signée.
        let pending_root = link::pending_root(&store)?;
        let devices = match pending_root {
            Some(root) => link::pending_devices(root),
            None => store
                .get_meta::<DeviceList>(META_DEVICE_LIST)?
                .ok_or_else(|| CoreError::Store("liste d'appareils absente".into()))?,
        };
        let linked_bundles = store
            .get_meta::<Vec<PrekeyBundle>>(META_LINKED_BUNDLES)?
            .unwrap_or_default();
        store.transaction(|tx| {
            link::purge_expired_offer(tx, now)?;
            sweep_skipped(tx, now)
        })?;
        Ok(Core::assemble(
            store,
            root,
            device,
            prekeys,
            devices,
            linked_bundles,
            pending_root.is_some(),
        ))
    }

    /// Empreinte de mon identité (racine).
    pub fn fingerprint(&self) -> Fingerprint {
        self.devices.root.fingerprint()
    }

    /// Ma carte de contact signée : liste d'appareils et un paquet de clés par appareil.
    pub fn contact_card(&self, display_name: &str) -> Result<ContactCard> {
        self.ensure_linked()?;
        let root = self.root.as_ref().ok_or(CoreError::NotAdmin)?;
        let mut bundles = vec![self.prekeys.bundle(&self.device, false)];
        bundles.extend(
            self.linked_bundles
                .iter()
                .filter(|b| self.devices.certs.iter().any(|c| c.device == b.device))
                .cloned(),
        );
        ContactCard::sign(root, display_name, self.devices.clone(), bundles)
    }

    /// Boîtes aux lettres à relever : la boîte d'introduction de cet appareil
    /// et celles de chaque session (de la dernière relève au lendemain, 9 jours
    /// au plus ; veille, jour et lendemain sans relève enregistrée), plus la boîte de
    /// chacun de mes messages en attente d'accusé, où l'accusé arrivera.
    ///
    /// En cas d'erreur de lecture du stockage, seules les boîtes
    /// d'introduction sont renvoyées (`receive` refait le calcul lui-même).
    pub fn watched_mailboxes(&self, now: u64) -> Vec<MailboxId> {
        // En attente de liaison : rien à relever (`receive` refuserait).
        if self.pending {
            return Vec::new();
        }
        let me = self.device.public();
        let my_id = me.id();
        let days = self.watched_days(now);
        let mut out: Vec<MailboxId> = Vec::new();
        let mut push = |m: MailboxId| {
            if !out.contains(&m) {
                out.push(m);
            }
        };
        for &d in &days {
            push(intro_mailbox(&me, d));
        }
        if let Ok(sessions) = self.store.all_sessions() {
            for s in &sessions {
                for &d in &days {
                    push(session_mailbox(&s.mailbox_secret, &my_id, d));
                }
            }
        }
        if let Ok(pending) = self.store.outbox_pending(now) {
            for (_, bytes) in pending {
                if let Ok(p) = Packet::decode(&bytes)
                    && p.kind == Kind::Message
                {
                    push(p.mailbox);
                }
            }
        }
        out
    }

    /// Enregistre que les boîtes ont été relevées à `now`. À appeler après
    /// avoir relevé toutes les boîtes avec succès ; écrase volontairement la
    /// valeur précédente (une valeur antérieure ne fait qu'élargir la fenêtre).
    pub fn mark_polled(&mut self, now: u64) -> Result<()> {
        self.store.put_meta(META_LAST_POLLED, &day_of(now))
    }

    /// Jours à relever : de la dernière relève (ou de la veille) au lendemain,
    /// 9 jours au plus. Une lecture ratée ou une relève datée du futur
    /// (horloge reculée) ramène à la fenêtre normale.
    fn watched_days(&self, now: u64) -> Vec<u32> {
        let today = day_of(now);
        let end = today.saturating_add(1);
        let normal = today.saturating_sub(1);
        let start = match self.store.get_meta::<u32>(META_LAST_POLLED) {
            Ok(Some(last)) if last <= end => last.min(normal),
            _ => normal,
        };
        let start = start.max(today.saturating_sub(MAX_POLL_BACK_DAYS));
        (start..=end).collect()
    }

    /// Code de sécurité à comparer avec le contact.
    pub fn safety_number(&self, contact: &Fingerprint) -> Result<String> {
        self.store
            .get_contact(*contact)?
            .ok_or(CoreError::UnknownContact)?;
        Ok(safety_number(&self.fingerprint(), contact))
    }

    /// Marque le contact comme vérifié (code de sécurité comparé).
    pub fn mark_verified(&mut self, contact: &Fingerprint) -> Result<()> {
        self.ensure_linked()?;
        self.store.transaction(|tx| {
            let row = tx.get_contact(*contact)?.ok_or(CoreError::UnknownContact)?;
            tx.upsert_contact(row.fp, &row.card, &row.alias, true)
        })
    }

    /// Les `limit` événements les plus récents, du plus ancien au plus récent.
    pub fn transparency_log(&self, limit: usize) -> Result<Vec<(u64, TransparencyEvent)>> {
        self.store
            .recent_events(limit)?
            .into_iter()
            .map(|(at, bytes)| {
                postcard::from_bytes(&bytes)
                    .map(|e| (at, e))
                    .map_err(|_| CoreError::Store("événement illisible".into()))
            })
            .collect()
    }

    /// Purge les paquets expirés de la file d'envoi puis rend les octets à
    /// (re)transmettre, du plus ancien au plus récent. Un paquet y reste
    /// jusqu'à son accusé de réception ou son expiration.
    pub fn pending_outbox(&mut self, now: u64) -> Result<Vec<Vec<u8>>> {
        self.store.transaction(|tx| {
            tx.outbox_purge_expired(now)?;
            sweep_skipped(tx, now)?;
            Ok(tx
                .outbox_pending(now)?
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect())
        })
    }

    /// Historique avec un contact, du plus ancien au plus récent.
    pub fn messages_with(&self, contact: &Fingerprint) -> Result<Vec<MessageRow>> {
        self.store.messages_with(*contact)
    }
}

/// Purge les clés sautées trop anciennes de toutes les sessions, même
/// inactives ; ne réécrit que les sessions modifiées. Une session illisible
/// est ignorée (elle ne doit pas bloquer l'ouverture). Un `now` très éloigné
/// dans le futur purge les clés de façon irréversible, exactement comme le
/// déchiffrement.
fn sweep_skipped(q: &impl Queries, now: u64) -> Result<()> {
    for mut row in q.all_sessions()? {
        let Ok(mut state) = de_state(&row.state) else {
            continue;
        };
        if state.purge_skipped(now) {
            let new = ser_state(&state)?;
            // L'ancien état sérialisé contient les clés purgées.
            let mut old = std::mem::replace(&mut row.state, new);
            old.zeroize();
            q.put_session(&row)?;
        }
    }
    Ok(())
}

/// Refuse d'écraser une base déjà initialisée.
fn ensure_empty(store: &Store) -> Result<()> {
    if store.get_meta::<Vec<u8>>(META_DEVICE)?.is_some() {
        return Err(CoreError::Store("base déjà initialisée".into()));
    }
    Ok(())
}

/// Identifiant de session : `BLAKE3(ek)[..16]`, où `ek` est la clé éphémère
/// PQXDH du message initial (jamais l'éphémère de scellement du paquet).
fn session_id(ek: &[u8; 32]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(&blake3::hash(ek).as_bytes()[..16]);
    id
}

/// Données associées du ratchet : `IK_A || IK_B` (PQXDH), puis les
/// identifiants complets des deux appareils (initiateur, répondeur).
///
/// La preuve de possession d'un certificat ne couvre que la clé de signature,
/// pas la clé X25519 : une carte pourrait associer sa propre clé de signature
/// à la clé `dh` d'un tiers. L'identifiant d'appareil hache les deux clés ;
/// le lier ici fait échouer toute session dont les deux côtés ne voient pas
/// exactement les mêmes appareils.
fn session_ad(pqxdh_ad: &[u8], initiator: &DeviceId, responder: &DeviceId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(pqxdh_ad.len() + 32);
    ad.extend_from_slice(pqxdh_ad);
    ad.extend_from_slice(&initiator.0);
    ad.extend_from_slice(&responder.0);
    ad
}

fn log(
    q: &impl Queries,
    at: u64,
    packet: Option<PacketId>,
    event: &TransparencyEvent,
) -> Result<()> {
    let bytes = postcard::to_allocvec(event).map_err(|_| CoreError::Store("événement".into()))?;
    let class = if event.is_security() {
        EventClass::Security
    } else {
        EventClass::Routine
    };
    q.append_event(at, packet, class, &bytes)
}

/// Mes appareils tels que stockés : ma liste signée et les paquets de clés
/// de mes autres appareils. Même source sur l'administrateur (`link_device`)
/// et sur un appareil lié (`finish_link`) ; absente tant qu'une liaison est
/// en attente.
pub(super) struct OwnDevices {
    pub list: DeviceList,
    pub bundles: Vec<PrekeyBundle>,
}

impl OwnDevices {
    pub fn read(q: &impl Queries) -> Result<Option<OwnDevices>> {
        let Some(list) = q.get_meta::<DeviceList>(META_DEVICE_LIST)? else {
            return Ok(None);
        };
        let bundles = q
            .get_meta::<Vec<PrekeyBundle>>(META_LINKED_BUNDLES)?
            .unwrap_or_default();
        Ok(Some(OwnDevices { list, bundles }))
    }

    /// Mes autres appareils (tous sauf `me`), avec leur paquet de clés s'il est connu.
    pub fn others(&self, me: &DevicePublic) -> Vec<(DevicePublic, Option<PrekeyBundle>)> {
        self.list
            .certs
            .iter()
            .filter(|c| c.device != *me)
            .map(|c| {
                let bundle = self.bundles.iter().find(|b| b.device == c.device).cloned();
                (c.device, bundle)
            })
            .collect()
    }
}

fn load_card(bytes: &[u8]) -> Result<ContactCard> {
    postcard::from_bytes(bytes).map_err(|_| CoreError::Store("carte stockée illisible".into()))
}

fn ser_state(state: &RatchetState) -> Result<Vec<u8>> {
    postcard::to_allocvec(state).map_err(|_| CoreError::Store("sérialisation".into()))
}

fn de_state(bytes: &[u8]) -> Result<RatchetState> {
    postcard::from_bytes(bytes).map_err(|_| CoreError::Store("session corrompue".into()))
}

fn ser_init(init: &InitialMessage) -> Result<Vec<u8>> {
    postcard::to_allocvec(init).map_err(|_| CoreError::Store("sérialisation".into()))
}

fn de_init(bytes: &[u8]) -> Result<InitialMessage> {
    postcard::from_bytes(bytes).map_err(|_| CoreError::Store("session corrompue".into()))
}
