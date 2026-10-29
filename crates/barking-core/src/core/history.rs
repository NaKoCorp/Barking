//! Archive de l'historique transférée pendant une liaison (spec §3.4).
//!
//! **Production (A, `link_device`).** Le clair est
//! `postcard(Vec<HistoryEntry>) || blake3(ce postcard)` : le hash occupe les
//! 32 derniers octets du dernier morceau. Ce clair est découpé en morceaux
//! de [`HISTORY_CHUNK_LEN`] octets (64 Kio, le dernier pouvant être plus
//! court), chacun chiffré par `xseal(derive_key(LINK_HISTORY, secret),
//! ad = index_u32_be || count_u32_be, morceau)`. Seuls les messages des
//! contacts copiés dans le paquet de liaison sont archivés (un contact
//! supprimé garde ses messages sur A, mais T ne le connaît pas).
//!
//! **Import (T, `finish_link`).** Tout est vérifié avant la moindre
//! écriture : nombre de morceaux (au moins un, au plus
//! [`MAX_HISTORY_CHUNKS`]), taille de chaque chiffré, déchiffrement de chaque
//! morceau avec son index et le nombre total dans les données associées (un
//! morceau manquant, en double, déplacé ou modifié échoue ici), découpage
//! canonique, hash final, décodage exact, puis chaque entrée : contact
//! présent dans le paquet de liaison (sinon toute l'archive est refusée, et
//! pas seulement l'entrée : une archive authentique n'en contient jamais),
//! identifiants de message uniques. L'insertion se fait ensuite dans la
//! transaction de `finish_link` ; un identifiant déjà présent est ignoré
//! (`insert_message` rend faux), donc importer deux fois ne crée aucun
//! doublon, et une copie `SyncSent` reçue plus tard pour un message archivé
//! (même identifiant brut, sens sortant) est ignorée de même.
//!
//! **Ce qui n'est pas copié.** Les livraisons (`deliveries`), les paquets
//! reçus (`inbound`) et la file d'envoi restent sur A : T ne recevra jamais
//! les accusés des paquets de A, ni de renvoi des paquets que A a reçus.
//! Le statut de chaque message est recopié tel quel (vue identique à A) ;
//! il n'évolue plus sur T.
//!
//! **Plafond.** Au plus [`MAX_HISTORY_CHUNKS`] morceaux (32 Mio de clair) :
//! un fichier malveillant ne peut pas épuiser la mémoire de T, et A refuse
//! la liaison (« historique trop volumineux », sans rien écrire) plutôt que
//! de produire une archive que T refuserait ; il faut alors lier sans
//! historique.
//!
//! **Secrets.** La clé dérivée est dans `Zeroizing`, comme les clairs ; le
//! texte de chaque entrée est effacé à sa destruction.

use std::collections::HashSet;

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{XNONCE_LEN, xopen, xseal};
use crate::crypto::labels;
use crate::identity::root::Fingerprint;
use crate::store::{Direction, MessageId, MessageRow, MessageStatus, Queries};
use crate::{CoreError, Result};

/// Taille d'un morceau clair : 64 Kio (le dernier peut être plus court).
pub const HISTORY_CHUNK_LEN: usize = 64 * 1024;
/// Nombre maximal de morceaux d'une archive : 512, soit 32 Mio de clair.
pub const MAX_HISTORY_CHUNKS: usize = 512;
/// Taille du hash BLAKE3 final.
const HASH_LEN: usize = 32;
/// Étiquette d'authentification de XChaCha20-Poly1305.
const TAG_LEN: usize = 16;

const BAD_HISTORY: CoreError = CoreError::Link("historique invalide");
const TOO_LARGE: CoreError = CoreError::Link("historique trop volumineux");

/// Archive de l'historique : morceaux chiffrés, dans l'ordre.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryArchive {
    pub chunks: Vec<Vec<u8>>,
}

impl core::fmt::Debug for HistoryArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoryArchive")
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl HistoryArchive {
    /// Octets du fichier d'historique (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Sérialisation vers un `Vec` d'une structure sans état invalide.
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse de [`HistoryArchive::to_bytes`] ; octets en trop refusés.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        super::link::decode_exact(bytes)
    }
}

/// Sens d'un message dans l'archive (format figé, indépendant du stockage).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum WireDirection {
    Out,
    In,
}

/// Statut d'un message dans l'archive.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum WireStatus {
    Queued,
    Sent,
    Delivered,
    Failed,
}

/// Un message de l'historique, tel que stocké sur A. Le texte est effacé à
/// la destruction ; `Debug` ne l'affiche pas.
#[derive(Serialize, Deserialize)]
pub(super) struct HistoryEntry {
    /// Identifiant stocké (brut pour un message sortant, dérivé de
    /// l'expéditeur pour un message reçu) : recopié tel quel.
    message_id: [u8; 16],
    contact: Fingerprint,
    direction: WireDirection,
    body: String,
    status: WireStatus,
    at: u64,
}

impl Drop for HistoryEntry {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl core::fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("message_id", &MessageId(self.message_id))
            .field("contact", &self.contact)
            .field("direction", &self.direction)
            .field("body", &format_args!("<{} octets>", self.body.len()))
            .field("status", &self.status)
            .field("at", &self.at)
            .finish()
    }
}

impl HistoryEntry {
    fn from_row(row: MessageRow) -> HistoryEntry {
        let MessageRow {
            contact_fp,
            direction,
            body,
            status,
            at,
            message_id,
            ..
        } = row;
        HistoryEntry {
            message_id: message_id.0,
            contact: contact_fp,
            direction: match direction {
                Direction::Out => WireDirection::Out,
                Direction::In => WireDirection::In,
            },
            body,
            status: match status {
                MessageStatus::Queued => WireStatus::Queued,
                MessageStatus::Sent => WireStatus::Sent,
                MessageStatus::Delivered => WireStatus::Delivered,
                MessageStatus::Failed => WireStatus::Failed,
            },
            at,
        }
    }

    fn direction(&self) -> Direction {
        match self.direction {
            WireDirection::Out => Direction::Out,
            WireDirection::In => Direction::In,
        }
    }

    fn status(&self) -> MessageStatus {
        match self.status {
            WireStatus::Queued => MessageStatus::Queued,
            WireStatus::Sent => MessageStatus::Sent,
            WireStatus::Delivered => MessageStatus::Delivered,
            WireStatus::Failed => MessageStatus::Failed,
        }
    }
}

fn history_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(labels::LINK_HISTORY, secret))
}

/// Données associées d'un morceau : `index_u32_be || count_u32_be`.
fn chunk_ad(index: usize, count: usize) -> Result<[u8; 8]> {
    let index = u32::try_from(index).map_err(|_| TOO_LARGE)?;
    let count = u32::try_from(count).map_err(|_| TOO_LARGE)?;
    let mut ad = [0u8; 8];
    ad[..4].copy_from_slice(&index.to_be_bytes());
    ad[4..].copy_from_slice(&count.to_be_bytes());
    Ok(ad)
}

/// Messages de A à archiver : ceux des contacts `contacts` (copiés dans le
/// paquet de liaison), dans l'ordre d'insertion.
pub(super) fn export(
    q: &impl Queries,
    contacts: &HashSet<Fingerprint>,
) -> Result<Vec<HistoryEntry>> {
    let mut out = Vec::new();
    for mut row in q.all_messages()? {
        if contacts.contains(&row.contact_fp) {
            out.push(HistoryEntry::from_row(row));
        } else {
            row.body.zeroize();
        }
    }
    Ok(out)
}

/// Chiffre l'archive avec la clé dérivée du secret de liaison. Plus de
/// [`MAX_HISTORY_CHUNKS`] morceaux → « historique trop volumineux ».
pub(super) fn seal_archive(
    secret: &[u8; 32],
    entries: &[HistoryEntry],
    rng: &mut impl CryptoRng,
) -> Result<HistoryArchive> {
    let size = postcard::experimental::serialized_size(entries)
        .map_err(|_| CoreError::Malformed("historique"))?;
    let total = size.checked_add(HASH_LEN).ok_or(TOO_LARGE)?;
    let count = total.div_ceil(HISTORY_CHUNK_LEN);
    if count > MAX_HISTORY_CHUNKS {
        return Err(TOO_LARGE);
    }
    // Tampon de taille exacte : aucune réallocation ne laisse de copie du
    // clair en mémoire libérée.
    let mut plain = Zeroizing::new(vec![0u8; total]);
    let (body, hash) = plain.split_at_mut(size);
    let written = postcard::to_slice(entries, body)
        .map_err(|_| CoreError::Malformed("historique"))?
        .len();
    if written != size {
        return Err(CoreError::Malformed("historique"));
    }
    hash.copy_from_slice(blake3::hash(body).as_bytes());
    let key = history_key(secret);
    let chunks = plain
        .chunks(HISTORY_CHUNK_LEN)
        .enumerate()
        .map(|(i, c)| Ok(xseal(&key, &chunk_ad(i, count)?, c, rng)))
        .collect::<Result<Vec<_>>>()?;
    Ok(HistoryArchive { chunks })
}

/// Vérifie et déchiffre toute l'archive (voir la documentation du module).
/// N'écrit rien.
pub(super) fn open_archive(
    secret: &[u8; 32],
    archive: &HistoryArchive,
) -> Result<Vec<HistoryEntry>> {
    let count = archive.chunks.len();
    if count == 0 {
        return Err(BAD_HISTORY);
    }
    if count > MAX_HISTORY_CHUNKS {
        return Err(TOO_LARGE);
    }
    const MAX_SEALED: usize = HISTORY_CHUNK_LEN + XNONCE_LEN + TAG_LEN;
    if archive.chunks.iter().any(|c| c.len() > MAX_SEALED) {
        return Err(BAD_HISTORY);
    }
    let key = history_key(secret);
    // Capacité bornée par les octets réellement fournis.
    let capacity: usize = archive.chunks.iter().map(Vec::len).sum();
    let mut plain = Zeroizing::new(Vec::with_capacity(capacity));
    for (i, sealed) in archive.chunks.iter().enumerate() {
        let pt =
            Zeroizing::new(xopen(&key, &chunk_ad(i, count)?, sealed).map_err(|_| BAD_HISTORY)?);
        // Découpage canonique : morceaux pleins, sauf le dernier (non vide).
        let last = i + 1 == count;
        if (!last && pt.len() != HISTORY_CHUNK_LEN) || (last && pt.is_empty()) {
            return Err(BAD_HISTORY);
        }
        plain.extend_from_slice(&pt);
    }
    let size = plain.len().checked_sub(HASH_LEN).ok_or(BAD_HISTORY)?;
    let (body, hash) = plain.split_at(size);
    let hash: [u8; HASH_LEN] = hash.try_into().map_err(|_| BAD_HISTORY)?;
    // Comparaison en temps constant (`blake3::Hash`).
    if blake3::hash(body) != blake3::Hash::from(hash) {
        return Err(BAD_HISTORY);
    }
    match postcard::take_from_bytes::<Vec<HistoryEntry>>(body) {
        Ok((entries, [])) => Ok(entries),
        _ => Err(BAD_HISTORY),
    }
}

/// Chaque entrée concerne un contact de `contacts` (ceux du paquet de
/// liaison) et les identifiants de message sont uniques ; sinon toute
/// l'archive est refusée.
pub(super) fn check_entries(
    entries: &[HistoryEntry],
    contacts: &HashSet<Fingerprint>,
) -> Result<()> {
    let mut ids = HashSet::with_capacity(entries.len());
    for e in entries {
        if !contacts.contains(&e.contact) || !ids.insert(e.message_id) {
            return Err(BAD_HISTORY);
        }
    }
    Ok(())
}

/// Insère les entrées absentes (un identifiant déjà présent est ignoré).
/// Rend le nombre de messages insérés.
pub(super) fn import(q: &impl Queries, entries: &[HistoryEntry]) -> Result<u32> {
    let mut inserted = 0u32;
    for e in entries {
        if q.insert_message(
            e.contact,
            e.direction(),
            &e.body,
            e.status(),
            e.at,
            MessageId(e.message_id),
        )? {
            inserted = inserted.saturating_add(1);
        }
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }

    fn entry(id: u8, contact: u8, body: &str) -> HistoryEntry {
        HistoryEntry {
            message_id: [id; 16],
            contact: fp(contact),
            direction: if id.is_multiple_of(2) {
                WireDirection::Out
            } else {
                WireDirection::In
            },
            body: body.to_owned(),
            status: WireStatus::Delivered,
            at: u64::from(id),
        }
    }

    fn known(fps: &[u8]) -> HashSet<Fingerprint> {
        fps.iter().map(|&b| fp(b)).collect()
    }

    #[test]
    fn roundtrip_and_garbage() {
        let a = HistoryArchive {
            chunks: vec![vec![1, 2, 3], vec![]],
        };
        assert_eq!(HistoryArchive::from_bytes(&a.to_bytes()).unwrap(), a);
        assert_eq!(
            HistoryArchive::from_bytes(&[0xff, 0xff]),
            Err(CoreError::Link("fichier de liaison illisible"))
        );
    }

    #[test]
    fn seal_open_roundtrip_multi_chunk() {
        let mut rng = rand::rng();
        let secret = [5u8; 32];
        let big = "y".repeat(40_000);
        let entries: Vec<_> = (0..5).map(|i| entry(i, 1, &big)).collect();
        let archive = seal_archive(&secret, &entries, &mut rng).unwrap();
        assert_eq!(archive.chunks.len(), 4);
        let back = open_archive(&secret, &archive).unwrap();
        assert_eq!(back.len(), 5);
        assert!(
            back.iter()
                .zip(&entries)
                .all(|(a, b)| a.message_id == b.message_id
                    && a.body == b.body
                    && a.direction == b.direction
                    && a.at == b.at)
        );
        // Autre secret : refusé.
        assert_eq!(open_archive(&[6u8; 32], &archive).err(), Some(BAD_HISTORY));
        // Debug n'affiche pas le texte.
        assert!(!format!("{:?}", back[0]).contains("yyy"));
    }

    #[test]
    fn open_refuses_too_many_or_oversized_chunks() {
        let secret = [5u8; 32];
        let many = HistoryArchive {
            chunks: vec![Vec::new(); MAX_HISTORY_CHUNKS + 1],
        };
        assert_eq!(open_archive(&secret, &many).err(), Some(TOO_LARGE));
        let oversized = HistoryArchive {
            chunks: vec![vec![0u8; HISTORY_CHUNK_LEN + XNONCE_LEN + TAG_LEN + 1]],
        };
        assert_eq!(open_archive(&secret, &oversized).err(), Some(BAD_HISTORY));
    }

    #[test]
    fn open_refuses_non_canonical_split_and_bad_hash() {
        let mut rng = rand::rng();
        let secret = [5u8; 32];
        let key = history_key(&secret);
        let entries = vec![entry(1, 1, "salut")];
        let size = postcard::experimental::serialized_size(&entries).unwrap();
        let mut plain = vec![0u8; size + HASH_LEN];
        postcard::to_slice(&entries, &mut plain[..size]).unwrap();
        let h = blake3::hash(&plain[..size]);
        plain[size..].copy_from_slice(h.as_bytes());
        // Valide, en un morceau.
        let one = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &plain, &mut rng)],
        };
        assert_eq!(open_archive(&secret, &one).unwrap().len(), 1);
        // Même clair découpé en deux morceaux non pleins : refusé.
        let (x, y) = plain.split_at(3);
        let split = HistoryArchive {
            chunks: vec![
                xseal(&key, &chunk_ad(0, 2).unwrap(), x, &mut rng),
                xseal(&key, &chunk_ad(1, 2).unwrap(), y, &mut rng),
            ],
        };
        assert_eq!(open_archive(&secret, &split).err(), Some(BAD_HISTORY));
        // Hash incorrect (chiffrement valide).
        let mut wrong = plain.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        let bad = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &wrong, &mut rng)],
        };
        assert_eq!(open_archive(&secret, &bad).err(), Some(BAD_HISTORY));
        // Clair plus court que le hash.
        let short = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &[1, 2], &mut rng)],
        };
        assert_eq!(open_archive(&secret, &short).err(), Some(BAD_HISTORY));
    }

    #[test]
    fn check_entries_refuses_unknown_contact_and_duplicate_id() {
        let ok = vec![entry(1, 1, "a"), entry(2, 2, "b")];
        assert_eq!(check_entries(&ok, &known(&[1, 2])), Ok(()));
        assert_eq!(check_entries(&ok, &known(&[1])), Err(BAD_HISTORY));
        let dup = vec![entry(1, 1, "a"), entry(1, 1, "b")];
        assert_eq!(check_entries(&dup, &known(&[1])), Err(BAD_HISTORY));
    }

    #[test]
    fn history_import_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let mut store = Store::open(&d.path().join("db"), &[3u8; 32]).unwrap();
        let mut rng = rand::rng();
        let secret = [7u8; 32];
        let entries = vec![entry(1, 1, "a"), entry(2, 1, "b"), entry(3, 2, "c")];
        let archive = seal_archive(&secret, &entries, &mut rng).unwrap();
        let opened = open_archive(&secret, &archive).unwrap();
        let n = store.transaction(|tx| import(tx, &opened)).unwrap();
        assert_eq!(n, 3);
        let again = open_archive(&secret, &archive).unwrap();
        let n = store.transaction(|tx| import(tx, &again)).unwrap();
        assert_eq!(n, 0);
        assert_eq!(store.messages_with(fp(1)).unwrap().len(), 2);
        assert_eq!(store.messages_with(fp(2)).unwrap().len(), 1);
        let m = &store.messages_with(fp(1)).unwrap()[0];
        assert_eq!(
            (m.message_id, m.direction, m.status, m.at, m.body.as_str()),
            (
                MessageId([1; 16]),
                Direction::In,
                MessageStatus::Delivered,
                1,
                "a"
            )
        );
        // Export depuis ce stockage : seuls les contacts connus.
        let out = export(&store, &known(&[2])).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message_id, [3; 16]);
    }
}
