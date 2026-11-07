//! History archive transferred during a link (spec §3.4).
//!
//! **Production (A, `link_device`).** The plaintext is
//! `postcard(Vec<HistoryEntry>) || h || sig`, where `h = blake3(that postcard)` and
//! `sig` is the root's signature of `h` (`LINK_HISTORY_SIG`): hash and
//! signature take up the last 96 bytes. The link secret alone is therefore not
//! enough to forge an archive. This plaintext is split into chunks
//! of [`HISTORY_CHUNK_LEN`] bytes (64 KiB, the last one possibly
//! shorter), each encrypted by `xseal(derive_key(LINK_HISTORY, secret),
//! ad = index_u32_be || count_u32_be, chunk)`. Only the messages of the
//! contacts copied into the link packet are archived (a deleted
//! contact keeps its messages on A, but T does not know it).
//!
//! **Import (T, `finish_link`).** Everything is verified before any
//! write: number of chunks (at least one, at most
//! [`MAX_HISTORY_CHUNKS`]), size of each ciphertext, decryption of each
//! chunk with its index and the total count in the associated data (a
//! missing, duplicated, moved or modified chunk fails here), canonical
//! splitting, final hash, expected root signature, exact decoding, then each entry: contact
//! present in the link packet (otherwise the whole archive is refused, and
//! not only the entry: an authentic archive never contains one),
//! unique message identifiers. Insertion then happens in the
//! `finish_link` transaction; an already present identifier is ignored
//! (`insert_message` returns false), so importing twice creates no
//! duplicate, and a `SyncSent` copy received later for an archived message
//! (same raw identifier, outgoing direction) is likewise ignored.
//!
//! **What is not copied.** Deliveries (`deliveries`), received packets
//! (`inbound`) and the send queue stay on A: T will never receive
//! the acks of A's packets, nor any resend of the packets A received.
//! The status of each message is copied as is (view identical to A);
//! it no longer evolves on T.
//!
//! **Cap.** At most [`MAX_HISTORY_CHUNKS`] chunks (32 MiB of plaintext):
//! a malicious file cannot exhaust T's memory, and A refuses
//! the link ("history too large", writing nothing) rather than
//! produce an archive that T would refuse; one must then link without
//! history.
//!
//! **Secrets.** The derived key is in `Zeroizing`, like the plaintexts; the
//! text of each entry is wiped on drop.

use std::collections::HashSet;

use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{XNONCE_LEN, xopen, xseal};
use crate::crypto::labels;
use crate::identity::root::{Fingerprint, RootIdentity, RootPublic};
use crate::store::{Direction, MessageId, MessageRow, MessageStatus, Queries};
use crate::{CoreError, Result};

/// Size of a plaintext chunk: 64 KiB (the last one may be shorter).
pub const HISTORY_CHUNK_LEN: usize = 64 * 1024;
/// Maximum number of chunks in an archive: 512, i.e. 32 MiB of plaintext.
pub const MAX_HISTORY_CHUNKS: usize = 512;
/// Maximum size of an archive file: each encrypted chunk fits in
/// `64 KiB + 24 (nonce) + 16 (tag)` plus 3 bytes of length, plus the
/// length of the list. Beyond that, the input is refused before any decoding
/// (many empty chunks would inflate memory).
pub const MAX_ARCHIVE_BYTES: usize = MAX_HISTORY_CHUNKS * (HISTORY_CHUNK_LEN + 43) + 64;

/// Size of the final BLAKE3 hash.
const HASH_LEN: usize = 32;
/// Size of the root signature that follows the hash.
const SIG_LEN: usize = 64;
/// End of the plaintext: hash then signature.
const TRAILER_LEN: usize = HASH_LEN + SIG_LEN;
/// Authentication tag of XChaCha20-Poly1305.
const TAG_LEN: usize = 16;

const BAD_HISTORY: CoreError = CoreError::Link("invalid history");
const TOO_LARGE: CoreError = CoreError::Link("history too large");

/// History archive: encrypted chunks, in order.
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
    /// Bytes of the history file (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialization into a `Vec` of a structure without invalid state.
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse of [`HistoryArchive::to_bytes`]; extra bytes refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(TOO_LARGE);
        }
        super::link::decode_exact(bytes)
    }
}

/// Direction of a message in the archive (frozen format, independent of storage).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum WireDirection {
    Out,
    In,
}

/// Status of a message in the archive. Wire format frozen: the v2 names
/// stay, mapped one to one on `MessageStatus` (`Queued` ↔ `Pending`,
/// `Sent` ↔ `OnNetwork`, `Delivered` ↔ `Received`, `Failed` ↔ `NotDelivered`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum WireStatus {
    Queued,
    Sent,
    Delivered,
    Failed,
}

/// A history message, as stored on A. The text is wiped on
/// drop; `Debug` does not display it.
#[derive(Serialize, Deserialize)]
pub(super) struct HistoryEntry {
    /// Stored identifier (raw for an outgoing message, derived from
    /// the sender for a received one): copied as is.
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
            .field("body", &format_args!("<{} bytes>", self.body.len()))
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
                MessageStatus::Pending => WireStatus::Queued,
                MessageStatus::OnNetwork => WireStatus::Sent,
                MessageStatus::Received => WireStatus::Delivered,
                MessageStatus::NotDelivered => WireStatus::Failed,
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
            WireStatus::Queued => MessageStatus::Pending,
            WireStatus::Sent => MessageStatus::OnNetwork,
            WireStatus::Delivered => MessageStatus::Received,
            WireStatus::Failed => MessageStatus::NotDelivered,
        }
    }
}

fn history_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(labels::LINK_HISTORY, secret))
}

/// Associated data of a chunk: `index_u32_be || count_u32_be`.
fn chunk_ad(index: usize, count: usize) -> Result<[u8; 8]> {
    let index = u32::try_from(index).map_err(|_| TOO_LARGE)?;
    let count = u32::try_from(count).map_err(|_| TOO_LARGE)?;
    let mut ad = [0u8; 8];
    ad[..4].copy_from_slice(&index.to_be_bytes());
    ad[4..].copy_from_slice(&count.to_be_bytes());
    Ok(ad)
}

/// A's messages to archive: those of the `contacts` (copied into the
/// link packet), in insertion order.
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

/// Encrypts the archive with the key derived from the link secret, signed by
/// `root`. More than [`MAX_HISTORY_CHUNKS`] chunks → "history too
/// large".
pub(super) fn seal_archive(
    secret: &[u8; 32],
    root: &RootIdentity,
    entries: &[HistoryEntry],
    rng: &mut impl CryptoRng,
) -> Result<HistoryArchive> {
    let size = postcard::experimental::serialized_size(entries)
        .map_err(|_| CoreError::Malformed("history"))?;
    let total = size.checked_add(TRAILER_LEN).ok_or(TOO_LARGE)?;
    let count = total.div_ceil(HISTORY_CHUNK_LEN);
    if count > MAX_HISTORY_CHUNKS {
        return Err(TOO_LARGE);
    }
    // Exact-size buffer: no reallocation leaves a copy of the
    // plaintext in freed memory.
    let mut plain = Zeroizing::new(vec![0u8; total]);
    let (body, trailer) = plain.split_at_mut(size);
    let written = postcard::to_slice(entries, body)
        .map_err(|_| CoreError::Malformed("history"))?
        .len();
    if written != size {
        return Err(CoreError::Malformed("history"));
    }
    let hash = blake3::hash(body);
    let (h, sig) = trailer.split_at_mut(HASH_LEN);
    h.copy_from_slice(hash.as_bytes());
    sig.copy_from_slice(&root.sign(labels::LINK_HISTORY_SIG, hash.as_bytes()));
    let key = history_key(secret);
    let chunks = plain
        .chunks(HISTORY_CHUNK_LEN)
        .enumerate()
        .map(|(i, c)| Ok(xseal(&key, &chunk_ad(i, count)?, c, rng)))
        .collect::<Result<Vec<_>>>()?;
    Ok(HistoryArchive { chunks })
}

/// Verifies and decrypts the whole archive (see the module documentation),
/// signed by `root`. Writes nothing.
pub(super) fn open_archive(
    secret: &[u8; 32],
    root: &RootPublic,
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
    // Capacity bounded by the bytes actually supplied.
    let capacity: usize = archive.chunks.iter().map(Vec::len).sum();
    let mut plain = Zeroizing::new(Vec::with_capacity(capacity));
    for (i, sealed) in archive.chunks.iter().enumerate() {
        let pt =
            Zeroizing::new(xopen(&key, &chunk_ad(i, count)?, sealed).map_err(|_| BAD_HISTORY)?);
        // Canonical splitting: full chunks, except the last (non-empty).
        let last = i + 1 == count;
        if (!last && pt.len() != HISTORY_CHUNK_LEN) || (last && pt.is_empty()) {
            return Err(BAD_HISTORY);
        }
        plain.extend_from_slice(&pt);
    }
    let size = plain.len().checked_sub(TRAILER_LEN).ok_or(BAD_HISTORY)?;
    let (body, trailer) = plain.split_at(size);
    let (hash, sig) = trailer.split_at(HASH_LEN);
    let hash: [u8; HASH_LEN] = hash.try_into().map_err(|_| BAD_HISTORY)?;
    let sig: [u8; SIG_LEN] = sig.try_into().map_err(|_| BAD_HISTORY)?;
    // Constant-time comparison (`blake3::Hash`).
    if blake3::hash(body) != blake3::Hash::from(hash) {
        return Err(BAD_HISTORY);
    }
    root.verify(labels::LINK_HISTORY_SIG, &hash, &sig)
        .map_err(|_| BAD_HISTORY)?;
    match postcard::take_from_bytes::<Vec<HistoryEntry>>(body) {
        Ok((entries, [])) => Ok(entries),
        _ => Err(BAD_HISTORY),
    }
}

/// Each entry concerns a contact of `contacts` (those of the link
/// packet) and message identifiers are unique; otherwise the whole
/// archive is refused.
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

/// Inserts the absent entries (an already present identifier is ignored).
/// Returns the number of messages inserted.
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

    fn root(seed: u64) -> RootIdentity {
        use rand::SeedableRng;
        RootIdentity::generate(&mut rand::rngs::StdRng::seed_from_u64(seed)).0
    }

    #[test]
    fn roundtrip_and_garbage() {
        let a = HistoryArchive {
            chunks: vec![vec![1, 2, 3], vec![]],
        };
        assert_eq!(HistoryArchive::from_bytes(&a.to_bytes()).unwrap(), a);
        assert_eq!(
            HistoryArchive::from_bytes(&[0xff, 0xff]),
            Err(CoreError::Link("unreadable link file"))
        );
    }

    #[test]
    fn from_bytes_refuses_oversized_input() {
        // Many empty chunks: few bytes, lots of memory.
        let mut bytes = vec![0u8; MAX_ARCHIVE_BYTES + 1];
        bytes[0] = 0xff;
        assert_eq!(HistoryArchive::from_bytes(&bytes), Err(TOO_LARGE));
        // At the limit: decoded (and refused as unreadable), not "too big".
        bytes.truncate(MAX_ARCHIVE_BYTES);
        assert_eq!(
            HistoryArchive::from_bytes(&bytes),
            Err(CoreError::Link("unreadable link file"))
        );
    }

    #[test]
    fn seal_open_roundtrip_multi_chunk() {
        let mut rng = rand::rng();
        let secret = [5u8; 32];
        let big = "y".repeat(40_000);
        let entries: Vec<_> = (0..5).map(|i| entry(i, 1, &big)).collect();
        let archive = seal_archive(&secret, &root(1), &entries, &mut rng).unwrap();
        assert_eq!(archive.chunks.len(), 4);
        let back = open_archive(&secret, &root(1).public(), &archive).unwrap();
        assert_eq!(back.len(), 5);
        assert!(
            back.iter()
                .zip(&entries)
                .all(|(a, b)| a.message_id == b.message_id
                    && a.body == b.body
                    && a.direction == b.direction
                    && a.at == b.at)
        );
        // Other expected root: refused.
        assert_eq!(
            open_archive(&secret, &root(2).public(), &archive).err(),
            Some(BAD_HISTORY)
        );
        // Other secret: refused.
        assert_eq!(
            open_archive(&[6u8; 32], &root(1).public(), &archive).err(),
            Some(BAD_HISTORY)
        );
        // Debug does not display the text.
        assert!(!format!("{:?}", back[0]).contains("yyy"));
    }

    #[test]
    fn open_refuses_too_many_or_oversized_chunks() {
        let secret = [5u8; 32];
        let many = HistoryArchive {
            chunks: vec![Vec::new(); MAX_HISTORY_CHUNKS + 1],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &many).err(),
            Some(TOO_LARGE)
        );
        let oversized = HistoryArchive {
            chunks: vec![vec![0u8; HISTORY_CHUNK_LEN + XNONCE_LEN + TAG_LEN + 1]],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &oversized).err(),
            Some(BAD_HISTORY)
        );
    }

    #[test]
    fn open_refuses_non_canonical_split_and_bad_hash() {
        let mut rng = rand::rng();
        let secret = [5u8; 32];
        let key = history_key(&secret);
        let entries = vec![entry(1, 1, "hello")];
        let size = postcard::experimental::serialized_size(&entries).unwrap();
        let mut plain = vec![0u8; size + TRAILER_LEN];
        postcard::to_slice(&entries, &mut plain[..size]).unwrap();
        let h = blake3::hash(&plain[..size]);
        plain[size..size + HASH_LEN].copy_from_slice(h.as_bytes());
        let sig = root(1).sign(labels::LINK_HISTORY_SIG, h.as_bytes());
        plain[size + HASH_LEN..].copy_from_slice(&sig);
        // Valid, in one chunk.
        let one = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &plain, &mut rng)],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &one)
                .unwrap()
                .len(),
            1
        );
        // Same plaintext split into two non-full chunks: refused.
        let (x, y) = plain.split_at(3);
        let split = HistoryArchive {
            chunks: vec![
                xseal(&key, &chunk_ad(0, 2).unwrap(), x, &mut rng),
                xseal(&key, &chunk_ad(1, 2).unwrap(), y, &mut rng),
            ],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &split).err(),
            Some(BAD_HISTORY)
        );
        // Incorrect signature (valid encryption and hash).
        let mut wrong = plain.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        let bad_sig = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &wrong, &mut rng)],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &bad_sig).err(),
            Some(BAD_HISTORY)
        );
        // Incorrect hash (valid encryption).
        let mut wrong = plain.clone();
        wrong[size] ^= 1;
        let bad = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &wrong, &mut rng)],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &bad).err(),
            Some(BAD_HISTORY)
        );
        // Plaintext shorter than the hash.
        let short = HistoryArchive {
            chunks: vec![xseal(&key, &chunk_ad(0, 1).unwrap(), &[1, 2], &mut rng)],
        };
        assert_eq!(
            open_archive(&secret, &root(1).public(), &short).err(),
            Some(BAD_HISTORY)
        );
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
        let archive = seal_archive(&secret, &root(1), &entries, &mut rng).unwrap();
        let opened = open_archive(&secret, &root(1).public(), &archive).unwrap();
        let n = store.transaction(|tx| import(tx, &opened)).unwrap();
        assert_eq!(n, 3);
        let again = open_archive(&secret, &root(1).public(), &archive).unwrap();
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
                MessageStatus::Received,
                1,
                "a"
            )
        );
        // Export from this store: only the known contacts.
        let out = export(&store, &known(&[2])).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message_id, [3; 16]);
    }
}
