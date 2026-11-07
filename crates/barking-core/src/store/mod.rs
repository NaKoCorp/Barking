//! Encrypted SQLCipher storage.
//!
//! Shared typed methods: they are defined once in the
//! [`Queries`] trait (default methods on top of a `&Connection`), which
//! [`Store`] (plain call) and [`Tx`] (inside [`Store::transaction`]) implement.
//! The trait must be imported (`use barking_core::store::Queries`).
//! Any `Err` returned by the `transaction` closure rolls back all
//! writes.

mod schema;

use std::cell::RefCell;
use std::fmt;
use std::path::Path;

use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

use crate::identity::device::DeviceId;
use crate::identity::root::Fingerprint;
use crate::packet::{Kind, Packet, PacketId};
use crate::{CoreError, Result};

/// State of a delivery (`deliveries.status`) or of a message
/// (`messages.status`). The stored values are those of v2 (`Queued`,
/// `Sent`, `Delivered`, `Failed`): only the names changed in v3.
///
/// An outgoing message takes the best state of its deliveries to the
/// contact's devices (`own = 0`), see `core::delivery::recompute_message_status`;
/// a copy for one of my devices never makes it `Received`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStatus {
    /// Delivery: queued, no node accepted it yet. Message: no delivery
    /// accepted, at least one pending.
    Pending = 0,
    /// Delivery: a node accepted it. Message: at least one delivery
    /// accepted, none received.
    OnNetwork = 1,
    /// Delivery: its acknowledgement is verified. Message: at least one
    /// delivery received. Also the state of every received message.
    Received = 3,
    /// Delivery: expired without a deposit, or deposited then expired
    /// without an acknowledgement (confirmed). Message: all deliveries so.
    NotDelivered = 5,
}

impl MessageStatus {
    fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::Pending),
            1 => Ok(Self::OnNetwork),
            3 => Ok(Self::Received),
            5 => Ok(Self::NotDelivered),
            _ => Err(CoreError::Store("unknown status".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Out = 0,
    In = 1,
}

impl Direction {
    fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::Out),
            1 => Ok(Self::In),
            _ => Err(CoreError::Store("unknown direction".into())),
        }
    }
}

/// Stored contact: `card` is the postcard of `ContactCard` (opaque here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRow {
    pub fp: Fingerprint,
    pub card: Vec<u8>,
    pub alias: String,
    pub verified: bool,
}

/// Last known operation on a contact (last writer wins between
/// my devices). The order is `(at, removed, writer)`: at equal date, a
/// deletion wins, then the device with the greatest identifier, so
/// that all my devices decide the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactClock {
    pub at: u64,
    pub removed: bool,
    /// Device that performed the operation (zero: unknown, earlier database).
    pub writer: DeviceId,
}

impl ContactClock {
    /// Comparison key: `(at, removed, writer)`.
    pub fn key(&self) -> (u64, bool, [u8; 16]) {
        (self.at, self.removed, self.writer.0)
    }

    /// `true` if `self` strictly wins over `other` (absent: always).
    pub fn newer_than(&self, other: Option<&ContactClock>) -> bool {
        other.is_none_or(|o| self.key() > o.key())
    }
}

/// Stored session. `state` is the postcard of `RatchetState` and
/// `pending_initial` that of `InitialMessage`; Core (de)serializes them.
/// Does not derive `Debug`: contains secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub contact_device: DeviceId,
    pub contact_fp: Fingerprint,
    pub session_id: [u8; 16],
    pub state: Vec<u8>,
    pub mailbox_secret: [u8; 32],
    pub ad: Vec<u8>,
    pub pending_initial: Option<Vec<u8>>,
    pub last_rx: u64,
    pub created_at: u64,
}

impl fmt::Debug for SessionRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRow")
            .field("contact_device", &self.contact_device)
            .field("contact_fp", &self.contact_fp)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionRow {
    fn drop(&mut self) {
        self.state.zeroize();
        self.mailbox_secret.zeroize();
        self.ad.zeroize();
        if let Some(p) = self.pending_initial.as_mut() {
            p.zeroize();
        }
    }
}

/// Logical identifier of a message (16 bytes), common to all the packets
/// (one per recipient device) that carry it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    /// Identifier derived from a packet identifier: messages migrated from v1.
    #[must_use]
    pub fn legacy_from_packet(packet_id: PacketId) -> MessageId {
        let full = blake3::derive_key(schema::LEGACY_MESSAGE_ID_CONTEXT, &packet_id.0);
        let mut id = [0u8; 16];
        id.copy_from_slice(&full[..16]);
        MessageId(id)
    }

    /// Stored identifier of a message received from `sender` with envelope
    /// identifier `envelope_id` (chosen by the sender): see
    /// `schema::SCHEMA_V2_TABLES`. Two packets of the same message (resend) have
    /// the same stored identifier; two senders, never.
    #[must_use]
    pub fn incoming(sender: &Fingerprint, envelope_id: &[u8; 16]) -> MessageId {
        let mut material = [0u8; 48];
        material[..32].copy_from_slice(&sender.0);
        material[32..].copy_from_slice(envelope_id);
        let full = blake3::derive_key(crate::crypto::labels::MESSAGE_ID_IN, &material);
        let mut id = [0u8; 16];
        id.copy_from_slice(&full[..16]);
        MessageId(id)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MessageId({})",
            data_encoding::HEXLOWER.encode(&self.0[..4])
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub id: i64,
    pub contact_fp: Fingerprint,
    pub direction: Direction,
    pub body: String,
    pub status: MessageStatus,
    pub at: u64,
    pub message_id: MessageId,
}

impl fmt::Debug for MessageRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The message text never appears: only its size.
        f.debug_struct("MessageRow")
            .field("id", &self.id)
            .field("contact_fp", &self.contact_fp)
            .field("direction", &self.direction)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("status", &self.status)
            .field("at", &self.at)
            .field("message_id", &self.message_id)
            .finish()
    }
}

/// Delivery of a sent message to the contact's devices (`own = 0`
/// deliveries only), spec §5.8. Absent for a received message and for a
/// sent message without any delivery to the contact (sent from another of
/// my devices, imported history).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverySummary {
    /// The message's state (`messages.status`).
    pub state: MessageStatus,
    /// First sealing of its contact packets.
    pub sealed_at: u64,
    /// First node acceptance of one of them.
    pub deposited_at: Option<u64>,
    /// First verified acknowledgement of one of them.
    pub received_at: Option<u64>,
    /// Latest expiry of its contact packets, set only when the message is
    /// `NotDelivered` (every contact packet failed).
    pub expired_at: Option<u64>,
    /// Contact devices it was sealed for (its deliveries, not the card).
    pub devices: u32,
    pub devices_received: u32,
    /// On the network or received.
    pub devices_left: u32,
    /// Still `Pending`, but a deposit request was sent (its answer may have
    /// been lost): a node may have it, so it counts as left when deleting
    /// (spec §14.1). Included in `devices_pending`.
    pub devices_tried: u32,
    /// Still waiting on this device (not deposited, not failed).
    pub devices_pending: u32,
}

/// One delivery of a sent message (`Queries::message_delivery`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceDeliveryRow {
    /// Recipient device: the contact's, or one of mine (`own`).
    pub device: DeviceId,
    /// Synchronisation copy for one of my devices.
    pub own: bool,
    pub state: MessageStatus,
    pub sealed_at: u64,
    pub deposited_at: Option<u64>,
    /// Short id of the first node that accepted it.
    pub node: Option<String>,
    pub received_at: Option<u64>,
    pub expired_at: Option<u64>,
    /// Packet bytes on the wire.
    pub size: Option<u32>,
}

/// A node that accepted at least one of the contact packets of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayHop {
    /// Short node id.
    pub node: String,
    /// First acceptance on that node.
    pub at: u64,
    /// Packet bytes (the largest of its packets there; 0 if unknown).
    pub size: u32,
}

/// Copies of a message for my other devices (`own = 1` deliveries).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnCopies {
    pub total: u32,
    /// On the network or received.
    pub left: u32,
    /// Still waiting on this device.
    pub waiting: u32,
}

/// Delivery detail of a sent message (the message sheet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDeliveryDetail {
    pub row_id: i64,
    pub contact: Fingerprint,
    pub summary: DeliverySummary,
    /// Deliveries to the contact's devices, then the copies for mine; each
    /// group by sealing date.
    pub deliveries: Vec<DeviceDeliveryRow>,
    /// Distinct nodes that accepted a contact packet, first acceptance
    /// first: from the route steps, or, once those are purged, from each
    /// delivery's first node. Only the latest attempt of a retried
    /// message is known (a retry drops the failed delivery and its steps).
    pub relays: Vec<RelayHop>,
    pub own_copies: OwnCopies,
}

/// Sort of a pending packet that is not one of my messages to a contact
/// (spec §5.7): the "Synchronisation" section, read only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingKind {
    /// A receipt for a message I received.
    Ack,
    /// A copy of one of my sent messages for my other devices. Includes
    /// the copies of a message I deleted after it left for the contact:
    /// the contact receives it, so its copies keep going without a row.
    OwnCopy,
    /// Synchronisation content for my devices without a message
    /// (contacts, device list, administration, leaving).
    DeviceSync,
    /// My card update for a contact's device.
    CardUpdate,
}

/// One of my messages with packets to the contact still pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMessage {
    pub row_id: i64,
    pub contact: Fingerprint,
    pub body: String,
    pub sealed_at: u64,
    /// Earliest expiry of its pending packets.
    pub expires_at: u64,
    /// Its pending packets.
    pub packets: u32,
    /// Its contact deliveries.
    pub devices: u32,
    /// Its contact deliveries on the network or received.
    pub devices_left: u32,
    /// Its contact deliveries still pending whose deposit was tried: a node
    /// may have them (spec §14.1).
    pub devices_tried: u32,
}

/// Pending packets of one sort of the "Synchronisation" section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSync {
    pub kind: PendingKind,
    pub packets: u32,
    /// Distinct contacts concerned, when known.
    pub contacts: Vec<Fingerprint>,
}

/// Packets in the send queue that no node accepted yet and that have not
/// expired (spec §5.7). `packets` = the sum of both sections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingPackets {
    /// Oldest expiry first.
    pub messages: Vec<PendingMessage>,
    /// In `PendingKind` order, only the sorts that have packets.
    pub sync: Vec<PendingSync>,
    pub packets: u32,
}

pub(crate) fn map_err(e: rusqlite::Error) -> CoreError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e
        && f.code == ErrorCode::NotADatabase
    {
        return CoreError::StoreLocked;
    }
    // The SQLite message contains no user data or key.
    CoreError::Store(e.to_string())
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|_| CoreError::Store("serialization".into()))
}

/// Fixed-size field. On a length error the bytes (possibly key material)
/// are wiped before being dropped.
pub(crate) fn arr<const N: usize>(b: Vec<u8>) -> Result<[u8; N]> {
    b.try_into().map_err(|mut v: Vec<u8>| {
        v.zeroize();
        CoreError::Store("invalid field length".into())
    })
}

/// Maximum age of transparency log entries (30 days).
pub const LOG_MAX_AGE_SECS: u64 = 30 * 86_400;
/// Maximum advance of the log purge clock per event (2 days).
///
/// More than one day: daily activity makes a lagging clock gain a day per day
/// (after a period of rare activity), so it catches up
/// with real time. With exactly one day, a lag would be permanent.
pub const LOG_PURGE_CLOCK_STEP_SECS: u64 = 2 * 86_400;

/// `meta` key of the log purge clock (u64, monotonic).
const META_LOG_PURGE_CLOCK: &str = "transparency_purge_clock";
/// Maximum number of regular entries kept in the transparency log.
pub const LOG_MAX_ROWS: u64 = 10_000;
/// Maximum number of security entries kept, a separate cap: regular
/// entries (which a third party can trigger) never evict them.
pub const LOG_MAX_SECURITY_ROWS: u64 = 10_000;

/// Class of a log entry (column `class`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventClass {
    /// Regular entry, subject to the `LOG_MAX_ROWS` cap.
    Routine = 0,
    /// Security proof (established session, changed contact key), subject
    /// to the separate `LOG_MAX_SECURITY_ROWS` cap.
    Security = 1,
}

pub(crate) fn to_i64(v: u64) -> i64 {
    // Unix seconds fit comfortably in an i64.
    i64::try_from(v).unwrap_or(i64::MAX)
}

pub(crate) fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// A stored route step, joined to its packet's delivery (see
/// `Queries::route_of_message`). `step`: `RouteStep` as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub at: u64,
    pub step: u8,
    pub node: Option<String>,
    pub size: Option<u32>,
    pub device: Option<DeviceId>,
    pub own: bool,
}

pub struct Store {
    conn: Connection,
    /// Changes noted by `Queries::note_change` (committed ones only).
    noted: RefCell<Vec<(Fingerprint, i64)>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Transaction handle, passed to the closure of [`Store::transaction`].
pub struct Tx<'a> {
    conn: &'a Connection,
    /// Changes noted in this transaction: handed to the store on commit,
    /// dropped on rollback.
    noted: RefCell<Vec<(Fingerprint, i64)>>,
}

impl Store {
    /// Opens (or creates) the encrypted database with a 32-byte key.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Store> {
        let conn = Connection::open(path).map_err(map_err)?;
        // Another process (`barking send` during `barking sync`) may hold
        // the write lock: wait a bit rather than failing immediately.
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(map_err)?;
        let mut hex = data_encoding::HEXLOWER.encode(key);
        let mut pragma = format!("PRAGMA key = \"x'{hex}'\";");
        let r = conn.execute_batch(&pragma);
        hex.zeroize();
        pragma.zeroize();
        r.map_err(map_err)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(map_err)?;
        // Freed pages overwritten with zeros (deleted messages, sessions).
        conn.execute_batch("PRAGMA secure_delete = ON;")
            .map_err(map_err)?;
        let store = Store {
            conn,
            noted: RefCell::new(Vec::new()),
        };
        store.apply_schema()?;
        Ok(store)
    }

    fn apply_schema(&self) -> Result<()> {
        // Version already written: a database newer than the code is rejected
        // before any write.
        let has_meta: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        let stored = if has_meta {
            self.get_meta::<u32>("schema_version")?
        } else {
            None
        };
        if stored.is_some_and(|v| v > schema::SCHEMA_VERSION) {
            return Err(CoreError::Store(
                "database newer than this version of Barking".into(),
            ));
        }
        // A new database (or v1 without version) goes through the v1 schema, then
        // the migration: a single path for all databases to migrate.
        if stored.is_none_or(|v| v < 2) {
            self.conn
                .execute_batch(schema::SCHEMA_V1_LEGACY)
                .map_err(map_err)?;
        }
        // `class` column of the log, added to the v1 schema after the fact: a
        // database created before it receives it here (idempotent); its existing entries
        // are classed as regular.
        let has_class: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('transparency') \
                 WHERE name = 'class'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if !has_class {
            self.conn
                .execute_batch(schema::TRANSPARENCY_ADD_CLASS)
                .map_err(map_err)?;
        }
        if stored.is_none_or(|v| v < 2) {
            schema::migrate_v1_to_v2(&self.conn).map_err(map_err)?;
        }
        let has_verified_at: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('contacts') WHERE name = 'verified_at'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if !has_verified_at {
            self.conn
                .execute_batch(schema::CONTACTS_ADD_VERIFIED_AT)
                .map_err(map_err)?;
        }
        self.conn
            .execute_batch(schema::SCHEMA_V2_INBOUND)
            .map_err(map_err)?;
        let has_own: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('deliveries') WHERE name = 'own'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if !has_own {
            self.conn
                .execute_batch(schema::DELIVERIES_ADD_OWN)
                .map_err(map_err)?;
        }
        let has_writer: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('contact_clock') \
                 WHERE name = 'writer'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if !has_writer {
            self.conn
                .execute_batch(schema::CONTACT_CLOCK_ADD_WRITER)
                .map_err(map_err)?;
        }
        self.conn
            .execute_batch(schema::TRANSPARENCY_INDEXES)
            .map_err(map_err)?;
        self.conn
            .execute_batch(schema::ROUTE_STEPS)
            .map_err(map_err)?;
        // Last: the backfill reads `deliveries.own` and `route_steps`.
        if stored.is_none_or(|v| v < 3) {
            schema::migrate_v2_to_v3(&self.conn).map_err(map_err)?;
        }
        // `outbox.deposit_tried_at`, added to v3 before its release: a
        // development database already at v3 receives it here (idempotent).
        let has_tried: bool = self
            .conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_info('outbox') \
                 WHERE name = 'deposit_tried_at'",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if !has_tried {
            self.conn
                .execute_batch(schema::OUTBOX_ADD_DEPOSIT_TRIED_AT)
                .map_err(map_err)?;
        }
        Ok(())
    }

    /// Runs `f` in a single transaction; `Err` => full rollback.
    pub fn transaction<R>(&mut self, f: impl FnOnce(&Tx) -> Result<R>) -> Result<R> {
        let txn = self.conn.transaction().map_err(map_err)?;
        let tx = Tx {
            conn: &txn,
            noted: RefCell::new(Vec::new()),
        };
        let out = f(&tx);
        let noted = tx.noted.into_inner();
        match out {
            Ok(v) => {
                txn.commit().map_err(map_err)?;
                self.noted.get_mut().extend(noted);
                Ok(v)
            }
            Err(e) => {
                let _ = txn.rollback();
                Err(e)
            }
        }
    }

    /// Takes the changes noted by `Queries::note_change` since the last
    /// call (committed transactions only).
    pub fn take_noted_changes(&mut self) -> Vec<(Fingerprint, i64)> {
        std::mem::take(self.noted.get_mut())
    }
}

/// Typed methods, common to [`Store`] and [`Tx`].
pub trait Queries {
    #[doc(hidden)]
    fn noted(&self) -> &RefCell<Vec<(Fingerprint, i64)>>;

    /// Notes that the delivery of the sent message `(contact, row id)`
    /// changed, from code too deep in a transaction to return it: kept in
    /// memory, handed over on commit (`Store::take_noted_changes`).
    fn note_change(&self, contact: Fingerprint, row_id: i64) {
        self.noted().borrow_mut().push((contact, row_id));
    }

    #[doc(hidden)]
    fn conn(&self) -> &Connection;

    fn put_meta<T: Serialize>(&self, k: &str, v: &T) -> Result<()> {
        let mut bytes = ser(v)?;
        let r = self.conn().execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) \
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, bytes],
        );
        bytes.zeroize();
        r.map_err(map_err)?;
        Ok(())
    }

    /// Raw bytes of a `meta` entry (for formats that changed over time).
    fn get_meta_raw(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.conn()
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()
            .map_err(map_err)
    }

    fn get_meta<T: DeserializeOwned>(&self, k: &str) -> Result<Option<T>> {
        let mut raw: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()
            .map_err(map_err)?;
        let out = match raw.as_deref() {
            None => Ok(None),
            Some(b) => postcard::from_bytes(b)
                .map(Some)
                .map_err(|_| CoreError::Store("corrupted meta data".into())),
        };
        if let Some(r) = raw.as_mut() {
            r.zeroize();
        }
        out
    }

    /// Deletes an entry; `true` if it existed.
    fn delete_meta(&self, k: &str) -> Result<bool> {
        let n = self
            .conn()
            .execute("DELETE FROM meta WHERE k = ?1", params![k])
            .map_err(map_err)?;
        Ok(n == 1)
    }

    fn upsert_contact(
        &self,
        fp: Fingerprint,
        card: &[u8],
        alias: &str,
        verified: bool,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO contacts(fp, card, alias, verified) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(fp) DO UPDATE SET card = excluded.card, \
                 alias = excluded.alias, verified = excluded.verified",
                params![fp.0.as_slice(), card, alias, verified],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Date of the contact's last verification change (0: unknown).
    fn verified_at(&self, fp: Fingerprint) -> Result<u64> {
        let at: Option<i64> = self
            .conn()
            .query_row(
                "SELECT verified_at FROM contacts WHERE fp = ?1",
                params![fp.0.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?;
        Ok(at.map_or(0, |a| u64::try_from(a).unwrap_or(0)))
    }

    /// Sets the verified register of a known contact.
    fn set_verified(&self, fp: Fingerprint, verified: bool, at: u64) -> Result<()> {
        self.conn()
            .execute(
                "UPDATE contacts SET verified = ?2, verified_at = ?3 WHERE fp = ?1",
                params![
                    fp.0.as_slice(),
                    verified,
                    i64::try_from(at).unwrap_or(i64::MAX)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    fn get_contact(&self, fp: Fingerprint) -> Result<Option<ContactRow>> {
        let row = self
            .conn()
            .query_row(
                "SELECT fp, card, alias, verified FROM contacts WHERE fp = ?1",
                params![fp.0.as_slice()],
                contact_raw,
            )
            .optional()
            .map_err(map_err)?;
        row.map(contact_from_raw).transpose()
    }

    fn list_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT fp, card, alias, verified FROM contacts ORDER BY alias, fp")
            .map_err(map_err)?;
        let raws = stmt
            .query_map([], contact_raw)
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter().map(contact_from_raw).collect()
    }

    fn find_contact_by_alias(&self, alias: &str) -> Result<Option<ContactRow>> {
        let row = self
            .conn()
            .query_row(
                "SELECT fp, card, alias, verified FROM contacts WHERE alias = ?1 \
                 ORDER BY fp LIMIT 1",
                params![alias],
                contact_raw,
            )
            .optional()
            .map_err(map_err)?;
        row.map(contact_from_raw).transpose()
    }

    fn put_session(&self, s: &SessionRow) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO sessions(contact_device, contact_fp, session_id, state, \
                 mailbox_secret, ad, pending_initial, last_rx, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(contact_fp, contact_device, session_id) DO UPDATE SET \
                 state = excluded.state, \
                 mailbox_secret = excluded.mailbox_secret, ad = excluded.ad, \
                 pending_initial = excluded.pending_initial, \
                 last_rx = excluded.last_rx, created_at = excluded.created_at",
                params![
                    s.contact_device.0.as_slice(),
                    s.contact_fp.0.as_slice(),
                    s.session_id.as_slice(),
                    s.state,
                    s.mailbox_secret.as_slice(),
                    s.ad,
                    s.pending_initial,
                    to_i64(s.last_rx),
                    to_i64(s.created_at)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Sessions with device `device` of contact `contact_fp`. A session
    /// always belongs to a (contact, device) pair: the same device
    /// claimed by two contacts never shares a session.
    fn sessions_for(&self, contact_fp: Fingerprint, device: DeviceId) -> Result<Vec<SessionRow>> {
        query_sessions(
            self.conn(),
            "WHERE contact_fp = ?1 AND contact_device = ?2 ORDER BY created_at, session_id",
            params![contact_fp.0.as_slice(), device.0.as_slice()],
        )
    }

    fn all_sessions(&self) -> Result<Vec<SessionRow>> {
        query_sessions(self.conn(), "ORDER BY created_at, session_id", [])
    }

    /// Inserts a message. `false` if `message_id` already exists, or was
    /// deleted from this device (a tombstone in `deleted_messages`, kept
    /// for good): nothing is written. A late `SyncSent` copy, a resend or
    /// retry by the contact or a history import thus never brings a deleted
    /// message back.
    fn insert_message(
        &self,
        contact_fp: Fingerprint,
        direction: Direction,
        body: &str,
        status: MessageStatus,
        at: u64,
        message_id: MessageId,
    ) -> Result<bool> {
        let n = self
            .conn()
            .execute(
                "INSERT OR IGNORE INTO messages(message_id, contact_fp, direction, body, \
                 status, at) SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE NOT EXISTS \
                 (SELECT 1 FROM deleted_messages WHERE message_id = ?1)",
                params![
                    message_id.0.as_slice(),
                    contact_fp.0.as_slice(),
                    direction as i64,
                    body,
                    status as i64,
                    to_i64(at)
                ],
            )
            .map_err(map_err)?;
        Ok(n == 1)
    }

    /// Tombstone of the message `message_id`, deleted at `at`:
    /// `insert_message` refuses it from now on. Never purged (16 bytes
    /// and a date per deleted message): a retry may come any time later.
    fn add_tombstone(&self, message_id: MessageId, at: u64) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO deleted_messages(message_id, at) VALUES (?1, ?2) \
                 ON CONFLICT(message_id) DO UPDATE SET at = excluded.at",
                params![message_id.0.as_slice(), to_i64(at)],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Records that the received packet `packet_id` carried the message
    /// `message_id` (a resend adds a row for the same message).
    fn record_inbound(&self, packet_id: PacketId, message_id: MessageId) -> Result<()> {
        self.conn()
            .execute(
                "INSERT OR IGNORE INTO inbound(packet_id, message_id) VALUES (?1, ?2)",
                params![packet_id.0.as_slice(), message_id.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Records the packet `packet_id`, destined for device `device`, as a
    /// `Pending` delivery of the message `message_id`, sealed at
    /// `sealed_at`, of `size` bytes. `own`: synchronisation copy for one of
    /// my devices.
    fn add_delivery(
        &self,
        message_id: MessageId,
        packet_id: PacketId,
        device: DeviceId,
        own: bool,
        sealed_at: u64,
        size: u32,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO deliveries(message_id, packet_id, device, status, own, \
                 sealed_at, size) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    message_id.0.as_slice(),
                    packet_id.0.as_slice(),
                    device.0.as_slice(),
                    MessageStatus::Pending as i64,
                    i64::from(own),
                    to_i64(sealed_at),
                    i64::from(size)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// `true` if a received packet carrying the message `message_id` is already
    /// recorded in `inbound`.
    fn inbound_has_message(&self, message_id: MessageId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM inbound WHERE message_id = ?1",
                params![message_id.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Marks the delivery `packet_id` as `Received`, acknowledged at `now`
    /// (the first acknowledgement's time is kept). Returns the message
    /// concerned, or `None` if no delivery carries this packet. The
    /// message's state is left to the caller
    /// (`core::delivery::recompute_message_status`): an acknowledgement from
    /// a single recipient device makes it `Received`; that of a copy for one
    /// of my devices (`own`) never does.
    fn mark_delivered_by_packet(&self, packet_id: PacketId, now: u64) -> Result<Option<MessageId>> {
        let mid: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT message_id FROM deliveries WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?;
        let Some(mid) = mid else {
            return Ok(None);
        };
        self.conn()
            .execute(
                "UPDATE deliveries SET status = ?1, acked_at = coalesce(acked_at, ?2) \
                 WHERE packet_id = ?3",
                params![
                    MessageStatus::Received as i64,
                    to_i64(now),
                    packet_id.0.as_slice()
                ],
            )
            .map_err(map_err)?;
        Ok(Some(MessageId(arr(mid)?)))
    }

    /// Last known operation on the contact `fp`.
    fn contact_clock(&self, fp: Fingerprint) -> Result<Option<ContactClock>> {
        let row: Option<(i64, i64, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT at, removed, writer FROM contact_clock WHERE fp = ?1",
                params![fp.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(map_err)?;
        row.map(|(at, removed, writer)| {
            Ok(ContactClock {
                at: to_u64(at),
                removed: removed != 0,
                writer: DeviceId(arr(writer)?),
            })
        })
        .transpose()
    }

    /// Records the last operation on the contact `fp` (`removed`:
    /// tombstone of a deletion).
    fn set_contact_clock(&self, fp: Fingerprint, clock: &ContactClock) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO contact_clock(fp, at, removed, writer) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(fp) DO UPDATE SET at = excluded.at, removed = excluded.removed, \
                 writer = excluded.writer",
                params![
                    fp.0.as_slice(),
                    to_i64(clock.at),
                    i64::from(clock.removed),
                    clock.writer.0.as_slice()
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// `true` if the delivery carrying `packet_id` has already received its acknowledgement.
    fn delivery_acked(&self, packet_id: PacketId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM deliveries WHERE packet_id = ?1 AND status = ?2",
                params![packet_id.0.as_slice(), MessageStatus::Received as i64],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// `true` if `packet_id` is one of my sent packets (a delivery).
    fn is_my_packet(&self, packet_id: PacketId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM deliveries WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Messages of a contact, from oldest to newest.
    fn messages_with(&self, contact_fp: Fingerprint) -> Result<Vec<MessageRow>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, contact_fp, direction, body, status, at, message_id \
                 FROM messages WHERE contact_fp = ?1 ORDER BY at, id",
            )
            .map_err(map_err)?;
        let raws = stmt
            .query_map(params![contact_fp.0.as_slice()], message_raw)
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter().map(message_from_raw).collect()
    }

    /// All messages, in insertion order (history archive).
    fn all_messages(&self) -> Result<Vec<MessageRow>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, contact_fp, direction, body, status, at, message_id \
                 FROM messages ORDER BY id",
            )
            .map_err(map_err)?;
        let raws = stmt
            .query_map([], message_raw)
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter().map(message_from_raw).collect()
    }

    /// `true` if the packet is new, `false` if it was already seen.
    fn mark_seen(&self, packet_id: PacketId, at: u64) -> Result<bool> {
        let n = self
            .conn()
            .execute(
                "INSERT OR IGNORE INTO seen(packet_id, at) VALUES (?1, ?2)",
                params![packet_id.0.as_slice(), to_i64(at)],
            )
            .map_err(map_err)?;
        Ok(n == 1)
    }

    /// `true` if the packet has already been seen (without recording it).
    fn is_seen(&self, packet_id: PacketId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM seen WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Deletes packets seen before `before`; returns the number of rows deleted.
    fn purge_seen(&self, before: u64) -> Result<usize> {
        self.conn()
            .execute("DELETE FROM seen WHERE at < ?1", params![to_i64(before)])
            .map_err(map_err)
    }

    /// Puts a packet in the send queue; no effect if it is already there.
    /// `reference`: for a receipt, the packet it acknowledges (`outbox.ref`).
    fn outbox_put(
        &self,
        packet_id: PacketId,
        bytes: &[u8],
        kind: Kind,
        expires_at: u64,
        now: u64,
        reference: Option<PacketId>,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at, ref)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(packet_id) DO NOTHING",
                params![
                    packet_id.0.as_slice(),
                    bytes,
                    kind as i64,
                    to_i64(expires_at),
                    to_i64(now),
                    reference.as_ref().map(|r| r.0.as_slice())
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Removes a packet from the queue; `true` if it was there.
    fn outbox_remove(&self, packet_id: PacketId) -> Result<bool> {
        let n = self
            .conn()
            .execute(
                "DELETE FROM outbox WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(n > 0)
    }

    /// Unexpired packets (`expires_at >= now`), from oldest to newest.
    fn outbox_pending(&self, now: u64) -> Result<Vec<(PacketId, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT packet_id, bytes FROM outbox WHERE expires_at >= ?1
                 ORDER BY created_at, rowid",
            )
            .map_err(map_err)?;
        let raws = stmt
            .query_map(params![to_i64(now)], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        raws.into_iter()
            .map(|(id, bytes)| Ok((PacketId(arr(id)?), bytes)))
            .collect()
    }

    /// Queued packets (`expires_at >= now`) that carry a message (a
    /// `messages` row) to a contact's device (`own = 0`) and still await
    /// its acknowledgement (`Pending` or `OnNetwork`), with the date they
    /// were queued; oldest first.
    fn outbox_awaiting_ack(&self, now: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT o.bytes, o.created_at FROM outbox o \
                 JOIN deliveries d ON d.packet_id = o.packet_id \
                 JOIN messages m ON m.message_id = d.message_id \
                 WHERE o.expires_at >= ?1 AND d.own = 0 AND d.status IN (?2, ?3) \
                 ORDER BY o.created_at, o.rowid",
            )
            .map_err(map_err)?;
        let awaiting = params![
            to_i64(now),
            MessageStatus::Pending as i64,
            MessageStatus::OnNetwork as i64
        ];
        let rows = stmt
            .query_map(awaiting, |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows.into_iter().map(|(b, at)| (b, to_u64(at))).collect())
    }

    /// Deletes expired packets, except the deposited ones whose delivery
    /// still awaits its verdict (`OnNetwork`, spec §15.5); returns the
    /// number of rows deleted.
    fn outbox_purge_expired(&self, now: u64) -> Result<usize> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE expires_at < ?1 AND NOT ( \
                 deposited_at IS NOT NULL AND EXISTS (SELECT 1 FROM deliveries d \
                 WHERE d.packet_id = outbox.packet_id AND d.status = ?2))",
                params![to_i64(now), MessageStatus::OnNetwork as i64],
            )
            .map_err(map_err)
    }

    /// Message linked to the packet identifier `packet_id`. Outgoing: via the
    /// `deliveries` table. Incoming: via the `inbound` table (never purged,
    /// unlike `seen`).
    fn message_by_packet(&self, packet_id: PacketId) -> Result<Option<MessageRow>> {
        const COLS: &str = "SELECT m.id, m.contact_fp, m.direction, m.body, m.status, m.at, \
                            m.message_id FROM messages m";
        let out = self
            .conn()
            .query_row(
                &format!(
                    "{COLS} JOIN deliveries d ON d.message_id = m.message_id \
                     WHERE d.packet_id = ?1 AND m.direction = ?2"
                ),
                params![packet_id.0.as_slice(), Direction::Out as i64],
                message_raw,
            )
            .optional()
            .map_err(map_err)?;
        let raw = match out {
            Some(r) => Some(r),
            None => self
                .conn()
                .query_row(
                    &format!(
                        "{COLS} JOIN inbound i ON i.message_id = m.message_id \
                         WHERE i.packet_id = ?1 AND m.direction = ?2"
                    ),
                    params![packet_id.0.as_slice(), Direction::In as i64],
                    message_raw,
                )
                .optional()
                .map_err(map_err)?,
        };
        raw.map(message_from_raw).transpose()
    }

    /// Deletes a contact, all its sessions and its packets in the send
    /// queue: my messages for it that never left (no deposit recorded nor
    /// tried: a deposited one stays for its verdict, `confirm_expired`), my
    /// card updates for its devices and my acknowledgements of its
    /// messages (the history is kept). The `SyncSent` copies of my
    /// messages for my other devices stay in the queue. Their pending
    /// deliveries are the caller's (`core::contacts::delete_in`).
    fn delete_contact(&self, fp: Fingerprint) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE deposited_at IS NULL AND deposit_tried_at IS NULL \
                 AND packet_id IN (SELECT d.packet_id FROM deliveries d \
                  JOIN messages m ON m.message_id = d.message_id \
                  WHERE m.contact_fp = ?1 AND m.direction = ?2 AND d.own = 0)",
                params![fp.0.as_slice(), Direction::Out as i64],
            )
            .map_err(map_err)?;
        // Card updates have no message row: found by the contact's devices,
        // those of its stored card and those it has a session with (devices
        // it has since dropped).
        const CARD_UPDATES: &str = "DELETE FROM outbox WHERE packet_id IN \
             (SELECT d.packet_id FROM deliveries d \
              WHERE d.own = 0 AND d.device IN ({devices}) AND NOT EXISTS \
              (SELECT 1 FROM messages m WHERE m.message_id = d.message_id))";
        self.conn()
            .execute(
                &CARD_UPDATES.replace(
                    "{devices}",
                    "SELECT contact_device FROM sessions WHERE contact_fp = ?1",
                ),
                params![fp.0.as_slice()],
            )
            .map_err(map_err)?;
        let card_devices: Vec<DeviceId> = self
            .get_contact(fp)?
            .and_then(|c| crate::contact::ContactCard::decode(&c.card).ok())
            .map(|card| card.devices.certs.iter().map(|c| c.device.id()).collect())
            .unwrap_or_default();
        for device in card_devices {
            self.conn()
                .execute(
                    &CARD_UPDATES.replace("{devices}", "?1"),
                    params![device.0.as_slice()],
                )
                .map_err(map_err)?;
        }
        // An acknowledgement carries the identifier of the received message it confirms.
        let acks = {
            let mut stmt = self
                .conn()
                .prepare("SELECT packet_id, bytes FROM outbox WHERE kind = ?1")
                .map_err(map_err)?;
            stmt.query_map(params![Kind::Ack as i64], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?
        };
        for (id, bytes) in acks {
            let Some(acked) = Packet::decode(&bytes)
                .ok()
                .and_then(|p| p.payload.get(..16).map(<[u8; 16]>::try_from))
                .and_then(core::result::Result::ok)
            else {
                continue;
            };
            if self
                .message_by_packet(PacketId(acked))?
                .is_some_and(|m| m.contact_fp == fp && m.direction == Direction::In)
            {
                self.outbox_remove(PacketId(arr(id)?))?;
            }
        }
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1",
                params![fp.0.as_slice()],
            )
            .map_err(map_err)?;
        self.conn()
            .execute(
                "DELETE FROM contacts WHERE fp = ?1",
                params![fp.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Deletes a session.
    fn delete_session(
        &self,
        contact_fp: Fingerprint,
        device: DeviceId,
        session_id: &[u8; 16],
    ) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1 AND contact_device = ?2 \
                 AND session_id = ?3",
                params![
                    contact_fp.0.as_slice(),
                    device.0.as_slice(),
                    session_id.as_slice()
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Deletes all sessions with a contact's device (revoked device).
    fn delete_sessions_for_device(&self, contact_fp: Fingerprint, device: DeviceId) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE contact_fp = ?1 AND contact_device = ?2",
                params![contact_fp.0.as_slice(), device.0.as_slice()],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// The `limit` most recent events, from oldest to newest.
    fn recent_events(&self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT at, event FROM (SELECT id, at, event FROM transparency \
                 ORDER BY id DESC LIMIT ?1) ORDER BY id",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![to_i64(limit as u64)], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows.into_iter().map(|(a, e)| (to_u64(a), e)).collect())
    }

    /// A page of the log, newest first: up to `limit` rows older than the
    /// row id `before` (none: from the newest), as (id, at, event).
    /// `security_only` keeps the security class only.
    fn transparency_page(
        &self,
        limit: usize,
        before: Option<i64>,
        security_only: bool,
    ) -> Result<Vec<(i64, u64, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, at, event FROM transparency \
                 WHERE id < ?1 AND (?2 = 0 OR class = 1) ORDER BY id DESC LIMIT ?3",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(
                params![
                    before.unwrap_or(i64::MAX),
                    i64::from(security_only),
                    to_i64(limit as u64)
                ],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|(i, a, e)| (i, to_u64(a), e))
            .collect())
    }

    /// Appends a transparency event (postcard, opaque here).
    fn append_event(
        &self,
        at: u64,
        packet_id: Option<PacketId>,
        class: EventClass,
        event: &[u8],
    ) -> Result<()> {
        // Monotonic purge clock, stored in `meta` (same transaction):
        // it never goes backwards and advances by at most LOG_PURGE_CLOCK_STEP_SECS
        // per event. Events dated far in the future
        // (misadjusted local clock) only advance it by 2 days each:
        // the log is not emptied. Trade-off: a low-activity log (fewer
        // than one event every 2 days) keeps its entries a bit longer than
        // 30 days, until activity lets the clock catch up (at
        // most the row caps); we prefer keeping too long to
        // losing a proof.
        let previous: Option<u64> = self.get_meta(META_LOG_PURGE_CLOCK)?;
        let clock = match previous {
            Some(p) => at.min(p.saturating_add(LOG_PURGE_CLOCK_STEP_SECS)).max(p),
            // First write (or database predating the clock): start from
            // the most recent existing entry, bounded in the same way.
            None => {
                let newest: Option<i64> = self
                    .conn()
                    .query_row("SELECT max(at) FROM transparency", [], |r| r.get(0))
                    .map_err(map_err)?;
                newest.map_or(at, |n| {
                    at.min(to_u64(n).saturating_add(LOG_PURGE_CLOCK_STEP_SECS))
                })
            }
        };
        if previous != Some(clock) {
            self.put_meta(META_LOG_PURGE_CLOCK, &clock)?;
        }
        // Purge time: never after `at` either, so that a clock
        // set back to the right time after an advance does not immediately purge the
        // new entries.
        let purge_at = at.min(clock);
        self.conn()
            .execute(
                "INSERT INTO transparency(at, packet_id, event, class) VALUES (?1, ?2, ?3, ?4)",
                params![
                    to_i64(at),
                    packet_id.map(|p| p.0.to_vec()),
                    event,
                    class as i64
                ],
            )
            .map_err(map_err)?;
        // Bounded purge, on the same connection (hence in the same transaction).
        // The age applies to all classes, and to the route steps.
        let oldest = to_i64(purge_at.saturating_sub(LOG_MAX_AGE_SECS));
        self.conn()
            .execute("DELETE FROM transparency WHERE at < ?1", params![oldest])
            .map_err(map_err)?;
        self.conn()
            .execute("DELETE FROM route_steps WHERE at < ?1", params![oldest])
            .map_err(map_err)?;
        // Per-class cap: only the class of the added entry has grown.
        let cap = match class {
            EventClass::Routine => LOG_MAX_ROWS,
            EventClass::Security => LOG_MAX_SECURITY_ROWS,
        };
        self.conn()
            .execute(
                "DELETE FROM transparency WHERE class = ?2 AND id <= \
                 (SELECT id FROM transparency WHERE class = ?2 \
                 ORDER BY id DESC LIMIT 1 OFFSET ?1)",
                params![to_i64(cap), class as i64],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Appends a route step of the packet `packet_id` (`step`: `RouteStep`
    /// as stored). A step on a node (`node` set) is kept once per packet,
    /// step and node: a refetch or a cross-check of the same packet on the
    /// same node adds nothing, the first date stays.
    fn add_route_step(
        &self,
        packet_id: PacketId,
        at: u64,
        step: u8,
        node: Option<&str>,
        size: Option<u32>,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO route_steps(packet_id, at, step, node, size) \
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE ?4 IS NULL OR NOT EXISTS ( \
                 SELECT 1 FROM route_steps WHERE packet_id = ?1 AND step = ?3 \
                 AND node = ?4)",
                params![
                    packet_id.0.as_slice(),
                    to_i64(at),
                    i64::from(step),
                    node,
                    size.map(i64::from)
                ],
            )
            .map_err(map_err)?;
        Ok(())
    }

    /// Whether `packet_id` carries a message: `(sent, received)`, sent if
    /// it is one of my deliveries, received if it is recorded in `inbound`.
    fn packet_has_message(&self, packet_id: PacketId) -> Result<(bool, bool)> {
        let (sent, received): (i64, i64) = self
            .conn()
            .query_row(
                "SELECT (SELECT count(*) FROM deliveries WHERE packet_id = ?1), \
                 (SELECT count(*) FROM inbound WHERE packet_id = ?1)",
                params![packet_id.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(map_err)?;
        Ok((sent > 0, received > 0))
    }

    /// Route steps of every packet of the message whose row is `row_id`
    /// (sent: through `deliveries`, with the recipient device and `own`;
    /// received: through `inbound`), by date then insertion order.
    fn route_of_message(&self, row_id: i64) -> Result<Vec<RouteRow>> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT at, step, node, size, device, own FROM ( \
                 SELECT r.rowid AS seq, r.at, r.step, r.node, r.size, d.device, d.own \
                 FROM messages m JOIN deliveries d ON d.message_id = m.message_id \
                 JOIN route_steps r ON r.packet_id = d.packet_id WHERE m.id = ?1 \
                 UNION ALL \
                 SELECT r.rowid, r.at, r.step, r.node, r.size, NULL, 0 \
                 FROM messages m JOIN inbound i ON i.message_id = m.message_id \
                 JOIN route_steps r ON r.packet_id = i.packet_id WHERE m.id = ?1) \
                 ORDER BY at, seq",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![row_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        rows.into_iter()
            .map(|(at, step, node, size, device, own)| {
                Ok(RouteRow {
                    at: to_u64(at),
                    step: u8::try_from(step).unwrap_or(u8::MAX),
                    node,
                    size: size.map(|s| u32::try_from(s).unwrap_or(u32::MAX)),
                    device: device.map(|d| arr(d).map(DeviceId)).transpose()?,
                    own: own != 0,
                })
            })
            .collect()
    }

    /// Messages with `contact`, oldest first, each with its delivery
    /// summary (spec §5.8; `None`: received, or no delivery to the contact).
    fn messages_with_delivery(
        &self,
        contact_fp: Fingerprint,
    ) -> Result<Vec<(MessageRow, Option<DeliverySummary>)>> {
        summaries(
            self.conn(),
            "m.contact_fp = ?1",
            "m.at, m.id",
            "",
            "m.at, m.id",
            &[&contact_fp.0.as_slice()],
        )
    }

    /// `messages_with_delivery` for the rows `ids` (any contact), at most
    /// `SUMMARY_CHUNK` per query: the rows found, in no given order.
    fn deliveries_of(&self, ids: &[i64]) -> Result<Vec<(MessageRow, Option<DeliverySummary>)>> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(SUMMARY_CHUNK) {
            let marks = vec!["?"; chunk.len()].join(", ");
            let args: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            out.extend(summaries(
                self.conn(),
                &format!("m.id IN ({marks})"),
                "m.id",
                "",
                "m.id",
                &args,
            )?);
        }
        Ok(out)
    }

    /// Sent messages to `contact` with a delivery to the contact, per
    /// state: `[pending, on_network, received, not_delivered]`.
    fn delivery_counts(&self, contact_fp: Fingerprint) -> Result<[u32; 4]> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT m.status, count(*) FROM messages m \
                 WHERE m.contact_fp = ?1 AND m.direction = ?2 AND EXISTS ( \
                 SELECT 1 FROM deliveries d WHERE d.message_id = m.message_id AND d.own = 0) \
                 GROUP BY m.status",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(
                params![contact_fp.0.as_slice(), Direction::Out as i64],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        let mut counts = [0u32; 4];
        for (status, n) in rows {
            let slot = match MessageStatus::from_i64(status)? {
                MessageStatus::Pending => 0,
                MessageStatus::OnNetwork => 1,
                MessageStatus::Received => 2,
                MessageStatus::NotDelivered => 3,
            };
            counts[slot] = u32::try_from(n).unwrap_or(u32::MAX);
        }
        Ok(counts)
    }

    /// One page of the sent messages to `contact` in `state` that have a
    /// delivery to the contact, newest first.
    fn delivery_page(
        &self,
        contact_fp: Fingerprint,
        state: MessageStatus,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<(MessageRow, DeliverySummary)>> {
        let rows = summaries(
            self.conn(),
            "m.contact_fp = ?1 AND m.direction = 0 AND m.status = ?2",
            "m.at, m.id",
            "HAVING count(d.packet_id) > 0",
            "m.at DESC, m.id DESC LIMIT ?3 OFFSET ?4",
            &[
                &contact_fp.0.as_slice(),
                &(state as i64),
                &i64::from(limit),
                &i64::from(offset),
            ],
        )?;
        Ok(rows
            .into_iter()
            .filter_map(|(m, s)| s.map(|s| (m, s)))
            .collect())
    }

    /// Delivery detail of the sent message `row_id`: its deliveries (to
    /// the contact, then to my devices) and the nodes that accepted its
    /// contact packets. `None` if unknown, received, or without any
    /// delivery to the contact.
    fn message_delivery(&self, row_id: i64) -> Result<Option<MessageDeliveryDetail>> {
        let Some((message, Some(summary))) =
            summaries(self.conn(), "m.id = ?1", "m.id", "", "m.id", &[&row_id])?.pop()
        else {
            return Ok(None);
        };
        let mid = message.message_id.0;
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT device, own, status, sealed_at, deposited_at, node, acked_at, \
                 expired_at, size FROM deliveries WHERE message_id = ?1 \
                 ORDER BY own, sealed_at, rowid",
            )
            .map_err(map_err)?;
        type Raw = (
            Vec<u8>,
            bool,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        );
        let raws = stmt
            .query_map(params![mid.as_slice()], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<Raw>>>()
            .map_err(map_err)?;
        let mut deliveries = Vec::with_capacity(raws.len());
        let mut own_copies = OwnCopies::default();
        for (device, own, status, sealed, deposited, node, acked, expired, size) in raws {
            let state = MessageStatus::from_i64(status)?;
            if own {
                own_copies.total += 1;
                match state {
                    MessageStatus::Pending => own_copies.waiting += 1,
                    MessageStatus::OnNetwork | MessageStatus::Received => own_copies.left += 1,
                    MessageStatus::NotDelivered => {}
                }
            }
            deliveries.push(DeviceDeliveryRow {
                device: DeviceId(arr(device)?),
                own,
                state,
                sealed_at: to_u64(sealed),
                deposited_at: deposited.map(to_u64),
                node,
                received_at: acked.map(to_u64),
                expired_at: expired.map(to_u64),
                size: size.map(|s| u32::try_from(s).unwrap_or(u32::MAX)),
            });
        }
        // Relays: the `Deposited` steps of the contact packets, or, for a
        // packet whose steps are purged, its delivery's first node.
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT node, min(at), max(size) FROM ( \
                 SELECT r.node AS node, r.at AS at, d.size AS size FROM deliveries d \
                 JOIN route_steps r ON r.packet_id = d.packet_id AND r.step = ?2 \
                 WHERE d.message_id = ?1 AND d.own = 0 AND r.node IS NOT NULL \
                 UNION ALL \
                 SELECT d.node, d.deposited_at, d.size FROM deliveries d \
                 WHERE d.message_id = ?1 AND d.own = 0 AND d.node IS NOT NULL \
                 AND d.deposited_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM route_steps r \
                 WHERE r.packet_id = d.packet_id AND r.step = ?2)) \
                 GROUP BY node ORDER BY min(at), node",
            )
            .map_err(map_err)?;
        let relays = stmt
            .query_map(params![mid.as_slice(), ROUTE_STEP_DEPOSITED], |r| {
                Ok(RelayHop {
                    node: r.get(0)?,
                    at: to_u64(r.get(1)?),
                    size: r
                        .get::<_, Option<i64>>(2)?
                        .map_or(0, |s| u32::try_from(s).unwrap_or(u32::MAX)),
                })
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(Some(MessageDeliveryDetail {
            row_id,
            contact: message.contact_fp,
            summary,
            deliveries,
            relays,
            own_copies,
        }))
    }

    /// Number of packets in the send queue that no node accepted yet and
    /// that have not expired (`expires_at >= now`), every sort.
    fn pending_count(&self, now: u64) -> Result<u32> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM outbox WHERE deposited_at IS NULL AND expires_at >= ?1",
                params![to_i64(now)],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// The packets of `pending_count`, classified (spec §5.7): my messages
    /// to a contact, then the other sorts.
    fn pending_packets(&self, now: u64) -> Result<PendingPackets> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT m.id, m.contact_fp, m.body, min(d.sealed_at), min(o.expires_at), \
                 count(*), \
                 (SELECT count(*) FROM deliveries d2 \
                  WHERE d2.message_id = m.message_id AND d2.own = 0), \
                 (SELECT count(*) FROM deliveries d3 \
                  WHERE d3.message_id = m.message_id AND d3.own = 0 AND d3.status IN (?2, ?3)), \
                 (SELECT count(*) FROM deliveries d4 \
                  JOIN outbox o4 ON o4.packet_id = d4.packet_id \
                  WHERE d4.message_id = m.message_id AND d4.own = 0 AND d4.status = ?5 \
                  AND o4.deposit_tried_at IS NOT NULL) \
                 FROM outbox o \
                 JOIN deliveries d ON d.packet_id = o.packet_id AND d.own = 0 \
                 JOIN messages m ON m.message_id = d.message_id AND m.direction = ?4 \
                 WHERE o.deposited_at IS NULL AND o.expires_at >= ?1 \
                 GROUP BY m.id ORDER BY min(o.expires_at), m.id",
            )
            .map_err(map_err)?;
        type Raw = (i64, Vec<u8>, String, i64, i64, i64, i64, i64, i64);
        let raws = stmt
            .query_map(
                params![
                    to_i64(now),
                    MessageStatus::OnNetwork as i64,
                    MessageStatus::Received as i64,
                    Direction::Out as i64,
                    MessageStatus::Pending as i64
                ],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<Raw>>>()
            .map_err(map_err)?;
        let count = |n: i64| u32::try_from(n).unwrap_or(u32::MAX);
        let mut out = PendingPackets::default();
        for (row_id, fp, body, sealed, expires, packets, devices, left, tried) in raws {
            out.packets = out.packets.saturating_add(count(packets));
            out.messages.push(PendingMessage {
                row_id,
                contact: Fingerprint(arr(fp)?),
                body,
                sealed_at: to_u64(sealed),
                expires_at: to_u64(expires),
                packets: count(packets),
                devices: count(devices),
                devices_left: count(left),
                devices_tried: count(tried),
            });
        }
        // Every other pending packet, with what classifies it: its kind,
        // its delivery (`own`), its message row or tombstone, and the
        // contact it concerns when known.
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT o.kind, d.packet_id IS NOT NULL, d.own, m.contact_fp, \
                 EXISTS (SELECT 1 FROM deleted_messages t WHERE t.message_id = d.message_id), \
                 (SELECT mi.contact_fp FROM inbound i \
                  JOIN messages mi ON mi.message_id = i.message_id AND mi.direction = ?3 \
                  WHERE i.packet_id = o.ref LIMIT 1), \
                 (SELECT s.contact_fp FROM sessions s \
                  WHERE s.contact_device = d.device LIMIT 1) \
                 FROM outbox o \
                 LEFT JOIN deliveries d ON d.packet_id = o.packet_id \
                 LEFT JOIN messages m ON m.message_id = d.message_id AND m.direction = ?2 \
                 WHERE o.deposited_at IS NULL AND o.expires_at >= ?1 \
                 AND NOT (d.own = 0 AND m.id IS NOT NULL)",
            )
            .map_err(map_err)?;
        type SyncRaw = (
            i64,
            bool,
            Option<bool>,
            Option<Vec<u8>>,
            Option<bool>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let raws = stmt
            .query_map(
                params![to_i64(now), Direction::Out as i64, Direction::In as i64],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<SyncRaw>>>()
            .map_err(map_err)?;
        let mut sync: std::collections::BTreeMap<PendingKind, (u32, Vec<Fingerprint>)> =
            std::collections::BTreeMap::new();
        for (kind, delivered, own, row_contact, tombstone, ack_contact, device_contact) in raws {
            let (kind, contact) = if kind == Kind::Ack as i64 {
                (PendingKind::Ack, ack_contact)
            } else if !delivered {
                // A queued message packet without a delivery: none is
                // written so today; counted with my devices' sync.
                (PendingKind::DeviceSync, None)
            } else if own == Some(true) {
                if row_contact.is_some() || tombstone == Some(true) {
                    (PendingKind::OwnCopy, row_contact)
                } else {
                    (PendingKind::DeviceSync, None)
                }
            } else {
                (PendingKind::CardUpdate, device_contact)
            };
            let entry = sync.entry(kind).or_default();
            entry.0 += 1;
            if let Some(fp) = contact {
                let fp = Fingerprint(arr(fp)?);
                if !entry.1.contains(&fp) {
                    entry.1.push(fp);
                }
            }
        }
        for (kind, (packets, mut contacts)) in sync {
            contacts.sort_by_key(|c| c.0);
            out.packets = out.packets.saturating_add(packets);
            out.sync.push(PendingSync {
                kind,
                packets,
                contacts,
            });
        }
        Ok(out)
    }

    /// The first `limit` events, in insertion order: `(at, event)`.
    fn events(&self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT at, event FROM transparency ORDER BY id LIMIT ?1")
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![to_i64(limit as u64)], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_err)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_err)?;
        Ok(rows.into_iter().map(|(a, e)| (to_u64(a), e)).collect())
    }
}

impl Queries for Store {
    fn conn(&self) -> &Connection {
        &self.conn
    }

    fn noted(&self) -> &RefCell<Vec<(Fingerprint, i64)>> {
        &self.noted
    }
}

impl Queries for Tx<'_> {
    fn conn(&self) -> &Connection {
        self.conn
    }

    fn noted(&self) -> &RefCell<Vec<(Fingerprint, i64)>> {
        &self.noted
    }
}

type MessageRaw = (i64, Vec<u8>, i64, String, i64, i64, Vec<u8>);

/// Ids per query of `Queries::deliveries_of`.
pub const SUMMARY_CHUNK: usize = 200;

/// `RouteStep::Deposited` as stored (`core::route`).
const ROUTE_STEP_DEPOSITED: i64 = 1;

/// The delivery summary query of spec §5.8: messages matching `filter`,
/// each with the aggregate of its deliveries to the contact (`own = 0`;
/// a received message joins none), grouped per message. `group` lists
/// columns that identify a message (`m.id` among them); giving the order's
/// columns lets one sort serve both the grouping and the order.
fn summaries(
    conn: &Connection,
    filter: &str,
    group: &str,
    having: &str,
    order: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<(MessageRow, Option<DeliverySummary>)>> {
    let sql = format!(
        "SELECT m.id, m.contact_fp, m.direction, m.body, m.status, m.at, m.message_id, \
         count(d.packet_id), coalesce(sum(d.status = 3), 0), \
         coalesce(sum(d.status IN (1, 3)), 0), coalesce(sum(d.status = 0), 0), \
         min(d.sealed_at), min(d.deposited_at), min(d.acked_at), max(d.expired_at), \
         coalesce(sum(d.status = 0 AND o.deposit_tried_at IS NOT NULL), 0) \
         FROM messages m \
         LEFT JOIN deliveries d ON d.message_id = m.message_id AND d.own = 0 AND m.direction = 0 \
         LEFT JOIN outbox o ON o.packet_id = d.packet_id \
         WHERE {filter} GROUP BY {group} {having} ORDER BY {order}"
    );
    let mut stmt = conn.prepare_cached(&sql).map_err(map_err)?;
    type Agg = (
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        i64,
    );
    let raws = stmt
        .query_map(args, |r| {
            Ok((
                message_raw(r)?,
                (
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                ),
            ))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<(MessageRaw, Agg)>>>()
        .map_err(map_err)?;
    let count = |n: i64| u32::try_from(n).unwrap_or(u32::MAX);
    raws.into_iter()
        .map(|(raw, agg)| {
            let message = message_from_raw(raw)?;
            let (devices, received, left, pending, sealed, deposited, acked, expired, tried) = agg;
            let summary = (devices > 0).then(|| DeliverySummary {
                state: message.status,
                sealed_at: sealed.map_or(0, to_u64),
                deposited_at: deposited.map(to_u64),
                received_at: acked.map(to_u64),
                expired_at: expired
                    .filter(|_| message.status == MessageStatus::NotDelivered)
                    .map(to_u64),
                devices: count(devices),
                devices_received: count(received),
                devices_left: count(left),
                devices_tried: count(tried),
                devices_pending: count(pending),
            });
            Ok((message, summary))
        })
        .collect()
}

fn message_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRaw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn message_from_raw((id, fp, dir, body, st, at, mid): MessageRaw) -> Result<MessageRow> {
    Ok(MessageRow {
        id,
        contact_fp: Fingerprint(arr(fp)?),
        direction: Direction::from_i64(dir)?,
        body,
        status: MessageStatus::from_i64(st)?,
        at: to_u64(at),
        message_id: MessageId(arr(mid)?),
    })
}

type ContactRaw = (Vec<u8>, Vec<u8>, String, bool);

fn contact_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRaw> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn contact_from_raw((fp, card, alias, verified): ContactRaw) -> Result<ContactRow> {
    Ok(ContactRow {
        fp: Fingerprint(arr(fp)?),
        card,
        alias,
        verified,
    })
}

fn query_sessions(
    conn: &Connection,
    tail: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<SessionRow>> {
    let sql = format!(
        "SELECT contact_device, contact_fp, session_id, state, mailbox_secret, ad, \
         pending_initial, last_rx, created_at FROM sessions {tail}"
    );
    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let raws = stmt
        .query_map(p, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;
    raws.into_iter()
        .map(|(dev, fp, sid, state, ms, ad, pi, rx, cr)| {
            Ok(SessionRow {
                contact_device: DeviceId(arr(dev)?),
                contact_fp: Fingerprint(arr(fp)?),
                session_id: arr(sid)?,
                state,
                mailbox_secret: arr(ms)?,
                ad,
                pending_initial: pi,
                last_rx: to_u64(rx),
                created_at: to_u64(cr),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
