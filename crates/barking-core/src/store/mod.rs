//! Encrypted SQLCipher storage.
//!
//! Shared typed methods: they are defined once in the
//! [`Queries`] trait (default methods on top of a `&Connection`), which
//! [`Store`] (plain call) and [`Tx`] (inside [`Store::transaction`]) implement.
//! The trait must be imported (`use barking_core::store::Queries`).
//! Any `Err` returned by the `transaction` closure rolls back all
//! writes.

mod schema;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStatus {
    Queued = 0,
    Sent = 1,
    Delivered = 3,
    Failed = 5,
}

impl MessageStatus {
    fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Sent),
            3 => Ok(Self::Delivered),
            5 => Ok(Self::Failed),
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

fn map_err(e: rusqlite::Error) -> CoreError {
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
fn arr<const N: usize>(b: Vec<u8>) -> Result<[u8; N]> {
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

fn to_i64(v: u64) -> i64 {
    // Unix seconds fit comfortably in an i64.
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
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
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Transaction handle, passed to the closure of [`Store::transaction`].
pub struct Tx<'a> {
    conn: &'a Connection,
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
        let store = Store { conn };
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
        Ok(())
    }

    /// Runs `f` in a single transaction; `Err` => full rollback.
    pub fn transaction<R>(&mut self, f: impl FnOnce(&Tx) -> Result<R>) -> Result<R> {
        let txn = self.conn.transaction().map_err(map_err)?;
        let out = f(&Tx { conn: &txn });
        match out {
            Ok(v) => {
                txn.commit().map_err(map_err)?;
                Ok(v)
            }
            Err(e) => {
                let _ = txn.rollback();
                Err(e)
            }
        }
    }
}

/// Typed methods, common to [`Store`] and [`Tx`].
pub trait Queries {
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

    /// Inserts a message. `false` if `message_id` already exists (nothing is written).
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
                 status, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
    /// delivery (awaiting acknowledgement) of the message `message_id`. `own`: synchronisation
    /// copy for one of my devices.
    fn add_delivery(
        &self,
        message_id: MessageId,
        packet_id: PacketId,
        device: DeviceId,
        own: bool,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO deliveries(message_id, packet_id, device, status, own) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    message_id.0.as_slice(),
                    packet_id.0.as_slice(),
                    device.0.as_slice(),
                    MessageStatus::Sent as i64,
                    i64::from(own)
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

    /// Marks the delivery `packet_id` as delivered and the message `Delivered` (an
    /// acknowledgement from a single recipient device is enough; that of a copy
    /// for one of my devices, `own`, never counts). Returns the message
    /// concerned, or `None` if no delivery carries this packet.
    fn mark_delivered_by_packet(&self, packet_id: PacketId) -> Result<Option<MessageId>> {
        let row: Option<(Vec<u8>, i64)> = self
            .conn()
            .query_row(
                "SELECT message_id, own FROM deliveries WHERE packet_id = ?1",
                params![packet_id.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_err)?;
        let Some((mid, own)) = row else {
            return Ok(None);
        };
        self.conn()
            .execute(
                "UPDATE deliveries SET status = ?1 WHERE packet_id = ?2",
                params![MessageStatus::Delivered as i64, packet_id.0.as_slice()],
            )
            .map_err(map_err)?;
        if own == 0 {
            self.conn()
                .execute(
                    "UPDATE messages SET status = ?1 WHERE message_id = ?2 AND direction = ?3",
                    params![MessageStatus::Delivered as i64, mid, Direction::Out as i64],
                )
                .map_err(map_err)?;
        }
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
                params![packet_id.0.as_slice(), MessageStatus::Delivered as i64],
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
    fn outbox_put(
        &self,
        packet_id: PacketId,
        bytes: &[u8],
        kind: Kind,
        expires_at: u64,
        now: u64,
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO outbox(packet_id, bytes, kind, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(packet_id) DO NOTHING",
                params![
                    packet_id.0.as_slice(),
                    bytes,
                    kind as i64,
                    to_i64(expires_at),
                    to_i64(now)
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

    /// Deletes expired packets; returns the number of rows deleted.
    fn outbox_purge_expired(&self, now: u64) -> Result<usize> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE expires_at < ?1",
                params![to_i64(now)],
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
    /// queue: my messages for it, my card updates for its devices and my
    /// acknowledgements of its messages (the history is kept). The
    /// `SyncSent` copies of my messages for my other devices stay in the
    /// queue.
    fn delete_contact(&self, fp: Fingerprint) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM outbox WHERE packet_id IN \
                 (SELECT d.packet_id FROM deliveries d \
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
    /// as stored).
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
                 VALUES (?1, ?2, ?3, ?4, ?5)",
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

    /// `true` if `packet_id` carries a message: one of my deliveries or a
    /// received packet recorded in `inbound`.
    fn packet_has_message(&self, packet_id: PacketId) -> Result<bool> {
        let n: i64 = self
            .conn()
            .query_row(
                "SELECT (SELECT count(*) FROM deliveries WHERE packet_id = ?1) \
                 + (SELECT count(*) FROM inbound WHERE packet_id = ?1)",
                params![packet_id.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        Ok(n > 0)
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
}

impl Queries for Tx<'_> {
    fn conn(&self) -> &Connection {
        self.conn
    }
}

type MessageRaw = (i64, Vec<u8>, i64, String, i64, i64, Vec<u8>);

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
