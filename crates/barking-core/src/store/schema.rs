//! SQL storage schema (v2) and migration from v1.

use rusqlite::{Connection, params};

pub const SCHEMA_VERSION: u32 = 2;

/// Schema v1 (batch 1A), kept for the migration and for its tests: a
/// v1 database is opened with this schema, then migrated.
pub const SCHEMA_V1_LEGACY: &str = "
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY NOT NULL,
    v BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    fp BLOB PRIMARY KEY NOT NULL,
    card BLOB NOT NULL,
    alias TEXT NOT NULL,
    verified INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    contact_device BLOB NOT NULL,
    contact_fp BLOB NOT NULL,
    session_id BLOB NOT NULL,
    state BLOB NOT NULL,
    mailbox_secret BLOB NOT NULL,
    ad BLOB NOT NULL,
    pending_initial BLOB,
    last_rx INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (contact_fp, contact_device, session_id)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    contact_fp BLOB NOT NULL,
    direction INTEGER NOT NULL,
    body TEXT NOT NULL,
    status INTEGER NOT NULL,
    at INTEGER NOT NULL,
    packet_id BLOB UNIQUE
);
CREATE TABLE IF NOT EXISTS seen (
    packet_id BLOB PRIMARY KEY NOT NULL,
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    packet_id BLOB PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL,
    kind INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transparency (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    packet_id BLOB,
    event BLOB NOT NULL,
    -- 0: regular, 1: security (see `EventClass`).
    class INTEGER NOT NULL DEFAULT 0
);
";

/// Tables of v2: one message per logical identifier, one delivery per
/// packet (hence per recipient device), and for each received packet the
/// message it carries (`inbound`, found via the acknowledgement I emitted).
///
/// Uniqueness of `messages.message_id`: an outgoing message carries the identifier
/// drawn by one of my devices; a received message, the identifier derived from
/// the sender's fingerprint and the identifier of its envelope
/// (`MessageId::incoming`). A contact can therefore neither hide nor overwrite a
/// message of another contact or one of mine: only a resend of their own
/// messages collides (duplicate).
pub const SCHEMA_V2_TABLES: &str = "
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    message_id BLOB UNIQUE NOT NULL,
    contact_fp BLOB NOT NULL,
    direction INTEGER NOT NULL,
    body TEXT NOT NULL,
    status INTEGER NOT NULL,
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    message_id BLOB NOT NULL,
    packet_id BLOB UNIQUE NOT NULL,
    device BLOB NOT NULL,
    status INTEGER NOT NULL,
    -- 1: synchronisation copy for one of my devices (its acknowledgement
    -- never marks the message as delivered).
    own INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS deliveries_message ON deliveries(message_id);
";

/// Tables of v2 added after the fact: applied on every open
/// (idempotent), because development v2 databases were created before they
/// were added. The v1 → v2 migration creates them too, before filling `inbound`.
///
/// `contact_clock`: for each fingerprint, date (envelope timestamp or
/// local time) of the last operation on this contact, and whether it was a
/// deletion (tombstone), and the device that performed it (tie-breaker at
/// equal date). Last writer wins between my devices.
pub const SCHEMA_V2_INBOUND: &str = "
CREATE TABLE IF NOT EXISTS inbound (
    packet_id BLOB PRIMARY KEY NOT NULL,
    message_id BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS contact_clock (
    fp BLOB PRIMARY KEY NOT NULL,
    at INTEGER NOT NULL,
    removed INTEGER NOT NULL,
    writer BLOB NOT NULL DEFAULT x'00000000000000000000000000000000'
);
";

/// Column `own` of `deliveries`, for a v2 database created before it was added.
pub const DELIVERIES_ADD_OWN: &str =
    "ALTER TABLE deliveries ADD COLUMN own INTEGER NOT NULL DEFAULT 0;";

/// Column `writer` of `contact_clock`, for a v2 database created before it was
/// added (unknown author: null identifier).
pub const CONTACT_CLOCK_ADD_WRITER: &str = "ALTER TABLE contact_clock ADD COLUMN writer BLOB \
     NOT NULL DEFAULT x'00000000000000000000000000000000';";

/// Derivation context of a message identifier from a
/// packet identifier (v1 messages and messages received before batch 1B).
pub const LEGACY_MESSAGE_ID_CONTEXT: &str = "barking/v0/legacy-message-id";

/// Persisted statuses (see `MessageStatus`) used by the migration.
const STATUS_SENT: i64 = 1;
const STATUS_DELIVERED: i64 = 3;
const DIRECTION_OUT: i64 = 0;

/// Migrates a v1 database to v2, in a single transaction: the rows of
/// `messages` receive a `message_id` derived from their `packet_id` (or from
/// their `id` if it is null), outgoing messages having a packet receive
/// the matching delivery, received messages having a packet are
/// recorded in `inbound`, then `schema_version` is set to 2.
pub fn migrate_v1_to_v2(conn: &Connection) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch("ALTER TABLE messages RENAME TO messages_v1;")?;
    tx.execute_batch(SCHEMA_V2_TABLES)?;
    tx.execute_batch(SCHEMA_V2_INBOUND)?;
    {
        let mut old = tx.prepare(
            "SELECT id, contact_fp, direction, body, status, at, packet_id \
             FROM messages_v1 ORDER BY id",
        )?;
        let rows = old
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, fp, dir, body, status, at, packet) in rows {
            let material = packet.clone().unwrap_or_else(|| id.to_le_bytes().to_vec());
            let full = blake3::derive_key(LEGACY_MESSAGE_ID_CONTEXT, &material);
            let mid = &full[..16];
            tx.execute(
                "INSERT INTO messages(id, message_id, contact_fp, direction, body, status, at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, mid, fp, dir, body, status, at],
            )?;
            match (dir, packet) {
                (_, None) => {}
                (DIRECTION_OUT, Some(pid)) => {
                    // The recipient device of a v1 packet is not known.
                    tx.execute(
                        "INSERT INTO deliveries(message_id, packet_id, device, status) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![mid, pid, [0u8; 16].as_slice(), delivery_status(status)],
                    )?;
                }
                (_, Some(pid)) => {
                    tx.execute(
                        "INSERT OR IGNORE INTO inbound(packet_id, message_id) VALUES (?1, ?2)",
                        params![pid, mid],
                    )?;
                }
            }
        }
    }
    tx.execute_batch("DROP TABLE messages_v1;")?;
    let version = postcard::to_allocvec(&SCHEMA_VERSION).unwrap_or_default();
    tx.execute(
        "INSERT INTO meta(k, v) VALUES ('schema_version', ?1) \
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![version],
    )?;
    tx.commit()
}

fn delivery_status(message_status: i64) -> i64 {
    if message_status == STATUS_DELIVERED {
        STATUS_DELIVERED
    } else {
        STATUS_SENT
    }
}

/// Migration within the v1 schema: `class` column of the log, for a database
/// created before it was added. Applied on open if the column is missing.
pub const TRANSPARENCY_ADD_CLASS: &str =
    "ALTER TABLE transparency ADD COLUMN class INTEGER NOT NULL DEFAULT 0;";

/// Log index (after the migration: `class` must exist). The purge
/// reads `max(at)` and the cap walks one class per identifier on each
/// append.
pub const TRANSPARENCY_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS transparency_at ON transparency(at);
CREATE INDEX IF NOT EXISTS transparency_class_id ON transparency(class, id);
";

/// Date of the last verification change of a contact (`SyncOp::UpsertV2`),
/// added to existing databases at open (idempotent); 0: unknown.
pub const CONTACTS_ADD_VERIFIED_AT: &str =
    "ALTER TABLE contacts ADD COLUMN verified_at INTEGER NOT NULL DEFAULT 0;";

/// Route of each packet (spec block 2b §4.1), created at open
/// (idempotent). `step`: `RouteStep` as stored, fixed order, additions at
/// the end. `node`: a node's short identifier, never an address. `size`:
/// packet bytes, for `Sealed`. Never synchronized, purged with the log.
pub const ROUTE_STEPS: &str = "
CREATE TABLE IF NOT EXISTS route_steps (
    packet_id BLOB NOT NULL,
    at INTEGER NOT NULL,
    step INTEGER NOT NULL,
    node TEXT,
    size INTEGER
);
CREATE INDEX IF NOT EXISTS route_steps_packet ON route_steps(packet_id);
CREATE INDEX IF NOT EXISTS route_steps_at ON route_steps(at);
";
