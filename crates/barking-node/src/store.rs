//! SQLite storage of the node (spec §6).
//!
//! The total of stored bytes (packets + acks, sum of the lengths of
//! `bytes`) is kept up to date in `meta('stored_bytes')`, in the same
//! transactions as the writes: the `storage_max_bytes` quota is checked
//! without scanning the table.

use std::path::{Path, PathBuf};
use std::time::Duration;

use barking_packet::{ACK_GRACE_SECS, MailboxId};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{Error, Result};

pub const SCHEMA_VERSION: i64 = 4;
/// Previous schema, migrated at startup by `NodeStore::open`.
const PREVIOUS_SCHEMA_VERSION: i64 = 3;
/// Maximum number of rows kept in `peers` (spec §7).
pub const MAX_PEER_ROWS: usize = 1024;
/// Wait for a lock held by another process (`status` during `run`).
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Rows deleted per table and per purge batch: one batch holds the writer
/// briefly, deposits run between two batches.
pub const PURGE_BATCH: usize = 2_000;
/// Page cache of the write connection (negative: KiB), 64 MiB.
const WRITER_CACHE_KIB: i64 = -65_536;
/// Read connections of a running node, beside the writer.
pub const READERS: usize = 4;
/// Page cache of each read connection (negative: KiB), 16 MiB.
const READER_CACHE_KIB: i64 = -16_384;
/// Memory-mapped reads: the system page cache, not process memory.
const MMAP_BYTES: i64 = 256 << 20;
/// Size the WAL file is brought back to after a checkpoint.
const JOURNAL_SIZE_LIMIT: i64 = 64 << 20;

/// Node counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub acks: u64,
    pub bytes: u64,
}

pub struct NodeStore {
    conn: Connection,
}

/// A peer of the routing table, as kept in `peers`. `first_seen` and
/// `last_seen` are rounded to the hour by the caller; `record` is the
/// encoded signed record (the only address written to disk is the one the
/// peer publishes itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub node_id: [u8; 32],
    pub record: Vec<u8>,
    pub first_seen: u64,
    pub last_seen: u64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS packets(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
    tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL, hash BLOB NOT NULL, bytes BLOB NOT NULL,
    pow INTEGER NOT NULL DEFAULT 0,
    UNIQUE(id, hash));
CREATE INDEX IF NOT EXISTS packets_mailbox ON packets(mailbox);
CREATE INDEX IF NOT EXISTS packets_expires ON packets(expires_at);
CREATE TABLE IF NOT EXISTS acks(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id BLOB NOT NULL, mailbox BLOB NOT NULL,
    expires_at INTEGER NOT NULL, bytes BLOB NOT NULL,
    UNIQUE(packet_id, mailbox));
CREATE INDEX IF NOT EXISTS acks_packet ON acks(packet_id);
CREATE INDEX IF NOT EXISTS acks_mailbox ON acks(mailbox);
CREATE INDEX IF NOT EXISTS acks_expires ON acks(expires_at);
CREATE TABLE IF NOT EXISTS peers(
    node_id BLOB PRIMARY KEY, record BLOB NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(
    mailbox BLOB NOT NULL, relay BLOB NOT NULL, sealed BLOB NOT NULL,
    cancel_hash BLOB NOT NULL, expires_day INTEGER NOT NULL,
    last_wake INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0,
    kind INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mailbox, cancel_hash));
CREATE INDEX IF NOT EXISTS subscriptions_mailbox ON subscriptions(mailbox);
CREATE INDEX IF NOT EXISTS subscriptions_pending ON subscriptions(pending, last_wake);
";

impl NodeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<NodeStore> {
        Self::init(Connection::open(path)?)
    }

    /// Read-only opening (`status`): no write, neither schema nor persistent
    /// pragma. The database must exist and have the right schema: a
    /// version 3 database, which must be migrated first, yields
    /// `SchemaVersion(3)`.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<NodeStore> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        if check_version(&conn)? {
            return Err(Error::SchemaVersion(PREVIOUS_SCHEMA_VERSION));
        }
        let has_meta: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |r| r.get(0),
        )?;
        if !has_meta {
            return Err(Error::SchemaVersion(0));
        }
        Ok(NodeStore { conn })
    }

    /// Read connection of a running node (`READERS` of them, beside the
    /// writer): the database must exist; neither schema nor migration, and
    /// `query_only` refuses any write.
    pub fn open_reader(path: impl AsRef<Path>) -> Result<NodeStore> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "query_only", "ON")?;
        conn.pragma_update(None, "cache_size", READER_CACHE_KIB)?;
        conn.pragma_update(None, "mmap_size", MMAP_BYTES)?;
        conn.set_prepared_statement_cache_capacity(crate::rules::STATEMENT_CACHE);
        Ok(NodeStore { conn })
    }

    /// File of the database; `None` in memory.
    pub fn file_path(&self) -> Option<PathBuf> {
        self.conn
            .path()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
    }

    /// In-memory database (tests).
    pub fn open_in_memory() -> Result<NodeStore> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<NodeStore> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // The version is read BEFORE any write (persistent pragmas, schema):
        // a database of another schema is refused without being modified.
        let migrate = check_version(&conn)?;
        // `journal_mode` returns a row: we read it so as not to leave it dangling.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        // A deposit confirmed to the client survives a power cut.
        conn.pragma_update(None, "synchronous", "FULL")?;
        // Cache sized for databases of several GiB; the WAL file is
        // truncated back to this size after a checkpoint.
        conn.pragma_update(None, "cache_size", WRITER_CACHE_KIB)?;
        conn.pragma_update(None, "mmap_size", MMAP_BYTES)?;
        conn.pragma_update(None, "journal_size_limit", JOURNAL_SIZE_LIMIT)?;
        conn.set_prepared_statement_cache_capacity(crate::rules::STATEMENT_CACHE);
        // Creation or migration, in a single transaction. The rows of a
        // migrated database keep their subscriptions as message subscriptions
        // (`kind = 0`); `SCHEMA` does not touch existing tables. The `kind`
        // column is the last one of `subscriptions`, as in a fresh database.
        let alter = if migrate {
            "ALTER TABLE subscriptions ADD COLUMN kind INTEGER NOT NULL DEFAULT 0;"
        } else {
            ""
        };
        conn.execute_batch(&format!(
            "BEGIN; {alter} {SCHEMA}
             INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version', {SCHEMA_VERSION}), ('stored_bytes', 0);
             UPDATE meta SET v={SCHEMA_VERSION} WHERE k='schema_version';
             COMMIT;"
        ))?;
        Ok(NodeStore { conn })
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn stats(&self) -> Result<Stats> {
        let count = |t: &str| -> Result<u64> {
            let n: i64 = self
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        };
        Ok(Stats {
            packets: count("packets")?,
            acks: count("acks")?,
            bytes: stored_bytes(&self.conn)?,
        })
    }

    /// Mailboxes holding at least one packet or ack, without duplicates.
    pub fn held_mailboxes(&self) -> Result<Vec<MailboxId>> {
        let mut st = self
            .conn
            .prepare_cached("SELECT mailbox FROM packets UNION SELECT mailbox FROM acks")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            // A mailbox of unexpected length (damaged database) is ignored.
            if let Ok(id) = <[u8; 16]>::try_from(row?.as_slice()) {
                out.push(MailboxId(id));
            }
        }
        Ok(out)
    }

    /// Records the replicated volume in the hourly window started at
    /// `window_start` (read by `status`).
    pub fn set_replicated(&mut self, window_start: u64, bytes: u64) -> Result<()> {
        let mut st = self
            .conn
            .prepare_cached("INSERT OR REPLACE INTO meta(k,v) VALUES(?1,?2)")?;
        st.execute(params![
            "replicated_window",
            i64::try_from(window_start).unwrap_or(i64::MAX)
        ])?;
        st.execute(params![
            "replicated_bytes",
            i64::try_from(bytes).unwrap_or(i64::MAX)
        ])?;
        Ok(())
    }

    /// Recorded hourly window and replicated volume, `(0, 0)` if none.
    pub fn replicated(&self) -> Result<(u64, u64)> {
        let get = |k: &str| -> Result<u64> {
            let v: Option<i64> = self
                .conn
                .query_row("SELECT v FROM meta WHERE k=?1", params![k], |r| r.get(0))
                .optional()?;
            Ok(v.map_or(0, |v| u64::try_from(v).unwrap_or(0)))
        };
        Ok((get("replicated_window")?, get("replicated_bytes")?))
    }

    /// Replaces the whole content of `peers` with `rows` (at most
    /// `MAX_PEER_ROWS` rows, the first ones: the caller puts active nodes
    /// first).
    pub fn save_peers(&mut self, rows: &[PeerRow]) -> Result<()> {
        let tx = self.conn.savepoint()?;
        tx.execute("DELETE FROM peers", [])?;
        {
            let mut st = tx.prepare_cached(
                "INSERT OR REPLACE INTO peers(node_id,record,first_seen,last_seen) VALUES(?1,?2,?3,?4)",
            )?;
            for r in rows.iter().take(MAX_PEER_ROWS) {
                st.execute(params![
                    &r.node_id[..],
                    &r.record[..],
                    i64::try_from(r.first_seen).unwrap_or(i64::MAX),
                    i64::try_from(r.last_seen).unwrap_or(i64::MAX)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Recorded peers, most recently seen first.
    pub fn load_peers(&self) -> Result<Vec<PeerRow>> {
        let mut st = self.conn.prepare_cached(
            "SELECT node_id,record,first_seen,last_seen FROM peers ORDER BY last_seen DESC, node_id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, record, first, last) = row?;
            let Ok(node_id) = <[u8; 32]>::try_from(id.as_slice()) else {
                continue;
            };
            out.push(PeerRow {
                node_id,
                record,
                first_seen: u64::try_from(first).unwrap_or(0),
                last_seen: u64::try_from(last).unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Deletes all expired packets (`expires_at <= now`), acks
    /// (`expires_at + ACK_GRACE_SECS <= now`) and subscriptions, batch after
    /// batch. Returns the number of deleted rows.
    pub fn purge_expired(&mut self, now: u64) -> Result<usize> {
        let mut removed = 0;
        loop {
            let (n, more, _) = self.purge_expired_batch(now, PURGE_BATCH)?;
            removed += n;
            if !more {
                return Ok(removed);
            }
        }
    }

    /// Deletes at most `limit` expired packets, `limit` acks and `limit`
    /// subscriptions, oldest expiry first. Returns the number of deleted rows,
    /// whether expired rows may remain (a table reached `limit`), and whether
    /// a subscription was marked pending. An expired packet is an unacked
    /// message (an ack deletes its message): its mailbox's `Acks`
    /// subscriptions are marked, in the same savepoint.
    pub fn purge_expired_batch(&mut self, now: u64, limit: usize) -> Result<(usize, bool, bool)> {
        let today = i64::from(crate::wake::day_of(now));
        let now_sql = i64::try_from(now).unwrap_or(i64::MAX);
        let limit_sql = i64::try_from(limit).unwrap_or(i64::MAX);
        let tx = self.conn.savepoint()?;
        let mut freed: i64 = 0;
        let mut removed = 0;
        let mut more = false;
        let mut expired_boxes: Vec<MailboxId> = Vec::new();
        {
            let mut st = tx.prepare_cached(
                "DELETE FROM packets WHERE seq IN (SELECT seq FROM packets \
                 WHERE expires_at <= ?1 ORDER BY expires_at, seq LIMIT ?2) \
                 RETURNING mailbox, kind, length(bytes)",
            )?;
            let rows = st.query_map(params![now_sql, limit_sql], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            let mut n = 0;
            for row in rows {
                let (mailbox, kind, len) = row?;
                freed += len;
                n += 1;
                if kind == i64::from(barking_packet::Kind::Message as u8)
                    && let Ok(id) = <[u8; 16]>::try_from(&mailbox[..])
                {
                    let id = MailboxId(id);
                    if !expired_boxes.contains(&id) {
                        expired_boxes.push(id);
                    }
                }
            }
            removed += n;
            more |= n >= limit;
        }
        {
            // An ack stays `ACK_GRACE_SECS` past its stored expiry (the
            // later of its own and its message's): a sender that missed the
            // receipt wake-up still finds it a day later.
            let ack_cut = i64::try_from(now.saturating_sub(ACK_GRACE_SECS)).unwrap_or(i64::MAX);
            let mut st = tx.prepare_cached(
                "DELETE FROM acks WHERE seq IN (SELECT seq FROM acks \
                 WHERE expires_at <= ?1 ORDER BY expires_at, seq LIMIT ?2) \
                 RETURNING length(bytes)",
            )?;
            let lens = st.query_map(params![ack_cut, limit_sql], |r| r.get::<_, i64>(0))?;
            let mut n = 0;
            for len in lens {
                freed += len?;
                n += 1;
            }
            removed += n;
            more |= n >= limit;
        }
        add_stored_bytes(&tx, -freed)?;
        let marked = crate::wake::mark_expired(&tx, &expired_boxes, now)?;
        let subs = tx.execute(
            "DELETE FROM subscriptions WHERE rowid IN (SELECT rowid FROM subscriptions \
             WHERE expires_day < ?1 LIMIT ?2)",
            params![today, limit_sql],
        )?;
        removed += subs;
        more |= subs >= limit;
        tx.commit()?;
        Ok((removed, more, marked))
    }
}

/// Empty database: accepted. Database with `meta`: `schema_version` must be
/// `SCHEMA_VERSION`, or the previous version (then returns `true`: it must
/// be migrated). Database with other tables but without `meta`: refused.
fn check_version(conn: &Connection) -> Result<bool> {
    let table_exists = |name: &str| -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            params![name],
            |r| r.get(0),
        )?)
    };
    if table_exists("meta")? {
        let version: Option<i64> = conn
            .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
                r.get(0)
            })
            .optional()?;
        return match version {
            Some(SCHEMA_VERSION) => Ok(false),
            Some(PREVIOUS_SCHEMA_VERSION) => Ok(true),
            other => Err(Error::SchemaVersion(other.unwrap_or(0))),
        };
    }
    let any_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')",
        [],
        |r| r.get(0),
    )?;
    if any_table {
        return Err(Error::SchemaVersion(0));
    }
    Ok(false)
}

pub(crate) fn stored_bytes(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row("SELECT v FROM meta WHERE k='stored_bytes'", [], |r| {
        r.get(0)
    })?;
    Ok(u64::try_from(n).unwrap_or(0))
}

pub(crate) fn add_stored_bytes(conn: &Connection, delta: i64) -> Result<()> {
    conn.execute(
        "UPDATE meta SET v = MAX(v + ?1, 0) WHERE k='stored_bytes'",
        params![delta],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_open_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.db");
        // Missing database: refused, nothing is created.
        assert!(NodeStore::open_read_only(&path).is_err());
        assert!(!path.exists());
        drop(NodeStore::open(&path).unwrap());
        let before = std::fs::read(&path).unwrap();
        let ro = NodeStore::open_read_only(&path).unwrap();
        assert_eq!(ro.stats().unwrap().packets, 0);
        // A write is refused by SQLite.
        assert!(ro.conn().execute("DELETE FROM packets", []).is_err());
        drop(ro);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn pragmas_and_cache() {
        let s = NodeStore::open_in_memory().unwrap();
        let sync: i64 = s
            .conn()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous=FULL");
        let busy: i64 = s
            .conn()
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, 5_000);
    }

    /// Schema 3 as it was before the migration.
    const SCHEMA_V3: &str = "
        CREATE TABLE packets(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id BLOB NOT NULL, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
            tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            received_at INTEGER NOT NULL, hash BLOB NOT NULL, bytes BLOB NOT NULL,
            pow INTEGER NOT NULL DEFAULT 0,
            UNIQUE(id, hash));
        CREATE INDEX packets_mailbox ON packets(mailbox);
        CREATE INDEX packets_expires ON packets(expires_at);
        CREATE TABLE acks(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id BLOB NOT NULL, mailbox BLOB NOT NULL,
            expires_at INTEGER NOT NULL, bytes BLOB NOT NULL,
            UNIQUE(packet_id, mailbox));
        CREATE INDEX acks_packet ON acks(packet_id);
        CREATE INDEX acks_mailbox ON acks(mailbox);
        CREATE INDEX acks_expires ON acks(expires_at);
        CREATE TABLE peers(
            node_id BLOB PRIMARY KEY, record BLOB NOT NULL,
            first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
        CREATE TABLE meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
        CREATE TABLE subscriptions(
            mailbox BLOB NOT NULL, relay BLOB NOT NULL, sealed BLOB NOT NULL,
            cancel_hash BLOB NOT NULL, expires_day INTEGER NOT NULL,
            last_wake INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0,
            UNIQUE(mailbox, cancel_hash));
        CREATE INDEX subscriptions_mailbox ON subscriptions(mailbox);
        CREATE INDEX subscriptions_pending ON subscriptions(pending, last_wake);
        INSERT INTO meta VALUES('schema_version', 3), ('stored_bytes', 0);";

    const T0: u64 = 1_800_000_000;

    fn v3_packet() -> barking_packet::Packet {
        use barking_packet::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier};
        Packet {
            kind: Kind::Message,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId([5; 16]),
            expires_at: u32::try_from(T0 + 86_400).unwrap(),
            mailbox: MailboxId([9; 16]),
            payload: vec![1; 8],
        }
    }

    /// (columns of `packets` and `subscriptions`, index definitions): the shape of the schema.
    fn shape(s: &NodeStore) -> (Vec<String>, Vec<(String, String)>) {
        let cols = s
            .conn()
            .prepare("SELECT 'packets.' || name || ' ' || type || ' ' || \"notnull\" || ' ' || COALESCE(dflt_value,'') FROM pragma_table_info('packets') UNION ALL SELECT 'subscriptions.' || name || ' ' || type || ' ' || \"notnull\" || ' ' || COALESCE(dflt_value,'') FROM pragma_table_info('subscriptions')")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<core::result::Result<_, _>>()
            .unwrap();
        let idx = s
            .conn()
            .prepare("SELECT name, COALESCE(sql,'') FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<core::result::Result<_, _>>()
            .unwrap();
        (cols, idx)
    }

    #[test]
    fn replicated_window_round_trips() {
        let mut s = NodeStore::open_in_memory().unwrap();
        assert_eq!(s.replicated().unwrap(), (0, 0));
        s.set_replicated(7200, 1234).unwrap();
        s.set_replicated(10_800, 99).unwrap();
        assert_eq!(s.replicated().unwrap(), (10_800, 99));
    }

    #[test]
    fn migrates_v3_keeps_subscriptions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v3.db");
        let p = v3_packet();
        let bytes = p.encode();
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA_V3).unwrap();
            c.execute(
                "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes,pow) VALUES(?1,?2,0,0,?3,0,?4,?5,7)",
                params![
                    &p.id.0[..],
                    &p.mailbox.0[..],
                    i64::from(p.expires_at),
                    &barking_proto::pow::content_hash(&bytes)[..],
                    &bytes[..]
                ],
            )
            .unwrap();
            c.execute(
                "UPDATE meta SET v=? WHERE k='stored_bytes'",
                params![bytes.len() as i64],
            )
            .unwrap();
            c.execute(
                "INSERT INTO subscriptions(mailbox,relay,sealed,cancel_hash,expires_day,last_wake,pending) VALUES(?1,x'01',x'02',x'03',99999,5,1)",
                params![&p.mailbox.0[..]],
            )
            .unwrap();
        }
        // `status` refuses version 3 without modifying it.
        assert!(matches!(
            NodeStore::open_read_only(&path),
            Err(Error::SchemaVersion(3))
        ));
        let s = NodeStore::open(&path).unwrap();
        let version: i64 = s
            .conn()
            .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 4);
        // The subscription is kept as a message subscription, state included.
        let sub: (i64, i64, i64) = s
            .conn()
            .query_row(
                "SELECT kind, last_wake, pending FROM subscriptions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(sub, (0, 5, 1));
        let (page, _) = crate::rules::fetch(&s, &[p.mailbox], None, 1 << 20)
            .unwrap()
            .unwrap();
        assert_eq!(page, vec![bytes.clone()]);
        let items = crate::rules::copy_items(&s, &p.mailbox, T0)
            .unwrap()
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].pow, 7);
        assert_eq!(s.stats().unwrap().bytes, bytes.len() as u64);
        // Same shape as a fresh database (columns and indexes).
        assert_eq!(shape(&s), shape(&NodeStore::open_in_memory().unwrap()));
        // Reopening: no effect, and `status` accepts the database.
        drop(s);
        drop(NodeStore::open(&path).unwrap());
        assert!(NodeStore::open_read_only(&path).is_ok());
    }

    #[test]
    fn unknown_schema_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.db");
        {
            let s = NodeStore::open(&path).unwrap();
            s.conn()
                .execute("UPDATE meta SET v=5 WHERE k='schema_version'", [])
                .unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            NodeStore::open(&path),
            Err(Error::SchemaVersion(5))
        ));
        assert!(matches!(
            NodeStore::open_read_only(&path),
            Err(Error::SchemaVersion(5))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn held_mailboxes_unique() {
        use crate::rules::{Policy, deposit};
        let mut s = NodeStore::open_in_memory().unwrap();
        assert!(s.held_mailboxes().unwrap().is_empty());
        let pol = Policy {
            pow_bits: 0,
            ..Policy::default()
        };
        // Two packets in mailbox 9, one in mailbox 3.
        for (n, mb) in [(1u8, 9u8), (2, 9), (3, 3)] {
            let mut p = v3_packet();
            p.id = barking_packet::PacketId([n; 16]);
            p.mailbox = MailboxId([mb; 16]);
            let nonce = barking_proto::pow::solve(
                &barking_proto::pow::content_hash(&p.encode()),
                &p.mailbox,
                0,
            )
            .unwrap();
            assert_eq!(
                deposit(&mut s, &pol, &p.encode(), nonce, T0).unwrap(),
                Ok(())
            );
        }
        // A mailbox holding only an ack counts too.
        s.conn()
            .execute(
                "INSERT INTO acks(packet_id,mailbox,expires_at,bytes) VALUES(?1,?2,?3,?4)",
                params![&[7u8; 16][..], &[9u8; 16][..], 1, &[0u8][..]],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO acks(packet_id,mailbox,expires_at,bytes) VALUES(?1,?2,?3,?4)",
                params![&[8u8; 16][..], &[5u8; 16][..], 1, &[0u8][..]],
            )
            .unwrap();
        let mut got: Vec<[u8; 16]> = s.held_mailboxes().unwrap().iter().map(|m| m.0).collect();
        got.sort_unstable();
        assert_eq!(got, vec![[3; 16], [5; 16], [9; 16]]);
    }

    fn peer(n: u16) -> PeerRow {
        let mut id = [0u8; 32];
        id[..2].copy_from_slice(&n.to_be_bytes());
        PeerRow {
            node_id: id,
            record: vec![1, 2, 3, (n % 256) as u8],
            first_seen: 3_600 * u64::from(n),
            last_seen: 3_600 * u64::from(n) + 7_200,
        }
    }

    #[test]
    fn reader_refuses_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.db");
        let s = NodeStore::open(&path).unwrap();
        // SQLite gives the canonical path.
        assert_eq!(
            s.file_path().map(|p| p.canonicalize().unwrap()),
            Some(path.canonicalize().unwrap())
        );
        assert_eq!(NodeStore::open_in_memory().unwrap().file_path(), None);
        let r = NodeStore::open_reader(&path).unwrap();
        assert_eq!(r.stats().unwrap().packets, 0);
        assert!(
            r.conn()
                .execute("INSERT INTO meta(k,v) VALUES('x', 0)", [])
                .is_err()
        );
        // A reader never creates a database.
        assert!(NodeStore::open_reader(dir.path().join("missing.db")).is_err());
    }

    #[test]
    fn peers_roundtrip_and_cap() {
        let mut s = NodeStore::open_in_memory().unwrap();
        assert!(s.load_peers().unwrap().is_empty());
        s.save_peers(&[peer(1), peer(2)]).unwrap();
        let mut got = s.load_peers().unwrap();
        got.sort_by_key(|r| r.node_id);
        assert_eq!(got, vec![peer(1), peer(2)]);
        // `save_peers` replaces everything, and caps at 1,024 rows.
        let rows: Vec<PeerRow> = (10..1_110).map(peer).collect();
        assert_eq!(rows.len(), 1_100);
        s.save_peers(&rows).unwrap();
        let got = s.load_peers().unwrap();
        assert_eq!(got.len(), 1_024);
        assert!(!got.contains(&peer(1)));
        // The rows kept are the first ones given.
        assert!(got.contains(&peer(10)));
        assert!(!got.contains(&peer(1_109)));
    }
}
