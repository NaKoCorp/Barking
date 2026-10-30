//! Stockage SQLite du nœud (spec §6).
//!
//! Le total d'octets stockés (paquets + accusés, somme des longueurs de
//! `bytes`) est tenu à jour dans `meta('stored_bytes')`, dans les mêmes
//! transactions que les écritures : le quota `storage_max_bytes` se vérifie
//! sans balayer la table.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{Error, Result};

pub const SCHEMA_VERSION: i64 = 2;
/// Attente d'un verrou tenu par un autre processus (`status` pendant `run`).
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Compteurs du nœud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub acks: u64,
    pub bytes: u64,
}

pub struct NodeStore {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS packets(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
    tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL, hash BLOB NOT NULL, bytes BLOB NOT NULL,
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
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
";

impl NodeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<NodeStore> {
        Self::init(Connection::open(path)?)
    }

    /// Ouverture en lecture seule (`status`) : aucune écriture, ni schéma ni
    /// pragma persistant. La base doit exister et être au bon schéma.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<NodeStore> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        check_version(&conn)?;
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

    /// Base en mémoire (tests).
    pub fn open_in_memory() -> Result<NodeStore> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<NodeStore> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // La version est lue AVANT toute écriture (pragmas persistants, schéma) :
        // une base d'un autre schéma est refusée sans être modifiée.
        check_version(&conn)?;
        // `journal_mode` renvoie une ligne : on la lit pour ne pas la laisser pendre.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        // Un dépôt confirmé au client survit à une coupure de courant.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.set_prepared_statement_cache_capacity(crate::rules::STATEMENT_CACHE);
        conn.execute_batch(&format!(
            "BEGIN; {SCHEMA}
             INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version', {SCHEMA_VERSION}), ('stored_bytes', 0);
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

    /// Supprime paquets et accusés expirés (`expires_at <= now`). Renvoie le
    /// nombre de lignes supprimées.
    pub fn purge_expired(&mut self, now: u64) -> Result<usize> {
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        let tx = self.conn.transaction()?;
        let mut freed: i64 = 0;
        let mut removed = 0;
        for (table, wh) in [("packets", "expires_at"), ("acks", "expires_at")] {
            let sum: i64 = tx.query_row(
                &format!("SELECT COALESCE(SUM(length(bytes)),0) FROM {table} WHERE {wh} <= ?1"),
                params![now],
                |r| r.get(0),
            )?;
            freed += sum;
            removed += tx.execute(
                &format!("DELETE FROM {table} WHERE {wh} <= ?1"),
                params![now],
            )?;
        }
        add_stored_bytes(&tx, -freed)?;
        tx.commit()?;
        Ok(removed)
    }
}

/// Base vide : acceptée. Base avec `meta` : `schema_version` doit valoir
/// `SCHEMA_VERSION`. Base avec d'autres tables mais sans `meta` : refusée.
fn check_version(conn: &Connection) -> Result<()> {
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
            Some(SCHEMA_VERSION) => Ok(()),
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
    Ok(())
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
        // Base absente : refus, rien n'est créé.
        assert!(NodeStore::open_read_only(&path).is_err());
        assert!(!path.exists());
        drop(NodeStore::open(&path).unwrap());
        let before = std::fs::read(&path).unwrap();
        let ro = NodeStore::open_read_only(&path).unwrap();
        assert_eq!(ro.stats().unwrap().packets, 0);
        // Une écriture est refusée par SQLite.
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
}
