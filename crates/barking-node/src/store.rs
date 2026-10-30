//! Stockage SQLite du nœud (spec §6).
//!
//! Le total d'octets stockés (paquets + accusés, somme des longueurs de
//! `bytes`) est tenu à jour dans `meta('stored_bytes')`, dans les mêmes
//! transactions que les écritures : le quota `storage_max_bytes` se vérifie
//! sans balayer la table.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Error, Result};

pub const SCHEMA_VERSION: i64 = 1;

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
    id BLOB PRIMARY KEY, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
    tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL, bytes BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS packets_mailbox ON packets(mailbox);
CREATE INDEX IF NOT EXISTS packets_expires ON packets(expires_at);
CREATE TABLE IF NOT EXISTS acks(
    packet_id BLOB PRIMARY KEY, mailbox BLOB NOT NULL,
    expires_at INTEGER NOT NULL, bytes BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS acks_mailbox ON acks(mailbox);
CREATE INDEX IF NOT EXISTS acks_expires ON acks(expires_at);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
";

impl NodeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<NodeStore> {
        Self::init(Connection::open(path)?)
    }

    /// Base en mémoire (tests).
    pub fn open_in_memory() -> Result<NodeStore> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<NodeStore> {
        // `journal_mode` renvoie une ligne : on la lit pour ne pas la laisser pendre.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        let version: Option<i64> = conn
            .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
                r.get(0)
            })
            .optional()?;
        match version {
            None => {
                conn.execute(
                    "INSERT INTO meta(k,v) VALUES('schema_version', ?1), ('stored_bytes', 0)",
                    params![SCHEMA_VERSION],
                )?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => return Err(Error::SchemaVersion(other)),
        }
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
