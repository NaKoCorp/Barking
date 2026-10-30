//! Stockage SQLite du nœud (spec §6).
//!
//! Le total d'octets stockés (paquets + accusés, somme des longueurs de
//! `bytes`) est tenu à jour dans `meta('stored_bytes')`, dans les mêmes
//! transactions que les écritures : le quota `storage_max_bytes` se vérifie
//! sans balayer la table.

use std::path::Path;
use std::time::Duration;

use barking_packet::MailboxId;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{Error, Result};

pub const SCHEMA_VERSION: i64 = 3;
/// Schéma précédent, migré au démarrage par `NodeStore::open`.
const PREVIOUS_SCHEMA_VERSION: i64 = 2;
/// Nombre maximal de lignes gardées dans `peers` (spec §7).
pub const MAX_PEER_ROWS: usize = 1024;
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

/// Un pair de la table de routage, tel que gardé dans `peers`. `first_seen`
/// et `last_seen` sont arrondis à l'heure par l'appelant ; `record` est la
/// fiche signée encodée (la seule adresse écrite sur disque est celle que le
/// pair publie lui-même).
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
";

impl NodeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<NodeStore> {
        Self::init(Connection::open(path)?)
    }

    /// Ouverture en lecture seule (`status`) : aucune écriture, ni schéma ni
    /// pragma persistant. La base doit exister et être au bon schéma : une
    /// base en version 2, qu'il faut d'abord migrer, donne `SchemaVersion(2)`.
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

    /// Base en mémoire (tests).
    pub fn open_in_memory() -> Result<NodeStore> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<NodeStore> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // La version est lue AVANT toute écriture (pragmas persistants, schéma) :
        // une base d'un autre schéma est refusée sans être modifiée.
        let migrate = check_version(&conn)?;
        // `journal_mode` renvoie une ligne : on la lit pour ne pas la laisser pendre.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        // Un dépôt confirmé au client survit à une coupure de courant.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.set_prepared_statement_cache_capacity(crate::rules::STATEMENT_CACHE);
        // Création ou migration, en une seule transaction. Les lignes d'une
        // base migrée gardent `pow = 0` ; `SCHEMA` crée `peers` et ne touche
        // pas aux tables existantes. La colonne `pow` est la dernière de
        // `packets`, comme dans une base neuve.
        let alter = if migrate {
            "ALTER TABLE packets ADD COLUMN pow INTEGER NOT NULL DEFAULT 0;"
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

    /// Boîtes qui tiennent au moins un paquet ou un accusé, sans doublon.
    pub fn held_mailboxes(&self) -> Result<Vec<MailboxId>> {
        let mut st = self
            .conn
            .prepare_cached("SELECT mailbox FROM packets UNION SELECT mailbox FROM acks")?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            // Une boîte de longueur inattendue (base abîmée) est ignorée.
            if let Ok(id) = <[u8; 16]>::try_from(row?.as_slice()) {
                out.push(MailboxId(id));
            }
        }
        Ok(out)
    }

    /// Enregistre le volume recopié dans la fenêtre horaire commencée à
    /// `window_start` (lu par `status`).
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

    /// Fenêtre horaire et volume recopié enregistrés, `(0, 0)` si aucun.
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

    /// Remplace tout le contenu de `peers` par `rows` (au plus `MAX_PEER_ROWS`
    /// lignes, les premières : l'appelant met les nœuds actifs d'abord).
    pub fn save_peers(&mut self, rows: &[PeerRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
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

    /// Pairs enregistrés, les plus récemment vus d'abord.
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
/// `SCHEMA_VERSION`, ou la version précédente (renvoie alors `true` : il
/// faut migrer). Base avec d'autres tables mais sans `meta` : refusée.
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

    /// Schéma 2 tel qu'il était avant la migration.
    const SCHEMA_V2: &str = "
        CREATE TABLE packets(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id BLOB NOT NULL, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
            tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            received_at INTEGER NOT NULL, hash BLOB NOT NULL, bytes BLOB NOT NULL,
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
        CREATE TABLE meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
        INSERT INTO meta VALUES('schema_version', 2), ('stored_bytes', 0);";

    const T0: u64 = 1_800_000_000;

    fn v2_packet() -> barking_packet::Packet {
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

    /// (colonnes de `packets`, définition des index) : la forme du schéma.
    fn shape(s: &NodeStore) -> (Vec<String>, Vec<(String, String)>) {
        let cols = s
            .conn()
            .prepare("SELECT name || ' ' || type || ' ' || \"notnull\" || ' ' || COALESCE(dflt_value,'') FROM pragma_table_info('packets')")
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
    fn migrates_v2_keeps_packets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v2.db");
        let p = v2_packet();
        let bytes = p.encode();
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA_V2).unwrap();
            c.execute(
                "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes) VALUES(?1,?2,0,0,?3,0,?4,?5)",
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
        }
        // `status` refuse la version 2 sans la modifier.
        assert!(matches!(
            NodeStore::open_read_only(&path),
            Err(Error::SchemaVersion(2))
        ));
        let s = NodeStore::open(&path).unwrap();
        let version: i64 = s
            .conn()
            .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 3);
        let (page, _) = crate::rules::fetch(&s, &[p.mailbox], None, 1 << 20)
            .unwrap()
            .unwrap();
        assert_eq!(page, vec![bytes.clone()]);
        let items = crate::rules::copy_items(&s, &p.mailbox, T0)
            .unwrap()
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].pow, 0);
        assert!(s.load_peers().unwrap().is_empty());
        assert_eq!(s.stats().unwrap().bytes, bytes.len() as u64);
        // Même forme qu'une base neuve (colonnes et index).
        assert_eq!(shape(&s), shape(&NodeStore::open_in_memory().unwrap()));
        // Réouverture : sans effet, et `status` accepte la base.
        drop(s);
        drop(NodeStore::open(&path).unwrap());
        assert!(NodeStore::open_read_only(&path).is_ok());
    }

    #[test]
    fn unknown_schema_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v4.db");
        {
            let s = NodeStore::open(&path).unwrap();
            s.conn()
                .execute("UPDATE meta SET v=4 WHERE k='schema_version'", [])
                .unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            NodeStore::open(&path),
            Err(Error::SchemaVersion(4))
        ));
        assert!(matches!(
            NodeStore::open_read_only(&path),
            Err(Error::SchemaVersion(4))
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
        // Deux paquets dans la boîte 9, un dans la boîte 3.
        for (n, mb) in [(1u8, 9u8), (2, 9), (3, 3)] {
            let mut p = v2_packet();
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
        // Une boîte qui ne tient qu'un accusé compte aussi.
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
    fn peers_roundtrip_and_cap() {
        let mut s = NodeStore::open_in_memory().unwrap();
        assert!(s.load_peers().unwrap().is_empty());
        s.save_peers(&[peer(1), peer(2)]).unwrap();
        let mut got = s.load_peers().unwrap();
        got.sort_by_key(|r| r.node_id);
        assert_eq!(got, vec![peer(1), peer(2)]);
        // `save_peers` remplace tout, et plafonne à 1 024 lignes.
        let rows: Vec<PeerRow> = (10..1_110).map(peer).collect();
        assert_eq!(rows.len(), 1_100);
        s.save_peers(&rows).unwrap();
        let got = s.load_peers().unwrap();
        assert_eq!(got.len(), 1_024);
        assert!(!got.contains(&peer(1)));
        // Les lignes gardées sont les premières données.
        assert!(got.contains(&peer(10)));
        assert!(!got.contains(&peer(1_109)));
    }
}
