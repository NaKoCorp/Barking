//! Schéma SQL du stockage (v2) et migration depuis la v1.

use rusqlite::{Connection, params};

pub const SCHEMA_VERSION: u32 = 2;

/// Schéma v1 (lot 1A), conservé pour la migration et pour ses tests : une
/// base v1 est ouverte avec ce schéma, puis migrée.
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
    -- 0 : courant, 1 : sécurité (voir `EventClass`).
    class INTEGER NOT NULL DEFAULT 0
);
";

/// Tables de la v2 : un message par identifiant logique, une livraison par
/// paquet (donc par appareil destinataire), et pour chaque paquet reçu le
/// message qu'il porte (`inbound`, retrouvé par l'accusé que j'ai émis).
///
/// Unicité de `messages.message_id` : un message sortant porte l'identifiant
/// tiré par un de mes appareils ; un message reçu, l'identifiant dérivé de
/// l'empreinte de l'expéditeur et de l'identifiant de son enveloppe
/// (`MessageId::incoming`). Un contact ne peut donc ni masquer ni écraser un
/// message d'un autre contact ou un des miens : seul un renvoi de ses propres
/// messages entre en collision (doublon).
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
    status INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS deliveries_message ON deliveries(message_id);
CREATE TABLE IF NOT EXISTS inbound (
    packet_id BLOB PRIMARY KEY NOT NULL,
    message_id BLOB NOT NULL
);
";

/// Contexte de dérivation d'un identifiant de message à partir d'un
/// identifiant de paquet (messages v1 et messages reçus avant le lot 1B).
pub const LEGACY_MESSAGE_ID_CONTEXT: &str = "barking/v0/legacy-message-id";

/// Statuts persistés (voir `MessageStatus`) utilisés par la migration.
const STATUS_DELIVERED: i64 = 3;
const DIRECTION_OUT: i64 = 0;

/// Migre une base v1 en v2, dans une seule transaction : les lignes de
/// `messages` reçoivent un `message_id` dérivé de leur `packet_id` (ou de
/// leur `id` s'il est nul), les messages sortants ayant un paquet reçoivent
/// la livraison correspondante, les messages reçus ayant un paquet sont
/// inscrits dans `inbound`, puis `schema_version` passe à 2.
pub fn migrate_v1_to_v2(conn: &Connection) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch("ALTER TABLE messages RENAME TO messages_v1;")?;
    tx.execute_batch(SCHEMA_V2_TABLES)?;
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
                    // L'appareil destinataire d'un paquet v1 n'est pas connu.
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
        1
    }
}

/// Migration dans le schéma v1 : colonne `class` du journal, pour une base
/// créée avant son ajout. Appliquée à l'ouverture si la colonne manque.
pub const TRANSPARENCY_ADD_CLASS: &str =
    "ALTER TABLE transparency ADD COLUMN class INTEGER NOT NULL DEFAULT 0;";

/// Index du journal (après la migration : `class` doit exister). La purge
/// lit `max(at)` et le plafond parcourt une classe par identifiant à chaque
/// ajout.
pub const TRANSPARENCY_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS transparency_at ON transparency(at);
CREATE INDEX IF NOT EXISTS transparency_class_id ON transparency(class, id);
";
