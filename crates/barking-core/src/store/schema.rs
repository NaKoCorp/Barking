//! Schéma SQL v1 du stockage.

pub const SCHEMA_VERSION: u32 = 1;

pub const SCHEMA_V1: &str = "
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
