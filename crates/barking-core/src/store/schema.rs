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
    event BLOB NOT NULL
);
";
