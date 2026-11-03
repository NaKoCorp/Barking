//! Barking node: SQLite storage, deposit and fetch rules (network-free),
//! anti-abuse limits and QUIC server.

pub mod config;
pub mod dht;
pub mod limits;
pub mod logging;
pub mod rules;
pub mod server;
pub mod store;
#[cfg(feature = "test-harness")]
pub mod testing;
pub mod wake;
mod writer;

pub use rules::{Policy, deposit, fetch};
pub use store::{NodeStore, Stats};

/// Storage error (business refusals go through `ErrorReason`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("incompatible database (schema_version {0})")]
    SchemaVersion(i64),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
