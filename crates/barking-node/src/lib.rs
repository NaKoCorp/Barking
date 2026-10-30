//! Nœud Barking : stockage SQLite, règles de dépôt et de relève (sans réseau),
//! limites anti-abus et serveur QUIC.

pub mod limits;
pub mod rules;
pub mod server;
pub mod store;

pub use rules::{Policy, deposit, fetch};
pub use store::{NodeStore, Stats};

/// Erreur de stockage (les refus métier passent par `ErrorReason`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("erreur de stockage : {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("base de données incompatible (schema_version {0})")]
    SchemaVersion(i64),
    #[error("configuration invalide : {0}")]
    Config(String),
    #[error("erreur réseau : {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
