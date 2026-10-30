//! Nœud Barking : stockage SQLite et règles de dépôt et de relève, sans réseau.

pub mod rules;
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
}

pub type Result<T> = core::result::Result<T, Error>;
