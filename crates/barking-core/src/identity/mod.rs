//! Identité : clé racine, empreinte, phrase de récupération, code de sécurité.

pub mod root;
pub mod safety;

pub use root::{Fingerprint, RecoveryPhrase, RootIdentity, RootPublic};
pub use safety::safety_number;
