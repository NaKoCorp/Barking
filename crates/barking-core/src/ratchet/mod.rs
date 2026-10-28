//! Double ratchet avec en-têtes chiffrés (spec Double Ratchet de Signal, §3.5 et §4).
//!
//! Écart d'implémentation assumé : `decrypt` ne reçoit pas de générateur
//! aléatoire. La moitié « envoi » de l'étape DH (nouvelle paire `DHs`, puis
//! `KDF_RK` pour `CKs` et `NHKs`) est donc reportée au prochain `encrypt`.
//! L'ancienne clé privée `DHs` est effacée dès la réception, comme chez
//! Signal ; la suite des clés produites est identique.

mod header;
mod state;

#[cfg(test)]
mod tests;

pub use header::RatchetMessage;
pub use state::RatchetState;

/// Nombre maximal de clés de message sautées dans une même chaîne.
pub const MAX_SKIP: u32 = 1000;

/// Nombre maximal de clés sautées gardées au total ; au-delà, les plus anciennes sont supprimées.
pub const MAX_SKIPPED_TOTAL: usize = 2000;
