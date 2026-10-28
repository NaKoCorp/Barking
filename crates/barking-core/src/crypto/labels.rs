//! Étiquettes de séparation de domaine.
//!
//! Chaque signature et chaque dérivation de clé utilise une étiquette de la
//! forme `b"barking/v0/<usage>"`, centralisée ici. Les tâches suivantes y
//! ajoutent leurs propres constantes.

/// Étiquette de test de la couche de dérivation (exemple de la convention).
pub const KDF_SELFTEST: &[u8] = b"barking/v0/kdf-selftest";
