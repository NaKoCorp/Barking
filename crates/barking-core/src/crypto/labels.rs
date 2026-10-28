//! Étiquettes de séparation de domaine.
//!
//! Chaque signature et chaque dérivation de clé utilise une étiquette de la
//! forme `b"barking/v0/<usage>"`, centralisée ici. Les tâches suivantes y
//! ajoutent leurs propres constantes.

/// Étiquette de test de la couche de dérivation (exemple de la convention).
pub const KDF_SELFTEST: &[u8] = b"barking/v0/kdf-selftest";

/// Graine de l'identité racine dérivée de l'entropie de la phrase de récupération.
pub const ROOT_FROM_ENTROPY: &[u8] = b"barking/v0/root-from-entropy";

/// Contexte BLAKE3 de l'empreinte d'une clé racine publique.
pub const FINGERPRINT_CONTEXT: &str = "barking/v0/fingerprint";

/// Domaine du code de sécurité (hash des deux empreintes triées).
pub const SAFETY_NUMBER: &[u8] = b"barking/v0/safety-number";
