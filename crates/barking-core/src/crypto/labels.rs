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

/// Domaine de signature du certificat d'appareil par la racine.
pub const DEVICE_CERT: &[u8] = b"barking/v0/device-cert";

/// Domaine de signature de la liste d'appareils par la racine.
pub const DEVICE_LIST: &[u8] = b"barking/v0/device-list";

/// Contexte BLAKE3 de l'identifiant d'appareil.
pub const DEVICE_ID_CONTEXT: &str = "barking/v0/device-id";

/// Domaine de signature d'un paquet de clés par l'appareil.
pub const PREKEYS: &[u8] = b"barking/v0/prekeys";

/// Dérivation de la clé de session PQXDH.
pub const PQXDH_SK: &[u8] = b"barking/v0/pqxdh-sk";

/// Dérivation du secret des boîtes aux lettres à l'ouverture de session.
pub const PQXDH_MAILBOX: &[u8] = b"barking/v0/pqxdh-mailbox";
