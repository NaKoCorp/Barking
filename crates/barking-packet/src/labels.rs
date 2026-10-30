//! Étiquettes de séparation de domaine propres au module paquet.

/// Contexte BLAKE3 de l'identifiant de paquet d'un accusé.
pub const ACK_CONTEXT: &str = "barking/v0/ack";

/// Contexte BLAKE3 de la clé de trame (fragmentation).
pub const FRAME_CONTEXT: &str = "barking/v0/frame";
