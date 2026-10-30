//! Protocole client↔nœud : messages, trames, preuve de travail de dépôt,
//! identité de nœud. Pas de réseau ici.

pub mod frame;
pub mod msg;
pub mod node_id;
pub mod pow;

pub use msg::{ErrorReason, Limits, Request, Response};
pub use node_id::{NodeId, generate_node_key};

/// Version du protocole.
pub const PROTOCOL_VERSION: u16 = 0;
/// Identifiant ALPN de la couche QUIC.
pub const ALPN: &[u8] = b"barking/0";
