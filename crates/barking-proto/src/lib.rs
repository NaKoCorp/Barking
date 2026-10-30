//! Protocole client↔nœud : messages, trames, preuve de travail de dépôt,
//! identité de nœud, TLS épinglé et client QUIC.

pub mod client;
pub mod frame;
pub mod msg;
pub mod node_id;
pub mod pow;
pub mod tls;

pub use msg::{ErrorReason, Limits, MIN_PAGE_BYTES, Request, Response};
pub use node_id::{NodeId, generate_node_key};

/// Version du protocole.
pub const PROTOCOL_VERSION: u16 = 0;
/// Identifiant ALPN de la couche QUIC.
pub const ALPN: &[u8] = b"barking/0";

/// Vrai si les plages de versions `a_min..=a_max` et `b_min..=b_max` ont une
/// version en commun.
pub fn versions_overlap(a_min: u16, a_max: u16, b_min: u16, b_max: u16) -> bool {
    a_min.max(b_min) <= a_max.min(b_max)
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions_overlap() {
        assert!(super::versions_overlap(0, 0, 0, 0));
        assert!(super::versions_overlap(0, 2, 2, 3));
        assert!(!super::versions_overlap(0, 1, 2, 3));
        assert!(!super::versions_overlap(3, 4, 0, 2));
    }
}
