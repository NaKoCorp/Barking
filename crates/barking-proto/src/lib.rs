//! Client-to-node protocol: messages, frames, deposit proof of work,
//! node identity, pinned TLS and QUIC client.

pub mod client;
pub mod frame;
pub mod msg;
pub mod node_id;
pub mod pow;
pub mod record;
pub mod tls;

pub use msg::{
    ACK_CURSOR_BASE, ErrorReason, Limits, MAX_HOLDINGS_PER_PAGE, MAX_NODES_PER_RESPONSE,
    MAX_PAGE_ITEMS, MIN_PAGE_BYTES, Request, Response,
};
pub use node_id::{NodeId, generate_node_key};
pub use record::{NodeRecord, RecordError, RecordPolicy, embeds_ipv4, routable};

/// Protocol version.
pub const PROTOCOL_VERSION: u16 = 0;
/// ALPN identifier of the QUIC layer.
pub const ALPN: &[u8] = b"barking/0";

/// True if the version ranges `a_min..=a_max` and `b_min..=b_max` share at least
/// one version.
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
