//! Client-to-node protocol: messages, frames, deposit proof of work,
//! node identity, pinned TLS and QUIC client.

pub mod client;
pub mod frame;
pub mod msg;
pub mod node_id;
pub mod pow;
pub mod push;
pub mod record;
pub mod tls;

pub use msg::{
    ACK_CURSOR_BASE, ErrorReason, FillTier, Limits, MAX_AS_NAME_LEN, MAX_HOLDINGS_PER_PAGE,
    MAX_NODES_PER_RESPONSE, MAX_PAGE_ITEMS, MAX_SOFTWARE_LEN, MAX_WAKE_ITEMS, MIN_PAGE_BYTES,
    NodeInfoReport, NodeOrigin, PUSH_LINK_MIN_SUBS, PushLink, Request, Response,
};
pub use node_id::{NodeId, generate_node_key};
pub use record::{NodeRecord, RecordError, RecordPolicy, embeds_ipv4, routable};

/// Protocol version. 4: messages may live `P4_LIFETIME_SECS` (7 days).
/// 5: the public `Info` request.
pub const PROTOCOL_VERSION: u16 = 5;

/// Message lifetime a protocol 4 node accepts: 7 days. Fixed by the
/// protocol, not by the client's `DEFAULT_TTL_SECS`: shortening the client
/// lifetime (the revert switch) changes neither what a protocol 4 node
/// accepts nor which nodes a packet already sealed may go to.
pub const P4_LIFETIME_SECS: u64 = 604_800;
/// Furthest expiry from its own clock a protocol 4 node accepts: the
/// protocol 4 lifetime plus one hour of clock tolerance.
pub const P4_MAX_EXPIRY_SECS: u64 = P4_LIFETIME_SECS + 3_600;
// A client never seals a packet that no protocol 4 node accepts.
const _: () = assert!(barking_packet::DEFAULT_TTL_SECS + 3_600 <= P4_MAX_EXPIRY_SECS);

/// Furthest expiry, from its own clock, that a node speaking protocol
/// `version` accepts: from protocol 4 on, `P4_MAX_EXPIRY_SECS`; before,
/// 24 h plus one hour.
pub const fn max_expiry_secs(version: u16) -> u64 {
    if version >= 4 {
        P4_MAX_EXPIRY_SECS
    } else {
        90_000
    }
}
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
