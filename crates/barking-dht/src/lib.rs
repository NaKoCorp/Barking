//! S/Kademlia distributed hash table between nodes: distance, mailbox
//! keys, address blocks and routing table.

pub mod bootstrap;
pub mod lookup;
pub mod table;

use barking_packet::MailboxId;
use barking_proto::{NodeId, NodeRecord};

pub use bootstrap::{BootstrapEntry, BootstrapError, builtin_bootstrap, parse_bootstrap};
pub use lookup::{Lookup, Suspect, filter_nodes};
pub use table::{DiversityLimits, Insert, Peer, Reject, RoutingTable};

/// Active nodes per bucket.
pub const K: usize = 20;
/// Parallel requests per lookup path.
pub const ALPHA: usize = 3;
/// Disjoint paths of a lookup.
pub const PATHS: usize = 3;
/// Nodes responsible for a mailbox.
pub const REPLICAS: usize = 5;
/// Copies deposited by the client.
pub const CLIENT_COPIES: usize = 3;
/// Responsibility window (2r): rank of the node that bounds proximity.
pub const RESPONSIBLE_WINDOW: usize = 10;
/// Size of a bucket's reserve.
pub const REPLACEMENTS: usize = 10;
/// Nodes from the same block per bucket (reserve included) and per result.
pub const MAX_PER_PREFIX: usize = 2;
/// Maximum share of the table's active nodes for a single block.
pub const MAX_PREFIX_SHARE_PERCENT: usize = 10;
/// Nodes always allowed per block, whatever the table size.
pub const MIN_PREFIX_ALLOWED: usize = 2;
/// Consecutive failures before an active node is removed.
pub const FAILS_BEFORE_EVICT: u8 = 3;
/// A node not seen for this long is pinged during maintenance.
pub const STALE_AFTER_SECS: u64 = 900;
/// A bucket without a lookup for this long is refreshed.
pub const REFRESH_AFTER_SECS: u64 = 3600;
/// Derivation context of a mailbox key.
pub const MAILBOX_KEY_CONTEXT: &str = "barking/v0/mailbox-key";

/// Key of a mailbox in the table: `BLAKE3(context, mailbox)`.
pub fn mailbox_key(mailbox: &MailboxId) -> [u8; 32] {
    blake3::derive_key(MAILBOX_KEY_CONTEXT, &mailbox.0)
}

/// XOR distance; comparing two distances as arrays amounts to comparing
/// them in big-endian.
pub fn distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Number of common leading bits, `None` if the identifiers are equal.
pub fn bucket_index(own: &NodeId, other: &NodeId) -> Option<usize> {
    let d = distance(&own.0, &other.0);
    let i = d.iter().position(|&b| b != 0)?;
    Some(i * 8 + d[i].leading_zeros() as usize)
}

/// Address block: /24 in IPv4, /48 in IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Prefix {
    V4([u8; 3]),
    V6([u8; 6]),
}

/// Blocks of a record: a dual-stack node counts in both.
pub fn prefixes(record: &NodeRecord) -> Vec<Prefix> {
    let mut out = Vec::with_capacity(2);
    if let Some(a) = record.v4 {
        let o = a.ip().octets();
        out.push(Prefix::V4([o[0], o[1], o[2]]));
    }
    if let Some(a) = record.v6 {
        let o = a.ip().octets();
        out.push(Prefix::V6([o[0], o[1], o[2], o[3], o[4], o[5]]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_is_xor_and_symmetric() {
        let a = [0b1010_0000; 32];
        let mut b = [0b1010_0000; 32];
        b[0] = 0b0110_0000;
        b[31] = 0b1010_0001;
        let d = distance(&a, &b);
        let mut expected = [0; 32];
        expected[0] = 0b1100_0000;
        expected[31] = 0b0000_0001;
        assert_eq!(d, expected);
        assert_eq!(distance(&b, &a), d);
        assert_eq!(distance(&a, &a), [0; 32]);
        // Big-endian comparison: the leading byte wins.
        let mut near = [0; 32];
        near[31] = 0xff;
        let mut far = [0; 32];
        far[0] = 1;
        assert!(near < far);
    }

    #[test]
    fn bucket_index_counts_common_prefix() {
        let own = NodeId([0; 32]);
        assert_eq!(bucket_index(&own, &own), None);
        let mut other = [0; 32];
        other[0] = 0x80;
        assert_eq!(bucket_index(&own, &NodeId(other)), Some(0));
        other[0] = 0x01;
        assert_eq!(bucket_index(&own, &NodeId(other)), Some(7));
        let mut other = [0; 32];
        other[2] = 0x20;
        assert_eq!(bucket_index(&own, &NodeId(other)), Some(18));
        let mut other = [0; 32];
        other[31] = 0x01;
        assert_eq!(bucket_index(&own, &NodeId(other)), Some(255));
    }

    #[test]
    fn mailbox_key_uses_context() {
        let mailbox = MailboxId([9; 16]);
        assert_eq!(
            mailbox_key(&mailbox),
            blake3::derive_key("barking/v0/mailbox-key", &[9; 16])
        );
    }

    #[test]
    fn prefixes_cover_both_families() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[3; 32]);
        let rec = NodeRecord::sign(
            &key,
            Some("1.2.3.4:4433".parse().unwrap()),
            Some("[2001:db8:1:2:3::1]:4433".parse().unwrap()),
            0,
        );
        assert_eq!(
            prefixes(&rec),
            vec![
                Prefix::V4([1, 2, 3]),
                Prefix::V6([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01])
            ]
        );
    }
}
