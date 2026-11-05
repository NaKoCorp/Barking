//! Signed node record: public key, public addresses and issue date
//! rounded to the hour, all signed by the node key. Only
//! these records circulate between nodes and are written to disk.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::node_id::{NODE_PUZZLE_BITS, NodeId};

/// Context of a record signature.
pub const RECORD_CONTEXT: &[u8] = b"barking/v0/node-record";
/// Maximum tolerated lead on `issued_at`, in seconds.
pub const MAX_RECORD_SKEW_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub public_key: [u8; 32],
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
    pub issued_at: u64,
    pub signature: Signature,
}

/// Validation rules for a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPolicy {
    /// Accepts non-routable addresses (private networks, tests).
    pub allow_private: bool,
    /// Required difficulty of the identifier puzzle.
    pub puzzle_bits: u32,
}

impl RecordPolicy {
    /// Network policy: full puzzle.
    pub fn network(allow_private: bool) -> RecordPolicy {
        RecordPolicy {
            allow_private,
            puzzle_bits: NODE_PUZZLE_BITS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("invalid public key")]
    BadKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("the identifier puzzle is not solved")]
    Puzzle,
    #[error("record issued in the future")]
    FromFuture,
    #[error("record without address")]
    NoAddress,
    #[error("non-routable address")]
    Unroutable,
}

/// Signed bytes: context, then `postcard(public_key, v4, v6, issued_at)`.
fn signed_bytes(
    public_key: &[u8; 32],
    v4: &Option<SocketAddrV4>,
    v6: &Option<SocketAddrV6>,
    issued_at: u64,
) -> Vec<u8> {
    let mut out = RECORD_CONTEXT.to_vec();
    out.extend(
        postcard::to_allocvec(&(public_key, v4, v6, issued_at))
            .expect("in-memory serialization does not fail"),
    );
    out
}

impl NodeRecord {
    /// Signs a record; `now` is rounded down to the hour.
    pub fn sign(
        key: &SigningKey,
        v4: Option<SocketAddrV4>,
        v6: Option<SocketAddrV6>,
        now: u64,
    ) -> NodeRecord {
        Self::sign_at(key, v4, v6, now - now % 3600)
    }

    fn sign_at(
        key: &SigningKey,
        v4: Option<SocketAddrV4>,
        v6: Option<SocketAddrV6>,
        issued_at: u64,
    ) -> NodeRecord {
        let public_key = key.verifying_key().to_bytes();
        let signature = key.sign(&signed_bytes(&public_key, &v4, &v6, issued_at));
        NodeRecord {
            public_key,
            v4,
            v6,
            issued_at,
            signature,
        }
    }

    /// Addresses of the record, v4 first.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(2);
        if let Some(a) = self.v4 {
            out.push(SocketAddr::V4(a));
        }
        if let Some(a) = self.v6 {
            out.push(SocketAddr::V6(a));
        }
        out
    }

    /// Checks key, signature, puzzle, date and addresses; returns
    /// the node identifier.
    pub fn verify(&self, now: u64, policy: &RecordPolicy) -> Result<NodeId, RecordError> {
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| RecordError::BadKey)?;
        let msg = signed_bytes(&self.public_key, &self.v4, &self.v6, self.issued_at);
        key.verify_strict(&msg, &self.signature)
            .map_err(|_| RecordError::BadSignature)?;
        let id = NodeId::from_public_key(&key);
        if !id.puzzle_ok_bits(policy.puzzle_bits) {
            return Err(RecordError::Puzzle);
        }
        if self.issued_at > now.saturating_add(MAX_RECORD_SKEW_SECS) {
            return Err(RecordError::FromFuture);
        }
        let addrs = self.addrs();
        if addrs.is_empty() {
            return Err(RecordError::NoAddress);
        }
        // Port 0 cannot be reached on any network: rejected whatever the
        // policy.
        if addrs.iter().any(|a| a.port() == 0) {
            return Err(RecordError::Unroutable);
        }
        if !policy.allow_private && !addrs.iter().all(routable) {
            return Err(RecordError::Unroutable);
        }
        // An IPv4 disguised as IPv6 would count in the `::/48` block instead
        // of its /24: rejected even under `allow_private`.
        if self.v6.is_some_and(|a| embeds_ipv4(a.ip())) {
            return Err(RecordError::Unroutable);
        }
        Ok(id)
    }
}

/// True if `ip` carries an IPv4: `::ffff:0:0/96` (encapsulated IPv4) or
/// `::/96` (IPv4-compatible, obsolete, unspecified address included).
/// `::1` (loopback) is not one.
pub fn embeds_ipv4(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    s[..5] == [0; 5] && (s[5] == 0xffff || (s[5] == 0 && !ip.is_loopback()))
}

fn routable_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        // 0.0.0.0/8: this network.
        || o[0] == 0
        // 100.64.0.0/10: shared operator space.
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 240.0.0.0/4: reserved.
        || o[0] >= 240)
}

fn routable_v6(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return routable_v4(&v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fe80::/10 link-local, fec0::/10 site-local (obsolete).
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // fc00::/7 unique local addresses.
        || (s[0] & 0xfe00) == 0xfc00
        // 2001:db8::/32 documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8))
}

/// True if the address is reachable from the Internet (neither private, nor local,
/// nor documentation, non-zero port).
pub fn routable(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && match addr.ip() {
            std::net::IpAddr::V4(ip) => routable_v4(&ip),
            std::net::IpAddr::V6(ip) => routable_v6(&ip),
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_000_000;

    fn v4(s: &str) -> Option<SocketAddrV4> {
        Some(s.parse().unwrap())
    }

    fn lax() -> RecordPolicy {
        RecordPolicy {
            allow_private: false,
            puzzle_bits: 0,
        }
    }

    fn any_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn signed_record_verifies() {
        // Solves the puzzle (seed drawn once with `generate_node_key` in
        // optimized mode).
        let key = SigningKey::from_bytes(&[
            150, 151, 201, 8, 34, 150, 13, 226, 60, 195, 190, 11, 19, 13, 22, 132, 240, 68, 139,
            241, 74, 28, 92, 145, 5, 25, 223, 169, 17, 160, 107, 234,
        ]);
        let rec = NodeRecord::sign(&key, v4("1.2.3.4:4433"), None, NOW);
        let id = rec.verify(NOW, &RecordPolicy::network(false)).unwrap();
        assert_eq!(id, NodeId::from_public_key(&key.verifying_key()));
        assert_eq!(rec.addrs(), vec!["1.2.3.4:4433".parse().unwrap()]);
    }

    #[test]
    fn issued_at_is_rounded_to_hour() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, 7_205);
        assert_eq!(rec.issued_at, 7_200);
    }

    #[test]
    fn tampered_record_is_refused() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        let mut moved = rec.clone();
        moved.v4 = v4("1.2.3.4:4434");
        assert_eq!(moved.verify(NOW, &lax()), Err(RecordError::BadSignature));
        let mut dated = rec;
        dated.issued_at += 3600;
        assert_eq!(dated.verify(NOW, &lax()), Err(RecordError::BadSignature));
    }

    #[test]
    fn future_record_is_refused() {
        let key = any_key();
        let late = NodeRecord::sign_at(&key, v4("1.2.3.4:4433"), None, NOW + 3_601);
        assert_eq!(late.verify(NOW, &lax()), Err(RecordError::FromFuture));
        let edge = NodeRecord::sign_at(&key, v4("1.2.3.4:4433"), None, NOW + 3_600);
        assert!(edge.verify(NOW, &lax()).is_ok());
    }

    #[test]
    fn bad_puzzle_is_refused() {
        let rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        assert_eq!(
            rec.verify(NOW, &RecordPolicy::network(false)),
            Err(RecordError::Puzzle)
        );
        assert!(rec.verify(NOW, &lax()).is_ok());
    }

    #[test]
    fn no_address_is_refused() {
        let rec = NodeRecord::sign(&any_key(), None, None, NOW);
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::NoAddress));
    }

    #[test]
    fn bad_key_is_refused() {
        let mut rec = NodeRecord::sign(&any_key(), v4("1.2.3.4:4433"), None, NOW);
        // y = 2 is not a point on the curve.
        rec.public_key = [0; 32];
        rec.public_key[0] = 2;
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::BadKey));
    }

    #[test]
    fn unroutable_addresses() {
        for s in [
            "10.0.0.1:1",
            "127.0.0.1:1",
            "169.254.1.1:1",
            "192.168.1.1:1",
            "0.0.0.0:1",
            "224.0.0.1:1",
            "192.0.2.1:1",
            "198.51.100.1:1",
            "203.0.113.1:1",
            "100.64.0.1:1",
            "1.2.3.4:0",
            "[::1]:1",
            "[fe80::1]:1",
            "[fc00::1]:1",
            "[ff02::1]:1",
            "[2001:db8::1]:1",
            "0.1.2.3:1",
            "240.0.0.1:1",
            "255.255.255.255:1",
            "[fec0::1]:1",
            "100.127.255.255:1",
        ] {
            assert!(!routable(&s.parse().unwrap()), "{s}");
        }
        for s in ["1.2.3.4:4433", "[2a01:4f8::1]:4433"] {
            assert!(routable(&s.parse().unwrap()), "{s}");
        }
        let key = any_key();
        let rec = NodeRecord::sign(&key, v4("10.0.0.1:4433"), None, NOW);
        assert_eq!(rec.verify(NOW, &lax()), Err(RecordError::Unroutable));
        let private_ok = RecordPolicy {
            allow_private: true,
            puzzle_bits: 0,
        };
        assert!(rec.verify(NOW, &private_ok).is_ok());
    }

    #[test]
    fn port_zero_is_refused_even_when_private_allowed() {
        let private_ok = RecordPolicy {
            allow_private: true,
            puzzle_bits: 0,
        };
        let rec = NodeRecord::sign(&any_key(), v4("127.0.0.1:0"), None, NOW);
        assert_eq!(rec.verify(NOW, &private_ok), Err(RecordError::Unroutable));
        let rec = NodeRecord::sign(&any_key(), None, Some("[::1]:0".parse().unwrap()), NOW);
        assert_eq!(rec.verify(NOW, &private_ok), Err(RecordError::Unroutable));
    }

    #[test]
    fn ipv4_in_ipv6_is_refused_even_when_private_allowed() {
        let private_ok = RecordPolicy {
            allow_private: true,
            puzzle_bits: 0,
        };
        for bad in ["[::ffff:1.2.3.4]:4433", "[::1.2.3.4]:4433", "[::]:4433"] {
            let rec = NodeRecord::sign(&any_key(), None, Some(bad.parse().unwrap()), NOW);
            for p in [lax(), private_ok] {
                assert_eq!(rec.verify(NOW, &p), Err(RecordError::Unroutable), "{bad}");
            }
            // Also as the second address of a dual-stack record.
            let rec = NodeRecord::sign(
                &any_key(),
                v4("1.2.3.4:4433"),
                Some(bad.parse().unwrap()),
                NOW,
            );
            assert_eq!(
                rec.verify(NOW, &lax()),
                Err(RecordError::Unroutable),
                "{bad}"
            );
        }
        // Loopback allowed under `allow_private`, public IPv6 everywhere.
        let rec = NodeRecord::sign(&any_key(), None, Some("[::1]:4433".parse().unwrap()), NOW);
        assert!(rec.verify(NOW, &private_ok).is_ok());
        let rec = NodeRecord::sign(
            &any_key(),
            None,
            Some("[2a01:4f8::1]:4433".parse().unwrap()),
            NOW,
        );
        assert!(rec.verify(NOW, &lax()).is_ok());
        assert!(!embeds_ipv4(&"::1".parse().unwrap()));
        assert!(!embeds_ipv4(&"2a01::ffff:1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn record_postcard_roundtrip() {
        let rec = NodeRecord::sign(
            &any_key(),
            v4("1.2.3.4:4433"),
            Some("[2a01:4f8::1]:4433".parse().unwrap()),
            NOW,
        );
        let bytes = postcard::to_allocvec(&rec).unwrap();
        assert_eq!(postcard::from_bytes::<NodeRecord>(&bytes).unwrap(), rec);
    }
}
