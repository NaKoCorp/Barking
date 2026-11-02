//! Node identity: `BLAKE3(context, public key)` and static S/Kademlia
//! puzzle (20 zero bits on `BLAKE3(context, identifier)`).

use std::{fmt, str::FromStr};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::pow::leading_zero_bits;

pub const NODE_ID_CONTEXT: &str = "barking/v0/node-id";
pub const NODE_PUZZLE_CONTEXT: &str = "barking/v0/node-puzzle";
pub const NODE_PUZZLE_BITS: u32 = 20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_public_key(key: &VerifyingKey) -> NodeId {
        NodeId(blake3::derive_key(NODE_ID_CONTEXT, key.as_bytes()))
    }

    /// True if the static puzzle is solved (20 zero bits).
    pub fn puzzle_ok(&self) -> bool {
        self.puzzle_ok_bits(NODE_PUZZLE_BITS)
    }

    /// True if at least `bits` bits are zero (0: always true, for
    /// simulations).
    pub fn puzzle_ok_bits(&self, bits: u32) -> bool {
        self.puzzle_bits() >= bits
    }

    fn puzzle_bits(&self) -> u32 {
        leading_zero_bits(&blake3::derive_key(NODE_PUZZLE_CONTEXT, &self.0))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&data_encoding::BASE32_NOPAD.encode(&self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string();
        write!(f, "NodeId({}…)", &s[..8])
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid node identifier")]
pub struct ParseNodeIdError;

impl FromStr for NodeId {
    type Err = ParseNodeIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| ParseNodeIdError)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| ParseNodeIdError)?;
        Ok(NodeId(arr))
    }
}

fn generate_with_bits(rng: &mut impl CryptoRng, bits: u32) -> SigningKey {
    loop {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        let key = SigningKey::from_bytes(&seed);
        let id = NodeId::from_public_key(&key.verifying_key());
        if id.puzzle_bits() >= bits {
            return key;
        }
    }
}

/// Draws keys until the 20-bit puzzle is solved (~1 million attempts).
pub fn generate_node_key(rng: &mut impl CryptoRng) -> SigningKey {
    generate_with_bits(rng, NODE_PUZZLE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn node_id_puzzle() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let key = generate_node_key(&mut rng);
        assert!(NodeId::from_public_key(&key.verifying_key()).puzzle_ok());
        // Any given key succeeds with probability 2^-20: over 64 keys, never in practice.
        let hits = (0..64u8)
            .filter(|i| {
                let k = SigningKey::from_bytes(&[*i; 32]);
                NodeId::from_public_key(&k.verifying_key()).puzzle_ok()
            })
            .count();
        assert_eq!(hits, 0);
    }

    #[test]
    fn node_id_small_puzzle_variant() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let key = generate_with_bits(&mut rng, 8);
        let id = NodeId::from_public_key(&key.verifying_key());
        assert!(id.puzzle_bits() >= 8);
    }

    #[test]
    fn node_id_base32_roundtrip() {
        let id = NodeId([0xab; 32]);
        let s = id.to_string();
        assert_eq!(s.len(), 52);
        assert_eq!(s.parse::<NodeId>().unwrap(), id);
        assert!("not-base32".parse::<NodeId>().is_err());
        assert!("AAAA".parse::<NodeId>().is_err());
        assert!(format!("{id:?}").len() < 30);
    }
}
