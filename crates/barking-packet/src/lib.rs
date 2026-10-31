//! Universal packet: 40-byte cleartext header, three size tiers.

pub mod ack;
pub mod error;
pub mod fragment;
mod header;
pub mod labels;

use serde::{Deserialize, Serialize};

pub use error::{PacketError, Result};

/// Mailbox identifier (16 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct MailboxId(pub [u8; 16]);

/// Size of the cleartext header (excluding the 2 length bytes).
pub const HEADER_LEN: usize = 40;
/// Default number of hops.
pub const DEFAULT_HOPS: u8 = 8;
/// Default lifetime: 7 days.
pub const DEFAULT_TTL_SECS: u64 = 7 * 86400;

/// Header bytes + length field.
pub const OVERHEAD: usize = HEADER_LEN + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Message = 0,
    Ack = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tier {
    S = 0,
    M = 1,
    L = 2,
}

impl Tier {
    /// Total size of the encoded packet.
    pub fn size(self) -> usize {
        match self {
            Tier::S => 245,
            Tier::M => 1024,
            Tier::L => 16384,
        }
    }

    /// Smallest tier able to hold `payload_len` bytes of payload.
    pub fn fit(payload_len: usize) -> Result<Tier> {
        let total = payload_len
            .checked_add(OVERHEAD)
            .ok_or(PacketError::TooLarge)?;
        [Tier::S, Tier::M, Tier::L]
            .into_iter()
            .find(|t| total <= t.size())
            .ok_or(PacketError::TooLarge)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PacketId(pub [u8; 16]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub hops: u8,
    pub tier: Tier,
    pub id: PacketId,
    pub expires_at: u32,
    pub mailbox: MailboxId,
    pub payload: Vec<u8>,
}

/// Default expiry from `now`, saturated into a `u32`.
pub fn default_expiry(now: u64) -> u32 {
    u32::try_from(now.saturating_add(DEFAULT_TTL_SECS)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
