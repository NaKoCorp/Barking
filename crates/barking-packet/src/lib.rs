//! Universal packet: 40-byte cleartext header, three size tiers.

pub mod ack;
pub mod error;
pub mod fragment;
mod header;
pub mod labels;

use serde::{Deserialize, Serialize};

pub use error::{PacketError, Result};

/// Mailbox identifier (16 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct MailboxId(pub [u8; 16]);

/// Size of the cleartext header (excluding the 2 length bytes).
pub const HEADER_LEN: usize = 40;
/// Default number of hops.
pub const DEFAULT_HOPS: u8 = 8;
/// Default lifetime: 24 hours.
pub const DEFAULT_TTL_SECS: u64 = 86_400;
/// How long past `max(ack expiry, acknowledged message's expiry)` a node
/// keeps a receipt, and how long past its own expiry a sender still takes
/// it: an app that missed the receipt wake-up and syncs a day later still
/// finds it, instead of concluding that the message was not delivered.
pub const ACK_GRACE_SECS: u64 = 86_400;

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

/// BLAKE3 context of the introduction mailbox (first message).
pub const INTRO_MAILBOX_CONTEXT: &str = "barking/v1/intro-mailbox";

/// Introduction mailbox of a device for a given day. Binding the device
/// signing key `sig` lets its owner later prove ownership of the mailbox.
pub fn intro_mailbox(sig: &[u8; 32], dh: &[u8; 32], day: u32) -> MailboxId {
    let mut input = [0u8; 68];
    input[..32].copy_from_slice(sig);
    input[32..64].copy_from_slice(dh);
    input[64..].copy_from_slice(&day.to_be_bytes());
    let full = blake3::derive_key(INTRO_MAILBOX_CONTEXT, &input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    MailboxId(out)
}

/// BLAKE3 context of the owner signature over a push subscription.
pub const OWNER_CONTEXT: &str = "barking/v1/subscribe-owner";

/// Message the owner of an intro mailbox signs to prove ownership of a push
/// subscription: BLAKE3 `derive_key(OWNER_CONTEXT, subscription_hash ||
/// day.to_be_bytes())`, raw 32 bytes. Lives here, beside `intro_mailbox`, so
/// the device key is only ever asked to sign this domain-separated message.
pub fn owner_message(subscription_hash: &[u8; 32], day: u32) -> [u8; 32] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(subscription_hash);
    input[32..].copy_from_slice(&day.to_be_bytes());
    blake3::derive_key(OWNER_CONTEXT, &input)
}

#[cfg(test)]
mod tests;
