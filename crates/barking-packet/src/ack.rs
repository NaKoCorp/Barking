//! Acknowledgements by revealed secret.
//!
//! A packet identifier equals `BLAKE3(ack_secret)[..16]`; the secret
//! exists only inside the encrypted content. Publishing the secret proves
//! receipt without revealing the identity of the acknowledger.

use rand_core::CryptoRng;

use super::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier, default_expiry};
use crate::labels;

/// Draws a random acknowledgement secret.
pub fn new_secret(rng: &mut impl CryptoRng) -> [u8; 16] {
    let mut s = [0u8; 16];
    rng.fill_bytes(&mut s);
    s
}

/// Packet identifier expected for an acknowledgement secret.
pub fn packet_id_for(secret: &[u8; 16]) -> PacketId {
    let full = blake3::derive_key(labels::ACK_CONTEXT, secret);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    PacketId(id)
}

/// True if `secret` matches the identifier `id`.
pub fn verify(id: &PacketId, secret: &[u8; 16]) -> bool {
    // Constant-time comparison (neither value is secret on the relay
    // side, but the identifier must not serve as an oracle).
    let expected = packet_id_for(secret);
    expected
        .0
        .iter()
        .zip(id.0.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

impl Packet {
    /// Acknowledgement for `acked`: tier S, in the mailbox of the acknowledged message (nodes
    /// that keep a copy of it pick it up, and so does the sender while
    /// it waits for the acknowledgement), payload `acked.id || secret`.
    pub fn ack(acked: &Packet, secret: [u8; 16], now: u64, rng: &mut impl CryptoRng) -> Packet {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&acked.id.0);
        payload.extend_from_slice(&secret);
        Packet {
            kind: Kind::Ack,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId(id),
            expires_at: default_expiry(now),
            mailbox: acked.mailbox,
            payload,
        }
    }
}
