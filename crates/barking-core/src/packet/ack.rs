//! Accusés de réception par secret révélé.
//!
//! L'identifiant d'un paquet vaut `BLAKE3(ack_secret)[..16]` ; le secret
//! n'existe que dans le contenu chiffré. Publier le secret prouve la
//! réception sans révéler l'identité de l'émetteur de l'accusé.

use rand_core::CryptoRng;

use super::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier, default_expiry};
use crate::crypto::labels;

/// Tire un secret d'accusé aléatoire.
pub fn new_secret(rng: &mut impl CryptoRng) -> [u8; 16] {
    let mut s = [0u8; 16];
    rng.fill_bytes(&mut s);
    s
}

/// Identifiant de paquet attendu pour un secret d'accusé.
pub fn packet_id_for(secret: &[u8; 16]) -> PacketId {
    let full = blake3::derive_key(labels::ACK_CONTEXT, secret);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    PacketId(id)
}

/// Vrai si `secret` correspond à l'identifiant `id`.
pub fn verify(id: &PacketId, secret: &[u8; 16]) -> bool {
    // Comparaison en temps constant (les deux valeurs ne sont pas secrètes
    // côté relais, mais l'identifiant ne doit pas servir d'oracle).
    let expected = packet_id_for(secret);
    expected
        .0
        .iter()
        .zip(id.0.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

impl Packet {
    /// Accusé pour `acked` : palier S, même boîte, charge `acked.id || secret`.
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
