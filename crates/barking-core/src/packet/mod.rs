//! Paquet universel : en-tête en clair de 40 octets, trois paliers de taille.

pub mod ack;
mod header;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::mailbox::MailboxId;

/// Taille de l'en-tête en clair (sans les 2 octets de longueur).
pub const HEADER_LEN: usize = 40;
/// Nombre de sauts par défaut.
pub const DEFAULT_HOPS: u8 = 8;
/// Durée de vie par défaut : 7 jours.
pub const DEFAULT_TTL_SECS: u64 = 7 * 86400;

/// Octets d'en-tête + champ de longueur.
pub(crate) const OVERHEAD: usize = HEADER_LEN + 2;

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
    /// Taille totale du paquet encodé.
    pub fn size(self) -> usize {
        match self {
            Tier::S => 245,
            Tier::M => 1024,
            Tier::L => 16384,
        }
    }

    /// Plus petit palier pouvant contenir `payload_len` octets de charge utile.
    pub fn fit(payload_len: usize) -> Result<Tier> {
        let total = payload_len
            .checked_add(OVERHEAD)
            .ok_or(CoreError::TooLarge)?;
        [Tier::S, Tier::M, Tier::L]
            .into_iter()
            .find(|t| total <= t.size())
            .ok_or(CoreError::TooLarge)
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

/// Expiration par défaut à partir de `now`, saturée dans un `u32`.
pub(crate) fn default_expiry(now: u64) -> u32 {
    u32::try_from(now.saturating_add(DEFAULT_TTL_SECS)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
