//! Encodage et décodage du paquet.
//!
//! Disposition : `version(=0) | kind | hops | tier | id(16) | expires_at u32 BE
//! | mailbox(16) | payload_len u16 BE | payload | zéros`.

use super::{HEADER_LEN, Kind, MailboxId, OVERHEAD, Packet, PacketId, Tier};
use crate::error::{CoreError, Result};

const VERSION: u8 = 0;

impl Packet {
    /// Encode sur exactement `tier.size()` octets.
    ///
    /// Invariant de l'appelant : `payload.len() <= tier.size() - 42`
    /// (`Tier::fit` le garantit). Au-delà, la charge est tronquée plutôt que de
    /// paniquer ; `decode` ne produit jamais un tel paquet.
    pub fn encode(&self) -> Vec<u8> {
        let size = self.tier.size();
        debug_assert!(self.payload.len() <= size - OVERHEAD);
        let len = u16::try_from(self.payload.len().min(size - OVERHEAD)).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(size);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.push(self.hops);
        out.push(self.tier as u8);
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.mailbox.0);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.resize(size, 0);
        out
    }

    /// Décode un paquet. Ne panique jamais ; n'alloue que `payload_len`
    /// octets, déjà borné par la longueur de l'entrée.
    pub fn decode(bytes: &[u8]) -> Result<Packet> {
        if bytes.len() < OVERHEAD {
            return Err(CoreError::Malformed("paquet trop court"));
        }
        if bytes[0] != VERSION {
            return Err(CoreError::Malformed("version de paquet inconnue"));
        }
        let kind = match bytes[1] {
            0 => Kind::Message,
            1 => Kind::Ack,
            _ => return Err(CoreError::Malformed("type de paquet inconnu")),
        };
        let tier = match bytes[3] {
            0 => Tier::S,
            1 => Tier::M,
            2 => Tier::L,
            _ => return Err(CoreError::Malformed("palier inconnu")),
        };
        if bytes.len() != tier.size() {
            return Err(CoreError::Malformed("longueur différente du palier"));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[4..20]);
        let mut exp = [0u8; 4];
        exp.copy_from_slice(&bytes[20..24]);
        let mut mailbox = [0u8; 16];
        mailbox.copy_from_slice(&bytes[24..40]);
        let len = usize::from(u16::from_be_bytes([
            bytes[HEADER_LEN],
            bytes[HEADER_LEN + 1],
        ]));
        if len > tier.size() - OVERHEAD {
            return Err(CoreError::Malformed("longueur de charge trop grande"));
        }
        let payload = &bytes[OVERHEAD..OVERHEAD + len];
        if bytes[OVERHEAD + len..].iter().any(|&b| b != 0) {
            return Err(CoreError::Malformed("remplissage non nul"));
        }
        Ok(Packet {
            kind,
            hops: bytes[2],
            tier,
            id: PacketId(id),
            expires_at: u32::from_be_bytes(exp),
            mailbox: MailboxId(mailbox),
            payload: payload.to_vec(),
        })
    }
}
