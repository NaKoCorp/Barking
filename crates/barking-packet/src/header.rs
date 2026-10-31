//! Packet encoding and decoding.
//!
//! Layout: `version(=0) | kind | hops | tier | id(16) | expires_at u32 BE
//! | mailbox(16) | payload_len u16 BE | payload | zeros`.

use super::{HEADER_LEN, Kind, MailboxId, OVERHEAD, Packet, PacketId, Result, Tier};
use crate::error::PacketError;

const VERSION: u8 = 0;

impl Packet {
    /// Encodes into exactly `tier.size()` bytes.
    ///
    /// Caller invariant: `payload.len() <= tier.size() - 42`
    /// (`Tier::fit` guarantees it). Beyond that, the payload is truncated (without
    /// panicking, in debug as in release) so that the output is always
    /// exactly `tier.size()` bytes; `decode` never produces such a packet.
    pub fn encode(&self) -> Vec<u8> {
        let size = self.tier.size();
        let n = self.payload.len().min(size - OVERHEAD);
        let len = u16::try_from(n).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(size);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.push(self.hops);
        out.push(self.tier as u8);
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.mailbox.0);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload[..n]);
        out.resize(size, 0);
        out
    }

    /// Decodes a packet. Never panics; allocates only `payload_len`
    /// bytes, already bounded by the input length.
    pub fn decode(bytes: &[u8]) -> Result<Packet> {
        if bytes.len() < OVERHEAD {
            return Err(PacketError::Malformed("packet too short"));
        }
        if bytes[0] != VERSION {
            return Err(PacketError::Malformed("unknown packet version"));
        }
        let kind = match bytes[1] {
            0 => Kind::Message,
            1 => Kind::Ack,
            _ => return Err(PacketError::Malformed("unknown packet kind")),
        };
        let tier = match bytes[3] {
            0 => Tier::S,
            1 => Tier::M,
            2 => Tier::L,
            _ => return Err(PacketError::Malformed("unknown tier")),
        };
        if bytes.len() != tier.size() {
            return Err(PacketError::Malformed("length differs from tier"));
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
            return Err(PacketError::Malformed("payload length too large"));
        }
        let payload = &bytes[OVERHEAD..OVERHEAD + len];
        if bytes[OVERHEAD + len..].iter().any(|&b| b != 0) {
            return Err(PacketError::Malformed("non-zero padding"));
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
