//! Double ratchet header: `dh(32) || pn u32 BE || n u32 BE`, encrypted separately.

use crate::crypto::aead::{XNONCE_LEN, xopen, xseal};
use crate::{CoreError, Result};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

/// Size of the plaintext header.
pub(super) const HEADER_LEN: usize = 32 + 4 + 4;
/// Size of the encrypted header: XChaCha20 nonce, header, Poly1305 tag.
pub(super) const ENC_HEADER_LEN: usize = XNONCE_LEN + HEADER_LEN + 16;

/// Double ratchet message as it travels.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Encrypted header (80 bytes).
    pub enc_header: Vec<u8>,
    /// Encrypted body (plaintext + 16 authentication bytes).
    pub ct: Vec<u8>,
}

/// Plaintext header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Header {
    /// Sender's ratchet public key.
    pub dh: [u8; 32],
    /// Length of the previous sending chain.
    pub pn: u32,
    /// Message number in the sending chain.
    pub n: u32,
}

impl Header {
    pub(super) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; HEADER_LEN] = bytes
            .try_into()
            .map_err(|_| CoreError::Malformed("ratchet header"))?;
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        let mut pn = [0u8; 4];
        pn.copy_from_slice(&bytes[32..36]);
        let mut n = [0u8; 4];
        n.copy_from_slice(&bytes[36..]);
        Ok(Header {
            dh,
            pn: u32::from_be_bytes(pn),
            n: u32::from_be_bytes(n),
        })
    }

    /// HENCRYPT: XChaCha20-Poly1305, random prefixed nonce, no associated data.
    pub(super) fn seal(&self, hk: &[u8; 32], rng: &mut impl CryptoRng) -> Vec<u8> {
        xseal(hk, &[], &self.encode(), rng)
    }

    /// HDECRYPT: fails if the key does not fit or if the size is wrong.
    pub(super) fn open(hk: &[u8; 32], enc: &[u8]) -> Result<Self> {
        if enc.len() != ENC_HEADER_LEN {
            return Err(CoreError::Malformed("encrypted header size"));
        }
        let pt = xopen(hk, &[], enc)?;
        Header::decode(&pt)
    }
}
