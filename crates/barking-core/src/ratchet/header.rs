//! En-tête du double ratchet : `dh(32) || pn u32 BE || n u32 BE`, chiffré à part.

use crate::crypto::aead::{XNONCE_LEN, xopen, xseal};
use crate::{CoreError, Result};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

/// Taille de l'en-tête en clair.
pub(super) const HEADER_LEN: usize = 32 + 4 + 4;
/// Taille de l'en-tête chiffré : nonce XChaCha20, en-tête, étiquette Poly1305.
pub(super) const ENC_HEADER_LEN: usize = XNONCE_LEN + HEADER_LEN + 16;

/// Message du double ratchet tel qu'il circule.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// En-tête chiffré (80 octets).
    pub enc_header: Vec<u8>,
    /// Corps chiffré (texte clair + 16 octets d'authentification).
    pub ct: Vec<u8>,
}

/// En-tête en clair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Header {
    /// Clé publique de ratchet de l'émetteur.
    pub dh: [u8; 32],
    /// Longueur de la chaîne d'envoi précédente.
    pub pn: u32,
    /// Numéro du message dans la chaîne d'envoi.
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
            .map_err(|_| CoreError::Malformed("en-tête du ratchet"))?;
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

    /// HENCRYPT : XChaCha20-Poly1305, nonce aléatoire préfixé, sans données associées.
    pub(super) fn seal(&self, hk: &[u8; 32], rng: &mut impl CryptoRng) -> Vec<u8> {
        xseal(hk, &[], &self.encode(), rng)
    }

    /// HDECRYPT : échoue si la clé ne convient pas ou si la taille est fausse.
    pub(super) fn open(hk: &[u8; 32], enc: &[u8]) -> Result<Self> {
        if enc.len() != ENC_HEADER_LEN {
            return Err(CoreError::Malformed("taille de l'en-tête chiffré"));
        }
        let pt = xopen(hk, &[], enc)?;
        Header::decode(&pt)
    }
}
