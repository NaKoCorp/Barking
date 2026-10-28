//! AEAD : ChaCha20-Poly1305 (nonce explicite) et XChaCha20-Poly1305 (nonce aléatoire préfixé).

use crate::{CoreError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand_core::CryptoRng;

/// Taille du nonce XChaCha20-Poly1305, préfixé au chiffré par [`xseal`].
pub const XNONCE_LEN: usize = 24;

/// Chiffre avec ChaCha20-Poly1305. L'appelant garantit l'unicité du couple (clé, nonce).
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    // Le chiffrement ne peut échouer que sur une taille démesurée (> 2^38 octets).
    cipher
        .encrypt(&(*nonce).into(), Payload { msg: pt, aad: ad })
        .expect("taille de message dans les limites de l'AEAD")
}

/// Déchiffre et authentifie. Toute altération donne `CoreError::Crypto`.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(&(*nonce).into(), Payload { msg: ct, aad: ad })
        .map_err(|_| CoreError::Crypto)
}

/// Chiffre avec XChaCha20-Poly1305 ; le nonce aléatoire de 24 octets est préfixé.
pub fn xseal(key: &[u8; 32], ad: &[u8], pt: &[u8], rng: &mut impl CryptoRng) -> Vec<u8> {
    let mut nonce = [0u8; XNONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let body = cipher
        .encrypt(&nonce.into(), Payload { msg: pt, aad: ad })
        .expect("taille de message dans les limites de l'AEAD");
    let mut out = Vec::with_capacity(XNONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    out
}

/// Inverse de [`xseal`] : lit le nonce préfixé, puis déchiffre.
pub fn xopen(key: &[u8; 32], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = ct.split_at_checked(XNONCE_LEN).ok_or(CoreError::Crypto)?;
    let nonce: [u8; XNONCE_LEN] = nonce.try_into().map_err(|_| CoreError::Crypto)?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(&nonce.into(), Payload { msg: body, aad: ad })
        .map_err(|_| CoreError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = seal(&key, &nonce, b"ad", b"hello");
        assert_eq!(open(&key, &nonce, b"ad", &ct).unwrap(), b"hello");
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert_eq!(open(&key, &nonce, b"ad", &bad), Err(CoreError::Crypto));
        }
        assert_eq!(open(&key, &nonce, b"aD", &ct), Err(CoreError::Crypto));
        assert_eq!(open(&key, &nonce, b"ad", &ct[..3]), Err(CoreError::Crypto));
    }

    #[test]
    fn xaead_nonces_differ() {
        let key = [9u8; 32];
        let mut rng = rand::rng();
        let a = xseal(&key, b"ad", b"payload", &mut rng);
        let b = xseal(&key, b"ad", b"payload", &mut rng);
        assert_ne!(a, b);
        assert_eq!(xopen(&key, b"ad", &a).unwrap(), b"payload");
        assert_eq!(xopen(&key, b"ad", &b).unwrap(), b"payload");
        assert_eq!(a.len(), 24 + 7 + 16);
        assert_eq!(xopen(&key, b"ad", &a[..10]), Err(CoreError::Crypto));
        let mut bad = a.clone();
        bad[0] ^= 1;
        assert_eq!(xopen(&key, b"ad", &bad), Err(CoreError::Crypto));
    }
}
