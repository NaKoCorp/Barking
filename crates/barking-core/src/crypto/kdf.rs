//! Dérivation de clés : HKDF-SHA256 et HMAC-SHA256.

use crate::{CoreError, Result};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// HKDF-SHA256 (RFC 5869). Échoue si `out` dépasse 255 * 32 octets.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| CoreError::Crypto)
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepte toute longueur de clé : `new_from_slice` ne peut pas échouer.
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepte toute taille de clé");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hkdf_rfc5869_case1() {
        let mut okm = [0u8; 42];
        hkdf_sha256(
            Some(&hex!("000102030405060708090a0b0c")),
            &[0x0b; 22],
            &hex!("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            okm,
            hex!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn hkdf_rejects_too_long_output() {
        let mut out = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            hkdf_sha256(None, b"ikm", b"info", &mut out),
            Err(crate::CoreError::Crypto)
        );
    }

    #[test]
    fn hmac_rfc4231_case1() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }
}
