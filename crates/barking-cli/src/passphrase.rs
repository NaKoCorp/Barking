//! Phrase de passe -> clé de la base (Argon2id).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Coût Argon2id : m = 64 Mio, t = 3, p = 1.
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

/// Dérive la clé de 32 octets de la base à partir de la phrase de passe et
/// du sel (16 octets aléatoires créés à `init`).
pub fn derive_key(pass: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        // Invariant : les paramètres ci-dessus sont des constantes valides.
        .expect("paramètres Argon2 constants et valides");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pass.as_bytes(), salt, key.as_mut())
        // Invariant : sel de 16 octets, sortie de 32 octets, pas de secret ni de
        // données associées : aucun paramètre ne peut être refusé.
        .expect("Argon2id accepte un sel de 16 octets et une sortie de 32 octets");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sensitive_to_inputs() {
        let salt = [7u8; 16];
        let k = derive_key("test", &salt);
        assert_eq!(*k, *derive_key("test", &salt));
        assert_ne!(*k, *derive_key("autre", &salt));
        assert_ne!(*k, *derive_key("test", &[8u8; 16]));
    }
}
