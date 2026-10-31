//! Passphrase -> database key (Argon2id).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id cost: m = 64 MiB, t = 3, p = 1.
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

/// Derives the 32-byte database key from the passphrase and the salt
/// (16 random bytes created at `init`).
pub fn derive_key(pass: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        // Invariant: the parameters above are valid constants.
        .expect("constant, valid Argon2 parameters");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pass.as_bytes(), salt, key.as_mut())
        // Invariant: 16-byte salt, 32-byte output, no secret and no associated
        // data: no parameter can be rejected.
        .expect("Argon2id accepts a 16-byte salt and a 32-byte output");
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
