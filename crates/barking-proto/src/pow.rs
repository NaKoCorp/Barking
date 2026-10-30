//! Preuve de travail de dépôt : `BLAKE3(contexte, id ‖ boîte ‖ nonce)` avec
//! au moins `bits` bits de tête à zéro.

use barking_packet::{MailboxId, PacketId};

/// Contexte BLAKE3 de la preuve de travail de dépôt.
pub const POW_CONTEXT: &str = "barking/v0/deposit-pow";
pub const DEFAULT_POW_BITS: u8 = 18;
pub const MAX_POW_BITS: u8 = 24;

/// Nombre de bits à zéro en tête de `bytes`.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for b in bytes {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

fn digest(id: &PacketId, mailbox: &MailboxId, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(POW_CONTEXT);
    h.update(&id.0);
    h.update(&mailbox.0);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn check(id: &PacketId, mailbox: &MailboxId, nonce: u64, bits: u8) -> bool {
    leading_zero_bits(&digest(id, mailbox, nonce)) >= u32::from(bits)
}

/// Cherche un nonce valide pour `bits` (au plus `MAX_POW_BITS` en pratique).
pub fn solve(id: &PacketId, mailbox: &MailboxId, bits: u8) -> u64 {
    (0u64..)
        .find(|n| check(id, mailbox, *n, bits))
        .expect("un nonce existe toujours dans l'espace u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: PacketId = PacketId([1; 16]);
    const MB: MailboxId = MailboxId([2; 16]);

    #[test]
    fn leading_zero_bits_counts() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x7f]), 1);
        assert_eq!(leading_zero_bits(&[0x00, 0x10]), 11);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn pow_solve_then_check() {
        let n = solve(&ID, &MB, DEFAULT_POW_BITS);
        assert!(check(&ID, &MB, n, DEFAULT_POW_BITS));
    }

    #[test]
    fn pow_bound_to_packet_and_mailbox() {
        let n = solve(&ID, &MB, 16);
        assert!(check(&ID, &MB, n, 16));
        // Une autre entrée passe par hasard avec probabilité 2^-16 : on en
        // essaie plusieurs, la quasi-totalité doit échouer.
        let others = (0u8..32)
            .filter(|i| check(&PacketId([100 + i; 16]), &MB, n, 16))
            .count()
            + (0u8..32)
                .filter(|i| check(&ID, &MailboxId([100 + i; 16]), n, 16))
                .count();
        assert!(others <= 1, "{others} entrées inattendues valides");
    }

    #[test]
    fn pow_bits_monotonic() {
        let n = solve(&ID, &MB, 20);
        assert!(check(&ID, &MB, n, 20));
        assert!(check(&ID, &MB, n, DEFAULT_POW_BITS));
        assert!(check(&ID, &MB, n, 0));
    }
}
