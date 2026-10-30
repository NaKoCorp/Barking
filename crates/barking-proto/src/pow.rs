//! Preuve de travail de dépôt : `BLAKE3(contexte, empreinte du contenu ‖ boîte ‖
//! nonce)` avec au moins `bits` bits de tête à zéro. L'empreinte du contenu
//! (`content_hash`) couvre tout le paquet encodé sauf `hops` : la preuve est
//! liée au contenu, un autre contenu sous le même identifiant en exige une autre.

use barking_packet::MailboxId;

/// Position de l'octet `hops` dans le paquet encodé.
const HOPS_OFFSET: usize = 2;

/// BLAKE3 du paquet encodé avec l'octet `hops` mis à zéro (il change d'un
/// relais à l'autre). Définition unique, partagée par le nœud (déduplication)
/// et le client (preuve de travail).
pub fn content_hash(packet_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    if packet_bytes.len() > HOPS_OFFSET {
        h.update(&packet_bytes[..HOPS_OFFSET]);
        h.update(&[0]);
        h.update(&packet_bytes[HOPS_OFFSET + 1..]);
    } else {
        h.update(packet_bytes);
    }
    *h.finalize().as_bytes()
}

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

fn digest(content: &[u8; 32], mailbox: &MailboxId, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(POW_CONTEXT);
    h.update(content);
    h.update(&mailbox.0);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Faux si `bits` dépasse `MAX_POW_BITS` : aucune preuve n'est valide au-delà.
pub fn check(content: &[u8; 32], mailbox: &MailboxId, nonce: u64, bits: u8) -> bool {
    bits <= MAX_POW_BITS && leading_zero_bits(&digest(content, mailbox, nonce)) >= u32::from(bits)
}

/// Cherche un nonce valide. Refuse (`None`) `bits > MAX_POW_BITS` : un nœud
/// hostile ne peut pas faire tourner le client indéfiniment.
pub fn solve(content: &[u8; 32], mailbox: &MailboxId, bits: u8) -> Option<u64> {
    if bits > MAX_POW_BITS {
        return None;
    }
    (0u64..).find(|n| check(content, mailbox, *n, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: [u8; 32] = [1; 32];
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
    fn content_hash_ignores_hops_only() {
        let a = vec![7u8; 64];
        let mut b = a.clone();
        b[2] = 1;
        assert_eq!(content_hash(&a), content_hash(&b));
        let mut c = a.clone();
        c[3] ^= 1;
        assert_ne!(content_hash(&a), content_hash(&c));
        let mut d = a.clone();
        d[40] ^= 1;
        assert_ne!(content_hash(&a), content_hash(&d));
        // Entrées courtes : pas de panique.
        let _ = content_hash(&[]);
        let _ = content_hash(&[1, 2]);
    }

    #[test]
    fn pow_solve_then_check() {
        let n = solve(&C, &MB, DEFAULT_POW_BITS).unwrap();
        assert!(check(&C, &MB, n, DEFAULT_POW_BITS));
    }

    #[test]
    fn pow_bound_to_content_and_mailbox() {
        let n = solve(&C, &MB, 16).unwrap();
        assert!(check(&C, &MB, n, 16));
        // Une autre entrée passe par hasard avec probabilité 2^-16 : on en
        // essaie plusieurs, la quasi-totalité doit échouer.
        let others = (0u8..32)
            .filter(|i| check(&[100 + i; 32], &MB, n, 16))
            .count()
            + (0u8..32)
                .filter(|i| check(&C, &MailboxId([100 + i; 16]), n, 16))
                .count();
        assert!(others <= 1, "{others} entrées inattendues valides");
    }

    #[test]
    fn pow_bits_monotonic() {
        let n = solve(&C, &MB, 20).unwrap();
        assert!(check(&C, &MB, n, 20));
        assert!(check(&C, &MB, n, DEFAULT_POW_BITS));
        assert!(check(&C, &MB, n, 0));
    }

    #[test]
    fn solve_refuses_bits_above_max() {
        assert_eq!(solve(&C, &MB, MAX_POW_BITS + 1), None);
        assert_eq!(solve(&C, &MB, 255), None);
        assert!(!check(&C, &MB, 0, 255));
        assert!(!check(&C, &MB, 0, MAX_POW_BITS + 1));
    }
}
