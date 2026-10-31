//! Deposit proof of work: `BLAKE3(context, content fingerprint ‖ mailbox ‖
//! nonce)` with at least `bits` leading zero bits. The content fingerprint
//! (`content_hash`) covers the whole encoded packet except `hops`: the proof is
//! bound to the content, other content under the same identifier requires another.

use barking_packet::{MailboxId, Tier};

/// Position of the `hops` byte in the encoded packet.
const HOPS_OFFSET: usize = 2;

/// BLAKE3 of the encoded packet with the `hops` byte zeroed (it changes from
/// one relay to the next). Single definition, shared by the node (deduplication)
/// and the client (proof of work).
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

/// BLAKE3 context of the deposit proof of work.
pub const POW_CONTEXT: &str = "barking/v0/deposit-pow";
pub const DEFAULT_POW_BITS: u8 = 18;
pub const MAX_POW_BITS: u8 = 24;

/// Number of leading zero bits in `bytes`.
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

/// Difficulty bits added per tier: a large packet costs more
/// storage, hence more work (S +0, M +2, L +6).
pub fn tier_surcharge(tier: Tier) -> u8 {
    match tier {
        Tier::S => 0,
        Tier::M => 2,
        Tier::L => 6,
    }
}

/// BLAKE3 state after the context, the fingerprint and the mailbox: computed once
/// and cloned for each nonce.
fn prefix(content: &[u8; 32], mailbox: &MailboxId) -> blake3::Hasher {
    let mut h = blake3::Hasher::new_derive_key(POW_CONTEXT);
    h.update(content);
    h.update(&mailbox.0);
    h
}

fn passes(prefix: &blake3::Hasher, nonce: u64, bits: u8) -> bool {
    let mut h = prefix.clone();
    h.update(&nonce.to_le_bytes());
    leading_zero_bits(h.finalize().as_bytes()) >= u32::from(bits)
}

/// False if `bits` exceeds `MAX_POW_BITS`: no proof is valid beyond it.
pub fn check(content: &[u8; 32], mailbox: &MailboxId, nonce: u64, bits: u8) -> bool {
    bits <= MAX_POW_BITS && passes(&prefix(content, mailbox), nonce, bits)
}

/// Searches for a valid nonce. Rejects (`None`) `bits > MAX_POW_BITS`: a hostile
/// node cannot make the client spin forever.
pub fn solve(content: &[u8; 32], mailbox: &MailboxId, bits: u8) -> Option<u64> {
    if bits > MAX_POW_BITS {
        return None;
    }
    let p = prefix(content, mailbox);
    (0u64..).find(|n| passes(&p, *n, bits))
}

/// Expected work (average number of attempts) for `bits` bits: `2^bits`.
pub fn expected_work(bits: u8) -> u64 {
    1u64 << bits.min(63)
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
        // Short inputs: no panic.
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
        // Another input passes by chance with probability 2^-16: we try
        // several, almost all must fail.
        let others = (0u8..32)
            .filter(|i| check(&[100 + i; 32], &MB, n, 16))
            .count()
            + (0u8..32)
                .filter(|i| check(&C, &MailboxId([100 + i; 16]), n, 16))
                .count();
        assert!(others <= 1, "{others} unexpected valid inputs");
    }

    #[test]
    fn pow_bits_monotonic() {
        let n = solve(&C, &MB, 20).unwrap();
        assert!(check(&C, &MB, n, 20));
        assert!(check(&C, &MB, n, DEFAULT_POW_BITS));
        assert!(check(&C, &MB, n, 0));
    }

    #[test]
    fn precomputed_prefix_matches_one_shot_digest() {
        // Same result as the single-pass computation.
        for nonce in [0u64, 1, 0xdead_beef, u64::MAX] {
            let mut h = blake3::Hasher::new_derive_key(POW_CONTEXT);
            h.update(&C);
            h.update(&MB.0);
            h.update(&nonce.to_le_bytes());
            let want = leading_zero_bits(h.finalize().as_bytes());
            for bits in 0..=MAX_POW_BITS {
                assert_eq!(check(&C, &MB, nonce, bits), want >= u32::from(bits));
            }
        }
    }

    #[test]
    fn tier_surcharges() {
        assert_eq!(tier_surcharge(Tier::S), 0);
        assert_eq!(tier_surcharge(Tier::M), 2);
        assert_eq!(tier_surcharge(Tier::L), 6);
        assert_eq!(expected_work(18), 1 << 18);
    }

    #[test]
    fn solve_refuses_bits_above_max() {
        assert_eq!(solve(&C, &MB, MAX_POW_BITS + 1), None);
        assert_eq!(solve(&C, &MB, 255), None);
        assert!(!check(&C, &MB, 0, 255));
        assert!(!check(&C, &MB, 0, MAX_POW_BITS + 1));
    }
}
