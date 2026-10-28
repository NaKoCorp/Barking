//! Code de sécurité : 12 groupes de 5 chiffres, identique des deux côtés.

use super::root::Fingerprint;
use crate::crypto::labels;

/// Code de sécurité entre deux empreintes (indépendant de l'ordre).
pub fn safety_number(a: &Fingerprint, b: &Fingerprint) -> String {
    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(labels::SAFETY_NUMBER);
    hasher.update(&lo.0);
    hasher.update(&hi.0);
    let mut digest = [0u8; 60]; // 12 groupes x 5 octets
    hasher.finalize_xof().fill(&mut digest);
    digest
        .chunks_exact(5)
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[3..].copy_from_slice(c);
            format!("{:05}", u64::from_be_bytes(buf) % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_symmetric_and_shaped() {
        let fa = Fingerprint([1; 32]);
        let fb = Fingerprint([2; 32]);
        let s1 = safety_number(&fa, &fb);
        assert_eq!(s1, safety_number(&fb, &fa));
        assert_eq!(s1.split(' ').count(), 12);
        assert!(
            s1.split(' ')
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
    }

    #[test]
    fn safety_number_differs_per_pair() {
        let (a, b, c) = (
            Fingerprint([1; 32]),
            Fingerprint([2; 32]),
            Fingerprint([3; 32]),
        );
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }
}
