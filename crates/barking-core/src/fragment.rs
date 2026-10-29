//! Fragmentation et réassemblage pour les liaisons à petite MTU (LoRa).
//!
//! Trame = 8 octets de clé (hash du paquet entier), `index u8`, `count u8`,
//! puis un morceau du paquet. Le réassemblage recalcule la clé : une trame
//! falsifiée ou contradictoire est détectée et l'entrée abandonnée.

use crate::crypto::labels::FRAME_CONTEXT;
use crate::error::{CoreError, Result};

/// Longueur de l'en-tête de trame.
pub const FRAG_HEADER_LEN: usize = 10;

/// Raison d'erreur : le paquet réassemblé ne correspond pas à la clé de trame.
pub const REASON_BAD_HASH: &str = "hash de trame incorrect";

/// Raison d'erreur : deux trames d'une même clé se contredisent.
pub const REASON_CONTRADICTORY: &str = "trames contradictoires";
/// Plus grand paquet décodable (palier L), en octets.
pub const MAX_PACKET_LEN: usize = 16_384;

/// Longueur maximale d'une trame : le plus grand paquet décodable (palier L)
/// tient en une seule trame avec son en-tête. `fragment` ne produit jamais de
/// trame plus longue, quelle que soit la MTU demandée, et le réassemblage
/// refuse toute trame plus longue.
pub const MAX_FRAME_LEN: usize = MAX_PACKET_LEN + FRAG_HEADER_LEN;

/// MTU minimale acceptée : en-tête + 64 octets de données.
const MIN_MTU: usize = 74;

/// Clé de trame : 8 premiers octets du hash BLAKE3 du paquet entier.
pub fn frame_key(packet: &[u8]) -> [u8; 8] {
    let h = blake3::derive_key(FRAME_CONTEXT, packet);
    let mut k = [0u8; 8];
    k.copy_from_slice(&h[..8]);
    k
}

/// Découpe `packet` en trames d'au plus `mtu` octets (en-tête de trame compris).
///
/// Exige `mtu >= 74`, un paquet d'au plus `MAX_PACKET_LEN` octets et au plus
/// 255 trames, sinon `TooLarge`. Une MTU plus grande que `MAX_FRAME_LEN` est
/// ramenée à `MAX_FRAME_LEN`. Un paquet vide donne tout de même une trame.
pub fn fragment(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
    if mtu < MIN_MTU || packet.len() > MAX_PACKET_LEN {
        return Err(CoreError::TooLarge);
    }
    let mtu = mtu.min(MAX_FRAME_LEN);
    let chunk = mtu - FRAG_HEADER_LEN;
    let count = packet.len().div_ceil(chunk).max(1);
    let count_u8 = u8::try_from(count).map_err(|_| CoreError::TooLarge)?;
    let key = frame_key(packet);
    let mut frames = Vec::with_capacity(count);
    for index in 0..count {
        let part = packet.chunks(chunk).nth(index).unwrap_or(&[]);
        let mut f = Vec::with_capacity(FRAG_HEADER_LEN + part.len());
        f.extend_from_slice(&key);
        // `index < count <= 255` : la conversion ne peut pas échouer.
        f.push(index as u8);
        f.push(count_u8);
        f.extend_from_slice(part);
        frames.push(f);
    }
    Ok(frames)
}

type Key = [u8; 8];

struct Entry {
    key: Key,
    first_seen: u64,
    count: usize,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    /// Longueur commune de tous les morceaux sauf le dernier.
    full_len: Option<usize>,
    last_len: Option<usize>,
}

/// Réassemble des trames. Mémoire bornée : au plus `max_pending` paquets
/// incomplets, chacun d'au plus 255 morceaux de longueur cohérente, dont
/// `count - 1` morceaux pleins tiennent dans `MAX_PACKET_LEN` : une entrée
/// garde au plus `MAX_PACKET_LEN` octets plus un morceau (moins de 32 Kio),
/// soit environ 2 Mio pour 64 paquets en attente.
pub struct Reassembler {
    max_pending: usize,
    ttl_secs: u64,
    /// Du plus ancien au plus récent.
    entries: Vec<Entry>,
}

impl Reassembler {
    pub fn new(max_pending: usize, ttl_secs: u64) -> Self {
        Reassembler {
            max_pending,
            ttl_secs,
            entries: Vec::new(),
        }
    }

    /// Nombre de paquets incomplets en attente.
    pub fn pending(&self) -> usize {
        self.entries.len()
    }

    pub fn push(&mut self, frame: &[u8], now: u64) -> Result<Option<Vec<u8>>> {
        let ttl = self.ttl_secs;
        self.entries
            .retain(|e| now.saturating_sub(e.first_seen) <= ttl);

        if frame.len() < FRAG_HEADER_LEN {
            return Err(CoreError::Malformed("trame trop courte"));
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(CoreError::Malformed("trame trop longue"));
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&frame[..8]);
        let index = usize::from(frame[8]);
        let count = usize::from(frame[9]);
        let chunk = &frame[FRAG_HEADER_LEN..];
        if count == 0 {
            return Err(CoreError::Malformed("nombre de fragments nul"));
        }
        if index >= count {
            return Err(CoreError::Malformed("index de fragment hors limites"));
        }
        if chunk.is_empty() && count > 1 {
            return Err(CoreError::Malformed("fragment vide"));
        }
        // Budget d'une entrée : les `count - 1` premiers morceaux ont tous la
        // longueur du plus long, donc `(count - 1) * len` ne dépasse jamais un
        // paquet décodable si la trame est légitime. Vaut pour le dernier
        // morceau aussi (il n'est pas plus long que les autres).
        if (count - 1).saturating_mul(chunk.len()) > MAX_PACKET_LEN {
            return Err(CoreError::Malformed("fragments trop volumineux"));
        }
        if count == 1 {
            if frame_key(chunk) != key {
                return Err(CoreError::Malformed(REASON_BAD_HASH));
            }
            return Ok(Some(chunk.to_vec()));
        }

        let pos = match self.entries.iter().position(|e| e.key == key) {
            Some(p) => p,
            None => {
                if self.max_pending == 0 {
                    return Ok(None);
                }
                while self.entries.len() >= self.max_pending {
                    self.entries.remove(0);
                }
                self.entries.push(Entry {
                    key,
                    first_seen: now,
                    count,
                    parts: vec![None; count],
                    received: 0,
                    full_len: None,
                    last_len: None,
                });
                self.entries.len() - 1
            }
        };
        let entry = &mut self.entries[pos];
        if entry.count != count {
            return Err(CoreError::Malformed("nombre de fragments incohérent"));
        }
        if let Some(prev) = &entry.parts[index] {
            if prev.as_slice() == chunk {
                return Ok(None);
            }
            // Deux contenus pour le même index : l'une des deux trames est
            // fausse, on abandonne tout le paquet.
            self.entries.remove(pos);
            return Err(CoreError::Malformed(REASON_CONTRADICTORY));
        }
        // Cohérence des longueurs : tous les morceaux sauf le dernier ont la
        // même longueur, et le dernier n'est pas plus long.
        let is_last = index == count - 1;
        let (full, last) = if is_last {
            (entry.full_len, Some(chunk.len()))
        } else {
            if entry.full_len.is_some_and(|f| f != chunk.len()) {
                return Err(CoreError::Malformed("longueur de fragment incohérente"));
            }
            (Some(chunk.len()), entry.last_len)
        };
        if let (Some(f), Some(l)) = (full, last)
            && l > f
        {
            return Err(CoreError::Malformed("longueur de fragment incohérente"));
        }
        entry.full_len = full;
        entry.last_len = last;
        entry.parts[index] = Some(chunk.to_vec());
        entry.received += 1;

        if entry.received < entry.count {
            return Ok(None);
        }
        let done = self.entries.remove(pos);
        let mut out = Vec::new();
        for p in done.parts.into_iter().flatten() {
            out.extend_from_slice(&p);
        }
        if frame_key(&out) != done.key {
            return Err(CoreError::Malformed(REASON_BAD_HASH));
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Kind, Packet, PacketId, Tier};
    use proptest::prelude::*;

    fn pid(n: u8) -> PacketId {
        PacketId([n; 16])
    }

    fn bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_add(seed)).collect()
    }

    #[test]
    fn lora_mtu_200() {
        let pkt = bytes(1024, 3);
        let frames = fragment(&pkt, 200).unwrap();
        assert_eq!(frames.len(), 6);
        assert!(frames.iter().all(|f| f.len() <= 200));
        let mut r = Reassembler::new(8, 60);
        let order = [3usize, 0, 5, 1, 4, 2];
        let mut out = None;
        for (n, &i) in order.iter().enumerate() {
            let res = r.push(&frames[i], 0).unwrap();
            if n < 5 {
                assert!(res.is_none());
            } else {
                out = res;
            }
        }
        assert_eq!(out.unwrap(), pkt);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn tier_s_fits_one_lora_frame() {
        let p = Packet {
            kind: Kind::Message,
            hops: 8,
            tier: Tier::S,
            id: pid(2),
            expires_at: 0,
            mailbox: crate::mailbox::MailboxId([0; 16]),
            payload: vec![1; 10],
        };
        let enc = p.encode();
        assert_eq!(enc.len(), 245);
        let frames = fragment(&enc, 255).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 255);
    }

    #[test]
    fn single_frame_when_fits() {
        let pkt = bytes(50, 0);
        let frames = fragment(&pkt, 255).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][9], 1);
        let mut r = Reassembler::new(4, 60);
        assert_eq!(r.push(&frames[0], 0).unwrap().unwrap(), pkt);
    }

    #[test]
    fn duplicates_ignored() {
        let pkt = bytes(500, 9);
        let frames = fragment(&pkt, 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 0).unwrap().is_none());
        assert_eq!(r.push(&frames[2], 0).unwrap().unwrap(), pkt);
    }

    #[test]
    fn missing_fragment_never_completes_then_expires() {
        let pkt = bytes(500, 9);
        let frames = fragment(&pkt, 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 10).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        // Une trame invalide déclenche la purge sans rien ajouter.
        assert!(r.push(&[0; 3], 100).is_err());
        assert_eq!(r.pending(), 0);
        // Le dernier fragment seul ne complète rien.
        assert!(r.push(&frames[2], 100).unwrap().is_none());
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn pending_bounded() {
        let mut r = Reassembler::new(4, 1000);
        for n in 0..10u8 {
            let frames = fragment(&bytes(500, n), 200).unwrap();
            assert!(r.push(&frames[0], n as u64).unwrap().is_none());
            assert!(r.pending() <= 4);
        }
        assert_eq!(r.pending(), 4);
        // Le plus ancien (0) a été évincé, le plus récent (9) survit.
        let f0 = fragment(&bytes(500, 0), 200).unwrap();
        assert!(r.push(&f0[1], 20).unwrap().is_none());
        assert!(r.push(&f0[2], 20).unwrap().is_none());
        let f9 = fragment(&bytes(500, 9), 200).unwrap();
        assert!(r.push(&f9[1], 20).unwrap().is_none());
        assert_eq!(r.push(&f9[2], 20).unwrap().unwrap(), bytes(500, 9));
    }

    #[test]
    fn mtu_too_small_rejected() {
        assert_eq!(fragment(&bytes(100, 0), 73), Err(CoreError::TooLarge));
        assert!(fragment(&bytes(100, 0), 74).is_ok());
    }

    #[test]
    fn too_many_fragments_rejected() {
        assert_eq!(fragment(&bytes(64 * 256, 0), 74), Err(CoreError::TooLarge));
        assert_eq!(fragment(&bytes(64 * 255, 0), 74).unwrap().len(), 255);
        assert_eq!(
            fragment(&bytes(MAX_PACKET_LEN + 1, 0), MAX_FRAME_LEN),
            Err(CoreError::TooLarge)
        );
    }

    #[test]
    fn inconsistent_count_rejected() {
        let frames = fragment(&bytes(500, 1), 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        r.push(&frames[0], 0).unwrap();
        let mut bad = frames[1].clone();
        bad[9] = 9;
        assert!(matches!(r.push(&bad, 0), Err(CoreError::Malformed(_))));
    }

    #[test]
    fn malformed_frames_rejected() {
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&[0; 9], 0).is_err());
        assert!(r.push(&[0; 10], 0).is_err()); // count = 0
        let mut f = vec![0u8; 8];
        f.extend_from_slice(&[5, 3, 1]); // index >= count
        assert!(r.push(&f, 0).is_err());
        let mut f = vec![0u8; 8];
        f.extend_from_slice(&[0, 3]); // morceau vide
        assert!(r.push(&f, 0).is_err());
    }

    #[test]
    fn frame_key_is_content_hash() {
        assert_eq!(frame_key(b"abc"), frame_key(b"abc"));
        assert_ne!(frame_key(b"abc"), frame_key(b"abd"));
        let p = bytes(500, 2);
        for f in fragment(&p, 200).unwrap() {
            assert_eq!(&f[..8], &frame_key(&p));
        }
    }

    #[test]
    fn single_frame_is_hash_checked() {
        let p = bytes(50, 1);
        let frames = fragment(&p, 255).unwrap();
        assert_eq!(frames.len(), 1);
        let mut r = Reassembler::new(4, 60);
        assert_eq!(r.push(&frames[0], 0).unwrap(), Some(p));
        let mut bad = frames[0].clone();
        bad[FRAG_HEADER_LEN + 3] ^= 1;
        assert!(r.push(&bad, 0).is_err());
    }

    #[test]
    fn tampered_chunk_never_yields() {
        let p = bytes(500, 4);
        let mut frames = fragment(&p, 200).unwrap();
        assert_eq!(frames.len(), 3);
        frames[1][FRAG_HEADER_LEN + 5] ^= 0x40;
        let mut r = Reassembler::new(4, 60);
        let n = frames.len();
        for (i, f) in frames.iter().enumerate() {
            let res = r.push(f, 0);
            assert!(!matches!(res, Ok(Some(_))));
            if i == n - 1 {
                assert!(res.is_err());
            }
        }
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn contradictory_index_drops_entry() {
        let p = bytes(500, 6);
        let frames = fragment(&p, 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        let mut forged = frames[0].clone();
        forged[FRAG_HEADER_LEN] ^= 1;
        assert!(matches!(r.push(&forged, 0), Err(CoreError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // Les trames légitimes reconstituent le paquet.
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 0).unwrap().is_none());
        assert_eq!(r.push(&frames[2], 0).unwrap().unwrap(), p);
    }

    #[test]
    fn identical_duplicate_ignored() {
        let p = bytes(500, 8);
        let frames = fragment(&p, 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[1], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 0).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert_eq!(r.push(&frames[2], 0).unwrap().unwrap(), p);
    }

    #[test]
    fn oversized_frame_refused() {
        let mut r = Reassembler::new(4, 60);
        // 64 Ko annoncés comme premier morceau d'un paquet en deux trames.
        let mut f = vec![7u8; 8];
        f.extend_from_slice(&[0, 2]);
        f.extend(std::iter::repeat_n(0xaa, 64 * 1024));
        assert!(matches!(r.push(&f, 0), Err(CoreError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // Même chose en une seule trame : refusée avant tout calcul de hash.
        let mut f = vec![7u8; 8];
        f.extend_from_slice(&[0, 1]);
        f.extend(std::iter::repeat_n(0xaa, 64 * 1024));
        assert!(matches!(r.push(&f, 0), Err(CoreError::Malformed(_))));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn entry_byte_budget_enforced() {
        let mut r = Reassembler::new(4, 60);
        // 255 morceaux de 1 000 octets : bien plus qu'un paquet de palier L.
        let mut f = vec![9u8; 8];
        f.extend_from_slice(&[0, 255]);
        f.extend(std::iter::repeat_n(0x55, 1000));
        assert!(matches!(r.push(&f, 0), Err(CoreError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // Le dernier morceau seul est soumis au même budget.
        let mut f = vec![9u8; 8];
        f.extend_from_slice(&[254, 255]);
        f.extend(std::iter::repeat_n(0x55, 1000));
        assert!(matches!(r.push(&f, 0), Err(CoreError::Malformed(_))));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn largest_packet_still_reassembles() {
        // Un paquet de palier L passe le budget, pour toute MTU qui le découpe en
        // 255 trames au plus (dès 75 octets).
        let p = bytes(Tier::L.size(), 3);
        for mtu in [75, 200, 255, 1500, MAX_FRAME_LEN, 100_000] {
            let frames = fragment(&p, mtu).unwrap();
            assert!(frames.iter().all(|f| f.len() <= MAX_FRAME_LEN));
            let mut r = Reassembler::new(4, 60);
            let mut out = None;
            for f in &frames {
                out = r.push(f, 0).unwrap();
            }
            assert_eq!(out.unwrap(), p, "mtu {mtu}");
        }
    }

    proptest! {
        #[test]
        fn any_order_with_duplicates_roundtrips(
            len in 1usize..4000,
            mtu in 74usize..=255,
            seed in any::<u64>(),
            dups in proptest::collection::vec(0usize..3, 64),
        ) {
            let p = bytes(len, 11);
            let Ok(frames) = fragment(&p, mtu) else { return Ok(()); };
            let mut seq: Vec<&Vec<u8>> = Vec::new();
            for (i, f) in frames.iter().enumerate() {
                // Un paquet d'une trame dupliqué rendrait deux fois le paquet.
                let extra = if frames.len() > 1 { dups[i % 64] } else { 0 };
                for _ in 0..=extra { seq.push(f); }
            }
            let n = seq.len();
            for i in (1..n).rev() {
                let j = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) >> 33) as usize % (i + 1);
                seq.swap(i, j);
            }
            let mut r = Reassembler::new(4, 60);
            let mut done = 0;
            for f in seq {
                // Des doublons arrivant après la complétion repartent sur une
                // nouvelle entrée qui peut se compléter à son tour : la
                // déduplication des paquets est l'affaire de la couche
                // au-dessus. Chaque paquet rendu doit être le bon.
                if let Some(out) = r.push(f, 0).unwrap() {
                    prop_assert_eq!(out, p.clone());
                    done += 1;
                }
            }
            prop_assert!(done >= 1);
        }
    }

    proptest! {
        #[test]
        fn proptest_push_never_panics(
            frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..60),
            times in proptest::collection::vec(0u64..200, 60),
        ) {
            let mut r = Reassembler::new(4, 50);
            for (f, t) in frames.iter().zip(times.iter()) {
                let _ = r.push(f, *t);
                prop_assert!(r.pending() <= 4);
            }
        }

        #[test]
        fn proptest_structured_never_panics(
            ops in proptest::collection::vec(
                (0u8..3, 0u8..7, 0u8..8, 0usize..4, 0u64..40, any::<u8>()),
                0..120,
            ),
        ) {
            const LENS: [usize; 4] = [0, 1, 5, 64];
            let mut r = Reassembler::new(2, 30);
            let mut now = 0u64;
            for (k, count, index, li, dt, fill) in ops {
                now += dt;
                let mut f = vec![k; 8];
                f.push(index);
                f.push(count);
                f.extend(std::iter::repeat_n(fill, LENS[li]));
                if let Ok(Some(out)) = r.push(&f, now) {
                    prop_assert!(!out.is_empty() || count <= 1);
                }
                prop_assert!(r.pending() <= 2);
            }
        }

        #[test]
        fn proptest_corrupted_frames_never_panic(
            len in 1usize..3000,
            mtu in 74usize..300,
            drops in proptest::collection::vec(any::<bool>(), 64),
            dups in proptest::collection::vec(0usize..3, 64),
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..6),
            seed in any::<u64>(),
        ) {
            let pkt = bytes(len, 5);
            let Ok(mut frames) = fragment(&pkt, mtu) else { return Ok(()); };
            // Ordre mélangé (déterministe selon la graine).
            let n = frames.len();
            for i in (1..n).rev() {
                let j = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) >> 33) as usize % (i + 1);
                frames.swap(i, j);
            }
            // Un jeu complet, mélangé : doit toujours se réassembler.
            let mut r = Reassembler::new(4, 60);
            let mut out = None;
            for f in &frames { out = r.push(f, 0).unwrap(); }
            prop_assert_eq!(out.unwrap(), pkt);
            // Même jeu avec pertes, doublons et corruption : aucune panique.
            let mut r = Reassembler::new(4, 60);
            for (i, f) in frames.iter().enumerate() {
                if drops[i % 64] { continue; }
                let mut f = f.clone();
                for (pos, b) in &flips {
                    if !f.is_empty() { let p = pos % f.len(); f[p] ^= b; }
                }
                for _ in 0..=dups[i % 64] {
                    let _ = r.push(&f, i as u64);
                    prop_assert!(r.pending() <= 4);
                }
            }
        }

        #[test]
        fn proptest_corruption_never_yields_wrong_packet(
            len in 1usize..3000,
            mtu in 74usize..300,
            drops in proptest::collection::vec(any::<bool>(), 64),
            dups in proptest::collection::vec(0usize..3, 64),
            flips in proptest::collection::vec((any::<usize>(), any::<usize>(), 1u8..=255), 1..6),
            seed in any::<u64>(),
        ) {
            let pkt = bytes(len, 13);
            let Ok(mut frames) = fragment(&pkt, mtu) else { return Ok(()); };
            let n = frames.len();
            for i in (1..n).rev() {
                let j = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) >> 33) as usize % (i + 1);
                frames.swap(i, j);
            }
            // Corruption d'octets quelconques (en-tête compris) de trames quelconques.
            for (fi, pos, b) in &flips {
                let f = &mut frames[fi % n];
                let p = pos % f.len();
                f[p] ^= b;
            }
            let mut r = Reassembler::new(4, 60);
            for (i, f) in frames.iter().enumerate() {
                if drops[i % 64] { continue; }
                for _ in 0..=dups[i % 64] {
                    if let Ok(Some(out)) = r.push(f, 0) {
                        prop_assert_eq!(&out, &pkt);
                    }
                }
            }
        }

        #[test]
        fn proptest_roundtrip(len in 1usize..3000, mtu in 74usize..400) {
            let pkt = bytes(len, 7);
            if let Ok(frames) = fragment(&pkt, mtu) {
                let mut r = Reassembler::new(2, 60);
                let mut out = None;
                for f in &frames { out = r.push(f, 0).unwrap(); }
                prop_assert_eq!(out.unwrap(), pkt);
            }
        }
    }
}
