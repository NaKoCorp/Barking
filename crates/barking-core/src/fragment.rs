//! Fragmentation et réassemblage pour les liaisons à petite MTU (LoRa).
//!
//! Trame = 8 octets de `PacketId`, `index u8`, `count u8`, puis un morceau du paquet.

use crate::error::{CoreError, Result};
use crate::packet::PacketId;

/// Longueur de l'en-tête de trame.
pub const FRAG_HEADER_LEN: usize = 10;
/// MTU minimale acceptée : en-tête + 64 octets de données.
const MIN_MTU: usize = 74;

/// Découpe `packet` en trames d'au plus `mtu` octets (en-tête de trame compris).
///
/// Exige `mtu >= 74` et au plus 255 trames, sinon `TooLarge`. Un paquet vide
/// donne tout de même une trame.
pub fn fragment(packet: &[u8], id: &PacketId, mtu: usize) -> Result<Vec<Vec<u8>>> {
    if mtu < MIN_MTU {
        return Err(CoreError::TooLarge);
    }
    let chunk = mtu - FRAG_HEADER_LEN;
    let count = packet.len().div_ceil(chunk).max(1);
    let count_u8 = u8::try_from(count).map_err(|_| CoreError::TooLarge)?;
    let mut frames = Vec::with_capacity(count);
    for index in 0..count {
        let part = packet.chunks(chunk).nth(index).unwrap_or(&[]);
        let mut f = Vec::with_capacity(FRAG_HEADER_LEN + part.len());
        f.extend_from_slice(&id.0[..8]);
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
/// incomplets, chacun d'au plus 255 morceaux de longueur cohérente.
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
        if count == 1 {
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
        if entry.parts[index].is_some() {
            return Ok(None);
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
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Kind, Packet, Tier};
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
        let frames = fragment(&pkt, &pid(1), 200).unwrap();
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
        let frames = fragment(&enc, &p.id, 255).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 255);
    }

    #[test]
    fn single_frame_when_fits() {
        let pkt = bytes(50, 0);
        let frames = fragment(&pkt, &pid(3), 255).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][9], 1);
        let mut r = Reassembler::new(4, 60);
        assert_eq!(r.push(&frames[0], 0).unwrap().unwrap(), pkt);
    }

    #[test]
    fn duplicates_ignored() {
        let pkt = bytes(500, 9);
        let frames = fragment(&pkt, &pid(4), 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 0).unwrap().is_none());
        assert_eq!(r.push(&frames[2], 0).unwrap().unwrap(), pkt);
    }

    #[test]
    fn missing_fragment_never_completes_then_expires() {
        let pkt = bytes(500, 9);
        let frames = fragment(&pkt, &pid(5), 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        assert!(r.push(&frames[0], 0).unwrap().is_none());
        assert!(r.push(&frames[1], 10).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        // Après expiration, l'entrée est purgée : le dernier fragment seul ne complète rien.
        assert!(r.push(&frames[2], 100).unwrap().is_none());
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn pending_bounded() {
        let mut r = Reassembler::new(4, 1000);
        for n in 0..10u8 {
            let frames = fragment(&bytes(500, n), &pid(n), 200).unwrap();
            assert!(r.push(&frames[0], n as u64).unwrap().is_none());
            assert!(r.pending() <= 4);
        }
        assert_eq!(r.pending(), 4);
    }

    #[test]
    fn mtu_too_small_rejected() {
        assert_eq!(
            fragment(&bytes(100, 0), &pid(1), 73),
            Err(CoreError::TooLarge)
        );
        assert!(fragment(&bytes(100, 0), &pid(1), 74).is_ok());
    }

    #[test]
    fn too_many_fragments_rejected() {
        assert_eq!(
            fragment(&bytes(64 * 256, 0), &pid(1), 74),
            Err(CoreError::TooLarge)
        );
        assert_eq!(
            fragment(&bytes(64 * 255, 0), &pid(1), 74).unwrap().len(),
            255
        );
    }

    #[test]
    fn inconsistent_count_rejected() {
        let frames = fragment(&bytes(500, 1), &pid(6), 200).unwrap();
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
        fn proptest_roundtrip(len in 1usize..3000, mtu in 74usize..400) {
            let pkt = bytes(len, 7);
            if let Ok(frames) = fragment(&pkt, &pid(9), mtu) {
                let mut r = Reassembler::new(2, 60);
                let mut out = None;
                for f in &frames { out = r.push(f, 0).unwrap(); }
                prop_assert_eq!(out.unwrap(), pkt);
            }
        }
    }
}
