//! Fragmentation and reassembly for small-MTU links (LoRa).
//!
//! Frame = 8 key bytes (hash of the whole packet), `index u8`, `count u8`,
//! then a chunk of the packet. Reassembly recomputes the key: a forged
//! or contradictory frame is detected and the entry dropped.

use crate::error::{PacketError, Result};
use crate::labels::FRAME_CONTEXT;

/// Length of the frame header.
pub const FRAG_HEADER_LEN: usize = 10;

/// Error reason: the reassembled packet does not match the frame key.
pub const REASON_BAD_HASH: &str = "bad frame hash";

/// Error reason: two frames with the same key contradict each other.
pub const REASON_CONTRADICTORY: &str = "contradictory frames";
/// Largest decodable packet (tier L), in bytes.
pub const MAX_PACKET_LEN: usize = 16_384;

/// Maximum frame length: the largest decodable packet (tier L)
/// fits in a single frame together with its header. `fragment` never produces a
/// longer frame, whatever MTU is requested, and reassembly
/// rejects any longer frame.
pub const MAX_FRAME_LEN: usize = MAX_PACKET_LEN + FRAG_HEADER_LEN;

/// Minimum accepted MTU: header + 64 bytes of data.
const MIN_MTU: usize = 74;

/// Frame key: first 8 bytes of the BLAKE3 hash of the whole packet.
pub fn frame_key(packet: &[u8]) -> [u8; 8] {
    let h = blake3::derive_key(FRAME_CONTEXT, packet);
    let mut k = [0u8; 8];
    k.copy_from_slice(&h[..8]);
    k
}

/// Splits `packet` into frames of at most `mtu` bytes (frame header included).
///
/// Requires `mtu >= 74`, a packet of at most `MAX_PACKET_LEN` bytes and at most
/// 255 frames, otherwise `TooLarge`. An MTU larger than `MAX_FRAME_LEN` is
/// clamped to `MAX_FRAME_LEN`. An empty packet still yields one frame.
pub fn fragment(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
    if mtu < MIN_MTU || packet.len() > MAX_PACKET_LEN {
        return Err(PacketError::TooLarge);
    }
    let mtu = mtu.min(MAX_FRAME_LEN);
    let chunk = mtu - FRAG_HEADER_LEN;
    let count = packet.len().div_ceil(chunk).max(1);
    let count_u8 = u8::try_from(count).map_err(|_| PacketError::TooLarge)?;
    let key = frame_key(packet);
    let frame = |index: usize, part: &[u8]| {
        let mut f = Vec::with_capacity(FRAG_HEADER_LEN + part.len());
        f.extend_from_slice(&key);
        // `index < count <= 255`: the conversion cannot fail.
        f.push(index as u8);
        f.push(count_u8);
        f.extend_from_slice(part);
        f
    };
    // An empty packet has no chunk but still yields one frame.
    if packet.is_empty() {
        return Ok(vec![frame(0, &[])]);
    }
    Ok(packet
        .chunks(chunk)
        .enumerate()
        .map(|(index, part)| frame(index, part))
        .collect())
}

type Key = [u8; 8];

struct Entry {
    key: Key,
    first_seen: u64,
    count: usize,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    /// Common length of all chunks except the last.
    full_len: Option<usize>,
    last_len: Option<usize>,
}

/// Reassembles frames. Bounded memory: at most `max_pending` incomplete
/// packets, each of at most 255 chunks of consistent length, of which
/// `count - 1` full chunks fit in `MAX_PACKET_LEN`: an entry
/// holds at most `MAX_PACKET_LEN` bytes plus one chunk (under 32 KiB),
/// i.e. about 2 MiB for 64 pending packets.
pub struct Reassembler {
    max_pending: usize,
    ttl_secs: u64,
    /// From oldest to most recent.
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

    /// Number of incomplete packets pending.
    pub fn pending(&self) -> usize {
        self.entries.len()
    }

    /// Adds a received frame. Returns the whole packet once its last
    /// missing frame arrives (its hash checked against the frame key),
    /// `None` while frames are missing or for a repeated frame. Entries
    /// older than the TTL are dropped first; a new packet beyond
    /// `max_pending` evicts the oldest one (none is kept when it is 0). A
    /// malformed or inconsistent frame is an error (`Malformed`); two
    /// contents for the same index drop the whole packet. Never panics on
    /// arbitrary bytes.
    pub fn push(&mut self, frame: &[u8], now: u64) -> Result<Option<Vec<u8>>> {
        let ttl = self.ttl_secs;
        self.entries
            .retain(|e| now.saturating_sub(e.first_seen) <= ttl);

        if frame.len() < FRAG_HEADER_LEN {
            return Err(PacketError::Malformed("frame too short"));
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(PacketError::Malformed("frame too long"));
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&frame[..8]);
        let index = usize::from(frame[8]);
        let count = usize::from(frame[9]);
        let chunk = &frame[FRAG_HEADER_LEN..];
        if count == 0 {
            return Err(PacketError::Malformed("fragment count is zero"));
        }
        if index >= count {
            return Err(PacketError::Malformed("fragment index out of range"));
        }
        if chunk.is_empty() && count > 1 {
            return Err(PacketError::Malformed("empty fragment"));
        }
        // Budget of an entry: the first `count - 1` chunks all have the
        // length of the longest, so `(count - 1) * len` never exceeds a
        // decodable packet if the frame is legitimate. Holds for the last
        // chunk too (it is no longer than the others).
        if (count - 1).saturating_mul(chunk.len()) > MAX_PACKET_LEN {
            return Err(PacketError::Malformed("fragments too large"));
        }
        if count == 1 {
            if frame_key(chunk) != key {
                return Err(PacketError::Malformed(REASON_BAD_HASH));
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
            return Err(PacketError::Malformed("inconsistent fragment count"));
        }
        if let Some(prev) = &entry.parts[index] {
            if prev.as_slice() == chunk {
                return Ok(None);
            }
            // Two contents for the same index: one of the two frames is
            // false, so the whole packet is dropped.
            self.entries.remove(pos);
            return Err(PacketError::Malformed(REASON_CONTRADICTORY));
        }
        // Length consistency: all chunks except the last have the
        // same length, and the last is no longer.
        let is_last = index == count - 1;
        let (full, last) = if is_last {
            (entry.full_len, Some(chunk.len()))
        } else {
            if entry.full_len.is_some_and(|f| f != chunk.len()) {
                return Err(PacketError::Malformed("inconsistent fragment length"));
            }
            (Some(chunk.len()), entry.last_len)
        };
        if let (Some(f), Some(l)) = (full, last)
            && l > f
        {
            return Err(PacketError::Malformed("inconsistent fragment length"));
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
            return Err(PacketError::Malformed(REASON_BAD_HASH));
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, Packet, PacketId, Tier};
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
            mailbox: crate::MailboxId([0; 16]),
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
        // An invalid frame triggers the purge without adding anything.
        assert!(r.push(&[0; 3], 100).is_err());
        assert_eq!(r.pending(), 0);
        // The last fragment alone completes nothing.
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
        // The oldest (0) was evicted, the most recent (9) survives.
        let f0 = fragment(&bytes(500, 0), 200).unwrap();
        assert!(r.push(&f0[1], 20).unwrap().is_none());
        assert!(r.push(&f0[2], 20).unwrap().is_none());
        let f9 = fragment(&bytes(500, 9), 200).unwrap();
        assert!(r.push(&f9[1], 20).unwrap().is_none());
        assert_eq!(r.push(&f9[2], 20).unwrap().unwrap(), bytes(500, 9));
    }

    #[test]
    fn mtu_too_small_rejected() {
        assert_eq!(fragment(&bytes(100, 0), 73), Err(PacketError::TooLarge));
        assert!(fragment(&bytes(100, 0), 74).is_ok());
    }

    #[test]
    fn too_many_fragments_rejected() {
        assert_eq!(
            fragment(&bytes(64 * 256, 0), 74),
            Err(PacketError::TooLarge)
        );
        assert_eq!(fragment(&bytes(64 * 255, 0), 74).unwrap().len(), 255);
        assert_eq!(
            fragment(&bytes(MAX_PACKET_LEN + 1, 0), MAX_FRAME_LEN),
            Err(PacketError::TooLarge)
        );
    }

    #[test]
    fn inconsistent_count_rejected() {
        let frames = fragment(&bytes(500, 1), 200).unwrap();
        let mut r = Reassembler::new(4, 60);
        r.push(&frames[0], 0).unwrap();
        let mut bad = frames[1].clone();
        bad[9] = 9;
        assert!(matches!(r.push(&bad, 0), Err(PacketError::Malformed(_))));
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
        f.extend_from_slice(&[0, 3]); // empty chunk
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
        assert!(matches!(r.push(&forged, 0), Err(PacketError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // Legitimate frames rebuild the packet.
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
        // 64 KB announced as the first chunk of a two-frame packet.
        let mut f = vec![7u8; 8];
        f.extend_from_slice(&[0, 2]);
        f.extend(std::iter::repeat_n(0xaa, 64 * 1024));
        assert!(matches!(r.push(&f, 0), Err(PacketError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // Same thing in a single frame: rejected before any hash computation.
        let mut f = vec![7u8; 8];
        f.extend_from_slice(&[0, 1]);
        f.extend(std::iter::repeat_n(0xaa, 64 * 1024));
        assert!(matches!(r.push(&f, 0), Err(PacketError::Malformed(_))));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn entry_byte_budget_enforced() {
        let mut r = Reassembler::new(4, 60);
        // 255 chunks of 1,000 bytes: far more than a tier L packet.
        let mut f = vec![9u8; 8];
        f.extend_from_slice(&[0, 255]);
        f.extend(std::iter::repeat_n(0x55, 1000));
        assert!(matches!(r.push(&f, 0), Err(PacketError::Malformed(_))));
        assert_eq!(r.pending(), 0);
        // The last chunk alone is subject to the same budget.
        let mut f = vec![9u8; 8];
        f.extend_from_slice(&[254, 255]);
        f.extend(std::iter::repeat_n(0x55, 1000));
        assert!(matches!(r.push(&f, 0), Err(PacketError::Malformed(_))));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn largest_packet_still_reassembles() {
        // A tier L packet passes the budget, for any MTU that splits it into
        // at most 255 frames (from 75 bytes).
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
                // A duplicated one-frame packet would yield the packet twice.
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
                // Duplicates arriving after completion start over on a
                // new entry that may complete in turn: packet
                // deduplication is the job of the layer
                // above. Each returned packet must be the right one.
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
            // Shuffled order (deterministic given the seed).
            let n = frames.len();
            for i in (1..n).rev() {
                let j = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) >> 33) as usize % (i + 1);
                frames.swap(i, j);
            }
            // A full set, shuffled: must always reassemble.
            let mut r = Reassembler::new(4, 60);
            let mut out = None;
            for f in &frames { out = r.push(f, 0).unwrap(); }
            prop_assert_eq!(out.unwrap(), pkt);
            // Same set with losses, duplicates and corruption: no panic.
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
            // Arbitrary byte corruption (header included) of arbitrary frames.
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
