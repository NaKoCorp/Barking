use super::*;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn sample(tier: Tier, len: usize) -> Packet {
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: PacketId([7; 16]),
        expires_at: 1_700_000_000,
        mailbox: MailboxId([9; 16]),
        payload: (0..len).map(|i| i as u8).collect(),
    }
}

#[test]
fn roundtrip_each_tier() {
    for (t, n) in [
        (Tier::S, 203),
        (Tier::M, 500),
        (Tier::L, 16342),
        (Tier::S, 0),
    ] {
        let p = sample(t, n);
        assert_eq!(Packet::decode(&p.encode()).unwrap(), p);
    }
}

#[test]
fn encoded_len_equals_tier() {
    assert_eq!(sample(Tier::S, 10).encode().len(), 245);
    assert_eq!(sample(Tier::M, 10).encode().len(), 1024);
    assert_eq!(sample(Tier::L, 10).encode().len(), 16384);
}

#[test]
fn max_payload_s_is_203() {
    assert_eq!(Tier::fit(203).unwrap(), Tier::S);
    assert_eq!(Tier::fit(204).unwrap(), Tier::M);
    assert_eq!(Tier::fit(982).unwrap(), Tier::M);
    assert_eq!(Tier::fit(983).unwrap(), Tier::L);
}

#[test]
fn too_large_rejected() {
    assert_eq!(Tier::fit(16342).unwrap(), Tier::L);
    assert_eq!(Tier::fit(16343), Err(PacketError::TooLarge));
    assert_eq!(Tier::fit(usize::MAX), Err(PacketError::TooLarge));
}

#[test]
fn ack_verifies_only_with_secret() {
    let mut rng = StdRng::seed_from_u64(1);
    let secret = ack::new_secret(&mut rng);
    let other = ack::new_secret(&mut rng);
    assert_ne!(secret, other);
    let id = ack::packet_id_for(&secret);
    assert!(ack::verify(&id, &secret));
    assert!(!ack::verify(&id, &other));
}

#[test]
fn ack_packet_carries_id_and_secret() {
    let mut rng = StdRng::seed_from_u64(2);
    let secret = ack::new_secret(&mut rng);
    let mut acked = sample(Tier::M, 50);
    acked.id = ack::packet_id_for(&secret);
    let now = 1_000_000;
    let a = Packet::ack(&acked, secret, now, &mut rng);
    assert_eq!(a.kind, Kind::Ack);
    assert_eq!(a.tier, Tier::S);
    assert_eq!(a.mailbox, acked.mailbox);
    assert_eq!(a.hops, DEFAULT_HOPS);
    assert_eq!(a.expires_at as u64, now + DEFAULT_TTL_SECS);
    assert_ne!(a.id, acked.id);
    assert_eq!(&a.payload[..16], &acked.id.0);
    assert_eq!(&a.payload[16..], &secret);
    assert_eq!(Packet::decode(&a.encode()).unwrap(), a);
    // saturation
    let late = Packet::ack(&acked, secret, u64::MAX, &mut rng);
    assert_eq!(late.expires_at, u32::MAX);
}

#[test]
fn decode_rejects_truncated() {
    let e = sample(Tier::S, 10).encode();
    assert!(Packet::decode(&e[..244]).is_err());
    assert!(Packet::decode(&[]).is_err());
    let mut long = e.clone();
    long.push(0);
    assert!(Packet::decode(&long).is_err());
}

#[test]
fn decode_rejects_bad_version() {
    let mut e = sample(Tier::S, 10).encode();
    e[0] = 1;
    assert!(Packet::decode(&e).is_err());
}

#[test]
fn decode_rejects_unknown_tier_and_kind() {
    let mut e = sample(Tier::S, 10).encode();
    e[3] = 9;
    assert!(Packet::decode(&e).is_err());
    let mut e = sample(Tier::S, 10).encode();
    e[1] = 9;
    assert!(Packet::decode(&e).is_err());
}

#[test]
fn decode_rejects_lying_length() {
    let mut e = sample(Tier::S, 10).encode();
    e[40] = 0xFF;
    e[41] = 0xFF;
    assert!(Packet::decode(&e).is_err());
    // 204 > 203 in tier S
    e[40] = 0;
    e[41] = 204;
    assert!(Packet::decode(&e).is_err());
}

#[test]
fn decode_rejects_nonzero_padding() {
    let mut e = sample(Tier::S, 10).encode();
    *e.last_mut().unwrap() = 1;
    assert!(Packet::decode(&e).is_err());
    let mut e = sample(Tier::S, 10).encode();
    e[42 + 10] = 1;
    assert!(Packet::decode(&e).is_err());
}

#[test]
fn encode_oversized_payload_truncates_to_tier_size() {
    let p = sample(Tier::S, 500);
    let e = p.encode();
    assert_eq!(e.len(), Tier::S.size());
    let d = Packet::decode(&e).unwrap();
    assert_eq!(d.payload, p.payload[..203].to_vec());
}

proptest! {
    #[test]
    fn proptest_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20000)) {
        let _ = Packet::decode(&bytes);
    }

    #[test]
    fn proptest_decode_exact_size_never_panics(
        tier in 0u8..3,
        kind in 0u8..3,
        len in any::<u16>(),
        body in proptest::collection::vec(any::<u8>(), 0..300),
        pad_byte in any::<u8>(),
    ) {
        let size = [245usize, 1024, 16384][tier as usize];
        let mut b = vec![0u8, kind, 8, tier];
        b.extend_from_slice(&[0u8; 36]);
        b.extend_from_slice(&len.to_be_bytes());
        b.extend(body);
        b.resize(size, pad_byte % 2);
        let _ = Packet::decode(&b);
    }
}
