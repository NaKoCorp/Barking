use super::*;
use barking_packet::{DEFAULT_HOPS, Kind, MailboxId, Packet, PacketId, Tier};
use barking_proto::pow;

const NOW: u64 = 1_800_000_000;
const BITS: u8 = 4;

fn policy() -> Policy {
    Policy {
        pow_bits: BITS,
        max_per_mailbox: 1_000,
        storage_max_bytes: 1 << 30,
    }
}

fn store() -> (tempfile::TempDir, NodeStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = NodeStore::open(dir.path().join("node.db")).unwrap();
    (dir, s)
}

fn mb(n: u8) -> MailboxId {
    MailboxId([n; 16])
}

fn msg(n: u8, mailbox: u8, tier: Tier, expires_at: u64) -> Packet {
    let mut id = [0u8; 16];
    id[0] = n;
    id[1] = mailbox;
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier,
        id: PacketId(id),
        expires_at: u32::try_from(expires_at).unwrap(),
        mailbox: mb(mailbox),
        payload: vec![n; 8],
    }
}

fn nonce(p: &Packet) -> u64 {
    pow::solve(&p.id, &p.mailbox, BITS).unwrap()
}

fn put(s: &mut NodeStore, p: &Packet) -> core::result::Result<(), ErrorReason> {
    deposit(s, &policy(), &p.encode(), nonce(p), NOW).unwrap()
}

fn ok_msg(n: u8, mailbox: u8) -> Packet {
    msg(n, mailbox, Tier::S, NOW + 86_400)
}

/// Un message et son accusé (secret fixe) dans la boîte du message.
fn msg_and_ack(n: u8, mailbox: u8) -> (Packet, [u8; 16], Packet) {
    let secret = [n; 16];
    let mut m = ok_msg(n, mailbox);
    m.id = ack::packet_id_for(&secret);
    let mut payload = m.id.0.to_vec();
    payload.extend_from_slice(&secret);
    let a = Packet {
        kind: Kind::Ack,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId([0xA0 + n; 16]),
        expires_at: u32::try_from(NOW + 86_400).unwrap(),
        mailbox: m.mailbox,
        payload,
    };
    (m, secret, a)
}

fn put_ack(s: &mut NodeStore, a: &Packet) -> core::result::Result<(), ErrorReason> {
    deposit(s, &policy(), &a.encode(), 0, NOW).unwrap()
}

#[test]
fn rejects_malformed() {
    let (_d, mut s) = store();
    let r = deposit(&mut s, &policy(), &[1, 2, 3], 0, NOW).unwrap();
    assert_eq!(r, Err(ErrorReason::Malformed));
    let mut bytes = ok_msg(1, 1).encode();
    bytes[0] = 9; // version inconnue
    assert_eq!(
        deposit(&mut s, &policy(), &bytes, 0, NOW).unwrap(),
        Err(ErrorReason::Malformed)
    );
}

#[test]
fn rejects_expired() {
    let (_d, mut s) = store();
    let p = msg(1, 1, Tier::S, NOW);
    assert_eq!(put(&mut s, &p), Err(ErrorReason::Expired));
    let p = msg(2, 1, Tier::S, NOW - 10);
    assert_eq!(put(&mut s, &p), Err(ErrorReason::Expired));
}

#[test]
fn rejects_too_far_in_future() {
    let (_d, mut s) = store();
    let p = msg(1, 1, Tier::S, NOW + MAX_EXPIRY_SECS + 1);
    assert_eq!(put(&mut s, &p), Err(ErrorReason::TooFarInFuture));
}

#[test]
fn rejects_wrong_tier() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    let mut bytes = p.encode();
    bytes.push(0); // 246 octets pour le palier S
    assert_eq!(
        deposit(&mut s, &policy(), &bytes, nonce(&p), NOW).unwrap(),
        Err(ErrorReason::WrongTier)
    );
    let mut short = p.encode();
    short.truncate(200);
    assert_eq!(
        deposit(&mut s, &policy(), &short, nonce(&p), NOW).unwrap(),
        Err(ErrorReason::WrongTier)
    );
}

#[test]
fn rejects_weak_pow() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    let strict = Policy {
        pow_bits: 20,
        ..policy()
    };
    let r = deposit(&mut s, &strict, &p.encode(), nonce(&p), NOW).unwrap();
    assert_eq!(r, Err(ErrorReason::PowTooWeak));
    assert_eq!(s.stats().unwrap().packets, 0);
}

#[test]
fn rejects_full_mailbox() {
    let (_d, mut s) = store();
    let pol = Policy {
        max_per_mailbox: 2,
        ..policy()
    };
    for n in 1..=2 {
        let p = ok_msg(n, 1);
        assert_eq!(
            deposit(&mut s, &pol, &p.encode(), nonce(&p), NOW).unwrap(),
            Ok(())
        );
    }
    let p = ok_msg(3, 1);
    assert_eq!(
        deposit(&mut s, &pol, &p.encode(), nonce(&p), NOW).unwrap(),
        Err(ErrorReason::MailboxFull)
    );
    // Une autre boîte reste ouverte.
    let q = ok_msg(4, 2);
    assert_eq!(
        deposit(&mut s, &pol, &q.encode(), nonce(&q), NOW).unwrap(),
        Ok(())
    );
}

#[test]
fn rejects_when_node_full() {
    let (_d, mut s) = store();
    let pol = Policy {
        storage_max_bytes: 245 * 2,
        ..policy()
    };
    for n in 1..=2 {
        let p = ok_msg(n, n);
        assert_eq!(
            deposit(&mut s, &pol, &p.encode(), nonce(&p), NOW).unwrap(),
            Ok(())
        );
    }
    assert_eq!(s.stats().unwrap().bytes, 490);
    let p = ok_msg(3, 3);
    assert_eq!(
        deposit(&mut s, &pol, &p.encode(), nonce(&p), NOW).unwrap(),
        Err(ErrorReason::NodeFull)
    );
}

#[test]
fn duplicate_deposit_is_idempotent() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    assert_eq!(put(&mut s, &p), Ok(()));
    assert_eq!(put(&mut s, &p), Ok(()));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.bytes), (1, 245));
}

#[test]
fn ack_deletes_packet_and_is_kept() {
    let (_d, mut s) = store();
    let (m, _secret, a) = msg_and_ack(1, 1);
    assert_eq!(put(&mut s, &m), Ok(()));
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (0, 1, 245));
    let (items, next) = fetch(&s, &[mb(1)], None, 1 << 20).unwrap().unwrap();
    assert_eq!(items, vec![a.encode()]);
    assert_eq!(next, None);
    // Second accusé identique (même cible) : accepté sans effet.
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (0, 1, 245));
    // Le message accusé ne ressuscite pas s'il est redéposé.
    assert_eq!(put(&mut s, &m), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 0);
}

#[test]
fn early_ack_is_refused() {
    let (_d, mut s) = store();
    let (_m, _secret, a) = msg_and_ack(1, 1);
    assert_eq!(put_ack(&mut s, &a), Err(ErrorReason::UnknownAckTarget));
    assert_eq!(s.stats().unwrap().acks, 0);
}

#[test]
fn ack_with_wrong_secret_is_refused() {
    let (_d, mut s) = store();
    let (m, _secret, mut a) = msg_and_ack(1, 1);
    assert_eq!(put(&mut s, &m), Ok(()));
    a.payload[16..].copy_from_slice(&[0x77; 16]);
    assert_eq!(put_ack(&mut s, &a), Err(ErrorReason::UnknownAckTarget));
    assert_eq!(s.stats().unwrap().packets, 1);
}

#[test]
fn ack_needs_no_pow() {
    let (_d, mut s) = store();
    let (m, _secret, a) = msg_and_ack(1, 1);
    put(&mut s, &m).unwrap();
    // nonce 0 avec une exigence de 20 bits : un message serait refusé.
    let strict = Policy {
        pow_bits: 20,
        ..policy()
    };
    assert_eq!(
        deposit(&mut s, &strict, &a.encode(), 0, NOW).unwrap(),
        Ok(())
    );
}

#[test]
fn deposit_window_tolerates_one_hour_skew() {
    let (_d, mut s) = store();
    // Horloge du client en avance d'une heure : expire à now + 7 j + 1 h.
    let p = msg(1, 1, Tier::S, NOW + MAX_EXPIRY_SECS);
    assert_eq!(put(&mut s, &p), Ok(()));
    // Horloge du client en retard d'une heure : expire dans 7 j - 1 h.
    let q = msg(2, 1, Tier::S, NOW + 7 * 86_400 - 3_600);
    assert_eq!(put(&mut s, &q), Ok(()));
    // Paquet qui expire dans une seconde : encore valide.
    let r = msg(3, 1, Tier::S, NOW + 1);
    assert_eq!(put(&mut s, &r), Ok(()));
}

#[test]
fn fetch_too_many_mailboxes() {
    let (_d, s) = store();
    let boxes: Vec<MailboxId> = (0..65).map(mb).collect();
    assert_eq!(
        fetch(&s, &boxes, None, 1 << 20).unwrap(),
        Err(ErrorReason::TooManyMailboxes)
    );
    assert!(fetch(&s, &boxes[..64], None, 1 << 20).unwrap().is_ok());
}

#[test]
fn fetch_pagination_is_complete_and_unique() {
    let (_d, mut s) = store();
    let mut expected: Vec<Vec<u8>> = Vec::new();
    // Mélange de paliers S, M, L sur 3 boîtes, plus un accusé.
    let tiers = [Tier::S, Tier::M, Tier::L, Tier::S, Tier::M];
    for n in 1..=10u8 {
        let p = msg(
            n,
            1 + n % 3,
            tiers[usize::from(n) % tiers.len()],
            NOW + 86_400,
        );
        put(&mut s, &p).unwrap();
        expected.push(p.encode());
    }
    let (m, _sec, a) = msg_and_ack(50, 2);
    put(&mut s, &m).unwrap();
    put_ack(&mut s, &a).unwrap();
    expected.push(a.encode());
    let boxes = [mb(1), mb(2), mb(3)];
    // Pages de 1 Kio (L = 16 Kio part seul), 2 Kio, et énorme.
    for max in [1_024usize, 2_048, 40_000, 1 << 20] {
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let (items, next) = fetch(&s, &boxes, cursor, max).unwrap().unwrap();
            let total: usize = items.iter().map(Vec::len).sum();
            assert!(items.len() == 1 || total <= max, "page trop grosse");
            assert!(!items.is_empty());
            got.extend(items);
            pages += 1;
            assert!(pages < 100);
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let mut a1 = got.clone();
        let mut a2 = expected.clone();
        a1.sort();
        a2.sort();
        assert_eq!(a1, a2, "max={max}");
        a1.dedup();
        assert_eq!(a1.len(), got.len(), "doublon, max={max}");
    }
}

#[test]
fn fetch_does_not_delete() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    put(&mut s, &p).unwrap();
    for _ in 0..2 {
        let (items, _) = fetch(&s, &[mb(1)], None, 1 << 20).unwrap().unwrap();
        assert_eq!(items, vec![p.encode()]);
    }
    assert_eq!(s.stats().unwrap().packets, 1);
    // Boîte vide ou inconnue.
    let (items, next) = fetch(&s, &[mb(9)], None, 1 << 20).unwrap().unwrap();
    assert!(items.is_empty() && next.is_none());
}

#[test]
fn purge_removes_expired_only() {
    let (_d, mut s) = store();
    put(&mut s, &msg(1, 1, Tier::S, NOW + 100)).unwrap();
    put(&mut s, &msg(2, 1, Tier::S, NOW + 10_000)).unwrap();
    let (m, _sec, mut a) = msg_and_ack(3, 1);
    a.expires_at = u32::try_from(NOW + 100).unwrap();
    put(&mut s, &m).unwrap();
    put_ack(&mut s, &a).unwrap();
    assert_eq!(s.purge_expired(NOW + 50).unwrap(), 0);
    assert_eq!(s.purge_expired(NOW + 100).unwrap(), 2); // paquet 1 et l'accusé
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (1, 0, 245));
}

#[test]
fn received_at_rounded_to_minute() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    let now = NOW + 37; // NOW est un multiple de 60
    deposit(&mut s, &policy(), &p.encode(), nonce(&p), now)
        .unwrap()
        .unwrap();
    let r: i64 = s
        .conn()
        .query_row("SELECT received_at FROM packets", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r, i64::try_from(NOW).unwrap());
    assert_eq!(r % 60, 0);
}

#[test]
fn reopen_keeps_data_and_pragmas() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("n.db");
    {
        let mut s = NodeStore::open(&path).unwrap();
        put(&mut s, &ok_msg(1, 1)).unwrap();
        let mode: String = s
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sd: i64 = s
            .conn()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!((mode.as_str(), sd), ("wal", 1));
    }
    let s = NodeStore::open(&path).unwrap();
    assert_eq!(s.stats().unwrap().packets, 1);
}
