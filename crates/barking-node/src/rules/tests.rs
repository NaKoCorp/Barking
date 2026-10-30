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

/// Preuve à la difficulté de base plus le palier (boîte et nœud peu remplis).
fn nonce(p: &Packet) -> u64 {
    let bits = BITS + pow::tier_surcharge(p.tier);
    pow::solve(&pow::content_hash(&p.encode()), &p.mailbox, bits).unwrap()
}

/// Preuve à la difficulté exigée maintenant par `s`.
fn nonce_for(s: &NodeStore, pol: &Policy, p: &Packet) -> u64 {
    let bits = required_pow_bits(s, pol, &p.mailbox, p.tier).unwrap();
    pow::solve(&pow::content_hash(&p.encode()), &p.mailbox, bits).unwrap()
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
            {
                let n = nonce_for(&s, &pol, &p);
                deposit(&mut s, &pol, &p.encode(), n, NOW)
            }
            .unwrap(),
            Ok(())
        );
    }
    assert_eq!(s.stats().unwrap().bytes, 490);
    let p = ok_msg(3, 3);
    assert_eq!(
        {
            let n = nonce_for(&s, &pol, &p);
            deposit(&mut s, &pol, &p.encode(), n, NOW)
        }
        .unwrap(),
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
    // Message expirant à NOW + 200 accusé : l'accusé vit jusqu'à NOW + 86 400.
    let (mut m, _sec, a) = msg_and_ack(3, 1);
    m.expires_at = u32::try_from(NOW + 200).unwrap();
    put(&mut s, &m).unwrap();
    put_ack(&mut s, &a).unwrap();
    assert_eq!(s.purge_expired(NOW + 50).unwrap(), 0);
    assert_eq!(s.purge_expired(NOW + 100).unwrap(), 1); // paquet 1
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (1, 1, 490));
    assert_eq!(s.purge_expired(NOW + 86_400).unwrap(), 2); // paquet 2 et accusé
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (0, 0, 0));
}

#[test]
fn readdressed_ack_is_refused() {
    let (_d, mut s) = store();
    let (m, _secret, mut a) = msg_and_ack(1, 1);
    put(&mut s, &m).unwrap();
    a.mailbox = mb(2);
    assert_eq!(put_ack(&mut s, &a), Err(ErrorReason::UnknownAckTarget));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks), (1, 0));
}

#[test]
fn short_expiry_ack_cannot_resurrect_message() {
    let (_d, mut s) = store();
    let (m, _secret, mut a) = msg_and_ack(1, 1);
    put(&mut s, &m).unwrap();
    a.expires_at = u32::try_from(NOW + 10).unwrap();
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    // L'accusé survit à sa propre expiration, jusqu'à celle du message.
    s.purge_expired(NOW + 20).unwrap();
    assert_eq!(s.stats().unwrap().acks, 1);
    assert_eq!(put(&mut s, &m), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 0);
    // Après l'expiration du message : purge, puis redépôt refusé (Expired).
    let later = u64::from(m.expires_at);
    s.purge_expired(later).unwrap();
    assert_eq!(s.stats().unwrap().acks, 0);
    let r = deposit(&mut s, &policy(), &m.encode(), nonce(&m), later).unwrap();
    assert_eq!(r, Err(ErrorReason::Expired));
}

#[test]
fn ack_must_be_tier_s_with_32_byte_payload() {
    let (_d, mut s) = store();
    let (m, _secret, a) = msg_and_ack(1, 1);
    put(&mut s, &m).unwrap();
    let mut big = a.clone();
    big.tier = Tier::L;
    assert_eq!(put_ack(&mut s, &big), Err(ErrorReason::Malformed));
    let mut long = a.clone();
    long.payload.push(0);
    assert_eq!(put_ack(&mut s, &long), Err(ErrorReason::Malformed));
    assert_eq!(s.stats().unwrap().packets, 1);
    assert_eq!(put_ack(&mut s, &a), Ok(()));
}

#[test]
fn ack_respects_node_full() {
    let (_d, mut s) = store();
    // Message M (1 Kio) accusé par un ack S (245) : delta négatif, accepté
    // même au plafond. Message S accusé alors que le nœud est plein de
    // lui-même : delta nul, accepté.
    let pol = Policy {
        storage_max_bytes: 245,
        ..policy()
    };
    let (m, _sec, a) = msg_and_ack(1, 1);
    let r = deposit(&mut s, &pol, &m.encode(), nonce(&m), NOW).unwrap();
    assert_eq!(r, Ok(()));
    assert_eq!(deposit(&mut s, &pol, &a.encode(), 0, NOW).unwrap(), Ok(()));
    // Delta positif : plafond abaissé sous la taille d'un accusé, mais le
    // paquet accusé est plus petit que l'accusé (charge vide en palier S
    // = 245 octets aussi, donc on simule via un plafond réduit après dépôt).
    let (_d2, mut s2) = store();
    let (m2, _s2, a2) = msg_and_ack(2, 1);
    put(&mut s2, &m2).unwrap();
    s2.conn()
        .execute("UPDATE meta SET v = 10 WHERE k='stored_bytes'", [])
        .unwrap();
    s2.conn()
        .execute("UPDATE packets SET bytes = x'00'", [])
        .unwrap();
    let tiny = Policy {
        storage_max_bytes: 100,
        ..policy()
    };
    assert_eq!(
        deposit(&mut s2, &tiny, &a2.encode(), 0, NOW).unwrap(),
        Err(ErrorReason::NodeFull)
    );
    assert_eq!(s2.stats().unwrap().packets, 1);
}

#[test]
fn squatted_id_does_not_block_real_message() {
    let (_d, mut s) = store();
    let (real, _secret, a) = msg_and_ack(1, 1);
    let mut junk = real.clone();
    junk.payload = vec![0xEE; 8];
    assert_eq!(put(&mut s, &junk), Ok(()));
    assert_eq!(put(&mut s, &real), Ok(()));
    assert_eq!(put(&mut s, &real), Ok(())); // même contenu : sans effet
    assert_eq!(s.stats().unwrap().packets, 2);
    let (items, _) = fetch(&s, &[mb(1)], None, 1 << 20).unwrap().unwrap();
    assert!(items.contains(&junk.encode()) && items.contains(&real.encode()));
    // `hops` ne compte pas dans la déduplication.
    let mut relayed = real.clone();
    relayed.hops = 3;
    assert_eq!(put(&mut s, &relayed), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 2);
    // L'accusé supprime les deux.
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (0, 1, 245));
}

fn fill(s: &NodeStore, mailbox: u8, count: u32) {
    let start: u32 = s
        .conn()
        .query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0))
        .unwrap();
    for n in start..start + count {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&n.to_be_bytes());
        id[15] = 0xFF;
        s.conn()
            .execute(
                "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes)
                 VALUES(?1,?2,0,0,?3,0,?1,x'00')",
                rusqlite::params![
                    &id[..],
                    &[mailbox; 16][..],
                    i64::try_from(NOW + 86_400).unwrap()
                ],
            )
            .unwrap();
    }
}

#[test]
fn pow_is_progressive_per_mailbox() {
    let (_d, mut s) = store();
    let pol = policy();
    let req = |s: &NodeStore| required_pow_bits(s, &pol, &mb(1), Tier::S).unwrap();
    assert_eq!(req(&s), BITS);
    fill(&s, 1, 64); // 64 : n / 64 = 1, log2 = 0
    assert_eq!(req(&s), BITS);
    fill(&s, 1, 63); // 127
    assert_eq!(req(&s), BITS);
    fill(&s, 1, 1); // 128 : n / 64 = 2
    assert_eq!(req(&s), BITS + 1);
    fill(&s, 1, 128); // 256 : n / 64 = 4
    assert_eq!(req(&s), BITS + 2);
    fill(&s, 1, 744); // 1 000 : n / 64 = 15
    assert_eq!(req(&s), BITS + 3);
    // Une autre boîte n'est pas touchée.
    assert_eq!(required_pow_bits(&s, &pol, &mb(2), Tier::S).unwrap(), BITS);
    // Plafonné à MAX_POW_BITS.
    let high = Policy {
        pow_bits: pow::MAX_POW_BITS,
        ..pol
    };
    assert_eq!(
        required_pow_bits(&s, &high, &mb(1), Tier::S).unwrap(),
        pow::MAX_POW_BITS
    );
    // Dépôt : une preuve à BITS bits ne suffit plus à 128 paquets.
    let (_d2, mut s2) = store();
    fill(&s2, 1, 128);
    let p = ok_msg(1, 1);
    let h = pow::content_hash(&p.encode());
    let weak = (0..)
        .find(|n| pow::check(&h, &p.mailbox, *n, BITS) && !pow::check(&h, &p.mailbox, *n, BITS + 1))
        .unwrap();
    assert_eq!(
        deposit(&mut s2, &pol, &p.encode(), weak, NOW).unwrap(),
        Err(ErrorReason::PowTooWeak)
    );
    let strong = pow::solve(&h, &p.mailbox, BITS + 1).unwrap();
    assert_eq!(
        deposit(&mut s2, &pol, &p.encode(), strong, NOW).unwrap(),
        Ok(())
    );
    let _ = &mut s;
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

#[test]
fn pow_is_bound_to_content() {
    let (_d, mut s) = store();
    let real = ok_msg(1, 1);
    let mut other = real.clone();
    other.payload = vec![0xEE; 8];
    // La preuve de `real` ne vaut pas pour un autre contenu du même identifiant,
    // sauf rencontre fortuite (2^-4) : on cherche un nonce qui ne passe pas.
    let h1 = pow::content_hash(&real.encode());
    let h2 = pow::content_hash(&other.encode());
    let n = (0..)
        .find(|k| {
            pow::check(&h1, &real.mailbox, *k, BITS) && !pow::check(&h2, &other.mailbox, *k, BITS)
        })
        .unwrap();
    assert_eq!(
        deposit(&mut s, &policy(), &other.encode(), n, NOW).unwrap(),
        Err(ErrorReason::PowTooWeak)
    );
    assert_eq!(
        deposit(&mut s, &policy(), &real.encode(), n, NOW).unwrap(),
        Ok(())
    );
    assert_eq!(s.stats().unwrap().packets, 1);
}

#[test]
fn ack_is_filed_in_every_mailbox_of_the_id() {
    let (_d, mut s) = store();
    let (real, _secret, mut a) = msg_and_ack(1, 1);
    let mut squat = real.clone();
    squat.mailbox = mb(2);
    assert_eq!(put(&mut s, &squat), Ok(()));
    assert_eq!(put(&mut s, &real), Ok(()));
    // Ack ré-adressé vers B (où se trouve la ligne squat).
    a.mailbox = mb(2);
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    let st = s.stats().unwrap();
    assert_eq!((st.packets, st.acks, st.bytes), (0, 2, 490));
    for m in [1, 2] {
        let (items, _) = fetch(&s, &[mb(m)], None, 1 << 20).unwrap().unwrap();
        assert_eq!(items, vec![a.encode()], "boîte {m}");
    }
    // Le message ne ressuscite pas.
    assert_eq!(put(&mut s, &real), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 0);
}

#[test]
fn old_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("n.db");
    {
        let s = NodeStore::open(&path).unwrap();
        s.conn()
            .execute("UPDATE meta SET v=1 WHERE k='schema_version'", [])
            .unwrap();
    }
    match NodeStore::open(&path) {
        Err(crate::Error::SchemaVersion(1)) => {}
        other => panic!("attendu SchemaVersion(1), obtenu {:?}", other.map(|_| ())),
    }
}

/// Schéma v1 réel (avant la déduplication par contenu) : refusé, et la base
/// n'est pas modifiée (ni index, ni mode WAL).
#[test]
fn v1_layout_refused_without_modification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    let snapshot = |c: &rusqlite::Connection| -> (Vec<String>, String) {
        let mut st = c
            .prepare("SELECT COALESCE(sql,'') FROM sqlite_master ORDER BY name")
            .unwrap();
        let sql = st
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<core::result::Result<Vec<String>, _>>()
            .unwrap();
        let mode: String = c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        (sql, mode)
    };
    let before = {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE packets(
                id BLOB PRIMARY KEY, mailbox BLOB NOT NULL, kind INTEGER NOT NULL,
                tier INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                received_at INTEGER NOT NULL, bytes BLOB NOT NULL);
             CREATE INDEX packets_mailbox ON packets(mailbox);
             CREATE INDEX packets_expires ON packets(expires_at);
             CREATE TABLE acks(
                packet_id BLOB PRIMARY KEY, mailbox BLOB NOT NULL,
                expires_at INTEGER NOT NULL, bytes BLOB NOT NULL);
             CREATE INDEX acks_mailbox ON acks(mailbox);
             CREATE INDEX acks_expires ON acks(expires_at);
             CREATE TABLE meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
             INSERT INTO meta VALUES('schema_version', 1), ('stored_bytes', 0);",
        )
        .unwrap();
        snapshot(&c)
    };
    match NodeStore::open(&path) {
        Err(crate::Error::SchemaVersion(1)) => {}
        other => panic!("attendu SchemaVersion(1), obtenu {:?}", other.map(|_| ())),
    }
    let c = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(snapshot(&c), before);
    assert_ne!(before.1, "wal");
}

#[test]
fn foreign_db_without_meta_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.db");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE autre(x INTEGER);")
        .unwrap();
    assert!(matches!(
        NodeStore::open(&path),
        Err(crate::Error::SchemaVersion(0))
    ));
}

#[test]
fn reopen_current_schema_ok() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("n.db");
    drop(NodeStore::open(&path).unwrap());
    let s = NodeStore::open(&path).unwrap();
    assert_eq!(s.stats().unwrap().bytes, 0);
}

#[test]
fn policy_validation() {
    assert!(Policy::default().validate().is_ok());
    let p = Policy {
        pow_bits: pow::MAX_POW_BITS + 1,
        ..Policy::default()
    };
    assert!(p.validate().is_err());
    let p = Policy {
        pow_bits: pow::MAX_POW_BITS,
        ..Policy::default()
    };
    assert!(p.validate().is_ok());
}

/// Grande table : la lecture de chaque boîte suit l'index (pas de tri
/// temporaire sur les charges), une page reste bornée en éléments, et la
/// pagination complète ne perd ni ne duplique rien.
#[test]
fn fetch_large_table_index_ordered_and_bounded() {
    let (_d, mut s) = store();
    const BOXES: u8 = 64;
    const PER_BOX: u32 = 300;
    {
        let tx = s.conn_mut().transaction().unwrap();
        {
            let mut st = tx
                .prepare(
                    "INSERT INTO packets(id,mailbox,kind,tier,expires_at,received_at,hash,bytes)
                     VALUES(?1,?2,0,0,?3,0,?4,?5)",
                )
                .unwrap();
            for n in 0..PER_BOX {
                for b in 0..BOXES {
                    let mut id = [0u8; 16];
                    id[..4].copy_from_slice(&n.to_le_bytes());
                    id[4] = b;
                    st.execute(rusqlite::params![
                        &id[..],
                        &[b; 16][..],
                        i64::try_from(NOW + 86_400).unwrap(),
                        &id[..],
                        vec![b; 245]
                    ])
                    .unwrap();
                }
            }
        }
        tx.commit().unwrap();
    }
    for table in ["packets", "acks"] {
        let plan: Vec<String> = s
            .conn()
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                super::fetch_scan_sql(table, 0)
            ))
            .unwrap()
            .query_map(rusqlite::params![&[1u8; 16][..], 0], |r| r.get(3))
            .unwrap()
            .collect::<core::result::Result<_, _>>()
            .unwrap();
        let plan = plan.join(" | ");
        assert!(!plan.contains("TEMP B-TREE"), "{table}: {plan}");
        assert!(plan.contains("INDEX"), "{table}: {plan}");
    }
    // Boîtes en double dans la requête : pas de doublon.
    let (dup, next) = fetch(&s, &[mb(3), mb(3)], None, 1 << 20).unwrap().unwrap();
    assert_eq!((dup.len(), next), (PER_BOX as usize, None));
    let boxes: Vec<MailboxId> = (0..BOXES).map(mb).collect();
    let mut cursor = None;
    let mut all = Vec::new();
    let mut pages = 0;
    loop {
        let (items, next) = fetch(&s, &boxes, cursor, 1 << 20).unwrap().unwrap();
        assert!(items.len() <= super::MAX_PAGE_ITEMS);
        assert!(!items.is_empty());
        pages += 1;
        all.extend(items);
        match next {
            Some(n) => cursor = Some(n),
            None => break,
        }
    }
    let total = usize::from(BOXES) * PER_BOX as usize;
    assert_eq!(all.len(), total);
    assert_eq!(pages, total.div_ceil(super::MAX_PAGE_ITEMS));
    // Ordre d'insertion (seq) respecté.
    for (k, it) in all.iter().enumerate() {
        assert_eq!(it[0], (k % usize::from(BOXES)) as u8);
    }
}

/// Nonce qui passe exactement `bits` bits, pas `bits + 1`.
fn exact_nonce(p: &Packet, bits: u8) -> u64 {
    let h = pow::content_hash(&p.encode());
    (0..)
        .find(|n| pow::check(&h, &p.mailbox, *n, bits) && !pow::check(&h, &p.mailbox, *n, bits + 1))
        .unwrap()
}

#[test]
fn pow_surcharge_by_tier() {
    for (tier, extra) in [(Tier::S, 0u8), (Tier::M, 2), (Tier::L, 6)] {
        let (_d, mut s) = store();
        let p = msg(1, 1, tier, NOW + 86_400);
        let bytes = p.encode();
        if extra > 0 {
            let weak = exact_nonce(&p, BITS + extra - 1);
            assert_eq!(
                deposit(&mut s, &policy(), &bytes, weak, NOW).unwrap(),
                Err(ErrorReason::PowTooWeak),
                "{tier:?}"
            );
        }
        let ok = exact_nonce(&p, BITS + extra);
        assert_eq!(
            deposit(&mut s, &policy(), &bytes, ok, NOW).unwrap(),
            Ok(()),
            "{tier:?}"
        );
    }
}

#[test]
fn pow_surcharge_by_global_fill() {
    // Plafond 8 000 octets : 1/8 = 1 000. Au-delà, +1 bit par doublement.
    let pol = Policy {
        storage_max_bytes: 8_000,
        ..policy()
    };
    for (stored, extra) in [
        (0i64, 0u8),
        (1_000, 0),
        (1_001, 1),
        (2_000, 1),
        (2_001, 2),
        (4_000, 2),
        (4_001, 3),
    ] {
        let (_d, mut s) = store();
        add_stored_bytes(s.conn(), stored).unwrap();
        let p = ok_msg(1, 1);
        let bytes = p.encode();
        if extra > 0 {
            let weak = exact_nonce(&p, BITS + extra - 1);
            assert_eq!(
                deposit(&mut s, &pol, &bytes, weak, NOW).unwrap(),
                Err(ErrorReason::PowTooWeak),
                "stored={stored}"
            );
        }
        let ok = exact_nonce(&p, BITS + extra);
        assert_eq!(
            deposit(&mut s, &pol, &bytes, ok, NOW).unwrap(),
            Ok(()),
            "stored={stored}"
        );
    }
}

// ---------------------------------------------------------------------
// Recopie entre nœuds (spec §5.2, points 3, 5, 6, 7) et stockage v3.
// ---------------------------------------------------------------------

/// Nonce qui satisfait `BITS + palier` mais pas un bit de plus : une preuve
/// « de base », trop faible pour un dépôt progressif.
fn base_only_nonce(p: &Packet) -> u64 {
    let hash = pow::content_hash(&p.encode());
    let bits = BITS + pow::tier_surcharge(p.tier);
    (0u64..)
        .find(|&n| {
            pow::check(&hash, &p.mailbox, n, bits) && !pow::check(&hash, &p.mailbox, n, bits + 1)
        })
        .unwrap()
}

fn copy(s: &mut NodeStore, p: &Packet, pow_nonce: u64) -> core::result::Result<(), ErrorReason> {
    store_copy(s, &policy(), &p.encode(), pow_nonce, NOW).unwrap()
}

#[test]
fn deposit_records_pow() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    let n = nonce(&p);
    assert_eq!(put(&mut s, &p), Ok(()));
    let items = copy_items(&s, &p.mailbox, NOW).unwrap().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].pow, n);
    assert_eq!(items[0].bytes, p.encode());
    assert!(!items[0].is_ack);
    assert_eq!(items[0].tier, p.tier);
}

#[test]
fn store_copy_requires_only_base_pow() {
    let (_d, mut s) = store();
    // 128 paquets : un bit progressif de plus (steps = 2, ilog2 = 1).
    for n in 0..128u8 {
        assert_eq!(put(&mut s, &ok_msg(n, 1)), Ok(()), "dépôt {n}");
    }
    let p = ok_msg(200, 1);
    let weak = base_only_nonce(&p);
    assert!(required_pow_bits(&s, &policy(), &p.mailbox, p.tier).unwrap() > BITS);
    // Le dépôt exige le progressif, la recopie seulement la base.
    assert_eq!(
        deposit(&mut s, &policy(), &p.encode(), weak, NOW).unwrap(),
        Err(ErrorReason::PowTooWeak)
    );
    assert_eq!(copy_pow_ok(&policy(), &p.encode(), weak), Ok(()));
    assert_eq!(copy(&mut s, &p, weak), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 129);
}

#[test]
fn copy_pow_too_weak() {
    let strict = Policy {
        pow_bits: 20,
        ..policy()
    };
    let p = ok_msg(1, 1);
    assert_eq!(
        copy_pow_ok(&strict, &p.encode(), nonce(&p)),
        Err(ErrorReason::PowTooWeak)
    );
    let (_d, mut s) = store();
    assert_eq!(
        store_copy(&mut s, &strict, &p.encode(), nonce(&p), NOW).unwrap(),
        Err(ErrorReason::PowTooWeak)
    );
    // Un accusé n'exige aucune preuve ; des octets illisibles sont refusés.
    let (_m, _sec, a) = msg_and_ack(1, 1);
    assert_eq!(copy_pow_ok(&strict, &a.encode(), 0), Ok(()));
    assert_eq!(
        copy_pow_ok(&strict, &[1, 2, 3], 0),
        Err(ErrorReason::Malformed)
    );
}

#[test]
fn copy_target_checks_shape_and_expiry() {
    let m = ok_msg(1, 3);
    assert_eq!(copy_target(&m.encode(), NOW), Ok((mb(3), false)));
    let (_m, _sec, a) = msg_and_ack(2, 4);
    assert_eq!(copy_target(&a.encode(), NOW), Ok((mb(4), true)));
    assert_eq!(copy_target(&[0; 5], NOW), Err(ErrorReason::Malformed));
    assert_eq!(
        copy_target(&msg(1, 1, Tier::S, NOW).encode(), NOW),
        Err(ErrorReason::Expired)
    );
    let mut long = m.encode();
    long.push(0);
    assert_eq!(copy_target(&long, NOW), Err(ErrorReason::WrongTier));
}

#[test]
fn store_copy_ack_unknown_target() {
    let (_d, mut s) = store();
    let (_m, _sec, a) = msg_and_ack(1, 1);
    assert_eq!(copy(&mut s, &a, 0), Err(ErrorReason::UnknownAckTarget));
    // Avec le paquet visé, l'accusé est accepté et supprime le paquet.
    let (m, _sec, a) = msg_and_ack(2, 1);
    assert_eq!(copy(&mut s, &m, nonce(&m)), Ok(()));
    assert_eq!(copy(&mut s, &a, 0), Ok(()));
    assert_eq!(s.stats().unwrap().packets, 0);
    assert_eq!(s.stats().unwrap().acks, 1);
}

#[test]
fn store_copy_dedups() {
    let (_d, mut s) = store();
    let p = ok_msg(1, 1);
    assert_eq!(copy(&mut s, &p, nonce(&p)), Ok(()));
    let before = s.stats().unwrap();
    assert_eq!(copy(&mut s, &p, nonce(&p)), Ok(()));
    assert_eq!(s.stats().unwrap(), before);
}

#[test]
fn store_copy_respects_quotas() {
    let (_d, mut s) = store();
    let small = Policy {
        max_per_mailbox: 1,
        ..policy()
    };
    let a = ok_msg(1, 1);
    let b = ok_msg(2, 1);
    assert_eq!(
        store_copy(&mut s, &small, &a.encode(), nonce(&a), NOW).unwrap(),
        Ok(())
    );
    assert_eq!(
        store_copy(&mut s, &small, &b.encode(), nonce(&b), NOW).unwrap(),
        Err(ErrorReason::MailboxFull)
    );
    let tiny = Policy {
        storage_max_bytes: 100,
        ..policy()
    };
    let c = ok_msg(3, 2);
    assert_eq!(
        store_copy(&mut s, &tiny, &c.encode(), nonce(&c), NOW).unwrap(),
        Err(ErrorReason::NodeFull)
    );
}

#[test]
fn holdings_pages_and_hashes() {
    let (_d, mut s) = store();
    let pol = Policy {
        max_per_mailbox: 2_000,
        ..policy()
    };
    // 1 500 messages, dont 500 accusés : 1 000 paquets et 500 accusés, soit
    // 1 500 éléments. La première page passe des paquets aux accusés.
    let mut all = Vec::new();
    for n in 0..1_500u16 {
        let mut secret = [0u8; 16];
        secret[..2].copy_from_slice(&n.to_be_bytes());
        let mut m = ok_msg(1, 1);
        m.id = ack::packet_id_for(&secret);
        m.payload = secret.to_vec();
        assert_eq!(
            store_copy(&mut s, &pol, &m.encode(), nonce(&m), NOW).unwrap(),
            Ok(())
        );
        all.push((m, secret));
    }
    for (m, secret) in all.iter().take(500) {
        let mut payload = m.id.0.to_vec();
        payload.extend_from_slice(secret);
        let a = Packet {
            kind: Kind::Ack,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId([0xA0; 16]),
            expires_at: u32::try_from(NOW + 86_400).unwrap(),
            mailbox: m.mailbox,
            payload,
        };
        assert_eq!(
            store_copy(&mut s, &pol, &a.encode(), 0, NOW).unwrap(),
            Ok(())
        );
    }
    let stats = s.stats().unwrap();
    assert_eq!((stats.packets, stats.acks), (1_000, 500));

    let (page1, c1) = holdings(&s, &mb(1), None).unwrap().unwrap();
    assert_eq!(page1.len(), 1024);
    let c1 = c1.expect("une seconde page");
    assert!(
        c1 >= barking_proto::ACK_CURSOR_BASE,
        "curseur dans les accusés"
    );
    let (page2, c2) = holdings(&s, &mb(1), Some(c1)).unwrap().unwrap();
    assert_eq!(page2.len(), 1_500 - 1024);
    assert_eq!(c2, None);
    // Les empreintes sont celles des octets : mêmes que `copy_items`.
    let mut want: Vec<[u8; 32]> = copy_items(&s, &mb(1), NOW)
        .unwrap()
        .unwrap()
        .iter()
        .map(|i| pow::content_hash(&i.bytes))
        .collect();
    let mut got: Vec<[u8; 32]> = page1.into_iter().chain(page2).collect();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(got.len(), 1_500);
    // Une boîte vide n'a rien.
    assert_eq!(holdings(&s, &mb(2), None).unwrap().unwrap(), (vec![], None));
}

#[test]
fn copy_items_acks_first() {
    let (_d, mut s) = store();
    let (m, _sec, a) = msg_and_ack(1, 1);
    let other = ok_msg(9, 1);
    assert_eq!(put(&mut s, &m), Ok(()));
    assert_eq!(put(&mut s, &other), Ok(()));
    assert_eq!(put_ack(&mut s, &a), Ok(()));
    let items = copy_items(&s, &mb(1), NOW).unwrap().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0].is_ack);
    assert_eq!(items[0].bytes, a.encode());
    assert_eq!(items[0].hash, pow::content_hash(&a.encode()));
    assert!(!items[1].is_ack);
    assert_eq!(items[1].hash, pow::content_hash(&other.encode()));
    // Rien d'expiré, et rien dans une autre boîte.
    assert!(
        copy_items(&s, &mb(1), NOW + 2 * 86_400)
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(copy_items(&s, &mb(2), NOW).unwrap().unwrap().is_empty());
}
