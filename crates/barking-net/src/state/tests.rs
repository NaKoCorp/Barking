use barking_packet::Kind;

use super::*;
use crate::plan::plan_deposits;
use crate::test_support::{id_of, record, subject};

const NOW: u64 = 1_800_000_000;

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

#[test]
fn encode_decode_roundtrip() {
    let mut s = NetState::new(true);
    s.view.insert(record(0, NOW), NOW);
    s.view.confirm(&id_of(0), NOW);
    s.positions.insert((id_of(0), MailboxId([3; 16])), 42);
    s.unaudited.insert(id_of(1), 2);
    s.note_audit(&id_of(0), &MailboxId([3; 16]), NOW + 1800);
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert!(back.view.get(&id_of(0)).unwrap().confirmed);
    assert_eq!(
        back.positions.get(&(id_of(0), MailboxId([3; 16]))),
        Some(&42)
    );
    assert_eq!(back.unaudited.get(&id_of(1)), Some(&2));
    // Audit dates are kept to the hour.
    assert_eq!(
        back.audited_at.get(&(id_of(0), MailboxId([3; 16]))),
        Some(&NOW)
    );
    assert!(!back.audit_due(&id_of(0), &MailboxId([3; 16]), NOW + 5 * 3600, 6 * 3600));
    assert!(back.audit_due(&id_of(0), &MailboxId([3; 16]), NOW + 6 * 3600, 6 * 3600));
    assert_eq!(back.ledger, s.ledger);
}

#[test]
fn unreadable_state_starts_empty() {
    let (_dir, mut core) = subject(NOW);
    core.set_transport_state(STATE_KEY, b"\xff\xfe garbage")
        .unwrap();
    let s = NetState::load(&mut core, NOW, true).unwrap();
    assert!(s.view.is_empty());
    assert!(s.positions.is_empty());
    assert_eq!(s.ledger, Ledger::default());
    // An unknown format version reads as unreadable too.
    let mut bytes = NetState::new(true).encode().unwrap();
    bytes[0] = FORMAT + 1;
    assert!(NetState::decode(&bytes, NOW, true).is_none());
    // Nothing stored at all: empty as well.
    let (_dir2, mut fresh) = subject(NOW);
    assert!(
        NetState::load(&mut fresh, NOW, true)
            .unwrap()
            .view
            .is_empty()
    );
}

#[test]
fn migration_keeps_deposits_and_positions() {
    let (_dir, mut core) = subject(NOW);
    let outbox = core.pending_outbox(NOW).unwrap();
    let message = outbox
        .iter()
        .find(|b| Packet::decode(b).unwrap().kind == Kind::Message)
        .unwrap()
        .clone();
    let p = Packet::decode(&message).unwrap();
    let (n0, n1) = (id_of(0), id_of(1));
    let legacy = LegacyState {
        nodes: vec![
            LegacyNode {
                id: n0.to_string(),
                sessions: vec![Seen {
                    mailbox: hex(&[5; 16]),
                    seq: 9,
                }],
                intro: vec![Seen {
                    mailbox: hex(&[6; 16]),
                    seq: 4,
                }],
                deposited: vec![
                    Deposited {
                        id: hex(&p.id.0),
                        until: NOW + 3600,
                    },
                    // Unknown packet: nothing to keep.
                    Deposited {
                        id: hex(&[0xee; 16]),
                        until: NOW + 3600,
                    },
                ],
            },
            // Malformed identifier: skipped.
            LegacyNode {
                id: "not-an-id".into(),
                ..LegacyNode::default()
            },
        ],
    };
    let text = toml::to_string(&legacy).unwrap();
    core.set_transport_state(LEGACY_STATE_KEY, text.as_bytes())
        .unwrap();

    let s = NetState::load(&mut core, NOW, true).unwrap();
    assert_eq!(s.positions.get(&(n0, MailboxId([5; 16]))), Some(&9));
    assert_eq!(s.positions.get(&(n0, MailboxId([6; 16]))), Some(&4));
    assert_eq!(s.positions.len(), 2);
    // The deposit delay holds: the message is not redeposited on n0 yet,
    // and goes to the next responsible.
    let plan = plan_deposits(
        std::slice::from_ref(&message),
        &s.ledger,
        |_| vec![n0, n1],
        NOW,
    );
    assert_eq!(plan.len(), 1);
    assert!(plan[0].node == n1 && plan[0].first_copy);
    // After the delay, n0 is eligible again.
    let later = plan_deposits(
        std::slice::from_ref(&message),
        &s.ledger,
        |_| vec![n0, n1],
        NOW + 3600,
    );
    assert_eq!(later[0].node, n0);

    // The old key is erased, the new state saved.
    assert_eq!(
        core.transport_state(LEGACY_STATE_KEY).unwrap(),
        Some(Vec::new())
    );
    let again = NetState::load(&mut core, NOW, true).unwrap();
    assert_eq!(again.positions, s.positions);
    assert_eq!(again.ledger, s.ledger);
}

#[test]
fn unreadable_legacy_state_is_dropped_and_erased() {
    let (_dir, mut core) = subject(NOW);
    core.set_transport_state(LEGACY_STATE_KEY, b"[[node]\nid = ")
        .unwrap();
    let s = NetState::load(&mut core, NOW, true).unwrap();
    assert!(s.positions.is_empty());
    assert_eq!(
        core.transport_state(LEGACY_STATE_KEY).unwrap(),
        Some(Vec::new())
    );
}

#[test]
fn positions_follow_resume_and_prune() {
    let mut s = NetState::new(true);
    let (n, m1, m2) = (id_of(0), MailboxId([1; 16]), MailboxId([2; 16]));
    let mut r = FetchResume::default();
    r.seen.insert(m1.0, 7);
    s.set_positions(&n, &[m1, m2], &r);
    assert_eq!(s.resume(&n, &[m1, m2]).seen.get(&m1.0), Some(&7));
    assert!(!s.resume(&n, &[m1, m2]).seen.contains_key(&m2.0));
    // A position back to zero is forgotten.
    r.seen.insert(m1.0, 0);
    s.set_positions(&n, &[m1], &r);
    assert!(s.positions.is_empty());
    s.positions.insert((n, m2), 3);
    s.note_audit(&n, &m2, 0);
    s.note_reread(&n, &m2, 0);
    s.retain_positions(&HashSet::from([m1]));
    assert!(s.positions.is_empty());
    assert!(s.audited_at.is_empty());
    assert!(s.reread_at.is_empty());
    // A recent re-read try holds the next one back, like an audit.
    s.note_reread(&n, &m1, NOW);
    assert!(!s.audit_due(&n, &m1, NOW + 3600, 6 * 3600));
    assert!(s.audit_due(&n, &m1, NOW + 6 * 3600, 6 * 3600));
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert_eq!(back.reread_at.get(&(n, m1)), Some(&NOW));
}

#[test]
fn old_positions_read_back() {
    let seen = vec![
        Seen {
            mailbox: data_encoding::HEXLOWER.encode(&[1; 16]),
            seq: 7,
        },
        // Malformed entries are skipped.
        Seen {
            mailbox: "zz".into(),
            seq: 9,
        },
    ];
    let back = to_resume(&seen);
    assert_eq!(back.seen.len(), 1);
    assert_eq!(back.seen.get(&[1; 16]), Some(&7));
    // Old format (`at`) read back as a deadline.
    let d: Deposited = toml::from_str("id = \"x\"\nat = 5").unwrap();
    assert_eq!(d.until, 5);
}

/// A state with one entry in every part (the view's and the ledger's
/// encodings are nested in it).
fn golden_state() -> NetState {
    let m = MailboxId([5; 16]);
    let (a, b) = (id_of(0), id_of(1));
    let mut s = NetState::new(true);
    s.view.insert(record(0, NOW), NOW);
    s.view.confirm(&a, NOW);
    crate::plan::record_outcome(&mut s.ledger, [9; 32], a, &Ok(()), NOW);
    s.positions.insert((a, m), 7);
    s.unaudited.insert(b, 2);
    s.note_audit(&a, &m, NOW);
    s.note_reread(&a, &m, NOW);
    s.note_crosscheck(&b, &m, NOW);
    s.note_down_failures([b], NOW);
    s.page_bytes.insert(a, 64 << 10);
    s
}

/// The bytes of `golden_state` under `FORMAT` 1.
const FORMAT_1: &str = concat!(
    "01a701018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c2069101ecc263",
    "164bd7c90cda670b9e5b2c0c1c56b4c79187158d8a514015787006ba31010a000001a01f0080a4a7",
    "da0640ff05568312955f35cb45b0adb7bab8e7f25877a6731b512daf9ecdd3085eabe8da09c17d6f",
    "49d45e8a3a836db02bce038237099f75071c9009711ee56c0e6b0c00010080a4a7da0680a4a7da06",
    "0000003f0080a4a7da06750109090909090909090909090909090909090909090909090909090909",
    "090909090180a4a7da06018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7",
    "c2069180a4a7da06018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c206",
    "9180c7acda060000018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c206",
    "9105050505050505050505050505050505070001c3fbc0923c6a6a8c64c0c62574ad50b04f05b53b",
    "d5804daedd43d2b584259c1b02018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab",
    "1a5fd7c206910505050505050505050505050505050580a4a7da06018d3a191424b7a6b371871d41",
    "18e5b63e4e0d6d398e90910e60ab1a5fd7c206910505050505050505050505050505050580a4a7da",
    "0601c3fbc0923c6a6a8c64c0c62574ad50b04f05b53bd5804daedd43d2b584259c1b050505050505",
    "0505050505050505050580a4a7da0601c3fbc0923c6a6a8c64c0c62574ad50b04f05b53bd5804dae",
    "dd43d2b584259c1b80a4a7da06018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab",
    "1a5fd7c20691808004",
);

#[test]
fn format_1_bytes_are_frozen() {
    let bytes = golden_state().encode().unwrap();
    assert_eq!(
        hex(&bytes),
        FORMAT_1,
        "the stored network state changed: bump FORMAT and migrate"
    );
    let back = NetState::decode(
        &data_encoding::HEXLOWER.decode(FORMAT_1.as_bytes()).unwrap(),
        NOW,
        true,
    )
    .expect("format 1 still reads");
    assert_eq!(back.encode().unwrap(), bytes);
}
