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
    s.retain_positions(&HashSet::from([m1]));
    assert!(s.positions.is_empty());
    assert!(s.audited_at.is_empty());
}

#[test]
fn seen_positions_roundtrip_and_prune() {
    let m = |b: u8| MailboxId([b; 16]);
    let mut r = FetchResume::default();
    r.seen.insert([1; 16], 7);
    r.seen.insert([2; 16], 0);
    r.seen.insert([3; 16], 9);
    // Only the mailboxes still watched, zero positions omitted.
    let s = from_resume(&r, &[m(1), m(2)]);
    assert_eq!(s.len(), 1);
    let back = to_resume(&s);
    assert_eq!(back.seen.get(&[1; 16]), Some(&7));
    assert!(!back.seen.contains_key(&[3; 16]));
    // Old format (`at`) read back as a deadline.
    let d: Deposited = toml::from_str("id = \"x\"\nat = 5").unwrap();
    assert_eq!(d.until, 5);
}
