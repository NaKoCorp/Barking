use std::time::Duration;

use barking_packet::Kind;
use barking_proto::{NodeInfoReport, NodeOrigin};

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
    // `StoredV1` still writes the bytes first released.
    assert_eq!(
        hex(&golden_state().encode_format_1().unwrap()),
        FORMAT_1,
        "the format 1 layout changed: it must stay readable as released"
    );
}

/// Empty trailing tables of format 2: five empty sequences.
const EMPTY_V2_TAIL: &str = "0000000000";

#[test]
fn format_1_state_migrates_to_2() {
    // The released bytes read as format 2, every format 1 field unchanged:
    // the encoding is the old one under the new version, then empty tables.
    let v1 = data_encoding::HEXLOWER.decode(FORMAT_1.as_bytes()).unwrap();
    let back = NetState::decode(&v1, NOW, true).expect("format 1 still reads");
    let golden = golden_state();
    assert_eq!(
        hex(&back.encode().unwrap()),
        format!("02{}{}", &FORMAT_1[2..], EMPTY_V2_TAIL)
    );
    assert_eq!(back.positions, golden.positions);
    assert_eq!(back.ledger, golden.ledger);
    assert_eq!(back.unaudited, golden.unaudited);
    assert_eq!(back.page_bytes, golden.page_bytes);
    assert!(back.view.get(&id_of(0)).unwrap().confirmed);
    assert!(back.info.is_empty() && back.latency.is_empty() && back.blocked.is_empty());
    assert!(back.defaults.is_empty() && back.dismissed_defaults.is_empty());

    // A format 1 state with nodes added by hand, through the database.
    let (_dir, mut core) = subject(NOW);
    let mut s = golden_state();
    s.view
        .add_manual(id_of(4), crate::test_support::addr(9, 9, 9).into(), NOW);
    s.view
        .add_manual(id_of(5), crate::test_support::addr(8, 8, 8).into(), NOW);
    core.set_transport_state(STATE_KEY, &s.encode_format_1().unwrap())
        .unwrap();
    let (back, reset) = NetState::load_checked(&mut core, NOW, true).unwrap();
    assert!(!reset);
    for n in [4, 5] {
        let e = back.view.get(&id_of(n)).expect("hand-added node kept");
        assert!(e.manual);
        assert_eq!(e.manual_addr, s.view.get(&id_of(n)).unwrap().manual_addr);
    }
    assert_eq!(back.view.len(), 3);
    assert_eq!(back.positions, s.positions);
    assert_eq!(back.ledger, s.ledger);
}

fn report(software: &str) -> NodeInfoReport {
    NodeInfoReport {
        software: software.into(),
        protocol: 5,
        uptime_secs: 86_400,
        storage: barking_proto::FillTier::Medium,
        wake: Some(barking_proto::FillTier::Low),
        push_link: None,
        origin: Some(NodeOrigin {
            asn: 64_496,
            as_name: "EXAMPLE-AS".into(),
            country: *b"FR",
            for_v6: false,
        }),
    }
}

/// `golden_state` with every format 2 table filled (two ids where a table
/// is sorted, so that the order is pinned).
fn golden_state_v2() -> NetState {
    let (a, b, c) = (id_of(0), id_of(1), id_of(2));
    let mut s = golden_state();
    s.info.insert(
        a,
        CachedInfo {
            report: report("barking-node 0.1.0"),
            fetched_at: NOW,
            observed: Some("2001:db8::7".parse().unwrap()),
        },
    );
    s.note_latency(a, &[Duration::from_millis(40), Duration::from_millis(60)]);
    s.note_latency(b, &[Duration::from_millis(120)]);
    s.blocked.insert(
        b,
        BlockedEntry {
            at: NOW,
            origin: None,
        },
    );
    s.blocked.insert(
        c,
        BlockedEntry {
            at: NOW,
            origin: report("x").origin,
        },
    );
    s.defaults.extend([a, c]);
    s.dismissed_defaults.extend([b, c]);
    s
}

#[test]
fn format_2_roundtrip() {
    let (_dir, mut core) = subject(NOW);
    let s = golden_state_v2();
    s.save(&mut core).unwrap();
    let back = NetState::load(&mut core, NOW, true).unwrap();
    assert_eq!(back.info, s.info);
    assert_eq!(back.latency, s.latency);
    assert_eq!(back.blocked, s.blocked);
    assert_eq!(back.defaults, s.defaults);
    assert_eq!(back.dismissed_defaults, s.dismissed_defaults);
    assert_eq!(back.positions, s.positions);
    assert_eq!(back.ledger, s.ledger);
    assert_eq!(back.encode().unwrap(), s.encode().unwrap());
    // The view refuses the blocked nodes again after a load.
    let mut view = back.view.clone();
    assert!(!view.add_manual(id_of(2), crate::test_support::addr(7, 7, 7).into(), NOW));
}

#[test]
fn format_2_load_sanitizes_new_tables() {
    let mut s = golden_state_v2();
    // Info of a node no longer in the view, latency too long, dates ahead.
    s.info.insert(
        id_of(3),
        CachedInfo {
            report: report("gone"),
            fetched_at: NOW,
            observed: None,
        },
    );
    s.info.get_mut(&id_of(0)).unwrap().fetched_at = NOW + 10 * 86_400;
    s.blocked.get_mut(&id_of(1)).unwrap().at = u64::MAX;
    s.latency.insert(id_of(0), (1..=12).collect());
    s.latency.insert(id_of(3), Vec::new());
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert!(!back.info.contains_key(&id_of(3)));
    assert_eq!(back.info[&id_of(0)].fetched_at, NOW);
    assert_eq!(back.blocked[&id_of(1)].at, NOW);
    assert_eq!(back.latency[&id_of(0)], (5..=12).collect::<Vec<u32>>());
    assert!(!back.latency.contains_key(&id_of(3)));
}

/// Node-sent strings stored before they were checked are checked on load:
/// a hostile origin is dropped (cache and blocked list), a report with a
/// hostile software is dropped whole.
#[test]
fn format_2_load_sanitizes_node_strings() {
    let mut s = golden_state_v2();
    let hostile = NodeOrigin {
        asn: 64_496,
        as_name: format!("EXAMPLE\u{202E}{}\n", "A".repeat(1 << 20)),
        country: *b"XY",
        for_v6: false,
    };
    s.info.get_mut(&id_of(0)).unwrap().report.origin = Some(hostile.clone());
    s.blocked.get_mut(&id_of(2)).unwrap().origin = Some(hostile.clone());
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    let kept = &back.info[&id_of(0)].report;
    assert_eq!(kept.origin, None, "origin dropped");
    assert_eq!(kept.software, "barking-node 0.1.0", "rest kept");
    assert_eq!(back.blocked[&id_of(2)].origin, None);

    // A lowercase country alone is refused too.
    let mut lower = hostile;
    lower.as_name = "EXAMPLE-AS".into();
    lower.country = *b"fr";
    s.info.get_mut(&id_of(0)).unwrap().report.origin = Some(lower);
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert_eq!(back.info[&id_of(0)].report.origin, None);

    // A 40-byte software: the whole report goes.
    s.info.get_mut(&id_of(0)).unwrap().report = report(&"v".repeat(40));
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert!(!back.info.contains_key(&id_of(0)));
}

#[test]
fn latency_median_of_last_eight() {
    let mut s = NetState::new(true);
    let x = id_of(0);
    assert_eq!(s.median_latency(&x), None);
    let samples: Vec<Duration> = (1..=10).map(|i| Duration::from_millis(i * 10)).collect();
    s.note_latency(x, &samples);
    assert_eq!(s.latency[&x], vec![30, 40, 50, 60, 70, 80, 90, 100]);
    assert_eq!(s.median_latency(&x), Some(65));
    // Odd count: the middle value; whole milliseconds, saturated.
    let y = id_of(1);
    s.note_latency(
        y,
        &[
            Duration::from_micros(1_900),
            Duration::from_secs(u64::MAX),
            Duration::from_millis(5),
        ],
    );
    assert_eq!(s.latency[&y], vec![1, u32::MAX, 5]);
    assert_eq!(s.median_latency(&y), Some(5));
    // Two saturated values do not overflow the mean.
    let z = id_of(2);
    s.note_latency(z, &[Duration::MAX, Duration::MAX]);
    assert_eq!(s.median_latency(&z), Some(u32::MAX));
    // No samples: no entry.
    s.note_latency(id_of(3), &[]);
    assert!(!s.latency.contains_key(&id_of(3)));
}

/// The bytes of `golden_state_v2` under `FORMAT` 2.
const FORMAT_2: &str = concat!(
    "02a701018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c2069101ecc263",
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
    "1a5fd7c20691808004018d3a191424b7a6b371871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c2",
    "0691126261726b696e672d6e6f646520302e312e300580a3050101000001f0f7030a4558414d504c",
    "452d415346520080a4a7da06010120010db8000000000000000000000007028d3a191424b7a6b371",
    "871d4118e5b63e4e0d6d398e90910e60ab1a5fd7c2069102283cc3fbc0923c6a6a8c64c0c62574ad",
    "50b04f05b53bd5804daedd43d2b584259c1b0178020456825618a8c20bb0ac92826f2e74475b0d03",
    "edde65f9eb1c319cb08a749b5a80a4a7da0601f0f7030a4558414d504c452d4153465200c3fbc092",
    "3c6a6a8c64c0c62574ad50b04f05b53bd5804daedd43d2b584259c1b80a4a7da0600020456825618",
    "a8c20bb0ac92826f2e74475b0d03edde65f9eb1c319cb08a749b5a8d3a191424b7a6b371871d4118",
    "e5b63e4e0d6d398e90910e60ab1a5fd7c20691020456825618a8c20bb0ac92826f2e74475b0d03ed",
    "de65f9eb1c319cb08a749b5ac3fbc0923c6a6a8c64c0c62574ad50b04f05b53bd5804daedd43d2b5",
    "84259c1b",
);

#[test]
fn format_2_bytes_are_frozen() {
    let bytes = golden_state_v2().encode().unwrap();
    assert_eq!(
        hex(&bytes),
        FORMAT_2,
        "the stored network state changed: bump FORMAT and migrate"
    );
    let back = NetState::decode(
        &data_encoding::HEXLOWER.decode(FORMAT_2.as_bytes()).unwrap(),
        NOW,
        true,
    )
    .expect("format 2 still reads");
    assert_eq!(back.encode().unwrap(), bytes);
}
