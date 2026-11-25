use std::net::SocketAddr;
use std::time::Duration;

use barking_core::transparency::TransparencyEvent;
use barking_packet::{Kind, MailboxId, Packet, PacketId, Tier};
use barking_proto::pow::content_hash;
use barking_proto::push::{ApnsEnv, RelayRef, SubKind};
use barking_proto::{FillTier, NodeInfoReport, NodeOrigin};
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::*;
use crate::plan::{plan_deposits, record_outcome};
use crate::push::{PushConfig, PushState, plan_push};
use crate::state::CachedInfo;
use crate::sync::short_id;
use crate::test_support::{addr, id_of, record, subject};

const NOW: u64 = 1_800_000_000; // On the hour.
const MB: MailboxId = MailboxId([7; 16]);

/// A state whose view holds nodes `ns`, all confirmed.
fn state_with(ns: &[usize]) -> NetState {
    let mut s = NetState::new(true);
    for &n in ns {
        s.view.insert(record(n, NOW), NOW);
        s.view.confirm(&id_of(n), NOW);
    }
    s
}

fn origin() -> NodeOrigin {
    NodeOrigin {
        asn: 64_500,
        as_name: "Example AS".into(),
        country: *b"FR",
        for_v6: false,
    }
}

fn report() -> NodeInfoReport {
    NodeInfoReport {
        software: "barking-node 0.5.0".into(),
        protocol: 5,
        uptime_secs: 3_600,
        storage: FillTier::Low,
        wake: Some(FillTier::Low),
        push_link: None,
        origin: Some(origin()),
    }
}

fn msg(n: u8) -> Vec<u8> {
    Packet {
        kind: Kind::Message,
        hops: 8,
        tier: Tier::S,
        id: PacketId([n; 16]),
        expires_at: (NOW + 7 * 86_400) as u32,
        mailbox: MB,
        payload: vec![n],
    }
    .encode()
}

fn cfg() -> PushConfig {
    PushConfig {
        relay: RelayRef {
            host: "relay.example.org".into(),
            port: 443,
            id: id_of(9),
        },
        seal_public: [7; 32],
        seal_key_id: 1,
        apns_token: vec![1; 32],
        env: ApnsEnv::Sandbox,
    }
}

fn manual_addr(n: u8) -> SocketAddr {
    addr(9, 9, n).into()
}

#[test]
fn block_forgets_everything_about_node() {
    let mut s = state_with(&[0, 1, 2]);
    let (x, y) = (id_of(0), id_of(1));
    let m = MailboxId([3; 16]);
    for id in [x, y] {
        s.positions.insert((id, m), 42);
        s.audited_at.insert((id, m), NOW);
        s.reread_at.insert((id, m), NOW);
        s.crosscheck_at.insert((id, m), NOW);
        s.unaudited.insert(id, 2);
        s.down_failed.insert(id, NOW);
        s.page_bytes.insert(id, 16 << 10);
        s.info.insert(
            id,
            CachedInfo {
                report: report(),
                fetched_at: NOW,
            },
        );
        s.note_latency(id, &[Duration::from_millis(40)]);
        record_outcome(&mut s.ledger, content_hash(&msg(1)), id, &Ok(()), NOW);
    }
    let mut push = PushState::default();
    push.apply_config(Some(&cfg()));
    let mut rng = StdRng::seed_from_u64(1);
    for id in [x, y] {
        push.note_subscribed(m, SubKind::Messages, 1, id, [1; 32], &mut rng);
    }

    block_node(&mut s, &mut push, x, NOW + 60);

    assert!(s.view.get(&x).is_none());
    assert!(s.view.is_blocked(&x));
    let entry = s.blocked.get(&x).expect("blocked");
    assert_eq!(entry.origin, Some(origin()));
    assert_eq!(entry.at, NOW);
    assert!(!s.positions.keys().any(|(n, _)| *n == x));
    assert!(!s.audited_at.keys().any(|(n, _)| *n == x));
    assert!(!s.reread_at.keys().any(|(n, _)| *n == x));
    assert!(!s.crosscheck_at.keys().any(|(n, _)| *n == x));
    for present in [
        s.unaudited.contains_key(&x),
        s.down_failed.contains_key(&x),
        s.page_bytes.contains_key(&x),
        s.info.contains_key(&x),
        s.latency.contains_key(&x),
    ] {
        assert!(!present);
    }
    assert_eq!(s.ledger.holders(&content_hash(&msg(1))), vec![y]);
    assert!(
        push.subs
            .values()
            .all(|b| b.nodes.iter().all(|(n, _)| *n != x))
    );
    // The other node keeps everything.
    assert!(s.view.get(&y).is_some());
    assert_eq!(s.positions.get(&(y, m)), Some(&42));
    assert!(s.info.contains_key(&y) && s.latency.contains_key(&y));
    // Nothing lets it back in.
    assert!(!s.view.add_manual(x, manual_addr(1), NOW));
    assert!(!s.view.insert(record(0, NOW + 10), NOW + 10));
    // The block survives a save and a load.
    let back = NetState::decode(&s.encode().unwrap(), NOW, true).unwrap();
    assert!(back.blocked.contains_key(&x) && back.view.is_blocked(&x));
}

#[test]
fn blocked_copy_is_redeposited() {
    let mut s = state_with(&[0, 1, 2, 3]);
    let bytes = msg(1);
    let outbox = vec![bytes.clone()];
    let responsibles = s.view.responsibles(&MB, NOW);
    assert_eq!(responsibles.len(), 4);
    let (x, rest) = (responsibles[0], &responsibles[1..]);
    for &n in [x].iter().chain(&rest[..2]) {
        record_outcome(&mut s.ledger, content_hash(&bytes), n, &Ok(()), NOW);
    }
    let plan =
        |s: &NetState| plan_deposits(&outbox, &s.ledger, |m| s.view.responsibles(m, NOW), NOW);
    // Three copies held: nothing to do.
    assert!(plan(&s).is_empty());

    block_node(&mut s, &mut PushState::default(), x, NOW);

    let after = plan(&s);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].node, rest[2]);
    assert!(!after[0].first_copy);
}

#[test]
fn block_of_the_only_holder_makes_a_fresh_first_copy() {
    let mut s = state_with(&[0, 1, 2, 3]);
    let bytes = msg(1);
    let x = s.view.responsibles(&MB, NOW)[0];
    record_outcome(&mut s.ledger, content_hash(&bytes), x, &Ok(()), NOW);
    block_node(&mut s, &mut PushState::default(), x, NOW);
    let plan = plan_deposits(&[bytes], &s.ledger, |m| s.view.responsibles(m, NOW), NOW);
    assert!(plan.iter().all(|d| d.node != x));
    assert!(plan[0].first_copy);
    assert_eq!(plan.len(), crate::plan::CLIENT_COPIES);
}

#[test]
fn block_drops_subscriptions_without_unsubscribe() {
    let mut s = state_with(&[0, 1, 2, 3, 4]);
    let c = cfg();
    let mut push = PushState::default();
    push.apply_config(Some(&c));
    let today = barking_core::mailbox::day_of(NOW);
    let ranked = s.view.responsibles(&MB, NOW);
    let x = ranked[0];
    let mut rng = StdRng::seed_from_u64(1);
    for &n in &ranked[..3] {
        push.note_subscribed(MB, SubKind::Messages, today, n, [2; 32], &mut rng);
    }

    block_node(&mut s, &mut push, x, NOW);

    let wanted = [(MB, today, SubKind::Messages)];
    let plan = plan_push(
        &push,
        Some(&c),
        &wanted,
        |m| s.view.responsibles(m, NOW),
        NOW,
    );
    assert!(plan.unsubscribe.iter().all(|(_, _, n, _)| *n != x));
    assert!(plan.subscribe.iter().all(|(_, _, n)| *n != x));
    // A replacement is subscribed elsewhere.
    assert_eq!(plan.subscribe.len(), 1);
}

#[test]
fn unblock_lets_the_node_back_by_normal_ways_only() {
    let mut s = state_with(&[0, 1]);
    let x = id_of(0);
    block_node(&mut s, &mut PushState::default(), x, NOW);
    assert!(unblock_node(&mut s, &x));
    assert!(!unblock_node(&mut s, &x));
    assert!(s.blocked.is_empty() && !s.view.is_blocked(&x));
    // Not back by itself, but discovery or a manual add may bring it.
    assert!(s.view.get(&x).is_none());
    assert!(s.view.add_manual(x, manual_addr(1), NOW));
}

#[test]
fn remove_default_is_remembered() {
    let mut s = NetState::new(true);
    let d = id_of(5);
    let defaults = [(d, manual_addr(5))];
    add_default_nodes(&mut s, &defaults, NOW);
    assert!(s.view.get(&d).is_some_and(|e| e.manual));
    assert!(s.defaults.contains(&d));

    assert!(remove_node(&mut s, &d));
    assert!(s.view.get(&d).is_none());
    assert!(s.dismissed_defaults.contains(&d));

    // At the next launch the default list comes again: D stays out.
    add_default_nodes(&mut s, &defaults, NOW + 3_600);
    assert!(s.view.get(&d).is_none());
}

#[test]
fn remove_node_keeps_a_discovered_node() {
    let mut s = state_with(&[0]);
    let x = id_of(0);
    s.view.add_manual(x, manual_addr(1), NOW);
    assert!(remove_node(&mut s, &x));
    let e = s.view.get(&x).expect("still known by the DHT");
    assert!(!e.manual && e.manual_addr.is_none());
    // Not a default node: nothing dismissed. Removing again does nothing.
    assert!(s.dismissed_defaults.is_empty());
    assert!(!remove_node(&mut s, &x));
}

#[test]
fn reset_defaults_keeps_blocked() {
    let mut s = NetState::new(true);
    let (d1, d2) = (id_of(5), id_of(6));
    let defaults = [(d1, manual_addr(5)), (d2, manual_addr(6))];
    add_default_nodes(&mut s, &defaults, NOW);
    assert!(remove_node(&mut s, &d1));
    block_node(&mut s, &mut PushState::default(), d2, NOW);
    // A blocked default is not added again at launch either.
    add_default_nodes(&mut s, &defaults, NOW);
    assert!(s.view.get(&d1).is_none() && s.view.get(&d2).is_none());

    assert_eq!(reset_default_nodes(&mut s, &defaults, NOW), 1);
    assert!(s.view.get(&d1).is_some_and(|e| e.manual));
    assert!(s.dismissed_defaults.is_empty());
    assert!(s.blocked.contains_key(&d2) && s.view.get(&d2).is_none());
    // Nothing left to restore.
    assert_eq!(reset_default_nodes(&mut s, &defaults, NOW), 0);
}

#[test]
fn journal_logs_block_and_unblock() {
    let (_dir, mut core) = subject(NOW);
    let s = state_with(&[0, 1]);
    s.save(&mut core).unwrap();
    let x = id_of(0);
    let logged = |core: &Core| -> Vec<TransparencyEvent> {
        core.transparency_log(100)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .filter(|e| {
                matches!(
                    e,
                    TransparencyEvent::NodeBlocked { .. } | TransparencyEvent::NodeUnblocked { .. }
                )
            })
            .collect()
    };

    block_node_in_core(&mut core, x, NOW, true).unwrap();
    let state = NetState::load(&mut core, NOW, true).unwrap();
    assert!(state.blocked.contains_key(&x) && state.view.get(&x).is_none());
    assert_eq!(
        logged(&core),
        vec![TransparencyEvent::NodeBlocked {
            id_short: short_id(&x)
        }]
    );

    assert!(unblock_node_in_core(&mut core, &x, NOW, true).unwrap());
    // Unblocking a node that is not blocked logs nothing.
    assert!(!unblock_node_in_core(&mut core, &x, NOW, true).unwrap());
    let mut events = logged(&core);
    events.sort_by_key(|e| matches!(e, TransparencyEvent::NodeUnblocked { .. }));
    assert_eq!(
        events,
        vec![
            TransparencyEvent::NodeBlocked {
                id_short: short_id(&x)
            },
            TransparencyEvent::NodeUnblocked {
                id_short: short_id(&x)
            },
        ]
    );
    assert!(
        NetState::load(&mut core, NOW, true)
            .unwrap()
            .blocked
            .is_empty()
    );
}

#[test]
fn core_wrappers_save_defaults_and_removals() {
    let (_dir, mut core) = subject(NOW);
    let (d1, d2) = (id_of(5), id_of(6));
    let defaults = [(d1, manual_addr(5)), (d2, manual_addr(6))];
    add_default_nodes_in_core(&mut core, &defaults, NOW, true).unwrap();
    assert!(remove_node_in_core(&mut core, &d1, NOW, true).unwrap());
    let s = NetState::load(&mut core, NOW, true).unwrap();
    assert!(s.view.get(&d1).is_none() && s.view.get(&d2).is_some());
    assert!(s.dismissed_defaults.contains(&d1));
    assert_eq!(
        reset_default_nodes_in_core(&mut core, &defaults, NOW, true).unwrap(),
        1
    );
    let s = NetState::load(&mut core, NOW, true).unwrap();
    assert!(s.view.get(&d1).is_some() && s.dismissed_defaults.is_empty());
}
