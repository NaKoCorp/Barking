use rand::SeedableRng;
use rand::rngs::StdRng;

use super::*;
use crate::test_support::{id_of, subject};

const NOW: u64 = 1_800_000_000;
const M: SubKind = SubKind::Messages;
const A: SubKind = SubKind::Acks;

fn today() -> u32 {
    day_of(NOW)
}

fn mb(n: u8) -> MailboxId {
    MailboxId([n; 16])
}

fn cfg(token: u8) -> PushConfig {
    PushConfig {
        relay: RelayRef {
            host: "relay.example.org".into(),
            port: 443,
            id: id_of(9),
        },
        seal_public: [7; 32],
        seal_key_id: 1,
        apns_token: vec![token; 32],
        env: ApnsEnv::Sandbox,
    }
}

/// Every mailbox is served by nodes 0..5 (its five responsibles), best first.
fn ranked(_: &MailboxId) -> Vec<NodeId> {
    (0..5).map(id_of).collect()
}

fn state_for(c: &PushConfig) -> PushState {
    let mut s = PushState::default();
    s.apply_config(Some(c));
    s
}

fn subbed(s: &mut PushState, m: MailboxId, day: u32, nodes: &[usize]) {
    subbed_kind(s, m, M, day, nodes);
}

fn subbed_kind(s: &mut PushState, m: MailboxId, kind: SubKind, day: u32, nodes: &[usize]) {
    let mut rng = StdRng::seed_from_u64(1);
    for &n in nodes {
        s.note_subscribed(m, kind, day, id_of(n), [n as u8; 32], &mut rng);
    }
}

#[test]
fn fresh_state_subscribes_three_nodes_per_mailbox() {
    let c = cfg(1);
    assert_eq!(WAKE_NODES, 3);
    let wanted = [(mb(1), today(), M), (mb(2), today() + 1, M)];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(1), M, id_of(0)),
            (mb(1), M, id_of(1)),
            (mb(1), M, id_of(2)),
            (mb(2), M, id_of(0)),
            (mb(2), M, id_of(1)),
            (mb(2), M, id_of(2)),
        ]
    );
    assert!(plan.unsubscribe.is_empty());
    assert!(plan.forget.is_empty());
}

#[test]
fn kept_nodes_stay_and_missing_are_completed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    // Node 3 is subscribed (not among the best): it stays, nodes 0 and 1
    // complete it.
    subbed(&mut s, mb(1), today(), &[3]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(
        plan.subscribe,
        vec![(mb(1), M, id_of(0)), (mb(1), M, id_of(1))]
    );
    assert!(plan.unsubscribe.is_empty());
    // Complete: nothing to do.
    subbed(&mut s, mb(1), today(), &[0, 1]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(plan, PushPlan::default());
}

#[test]
fn node_leaving_responsibles_is_unsubscribed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 5]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), M, id_of(5), [5; 32])]);
    assert_eq!(
        plan.subscribe,
        vec![(mb(1), M, id_of(1)), (mb(1), M, id_of(2))]
    );
}

#[test]
fn no_wake_node_is_skipped_for_a_day() {
    let c = cfg(1);
    let mut s = state_for(&c);
    s.note_no_wake(id_of(0), NOW);
    let wanted = [(mb(1), today(), M)];
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW);
    let without_0 = vec![
        (mb(1), M, id_of(1)),
        (mb(1), M, id_of(2)),
        (mb(1), M, id_of(3)),
    ];
    assert_eq!(plan.subscribe, without_0);
    // Still left out just before the end, back after it.
    let wanted = [(mb(1), today() + 1, M)];
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW + NO_WAKE_SECS - 1);
    assert_eq!(plan.subscribe, without_0);
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW + NO_WAKE_SECS);
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(1), M, id_of(0)),
            (mb(1), M, id_of(1)),
            (mb(1), M, id_of(2))
        ]
    );
}

#[test]
fn token_change_resubscribes_all() {
    let old = cfg(1);
    let new = cfg(2);
    let mut s = state_for(&old);
    subbed(&mut s, mb(1), today(), &[0, 1]);
    subbed(&mut s, mb(2), today() + 1, &[0, 1]);
    let wanted = [(mb(1), today(), M), (mb(2), today() + 1, M)];
    let plan = plan_push(&s, Some(&new), &wanted, ranked, NOW);
    assert_eq!(plan.unsubscribe.len(), 4);
    assert!(plan.unsubscribe.contains(&(mb(2), M, id_of(1), [1; 32])));
    assert_eq!(plan.subscribe.len(), 2 * WAKE_NODES);
    assert!(plan.forget.is_empty());
    assert_ne!(
        PushState::config_hash_of(&old),
        PushState::config_hash_of(&new)
    );
}

#[test]
fn disabled_unsubscribes_all() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1]);
    subbed(&mut s, mb(2), today() + 1, &[2]);
    let plan = plan_push(&s, None, &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(
        plan.unsubscribe,
        vec![
            (mb(1), M, id_of(0), [0; 32]),
            (mb(1), M, id_of(1), [1; 32]),
            (mb(2), M, id_of(2), [2; 32]),
        ]
    );
    assert!(plan.subscribe.is_empty());
    assert_eq!(plan.forget, vec![(mb(1), M), (mb(2), M)]);
}

#[test]
fn past_days_are_forgotten_without_unsubscribe() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today() - 1, &[0, 1]);
    subbed(&mut s, mb(2), today(), &[0, 1, 2]);
    let plan = plan_push(&s, Some(&c), &[(mb(2), today(), M)], ranked, NOW);
    assert_eq!(plan.forget, vec![(mb(1), M)]);
    assert!(plan.unsubscribe.is_empty());
    assert!(plan.subscribe.is_empty());
    // A past wanted day is not subscribed either, beyond the horizon neither.
    let wanted = [
        (mb(3), today() - 1, M),
        (mb(4), today() + HORIZON_DAYS, M),
        (mb(5), today() + HORIZON_DAYS + 1, M),
    ];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert!(plan.subscribe.iter().all(|(m, _, _)| *m == mb(4)));
    assert_eq!(plan.subscribe.len(), WAKE_NODES);
}

#[test]
fn same_collapse_tag_for_both_nodes_of_a_mailbox() {
    let c = cfg(1);
    let mut rng = StdRng::seed_from_u64(3);
    let mut s = state_for(&c);
    let tag = s.collapse_for(mb(1), M, today(), &mut rng);
    s.note_subscribed(mb(1), M, today(), id_of(0), [0; 32], &mut rng);
    s.note_subscribed(mb(1), M, today(), id_of(1), [1; 32], &mut rng);
    assert_eq!(s.subs[&(mb(1), M)].collapse, tag);
    assert_eq!(s.subs[&(mb(1), M)].nodes.len(), 2);
    // A second mailbox gets its own label.
    let other = s.collapse_for(mb(2), M, today(), &mut rng);
    assert_ne!(other, tag);
    // Unsubscribing the last node drops the mailbox.
    s.note_unsubscribed(&mb(1), M, &id_of(0));
    assert_eq!(s.subs[&(mb(1), M)].collapse, tag);
    s.note_unsubscribed(&mb(1), M, &id_of(1));
    assert!(!s.subs.contains_key(&(mb(1), M)));
}

#[test]
fn expires_day_is_day_plus_one() {
    let c = cfg(1);
    let mut rng = StdRng::seed_from_u64(4);
    let (sub, secret) = build_subscription(&c, mb(1), 100, M, [8; 16], &mut rng);
    assert_eq!(sub.expires_day, 101);
    assert_eq!(sub.mailbox, mb(1));
    assert_eq!(sub.relay, c.relay);
    assert_eq!(sub.cancel_hash, cancel_hash(&secret));
    assert!(sub.sealed.len() <= barking_proto::push::MAX_SEALED);
}

#[test]
fn sealed_token_carries_expiry_and_collapse() {
    let secret = x25519_dalek::StaticSecret::from([5u8; 32]);
    let mut c = cfg(1);
    c.seal_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let mut rng = StdRng::seed_from_u64(4);
    let (sub, _) = build_subscription(&c, mb(1), 100, M, [8; 16], &mut rng);
    let token = barking_proto::push::open(&[(1, secret)], &sub.sealed).unwrap();
    assert_eq!(token.expires_day, 101);
    assert_eq!(token.collapse, [8; 16]);
    assert_eq!(token.apns_token, c.apns_token);
    assert_eq!(token.env, ApnsEnv::Sandbox);
}

#[test]
fn stored_node_in_no_wake_is_unsubscribed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1, 2]);
    s.note_no_wake(id_of(0), NOW);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), M, id_of(0), [0; 32])]);
    assert_eq!(plan.subscribe, vec![(mb(1), M, id_of(3))]);
}

#[test]
fn surplus_stored_nodes_are_unsubscribed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1, 2, 3]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), M, id_of(3), [3; 32])]);
    assert!(plan.subscribe.is_empty());
}

#[test]
fn future_mailbox_no_longer_wanted_is_unsubscribed_and_forgotten() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today() + 2, &[0, 1]);
    subbed(&mut s, mb(2), today(), &[0, 1, 2]);
    let plan = plan_push(&s, Some(&c), &[(mb(2), today(), M)], ranked, NOW);
    assert_eq!(
        plan.unsubscribe,
        vec![(mb(1), M, id_of(0), [0; 32]), (mb(1), M, id_of(1), [1; 32])]
    );
    assert_eq!(plan.forget, vec![(mb(1), M)]);
    assert!(plan.subscribe.is_empty());
}

#[test]
fn apply_config_sets_hash_and_clears_subs() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0]);
    s.apply_config(Some(&cfg(2)));
    assert!(s.subs.is_empty());
    assert_eq!(s.config_hash, Some(PushState::config_hash_of(&cfg(2))));
    s.apply_config(None);
    assert_eq!(s.config_hash, None);
}

#[test]
fn load_save_roundtrip_and_unreadable_state() {
    let (_dir, mut core) = subject(NOW);
    assert_eq!(PushState::load(&core).unwrap(), PushState::default());
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1]);
    s.note_no_wake(id_of(3), NOW);
    s.save(&mut core).unwrap();
    assert_eq!(PushState::load(&core).unwrap(), s);
    core.set_transport_state(PUSH_STATE_KEY, b"\xff\xfe garbage")
        .unwrap();
    assert_eq!(PushState::load(&core).unwrap(), PushState::default());
    let mut bytes = s.encode();
    bytes[0] = FORMAT + 1;
    assert!(PushState::decode(&bytes).is_none());
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn golden_state() -> PushState {
    let mut s = PushState {
        config_hash: Some([0xAB; 32]),
        ..PushState::default()
    };
    s.subs.insert(
        (MailboxId([1; 16]), M),
        BoxSubs {
            day: 20_000,
            collapse: [2; 16],
            nodes: vec![(NodeId([3; 32]), [4; 32]), (NodeId([5; 32]), [6; 32])],
        },
    );
    s.no_wake.insert(NodeId([7; 32]), 1_800_086_400);
    s
}

const FORMAT_1: &str = "0101abababababababababababababababababababababababababababababababab0101010101010101010101010101010101a09c010202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060601070707070707070707070707070707070707070707070707070707070707070780c7acda06";

/// `golden_state` plus an `Acks` entry: what format 2 adds.
fn golden_state_2() -> PushState {
    let mut s = golden_state();
    s.subs.insert(
        (MailboxId([8; 16]), A),
        BoxSubs {
            day: 20_001,
            collapse: [9; 16],
            nodes: vec![(NodeId([10; 32]), [11; 32])],
        },
    );
    s
}

const FORMAT_2: &str = "0201abababababababababababababababababababababababababababababababab020101010101010101010101010101010100a09c01020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060808080808080808080808080808080801a19c0109090909090909090909090909090909010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01070707070707070707070707070707070707070707070707070707070707070780c7acda06";

#[test]
fn push_state_golden_bytes() {
    assert_eq!(FORMAT, 2);
    let bytes = golden_state_2().encode();
    assert_eq!(
        hex(&bytes),
        FORMAT_2,
        "the stored push state changed: bump FORMAT and migrate"
    );
    let back = PushState::decode(&data_encoding::HEXLOWER.decode(FORMAT_2.as_bytes()).unwrap())
        .expect("format 2 reads");
    assert_eq!(back, golden_state_2());
}

#[test]
fn push_state_format_1_reads_as_messages() {
    let bytes = data_encoding::HEXLOWER.decode(FORMAT_1.as_bytes()).unwrap();
    // Every subscription of format 1 was a `Messages` one: none is lost.
    let back = PushState::decode(&bytes).expect("format 1 still reads");
    assert_eq!(back, golden_state());
    assert_eq!(back.subs.len(), 1);
    assert!(back.subs.keys().all(|(_, kind)| *kind == M));
    // Read through the core's database too, and written back as format 2.
    let (_dir, mut core) = subject(NOW);
    core.set_transport_state(PUSH_STATE_KEY, &bytes).unwrap();
    let loaded = PushState::load(&core).unwrap();
    assert_eq!(loaded, golden_state());
    loaded.save(&mut core).unwrap();
    let saved = core.transport_state(PUSH_STATE_KEY).unwrap().unwrap();
    assert_eq!(saved[0], FORMAT);
    assert_eq!(PushState::decode(&saved), Some(golden_state()));
    // The plan keeps the old subscriptions where they are.
    let c = cfg(1);
    let mut st = loaded;
    st.config_hash = Some(PushState::config_hash_of(&c));
    let wanted = [(MailboxId([1; 16]), 20_000, M)];
    let plan = plan_push(
        &st,
        Some(&c),
        &wanted,
        |_| vec![NodeId([3; 32]), NodeId([5; 32])],
        20_000 * 86_400,
    );
    assert_eq!(plan, PushPlan::default());
}

#[test]
fn plan_push_keeps_kinds_apart() {
    let c = cfg(1);
    // The same mailbox wanted for messages and for acks: two subscriptions
    // on each node.
    let wanted = [(mb(1), today(), M), (mb(1), today(), A)];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(1), M, id_of(0)),
            (mb(1), M, id_of(1)),
            (mb(1), M, id_of(2)),
            (mb(1), A, id_of(0)),
            (mb(1), A, id_of(1)),
            (mb(1), A, id_of(2)),
        ]
    );
    // Held for messages, no longer awaited for acks: only the acks are
    // cancelled and forgotten.
    let mut s = state_for(&c);
    subbed_kind(&mut s, mb(1), M, today(), &[0, 1, 2]);
    subbed_kind(&mut s, mb(1), A, today(), &[3, 4]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], ranked, NOW);
    assert!(plan.subscribe.is_empty());
    assert_eq!(
        plan.unsubscribe,
        vec![(mb(1), A, id_of(3), [3; 32]), (mb(1), A, id_of(4), [4; 32])]
    );
    assert_eq!(plan.forget, vec![(mb(1), A)]);
    // Each kind has its own collapse label and its own nodes.
    let mut rng = StdRng::seed_from_u64(5);
    let mut fresh = state_for(&c);
    let labels = [
        fresh.collapse_for(mb(1), M, today(), &mut rng),
        fresh.collapse_for(mb(1), A, today(), &mut rng),
    ];
    assert_ne!(labels[0], labels[1]);
    assert_eq!(fresh.subs.len(), 2);
    s.note_unsubscribed(&mb(1), A, &id_of(3));
    s.note_unsubscribed(&mb(1), A, &id_of(4));
    assert!(!s.subs.contains_key(&(mb(1), A)));
    assert_eq!(s.subs[&(mb(1), M)].nodes.len(), 3);
}

#[test]
fn acks_of_yesterday_are_still_subscribed() {
    let c = cfg(1);
    // A message sealed yesterday may be acked today: its mailbox (of
    // yesterday) is still subscribed for acks, not for messages.
    let wanted = [
        (mb(1), today() - 1, A),
        (mb(2), today() - 1, M),
        (mb(3), today() - 2, A),
    ];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(1), A, id_of(0)),
            (mb(1), A, id_of(1)),
            (mb(1), A, id_of(2))
        ]
    );
    // No longer awaited: yesterday's is cancelled (its subscription runs
    // until the end of today), older ones are forgotten.
    let mut s = state_for(&c);
    subbed_kind(&mut s, mb(1), A, today() - 1, &[0]);
    subbed_kind(&mut s, mb(3), A, today() - 2, &[1]);
    let plan = plan_push(&s, Some(&c), &[], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), A, id_of(0), [0; 32])]);
    assert_eq!(plan.forget, vec![(mb(1), A), (mb(3), A)]);
}

#[test]
fn subscription_carries_its_kind_and_the_wake_reason() {
    let secret = x25519_dalek::StaticSecret::from([5u8; 32]);
    let mut c = cfg(1);
    c.seal_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let mut rng = StdRng::seed_from_u64(4);
    for (kind, reason) in [(M, WakeReason::Message), (A, WakeReason::Receipt)] {
        let (sub, _) = build_subscription(&c, mb(1), 100, kind, [8; 16], &mut rng);
        assert_eq!(sub.kind, kind);
        let token = barking_proto::push::open(&[(1, secret.clone())], &sub.sealed).unwrap();
        assert_eq!(token.reason, reason);
    }
}

#[test]
fn mailbox_without_responsibles_keeps_its_subscriptions() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1]);
    // No responsible known for the mailbox (a view without records): its
    // stored nodes are neither cancelled nor replaced, nor forgotten.
    let plan = plan_push(&s, Some(&c), &[(mb(1), today(), M)], |_| Vec::new(), NOW);
    assert_eq!(plan, PushPlan::default());
    // Wanted but without responsibles, next to a mailbox that has some.
    let wanted = [(mb(1), today(), M), (mb(2), today(), M)];
    let plan = plan_push(
        &s,
        Some(&c),
        &wanted,
        |m| if *m == mb(1) { Vec::new() } else { ranked(m) },
        NOW,
    );
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(2), M, id_of(0)),
            (mb(2), M, id_of(1)),
            (mb(2), M, id_of(2))
        ]
    );
    assert!(plan.unsubscribe.is_empty() && plan.forget.is_empty());
}

#[test]
fn wake_nodes_always_meet_the_first_copies() {
    // A sender puts its first copies on CLIENT_COPIES of the RESPONSIBLES;
    // the recipient subscribes on WAKE_NODES of them. With agreeing views,
    // the two sets always share a node, so the first wake-up does not wait
    // for replication (spec §1).
    const { assert!(WAKE_NODES + crate::plan::CLIENT_COPIES > crate::RESPONSIBLES) };
    // The node keeps at most 4 subscriptions per mailbox.
    const { assert!(WAKE_NODES <= 4) };
}
