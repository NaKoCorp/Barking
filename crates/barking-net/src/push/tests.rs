use rand::SeedableRng;
use rand::rngs::StdRng;

use super::*;
use crate::test_support::{id_of, subject};

const NOW: u64 = 1_800_000_000;

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

/// Every mailbox is served by nodes 0..4, best first.
fn ranked(_: &MailboxId) -> Vec<NodeId> {
    (0..4).map(id_of).collect()
}

fn state_for(c: &PushConfig) -> PushState {
    let mut s = PushState::default();
    s.apply_config(Some(c));
    s
}

fn subbed(s: &mut PushState, m: MailboxId, day: u32, nodes: &[usize]) {
    let mut rng = StdRng::seed_from_u64(1);
    for &n in nodes {
        s.note_subscribed(m, day, id_of(n), [n as u8; 32], &mut rng);
    }
}

#[test]
fn fresh_state_subscribes_two_nodes_per_mailbox() {
    let c = cfg(1);
    let wanted = [(mb(1), today()), (mb(2), today() + 1)];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert_eq!(
        plan.subscribe,
        vec![
            (mb(1), id_of(0)),
            (mb(1), id_of(1)),
            (mb(2), id_of(0)),
            (mb(2), id_of(1)),
        ]
    );
    assert!(plan.unsubscribe.is_empty());
    assert!(plan.forget.is_empty());
}

#[test]
fn kept_nodes_stay_and_missing_are_completed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    // Node 2 is subscribed (not the best): it stays, node 0 completes it.
    subbed(&mut s, mb(1), today(), &[2]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today())], ranked, NOW);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(0))]);
    assert!(plan.unsubscribe.is_empty());
    // Complete: nothing to do.
    subbed(&mut s, mb(1), today(), &[0]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today())], ranked, NOW);
    assert_eq!(plan, PushPlan::default());
}

#[test]
fn node_leaving_responsibles_is_unsubscribed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 5]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today())], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), id_of(5), [5; 32])]);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(1))]);
}

#[test]
fn no_wake_node_is_skipped_for_a_day() {
    let c = cfg(1);
    let mut s = state_for(&c);
    s.note_no_wake(id_of(0), NOW);
    let wanted = [(mb(1), today())];
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(1)), (mb(1), id_of(2))]);
    // Still left out just before the end, back after it.
    let wanted = [(mb(1), today() + 1)];
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW + NO_WAKE_SECS - 1);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(1)), (mb(1), id_of(2))]);
    let plan = plan_push(&s, Some(&c), &wanted, ranked, NOW + NO_WAKE_SECS);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(0)), (mb(1), id_of(1))]);
}

#[test]
fn token_change_resubscribes_all() {
    let old = cfg(1);
    let new = cfg(2);
    let mut s = state_for(&old);
    subbed(&mut s, mb(1), today(), &[0, 1]);
    subbed(&mut s, mb(2), today() + 1, &[0, 1]);
    let wanted = [(mb(1), today()), (mb(2), today() + 1)];
    let plan = plan_push(&s, Some(&new), &wanted, ranked, NOW);
    assert_eq!(plan.unsubscribe.len(), 4);
    assert!(plan.unsubscribe.contains(&(mb(2), id_of(1), [1; 32])));
    assert_eq!(plan.subscribe.len(), 4);
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
    let plan = plan_push(&s, None, &[(mb(1), today())], ranked, NOW);
    assert_eq!(
        plan.unsubscribe,
        vec![
            (mb(1), id_of(0), [0; 32]),
            (mb(1), id_of(1), [1; 32]),
            (mb(2), id_of(2), [2; 32]),
        ]
    );
    assert!(plan.subscribe.is_empty());
    assert_eq!(plan.forget, vec![mb(1), mb(2)]);
}

#[test]
fn past_days_are_forgotten_without_unsubscribe() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today() - 1, &[0, 1]);
    subbed(&mut s, mb(2), today(), &[0, 1]);
    let plan = plan_push(&s, Some(&c), &[(mb(2), today())], ranked, NOW);
    assert_eq!(plan.forget, vec![mb(1)]);
    assert!(plan.unsubscribe.is_empty());
    assert!(plan.subscribe.is_empty());
    // A past wanted day is not subscribed either, beyond the horizon neither.
    let wanted = [
        (mb(3), today() - 1),
        (mb(4), today() + HORIZON_DAYS),
        (mb(5), today() + HORIZON_DAYS + 1),
    ];
    let plan = plan_push(&state_for(&c), Some(&c), &wanted, ranked, NOW);
    assert!(plan.subscribe.iter().all(|(m, _)| *m == mb(4)));
    assert_eq!(plan.subscribe.len(), 2);
}

#[test]
fn same_collapse_tag_for_both_nodes_of_a_mailbox() {
    let c = cfg(1);
    let mut rng = StdRng::seed_from_u64(3);
    let mut s = state_for(&c);
    let tag = s.collapse_for(mb(1), today(), &mut rng);
    s.note_subscribed(mb(1), today(), id_of(0), [0; 32], &mut rng);
    s.note_subscribed(mb(1), today(), id_of(1), [1; 32], &mut rng);
    assert_eq!(s.subs[&mb(1)].collapse, tag);
    assert_eq!(s.subs[&mb(1)].nodes.len(), 2);
    // A second mailbox gets its own label.
    let other = s.collapse_for(mb(2), today(), &mut rng);
    assert_ne!(other, tag);
    // Unsubscribing the last node drops the mailbox.
    s.note_unsubscribed(&mb(1), &id_of(0));
    assert_eq!(s.subs[&mb(1)].collapse, tag);
    s.note_unsubscribed(&mb(1), &id_of(1));
    assert!(!s.subs.contains_key(&mb(1)));
}

#[test]
fn expires_day_is_day_plus_one() {
    let c = cfg(1);
    let mut rng = StdRng::seed_from_u64(4);
    let (sub, secret) = build_subscription(&c, mb(1), 100, [8; 16], &mut rng);
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
    let (sub, _) = build_subscription(&c, mb(1), 100, [8; 16], &mut rng);
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
    subbed(&mut s, mb(1), today(), &[0, 1]);
    s.note_no_wake(id_of(0), NOW);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today())], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), id_of(0), [0; 32])]);
    assert_eq!(plan.subscribe, vec![(mb(1), id_of(2))]);
}

#[test]
fn surplus_stored_nodes_are_unsubscribed() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today(), &[0, 1, 2]);
    let plan = plan_push(&s, Some(&c), &[(mb(1), today())], ranked, NOW);
    assert_eq!(plan.unsubscribe, vec![(mb(1), id_of(2), [2; 32])]);
    assert!(plan.subscribe.is_empty());
}

#[test]
fn future_mailbox_no_longer_wanted_is_unsubscribed_and_forgotten() {
    let c = cfg(1);
    let mut s = state_for(&c);
    subbed(&mut s, mb(1), today() + 2, &[0, 1]);
    subbed(&mut s, mb(2), today(), &[0, 1]);
    let plan = plan_push(&s, Some(&c), &[(mb(2), today())], ranked, NOW);
    assert_eq!(
        plan.unsubscribe,
        vec![(mb(1), id_of(0), [0; 32]), (mb(1), id_of(1), [1; 32])]
    );
    assert_eq!(plan.forget, vec![mb(1)]);
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
        MailboxId([1; 16]),
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

#[test]
fn push_state_golden_bytes() {
    let bytes = golden_state().encode();
    assert_eq!(
        hex(&bytes),
        FORMAT_1,
        "the stored push state changed: bump FORMAT and migrate"
    );
    let back = PushState::decode(&data_encoding::HEXLOWER.decode(FORMAT_1.as_bytes()).unwrap())
        .expect("format 1 still reads");
    assert_eq!(back, golden_state());
}
