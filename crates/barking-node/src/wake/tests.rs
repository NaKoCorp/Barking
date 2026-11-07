use super::*;
use crate::rules::{self, Policy};
use barking_packet::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier, ack};
use barking_proto::node_id::NodeId;
use barking_proto::push::SubKind;

const NOW: u64 = 1_800_000_000;
const BITS: u8 = 1;

fn today() -> u32 {
    day_of(NOW)
}

fn mb(n: u8) -> MailboxId {
    MailboxId([n; 16])
}

fn relay(host: &str) -> RelayRef {
    RelayRef {
        host: host.to_string(),
        port: 4433,
        id: NodeId([7; 32]),
    }
}

fn policy() -> Policy {
    Policy {
        pow_bits: BITS,
        max_per_mailbox: 1_000,
        storage_max_bytes: 1 << 30,
    }
}

fn store() -> NodeStore {
    NodeStore::open_in_memory().unwrap()
}

/// A valid subscription for `mailbox`, identified by `cancel`.
fn raw_sub(mailbox: u8, cancel: u8) -> Subscription {
    Subscription {
        mailbox: mb(mailbox),
        relay: relay("relay.example.org"),
        sealed: vec![cancel; 80],
        cancel_hash: cancel_hash(&[cancel; 32]),
        expires_day: today() + 1,
        kind: SubKind::Messages,
    }
}

fn solve(sub: &Subscription) -> u64 {
    pow::solve(&subscription_hash(sub), &sub.mailbox, BITS).unwrap()
}

fn sub(mailbox: u8, cancel: u8) -> (Subscription, u64) {
    let s = raw_sub(mailbox, cancel);
    let n = solve(&s);
    (s, n)
}

fn subscribe_ok(s: &mut NodeStore, mailbox: u8, cancel: u8) {
    let (sb, n) = sub(mailbox, cancel);
    assert_eq!(
        subscribe(s, &WakeConfig::default(), BITS, &sb, n, NOW).unwrap(),
        Ok(())
    );
}

fn try_subscribe(
    s: &mut NodeStore,
    cfg: &WakeConfig,
    sb: &Subscription,
) -> core::result::Result<(), ErrorReason> {
    subscribe(s, cfg, BITS, sb, solve(sb), NOW).unwrap()
}

fn message(n: u8, mailbox: u8) -> Packet {
    let mut id = [0u8; 16];
    id[0] = n;
    id[1] = mailbox;
    Packet {
        kind: Kind::Message,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId(id),
        expires_at: u32::try_from(NOW + 86_400).unwrap(),
        mailbox: mb(mailbox),
        payload: vec![n; 8],
    }
}

fn deposit_at(s: &mut NodeStore, p: &Packet, now: u64) {
    let bits = rules::required_pow_bits(s, &policy(), &p.mailbox, p.tier).unwrap();
    let nonce = pow::solve(&pow::content_hash(&p.encode()), &p.mailbox, bits).unwrap();
    assert_eq!(
        rules::deposit(s, &policy(), &p.encode(), nonce, now).unwrap(),
        Ok(())
    );
}

fn order(sb: &Subscription) -> WakeOrder {
    WakeOrder {
        relay: sb.relay.clone(),
        sealed: sb.sealed.clone(),
    }
}

#[test]
fn subscribe_then_message_gives_one_wake() {
    let mut s = store();
    let (sb, n) = sub(1, 1);
    subscribe(&mut s, &WakeConfig::default(), BITS, &sb, n, NOW)
        .unwrap()
        .unwrap();
    deposit_at(&mut s, &message(1, 1), NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap(), vec![order(&sb)]);
    assert!(take_due(&mut s, NOW, 100).unwrap().is_empty());
}

#[test]
fn burst_is_coalesced_to_the_next_minute() {
    let mut s = store();
    let (sb, _) = sub(1, 1);
    subscribe_ok(&mut s, 1, 1);
    deposit_at(&mut s, &message(1, 1), NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap().len(), 1);
    deposit_at(&mut s, &message(2, 1), NOW + 10);
    assert!(take_due(&mut s, NOW + 10, 100).unwrap().is_empty());
    assert_eq!(next_due(&s).unwrap(), Some(NOW + 60));
    assert_eq!(take_due(&mut s, NOW + 60, 100).unwrap(), vec![order(&sb)]);
    assert_eq!(next_due(&s).unwrap(), None);
}

const SECRET: [u8; 16] = [9; 16];

/// A message of `mailbox` whose id is derived from `SECRET`, expiring at `expires`.
fn acked_message(mailbox: u8, expires: u64) -> Packet {
    Packet {
        id: ack::packet_id_for(&SECRET),
        expires_at: u32::try_from(expires).unwrap(),
        ..message(1, mailbox)
    }
}

fn ack_of(m: &Packet) -> Packet {
    let mut payload = m.id.0.to_vec();
    payload.extend_from_slice(&SECRET);
    Packet {
        kind: Kind::Ack,
        hops: DEFAULT_HOPS,
        tier: Tier::S,
        id: PacketId([0xA0; 16]),
        expires_at: u32::try_from(NOW + 86_400).unwrap(),
        mailbox: m.mailbox,
        payload,
    }
}

fn subscribe_kind(s: &mut NodeStore, mailbox: u8, cancel: u8, kind: SubKind) -> Subscription {
    let sb = Subscription {
        kind,
        ..raw_sub(mailbox, cancel)
    };
    assert_eq!(try_subscribe(s, &WakeConfig::default(), &sb), Ok(()));
    sb
}

fn kind_of(s: &NodeStore, cancel: u8) -> i64 {
    s.conn()
        .query_row(
            "SELECT kind FROM subscriptions WHERE cancel_hash=?1",
            params![&cancel_hash(&[cancel; 32])[..]],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn ack_marks_only_ack_subscribers() {
    let mut s = store();
    let msgs = subscribe_kind(&mut s, 1, 1, SubKind::Messages);
    let acks = subscribe_kind(&mut s, 1, 2, SubKind::Acks);
    assert_eq!(kind_of(&s, 1), 0);
    assert_eq!(kind_of(&s, 2), 1);
    // Deposit then drain the message's own wake-up, so only the ack could mark.
    let m = acked_message(1, NOW + 86_400);
    deposit_at(&mut s, &m, NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap(), vec![order(&msgs)]);
    assert_eq!(
        rules::deposit(&mut s, &policy(), &ack_of(&m).encode(), 0, NOW + 120).unwrap(),
        Ok(())
    );
    assert_eq!(
        take_due(&mut s, NOW + 120, 100).unwrap(),
        vec![order(&acks)]
    );
}

#[test]
fn message_marks_only_message_subscribers() {
    let mut s = store();
    let msgs = subscribe_kind(&mut s, 1, 1, SubKind::Messages);
    subscribe_kind(&mut s, 1, 2, SubKind::Acks);
    deposit_at(&mut s, &message(1, 1), NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap(), vec![order(&msgs)]);
    assert!(take_due(&mut s, NOW + 120, 100).unwrap().is_empty());
}

#[test]
fn replicated_ack_marks_once() {
    let mut s = store();
    let acks = subscribe_kind(&mut s, 1, 1, SubKind::Acks);
    let m = acked_message(1, NOW + 86_400);
    deposit_at(&mut s, &m, NOW);
    let a = ack_of(&m).encode();
    assert_eq!(
        rules::deposit(&mut s, &policy(), &a, 0, NOW + 1).unwrap(),
        Ok(())
    );
    assert_eq!(take_due(&mut s, NOW + 1, 100).unwrap(), vec![order(&acks)]);
    // The same ack arriving again by replication is already known.
    assert_eq!(
        rules::store_copy(&mut s, &policy(), &a, 0, NOW + 120).unwrap(),
        Ok(())
    );
    assert!(take_due(&mut s, NOW + 120, 100).unwrap().is_empty());
}

#[test]
fn ack_arriving_by_replication_marks_ack_subscribers() {
    let mut s = store();
    let acks = subscribe_kind(&mut s, 1, 1, SubKind::Acks);
    let m = acked_message(1, NOW + 86_400);
    deposit_at(&mut s, &m, NOW);
    assert_eq!(
        rules::store_copy(&mut s, &policy(), &ack_of(&m).encode(), 0, NOW + 1).unwrap(),
        Ok(())
    );
    assert_eq!(take_due(&mut s, NOW + 1, 100).unwrap(), vec![order(&acks)]);
}

#[test]
fn expired_unacked_message_marks_ack_subscribers() {
    let mut s = store();
    let acks = subscribe_kind(&mut s, 1, 1, SubKind::Acks);
    subscribe_kind(&mut s, 1, 2, SubKind::Messages);
    let m = message(1, 1);
    let m = Packet {
        expires_at: u32::try_from(NOW + 60).unwrap(),
        ..m
    };
    deposit_at(&mut s, &m, NOW);
    // Drain the message subscriber's own wake-up.
    assert_eq!(take_due(&mut s, NOW, 100).unwrap().len(), 1);
    // Not expired yet: nothing marked.
    let (_, _, marked) = s.purge_expired_batch(NOW + 59, 100).unwrap();
    assert!(!marked);
    let (removed, more, marked) = s.purge_expired_batch(NOW + 61, 100).unwrap();
    assert_eq!((removed, more, marked), (1, false, true));
    assert_eq!(take_due(&mut s, NOW + 61, 100).unwrap(), vec![order(&acks)]);
}

#[test]
fn acked_message_purge_does_not_mark() {
    let mut s = store();
    let acks = subscribe_kind(&mut s, 1, 1, SubKind::Acks);
    let m = acked_message(1, NOW + 60);
    deposit_at(&mut s, &m, NOW);
    assert_eq!(
        rules::deposit(&mut s, &policy(), &ack_of(&m).encode(), 0, NOW + 1).unwrap(),
        Ok(())
    );
    assert_eq!(take_due(&mut s, NOW + 1, 100).unwrap(), vec![order(&acks)]);
    // The message is gone with its ack; purging its (and the ack's) expiry
    // marks nothing again.
    let (_, _, marked) = s.purge_expired_batch(NOW + 200_000, 100).unwrap();
    assert!(!marked);
    assert!(take_due(&mut s, NOW + 200_000, 100).unwrap().is_empty());
}

#[test]
fn cap_is_per_kind() {
    let mut s = store();
    let cfg = WakeConfig::default();
    let of = |cancel: u8, kind: SubKind| Subscription {
        kind,
        ..raw_sub(1, cancel)
    };
    for c in 1..=4 {
        assert_eq!(
            try_subscribe(&mut s, &cfg, &of(c, SubKind::Messages)),
            Ok(())
        );
    }
    for c in 11..=14 {
        assert_eq!(try_subscribe(&mut s, &cfg, &of(c, SubKind::Acks)), Ok(()));
    }
    assert_eq!(
        try_subscribe(&mut s, &cfg, &of(15, SubKind::Acks)),
        Err(ErrorReason::MailboxFull)
    );
    assert_eq!(
        try_subscribe(&mut s, &cfg, &of(5, SubKind::Messages)),
        Err(ErrorReason::MailboxFull)
    );
}

#[test]
fn known_packet_does_not_mark() {
    let mut s = store();
    subscribe_ok(&mut s, 1, 1);
    let p = message(1, 1);
    deposit_at(&mut s, &p, NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap().len(), 1);
    // The replicated copy of the same message is already known.
    assert_eq!(
        rules::store_copy(&mut s, &policy(), &p.encode(), 0, NOW + 120).unwrap(),
        Ok(())
    );
    assert!(take_due(&mut s, NOW + 120, 100).unwrap().is_empty());
}

#[test]
fn subscribe_day_bounds() {
    let mut s = store();
    let cfg = WakeConfig::default();
    let at = |day: u32, cancel: u8| Subscription {
        expires_day: day,
        ..raw_sub(1, cancel)
    };
    assert_eq!(try_subscribe(&mut s, &cfg, &at(today(), 1)), Ok(()));
    assert_eq!(try_subscribe(&mut s, &cfg, &at(today() + 8, 2)), Ok(()));
    assert_eq!(
        try_subscribe(&mut s, &cfg, &at(today() - 1, 3)),
        Err(ErrorReason::Expired)
    );
    assert_eq!(
        try_subscribe(&mut s, &cfg, &at(today() + 9, 3)),
        Err(ErrorReason::TooFarInFuture)
    );
}

#[test]
fn subscribe_caps() {
    let mut s = store();
    let cfg = WakeConfig::default();
    for c in 1..=4 {
        assert_eq!(try_subscribe(&mut s, &cfg, &raw_sub(1, c)), Ok(()));
    }
    assert_eq!(
        try_subscribe(&mut s, &cfg, &raw_sub(1, 5)),
        Err(ErrorReason::MailboxFull)
    );
    // Same (mailbox, cancel_hash): replacement, not counted against the cap.
    assert_eq!(try_subscribe(&mut s, &cfg, &raw_sub(1, 2)), Ok(()));
    let count: i64 = s
        .conn()
        .query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 4);
    // Another mailbox is unaffected by the per-mailbox cap.
    assert_eq!(try_subscribe(&mut s, &cfg, &raw_sub(2, 1)), Ok(()));

    let mut s = store();
    let cfg = WakeConfig {
        max_subscriptions: 1,
        ..WakeConfig::default()
    };
    assert_eq!(try_subscribe(&mut s, &cfg, &raw_sub(1, 1)), Ok(()));
    assert_eq!(
        try_subscribe(&mut s, &cfg, &raw_sub(2, 1)),
        Err(ErrorReason::NodeFull)
    );
    // Replacement still works when the node is full.
    assert_eq!(try_subscribe(&mut s, &cfg, &raw_sub(1, 1)), Ok(()));
}

#[test]
fn subscribe_rejects_bad_relay() {
    let mut s = store();
    let cfg = WakeConfig::default();
    for host in ["127.0.0.1", "::1", "10.0.0.1", &"a".repeat(300)] {
        let sb = Subscription {
            relay: relay(host),
            ..raw_sub(1, 1)
        };
        assert_eq!(
            try_subscribe(&mut s, &cfg, &sb),
            Err(ErrorReason::Malformed),
            "{host}"
        );
    }
    let port0 = Subscription {
        relay: RelayRef {
            port: 0,
            ..relay("relay.example.org")
        },
        ..raw_sub(1, 1)
    };
    assert_eq!(
        try_subscribe(&mut s, &cfg, &port0),
        Err(ErrorReason::Malformed)
    );
    let big = Subscription {
        sealed: vec![1; MAX_SEALED + 1],
        ..raw_sub(1, 1)
    };
    assert_eq!(
        try_subscribe(&mut s, &cfg, &big),
        Err(ErrorReason::Malformed)
    );
    let empty = Subscription {
        sealed: vec![],
        ..raw_sub(1, 1)
    };
    assert_eq!(
        try_subscribe(&mut s, &cfg, &empty),
        Err(ErrorReason::Malformed)
    );
}

#[test]
fn subscribe_disabled_and_weak_pow() {
    let mut s = store();
    let off = WakeConfig {
        enabled: false,
        ..WakeConfig::default()
    };
    assert_eq!(
        try_subscribe(&mut s, &off, &raw_sub(1, 1)),
        Err(ErrorReason::Unsupported)
    );
    let sb = raw_sub(1, 1);
    let bad = (0u64..)
        .find(|n| !pow::check(&subscription_hash(&sb), &sb.mailbox, *n, 8))
        .unwrap();
    assert_eq!(
        subscribe(&mut s, &WakeConfig::default(), 8, &sb, bad, NOW).unwrap(),
        Err(ErrorReason::PowTooWeak)
    );
}

#[test]
fn unsubscribe_needs_the_secret() {
    let mut s = store();
    subscribe_ok(&mut s, 1, 1);
    unsubscribe(&mut s, &mb(1), &[99; 32]).unwrap();
    deposit_at(&mut s, &message(1, 1), NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap().len(), 1);
    unsubscribe(&mut s, &mb(1), &[1; 32]).unwrap();
    deposit_at(&mut s, &message(2, 1), NOW + 120);
    assert!(take_due(&mut s, NOW + 120, 100).unwrap().is_empty());
    // Silent when nothing matches.
    unsubscribe(&mut s, &mb(1), &[1; 32]).unwrap();
}

#[test]
fn purge_drops_expired_subscriptions() {
    let mut s = store();
    let cfg = WakeConfig::default();
    let expiring = Subscription {
        expires_day: today(),
        ..raw_sub(1, 1)
    };
    assert_eq!(try_subscribe(&mut s, &cfg, &expiring), Ok(()));
    // A later expiry must survive the purge.
    let keeper = Subscription {
        expires_day: today() + 2,
        ..raw_sub(1, 2)
    };
    assert_eq!(try_subscribe(&mut s, &cfg, &keeper), Ok(()));
    let count = |s: &NodeStore| -> i64 {
        s.conn()
            .query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(count(&s), 2);
    // Purging on the same day removes nothing.
    s.purge_expired(NOW).unwrap();
    assert_eq!(count(&s), 2);
    // The next day, the expired row is deleted and the other one kept.
    let removed = s.purge_expired(NOW + 86_400).unwrap();
    assert_eq!(removed, 1);
    assert_eq!(count(&s), 1);
    let left: Vec<u8> = s
        .conn()
        .query_row("SELECT sealed FROM subscriptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, keeper.sealed);
}

#[test]
fn expired_subscription_is_not_marked_before_purge() {
    let mut s = store();
    let sb = Subscription {
        expires_day: today(),
        ..raw_sub(1, 1)
    };
    assert_eq!(try_subscribe(&mut s, &WakeConfig::default(), &sb), Ok(()));
    // Next day, purge has not run yet: the expired subscription stays silent.
    let tx = s.conn_mut().transaction().unwrap();
    mark_new_message(&tx, &mb(1), NOW + 86_400).unwrap();
    tx.commit().unwrap();
    assert!(take_due(&mut s, NOW + 86_400, 100).unwrap().is_empty());
}

#[test]
fn take_due_respects_max_and_drops_undecodable_relays() {
    let mut s = store();
    for c in 1..=3 {
        subscribe_ok(&mut s, 1, c);
    }
    deposit_at(&mut s, &message(1, 1), NOW);
    assert_eq!(take_due(&mut s, NOW, 2).unwrap().len(), 2);
    assert_eq!(take_due(&mut s, NOW, 2).unwrap().len(), 1);
    subscribe_ok(&mut s, 2, 1);
    s.conn()
        .execute(
            "UPDATE subscriptions SET relay=x'ff', pending=1 WHERE mailbox=?1",
            params![&mb(2).0[..]],
        )
        .unwrap();
    assert!(take_due(&mut s, NOW + 60, 100).unwrap().is_empty());
    let left: i64 = s
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE mailbox=?1",
            params![&mb(2).0[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 0);
}

#[test]
fn config_wake_section() {
    use crate::config::Config;
    let c = Config::parse("[wake]\nenabled = false\nmax_subscriptions = 10\n").unwrap();
    assert_eq!(
        c.wake,
        WakeConfig {
            enabled: false,
            max_subscriptions: 10
        }
    );
    assert!(Config::parse("[wake]\nbogus = 1\n").is_err());
    let d = Config::parse("").unwrap();
    assert_eq!(d.wake, WakeConfig::default());
    assert!(d.wake.enabled);
    assert_eq!(d.wake.max_subscriptions, 1_000_000);
}

#[tokio::test(start_paused = true)]
async fn wake_signal_is_silent_until_armed() {
    use std::time::Duration;
    let s = WakeSignal::new(false);
    // No subscription on the node: a new message wakes nobody.
    s.message_arrived();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), s.notified())
            .await
            .is_err()
    );
    s.arm();
    s.message_arrived();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), s.notified())
            .await
            .is_ok()
    );
    // Armed at startup when the database already holds subscriptions.
    let s = WakeSignal::new(true);
    s.message_arrived();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), s.notified())
            .await
            .is_ok()
    );
}

#[test]
fn has_subscriptions_reads_the_table() {
    let mut store = NodeStore::open_in_memory().unwrap();
    assert!(!has_subscriptions(&store).unwrap());
    subscribe_ok(&mut store, 1, 1);
    assert!(has_subscriptions(&store).unwrap());
}
