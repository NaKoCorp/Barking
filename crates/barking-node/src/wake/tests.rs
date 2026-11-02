use super::*;
use crate::rules::{self, Policy};
use barking_packet::{DEFAULT_HOPS, Kind, Packet, PacketId, Tier, ack};
use barking_proto::node_id::NodeId;

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

#[test]
fn ack_does_not_mark() {
    let mut s = store();
    subscribe_ok(&mut s, 1, 1);
    let secret = [9u8; 16];
    let mut m = message(1, 1);
    m.id = ack::packet_id_for(&secret);
    // Deposit then drain the message's own wake-up, so only the ack could mark.
    deposit_at(&mut s, &m, NOW);
    assert_eq!(take_due(&mut s, NOW, 100).unwrap().len(), 1);
    let mut payload = m.id.0.to_vec();
    payload.extend_from_slice(&secret);
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
        rules::deposit(&mut s, &policy(), &a.encode(), 0, NOW + 120).unwrap(),
        Ok(())
    );
    assert!(take_due(&mut s, NOW + 120, 100).unwrap().is_empty());
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
    let sb = Subscription {
        expires_day: today(),
        ..raw_sub(1, 1)
    };
    assert_eq!(try_subscribe(&mut s, &WakeConfig::default(), &sb), Ok(()));
    s.purge_expired(NOW + 86_400).unwrap();
    let mut p = message(1, 1);
    p.expires_at = u32::try_from(NOW + 2 * 86_400).unwrap();
    deposit_at(&mut s, &p, NOW + 86_400);
    assert!(take_due(&mut s, NOW + 86_400, 100).unwrap().is_empty());
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
