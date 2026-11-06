//! Test helpers: node keys that solve the 20-bit identifier puzzle.
//!
//! Seeds come from the node test harness (`barking_node::testing`).

use std::net::{Ipv4Addr, SocketAddrV4};

use barking_proto::{NodeId, NodeRecord};

pub(crate) use barking_node::testing::key;

pub(crate) fn id_of(n: usize) -> NodeId {
    NodeId::from_public_key(&key(n).verifying_key())
}

/// Address `10.<a>.<b>.<host>:4000`.
pub(crate) fn addr(a: u8, b: u8, host: u8) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, a, b, host), 4000)
}

/// Record of key `n` at a distinct /24 (`10.0.n.1`), issued at `now`.
pub(crate) fn record(n: usize, now: u64) -> NodeRecord {
    record_at(n, addr(0, n as u8, 1), now)
}

pub(crate) fn record_at(n: usize, at: SocketAddrV4, now: u64) -> NodeRecord {
    NodeRecord::sign(&key(n), Some(at), None, now)
}

/// A core with a session and a send queue: Bob, after receiving Alice's
/// first message (his receipt is queued) and replying on the session.
/// Returns the temporary directory (to keep alive) and Bob's core.
pub(crate) fn subject(now: u64) -> (tempfile::TempDir, barking_core::Core) {
    let (dir, bob, _) = subject_with_ack(now);
    (dir, bob)
}

/// `subject`, plus Alice's first message (encoded packets), already
/// received by Bob.
pub(crate) fn subject_with_hello(
    now: u64,
) -> (tempfile::TempDir, barking_core::Core, Vec<Vec<u8>>) {
    let (dir, bob, _, hello) = build_subject(now, false);
    (dir, bob, hello)
}

/// `subject`, plus Alice's receipt for Bob's reply (encoded), as a node
/// would serve it in the reply's mailbox.
pub(crate) fn subject_with_ack(now: u64) -> (tempfile::TempDir, barking_core::Core, Vec<u8>) {
    let (dir, bob, ack, _) = build_subject(now, false);
    (dir, bob, ack)
}

/// `subject`, where Bob also sent a second message the next day (another
/// session mailbox).
pub(crate) fn subject_two_messages(now: u64) -> (tempfile::TempDir, barking_core::Core) {
    let (dir, bob, _, _) = build_subject(now, true);
    (dir, bob)
}

type Subject = (tempfile::TempDir, barking_core::Core, Vec<u8>, Vec<Vec<u8>>);

fn build_subject(now: u64, second: bool) -> Subject {
    use barking_core::{Core, ReceiveOutcome};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let (mut alice, _) = Core::create(
        &dir.path().join("alice.db"),
        &[1; 32],
        "alice",
        now,
        &mut rng,
    )
    .unwrap();
    let (mut bob, _) =
        Core::create(&dir.path().join("bob.db"), &[2; 32], "bob", now, &mut rng).unwrap();
    let card_a = alice.contact_card("Alice").unwrap();
    let card_b = bob.contact_card("Bob").unwrap();
    let fa = bob
        .add_contact(&card_a, Some("alice"), now, &mut rng)
        .unwrap();
    let fb = alice
        .add_contact(&card_b, Some("bob"), now, &mut rng)
        .unwrap();
    let mut hello = Vec::new();
    for p in alice.send_text(&fb, "hello", now, &mut rng).unwrap() {
        bob.receive(&p.encode(), "test", now, &mut rng).unwrap();
        hello.push(p.encode());
    }
    let mut ack = None;
    for p in bob.send_text(&fa, "hi", now, &mut rng).unwrap() {
        if let ReceiveOutcome::Message { ack: a, .. } =
            alice.receive(&p.encode(), "test", now, &mut rng).unwrap()
        {
            ack = Some(a.encode());
        }
    }
    if second {
        bob.send_text(&fa, "again", now + 86_400, &mut rng).unwrap();
    }
    (dir, bob, ack.unwrap(), hello)
}
