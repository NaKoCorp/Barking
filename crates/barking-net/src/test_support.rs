//! Test helpers: node keys that solve the 20-bit identifier puzzle.
//!
//! Seeds are the first eleven keys of `generate_node_key` on
//! `StdRng::seed_from_u64(4243)`, drawn once in optimized mode (~15 s per key
//! without optimization). Same constants as `barking-node/tests/dht.rs`.

use std::net::{Ipv4Addr, SocketAddrV4};

use barking_proto::{NodeId, NodeRecord};
use ed25519_dalek::SigningKey;

pub(crate) const SEEDS: [[u8; 32]; 11] = [
    [
        66, 125, 129, 83, 32, 106, 225, 91, 180, 232, 72, 26, 247, 131, 101, 82, 217, 244, 181, 75,
        156, 236, 14, 63, 198, 19, 50, 80, 99, 40, 172, 214,
    ],
    [
        132, 124, 253, 169, 65, 12, 180, 150, 216, 192, 72, 216, 245, 177, 206, 219, 134, 97, 245,
        5, 63, 158, 43, 124, 74, 232, 33, 130, 79, 123, 173, 159,
    ],
    [
        234, 137, 237, 175, 142, 105, 110, 146, 110, 20, 38, 242, 125, 235, 114, 172, 231, 15, 182,
        90, 226, 94, 55, 247, 224, 138, 67, 252, 70, 225, 56, 156,
    ],
    [
        166, 182, 165, 103, 105, 4, 202, 102, 34, 253, 254, 113, 121, 70, 72, 199, 59, 6, 50, 5, 5,
        79, 142, 48, 79, 62, 60, 146, 133, 166, 36, 137,
    ],
    [
        181, 107, 144, 32, 133, 91, 24, 125, 131, 19, 59, 4, 163, 25, 94, 26, 188, 68, 48, 99, 139,
        21, 14, 153, 137, 147, 95, 178, 173, 241, 135, 60,
    ],
    [
        143, 9, 122, 62, 15, 150, 214, 180, 8, 202, 136, 239, 60, 164, 122, 76, 126, 126, 205, 31,
        254, 86, 31, 61, 35, 75, 140, 11, 153, 195, 38, 31,
    ],
    [
        100, 45, 18, 125, 17, 100, 71, 236, 188, 86, 88, 173, 1, 219, 74, 150, 172, 49, 7, 166, 21,
        85, 113, 31, 196, 96, 235, 121, 65, 81, 37, 79,
    ],
    [
        108, 2, 96, 230, 104, 186, 14, 87, 51, 93, 113, 146, 186, 122, 40, 106, 197, 25, 211, 137,
        48, 62, 158, 201, 63, 90, 197, 153, 234, 2, 137, 198,
    ],
    [
        100, 235, 137, 137, 164, 69, 18, 125, 42, 2, 92, 148, 76, 239, 254, 124, 121, 53, 100, 210,
        223, 3, 61, 255, 247, 186, 230, 223, 182, 226, 78, 49,
    ],
    [
        31, 218, 187, 199, 22, 51, 5, 234, 203, 4, 46, 116, 191, 59, 174, 161, 96, 208, 232, 157,
        43, 32, 245, 66, 69, 19, 53, 207, 121, 21, 18, 98,
    ],
    [
        154, 84, 109, 217, 229, 209, 30, 44, 94, 56, 148, 35, 60, 27, 37, 204, 66, 116, 195, 68,
        71, 85, 233, 218, 72, 130, 249, 253, 120, 51, 172, 162,
    ],
];

pub(crate) fn key(n: usize) -> SigningKey {
    SigningKey::from_bytes(&SEEDS[n])
}

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

#[test]
fn seeds_solve_puzzle() {
    for n in 0..SEEDS.len() {
        assert!(id_of(n).puzzle_ok(), "key {n}");
    }
}

/// A core with a session and a send queue: Bob, after receiving Alice's
/// first message (his receipt is queued) and replying on the session.
/// Returns the temporary directory (to keep alive) and Bob's core.
pub(crate) fn subject(now: u64) -> (tempfile::TempDir, barking_core::Core) {
    let (dir, bob, _) = subject_with_ack(now);
    (dir, bob)
}

/// `subject`, plus Alice's receipt for Bob's reply (encoded), as a node
/// would serve it in the reply's mailbox.
pub(crate) fn subject_with_ack(now: u64) -> (tempfile::TempDir, barking_core::Core, Vec<u8>) {
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
    for p in alice.send_text(&fb, "hello", now, &mut rng).unwrap() {
        bob.receive(&p.encode(), "test", now, &mut rng).unwrap();
    }
    let mut ack = None;
    for p in bob.send_text(&fa, "hi", now, &mut rng).unwrap() {
        if let ReceiveOutcome::Message { ack: a, .. } =
            alice.receive(&p.encode(), "test", now, &mut rng).unwrap()
        {
            ack = Some(a.encode());
        }
    }
    (dir, bob, ack.unwrap())
}
