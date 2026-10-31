//! Common harness for the `receive` and `receive_frame` targets and the `seed` binary.
//!
//! Deterministic: fixed-seed generator, fixed clock. Alice and Bob are contacts of each
//! other, the session is opened in both directions, then Alice prepares messages that Bob
//! has not received yet: these (packets and frames) seed the corpus.
//!
//! The setup is done only once; Bob's database is then frozen in a snapshot
//! and restored before each input (`Fixture::fresh_bob`): every input starts from the same state, so
//! a crash replays identically with `cargo fuzz run <target> <artifact>`.

use std::path::PathBuf;

use barking_core::Core;
use rand::SeedableRng;
use rand::rngs::StdRng;

pub const NOW: u64 = 1_800_000_000;

/// MTU of the corpus frames: 10-byte header + 90 bytes of data.
pub const MTU: usize = 100;

/// Bob's database key: fuzzing-specific value, never a real key.
const BOB_KEY: [u8; 32] = [12; 32];

pub struct Fixture {
    /// Alice's packets never delivered to Bob, encoded.
    pub packets: Vec<Vec<u8>>,
    /// The same packets, split into frames.
    pub frames: Vec<Vec<u8>>,
    snapshot: PathBuf,
    work: PathBuf,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// Bob as after the setup, with a fresh generator and an empty reassembler.
    pub fn fresh_bob(&self) -> (Core, StdRng) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut f = self.work.clone().into_os_string();
            f.push(suffix);
            let _ = std::fs::remove_file(f);
        }
        std::fs::copy(&self.snapshot, &self.work).expect("restoring Bob's database");
        let bob = Core::open(&self.work, &BOB_KEY, NOW).expect("opening Bob");
        (bob, StdRng::seed_from_u64(2))
    }
}

// The database keys ([seed; 32]) are fixed values specific to fuzzing.
fn create(name: &str, rng: &mut StdRng, key: &[u8; 32], dir: &tempfile::TempDir) -> Core {
    let (core, _) = Core::create(&dir.path().join(format!("{name}.db")), key, name, NOW, rng)
        .expect("creating the Core");
    core
}

pub fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary directory");
    let mut rng = StdRng::seed_from_u64(1);
    let mut alice = create("alice", &mut rng, &[11; 32], &dir);
    let mut bob = create("bob", &mut rng, &BOB_KEY, &dir);
    let card_a = alice.contact_card("Alice").expect("Alice's card");
    let card_b = bob.contact_card("Bob").expect("Bob's card");
    let fp_b = alice
        .add_contact(&card_b, Some("bob"), NOW, &mut rng)
        .expect("Bob contact");
    let fp_a = bob
        .add_contact(&card_a, Some("alice"), NOW, &mut rng)
        .expect("Alice contact");

    // Alice -> Bob (Initial), then Bob -> Alice: the session is opened in both directions.
    let first = alice
        .send_text(&fp_b, "opening", NOW, &mut rng)
        .expect("send");
    for p in &first {
        bob.receive(&p.encode(), "fuzz", NOW, &mut rng)
            .expect("receive");
    }
    let reply = bob
        .send_text(&fp_a, "reply", NOW, &mut rng)
        .expect("reply");
    for p in &reply {
        alice
            .receive(&p.encode(), "fuzz", NOW, &mut rng)
            .expect("receive");
    }

    // Alice's messages that Bob has not received: a short one (one frame) and a long one (several).
    let long =
        "Hi Bob, here is a message long enough to be split into several frames. ".repeat(4);
    let mut packets = Vec::new();
    for text in ["short", long.as_str()] {
        for p in alice.send_text(&fp_b, text, NOW, &mut rng).expect("send") {
            packets.push(p.encode());
        }
    }
    let frames: Vec<Vec<u8>> = packets
        .iter()
        .flat_map(|p| alice.frames(p, MTU).expect("splitting"))
        .collect();

    // Snapshot: Bob is closed (journal flushed) before the file is copied.
    drop(bob);
    drop(alice);
    let snapshot = dir.path().join("bob-snapshot.db");
    std::fs::copy(dir.path().join("bob.db"), &snapshot).expect("Bob snapshot");
    Fixture {
        packets,
        frames,
        snapshot,
        work: dir.path().join("bob-work.db"),
        _dir: dir,
    }
}
