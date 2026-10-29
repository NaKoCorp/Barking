//! Harnais commun des cibles `receive` et `receive_frame` et du binaire `seed`.
//!
//! Déterministe : générateur à graine fixe, horloge fixe. Alice et Bob sont contacts l'un de
//! l'autre, la session est ouverte dans les deux sens, puis Alice prépare des messages que Bob
//! n'a pas encore reçus : ce sont eux (paquets et trames) qui amorcent le corpus.

use barking_core::Core;
use rand::SeedableRng;
use rand::rngs::StdRng;

pub const NOW: u64 = 1_800_000_000;

/// MTU des trames du corpus : en-tête de 10 octets + 90 octets de données.
pub const MTU: usize = 100;

pub struct Harness {
    /// Le destinataire dont `receive` / `receive_frame` est fuzzé.
    pub bob: Core,
    pub rng: StdRng,
    /// Paquets d'Alice jamais livrés à Bob, encodés.
    pub packets: Vec<Vec<u8>>,
    /// Les mêmes paquets, découpés en trames.
    pub frames: Vec<Vec<u8>>,
    _dirs: Vec<tempfile::TempDir>,
}

fn create(name: &str, seed: u64, rng: &mut StdRng) -> (Core, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("répertoire temporaire");
    let (core, _) = Core::create(
        &dir.path().join("fuzz.db"),
        &[seed as u8; 32],
        name,
        NOW,
        rng,
    )
    .expect("création du Core");
    (core, dir)
}

pub fn harness() -> Harness {
    let mut rng = StdRng::seed_from_u64(1);
    let (mut alice, d_alice) = create("alice", 11, &mut rng);
    let (mut bob, d_bob) = create("bob", 12, &mut rng);
    let card_a = alice.contact_card("Alice").expect("carte d'Alice");
    let card_b = bob.contact_card("Bob").expect("carte de Bob");
    let fp_b = alice
        .add_contact(&card_b, Some("bob"))
        .expect("contact Bob");
    let fp_a = bob
        .add_contact(&card_a, Some("alice"))
        .expect("contact Alice");

    // Alice -> Bob (Initial), puis Bob -> Alice : la session est ouverte dans les deux sens.
    let first = alice
        .send_text(&fp_b, "ouverture", NOW, &mut rng)
        .expect("envoi");
    for p in &first {
        bob.receive(&p.encode(), "fuzz", NOW, &mut rng)
            .expect("réception");
    }
    let reply = bob
        .send_text(&fp_a, "réponse", NOW, &mut rng)
        .expect("réponse");
    for p in &reply {
        alice
            .receive(&p.encode(), "fuzz", NOW, &mut rng)
            .expect("réception");
    }

    // Messages d'Alice que Bob n'a pas reçus : un court (une trame) et un long (plusieurs).
    let long =
        "Salut Bob, voici un message assez long pour être découpé en plusieurs trames. ".repeat(4);
    let mut packets = Vec::new();
    for text in ["court", long.as_str()] {
        for p in alice.send_text(&fp_b, text, NOW, &mut rng).expect("envoi") {
            packets.push(p.encode());
        }
    }
    let mut frames = Vec::new();
    for p in &packets {
        frames.extend(bob.frames(p, MTU).expect("découpage"));
    }
    Harness {
        bob,
        rng,
        packets,
        frames,
        _dirs: vec![d_alice, d_bob],
    }
}
