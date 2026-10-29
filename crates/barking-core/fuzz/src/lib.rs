//! Harnais commun des cibles `receive` et `receive_frame` et du binaire `seed`.
//!
//! Déterministe : générateur à graine fixe, horloge fixe. Alice et Bob sont contacts l'un de
//! l'autre, la session est ouverte dans les deux sens, puis Alice prépare des messages que Bob
//! n'a pas encore reçus : ce sont eux (paquets et trames) qui amorcent le corpus.
//!
//! La mise en place n'est faite qu'une fois ; la base de Bob est ensuite figée dans un instantané
//! et restaurée avant chaque entrée (`Fixture::fresh_bob`) : chaque entrée part du même état, donc
//! un plantage se rejoue à l'identique avec `cargo fuzz run <cible> <artefact>`.

use std::path::PathBuf;

use barking_core::Core;
use rand::SeedableRng;
use rand::rngs::StdRng;

pub const NOW: u64 = 1_800_000_000;

/// MTU des trames du corpus : en-tête de 10 octets + 90 octets de données.
pub const MTU: usize = 100;

/// Clé de base de Bob : valeur propre au fuzzing, jamais une vraie clé.
const BOB_KEY: [u8; 32] = [12; 32];

pub struct Fixture {
    /// Paquets d'Alice jamais livrés à Bob, encodés.
    pub packets: Vec<Vec<u8>>,
    /// Les mêmes paquets, découpés en trames.
    pub frames: Vec<Vec<u8>>,
    snapshot: PathBuf,
    work: PathBuf,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// Bob tel qu'après la mise en place, avec un générateur neuf et un réassembleur vide.
    pub fn fresh_bob(&self) -> (Core, StdRng) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut f = self.work.clone().into_os_string();
            f.push(suffix);
            let _ = std::fs::remove_file(f);
        }
        std::fs::copy(&self.snapshot, &self.work).expect("restauration de la base de Bob");
        let bob = Core::open(&self.work, &BOB_KEY, NOW).expect("ouverture de Bob");
        (bob, StdRng::seed_from_u64(2))
    }
}

// Les clés de base ([seed; 32]) sont des valeurs fixes, propres au fuzzing.
fn create(name: &str, rng: &mut StdRng, key: &[u8; 32], dir: &tempfile::TempDir) -> Core {
    let (core, _) = Core::create(&dir.path().join(format!("{name}.db")), key, name, NOW, rng)
        .expect("création du Core");
    core
}

pub fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("répertoire temporaire");
    let mut rng = StdRng::seed_from_u64(1);
    let mut alice = create("alice", &mut rng, &[11; 32], &dir);
    let mut bob = create("bob", &mut rng, &BOB_KEY, &dir);
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
    let frames: Vec<Vec<u8>> = packets
        .iter()
        .flat_map(|p| alice.frames(p, MTU).expect("découpage"))
        .collect();

    // Instantané : Bob est fermé (journal vidé) avant la copie du fichier.
    drop(bob);
    drop(alice);
    let snapshot = dir.path().join("bob-snapshot.db");
    std::fs::copy(dir.path().join("bob.db"), &snapshot).expect("instantané de Bob");
    Fixture {
        packets,
        frames,
        snapshot,
        work: dir.path().join("bob-work.db"),
        _dir: dir,
    }
}
