//! Écrit le corpus initial (vrais paquets et vraies trames de l'échange du harnais) :
//! `seed <répertoire du corpus> [cible]` écrit les graines de `receive`, `receive_frame` et
//! `packet_decode` (ou de la seule cible donnée).

use std::fs;
use std::path::PathBuf;

use barking_core::ReceiveOutcome;
use barking_core_fuzz::NOW;

fn write(dir: PathBuf, items: &[Vec<u8>]) {
    fs::create_dir_all(&dir).expect("création du répertoire de corpus");
    for (i, item) in items.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i:02}")), item).expect("écriture d'une graine");
    }
}

fn main() {
    let Some(root) = std::env::args().nth(1) else {
        eprintln!("usage : seed <répertoire du corpus>");
        std::process::exit(2);
    };
    let only = std::env::args().nth(2);
    let root = PathBuf::from(root);
    let h = barking_core_fuzz::fixture();
    // Graines vivantes : Bob déchiffre chaque paquet. Une graine refusée dès
    // l'en-tête (`NotForUs`) ne ferait fuzzer que le décodage.
    for (i, p) in h.packets.iter().enumerate() {
        let (mut bob, mut rng) = h.fresh_bob();
        match bob.receive(p, "seed", NOW, &mut rng) {
            Ok(ReceiveOutcome::Message { .. }) => {}
            other => {
                eprintln!("graine {i} inutilisable : {other:?}");
                std::process::exit(1);
            }
        }
    }
    let wanted = |name: &str| only.as_deref().is_none_or(|o| o == name);
    if wanted("receive") {
        write(root.join("receive"), &h.packets);
    }
    if wanted("packet_decode") {
        write(root.join("packet_decode"), &h.packets);
    }
    if wanted("receive_frame") {
        write(root.join("receive_frame"), &h.frames);
    }
    println!(
        "{} paquets, {} trames disponibles ; graines écrites dans {}",
        h.packets.len(),
        h.frames.len(),
        root.display()
    );
}
