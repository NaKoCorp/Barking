//! Écrit le corpus initial (vrais paquets et vraies trames de l'échange du harnais) :
//! `seed <répertoire du corpus> [cible]` écrit les graines de `receive`, `receive_frame` et
//! `packet_decode` (ou de la seule cible donnée).

use std::fs;
use std::path::PathBuf;

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
