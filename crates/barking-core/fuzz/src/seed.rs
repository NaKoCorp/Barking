//! Écrit le corpus initial (vrais paquets et vraies trames de l'échange du harnais) :
//! `seed <répertoire du corpus>` crée `receive/`, `receive_frame/`, `packet_decode/`.

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
    let root = PathBuf::from(root);
    let h = barking_core_fuzz::harness();
    write(root.join("receive"), &h.packets);
    write(root.join("packet_decode"), &h.packets);
    write(root.join("receive_frame"), &h.frames);
    println!(
        "{} paquets, {} trames écrits dans {}",
        h.packets.len(),
        h.frames.len(),
        root.display()
    );
}
