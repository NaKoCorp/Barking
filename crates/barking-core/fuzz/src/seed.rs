//! Writes the initial corpus (real packets and real frames from the harness exchange):
//! `seed <corpus directory> [target]` writes the seeds of `receive`, `receive_frame` and
//! `packet_decode` (or of the given target only).

use std::fs;
use std::path::PathBuf;

use barking_core::ReceiveOutcome;
use barking_core_fuzz::NOW;

fn write(dir: PathBuf, items: &[Vec<u8>]) {
    fs::create_dir_all(&dir).expect("creating the corpus directory");
    for (i, item) in items.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i:02}")), item).expect("writing a seed");
    }
}

fn main() {
    let Some(root) = std::env::args().nth(1) else {
        eprintln!("usage: seed <corpus directory>");
        std::process::exit(2);
    };
    let only = std::env::args().nth(2);
    let root = PathBuf::from(root);
    let h = barking_core_fuzz::fixture();
    // Live seeds: Bob decrypts every packet. A seed rejected right at
    // the header (`NotForUs`) would only fuzz the decoding.
    for (i, p) in h.packets.iter().enumerate() {
        let (mut bob, mut rng) = h.fresh_bob();
        match bob.receive(p, "seed", NOW, &mut rng) {
            Ok(ReceiveOutcome::Message { .. }) => {}
            other => {
                eprintln!("seed {i} unusable: {other:?}");
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
        "{} packets, {} frames available; seeds written to {}",
        h.packets.len(),
        h.frames.len(),
        root.display()
    );
}
