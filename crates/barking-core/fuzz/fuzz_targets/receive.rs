#![no_main]

//! `Core::receive` sur des octets quelconques : jamais de panique, toujours `Ok(_)`.

use std::sync::{Mutex, OnceLock};

use barking_core::Core;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;

const NOW: u64 = 1_800_000_000;

struct Harness {
    core: Core,
    rng: StdRng,
    _dir: tempfile::TempDir,
}

fn harness() -> &'static Mutex<Harness> {
    static H: OnceLock<Mutex<Harness>> = OnceLock::new();
    H.get_or_init(|| {
        let dir = tempfile::tempdir().expect("répertoire temporaire");
        let mut rng = StdRng::seed_from_u64(1);
        let (core, _) = Core::create(&dir.path().join("fuzz.db"), &[7; 32], "fuzz", NOW, &mut rng)
            .expect("création du Core");
        Mutex::new(Harness {
            core,
            rng,
            _dir: dir,
        })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut guard = harness().lock().unwrap_or_else(|e| e.into_inner());
    let h = &mut *guard;
    let out = h.core.receive(data, "fuzz", NOW, &mut h.rng);
    assert!(out.is_ok(), "receive a renvoyé une erreur : {out:?}");
});
