#![no_main]

//! `Core::receive_frame` sur des octets quelconques, avec une session ouverte : jamais de panique,
//! toujours `Ok(_)`. Bob repart de l'état post-mise en place à chaque entrée.

use std::sync::{Mutex, OnceLock};

use barking_core_fuzz::{Fixture, NOW, fixture};
use libfuzzer_sys::fuzz_target;

fn shared() -> &'static Mutex<Fixture> {
    static F: OnceLock<Mutex<Fixture>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(fixture()))
}

fuzz_target!(|data: &[u8]| {
    let guard = shared().lock().unwrap_or_else(|e| e.into_inner());
    let (mut bob, mut rng) = guard.fresh_bob();
    let out = bob.receive_frame(data, "fuzz", NOW, &mut rng);
    assert!(out.is_ok(), "receive_frame a renvoyé une erreur : {out:?}");
});
