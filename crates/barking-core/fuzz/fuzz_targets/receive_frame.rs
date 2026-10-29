#![no_main]

//! `Core::receive_frame` sur des octets quelconques, avec une session ouverte : jamais de panique,
//! toujours `Ok(_)`.

use std::sync::{Mutex, OnceLock};

use barking_core_fuzz::{Harness, NOW, harness};
use libfuzzer_sys::fuzz_target;

fn shared() -> &'static Mutex<Harness> {
    static H: OnceLock<Mutex<Harness>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(harness()))
}

fuzz_target!(|data: &[u8]| {
    let mut guard = shared().lock().unwrap_or_else(|e| e.into_inner());
    let h = &mut *guard;
    let out = h.bob.receive_frame(data, "fuzz", NOW, &mut h.rng);
    assert!(out.is_ok(), "receive_frame a renvoyé une erreur : {out:?}");
});
