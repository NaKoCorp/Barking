#![no_main]

//! `Core::receive` on arbitrary bytes, with an open session: never a panic,
//! always `Ok(_)`. Bob restarts from the post-setup state on every input.

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
    let out = bob.receive(data, "fuzz", NOW, &mut rng);
    assert!(out.is_ok(), "receive returned an error: {out:?}");
});
