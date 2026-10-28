#![no_main]

use barking_core::fragment::Reassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Le premier octet fixe la taille des trames ; le reste est découpé en trames.
    // Chaque trame consomme son premier octet comme avance d'horloge (expiration).
    let Some((&size, rest)) = data.split_first() else {
        return;
    };
    let size = usize::from(size).max(1);
    let mut r = Reassembler::new(4, 60);
    let mut now = 0u64;
    for chunk in rest.chunks(size + 1) {
        let (dt, frame) = chunk.split_at(1);
        now += u64::from(dt[0]);
        let _ = r.push(frame, now);
    }
});
