#![no_main]

use barking_core::fragment::Reassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Le premier octet fixe la taille des trames ; le reste est découpé en trames.
    let Some((&size, rest)) = data.split_first() else {
        return;
    };
    let size = usize::from(size).max(1);
    let mut r = Reassembler::new(4, 60);
    for (i, frame) in rest.chunks(size).enumerate() {
        let _ = r.push(frame, i as u64);
    }
});
