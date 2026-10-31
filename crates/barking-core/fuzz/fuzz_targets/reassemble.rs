#![no_main]

use barking_core::fragment::Reassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte sets the frame size; the rest is split into frames.
    // Each frame consumes its first byte as a clock advance (expiry).
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
