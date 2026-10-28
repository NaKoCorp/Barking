#![no_main]

use barking_core::packet::Packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
});
