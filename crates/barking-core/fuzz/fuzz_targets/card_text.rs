#![no_main]

use barking_core::contact::ContactCard;
use libfuzzer_sys::fuzz_target;

// Both card decoders: the shared text form and the stored bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ContactCard::from_text(text);
    }
    let _ = ContactCard::decode(data);
});
