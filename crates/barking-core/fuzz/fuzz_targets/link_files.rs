#![no_main]

use barking_core::{HistoryArchive, LinkBundle, LinkOffer, LinkRequest};
use libfuzzer_sys::fuzz_target;

// The first byte selects the link file type, the rest is the file.
fuzz_target!(|data: &[u8]| {
    let Some((sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => {
            let _ = LinkOffer::from_bytes(rest);
        }
        1 => {
            let _ = LinkRequest::from_bytes(rest);
        }
        2 => {
            let _ = LinkBundle::from_bytes(rest);
        }
        _ => {
            let _ = HistoryArchive::from_bytes(rest);
        }
    }
});
