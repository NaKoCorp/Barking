#![no_main]

use barking_proto::{Request, Response, frame};
use libfuzzer_sys::fuzz_target;

// Le premier octet choisit le type décodé (pair : requête, impair : réponse),
// le reste est le flux d'octets.
fuzz_target!(|data: &[u8]| {
    let Some((sel, rest)) = data.split_first() else {
        return;
    };
    let mut r = rest;
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    if sel % 2 == 0 {
        let _ = rt.block_on(frame::read::<Request>(&mut r, frame::MAX_REQUEST_BYTES));
    } else {
        let _ = rt.block_on(frame::read::<Response>(&mut r, frame::MAX_RESPONSE_BYTES));
    }
});
