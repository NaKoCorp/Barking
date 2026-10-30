#![no_main]

use barking_proto::{Request, frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let mut r = data;
    let _ = rt.block_on(frame::read::<Request>(&mut r, frame::MAX_REQUEST_BYTES));
});
