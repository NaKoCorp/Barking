#![no_main]

use barking_dht::filter_nodes;
use barking_proto::{RecordPolicy, Response};
use libfuzzer_sys::fuzz_target;

// The first byte selects the policy (bit 0: private addresses, bit 1:
// full puzzle), the next eight the current time; the rest is decoded
// as a `Response`. A `Nodes` response goes through `filter_nodes`, which must
// never panic.
fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Some((now, rest)) = rest.split_first_chunk::<8>() else {
        return;
    };
    let policy = if sel & 2 == 0 {
        RecordPolicy {
            allow_private: sel & 1 == 1,
            puzzle_bits: 0,
        }
    } else {
        RecordPolicy::network(sel & 1 == 1)
    };
    if let Ok(Response::Nodes { records }) = postcard::from_bytes::<Response>(rest) {
        let _ = filter_nodes(records, u64::from_le_bytes(*now), &policy);
    }
});
