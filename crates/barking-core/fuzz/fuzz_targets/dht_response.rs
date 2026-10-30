#![no_main]

use barking_dht::filter_nodes;
use barking_proto::{RecordPolicy, Response};
use libfuzzer_sys::fuzz_target;

// Le premier octet choisit la politique (bit 0 : adresses privées, bit 1 :
// puzzle complet), les huit suivants l'heure courante ; le reste est décodé
// comme une `Response`. Une réponse `Nodes` passe par `filter_nodes`, qui ne
// doit jamais paniquer.
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
