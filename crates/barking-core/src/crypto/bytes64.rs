//! Serde serialization of a `[u8; 64]` (serde does not handle it natively):
//! 64-byte tuple, i.e. 64 bytes in postcard. Used for signatures and the
//! 64-byte ML-KEM seed.

use core::fmt;
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    let mut t = s.serialize_tuple(64)?;
    for b in v {
        t.serialize_element(b)?;
    }
    t.end()
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = [u8; 64];
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("64 bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
            let mut out = [0u8; 64];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            Ok(out)
        }
    }
    d.deserialize_tuple(64, V)
}
