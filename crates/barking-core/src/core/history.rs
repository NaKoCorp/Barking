//! Archive de l'historique transférée pendant une liaison (spec §3.4).
//!
//! Pour l'instant, seul le format de fichier existe : la production et
//! l'import (morceaux chiffrés, hash final) viendront ensuite.

use serde::{Deserialize, Serialize};

use crate::Result;

/// Archive de l'historique : morceaux chiffrés, dans l'ordre.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryArchive {
    pub chunks: Vec<Vec<u8>>,
}

impl core::fmt::Debug for HistoryArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoryArchive")
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl HistoryArchive {
    /// Octets du fichier d'historique (postcard).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Sérialisation vers un `Vec` d'une structure sans état invalide.
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Inverse de [`HistoryArchive::to_bytes`] ; octets en trop refusés.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        super::link::decode_exact(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;

    #[test]
    fn roundtrip_and_garbage() {
        let a = HistoryArchive {
            chunks: vec![vec![1, 2, 3], vec![]],
        };
        assert_eq!(HistoryArchive::from_bytes(&a.to_bytes()).unwrap(), a);
        assert_eq!(
            HistoryArchive::from_bytes(&[0xff, 0xff]),
            Err(CoreError::Link("fichier de liaison illisible"))
        );
    }
}
