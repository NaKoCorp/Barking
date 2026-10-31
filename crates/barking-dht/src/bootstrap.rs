//! Bootstrap list: entries `<base32 identifier>@<ip:port>`, those of
//! `bootstrap.toml` (built into the binary) then those of the config.

use std::net::SocketAddr;

use barking_proto::NodeId;
use serde::Deserialize;

/// Bootstrap node: expected identifier and address to reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapEntry {
    pub id: NodeId,
    pub addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    #[error("bootstrap entry without '@' (expected: identifier@ip:port)")]
    MissingAt,
    #[error("invalid node identifier in the bootstrap entry")]
    BadId,
    #[error("invalid address in the bootstrap entry (expected: ip:port)")]
    BadAddr,
}

/// Reads an entry `<base32 identifier>@<ip:port>`.
pub fn parse_bootstrap(s: &str) -> Result<BootstrapEntry, BootstrapError> {
    let (id, addr) = s.trim().split_once('@').ok_or(BootstrapError::MissingAt)?;
    Ok(BootstrapEntry {
        id: id.parse().map_err(|_| BootstrapError::BadId)?,
        addr: addr.parse().map_err(|_| BootstrapError::BadAddr)?,
    })
}

const BUILTIN: &str = include_str!("../bootstrap.toml");

#[derive(Deserialize)]
struct BootstrapFile {
    nodes: Vec<String>,
}

/// List built into the binary. An unreadable entry is discarded; the test
/// `builtin_list_is_valid` guarantees there are none.
pub fn builtin_bootstrap() -> Vec<BootstrapEntry> {
    toml::from_str::<BootstrapFile>(BUILTIN)
        .map(|f| {
            f.nodes
                .iter()
                .filter_map(|e| parse_bootstrap(e).ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bootstrap_roundtrip() {
        let id = NodeId([7; 32]);
        let e = parse_bootstrap(&format!("{id}@1.2.3.4:4433")).unwrap();
        assert_eq!(e.id, id);
        assert_eq!(e.addr, "1.2.3.4:4433".parse().unwrap());
        let e = parse_bootstrap(&format!("{id}@[2a01::1]:4433")).unwrap();
        assert_eq!(e.addr, "[2a01::1]:4433".parse().unwrap());
        assert_eq!(
            parse_bootstrap("1.2.3.4:4433"),
            Err(BootstrapError::MissingAt)
        );
        assert_eq!(
            parse_bootstrap("pasbase32!@1.2.3.4:4433"),
            Err(BootstrapError::BadId)
        );
        assert_eq!(
            parse_bootstrap(&format!("{id}@1.2.3.4")),
            Err(BootstrapError::BadAddr)
        );
        assert_eq!(
            parse_bootstrap(&format!("{id}@[2a01::1]")),
            Err(BootstrapError::BadAddr)
        );
        assert!(builtin_bootstrap().is_empty());
    }

    #[test]
    fn builtin_list_is_valid() {
        let file: BootstrapFile = toml::from_str(BUILTIN).unwrap();
        for entry in &file.nodes {
            parse_bootstrap(entry).unwrap();
        }
    }
}
