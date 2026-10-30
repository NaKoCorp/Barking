//! Liste d'amorçage : entrées `<identifiant base32>@<ip:port>`, celles de
//! `bootstrap.toml` (intégré au binaire) puis celles de la config.

use std::net::SocketAddr;

use barking_proto::NodeId;
use serde::Deserialize;

/// Nœud d'amorçage : identifiant attendu et adresse à joindre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapEntry {
    pub id: NodeId,
    pub addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    #[error("entrée d'amorçage sans « @ » (attendu : identifiant@ip:port)")]
    MissingAt,
    #[error("identifiant de nœud invalide dans l'entrée d'amorçage")]
    BadId,
    #[error("adresse invalide dans l'entrée d'amorçage (attendu : ip:port)")]
    BadAddr,
}

/// Lit une entrée `<identifiant base32>@<ip:port>`.
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

/// Liste intégrée au binaire. Une entrée illisible est écartée ; le test
/// `builtin_list_is_valid` garantit qu'il n'y en a pas.
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
