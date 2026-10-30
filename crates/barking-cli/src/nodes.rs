//! Nœuds de relais configurés : `<home>/nodes.toml`, en mode 0600. Ce ne sont
//! pas des données du cœur (adresse et identifiant publics d'un nœud choisi
//! par l'utilisateur), mais la liste dit quels nœuds il utilise.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use barking_proto::NodeId;
use serde::{Deserialize, Serialize};

use super::{CliError, CliResult, NodeCommand, fail};

const NODES_FILE: &str = "nodes.toml";

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub addr: SocketAddr,
    /// Identifiant en base32 majuscule.
    pub id: String,
}

impl NodeEntry {
    pub fn node_id(&self) -> CliResult<NodeId> {
        parse_id(&self.id)
    }

    /// Les 8 premiers caractères de l'identifiant : ce que le journal affiche.
    pub fn short_id(&self) -> String {
        short_id(&self.id)
    }
}

pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

#[derive(Default, Serialize, Deserialize)]
struct NodesFile {
    #[serde(default, rename = "node")]
    nodes: Vec<NodeEntry>,
}

fn path(home: &Path) -> PathBuf {
    home.join(NODES_FILE)
}

/// Identifiant saisi : espaces retirés, majuscules, base32, puzzle résolu.
fn parse_id(raw: &str) -> CliResult<NodeId> {
    let id: NodeId = raw.trim().to_ascii_uppercase().parse().map_err(|_| {
        CliError("Identifiant de nœud invalide (base32 de 52 caractères attendu)".into())
    })?;
    if !id.puzzle_ok() {
        return fail(
            "Identifiant de nœud refusé : il ne résout pas le puzzle d'identité (20 bits)",
        );
    }
    Ok(id)
}

pub fn load(home: &Path) -> CliResult<Vec<NodeEntry>> {
    let text = match fs::read_to_string(path(home)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let file: NodesFile = toml::from_str(&text).map_err(|_| {
        CliError(format!(
            "{NODES_FILE} illisible : corrige-le ou supprime-le"
        ))
    })?;
    // Fichier éventuellement édité à la main : forme canonique, ou refus.
    file.nodes
        .into_iter()
        .map(|n| {
            Ok(NodeEntry {
                addr: n.addr,
                id: parse_id(&n.id)?.to_string(),
            })
        })
        .collect()
}

fn save(home: &Path, nodes: Vec<NodeEntry>) -> CliResult<()> {
    let text = toml::to_string(&NodesFile { nodes })
        .map_err(|_| CliError("Erreur : écriture des nœuds impossible".into()))?;
    // Fichier temporaire créé en 0600 (pas de fenêtre en lecture large),
    // puis renommé : l'ancienne liste reste intacte en cas d'échec.
    let tmp = home.join(format!("{NODES_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path(home))?;
    Ok(())
}

pub fn run(home: &Path, cmd: NodeCommand) -> CliResult<()> {
    if !home.is_dir() {
        return fail("Aucune identité dans ce dossier : lance `barking init`");
    }
    match cmd {
        NodeCommand::Add { address, id } => {
            let addr: SocketAddr = address.trim().parse().map_err(|_| {
                CliError(
                    "Adresse invalide (attendu : IP:port, par exemple 203.0.113.7:4433)".into(),
                )
            })?;
            let id = parse_id(&id)?.to_string();
            let mut nodes = load(home)?;
            if nodes.iter().any(|n| n.id == id) {
                return fail("Ce nœud est déjà configuré");
            }
            nodes.push(NodeEntry {
                addr,
                id: id.clone(),
            });
            save(home, nodes)?;
            println!("Nœud {} ajouté ({addr})", short_id(&id));
        }
        NodeCommand::List => {
            let nodes = load(home)?;
            if nodes.is_empty() {
                println!("Aucun nœud configuré");
            }
            for n in nodes {
                println!("{}  {}", n.id, n.addr);
            }
        }
        NodeCommand::Remove { id } => {
            let id = id.trim().to_ascii_uppercase();
            let mut nodes = load(home)?;
            let before = nodes.len();
            nodes.retain(|n| n.id != id);
            if nodes.len() == before {
                return fail("Nœud inconnu");
            }
            save(home, nodes)?;
            println!("Nœud {} retiré", short_id(&id));
        }
    }
    Ok(())
}
