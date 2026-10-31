//! Configured relay nodes: `<home>/nodes.toml`, mode 0600. This is not core
//! data (the public address and identifier of a node chosen by the user),
//! but the list does reveal which nodes they use.

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
    /// Identifier in uppercase base32.
    pub id: String,
}

impl NodeEntry {
    pub fn node_id(&self) -> CliResult<NodeId> {
        parse_id(&self.id)
    }

    /// The first 8 characters of the identifier: what the log shows.
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

/// Identifier as typed: whitespace trimmed, uppercased, base32, puzzle solved.
fn parse_id(raw: &str) -> CliResult<NodeId> {
    let id: NodeId =
        raw.trim().to_ascii_uppercase().parse().map_err(|_| {
            CliError("Invalid node identifier (52-character base32 expected)".into())
        })?;
    if !id.puzzle_ok() {
        return fail("Node identifier rejected: it does not solve the identity puzzle (20 bits)");
    }
    Ok(id)
}

pub fn load(home: &Path) -> CliResult<Vec<NodeEntry>> {
    let text = match fs::read_to_string(path(home)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let file: NodesFile = toml::from_str(&text)
        .map_err(|_| CliError(format!("{NODES_FILE} is unreadable: fix it or delete it")))?;
    // File possibly edited by hand: canonical form, or rejection.
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
        .map_err(|_| CliError("Error: cannot write the nodes".into()))?;
    // Temporary file created as 0600 (no window of wide read access),
    // then renamed: the old list stays intact on failure.
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
        return fail("No identity in this directory: run `barking init`");
    }
    match cmd {
        NodeCommand::Add { address, id } => {
            let addr: SocketAddr = address.trim().parse().map_err(|_| {
                CliError("Invalid address (expected: IP:port, for example 203.0.113.7:4433)".into())
            })?;
            let id = parse_id(&id)?.to_string();
            let mut nodes = load(home)?;
            if nodes.iter().any(|n| n.id == id) {
                return fail("This node is already configured");
            }
            nodes.push(NodeEntry {
                addr,
                id: id.clone(),
            });
            save(home, nodes)?;
            println!("Node {} added ({addr})", short_id(&id));
        }
        NodeCommand::List => {
            let nodes = load(home)?;
            if nodes.is_empty() {
                println!("No node configured");
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
                return fail("Unknown node");
            }
            save(home, nodes)?;
            println!("Node {} removed", short_id(&id));
        }
    }
    Ok(())
}
