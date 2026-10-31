//! `barking node`: the nodes added by hand live in the network view
//! (`barking_net::View`), kept in the core's encrypted database. This module
//! is a thin layer around `View::add_manual` and `View::remove_manual`, and
//! migrates the old plaintext files:
//!
//! - `nodes.toml` (the node list of the first network client): its nodes
//!   enter the view as added by hand, then the file is erased;
//! - `sync_state.toml` and `fetch_cursors.toml` (fetch positions and
//!   deposits of an even older client): moved to the old sync state key,
//!   which `NetState::load` migrates in turn, then erased.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use barking_core::Core;
use barking_net::state::{LEGACY_STATE_KEY, LegacyState, STATE_KEY};
use barking_net::{DialError, Dialer, NetState, QuicDialer};
use barking_proto::{ErrorReason, NodeId, RecordPolicy};
use serde::Deserialize;

use super::{CliError, CliResult, NodeCommand, fail, now, open_core};

/// The old plaintext node list.
const NODES_FILE: &str = "nodes.toml";
/// Older plaintext sync state files.
const LEGACY_FILES: [&str; 2] = ["sync_state.toml", "fetch_cursors.toml"];

/// Accept non-routable node addresses (test builds only: the test nodes
/// listen on 127.0.0.1).
pub fn allow_private() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var("BARKING_TEST_ALLOW_PRIVATE").is_ok_and(|v| v == "1") {
        return true;
    }
    false
}

/// The first 8 characters of the identifier: what the log shows.
fn short_id(id: &NodeId) -> String {
    barking_net::sync::short_id(id)
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

#[derive(Deserialize)]
struct OldNode {
    addr: SocketAddr,
    id: String,
}

#[derive(Deserialize)]
struct OldNodesFile {
    #[serde(default, rename = "node")]
    nodes: Vec<OldNode>,
}

/// Opens the core and migrates the old plaintext files into it.
pub fn open(home: &Path) -> CliResult<Core> {
    if !home.is_dir() {
        return fail("No identity in this directory: run `barking init`");
    }
    let mut core = open_core(home)?;
    migrate_sync_files(home, &mut core)?;
    migrate_nodes_file(home, &mut core)?;
    Ok(core)
}

/// Moves an old plaintext sync state to the old state key, unless the
/// database already has a state, then erases the files.
fn migrate_sync_files(home: &Path, core: &mut Core) -> CliResult<()> {
    let mut has_state = core.transport_state(STATE_KEY)?.is_some()
        || core.transport_state(LEGACY_STATE_KEY)?.is_some();
    for name in LEGACY_FILES {
        let path = home.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if !has_state && toml::from_str::<LegacyState>(&text).is_ok() {
            core.set_transport_state(LEGACY_STATE_KEY, text.as_bytes())?;
            has_state = true;
        }
        wipe(&path);
    }
    Ok(())
}

/// Adds the nodes of `nodes.toml` to the view as added by hand, saves, then
/// erases the file. A file that cannot be read is left in place. A leftover
/// temporary file of the old writer (`nodes.toml.tmp`) is erased too.
fn migrate_nodes_file(home: &Path, core: &mut Core) -> CliResult<()> {
    wipe(&home.join(format!("{NODES_FILE}.tmp")));
    let path = home.join(NODES_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return fail(format!("{NODES_FILE} cannot be read: fix it or delete it")),
    };
    let unreadable = || CliError(format!("{NODES_FILE} is unreadable: fix it or delete it"));
    let file: OldNodesFile = toml::from_str(&text).map_err(|_| unreadable())?;
    let nodes = file
        .nodes
        .into_iter()
        .map(|n| Ok((parse_id(&n.id).map_err(|_| unreadable())?, n.addr)))
        .collect::<CliResult<Vec<_>>>()?;
    let t = now();
    let mut state = load_state(core, t)?;
    for (id, addr) in nodes {
        state.view.add_manual(id, addr, t);
    }
    save_state(core, &state)?;
    wipe(&path);
    Ok(())
}

/// Overwrites a file with zeros then erases it. Best effort: errors are
/// ignored, and on copy-on-write or journaling file systems the old blocks
/// may survive the overwrite.
fn wipe(path: &Path) {
    if let Ok(meta) = fs::metadata(path)
        && let Ok(mut f) = fs::OpenOptions::new().write(true).open(path)
    {
        let len = usize::try_from(meta.len()).unwrap_or(0);
        let _ = f.write_all(&vec![0u8; len]);
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(path);
}

fn load_state(core: &mut Core, now: u64) -> CliResult<NetState> {
    NetState::load(core, now, allow_private())
        .map_err(|e| CliError(format!("Cannot read the network state: {e}")))
}

fn save_state(core: &mut Core, state: &NetState) -> CliResult<()> {
    state
        .save(core)
        .map_err(|e| CliError(format!("Cannot save the network state: {e}")))
}

pub fn run(home: &Path, cmd: NodeCommand) -> CliResult<()> {
    match cmd {
        NodeCommand::Add { address, id } => {
            let addr: SocketAddr = address.trim().parse().map_err(|_| {
                CliError("Invalid address (expected: IP:port, for example 203.0.113.7:4433)".into())
            })?;
            let id = parse_id(&id)?;
            let mut core = open(home)?;
            let t = now();
            let mut state = load_state(&mut core, t)?;
            if state
                .view
                .get(&id)
                .is_some_and(|e| e.manual && e.manual_addr == Some(addr))
            {
                return fail("This node is already added");
            }
            let record = ping(id, addr)?;
            match record.verify(t, &RecordPolicy::network(allow_private())) {
                Ok(rid) if rid == id => {}
                Ok(_) => {
                    return fail(
                        "The node answered with a record of another node: nothing was added",
                    );
                }
                Err(e) => {
                    return fail(format!(
                        "The node's record is invalid ({e}): nothing was added"
                    ));
                }
            }
            state.view.add_manual(id, addr, t);
            state.view.set_record(&id, record, t);
            state.view.confirm(&id, t);
            save_state(&mut core, &state)?;
            println!("Node {} added", short_id(&id));
        }
        NodeCommand::List => {
            let mut core = open(home)?;
            let t = now();
            let state = load_state(&mut core, t)?;
            let mut lines: Vec<String> = state
                .view
                .entries()
                .map(|(id, e)| {
                    let mut parts = vec![
                        short_id(id),
                        if e.confirmed {
                            "confirmed"
                        } else {
                            "candidate"
                        }
                        .to_owned(),
                        format!("score {:.2}", e.score.value()),
                    ];
                    if e.avoided(t) {
                        parts.push("avoided".to_owned());
                    }
                    // The address only for nodes the user typed in.
                    if e.manual
                        && let Some(addr) = e.manual_addr
                    {
                        parts.push(format!("manual {addr}"));
                    }
                    parts.join("  ")
                })
                .collect();
            lines.sort();
            if lines.is_empty() {
                println!("No known node");
            }
            for line in lines {
                println!("{line}");
            }
        }
        NodeCommand::Remove { id } => {
            let id: NodeId = id
                .trim()
                .to_ascii_uppercase()
                .parse()
                .map_err(|_| CliError("Unknown node".into()))?;
            let mut core = open(home)?;
            let mut state = load_state(&mut core, now())?;
            if !state.view.remove_manual(&id) {
                return fail(if state.view.get(&id).is_some() {
                    "This node was not added by hand"
                } else {
                    "Unknown node"
                });
            }
            save_state(&mut core, &state)?;
            if state.view.get(&id).is_some() {
                println!(
                    "Node {} is no longer added by hand (it stays known from the network)",
                    short_id(&id)
                );
            } else {
                println!("Node {} removed", short_id(&id));
            }
        }
    }
    Ok(())
}

/// Pings `id` at `addr`, TLS pinned on `id`: returns the record it signed.
fn ping(id: NodeId, addr: SocketAddr) -> CliResult<barking_proto::NodeRecord> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("I/O error: {e}")))?;
    let r = rt.block_on(QuicDialer.ping(id, &[addr]));
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    r.map_err(|e| match e {
        // A relay-only node (no `[dht]`) answers `Ping` with `Unsupported`.
        DialError::Refused(ErrorReason::Unsupported) => CliError(format!(
            "Node {} does not take part in the network table (no public address): nothing was added",
            short_id(&id)
        )),
        e => CliError(format!(
            "Node {} could not prove its identity at this address ({e}): nothing was added",
            short_id(&id)
        )),
    })
}
