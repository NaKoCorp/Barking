//! `barking-node`: `init`, `run`, `status`, `peers`.

use std::collections::HashSet;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use barking_dht::mailbox_key;
use barking_node::config::{Config, DEFAULT_DATA_DIR};
use barking_node::dht::table_from_rows;
use barking_node::server::{self, ServerStats};
use barking_node::{Error, NodeStore, Result, logging};
use barking_proto::{NodeId, PROTOCOL_VERSION, generate_node_key};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

const KEY_FILE: &str = "node.key";
const DB_FILE: &str = "node.db";

#[derive(Parser)]
#[command(
    name = "barking-node",
    version,
    about = "Barking node: keeps pending encrypted packets"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generates the node identity and creates the database; prints the
    /// identifier and the address to publish.
    Init {
        /// Data directory (default: `data_dir` from the configuration).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Configuration file (for the printed listen address).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Runs the node.
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Identifier, version, packets, acks and bytes held; hash table and
    /// replication.
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Active peers of the table (identifier, age, last contact), from the
    /// last save of `peers`, without addresses.
    Peers {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

fn fail(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    match path {
        Some(p) => Config::load(p),
        None => Ok(Config::default()),
    }
}

/// Warns (stderr) if the data directory is accessible to users other than
/// the owner.
fn warn_dir_perms(dir: &Path) {
    if let Ok(m) = fs::metadata(dir)
        && m.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "warning: directory {} is accessible to the group or others \
             (mode {:04o}); `chmod 700` is recommended.",
            dir.display(),
            m.permissions().mode() & 0o7777
        );
    }
}

/// Reads the node key; refuses a symbolic link, an irregular file or a
/// file readable by other users.
fn load_key(dir: &Path) -> Result<SigningKey> {
    let path = dir.join(KEY_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|_| {
        fail(format!(
            "{} is not initialized (`barking-node init`)",
            dir.display()
        ))
    })?;
    if !meta.file_type().is_file() {
        return Err(fail(format!(
            "{} must be a regular file (neither a symbolic link nor another type)",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(fail(format!(
            "{} must have mode 0600 (readable by other users)",
            path.display()
        )));
    }
    let text = Zeroizing::new(fs::read_to_string(&path)?);
    let bytes = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(text.trim().as_bytes())
            .map_err(|_| fail("node key unreadable"))?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| fail("node key has the wrong size"))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

/// Writes the key to `node.key.tmp` (0600) then moves it into place with a
/// `rename`.
fn write_key(dir: &Path, key: &SigningKey) -> Result<()> {
    let tmp = dir.join(format!("{KEY_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let enc = Zeroizing::new(format!(
            "{}\n",
            data_encoding::BASE32_NOPAD.encode(&key.to_bytes())
        ));
        f.write_all(enc.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(KEY_FILE))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Creates an empty database file as 0600, before SQLite opens it (which
/// would create it with the umask's permissions). Fails if it exists.
fn create_private_db(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok(())
}

fn init(data_dir: Option<PathBuf>, config: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config.as_deref())?;
    let dir = data_dir.unwrap_or_else(|| cfg.data_dir.clone());
    let (key_path, db_path) = (dir.join(KEY_FILE), dir.join(DB_FILE));
    if key_path.exists() || db_path.exists() {
        return Err(fail(format!("{} is already initialized", dir.display())));
    }
    eprintln!("Searching for an identity (20-bit puzzle, a few seconds)…");
    let key = generate_node_key(&mut rand::rng());
    let id = NodeId::from_public_key(&key.verifying_key());

    // Directory created as 0700; the permissions of a directory already there
    // (for example created by systemd) are not modified.
    let created = !dir.exists();
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    warn_dir_perms(&dir);
    // Key stored first (last atomic step of the identity), then the database
    // as 0600 from its creation. On failure, everything that was created is
    // removed: `init` can be rerun.
    let res = write_key(&dir, &key).and_then(|()| {
        create_private_db(&db_path)?;
        NodeStore::open(&db_path)?;
        Ok(())
    });
    if let Err(e) = res {
        for f in [&key_path, &db_path] {
            let _ = fs::remove_file(f);
        }
        for ext in ["-wal", "-shm"] {
            let _ = fs::remove_file(dir.join(format!("{DB_FILE}{ext}")));
        }
        if created {
            let _ = fs::remove_dir(&dir);
        }
        return Err(e);
    }

    let listen = cfg.listen.first().cloned().unwrap_or_default();
    println!("identifier  : {id}");
    println!("address     : {listen}");
    println!();
    println!(
        "To publish: the identifier above and the public address (host or IP) of \
         the server with the listen port ({listen} is the configured local address)."
    );
    Ok(())
}

/// Node identifier and database opened read-only: `status` and `peers`
/// modify nothing, even during `run`.
fn open_for_reading(data_dir: Option<PathBuf>) -> Result<(NodeId, NodeStore)> {
    let dir = data_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let key = load_key(&dir)?;
    let id = NodeId::from_public_key(&key.verifying_key());
    let db = dir.join(DB_FILE);
    if !db.exists() {
        return Err(fail(format!("no database in {}", dir.display())));
    }
    // A v2 database yields `SchemaVersion(2)`, reported by `main`.
    Ok((id, NodeStore::open_read_only(&db)?))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whole hours elapsed between `t` and `now`.
fn hours_since(now: u64, t: u64) -> u64 {
    now.saturating_sub(t) / 3600
}

fn status(data_dir: Option<PathBuf>) -> Result<()> {
    let (id, store) = open_for_reading(data_dir)?;
    let stats = store.stats()?;
    let now = unix_now();
    let table = table_from_rows(id, &store.load_peers()?);
    let responsible = store
        .held_mailboxes()?
        .iter()
        .filter(|m| table.may_hold(&mailbox_key(m), &id))
        .count();
    let (window, bytes) = store.replicated()?;
    let recent = if now.saturating_sub(window) < 3600 {
        bytes
    } else {
        0
    };
    println!("identifier  : {id}");
    println!(
        "version     : {} (protocol {PROTOCOL_VERSION})",
        env!("CARGO_PKG_VERSION")
    );
    println!("packets     : {}", stats.packets);
    println!("acks        : {}", stats.acks);
    println!("bytes       : {}", stats.bytes);
    println!("peers       : {}", table.len());
    println!("buckets     : {} non-empty", table.non_empty_buckets());
    if table.is_empty() {
        // With no known peer, every held mailbox would look "responsible".
        println!("responsible : table empty or disabled");
    } else {
        println!("responsible : {responsible} mailboxes");
    }
    println!("replicated  : {recent} bytes in the last hour");
    Ok(())
}

fn peers(data_dir: Option<PathBuf>) -> Result<()> {
    let (id, store) = open_for_reading(data_dir)?;
    let rows = store.load_peers()?;
    // Active nodes of the table (the reserve is excluded).
    let active: HashSet<NodeId> = table_from_rows(id, &rows)
        .closest(&id.0, usize::MAX)
        .into_iter()
        .map(|p| p.id)
        .collect();
    let now = unix_now();
    // In `load_peers` order: most recently seen first.
    for row in rows.iter().filter(|r| active.contains(&NodeId(r.node_id))) {
        println!(
            "{}  age {} h  seen {} h ago",
            NodeId(row.node_id),
            hours_since(now, row.first_seen),
            hours_since(now, row.last_seen)
        );
    }
    Ok(())
}

fn run(config: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config.as_deref())?;
    warn_dir_perms(&cfg.data_dir);
    let key = load_key(&cfg.data_dir)?;
    let id = NodeId::from_public_key(&key.verifying_key());
    let db_path = cfg.data_dir.join(DB_FILE);
    if !db_path.exists() {
        // A missing database is recreated private, like at `init`.
        match create_private_db(&db_path) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
            _ => {}
        }
    }
    let store = NodeStore::open(&db_path)?;
    let sockets = cfg.bind()?;
    let server_cfg = cfg.server_config(sockets, key);
    let stats: std::sync::Arc<ServerStats> = std::sync::Arc::clone(&server_cfg.stats);
    let every = std::time::Duration::from_secs(cfg.log_interval_secs);
    let policy = cfg.policy();
    let dht_off = cfg.dht_without_public_addr;

    logging::init_stderr();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        tracing::info!("node {id} started");
        if dht_off {
            tracing::warn!("[dht] without public_addr: table disabled, plain relay");
        }
        let reporter = tokio::spawn(server::report_loop(stats, every));
        let r = server::run(server_cfg, store, policy, shutdown_signal()).await;
        reporter.abort();
        tracing::info!("node stopped");
        r
    })
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut t), Ok(mut i)) => {
            tokio::select! { _ = t.recv() => {}, _ = i.recv() => {} }
        }
        // No signal handling possible: run until killed.
        _ => std::future::pending::<()>().await,
    }
}

fn main() -> ExitCode {
    // Fixed message: a panic payload could contain an address.
    // A panic in a connection task only ends that task.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("internal error: panic (details omitted)");
    }));
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Init { data_dir, config } => init(data_dir, config),
        Cmd::Run { config } => run(config),
        Cmd::Status { data_dir } => status(data_dir),
        Cmd::Peers { data_dir } => peers(data_dir),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        // Database of the previous schema (`status`, `peers` read-only).
        Err(Error::SchemaVersion(2)) => {
            eprintln!("error: database is version 2, run the node once to migrate it");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
