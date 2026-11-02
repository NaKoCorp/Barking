//! `barking-push`: `run`, `keygen-seal`, `keygen-node`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use barking_proto::{NodeId, generate_node_key};
use barking_push::config::{self, RelayConfig};
use barking_push::{ApnsPusher, ConnLimits, RelayStats, bind, report_loop, serve};
use clap::{Parser, Subcommand};
use rand::Rng;
use tokio::sync::watch;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, registry};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "barking-push",
    version,
    about = "Barking push relay: wakes iOS devices through APNs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Runs the relay.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Writes a new X25519 seal key (raw 32 bytes, mode 0600); prints its id
    /// and public key (hex), to be published for clients.
    KeygenSeal {
        #[arg(long)]
        out: PathBuf,
        /// Key identifier (0 to 255), unique among the configured keys.
        #[arg(long)]
        id: u8,
    },
    /// Writes a new relay identity (node key format, mode 0600); prints the
    /// NodeId.
    KeygenNode {
        #[arg(long)]
        out: PathBuf,
    },
}

type BoxError = Box<dyn std::error::Error>;

/// Creates `path` as 0600, failing if it exists, and writes `data` to it.
/// A partial file is removed on failure.
fn create_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let res = f.write_all(data).and_then(|()| f.sync_all());
    if res.is_err() {
        let _ = fs::remove_file(path);
    }
    res
}

fn keygen_seal(out: &Path, id: u8) -> Result<(), BoxError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(raw.as_mut_slice());
    let secret = StaticSecret::from(*raw);
    create_private(out, raw.as_slice())?;
    let public = PublicKey::from(&secret);
    println!("id         : {id}");
    println!(
        "public key : {}",
        data_encoding::HEXLOWER.encode(public.as_bytes())
    );
    Ok(())
}

/// Writes the key (base32 text, like `barking-node`'s node.key) to a
/// temporary 0600 file, then links it into place: an existing `out` is
/// never overwritten, and `out` never exists half-written.
fn keygen_node(out: &Path) -> Result<(), BoxError> {
    if fs::symlink_metadata(out).is_ok() {
        return Err(format!("{} already exists", out.display()).into());
    }
    let mut tmp = out.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if fs::symlink_metadata(&tmp).is_ok() {
        return Err(format!("{} already exists", tmp.display()).into());
    }
    eprintln!("Searching for an identity (20-bit puzzle, a few seconds)...");
    let key = generate_node_key(&mut rand::rng());
    let id = NodeId::from_public_key(&key.verifying_key());
    let text = Zeroizing::new(format!(
        "{}\n",
        data_encoding::BASE32_NOPAD.encode(&key.to_bytes())
    ));
    let res = create_private(&tmp, text.as_bytes()).and_then(|()| fs::hard_link(&tmp, out));
    let _ = fs::remove_file(&tmp);
    res?;
    println!("node id : {id}");
    Ok(())
}

fn init_logging() {
    let filter = Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target("barking_push", LevelFilter::INFO)
        .with_target("barking_proto", LevelFilter::WARN)
        .with_target("quinn", LevelFilter::WARN)
        .with_target("quinn_proto", LevelFilter::WARN);
    registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .without_time()
                .with_filter(filter),
        )
        .init();
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut t), Ok(mut i)) => {
            tokio::select! { _ = t.recv() => {}, _ = i.recv() => {} }
        }
        // No signal handling possible: run until killed.
        _ => std::future::pending::<()>().await,
    }
}

fn run(config_path: &Path) -> Result<(), BoxError> {
    let cfg = RelayConfig::load(config_path)?;
    let node_key = config::load_node_key(&cfg.node_key_file)?;
    let keys = config::load_seal_keys(&cfg.seal_keys)?;
    let apns_key = config::load_apns_key(&cfg.apns.key_file)?;
    barking_push::apns::verify_trust_store()?;
    let pusher = Arc::new(ApnsPusher::new(&cfg.apns, apns_key)?);
    let id = NodeId::from_public_key(&node_key.verifying_key());
    let limits = ConnLimits {
        max_connections: cfg.max_connections,
        max_connections_per_ip: cfg.max_connections_per_ip,
    };
    let every = Duration::from_secs(cfg.log_interval_secs);

    init_logging();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let endpoints = bind(&cfg.listen, &node_key)?;
        let stats = Arc::new(RelayStats::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        tracing::info!("relay {id} started");
        let reporter = tokio::spawn(report_loop(stats.clone(), every, stop_rx.clone()));
        let server = tokio::spawn(serve(endpoints, id, keys, pusher, stats, limits, stop_rx));
        shutdown_signal().await;
        let _ = stop_tx.send(true);
        let _ = server.await;
        let _ = reporter.await;
        tracing::info!("relay stopped");
        Ok::<(), BoxError>(())
    })
}

fn main() -> ExitCode {
    // Fixed message: a panic payload could contain an address or a token.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("internal error: panic (details omitted)");
    }));
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Run { config } => run(&config),
        Cmd::KeygenSeal { out, id } => keygen_seal(&out, id),
        Cmd::KeygenNode { out } => keygen_node(&out),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
