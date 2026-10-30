//! `barking-node` : `init`, `run`, `status`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barking_node::config::{Config, DEFAULT_DATA_DIR};
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
    about = "Nœud Barking : garde des paquets chiffrés en attente"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Génère l'identité du nœud et crée la base ; affiche l'identifiant et
    /// l'adresse à publier.
    Init {
        /// Dossier de données (défaut : `data_dir` de la configuration).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Fichier de configuration (pour l'adresse d'écoute affichée).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Fait tourner le nœud.
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Identifiant, version, paquets, accusés et octets gardés.
    Status {
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

/// Lit la clé du nœud ; refuse un fichier lisible par d'autres utilisateurs.
fn load_key(dir: &Path) -> Result<SigningKey> {
    let path = dir.join(KEY_FILE);
    let meta = fs::metadata(&path).map_err(|_| {
        fail(format!(
            "{} n'est pas initialisé (`barking-node init`)",
            dir.display()
        ))
    })?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(fail(format!(
            "{} doit être en mode 0600 (lisible par d'autres utilisateurs)",
            path.display()
        )));
    }
    let text = Zeroizing::new(fs::read_to_string(&path)?);
    let bytes = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(text.trim().as_bytes())
            .map_err(|_| fail("clé du nœud illisible"))?,
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| fail("clé du nœud de mauvaise taille"))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

fn init(data_dir: Option<PathBuf>, config: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config.as_deref())?;
    let dir = data_dir.unwrap_or_else(|| cfg.data_dir.clone());
    let (key_path, db_path) = (dir.join(KEY_FILE), dir.join(DB_FILE));
    if key_path.exists() || db_path.exists() {
        return Err(fail(format!("{} est déjà initialisé", dir.display())));
    }
    eprintln!("Recherche d'une identité (puzzle de 20 bits, quelques secondes)…");
    let key = generate_node_key(&mut rand::rng());
    let id = NodeId::from_public_key(&key.verifying_key());

    // Dossier créé en 0700 ; les droits d'un dossier déjà là (par exemple
    // créé par systemd) ne sont pas modifiés.
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)?;
    let enc = Zeroizing::new(format!(
        "{}\n",
        data_encoding::BASE32_NOPAD.encode(&key.to_bytes())
    ));
    f.write_all(enc.as_bytes())?;
    f.sync_all()?;
    NodeStore::open(&db_path)?;
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;

    let listen = cfg.listen.first().cloned().unwrap_or_default();
    println!("identifiant : {id}");
    println!("adresse     : {listen}");
    println!();
    println!(
        "À publier : l'identifiant ci-dessus et l'adresse publique (hôte ou IP) du \
         serveur avec le port d'écoute ({listen} est l'adresse locale configurée)."
    );
    Ok(())
}

fn status(data_dir: Option<PathBuf>) -> Result<()> {
    let dir = data_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let key = load_key(&dir)?;
    let id = NodeId::from_public_key(&key.verifying_key());
    let db = dir.join(DB_FILE);
    if !db.exists() {
        return Err(fail(format!("base absente de {}", dir.display())));
    }
    let stats = NodeStore::open(&db)?.stats()?;
    println!("identifiant : {id}");
    println!(
        "version     : {} (protocole {PROTOCOL_VERSION})",
        env!("CARGO_PKG_VERSION")
    );
    println!("paquets     : {}", stats.packets);
    println!("accusés     : {}", stats.acks);
    println!("octets      : {}", stats.bytes);
    Ok(())
}

fn run(config: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config.as_deref())?;
    let key = load_key(&cfg.data_dir)?;
    let id = NodeId::from_public_key(&key.verifying_key());
    let store = NodeStore::open(cfg.data_dir.join(DB_FILE))?;
    let sockets = cfg.bind()?;
    let server_cfg = cfg.server_config(sockets, key);
    let stats: std::sync::Arc<ServerStats> = std::sync::Arc::clone(&server_cfg.stats);
    let every = std::time::Duration::from_secs(cfg.log_interval_secs);
    let policy = cfg.policy();

    logging::init_stderr();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        tracing::info!("nœud {id} démarré");
        let reporter = tokio::spawn(server::report_loop(stats, every));
        let r = server::run(server_cfg, store, policy, shutdown_signal()).await;
        reporter.abort();
        tracing::info!("nœud arrêté");
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
        // Pas de gestion de signaux possible : on tourne jusqu'à être tué.
        _ => std::future::pending::<()>().await,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Init { data_dir, config } => init(data_dir, config),
        Cmd::Run { config } => run(config),
        Cmd::Status { data_dir } => status(data_dir),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("erreur : {e}");
            ExitCode::FAILURE
        }
    }
}
