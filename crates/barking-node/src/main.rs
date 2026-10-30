//! `barking-node` : `init`, `run`, `status`, `peers`.

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
    /// Identifiant, version, paquets, accusés et octets gardés ; table de
    /// hachage et recopie.
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Pairs actifs de la table (identifiant, ancienneté, dernier contact),
    /// d'après la dernière sauvegarde de `peers`, sans adresse.
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

/// Avertit (stderr) si le dossier de données est accessible à d'autres
/// utilisateurs que le propriétaire.
fn warn_dir_perms(dir: &Path) {
    if let Ok(m) = fs::metadata(dir)
        && m.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "avertissement : le dossier {} est accessible au groupe ou aux autres \
             (mode {:04o}) ; `chmod 700` est recommandé.",
            dir.display(),
            m.permissions().mode() & 0o7777
        );
    }
}

/// Lit la clé du nœud ; refuse un lien symbolique, un fichier irrégulier ou
/// un fichier lisible par d'autres utilisateurs.
fn load_key(dir: &Path) -> Result<SigningKey> {
    let path = dir.join(KEY_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|_| {
        fail(format!(
            "{} n'est pas initialisé (`barking-node init`)",
            dir.display()
        ))
    })?;
    if !meta.file_type().is_file() {
        return Err(fail(format!(
            "{} doit être un fichier ordinaire (ni lien symbolique ni autre type)",
            path.display()
        )));
    }
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

/// Écrit la clé dans `node.key.tmp` (0600) puis la range d'un `rename`.
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
    let created = !dir.exists();
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    warn_dir_perms(&dir);
    // Clé rangée d'abord (dernier geste atomique de l'identité), puis la base
    // en 0600 dès sa création. En cas d'échec, tout ce qui a été créé est
    // retiré : `init` peut être relancé.
    let res = write_key(&dir, &key).and_then(|()| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&db_path)?;
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
    println!("identifiant : {id}");
    println!("adresse     : {listen}");
    println!();
    println!(
        "À publier : l'identifiant ci-dessus et l'adresse publique (hôte ou IP) du \
         serveur avec le port d'écoute ({listen} est l'adresse locale configurée)."
    );
    Ok(())
}

/// Identifiant du nœud et base ouverte en lecture seule : `status` et
/// `peers` ne modifient rien, même pendant `run`.
fn open_for_reading(data_dir: Option<PathBuf>) -> Result<(NodeId, NodeStore)> {
    let dir = data_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let key = load_key(&dir)?;
    let id = NodeId::from_public_key(&key.verifying_key());
    let db = dir.join(DB_FILE);
    if !db.exists() {
        return Err(fail(format!("base absente de {}", dir.display())));
    }
    // Une base v2 donne `SchemaVersion(2)`, affiché par `main`.
    Ok((id, NodeStore::open_read_only(&db)?))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Heures entières écoulées entre `t` et `now`.
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
    println!("identifiant : {id}");
    println!(
        "version     : {} (protocole {PROTOCOL_VERSION})",
        env!("CARGO_PKG_VERSION")
    );
    println!("paquets     : {}", stats.packets);
    println!("accusés     : {}", stats.acks);
    println!("octets      : {}", stats.bytes);
    println!("pairs       : {}", table.len());
    println!("compartiments : {} non vides", table.non_empty_buckets());
    if table.is_empty() {
        // Sans pair connu, toute boîte gardée paraîtrait « responsable ».
        println!("responsable : table vide ou désactivée");
    } else {
        println!("responsable : {responsible} boîtes");
    }
    println!("recopié     : {recent} octets dans l'heure");
    Ok(())
}

fn peers(data_dir: Option<PathBuf>) -> Result<()> {
    let (id, store) = open_for_reading(data_dir)?;
    let rows = store.load_peers()?;
    // Nœuds actifs de la table (la réserve est écartée).
    let active: HashSet<NodeId> = table_from_rows(id, &rows)
        .closest(&id.0, usize::MAX)
        .into_iter()
        .map(|p| p.id)
        .collect();
    let now = unix_now();
    // Dans l'ordre de `load_peers` : les plus récemment vus d'abord.
    for row in rows.iter().filter(|r| active.contains(&NodeId(r.node_id))) {
        println!(
            "{}  ancienneté {} h  vu il y a {} h",
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
    let store = NodeStore::open(cfg.data_dir.join(DB_FILE))?;
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
        tracing::info!("nœud {id} démarré");
        if dht_off {
            tracing::warn!("[dht] sans public_addr : table désactivée, simple relais");
        }
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
    // Message fixe : la charge d'une panique pourrait contenir une adresse.
    // Une panique dans une tâche de connexion ne termine que cette tâche.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("erreur interne : panique (détails omis)");
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
        // Base du schéma précédent (`status`, `peers` en lecture seule).
        Err(Error::SchemaVersion(2)) => {
            eprintln!("erreur : base en version 2, lancez le nœud une fois pour migrer la base");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("erreur : {e}");
            ExitCode::FAILURE
        }
    }
}
