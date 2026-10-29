//! `barking` : CLI au-dessus de `barking-core`. Le transport de la v0 est le
//! fichier : un paquet = un fichier `.pkt`.

mod passphrase;

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use barking_core::contact::ContactCard;
use barking_core::identity::Fingerprint;
use barking_core::packet::Packet;
use barking_core::store::{Direction, MessageStatus};
use barking_core::{
    Core, CoreError, HistoryArchive, LinkBundle, LinkOffer, LinkRequest, MAX_ARCHIVE_BYTES,
    MAX_LINK_BUNDLE_BYTES, MAX_LINK_FILE_BYTES, ReceiveOutcome,
};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

const DB_FILE: &str = "barking.db";
const SALT_FILE: &str = "salt";
const DEFAULT_LOG_LIMIT: usize = 50;

#[derive(Parser)]
#[command(
    name = "barking",
    about = "Messagerie décentralisée chiffrée de bout en bout"
)]
struct Cli {
    /// Dossier de données (défaut : ~/.barking).
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Crée une nouvelle identité.
    Init {
        #[arg(long, value_name = "APPAREIL")]
        name: String,
    },
    /// Retrouve une identité à partir de sa phrase de 24 mots (lue sur l'entrée standard).
    Recover {
        #[arg(long, value_name = "APPAREIL")]
        name: String,
    },
    /// Affiche mon empreinte.
    Whoami,
    /// Affiche ma carte de contact.
    Card {
        #[arg(long, value_name = "NOM")]
        display_name: String,
    },
    /// Ajoute un contact à partir de sa carte.
    Add {
        card: String,
        #[arg(long)]
        alias: Option<String>,
    },
    /// Supprime un contact et ses sessions (l'historique est conservé).
    Remove { contact: String },
    /// Liste les contacts.
    Contacts,
    /// Chiffre un texte pour un contact : un fichier .pkt par paquet.
    Send {
        contact: String,
        text: String,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Traite des fichiers de paquets reçus.
    Receive {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Dossier où écrire les accusés de réception.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Réécrit les paquets en attente d'accusé (à retransmettre).
    Outbox {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Affiche le code de sécurité d'un contact.
    Safety {
        contact: String,
        /// Marque le contact comme vérifié.
        #[arg(long)]
        verified: bool,
    },
    /// Affiche le journal de transparence.
    Log {
        #[arg(long, default_value_t = DEFAULT_LOG_LIMIT)]
        limit: usize,
    },
    /// Affiche les messages échangés avec un contact : une ligne par message.
    Messages { contact: String },
    /// Change l'alias d'un contact (un alias vide le retire).
    Alias { contact: String, alias: String },
    /// Lie un nouvel appareil à cette identité.
    #[command(subcommand)]
    Link(LinkCommand),
}

#[derive(Subcommand)]
enum LinkCommand {
    /// Sur l'appareil administrateur : écrit une offre de liaison (valable 10 minutes).
    Offer {
        #[arg(long, value_name = "FICHIER")]
        out: PathBuf,
    },
    /// Sur le nouvel appareil : crée le dossier de données et écrit la demande de liaison.
    Request {
        #[arg(long, value_name = "FICHIER")]
        offer: PathBuf,
        #[arg(long, value_name = "APPAREIL")]
        name: String,
        #[arg(long, value_name = "FICHIER")]
        out: PathBuf,
    },
    /// Sur l'appareil administrateur : accepte la demande et écrit le paquet de liaison.
    Accept {
        #[arg(long, value_name = "FICHIER")]
        request: PathBuf,
        #[arg(long, value_name = "FICHIER")]
        out: PathBuf,
        /// Écrit aussi l'historique chiffré dans ce fichier.
        #[arg(long, value_name = "FICHIER")]
        history: Option<PathBuf>,
        /// Dossier où écrire les paquets à envoyer (comme `send --out`) ;
        /// sans lui, ils restent en attente (`barking outbox`).
        #[arg(long, value_name = "DIR")]
        packets: Option<PathBuf>,
    },
    /// Sur le nouvel appareil : termine la liaison avec le paquet reçu.
    Finish {
        #[arg(long, value_name = "FICHIER")]
        bundle: PathBuf,
        /// Historique chiffré remis avec le paquet de liaison.
        #[arg(long, value_name = "FICHIER")]
        history: Option<PathBuf>,
    },
}

/// Erreur affichée sur la sortie d'erreur ; le programme sort avec le code 1.
struct CliError(String);

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        CliError(match e {
            CoreError::StoreLocked => "Phrase de passe incorrecte".to_owned(),
            CoreError::UnknownContact => "Contact inconnu".to_owned(),
            CoreError::InvalidPhrase => "Phrase de récupération invalide".to_owned(),
            CoreError::NotAdmin => "Cet appareil ne détient pas la clé racine".to_owned(),
            CoreError::TooLarge => "Texte trop long".to_owned(),
            CoreError::LinkPending => {
                "Cet appareil attend la fin de sa liaison : lance `barking link finish`".to_owned()
            }
            CoreError::Link(reason) => format!("Liaison refusée : {reason}"),
            other => format!("Erreur : {other}"),
        })
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError(format!("Erreur d'entrée/sortie : {e}"))
    }
}

type CliResult<T> = Result<T, CliError>;

fn fail<T>(msg: impl Into<String>) -> CliResult<T> {
    Err(CliError(msg.into()))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError(msg)) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn default_home() -> CliResult<PathBuf> {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h).join(".barking")),
        _ => fail("Dossier personnel introuvable : utilise --home"),
    }
}

/// Phrase de passe : `BARKING_PASSPHRASE`, sinon saisie masquée.
fn read_passphrase(confirm: bool) -> CliResult<Zeroizing<String>> {
    if let Ok(p) = std::env::var("BARKING_PASSPHRASE") {
        let p = Zeroizing::new(p);
        if p.is_empty() {
            return fail("La phrase de passe ne peut pas être vide");
        }
        return Ok(p);
    }
    let first = Zeroizing::new(rpassword::prompt_password("Phrase de passe : ")?);
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password(
            "Confirme la phrase de passe : ",
        )?);
        if *first != *again {
            return fail("Les deux phrases de passe sont différentes");
        }
    }
    if first.is_empty() {
        return fail("La phrase de passe ne peut pas être vide");
    }
    Ok(first)
}

fn read_salt(home: &Path) -> CliResult<[u8; 16]> {
    let bytes = fs::read(home.join(SALT_FILE)).map_err(|_| {
        CliError(format!(
            "Aucune identité dans {} : lance `barking init`",
            home.display()
        ))
    })?;
    <[u8; 16]>::try_from(bytes.as_slice()).or_else(|_| fail("Fichier de sel corrompu"))
}

/// Prépare le dossier et le sel d'une nouvelle identité ; refuse si la base existe.
fn prepare_new_home(home: &Path) -> CliResult<[u8; 16]> {
    if home.join(DB_FILE).exists() {
        return fail(format!(
            "Une identité existe déjà dans {} : rien n'a été modifié",
            home.display()
        ));
    }
    fs::create_dir_all(home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    }
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    fs::write(home.join(SALT_FILE), salt)?;
    Ok(salt)
}

fn open_core(home: &Path) -> CliResult<Core> {
    let salt = read_salt(home)?;
    let pass = read_passphrase(false)?;
    let key = passphrase::derive_key(&pass, &salt);
    Ok(Core::open(&home.join(DB_FILE), &key, now())?)
}

fn show_created(core: &Core) {
    println!("Empreinte : {}", core.fingerprint());
}

fn run(cli: Cli) -> CliResult<()> {
    let home = match cli.home {
        Some(h) => h,
        None => default_home()?,
    };
    match cli.command {
        Command::Init { name } => {
            let pass = read_passphrase(true)?;
            let salt = prepare_new_home(&home)?;
            let key = passphrase::derive_key(&pass, &salt);
            let (core, phrase) =
                Core::create(&home.join(DB_FILE), &key, &name, now(), &mut rand::rng())?;
            println!("Identité créée.");
            show_created(&core);
            println!();
            println!("Phrase de récupération (24 mots) :");
            println!("{}", phrase.as_str());
            println!();
            println!("Note-la hors ligne : elle seule permet de retrouver ton identité.");
        }
        Command::Recover { name } => {
            let mut phrase = Zeroizing::new(String::new());
            io::stdin().read_to_string(&mut phrase)?;
            let pass = read_passphrase(true)?;
            let salt = prepare_new_home(&home)?;
            let key = passphrase::derive_key(&pass, &salt);
            let core = Core::recover(
                &home.join(DB_FILE),
                &key,
                phrase.trim(),
                &name,
                now(),
                &mut rand::rng(),
            )?;
            println!("Identité retrouvée.");
            show_created(&core);
            println!("Les contacts ne sont pas restaurés : ajoute-les de nouveau.");
        }
        Command::Whoami => println!("{}", open_core(&home)?.fingerprint()),
        Command::Card { display_name } => {
            println!(
                "{}",
                open_core(&home)?.contact_card(&display_name)?.to_text()
            );
        }
        Command::Add { card, alias } => {
            let card = ContactCard::from_text(&card)
                .map_err(|e| CliError(format!("Carte de contact invalide : {e}")))?;
            let mut core = open_core(&home)?;
            let fp = core
                .add_contact(&card, alias.as_deref(), now(), &mut rand::rng())
                .map_err(|e| match e {
                    CoreError::StoreLocked => CliError::from(e),
                    other => CliError(format!("Carte de contact invalide : {other}")),
                })?;
            println!("Contact ajouté : {fp}");
        }
        Command::Remove { contact } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            core.remove_contact(&fp, now(), &mut rand::rng())?;
            println!("Contact supprimé : {fp} (l'historique est conservé)");
        }
        Command::Contacts => {
            let core = open_core(&home)?;
            for c in core.contacts()? {
                let alias = c.alias.as_deref().unwrap_or("-");
                let state = if c.verified {
                    "vérifié"
                } else {
                    "non vérifié"
                };
                println!("{}  {}  {state}", printable(alias), c.fingerprint);
            }
        }
        Command::Send { contact, text, out } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            let packets = core.send_text(&fp, &text, now(), &mut rand::rng())?;
            fs::create_dir_all(&out)?;
            for p in &packets {
                let path = write_packet(&out, p)?;
                println!("{}", path.display());
            }
        }
        Command::Receive { files, out } => return receive(&home, &files, out.as_deref()),
        Command::Outbox { out } => {
            let mut core = open_core(&home)?;
            let pending = core.pending_outbox(now())?;
            fs::create_dir_all(&out)?;
            for bytes in &pending {
                let packet = Packet::decode(bytes)
                    .map_err(|e| CliError(format!("Paquet en file illisible : {e}")))?;
                let path = write_packet(&out, &packet)?;
                println!("{}", path.display());
            }
            match pending.len() {
                0 => println!("0 paquet en attente"),
                1 => println!("1 paquet en attente"),
                n => println!("{n} paquets en attente"),
            }
        }
        Command::Safety { contact, verified } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            if verified {
                core.mark_verified(&fp, now(), &mut rand::rng())?;
            }
            println!("{}", core.safety_number(&fp)?);
            if verified {
                println!("Contact marqué comme vérifié.");
            }
        }
        Command::Log { limit } => {
            let core = open_core(&home)?;
            for (at, event) in core.transparency_log(limit)? {
                println!("[{}] {}", format_time(at), event.describe());
            }
        }
        Command::Messages { contact } => {
            let core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            for m in core.messages_with(&fp)? {
                println!("{}", render_row(m.at, m.direction, m.status, &m.body));
            }
        }
        Command::Alias { contact, alias } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            core.set_alias(&fp, &alias, now(), &mut rand::rng())
                .map_err(|e| match e {
                    CoreError::TooLarge => CliError("Alias trop long".to_owned()),
                    other => other.into(),
                })?;
            println!("Alias de {fp} : {}", printable(&alias));
        }
        Command::Link(cmd) => link(&home, cmd)?,
    }
    Ok(())
}

fn link(home: &Path, cmd: LinkCommand) -> CliResult<()> {
    match cmd {
        LinkCommand::Offer { out } => {
            let mut core = open_core(home)?;
            let mut file = OutFile::open(&out)?;
            let offer = match core.link_offer(now(), &mut rand::rng()) {
                Ok(o) => o,
                Err(e) => {
                    file.discard();
                    return Err(e.into());
                }
            };
            // Le fichier contient le secret de liaison : jamais affiché.
            file.write(&offer.to_bytes())?;
            println!("Offre de liaison écrite : {}", out.display());
            println!("Elle est valable 10 minutes et ne sert qu'une fois.");
            println!("Remets ce fichier au nouvel appareil par un canal que tu maîtrises.");
        }
        LinkCommand::Request { offer, name, out } => {
            // Tout est lu et vérifié avant de créer le dossier.
            let bytes = read_limited(&offer, MAX_LINK_FILE_BYTES)?;
            let parsed = LinkOffer::from_bytes(&bytes)?;
            drop(bytes);
            let pass = read_passphrase(true)?;
            let mut file = OutFile::open(&out)?;
            let existed = home.exists();
            let salt = match prepare_new_home(home) {
                Ok(s) => s,
                Err(e) => {
                    file.discard();
                    return Err(e);
                }
            };
            let key = passphrase::derive_key(&pass, &salt);
            let begun = Core::begin_link(
                &home.join(DB_FILE),
                &key,
                &parsed,
                &name,
                now(),
                &mut rand::rng(),
            );
            let written = match begun {
                Ok((core, request)) => {
                    drop(core);
                    file.write(&request.to_bytes())
                }
                Err(e) => Err(e.into()),
            };
            if let Err(e) = written {
                // Aucun état à moitié prêt : un nouvel essai doit être possible.
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    let _ = fs::remove_file(home.join(format!("{DB_FILE}{suffix}")));
                }
                let _ = fs::remove_file(home.join(SALT_FILE));
                if !existed {
                    let _ = fs::remove_dir(home);
                }
                file.discard();
                return Err(e);
            }
            println!("Demande de liaison écrite : {}", out.display());
            println!("Remets-la à l'appareil administrateur (`barking link accept`).");
            println!(
                "Supprime maintenant le fichier d'offre : {}",
                offer.display()
            );
        }
        LinkCommand::Accept {
            request,
            out,
            history,
            packets,
        } => {
            let bytes = read_limited(&request, MAX_LINK_FILE_BYTES)?;
            let request = LinkRequest::from_bytes(&bytes)?;
            if history.as_ref().is_some_and(|h| *h == out) {
                return fail("--out et --history doivent désigner deux fichiers différents");
            }
            let mut core = open_core(home)?;
            // `link_device` consomme l'offre : toutes les sorties sont ouvertes
            // et validées avant, pour ne pas perdre le paquet sur une erreur
            // d'écriture.
            let mut bundle_file = OutFile::open(&out)?;
            let mut history_file = match &history {
                Some(path) => match OutFile::open(path) {
                    Ok(f) => Some(f),
                    Err(e) => {
                        bundle_file.discard();
                        return Err(e);
                    }
                },
                None => None,
            };
            let packets_ok = match &packets {
                Some(dir) => check_packets_dir(dir),
                None => Ok(()),
            };
            if let Err(e) = packets_ok {
                bundle_file.discard();
                if let Some(f) = history_file.as_mut() {
                    f.discard();
                }
                return Err(e);
            }
            let outcome =
                match core.link_device(&request, history.is_some(), now(), &mut rand::rng()) {
                    Ok(o) => o,
                    Err(e) => {
                        bundle_file.discard();
                        if let Some(f) = history_file.as_mut() {
                            f.discard();
                        }
                        return Err(e.into());
                    }
                };
            bundle_file.write(&outcome.bundle.to_bytes())?;
            if let (Some(file), Some(archive)) = (history_file.as_mut(), &outcome.history) {
                file.write(&archive.to_bytes())?;
            }
            println!("Appareil lié : {}", printable(&request.name));
            println!("Paquet de liaison écrit : {}", out.display());
            if let Some(path) = &history {
                println!("Historique écrit : {}", path.display());
            }
            match packets {
                Some(dir) => {
                    for p in &outcome.packets {
                        println!("{}", write_packet(&dir, p)?.display());
                    }
                }
                None if !outcome.packets.is_empty() => {
                    println!(
                        "{} paquet(s) à envoyer à tes contacts et appareils : `barking outbox`",
                        outcome.packets.len()
                    );
                }
                None => {}
            }
        }
        LinkCommand::Finish { bundle, history } => {
            let bytes = read_limited(&bundle, MAX_LINK_BUNDLE_BYTES)?;
            let bundle = LinkBundle::from_bytes(&bytes)?;
            drop(bytes);
            let archive = match &history {
                Some(path) => Some(HistoryArchive::from_bytes(&read_limited(
                    path,
                    MAX_ARCHIVE_BYTES,
                )?)?),
                None => None,
            };
            let mut core = open_core(home)?;
            core.finish_link(&bundle, archive.as_ref(), now())?;
            println!("Liaison terminée.");
            show_created(&core);
        }
    }
    Ok(())
}

/// Lit un fichier d'au plus `max` octets : la taille est vérifiée avant la
/// lecture, et la lecture elle-même est bornée.
fn read_limited(path: &Path, max: usize) -> CliResult<Zeroizing<Vec<u8>>> {
    let too_large = || {
        CliError(format!(
            "{} : fichier trop volumineux (au plus {max} octets)",
            path.display()
        ))
    };
    let meta = fs::metadata(path)
        .map_err(|e| CliError(format!("{} : lecture impossible ({e})", path.display())))?;
    if !meta.is_file() {
        return fail(format!("{} : ce n'est pas un fichier", path.display()));
    }
    if meta.len() > max as u64 {
        return Err(too_large());
    }
    // Effacé à la destruction : l'offre contient le secret de liaison.
    let mut buf = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(too_large());
    }
    Ok(buf)
}

/// Fichier de sortie ouvert à l'avance, en 0600 : une erreur d'écriture
/// possible est connue avant toute action irréversible.
struct OutFile {
    file: fs::File,
    path: PathBuf,
    created: bool,
}

impl OutFile {
    /// Ouvre (ou crée) le fichier sans le vider.
    fn open(path: &Path) -> CliResult<Self> {
        let created = !path.exists();
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path).map_err(|e| {
            CliError(format!(
                "{} : écriture impossible ({e}) ; rien n'a été modifié",
                path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Un fichier déjà présent garde ses droits à l'ouverture.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            file,
            path: path.to_owned(),
            created,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> CliResult<()> {
        use std::io::Write;
        let r = (|| {
            self.file.set_len(0)?;
            self.file.write_all(bytes)?;
            self.file.sync_all()
        })();
        r.map_err(|e| {
            CliError(format!(
                "{} : écriture impossible ({e})",
                self.path.display()
            ))
        })
    }

    /// Abandon : un fichier créé par nous et resté vide est supprimé.
    fn discard(&mut self) {
        if self.created {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Crée le dossier des paquets s'il manque et vérifie qu'on peut y écrire.
fn check_packets_dir(dir: &Path) -> CliResult<()> {
    let bad = |e: io::Error| {
        CliError(format!(
            "{} : dossier des paquets inutilisable ({e}) ; rien n'a été modifié",
            dir.display()
        ))
    };
    fs::create_dir_all(dir).map_err(bad)?;
    let probe = dir.join(".barking-sonde");
    fs::write(&probe, b"").map_err(bad)?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

/// Une ligne par message : `date  sens  statut  texte`. Le texte est
/// assaini : un message ne peut ni ajouter de ligne ni piloter le terminal.
fn render_row(at: u64, direction: Direction, status: MessageStatus, body: &str) -> String {
    let arrow = match direction {
        Direction::Out => "→",
        Direction::In => "←",
    };
    let status = match (direction, status) {
        (Direction::In, _) => "reçu",
        (_, MessageStatus::Queued) => "en attente",
        (_, MessageStatus::Sent) => "envoyé",
        (_, MessageStatus::Delivered) => "livré",
        (_, MessageStatus::Failed) => "échec",
    };
    format!(
        "{}  {arrow}  {status}  {}",
        format_time(at),
        printable(body)
    )
}

fn resolve(core: &Core, who: &str) -> CliResult<Fingerprint> {
    core.resolve(who).map_err(|e| match e {
        CoreError::UnknownContact => CliError(format!("Contact inconnu : {}", printable(who))),
        other => other.into(),
    })
}

fn write_packet(dir: &Path, packet: &Packet) -> CliResult<PathBuf> {
    let name = data_encoding::HEXLOWER.encode(&packet.id.0);
    let path = dir.join(format!("{name}.pkt"));
    fs::write(&path, packet.encode())?;
    Ok(path)
}

fn receive(home: &Path, files: &[PathBuf], out: Option<&Path>) -> CliResult<()> {
    let mut core = open_core(home)?;
    let mut failed = false;
    for file in files {
        let label = file.display();
        let bytes = match fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{label} : lecture impossible ({e})");
                failed = true;
                continue;
            }
        };
        match core.receive(&bytes, "fichier", now(), &mut rand::rng())? {
            ReceiveOutcome::Message {
                from,
                alias,
                text,
                ack,
            } => {
                let who = alias.unwrap_or_else(|| from.to_string());
                print!("{}", render_message(&who, &text));
                match out {
                    Some(dir) => {
                        fs::create_dir_all(dir)?;
                        let path = write_packet(dir, &ack)?;
                        println!("  accusé : {}", path.display());
                    }
                    None => println!("  accusé non écrit (aucun --out)"),
                }
            }
            ReceiveOutcome::AckReceived { .. } => println!("{label} : livré ✓"),
            ReceiveOutcome::Partial => println!("{label} : trame partielle"),
            ReceiveOutcome::Duplicate => println!("{label} : doublon"),
            ReceiveOutcome::NotForUs => println!("{label} : pas pour toi"),
            ReceiveOutcome::Expired => println!("{label} : expiré"),
            ReceiveOutcome::Quarantined { reason } => {
                println!("{label} : mis en quarantaine : {reason}");
            }
            ReceiveOutcome::Synced { kind } => println!(
                "{label} : synchronisé depuis un de tes appareils ({})",
                kind.label()
            ),
            ReceiveOutcome::CardUpdated { from, alias } => {
                let who = alias.unwrap_or_else(|| from.to_string());
                println!(
                    "{label} : {} a mis à jour sa liste d'appareils",
                    printable(&who)
                );
            }
        }
    }
    if failed {
        return fail("Certains fichiers n'ont pas pu être lus");
    }
    core.mark_polled(now())?;
    Ok(())
}

/// Préfixe des lignes de suite d'un message : chaque ligne affichée reste
/// attribuable, un texte reçu ne peut pas imiter la ligne d'un autre expéditeur.
const CONTINUATION: &str = "  │ ";

/// Message reçu, prêt à afficher : `[expéditeur] première ligne`, puis une
/// ligne préfixée par [`CONTINUATION`] pour chaque ligne suivante.
fn render_message(who: &str, text: &str) -> String {
    let mut lines = text.split('\n');
    let first = lines.next().unwrap_or("");
    let mut out = format!("[{}] {}\n", printable(who), printable(first));
    for line in lines {
        out.push_str(CONTINUATION);
        out.push_str(&printable(line));
        out.push('\n');
    }
    out
}

/// Caractères de mise en forme invisibles (catégorie Unicode Cf, dont les
/// contrôles bidirectionnels) et séparateurs de ligne ou de paragraphe : ils
/// peuvent réordonner ou masquer le texte affiché.
fn is_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Texte venu de l'extérieur, sur une seule ligne : les caractères de
/// contrôle (séquences d'échappement du terminal, retours à la ligne) et de
/// mise en forme invisibles sont remplacés ; seule la tabulation est gardée.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c.is_control() && c != '\t') || is_format_control(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Date UTC `AAAA-MM-JJ HH:MM:SS` (algorithme civil de Howard Hinnant).
fn format_time(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_time_in_utc() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_time(1_800_000_000), "2027-01-15 08:00:00");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00:00");
    }

    #[test]
    fn printable_strips_terminal_escapes() {
        // Une seule ligne : le retour à la ligne est remplacé aussi (les
        // messages multilignes passent par `render_message`).
        assert_eq!(
            printable("a\u{1b}[31mb\nc\td"),
            "a\u{FFFD}[31mb\u{FFFD}c\td"
        );
    }

    #[test]
    fn printable_strips_bidi_and_format_controls() {
        for c in [
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{061C}',
            '\u{200B}',
            '\u{FEFF}',
            '\u{2028}',
            '\u{E0041}',
        ] {
            assert_eq!(printable(&format!("a{c}b")), "a\u{FFFD}b", "{:X}", c as u32);
        }
        assert_eq!(printable("café 🐕"), "café 🐕");
    }

    #[test]
    fn render_row_is_one_sanitized_line() {
        let line = render_row(
            0,
            Direction::Out,
            MessageStatus::Delivered,
            "a\n[bob] x\u{1b}[31m",
        );
        assert_eq!(
            line,
            "1970-01-01 00:00:00  →  livré  a\u{FFFD}[bob] x\u{FFFD}[31m"
        );
        assert!(!line.contains('\n'));
    }

    #[test]
    fn render_message_prefixes_continuation_lines() {
        assert_eq!(
            render_message("alice", "hi\n[alice] send me the code"),
            "[alice] hi\n  │ [alice] send me the code\n"
        );
        assert_eq!(render_message("bob", "x"), "[bob] x\n");
        assert_eq!(render_message("bob", "a\r\n"), "[bob] a\u{FFFD}\n  │ \n");
    }
}
