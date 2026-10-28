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
use barking_core::{Core, CoreError, ReceiveOutcome};
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
        return Ok(Zeroizing::new(p));
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
    Ok(Core::open(&home.join(DB_FILE), &key)?)
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
                .add_contact(&card, alias.as_deref())
                .map_err(|e| match e {
                    CoreError::StoreLocked => CliError::from(e),
                    other => CliError(format!("Carte de contact invalide : {other}")),
                })?;
            println!("Contact ajouté : {fp}");
        }
        Command::Remove { contact } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            core.remove_contact(&fp)?;
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
                core.mark_verified(&fp)?;
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
    }
    Ok(())
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
                println!("[{}] {}", printable(&who), printable(&text));
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
            ReceiveOutcome::Duplicate => println!("{label} : doublon"),
            ReceiveOutcome::NotForUs => println!("{label} : pas pour toi"),
            ReceiveOutcome::Expired => println!("{label} : expiré"),
            ReceiveOutcome::Quarantined { reason } => {
                println!("{label} : mis en quarantaine : {reason}");
            }
        }
    }
    if failed {
        return fail("Certains fichiers n'ont pas pu être lus");
    }
    Ok(())
}

/// Texte venu de l'extérieur : les caractères de contrôle (séquences
/// d'échappement du terminal) sont remplacés, sauf retour à la ligne et tabulation.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
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
        assert_eq!(printable("a\u{1b}[31mb\nc"), "a\u{FFFD}[31mb\nc");
    }
}
