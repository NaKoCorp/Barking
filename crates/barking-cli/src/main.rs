//! `barking`: CLI on top of `barking-core`. Two transports: files (one
//! packet = one `.pkt` file) and the network (`barking sync`, through
//! `barking-net`).

mod nodes;
mod passphrase;

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::contact::ContactCard;
use barking_core::identity::{Fingerprint, safety_number};
use barking_core::packet::Packet;
use barking_core::store::{Direction, MessageStatus};
use barking_core::{
    Accepted, Core, CoreError, HistoryArchive, InviteState, LinkBundle, LinkOffer, LinkRequest,
    MAX_ARCHIVE_BYTES, MAX_LINK_BUNDLE_BYTES, MAX_LINK_FILE_BYTES, ReceiveOutcome,
};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

const DB_FILE: &str = "barking.db";
const SALT_FILE: &str = "salt";
const DEFAULT_LOG_LIMIT: usize = 50;

#[derive(Parser)]
#[command(
    name = "barking",
    about = "End-to-end encrypted decentralized messaging"
)]
struct Cli {
    /// Data directory (default: ~/.barking).
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new identity.
    Init {
        #[arg(long, value_name = "DEVICE")]
        name: String,
    },
    /// Recovers an identity from its 24-word phrase (read from standard input).
    Recover {
        #[arg(long, value_name = "DEVICE")]
        name: String,
    },
    /// Shows my fingerprint.
    Whoami,
    /// Shows my contact card.
    Card {
        #[arg(long, value_name = "NAME")]
        display_name: String,
    },
    /// Adds a contact from their card and invites them: the invitation
    /// packets are written to --out.
    Add {
        card: String,
        #[arg(long)]
        alias: Option<String>,
        /// Adds the contact without sending an invitation.
        #[arg(long)]
        no_invite: bool,
        /// Directory where to write the invitation packets.
        #[arg(long, value_name = "DIR", required_unless_present = "no_invite")]
        out: Option<PathBuf>,
    },
    /// Sends the invitation to a contact again (at most once a day).
    Invite {
        contact: String,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Lists the contact requests (people who invited me and are not contacts).
    Requests,
    /// Accepts a contact request: adds the contact, shows the held messages
    /// and writes the answer packets.
    Accept {
        fingerprint: String,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Refuses a contact request; nothing is sent to the requester.
    Refuse {
        fingerprint: String,
        /// Directory where to write the packets for my other devices.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Blocks the sender of a contact request.
    Block {
        fingerprint: String,
        /// Directory where to write the packets for my other devices.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Removes a contact and their sessions (the history is kept).
    Remove { contact: String },
    /// Lists the contacts.
    Contacts,
    /// Encrypts a text for a contact: one .pkt file per packet.
    Send {
        contact: String,
        text: String,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Processes received packet files.
    Receive {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Directory where to write the delivery receipts.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Rewrites the packets awaiting a receipt (to retransmit).
    Outbox {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Shows a contact's safety code.
    Safety {
        contact: String,
        /// Marks the contact as verified.
        #[arg(long)]
        verified: bool,
    },
    /// Shows the transparency log.
    Log {
        #[arg(long, default_value_t = DEFAULT_LOG_LIMIT)]
        limit: usize,
    },
    /// Shows the messages exchanged with a contact: one line per message.
    Messages { contact: String },
    /// Changes a contact's alias (an empty alias removes it).
    Alias { contact: String, alias: String },
    /// Links a new device to this identity.
    #[command(subcommand)]
    Link(LinkCommand),
    /// Manages the relay nodes.
    #[command(subcommand)]
    Node(NodeCommand),
    /// Drops the pending packets on the nodes, polls my mailboxes and processes what was received.
    Sync,
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Adds a node by hand: address (IP:port) and identifier published by its
    /// operator. The node must answer and prove its identity.
    Add { address: String, id: String },
    /// Lists the known nodes (the address only for those added by hand).
    List,
    /// Removes a node added by hand.
    Remove { id: String },
}

#[derive(Subcommand)]
enum LinkCommand {
    /// On the admin device: writes a link offer (valid for 10 minutes).
    Offer {
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// On the new device: creates the data directory and writes the link request.
    Request {
        #[arg(long, value_name = "FILE")]
        offer: PathBuf,
        #[arg(long, value_name = "DEVICE")]
        name: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// On the admin device: accepts the request and writes the link bundle.
    Accept {
        #[arg(long, value_name = "FILE")]
        request: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Also writes the encrypted history to this file.
        #[arg(long, value_name = "FILE")]
        history: Option<PathBuf>,
        /// Directory where to write the packets to send (like `send --out`);
        /// without it, they stay pending (`barking outbox`).
        #[arg(long, value_name = "DIR")]
        packets: Option<PathBuf>,
    },
    /// On the new device: completes the link with the received bundle.
    Finish {
        #[arg(long, value_name = "FILE")]
        bundle: PathBuf,
        /// Encrypted history delivered with the link bundle.
        #[arg(long, value_name = "FILE")]
        history: Option<PathBuf>,
    },
}

/// Error printed on the error output; the program exits with code 1.
struct CliError(String);

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        CliError(match e {
            CoreError::StoreLocked => "Incorrect passphrase".to_owned(),
            CoreError::UnknownContact => "Unknown contact".to_owned(),
            CoreError::InvalidPhrase => "Invalid recovery phrase".to_owned(),
            CoreError::NotAdmin => "This device does not hold the root key".to_owned(),
            CoreError::TooLarge => "Text too long".to_owned(),
            CoreError::LinkPending => {
                "This device is waiting for its link to finish: run `barking link finish`"
                    .to_owned()
            }
            CoreError::Link(reason) => format!("Link rejected: {reason}"),
            other => format!("Error: {other}"),
        })
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError(format!("I/O error: {e}"))
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
        _ => fail("Home directory not found: use --home"),
    }
}

/// Passphrase: `BARKING_PASSPHRASE`, otherwise hidden input.
fn read_passphrase(confirm: bool) -> CliResult<Zeroizing<String>> {
    if let Ok(p) = std::env::var("BARKING_PASSPHRASE") {
        let p = Zeroizing::new(p);
        if p.is_empty() {
            return fail("The passphrase cannot be empty");
        }
        return Ok(p);
    }
    let first = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Confirm the passphrase: ")?);
        if *first != *again {
            return fail("The two passphrases differ");
        }
    }
    if first.is_empty() {
        return fail("The passphrase cannot be empty");
    }
    Ok(first)
}

fn read_salt(home: &Path) -> CliResult<[u8; 16]> {
    let bytes = fs::read(home.join(SALT_FILE)).map_err(|_| {
        CliError(format!(
            "No identity in {}: run `barking init`",
            home.display()
        ))
    })?;
    <[u8; 16]>::try_from(bytes.as_slice()).or_else(|_| fail("Salt file corrupted"))
}

/// Refuses if the database exists; checked before any input is read.
fn ensure_no_identity(home: &Path) -> CliResult<()> {
    if home.join(DB_FILE).exists() {
        return fail(format!(
            "An identity already exists in {}: nothing was modified",
            home.display()
        ));
    }
    Ok(())
}

/// Prepares the directory and the salt of a new identity; refuses if the database exists.
/// Only a directory created here has its permissions set: an existing one is left as is.
fn prepare_new_home(home: &Path) -> CliResult<[u8; 16]> {
    ensure_no_identity(home)?;
    let created = !home.exists();
    fs::create_dir_all(home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if created {
            fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
        } else if fs::metadata(home)?.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "Warning: the data directory is accessible to other users: restrict it (chmod 700)"
            );
        }
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
    println!("Fingerprint: {}", core.fingerprint());
}

fn run(cli: Cli) -> CliResult<()> {
    let home = match cli.home {
        Some(h) => h,
        None => default_home()?,
    };
    match cli.command {
        Command::Init { name } => {
            ensure_no_identity(&home)?;
            let pass = read_passphrase(true)?;
            let salt = prepare_new_home(&home)?;
            let key = passphrase::derive_key(&pass, &salt);
            let (core, phrase) =
                Core::create(&home.join(DB_FILE), &key, &name, now(), &mut rand::rng())?;
            println!("Identity created.");
            show_created(&core);
            println!();
            println!("Recovery phrase (24 words):");
            println!("{}", phrase.as_str());
            println!();
            println!("Write it down offline: it alone lets you recover your identity.");
        }
        Command::Recover { name } => {
            ensure_no_identity(&home)?;
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
            println!("Identity recovered.");
            show_created(&core);
            println!("Contacts are not restored: add them again.");
        }
        Command::Whoami => println!("{}", open_core(&home)?.fingerprint()),
        Command::Card { display_name } => {
            println!(
                "{}",
                open_core(&home)?.contact_card(&display_name)?.to_text()
            );
        }
        Command::Add {
            card,
            alias,
            no_invite,
            out,
        } => {
            let card = ContactCard::from_text(&card)
                .map_err(|e| CliError(format!("Invalid contact card: {e}")))?;
            let out = if no_invite { None } else { out };
            let mut core = open_core(&home)?;
            // Checked before anything is added: a failure leaves no half-done add.
            if let Some(dir) = &out {
                check_packets_dir(dir)?;
            }
            let fp = core
                .add_contact(&card, alias.as_deref(), now(), &mut rand::rng())
                .map_err(|e| match e {
                    CoreError::InvalidSignature | CoreError::Malformed(_) | CoreError::TooLarge => {
                        CliError(format!("Invalid contact card: {e}"))
                    }
                    other => CliError::from(other),
                })?;
            println!("Contact added: {fp}");
            if let Some(dir) = out {
                match core.invite(&fp, now(), &mut rand::rng()) {
                    Ok(packets) => write_packets(&dir, &packets, "Invitation")?,
                    // The contact stays added: only the invitation waits.
                    Err(CoreError::TooSoon { retry_at }) => {
                        println!(
                            "Invitation not sent: possible after {}",
                            format_time(retry_at)
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Command::Invite { contact, out } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            check_packets_dir(&out)?;
            match core.invite(&fp, now(), &mut rand::rng()) {
                Ok(packets) => write_packets(&out, &packets, "Invitation")?,
                Err(CoreError::TooSoon { retry_at }) => {
                    return fail(format!(
                        "Invitation not sent: possible after {}",
                        format_time(retry_at)
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Command::Requests => {
            let mut core = open_core(&home)?;
            let me = core.fingerprint();
            for r in core.requests()? {
                let mut line = format!(
                    "{}  {}  code {}  {} invitations  {} messages pending  last {}",
                    r.fingerprint,
                    if r.display_name.is_empty() {
                        "-".to_owned()
                    } else {
                        printable(&r.display_name)
                    },
                    safety_number(&me, &r.fingerprint),
                    r.invite_count,
                    r.pending_messages,
                    format_time(r.last_seen),
                );
                if r.hidden {
                    line.push_str("  hidden");
                }
                println!("{line}");
            }
            core.mark_requests_seen()?;
        }
        Command::Accept {
            fingerprint,
            alias,
            out,
        } => {
            let mut core = open_core(&home)?;
            let fp = resolve_request(&core, &fingerprint)?;
            check_packets_dir(&out)?;
            let accepted = core.accept_request(&fp, alias.as_deref(), now(), &mut rand::rng())?;
            println!("Contact added: {}", accepted.contact);
            show_accepted(&core, accepted, &out)?;
        }
        Command::Refuse { fingerprint, out } => {
            let mut core = open_core(&home)?;
            let fp = resolve_request(&core, &fingerprint)?;
            let packets = core.refuse_request(&fp, now(), &mut rand::rng())?;
            println!("Request refused: {fp} (nothing is sent to them)");
            write_sync_packets(out.as_deref(), &packets)?;
        }
        Command::Block { fingerprint, out } => {
            let mut core = open_core(&home)?;
            let fp = resolve_request(&core, &fingerprint)?;
            let packets = core.block_request(&fp, now(), &mut rand::rng())?;
            println!("Blocked: {fp}");
            write_sync_packets(out.as_deref(), &packets)?;
        }
        Command::Remove { contact } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            core.remove_contact(&fp, now(), &mut rand::rng())?;
            println!("Contact removed: {fp} (the history is kept)");
        }
        Command::Contacts => {
            let core = open_core(&home)?;
            for c in core.contacts()? {
                let alias = c.alias.as_deref().unwrap_or("-");
                let state = if c.verified { "verified" } else { "unverified" };
                let invite = match core.invite_state(&c.fingerprint, now())? {
                    InviteState::None => "-",
                    InviteState::Sent { .. } => "invited",
                    InviteState::Unanswered { .. } => "unanswered",
                    InviteState::Accepted { .. } => "accepted",
                };
                println!("{}  {}  {state}  {invite}", printable(alias), c.fingerprint);
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
                    .map_err(|e| CliError(format!("Queued packet unreadable: {e}")))?;
                let path = write_packet(&out, &packet)?;
                println!("{}", path.display());
            }
            match pending.len() {
                0 => println!("0 packets pending"),
                1 => println!("1 packet pending"),
                n => println!("{n} packets pending"),
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
                println!("Contact marked as verified.");
            }
        }
        Command::Log { limit } => {
            let core = open_core(&home)?;
            for (at, event) in core.transparency_log(limit)? {
                // The text reuses names and aliases chosen by others.
                println!("[{}] {}", format_time(at), printable(&event.describe()));
            }
        }
        Command::Messages { contact } => {
            let core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            for m in core.messages_with(&fp, now())? {
                println!("{}", render_row(m.at, m.direction, m.status, &m.body));
            }
        }
        Command::Alias { contact, alias } => {
            let mut core = open_core(&home)?;
            let fp = resolve(&core, &contact)?;
            core.set_alias(&fp, &alias, now(), &mut rand::rng())
                .map_err(|e| match e {
                    CoreError::TooLarge => CliError("Alias too long".to_owned()),
                    other => other.into(),
                })?;
            println!("Alias of {fp}: {}", printable(&alias));
        }
        Command::Link(cmd) => link(&home, cmd)?,
        Command::Node(cmd) => nodes::run(&home, cmd)?,
        Command::Sync => return sync(&home),
    }
    Ok(())
}

/// `barking sync`: one synchronization with the network (`barking_net::sync`),
/// then what was received and a summary.
fn sync(home: &Path) -> CliResult<()> {
    let mut core = nodes::open(home)?;
    let opts = barking_net::SyncOptions {
        allow_private: nodes::allow_private(),
        ..barking_net::SyncOptions::default()
    };
    // The runtime only exists for the duration of the sync.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("I/O error: {e}")))?;
    let mut report = rt.block_on(barking_net::sync(&mut core, &barking_net::QuicDialer, opts));
    // A proof of work still being computed is not waited for.
    rt.shutdown_timeout(Duration::from_secs(1));
    nodes::warn_state(report.state_reset, report.state_unsaved);
    if let Some(e) = &report.error {
        return fail(format!("Sync failed: {e}"));
    }
    for outcome in std::mem::take(&mut report.received) {
        show_outcome(&core, "network", outcome, AckSink::Queued)?;
    }
    if report.receive_errors > 0 {
        println!(
            "{} item(s) not processed: fetched again at the next sync",
            report.receive_errors
        );
    }
    if report.intro_partial {
        println!("introductions: partial poll, the rest at the next sync");
    }
    if report.pow_exhausted {
        println!("proof-of-work budget exhausted: remaining messages at the next sync");
    }
    for node in &report.avoided {
        println!(
            "Node {} avoided: it lost messages or kept failing",
            printable(node)
        );
    }
    if report.polled_all_sessions {
        println!("Poll recorded");
    } else {
        println!("Poll not recorded: some mailboxes were not fetched in full");
    }
    println!(
        "polled {} mailboxes, received {} items, deposited {} (first copies {}, extra {}), avoided {} nodes, view {} nodes",
        report.mailboxes_polled,
        report.items_received,
        report.acks_deposited + report.first_copies + report.extra_copies,
        report.first_copies,
        report.extra_copies,
        report.avoided.len(),
        report.view_size,
    );
    if report.view_size == 0 {
        return fail("no known node: add a contact or a node");
    }
    if !report.network_up {
        println!("network unreachable, nothing is lost");
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
            // The file contains the link secret: never displayed.
            file.write(&offer.to_bytes())?;
            println!("Link offer written: {}", out.display());
            println!("It is valid for 10 minutes and can be used only once.");
            println!("Hand this file to the new device over a channel you control.");
        }
        LinkCommand::Request { offer, name, out } => {
            // Everything is read and checked before the directory is created.
            ensure_no_identity(home)?;
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
                // No half-ready state: a new attempt must be possible.
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
            println!("Link request written: {}", out.display());
            println!("Hand it to the admin device (`barking link accept`).");
            println!("Delete the offer file now: {}", offer.display());
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
                return fail("--out and --history must name two different files");
            }
            let mut core = open_core(home)?;
            // `link_device` consumes the offer: all outputs are opened and
            // validated beforehand, so the bundle is not lost on a write
            // error.
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
            println!("Device linked: {}", printable(&request.name));
            println!("Link bundle written: {}", out.display());
            if let Some(path) = &history {
                println!("History written: {}", path.display());
            }
            match packets {
                Some(dir) => {
                    for p in &outcome.packets {
                        println!("{}", write_packet(&dir, p)?.display());
                    }
                }
                None if !outcome.packets.is_empty() => {
                    println!(
                        "{} packet(s) to send to your contacts and devices: `barking outbox`",
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
            println!("Link completed.");
            show_created(&core);
            println!(
                "Delete the link files now: the offer, the link bundle \
                 and the history. They are no longer needed, and the bundle and the \
                 history contain your contacts and your messages."
            );
        }
    }
    Ok(())
}

/// Reads a file of at most `max` bytes: the size is checked before
/// reading, and the read itself is bounded.
fn read_limited(path: &Path, max: usize) -> CliResult<Zeroizing<Vec<u8>>> {
    let too_large = || {
        CliError(format!(
            "{}: file too large (at most {max} bytes)",
            path.display()
        ))
    };
    let meta = fs::metadata(path)
        .map_err(|e| CliError(format!("{}: cannot read ({e})", path.display())))?;
    if !meta.is_file() {
        return fail(format!("{}: not a file", path.display()));
    }
    if meta.len() > max as u64 {
        return Err(too_large());
    }
    // Wiped on drop: the offer contains the link secret.
    let mut buf = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(too_large());
    }
    Ok(buf)
}

/// Output file opened in advance, as 0600: a possible write error is
/// known before any irreversible action.
struct OutFile {
    file: fs::File,
    path: PathBuf,
    created: bool,
}

impl OutFile {
    /// Opens (or creates) the file without truncating it.
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
                "{}: cannot write ({e}); nothing was modified",
                path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // A file that already exists keeps its permissions on open.
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
        r.map_err(|e| CliError(format!("{}: cannot write ({e})", self.path.display())))
    }

    /// Abandon: a file we created and left empty is removed.
    fn discard(&mut self) {
        if self.created {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Creates the packets directory if missing and checks that it is writable.
fn check_packets_dir(dir: &Path) -> CliResult<()> {
    let bad = |e: io::Error| {
        CliError(format!(
            "{}: packets directory unusable ({e}); nothing was modified",
            dir.display()
        ))
    };
    fs::create_dir_all(dir).map_err(bad)?;
    let probe = dir.join(".barking-sonde");
    fs::write(&probe, b"").map_err(bad)?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

/// One line per message: `date  direction  status  text`. The text is
/// sanitized: a message can neither add a line nor drive the terminal.
fn render_row(at: u64, direction: Direction, status: MessageStatus, body: &str) -> String {
    let arrow = match direction {
        Direction::Out => "→",
        Direction::In => "←",
    };
    let status = match (direction, status) {
        (Direction::In, _) => "received",
        (_, MessageStatus::Pending) => "pending",
        (_, MessageStatus::OnNetwork) => "sent",
        (_, MessageStatus::Received) => "delivered",
        (_, MessageStatus::NotDelivered) => "failed",
    };
    format!(
        "{}  {arrow}  {status}  {}",
        format_time(at),
        printable(body)
    )
}

fn resolve(core: &Core, who: &str) -> CliResult<Fingerprint> {
    core.resolve(who).map_err(|e| match e {
        CoreError::UnknownContact => CliError(format!("Unknown contact: {}", printable(who))),
        other => other.into(),
    })
}

/// Finds the pending request named by `who` (displayed fingerprint, with or
/// without dashes, in any case).
fn resolve_request(core: &Core, who: &str) -> CliResult<Fingerprint> {
    let compact = |s: &str| {
        s.chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect::<String>()
    };
    let wanted = compact(who);
    if !wanted.is_empty() {
        for r in core.requests()? {
            if compact(&r.fingerprint.to_string()) == wanted {
                return Ok(r.fingerprint);
            }
        }
    }
    fail(format!("No contact request from: {}", printable(who)))
}

/// Writes the packets and lists them; `what` names them in the summary.
fn write_packets(dir: &Path, packets: &[Packet], what: &str) -> CliResult<()> {
    fs::create_dir_all(dir)?;
    for p in packets {
        println!("{}", write_packet(dir, p)?.display());
    }
    if packets.is_empty() {
        println!("{what}: no packet to send (every device already answered)");
    }
    Ok(())
}

/// Packets for my other devices after a refusal or a block: written when a
/// directory is given, otherwise left to `barking outbox`.
fn write_sync_packets(out: Option<&Path>, packets: &[Packet]) -> CliResult<()> {
    match out {
        Some(dir) => {
            fs::create_dir_all(dir)?;
            for p in packets {
                println!("{}", write_packet(dir, p)?.display());
            }
        }
        None if !packets.is_empty() => println!("{}", sync_packets_hint(packets.len())),
        None => {}
    }
    Ok(())
}

/// What to do with the packets for my other devices left unwritten. Not
/// "rerun": the request is gone. They wait in the send queue.
fn sync_packets_hint(n: usize) -> String {
    format!("{n} packet(s) for your other devices: write them with `barking outbox --out <dir>`")
}

/// The line for a `ReceiveOutcome::Ignored`, whatever its cause (content
/// set aside, an ephemeral already due, an answer to my invite, an
/// invitation dropped as blocked, refused or beyond the list): true of
/// each, nothing to show.
fn ignored_line(label: &str) -> String {
    format!("{label}: nothing to show")
}

/// Shows what `accept` replayed, then writes the answer packets.
///
/// The receipts of the replayed messages are NEVER written, nor shown as
/// receipts: a replayed message can be older than the receipt grace window,
/// and the core then deliberately does not queue its receipt (a late receipt
/// would reveal when the request was accepted). The core keeps the receipts
/// it did queue in its send queue (`barking outbox`). Only `accepted.packets`
/// are written here.
fn show_accepted(core: &Core, accepted: Accepted, out: &Path) -> CliResult<()> {
    for outcome in accepted.replayed {
        show_outcome(core, "replayed", outcome, AckSink::Withheld)?;
    }
    write_packets(out, &accepted.packets, "Answer")?;
    println!("Receipts of the replayed messages, if any, go out with `barking outbox`");
    Ok(())
}

fn write_packet(dir: &Path, packet: &Packet) -> CliResult<PathBuf> {
    let name = data_encoding::HEXLOWER.encode(&packet.id.0);
    let path = dir.join(format!("{name}.pkt"));
    fs::write(&path, packet.encode())?;
    Ok(path)
}

/// Where the receipt of a received message goes.
#[derive(Clone, Copy)]
enum AckSink<'a> {
    /// No output directory: the receipt is not written.
    Unwritten,
    /// Written as `.pkt` in this directory.
    Dir(&'a Path),
    /// Stored in the core's send queue (dropped by the sync).
    Queued,
    /// The receipt is neither written nor mentioned (replayed messages).
    Withheld,
}

impl<'a> From<Option<&'a Path>> for AckSink<'a> {
    fn from(out: Option<&'a Path>) -> Self {
        out.map_or(AckSink::Unwritten, AckSink::Dir)
    }
}

/// Shows the result of processing a received packet (file or node).
fn show_outcome(
    core: &Core,
    label: &str,
    outcome: ReceiveOutcome,
    ack_sink: AckSink<'_>,
) -> CliResult<()> {
    match outcome {
        ReceiveOutcome::Message {
            from,
            alias,
            text,
            ack,
            ..
        } => {
            let who = alias.unwrap_or_else(|| from.to_string());
            print!("{}", render_message(&who, &text));
            match ack_sink {
                AckSink::Dir(dir) => {
                    fs::create_dir_all(dir)?;
                    let path = write_packet(dir, &ack)?;
                    println!("  receipt: {}", path.display());
                }
                AckSink::Unwritten => println!("  receipt not written (no --out)"),
                AckSink::Queued => println!("  receipt queued for sending"),
                AckSink::Withheld => {}
            }
        }
        ReceiveOutcome::AckReceived { .. } => println!("{label}: delivered ✓"),
        ReceiveOutcome::Partial => println!("{label}: partial frame"),
        ReceiveOutcome::Duplicate | ReceiveOutcome::DuplicateMessage => {
            println!("{label}: duplicate");
        }
        ReceiveOutcome::NotForUs => println!("{label}: not for you"),
        ReceiveOutcome::Expired => println!("{label}: expired"),
        ReceiveOutcome::Quarantined { reason } => {
            println!("{label}: quarantined: {reason}");
        }
        ReceiveOutcome::Synced { kind, .. } => println!(
            "{label}: synced from one of your devices ({})",
            kind.label()
        ),
        ReceiveOutcome::CardUpdated { from, alias } => {
            let who = alias.unwrap_or_else(|| from.to_string());
            println!("{label}: {} updated their device list", printable(&who));
        }
        ReceiveOutcome::Removed => {
            println!("{label}: this device was removed from your account");
        }
        ReceiveOutcome::ContactRequest {
            contact, resent, ..
        } => {
            // The declared name is read from the stored request.
            let name = core
                .requests()?
                .into_iter()
                .find(|r| r.fingerprint == contact)
                .map(|r| format!(" ({})", printable(&r.display_name)))
                .unwrap_or_default();
            let again = if resent { " resent" } else { "" };
            println!("{label}: Contact request from {contact}{name}{again}");
        }
        ReceiveOutcome::Ignored => println!("{}", ignored_line(label)),
        ReceiveOutcome::NeedsUpdate { from, alias } => {
            let who = alias.unwrap_or_else(|| from.to_string());
            println!(
                "{label}: {} sent content this version cannot read (update needed)",
                printable(&who)
            );
        }
        ReceiveOutcome::Reaction {
            from, alias, added, ..
        } => {
            let who = alias.unwrap_or_else(|| from.to_string());
            if added.is_empty() {
                println!("{label}: {} changed their reactions", printable(&who));
            } else {
                println!(
                    "{label}: {} reacted {}",
                    printable(&who),
                    printable(&added.join(" "))
                );
            }
        }
    }
    Ok(())
}

fn receive(home: &Path, files: &[PathBuf], out: Option<&Path>) -> CliResult<()> {
    let mut core = open_core(home)?;
    let mut failed = false;
    for file in files {
        let label = file.display();
        let bytes = match fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{label}: cannot read ({e})");
                failed = true;
                continue;
            }
        };
        let outcome = core.receive(&bytes, "file", now(), &mut rand::rng())?;
        show_outcome(&core, &label.to_string(), outcome, AckSink::from(out))?;
    }
    if failed {
        return fail("Some files could not be read");
    }
    core.mark_polled(now())?;
    Ok(())
}

/// Prefix of a message's continuation lines: every displayed line stays
/// attributable, a received text cannot imitate another sender's line.
const CONTINUATION: &str = "  │ ";

/// Received message, ready to display: `[sender] first line`, then one
/// line prefixed by [`CONTINUATION`] for each following line.
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

/// Invisible formatting characters (Unicode category Cf, including the
/// bidirectional controls) and line or paragraph separators: they can
/// reorder or hide the displayed text.
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

/// Text from the outside, on a single line: control characters (terminal
/// escape sequences, line breaks) and invisible formatting characters are
/// replaced; only the tab is kept.
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

/// UTC date `YYYY-MM-DD HH:MM:SS` (Howard Hinnant's civil algorithm).
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
    fn sync_packets_hint_points_to_the_outbox() {
        // The request is gone after `refuse`/`block`: rerunning fails.
        let hint = sync_packets_hint(2);
        assert!(hint.contains("barking outbox --out <dir>"), "{hint}");
        assert!(!hint.contains("rerun"), "{hint}");
    }

    #[test]
    fn ignored_outcome_is_neutral() {
        // Also an invitation dropped (blocked, refused, list full).
        assert_eq!(ignored_line("p.bin"), "p.bin: nothing to show");
    }

    #[test]
    fn formats_unix_time_in_utc() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_time(1_800_000_000), "2027-01-15 08:00:00");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00:00");
    }

    #[test]
    fn printable_strips_terminal_escapes() {
        // A single line: the line break is replaced too (multi-line
        // messages go through `render_message`).
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
            MessageStatus::Received,
            "a\n[bob] x\u{1b}[31m",
        );
        assert_eq!(
            line,
            "1970-01-01 00:00:00  →  delivered  a\u{FFFD}[bob] x\u{FFFD}[31m"
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

    /// Spec §8.3: past the receipt grace window, writing the receipt of a
    /// replayed message would reveal when the request was accepted. `accept`
    /// writes only `Accepted.packets`, never the receipts carried by the
    /// replayed outcomes. (The binary cannot control its clock: the day-20
    /// case is exercised here, at the helper level.)
    #[test]
    fn accept_on_day_20_writes_no_receipt() {
        const T0: u64 = 1_800_000_000;
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let mut rng = rand::rng();
        let (mut alice, _) =
            Core::create(&dir.path().join("a.db"), &key, "tel-a", T0, &mut rng).unwrap();
        let (mut bob, _) =
            Core::create(&dir.path().join("b.db"), &key, "tel-b", T0, &mut rng).unwrap();
        alice.contact_card("Alice").unwrap();
        let bob_card = bob.contact_card("Bob").unwrap();
        let bob_fp = alice.add_contact(&bob_card, None, T0, &mut rng).unwrap();
        let mut sent = alice.invite(&bob_fp, T0, &mut rng).unwrap();
        sent.extend(alice.send_text(&bob_fp, "salut", T0 + 1, &mut rng).unwrap());
        for p in &sent {
            bob.receive(&p.encode(), "file", T0 + 2, &mut rng).unwrap();
        }
        let request = bob.requests().unwrap().remove(0);
        assert_eq!(request.pending_messages, 1);

        let day_20 = T0 + 20 * 86_400;
        let accepted = bob
            .accept_request(&request.fingerprint, Some("alice"), day_20, &mut rng)
            .unwrap();
        let receipts: Vec<_> = accepted
            .replayed
            .iter()
            .filter_map(|o| match o {
                ReceiveOutcome::Message { ack, .. } => Some(ack.id),
                _ => None,
            })
            .collect();
        assert_eq!(receipts.len(), 1, "the held message is replayed");
        let written: Vec<_> = accepted.packets.iter().map(|p| p.id).collect();
        assert!(!written.is_empty());

        let out = dir.path().join("out");
        show_accepted(&bob, accepted, &out).unwrap_or_else(|e| panic!("{}", e.0));
        let on_disk: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(on_disk.len(), written.len(), "{on_disk:?}");
        for id in receipts {
            let name = format!("{}.pkt", data_encoding::HEXLOWER.encode(&id.0));
            assert!(!on_disk.contains(&name), "a receipt was written");
        }
    }
}
