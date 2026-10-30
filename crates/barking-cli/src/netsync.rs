//! `barking sync` : pour chaque nœud configuré, relève les boîtes surveillées
//! et traite le reçu, puis dépose la file d'envoi (accusés produits compris).
//!
//! **Relève.** D'abord les boîtes de session (et d'accusés attendus sur une
//! session), avec le budget complet du client, puis les boîtes
//! d'introduction, avec `INTRO_FETCH_BYTES` : une boîte d'introduction se
//! calcule à partir d'une clé publique, n'importe qui peut la remplir de
//! déchets. Pour chaque nœud et chaque boîte, la position atteinte (`seen`)
//! est gardée et reprise la fois suivante, même si la liste des boîtes a
//! changé. Seule une relève de sessions incomplète empêche `mark_polled` :
//! une boîte d'introduction inondée ne retarde que les premiers contacts. Un
//! `RateLimited` sur une relève la rend partielle, sans faire échouer le nœud.
//!
//! **Dépôts**, après la relève : accusés d'abord (sans preuve de travail),
//! puis les paquets jamais déposés sur ce nœud, puis les anciens. Après une
//! issue sur un nœud, un paquet n'y est redéposé qu'au bout d'un délai
//! (`retry_after`) : 24 h s'il a été accepté (ou refusé pour de bon), 10 min
//! si le nœud ou la boîte était plein, 1 h pour un accusé arrivé avant son
//! paquet. Budget de preuve épuisé : les paquets à preuve
//! restants attendent, les autres partent. `RateLimited` : arrêt des dépôts
//! sur ce nœud pour cette synchronisation, sans échec.
//!
//! Positions et dépôts sont gardés dans la base chiffrée du cœur
//! (`Core::transport_state`), jamais en clair : ils contiennent des
//! identifiants de boîtes et de paquets. Un ancien fichier en clair
//! (`sync_state.toml`, `fetch_cursors.toml`) est migré puis effacé.
//! Chaque nœud a `SYNC_NODE_DEADLINE` ; toute la synchronisation dispose de
//! `SYNC_POW_BUDGET` essais de preuve de travail.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use barking_core::Core;
use barking_core::mailbox::MailboxId;
use barking_core::packet::{Kind, Packet};
use barking_core::transparency::TransparencyEvent;
use barking_proto::ErrorReason;
use barking_proto::client::{Client, ClientError, FetchResume, MAX_FETCH_BYTES, Session};
use serde::{Deserialize, Serialize};

use super::nodes::{self, NodeEntry};
use super::{AckSink, CliError, CliResult, fail, now, open_core, printable, show_outcome};

/// Octets relevés au plus par synchronisation dans les boîtes d'introduction.
pub const INTRO_FETCH_BYTES: usize = 8 << 20;
/// Durée maximale de la synchronisation avec un nœud.
pub const SYNC_NODE_DEADLINE: Duration = Duration::from_secs(180);
/// Travail de preuve permis par synchronisation (essais attendus) : environ
/// 1 000 dépôts à 18 bits, 16 à 24 bits.
pub const SYNC_POW_BUDGET: u64 = 1 << 28;
/// Délai avant de redéposer sur un nœud un paquet qu'il a déjà accepté ou
/// refusé pour de bon (au cas où il l'aurait perdu).
pub const REDEPOSIT_AFTER_SECS: u64 = 86_400;
/// Délai après un refus `NodeFull` ou `MailboxFull` (la place peut revenir).
pub const FULL_RETRY_SECS: u64 = 600;
/// Délai après un accusé arrivé avant son paquet (`UnknownAckTarget`).
pub const DEFERRED_ACK_RETRY_SECS: u64 = 3_600;
/// Part de `SYNC_NODE_DEADLINE` pour la relève des sessions.
pub const SESSION_FETCH_SLICE: Duration = Duration::from_secs(90);
/// Part de `SYNC_NODE_DEADLINE` pour la relève des introductions : au-delà,
/// relève partielle, sans échec du nœud.
pub const INTRO_FETCH_SLICE: Duration = Duration::from_secs(45);

/// Clé de l'état dans la base du cœur.
const STATE_KEY: &str = "netsync";
/// Anciens fichiers d'état en clair (migrés puis effacés).
const LEGACY_FILES: [&str; 2] = ["sync_state.toml", "fetch_cursors.toml"];

/// Ce qui s'est passé avec un nœud, même s'il a échoué en route.
#[derive(Default)]
struct Report {
    deposited: u32,
    refused: u32,
    /// Paquets déjà déposés récemment sur ce nœud : pas redéposés.
    already: u32,
    /// `Some((boîtes, éléments reçus))` une fois la relève terminée.
    fetched: Option<(u32, u32)>,
    /// La relève des sessions n'est pas allée au bout (plafond, débit) : le
    /// reste attend.
    truncated: bool,
    /// Un élément de session relevé n'a pas pu être traité (erreur locale,
    /// par exemple base occupée) : il ne doit pas sortir de la fenêtre de relève.
    receive_failed: bool,
    /// Les introductions n'ont pas été relevées en entier (plafond, erreur,
    /// élément non traité) : sans effet sur `mark_polled`.
    intro_partial: bool,
    /// Budget de preuve de travail épuisé : paquets à preuve remis à plus tard.
    pow_exhausted: bool,
    /// Dépôts arrêtés par le nœud (débit) ou par une erreur ou le délai.
    deposits_stopped: Option<String>,
    pow_spent: u64,
}

impl Report {
    /// Les boîtes de session ont été relevées en entier et tout a été
    /// traité : seul cas où `mark_polled` peut avancer la fenêtre de relève.
    fn fully_polled(&self) -> bool {
        self.fetched.is_some() && !self.truncated && !self.receive_failed
    }
}

/// Sort d'un dépôt, vu du résumé.
#[derive(Debug, PartialEq, Eq)]
enum DepositTally {
    Deposited,
    Refused,
    /// Accusé arrivé avant son paquet sur ce nœud (ordre réseau entre deux
    /// nœuds) : ni dépôt ni refus, il sera redéposé à la prochaine synchronisation.
    Deferred,
}

fn tally(is_ack: bool, result: &Result<(), ErrorReason>) -> DepositTally {
    match result {
        Ok(()) => DepositTally::Deposited,
        Err(ErrorReason::UnknownAckTarget) if is_ack => DepositTally::Deferred,
        Err(_) => DepositTally::Refused,
    }
}

/// Position d'une boîte sur un nœud (voir `FetchResume`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    mailbox: String,
    seq: u64,
}

/// Paquet déposé (accepté, refusé ou différé) sur un nœud : pas de nouveau
/// dépôt avant `until`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Deposited {
    id: String,
    #[serde(alias = "at")]
    until: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NodeState {
    id: String,
    #[serde(default)]
    sessions: Vec<Seen>,
    #[serde(default)]
    intro: Vec<Seen>,
    #[serde(default)]
    deposited: Vec<Deposited>,
}

fn to_resume(seen: &[Seen]) -> FetchResume {
    let mut r = FetchResume::default();
    for s in seen {
        if let Ok(b) = data_encoding::HEXLOWER.decode(s.mailbox.as_bytes())
            && let Ok(k) = <[u8; 16]>::try_from(b.as_slice())
        {
            r.seen.insert(k, s.seq);
        }
    }
    r
}

/// Positions des seules boîtes de `current`, dans un ordre stable.
fn from_resume(r: &FetchResume, current: &[MailboxId]) -> Vec<Seen> {
    let mut v: Vec<Seen> = current
        .iter()
        .filter_map(|m| {
            r.seen.get(&m.0).filter(|s| **s > 0).map(|s| Seen {
                mailbox: data_encoding::HEXLOWER.encode(&m.0),
                seq: *s,
            })
        })
        .collect();
    v.sort_by(|a, b| a.mailbox.cmp(&b.mailbox));
    v.dedup();
    v
}

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default, rename = "node")]
    nodes: Vec<NodeState>,
}

/// État gardé dans la base ; absent ou illisible : depuis le début. Un
/// ancien fichier en clair est d'abord migré (si la base n'a pas d'état),
/// puis écrasé de zéros et effacé.
fn load_state(home: &Path, core: &mut Core) -> CliResult<Vec<NodeState>> {
    let parse = |t: &str| toml::from_str::<StateFile>(t).ok().map(|f| f.nodes);
    let mut nodes = core
        .transport_state(STATE_KEY)?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| parse(&t));
    for name in LEGACY_FILES {
        let path = home.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if nodes.is_none() {
            nodes = parse(&text);
            if let Some(n) = &nodes {
                save_state(core, n)?;
            }
        }
        wipe(&path);
    }
    Ok(nodes.unwrap_or_default())
}

/// Écrase un fichier de zéros puis l'efface (au mieux).
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

/// Écrit l'état dans la base chiffrée du cœur.
fn save_state(core: &mut Core, nodes: &[NodeState]) -> CliResult<()> {
    let text = toml::to_string(&StateFile {
        nodes: nodes.to_vec(),
    })
    .map_err(|_| CliError("Erreur : écriture de l'état de synchronisation impossible".into()))?;
    core.set_transport_state(STATE_KEY, text.as_bytes())?;
    Ok(())
}

fn intro_slice() -> Duration {
    // Réglable dans les builds de test seulement.
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("BARKING_TEST_INTRO_SLICE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return Duration::from_millis(ms);
    }
    INTRO_FETCH_SLICE
}

fn pow_budget() -> u64 {
    // Réglable dans les builds de test seulement.
    #[cfg(debug_assertions)]
    if let Some(b) = std::env::var("BARKING_TEST_POW_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return b;
    }
    SYNC_POW_BUDGET
}

pub fn sync(home: &Path) -> CliResult<()> {
    let nodes = nodes::load(home)?;
    if nodes.is_empty() {
        return fail(
            "Aucun nœud configuré : lance `barking node add <adresse:port> <identifiant>`",
        );
    }
    let mut core = open_core(home)?;
    // État des seuls nœuds configurés.
    let mut state: Vec<NodeState> = load_state(home, &mut core)?
        .into_iter()
        .filter(|c| nodes.iter().any(|n| n.id == c.id))
        .collect();
    // Le runtime n'existe que le temps de la synchronisation.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("Erreur d'entrée/sortie : {e}")))?;
    let mut ok_nodes = 0usize;
    let mut all_polled = true;
    let mut pow_left = pow_budget();
    for node in &nodes {
        let short = node.short_id();
        let mut report = Report::default();
        let k = match state.iter().position(|c| c.id == node.id) {
            Some(k) => k,
            None => {
                state.push(NodeState {
                    id: node.id.clone(),
                    ..NodeState::default()
                });
                state.len() - 1
            }
        };
        let result = rt.block_on(sync_node(
            &mut core,
            node,
            &mut report,
            &mut state[k],
            pow_left,
        ));
        pow_left = pow_left.saturating_sub(report.pow_spent);
        log_report(&mut core, &short, &report)?;
        save_state(&mut core, &state)?;
        match result {
            Ok(()) => {
                ok_nodes += 1;
                if !report.fully_polled() {
                    all_polled = false;
                }
                let mut notes = String::new();
                if report.receive_failed {
                    notes +=
                        " (élément non traité : il sera relevé à la prochaine synchronisation)";
                } else if report.truncated {
                    notes += " (relève partielle : la suite à la prochaine synchronisation)";
                }
                if report.intro_partial {
                    notes += " (introductions : relève partielle, la suite à la prochaine synchronisation)";
                }
                if report.pow_exhausted {
                    notes += " (budget de preuve de travail épuisé : dépôts restants à la prochaine synchronisation)";
                }
                if let Some(why) = &report.deposits_stopped {
                    notes += &format!(
                        " (dépôts interrompus : {} ; la suite à la prochaine synchronisation)",
                        printable(why)
                    );
                }
                println!(
                    "Nœud {short} : {} déposés ({} refusés, {} déjà présents), {} boîtes relevées, {} éléments reçus{notes}",
                    report.deposited,
                    report.refused,
                    report.already,
                    report.fetched.map_or(0, |f| f.0),
                    report.fetched.map_or(0, |f| f.1),
                );
            }
            Err(msg) => {
                all_polled = false;
                eprintln!("Nœud {short} : {}", printable(&msg));
            }
        }
    }
    // Une preuve de travail en cours de calcul n'est pas attendue.
    rt.shutdown_timeout(Duration::from_secs(1));
    if all_polled {
        core.mark_polled(now())?;
        println!("Relève enregistrée");
    } else {
        println!("Relève non enregistrée : un nœud n'a pas répondu en entier");
    }
    if ok_nodes == 0 {
        return fail("Aucun nœud n'a répondu");
    }
    Ok(())
}

fn log_report(core: &mut Core, short: &str, r: &Report) -> CliResult<()> {
    if r.deposited + r.refused > 0 {
        core.log_transport_event(
            TransparencyEvent::NodeDeposit {
                node: short.to_owned(),
                count: r.deposited,
                refused: r.refused,
            },
            now(),
        )?;
    }
    if let Some((mailboxes, received)) = r.fetched {
        core.log_transport_event(
            TransparencyEvent::NodeFetch {
                node: short.to_owned(),
                mailboxes,
                received,
            },
            now(),
        )?;
    }
    Ok(())
}

/// Un paquet de la file d'envoi, prêt à déposer.
#[derive(Debug, PartialEq, Eq)]
struct Planned {
    bytes: Vec<u8>,
    /// Identifiant (hex) ; `None` si le paquet est illisible.
    id: Option<String>,
    /// Accusé (sans preuve de travail).
    ack: bool,
}

/// Délai avant un nouveau dépôt sur ce nœud, selon l'issue du dernier.
fn retry_after(tally: &DepositTally, result: &Result<(), ErrorReason>) -> u64 {
    match (tally, result) {
        (DepositTally::Deferred, _) => DEFERRED_ACK_RETRY_SECS,
        (_, Err(ErrorReason::NodeFull | ErrorReason::MailboxFull)) => FULL_RETRY_SECS,
        _ => REDEPOSIT_AFTER_SECS,
    }
}

/// Ordre des dépôts sur un nœud : accusés, paquets jamais déposés ici, puis
/// anciens dépôts à refaire ; ce dont le délai (`retry_after`) court encore
/// est écarté (compté dans le second terme).
fn plan_deposits(outbox: Vec<Vec<u8>>, deposited: &[Deposited], now: u64) -> (Vec<Planned>, u32) {
    let until: HashMap<&str, u64> = deposited.iter().map(|d| (d.id.as_str(), d.until)).collect();
    let (mut acks, mut new, mut old) = (Vec::new(), Vec::new(), Vec::new());
    let mut skipped = 0;
    for bytes in outbox {
        let p = Packet::decode(&bytes).ok();
        let id = p.as_ref().map(|p| data_encoding::HEXLOWER.encode(&p.id.0));
        let ack = p.as_ref().is_some_and(|p| p.kind == Kind::Ack);
        let last = id.as_deref().and_then(|i| until.get(i).copied());
        if last.is_some_and(|t| now < t) {
            skipped += 1;
            continue;
        }
        let item = Planned { bytes, id, ack };
        if ack {
            acks.push(item);
        } else if last.is_none() {
            new.push(item);
        } else {
            old.push(item);
        }
    }
    acks.append(&mut new);
    acks.append(&mut old);
    (acks, skipped)
}

/// Dépose `plan` dans l'ordre et note chaque issue définitive dans
/// `deposited`. Budget de preuve épuisé : les paquets à preuve suivants sont
/// sautés, les autres partent. `RateLimited` ou erreur : arrêt des dépôts.
async fn deposit_all(
    session: &mut Session,
    plan: &[Planned],
    deposited: &mut Vec<Deposited>,
    report: &mut Report,
) {
    for item in plan {
        if !item.ack && report.pow_exhausted {
            continue;
        }
        let r = session.deposit(&item.bytes).await;
        report.pow_spent = session.pow_spent();
        let result = match r {
            Ok(Err(ErrorReason::RateLimited)) => {
                report.deposits_stopped = Some("trop de requêtes".into());
                return;
            }
            Ok(result) => result,
            Err(ClientError::PowBudget) => {
                report.pow_exhausted = true;
                continue;
            }
            Err(e) => {
                report.deposits_stopped = Some(e.to_string());
                return;
            }
        };
        let t = tally(item.ack, &result);
        match t {
            DepositTally::Deposited => report.deposited += 1,
            DepositTally::Refused => report.refused += 1,
            DepositTally::Deferred => {}
        }
        if let Some(id) = &item.id {
            deposited.retain(|d| &d.id != id);
            deposited.push(Deposited {
                id: id.clone(),
                until: now().saturating_add(retry_after(&t, &result)),
            });
        }
    }
}

/// Passe chaque élément relevé à `receive`. Faux si un élément n'a pas pu
/// être traité.
fn receive_all(core: &mut Core, items: &[Vec<u8>], label: &str) -> Result<bool, String> {
    let mut all = true;
    for item in items {
        // Un accusé peut arriver dans une autre boîte que celles relevées
        // pour lui : tout passe par `receive`, qui décide.
        match core.receive(item, "nœud", now(), &mut rand::rng()) {
            Ok(outcome) => {
                show_outcome(label, outcome, AckSink::Queued).map_err(|e| e.0)?;
            }
            Err(e) => {
                all = false;
                eprintln!("{label} : élément ignoré ({})", printable(&e.to_string()));
            }
        }
    }
    Ok(all)
}

/// Relève d'un groupe de boîtes.
enum Fetched {
    /// Éléments, et relève allée au bout.
    Items(Vec<Vec<u8>>, bool),
    /// Débit épuisé avant la première page.
    RateLimited,
}

async fn fetch_group(
    session: &mut Session,
    mailboxes: &[MailboxId],
    resume: &mut FetchResume,
    max_bytes: usize,
    slice: Duration,
) -> Result<Fetched, ClientError> {
    if mailboxes.is_empty() {
        return Ok(Fetched::Items(Vec::new(), true));
    }
    // Le temps écoulé rend la relève partielle, avec ce qui a été pris.
    session.set_fetch_deadline(slice);
    match session.fetch_resumable(mailboxes, resume, max_bytes).await {
        Ok(items) => Ok(Fetched::Items(items, !session.last_fetch_truncated())),
        Err(ClientError::Refused(ErrorReason::RateLimited)) => Ok(Fetched::RateLimited),
        Err(e) => Err(e),
    }
}

async fn sync_node(
    core: &mut Core,
    node: &NodeEntry,
    report: &mut Report,
    state: &mut NodeState,
    pow_budget: u64,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + SYNC_NODE_DEADLINE;
    let timed_out = || "délai de synchronisation dépassé (3 min)".to_string();
    let id = node.node_id().map_err(|e| e.0)?;
    let mut session = tokio::time::timeout_at(deadline, Client::connect(node.addr, id))
        .await
        .map_err(|_| timed_out())?
        .map_err(|e| e.to_string())?;
    session.set_pow_budget(Some(pow_budget));
    let label = format!("nœud {}", node.short_id());

    // Relève : sessions d'abord, introductions ensuite.
    let fetch = async {
        let mut groups = core.watched_mailbox_groups(now());
        groups.sessions.sort_unstable_by_key(|m| m.0);
        groups.intro.sort_unstable_by_key(|m| m.0);
        let mut received = 0usize;
        let mut limited = false;

        let mut resume = to_resume(&state.sessions);
        match fetch_group(
            &mut session,
            &groups.sessions,
            &mut resume,
            MAX_FETCH_BYTES,
            SESSION_FETCH_SLICE,
        )
        .await
        .map_err(|e| e.to_string())?
        {
            Fetched::Items(items, complete) => {
                report.truncated = !complete;
                if receive_all(core, &items, &label)? {
                    state.sessions = from_resume(&resume, &groups.sessions);
                } else {
                    report.receive_failed = true;
                }
                received += items.len();
            }
            Fetched::RateLimited => {
                report.truncated = true;
                limited = true;
            }
        }

        // Débit épuisé : pas de seconde requête refusée d'affilée.
        let mut resume = to_resume(&state.intro);
        let intro = if limited {
            Ok(Fetched::RateLimited)
        } else {
            fetch_group(
                &mut session,
                &groups.intro,
                &mut resume,
                INTRO_FETCH_BYTES,
                intro_slice(),
            )
            .await
        };
        match intro {
            Ok(Fetched::Items(items, complete)) => {
                report.intro_partial = !complete;
                if receive_all(core, &items, &label)? {
                    state.intro = from_resume(&resume, &groups.intro);
                } else {
                    report.intro_partial = true;
                }
                received += items.len();
            }
            Ok(Fetched::RateLimited) => {
                report.intro_partial = true;
                limited = true;
            }
            Err(e) => {
                report.intro_partial = true;
                eprintln!(
                    "{label} : relève des introductions interrompue ({})",
                    printable(&e.to_string())
                );
            }
        }
        report.fetched = Some((
            u32::try_from(groups.sessions.len() + groups.intro.len()).unwrap_or(u32::MAX),
            u32::try_from(received).unwrap_or(u32::MAX),
        ));
        Ok::<bool, String>(limited)
    };
    let limited = tokio::time::timeout_at(deadline, fetch)
        .await
        .map_err(|_| timed_out())??;

    // Dépôts : la file entière (accusés produits par la relève compris),
    // sauf ce que ce nœud a déjà eu récemment.
    let outbox = core.pending_outbox(now()).map_err(|e| e.to_string())?;
    let live: HashSet<String> = outbox
        .iter()
        .filter_map(|b| Packet::decode(b).ok())
        .map(|p| data_encoding::HEXLOWER.encode(&p.id.0))
        .collect();
    // Paquets accusés ou expirés (sortis de la file) : oubliés.
    state.deposited.retain(|d| live.contains(&d.id));
    let (plan, skipped) = plan_deposits(outbox, &state.deposited, now());
    report.already = skipped;
    if limited && !plan.is_empty() {
        report.deposits_stopped = Some("trop de requêtes".into());
    } else if tokio::time::timeout_at(
        deadline,
        deposit_all(&mut session, &plan, &mut state.deposited, report),
    )
    .await
    .is_err()
    {
        report.deposits_stopped = Some(timed_out());
    }
    session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use barking_core::packet::{DEFAULT_HOPS, PacketId, Tier};

    #[test]
    fn receive_failure_or_truncation_blocks_mark_polled() {
        let ok = Report {
            fetched: Some((3, 1)),
            ..Report::default()
        };
        assert!(ok.fully_polled());
        assert!(
            !Report {
                receive_failed: true,
                ..ok_clone(&ok)
            }
            .fully_polled()
        );
        assert!(
            !Report {
                truncated: true,
                ..ok_clone(&ok)
            }
            .fully_polled()
        );
        assert!(!Report::default().fully_polled());
    }

    fn ok_clone(r: &Report) -> Report {
        Report {
            fetched: r.fetched,
            ..Report::default()
        }
    }

    #[test]
    fn intro_partial_or_stopped_deposits_do_not_block_mark_polled() {
        let r = Report {
            fetched: Some((3, 1)),
            intro_partial: true,
            pow_exhausted: true,
            deposits_stopped: Some("x".into()),
            ..Report::default()
        };
        assert!(r.fully_polled());
    }

    #[test]
    fn seen_positions_roundtrip_and_prune() {
        let m = |b: u8| MailboxId([b; 16]);
        let mut r = FetchResume::default();
        r.seen.insert([1; 16], 7);
        r.seen.insert([2; 16], 0);
        r.seen.insert([3; 16], 9);
        // Seules les boîtes encore surveillées, positions nulles omises.
        let s = from_resume(&r, &[m(1), m(2)]);
        assert_eq!(s.len(), 1);
        let back = to_resume(&s);
        assert_eq!(back.seen.get(&[1; 16]), Some(&7));
        assert!(!back.seen.contains_key(&[3; 16]));
    }

    fn pkt(n: u8, kind: Kind) -> Vec<u8> {
        Packet {
            kind,
            hops: DEFAULT_HOPS,
            tier: Tier::S,
            id: PacketId([n; 16]),
            expires_at: 2_000_000_000,
            mailbox: MailboxId([n; 16]),
            payload: vec![n; 8],
        }
        .encode()
    }

    #[test]
    fn deposit_plan_order_and_backoff() {
        let now = 1_800_000_000;
        let hex = |n: u8| data_encoding::HEXLOWER.encode(&[n; 16]);
        let outbox = vec![
            pkt(1, Kind::Message), // ancien, à refaire
            pkt(2, Kind::Message), // déposé récemment : écarté
            pkt(3, Kind::Ack),     // accusé jamais déposé
            pkt(4, Kind::Message), // nouveau
            pkt(5, Kind::Ack),     // accusé déposé récemment : écarté
        ];
        let done = vec![
            Deposited {
                id: hex(1),
                until: now,
            },
            Deposited {
                id: hex(2),
                until: now + 10,
            },
            Deposited {
                id: hex(5),
                until: now + 10,
            },
        ];
        let (plan, skipped) = plan_deposits(outbox, &done, now);
        assert_eq!(skipped, 2);
        let ids: Vec<String> = plan.iter().map(|p| p.id.clone().unwrap()).collect();
        assert_eq!(ids, vec![hex(3), hex(4), hex(1)]);
        assert!(plan[0].ack && !plan[1].ack);
    }

    #[test]
    fn backoff_by_outcome() {
        let ok = Ok(());
        let full = Err(ErrorReason::NodeFull);
        let mfull = Err(ErrorReason::MailboxFull);
        let bad = Err(ErrorReason::Malformed);
        let early = Err(ErrorReason::UnknownAckTarget);
        let r = |ack, res: &Result<(), ErrorReason>| retry_after(&tally(ack, res), res);
        assert_eq!(r(false, &ok), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(true, &ok), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(false, &full), FULL_RETRY_SECS);
        assert_eq!(r(false, &mfull), FULL_RETRY_SECS);
        assert_eq!(r(false, &bad), REDEPOSIT_AFTER_SECS);
        assert_eq!(r(true, &early), DEFERRED_ACK_RETRY_SECS);
        assert_eq!((FULL_RETRY_SECS, DEFERRED_ACK_RETRY_SECS), (600, 3_600));
        // Ancien format (`at`) relu comme échéance.
        let d: Deposited = toml::from_str("id = \"x\"\nat = 5").unwrap();
        assert_eq!(d.until, 5);
    }

    #[test]
    fn early_ack_is_deferred_not_refused() {
        let early = Err(ErrorReason::UnknownAckTarget);
        assert_eq!(tally(true, &early), DepositTally::Deferred);
        assert_eq!(tally(false, &early), DepositTally::Refused);
        assert_eq!(tally(true, &Ok(())), DepositTally::Deposited);
        assert_eq!(
            tally(true, &Err(ErrorReason::PowTooWeak)),
            DepositTally::Refused
        );
    }
}
