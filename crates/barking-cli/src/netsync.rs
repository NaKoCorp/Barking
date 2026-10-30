//! `barking sync` : dépose la file d'envoi sur chaque nœud configuré, relève
//! les boîtes surveillées, traite le reçu, puis dépose les accusés produits.
//!
//! La relève se fait en deux groupes : d'abord les boîtes de session (et
//! d'accusés attendus sur une session), avec le budget complet du client,
//! puis les boîtes d'introduction, avec `INTRO_FETCH_BYTES`. Une boîte
//! d'introduction se calcule à partir d'une clé publique : n'importe qui peut
//! la remplir de déchets. Pour chaque nœud et chaque groupe, la position
//! atteinte est gardée dans `<home>/fetch_cursors.toml` (0600) et reprise à
//! la synchronisation suivante, tant que la liste des boîtes du groupe ne
//! change pas. Seule une relève de sessions incomplète empêche `mark_polled` :
//! une boîte d'introduction inondée ne retarde que les premiers contacts.
//!
//! Chaque nœud a `SYNC_NODE_DEADLINE` ; toute la synchronisation dispose de
//! `SYNC_POW_BUDGET` essais de preuve de travail (au-delà, les dépôts
//! restants attendent la synchronisation suivante).

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
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

const CURSORS_FILE: &str = "fetch_cursors.toml";

/// Ce qui s'est passé avec un nœud, même s'il a échoué en route.
#[derive(Default)]
struct Report {
    deposited: u32,
    refused: u32,
    /// `Some((boîtes, éléments reçus))` une fois la relève des sessions terminée.
    fetched: Option<(u32, u32)>,
    /// La relève des sessions s'est arrêtée sur un plafond : le reste attend.
    truncated: bool,
    /// Un élément de session relevé n'a pas pu être traité (erreur locale,
    /// par exemple base occupée) : il ne doit pas sortir de la fenêtre de relève.
    receive_failed: bool,
    /// Les introductions n'ont pas été relevées en entier (plafond, erreur,
    /// élément non traité) : sans effet sur `mark_polled`.
    intro_partial: bool,
    /// Budget de preuve de travail épuisé : dépôts restants remis à plus tard.
    pow_exhausted: bool,
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

/// Position de reprise d'un groupe de boîtes sur un nœud. `set` : empreinte
/// de la liste des boîtes ; `cursors` : un par tranche, 0 = depuis le début.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct GroupCursor {
    #[serde(default)]
    set: String,
    #[serde(default)]
    cursors: Vec<u64>,
}

impl GroupCursor {
    /// Reprise pour cette liste de boîtes : depuis le début si elle a changé.
    fn resume_for(&self, set: &str) -> FetchResume {
        if self.set != set {
            return FetchResume::default();
        }
        FetchResume {
            cursors: self
                .cursors
                .iter()
                .map(|c| (*c != 0).then_some(*c))
                .collect(),
        }
    }

    fn store(&mut self, set: String, r: &FetchResume) {
        self.set = set;
        self.cursors = r.cursors.iter().map(|c| c.unwrap_or(0)).collect();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NodeCursors {
    id: String,
    #[serde(default)]
    sessions: GroupCursor,
    #[serde(default)]
    intro: GroupCursor,
}

#[derive(Default, Serialize, Deserialize)]
struct CursorsFile {
    #[serde(default, rename = "node")]
    nodes: Vec<NodeCursors>,
}

/// Curseurs gardés ; fichier absent ou illisible : depuis le début.
fn load_cursors(home: &Path) -> Vec<NodeCursors> {
    fs::read_to_string(home.join(CURSORS_FILE))
        .ok()
        .and_then(|t| toml::from_str::<CursorsFile>(&t).ok())
        .map(|f| f.nodes)
        .unwrap_or_default()
}

/// Écrit les curseurs (0600, remplacement atomique).
fn save_cursors(home: &Path, nodes: &[NodeCursors]) -> CliResult<()> {
    let text = toml::to_string(&CursorsFile {
        nodes: nodes.to_vec(),
    })
    .map_err(|_| CliError("Erreur : écriture des curseurs de relève impossible".into()))?;
    let tmp = home.join(format!("{CURSORS_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, home.join(CURSORS_FILE))?;
    Ok(())
}

/// Empreinte d'une liste de boîtes (triée).
fn set_id(mailboxes: &[MailboxId]) -> String {
    let mut h = blake3::Hasher::new();
    for m in mailboxes {
        h.update(&m.0);
    }
    data_encoding::HEXLOWER.encode(&h.finalize().as_bytes()[..16])
}

pub fn sync(home: &Path) -> CliResult<()> {
    let nodes = nodes::load(home)?;
    if nodes.is_empty() {
        return fail(
            "Aucun nœud configuré : lance `barking node add <adresse:port> <identifiant>`",
        );
    }
    let mut core = open_core(home)?;
    // Curseurs des seuls nœuds configurés.
    let mut cursors: Vec<NodeCursors> = load_cursors(home)
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
    let mut pow_left = SYNC_POW_BUDGET;
    for node in &nodes {
        let short = node.short_id();
        let mut report = Report::default();
        let k = match cursors.iter().position(|c| c.id == node.id) {
            Some(k) => k,
            None => {
                cursors.push(NodeCursors {
                    id: node.id.clone(),
                    ..NodeCursors::default()
                });
                cursors.len() - 1
            }
        };
        let result = rt
            .block_on(async {
                tokio::time::timeout(
                    SYNC_NODE_DEADLINE,
                    sync_node(&mut core, node, &mut report, &mut cursors[k], pow_left),
                )
                .await
            })
            .unwrap_or_else(|_| Err("délai de synchronisation dépassé (3 min)".into()));
        pow_left = pow_left.saturating_sub(report.pow_spent);
        log_report(&mut core, &short, &report)?;
        save_cursors(home, &cursors)?;
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
                println!(
                    "Nœud {short} : {} déposés ({} refusés), {} boîtes relevées, {} éléments reçus{notes}",
                    report.deposited,
                    report.refused,
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

/// Dépose ces paquets ; un refus du nœud est compté, une erreur de
/// connexion interrompt (le reste sera redéposé à la prochaine synchronisation).
/// Budget de preuve épuisé : arrêt des dépôts, sans erreur.
async fn deposit_all(
    session: &mut Session,
    packets: &[Vec<u8>],
    report: &mut Report,
) -> Result<(), String> {
    for bytes in packets {
        let r = session.deposit(bytes).await;
        report.pow_spent = session.pow_spent();
        match r {
            Ok(result) => {
                let is_ack = Packet::decode(bytes).is_ok_and(|p| p.kind == Kind::Ack);
                match tally(is_ack, &result) {
                    DepositTally::Deposited => report.deposited += 1,
                    DepositTally::Refused => report.refused += 1,
                    DepositTally::Deferred => {}
                }
            }
            Err(ClientError::PowBudget) => {
                report.pow_exhausted = true;
                return Ok(());
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
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

async fn sync_node(
    core: &mut Core,
    node: &NodeEntry,
    report: &mut Report,
    cursors: &mut NodeCursors,
    pow_budget: u64,
) -> Result<(), String> {
    let id = node.node_id().map_err(|e| e.0)?;
    let mut session = Client::connect(node.addr, id)
        .await
        .map_err(|e| e.to_string())?;
    session.set_pow_budget(Some(pow_budget));

    let first = core.pending_outbox(now()).map_err(|e| e.to_string())?;
    deposit_all(&mut session, &first, report).await?;

    let mut groups = core.watched_mailbox_groups(now());
    groups.sessions.sort_unstable_by_key(|m| m.0);
    groups.intro.sort_unstable_by_key(|m| m.0);
    let label = format!("nœud {}", node.short_id());

    // Sessions d'abord, budget complet.
    let set = set_id(&groups.sessions);
    let mut resume = cursors.sessions.resume_for(&set);
    let items = session
        .fetch_resumable(&groups.sessions, &mut resume, MAX_FETCH_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    report.truncated = session.last_fetch_truncated();
    if receive_all(core, &items, &label)? {
        cursors.sessions.store(set, &resume);
    } else {
        report.receive_failed = true;
    }
    let mut received = items.len();

    // Introductions ensuite, budget réduit ; une erreur n'arrête pas le nœud.
    let set = set_id(&groups.intro);
    let mut resume = cursors.intro.resume_for(&set);
    match session
        .fetch_resumable(&groups.intro, &mut resume, INTRO_FETCH_BYTES)
        .await
    {
        Ok(items) => {
            report.intro_partial = session.last_fetch_truncated();
            if receive_all(core, &items, &label)? {
                cursors.intro.store(set, &resume);
            } else {
                report.intro_partial = true;
            }
            received += items.len();
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

    // Accusés (et tout nouveau paquet) produits par la relève : seulement ce
    // qui n'a pas déjà été déposé, pour ne pas refaire la preuve de travail.
    let sent: HashSet<&Vec<u8>> = first.iter().collect();
    let more: Vec<Vec<u8>> = core
        .pending_outbox(now())
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|b| !sent.contains(b))
        .collect();
    if !report.pow_exhausted {
        deposit_all(&mut session, &more, report).await?;
    }
    session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn intro_partial_does_not_block_mark_polled() {
        let r = Report {
            fetched: Some((3, 1)),
            intro_partial: true,
            pow_exhausted: true,
            ..Report::default()
        };
        assert!(r.fully_polled());
    }

    #[test]
    fn group_cursor_resets_when_set_changes() {
        let mut g = GroupCursor::default();
        let r = FetchResume {
            cursors: vec![Some(7), None],
        };
        g.store("a".into(), &r);
        assert_eq!(g.cursors, vec![7, 0]);
        assert_eq!(g.resume_for("a"), r);
        assert_eq!(g.resume_for("b"), FetchResume::default());
        let m = |b: u8| MailboxId([b; 16]);
        assert_ne!(set_id(&[m(1), m(2)]), set_id(&[m(1)]));
        assert_eq!(set_id(&[m(1), m(2)]), set_id(&[m(1), m(2)]));
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
