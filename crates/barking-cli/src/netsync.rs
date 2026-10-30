//! `barking sync` : dépose la file d'envoi sur chaque nœud configuré, relève
//! les boîtes surveillées, traite le reçu, puis dépose les accusés produits.

use std::collections::HashSet;
use std::path::Path;

use barking_core::Core;
use barking_core::packet::{Kind, Packet};
use barking_core::transparency::TransparencyEvent;
use barking_proto::ErrorReason;
use barking_proto::client::{Client, Session};

use super::nodes::{self, NodeEntry};
use super::{AckSink, CliError, CliResult, fail, now, open_core, printable, show_outcome};

/// Ce qui s'est passé avec un nœud, même s'il a échoué en route.
#[derive(Default)]
struct Report {
    deposited: u32,
    refused: u32,
    /// `Some((boîtes, éléments reçus))` une fois la relève terminée.
    fetched: Option<(u32, u32)>,
    /// La relève s'est arrêtée sur un plafond du client : le reste attend.
    truncated: bool,
    /// Un élément relevé n'a pas pu être traité (erreur locale, par exemple
    /// base occupée) : il ne doit pas sortir de la fenêtre de relève.
    receive_failed: bool,
}

impl Report {
    /// Les boîtes ont été relevées en entier et tout a été traité : seul cas
    /// où `mark_polled` peut avancer la fenêtre de relève.
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

pub fn sync(home: &Path) -> CliResult<()> {
    let nodes = nodes::load(home)?;
    if nodes.is_empty() {
        return fail(
            "Aucun nœud configuré : lance `barking node add <adresse:port> <identifiant>`",
        );
    }
    let mut core = open_core(home)?;
    // Le runtime n'existe que le temps de la synchronisation.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("Erreur d'entrée/sortie : {e}")))?;
    let mut ok_nodes = 0usize;
    let mut all_polled = true;
    for node in &nodes {
        let short = node.short_id();
        let mut report = Report::default();
        let result = rt.block_on(sync_node(&mut core, node, &mut report));
        log_report(&mut core, &short, &report)?;
        match result {
            Ok(()) => {
                ok_nodes += 1;
                if !report.fully_polled() {
                    all_polled = false;
                }
                println!(
                    "Nœud {short} : {} déposés ({} refusés), {} boîtes relevées, {} éléments reçus{}",
                    report.deposited,
                    report.refused,
                    report.fetched.map_or(0, |f| f.0),
                    report.fetched.map_or(0, |f| f.1),
                    if report.receive_failed {
                        " (élément non traité : il sera relevé à la prochaine synchronisation)"
                    } else if report.truncated {
                        " (relève partielle : la suite à la prochaine synchronisation)"
                    } else {
                        ""
                    },
                );
            }
            Err(msg) => {
                all_polled = false;
                eprintln!("Nœud {short} : {}", printable(&msg));
            }
        }
    }
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
async fn deposit_all(
    session: &mut Session,
    packets: &[Vec<u8>],
    report: &mut Report,
) -> Result<(), String> {
    for bytes in packets {
        match session.deposit(bytes).await {
            Ok(result) => {
                let is_ack = Packet::decode(bytes).is_ok_and(|p| p.kind == Kind::Ack);
                match tally(is_ack, &result) {
                    DepositTally::Deposited => report.deposited += 1,
                    DepositTally::Refused => report.refused += 1,
                    DepositTally::Deferred => {}
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

async fn sync_node(core: &mut Core, node: &NodeEntry, report: &mut Report) -> Result<(), String> {
    let id = node.node_id().map_err(|e| e.0)?;
    let mut session = Client::connect(node.addr, id)
        .await
        .map_err(|e| e.to_string())?;

    let first = core.pending_outbox(now()).map_err(|e| e.to_string())?;
    deposit_all(&mut session, &first, report).await?;

    let mailboxes = core.watched_mailboxes(now());
    let items = session.fetch(&mailboxes).await.map_err(|e| e.to_string())?;
    report.truncated = session.last_fetch_truncated();
    let label = format!("nœud {}", node.short_id());
    for item in &items {
        // Un accusé peut arriver dans une autre boîte que celles relevées
        // pour lui : tout passe par `receive`, qui décide.
        match core.receive(item, "nœud", now(), &mut rand::rng()) {
            Ok(outcome) => {
                show_outcome(&label, outcome, AckSink::Queued).map_err(|e| e.0)?;
            }
            Err(e) => {
                report.receive_failed = true;
                eprintln!("{label} : élément ignoré ({})", printable(&e.to_string()));
            }
        }
    }
    report.fetched = Some((
        u32::try_from(mailboxes.len()).unwrap_or(u32::MAX),
        u32::try_from(items.len()).unwrap_or(u32::MAX),
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
    deposit_all(&mut session, &more, report).await?;
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
