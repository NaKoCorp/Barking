//! Entretien des copies (spec §5.3) : chaque boîte gardée dont le nœud est
//! responsable est recopiée vers ses autres responsables, calculés dans sa
//! propre table.
//!
//! - **Ordre** : les boîtes mises en file (un nœud est entré parmi leurs 5
//!   plus proches) d'abord, puis celles traitées le moins récemment. Le
//!   moment du dernier traitement n'est gardé qu'en mémoire.
//! - **Par responsable** : `FindValue` sur toutes les pages, puis `Store`
//!   de ce qui manque, accusés d'abord. Un message sans preuve gardée (ligne
//!   d'une base migrée, `pow = 0`) n'est pas envoyé : il serait refusé.
//! - **Bornes** : `MAX_MAILBOXES_PER_PEER` boîtes par responsable et par
//!   passe ; `replication_bytes_per_hour` octets envoyés par heure, au-delà
//!   la passe s'arrête et reprend à la suivante.
//! - **Refus** : un pair qui ne répond pas, renvoie `RateLimited` ou une
//!   page `Holdings` hors bornes est sauté jusqu'à la passe suivante ; sans
//!   réponse, son échec est compté dans la table (3 échecs le retirent, et
//!   la boîte est alors recopiée vers le suivant dans la même passe).
//!   `NotResponsible`, `PowTooWeak` et `UnknownAckTarget` sont comptés sans
//!   rien réessayer.
//! - **Cadence** : toutes les heures ; une boîte mise en file déclenche une
//!   passe 1 min plus tard au plus tôt. Avec `ServerConfig::dht_tick`, ces
//!   deux délais valent `dht_tick`.
//!
//! Les journaux ne donnent que des compteurs : ni adresse, ni boîte.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use barking_dht::mailbox_key;
use barking_packet::MailboxId;
use barking_proto::{ErrorReason, MAX_HOLDINGS_PER_PAGE, NodeId, Request, Response};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, sleep_until, timeout};

use super::{CALL_TIMEOUT, Dht};
use crate::rules::{self, CopyItem};
use crate::server::{Shared, Stored, unix_now};

/// Passe complète.
pub const PASS_EVERY: Duration = Duration::from_secs(3600);
/// Délai minimal entre une mise en file et la passe qu'elle déclenche.
pub const QUEUE_DELAY: Duration = Duration::from_secs(60);
/// Boîtes recopiées au plus par responsable et par passe (spec §5.3).
pub const MAX_MAILBOXES_PER_PEER: usize = 64;
/// Pages `Holdings` lues au plus par boîte et par responsable : au-delà, le
/// pair est jugé défaillant pour la passe.
pub const MAX_HOLDINGS_PAGES: usize = 16;
/// Fenêtre du plafond de recopie.
const BUDGET_WINDOW_SECS: u64 = 3600;

/// Bilan d'une passe (ou somme de passes), sans donnée par pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Boîtes recopiées (le nœud en est responsable et a de quoi envoyer).
    pub mailboxes: usize,
    /// Éléments acceptés par un responsable.
    pub sent: usize,
    /// Octets envoyés par `Store`, acceptés ou non.
    pub bytes: u64,
    /// Pairs sautés jusqu'à la passe suivante.
    pub skipped_peers: usize,
    pub not_responsible: usize,
    pub pow_too_weak: usize,
    pub unknown_ack: usize,
    /// Autres refus d'un `Store`.
    pub refused: usize,
    /// La passe s'est arrêtée au plafond horaire.
    pub budget_exhausted: bool,
}

impl PassReport {
    /// Ajoute `other` à ce bilan.
    pub fn add(&mut self, other: &PassReport) {
        self.mailboxes += other.mailboxes;
        self.sent += other.sent;
        self.bytes += other.bytes;
        self.skipped_peers += other.skipped_peers;
        self.not_responsible += other.not_responsible;
        self.pow_too_weak += other.pow_too_weak;
        self.unknown_ack += other.unknown_ack;
        self.refused += other.refused;
        self.budget_exhausted |= other.budget_exhausted;
    }
}

impl fmt::Display for PassReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} boîtes, {} envois acceptés, {} octets, {} pairs sautés, refus : \
             NotResponsible={} PowTooWeak={} UnknownAckTarget={} autres={}{}",
            self.mailboxes,
            self.sent,
            self.bytes,
            self.skipped_peers,
            self.not_responsible,
            self.pow_too_weak,
            self.unknown_ack,
            self.refused,
            if self.budget_exhausted {
                ", plafond horaire atteint"
            } else {
                ""
            }
        )
    }
}

/// Plafond d'octets recopiés par fenêtre d'une heure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudget {
    limit: u64,
    window_start: u64,
    used: u64,
}

impl ByteBudget {
    pub fn new(limit: u64) -> ByteBudget {
        ByteBudget {
            limit,
            window_start: 0,
            used: 0,
        }
    }

    /// Reprend une fenêtre enregistrée (redémarrage dans l'heure).
    pub fn resume(limit: u64, window_start: u64, used: u64) -> ByteBudget {
        ByteBudget {
            limit,
            window_start,
            used,
        }
    }

    fn roll(&mut self, now: u64) {
        if now.saturating_sub(self.window_start) >= BUDGET_WINDOW_SECS {
            self.window_start = now;
            self.used = 0;
        }
    }

    /// Vrai si le plafond de la fenêtre courante est atteint.
    pub fn exhausted(&mut self, now: u64) -> bool {
        self.roll(now);
        self.used >= self.limit
    }

    /// Compte `n` octets envoyés.
    pub fn spend(&mut self, now: u64, n: u64) {
        self.roll(now);
        self.used = self.used.saturating_add(n);
    }

    /// (début de la fenêtre, octets envoyés dans la fenêtre).
    pub fn window(&self) -> (u64, u64) {
        (self.window_start, self.used)
    }
}

/// Ordre et file des boîtes, en mémoire seulement.
#[derive(Default)]
pub(crate) struct Queue {
    /// Numéro croissant de traitement.
    seq: u64,
    /// Dernier traitement complet de chaque boîte gardée.
    done: HashMap<MailboxId, u64>,
    /// Boîtes à traiter en premier.
    queued: HashSet<MailboxId>,
}

impl Queue {
    /// Boîtes gardées dans l'ordre de traitement ; oublie celles qui ne le
    /// sont plus et vide la file.
    fn order(&mut self, held: Vec<MailboxId>) -> Vec<MailboxId> {
        let keep: HashSet<MailboxId> = held.iter().copied().collect();
        self.done.retain(|m, _| keep.contains(m));
        let queued = std::mem::take(&mut self.queued);
        let mut order = held;
        order.sort_by_key(|m| (!queued.contains(m), self.done.get(m).copied().unwrap_or(0)));
        order
    }

    fn mark_done(&mut self, m: MailboxId) {
        self.seq += 1;
        self.done.insert(m, self.seq);
    }

    /// Boîtes connues de la dernière passe.
    pub(crate) fn known(&self) -> Vec<MailboxId> {
        self.done.keys().copied().collect()
    }

    /// Met des boîtes en file ; vrai si la file en a gagné.
    pub(crate) fn enqueue(&mut self, boxes: impl IntoIterator<Item = MailboxId>) -> bool {
        let before = self.queued.len();
        self.queued.extend(boxes);
        self.queued.len() > before
    }
}

/// Issue de la recopie d'une boîte vers un responsable.
enum Outcome {
    Done,
    /// Pas de réponse, ou réponse hors bornes : pair sauté, échec compté.
    Failed,
    /// `RateLimited` : pair sauté.
    RateLimited,
    /// Plafond horaire atteint : fin de la passe.
    Budget,
}

/// Fait tourner les passes jusqu'à `stop`.
pub(crate) async fn run(dht: Arc<Dht>, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let every = dht.tick().unwrap_or(PASS_EVERY);
    let delay = dht.tick().unwrap_or(QUEUE_DELAY);
    let limit = dht.config().replication_bytes_per_hour;
    let mut budget = match shared.with_store(true, None, |s, _| s.replicated()).await {
        Stored::Done((start, used)) => ByteBudget::resume(limit, start, used),
        Stored::Busy | Stored::Failed => ByteBudget::new(limit),
    };
    let work = async {
        let mut next = Instant::now() + every;
        loop {
            tokio::select! {
                () = sleep_until(next) => {}
                () = dht.replication_wake().notified() => sleep(delay).await,
            }
            let report = pass(&dht, &shared, &mut budget, unix_now()).await;
            let (start, used) = budget.window();
            shared
                .with_store(true, None, move |s, _| s.set_replicated(start, used))
                .await;
            shared.stats().replicated(&report);
            tracing::debug!("recopie : {report}");
            next = Instant::now() + every;
        }
    };
    tokio::select! {
        () = work => {}
        _ = stop.changed() => {}
    }
}

/// Une passe de recopie sur toutes les boîtes gardées.
pub(crate) async fn pass(
    dht: &Dht,
    shared: &Arc<Shared>,
    budget: &mut ByteBudget,
    now: u64,
) -> PassReport {
    let mut report = PassReport::default();
    let held = match shared
        .with_store(true, None, |s, _| s.held_mailboxes())
        .await
    {
        Stored::Done(h) => h,
        Stored::Busy | Stored::Failed => return report,
    };
    let order = dht.replication_queue().order(held);
    let mut skipped: HashSet<NodeId> = HashSet::new();
    let mut served: HashMap<NodeId, usize> = HashMap::new();
    for mailbox in order {
        let key = mailbox_key(&mailbox);
        // Hors de la fenêtre de responsabilité : plus de recopie, rien
        // n'est effacé (spec §5.3, point 2).
        let Some(mut targets) = dht.table().replica_targets(&key) else {
            dht.replication_queue().mark_done(mailbox);
            continue;
        };
        let items = match shared
            .with_store(true, None, move |s, _| rules::copy_items(s, &mailbox, now))
            .await
        {
            Stored::Done(Ok(items)) => items,
            Stored::Done(Err(_)) | Stored::Busy | Stored::Failed => continue,
        };
        // Un message sans preuve gardée serait refusé (`PowTooWeak`).
        let items: Vec<CopyItem> = items
            .into_iter()
            .filter(|i| i.is_ack || i.pow != 0)
            .collect();
        if items.is_empty() {
            dht.replication_queue().mark_done(mailbox);
            continue;
        }
        report.mailboxes += 1;
        let mut tried: HashSet<NodeId> = HashSet::new();
        let mut complete = true;
        // Un responsable retiré de la table pendant la boîte laisse sa
        // place au suivant, servi dans la même passe.
        for _ in 0..2 {
            let mut evicted = false;
            for peer in targets {
                if !tried.insert(peer) {
                    continue;
                }
                let count = served.entry(peer).or_default();
                if skipped.contains(&peer) || *count >= MAX_MAILBOXES_PER_PEER {
                    complete = false;
                    continue;
                }
                *count += 1;
                match copy_to(dht, peer, mailbox, &items, budget, now, &mut report).await {
                    Outcome::Done => {}
                    Outcome::RateLimited => {
                        skipped.insert(peer);
                        report.skipped_peers += 1;
                        complete = false;
                    }
                    Outcome::Failed => {
                        skipped.insert(peer);
                        report.skipped_peers += 1;
                        complete = false;
                        evicted |= dht.peer_failed(peer).await;
                    }
                    Outcome::Budget => {
                        report.budget_exhausted = true;
                        return report;
                    }
                }
            }
            if !evicted {
                break;
            }
            match dht.table().replica_targets(&key) {
                Some(t) => targets = t,
                None => break,
            }
        }
        if complete {
            dht.replication_queue().mark_done(mailbox);
        }
    }
    report
}

/// Envoie `req` au pair `peer` (adresses de sa fiche dans la table).
async fn call(dht: &Dht, peer: NodeId, req: &Request) -> Option<Response> {
    let addrs = dht.table().get(&peer).map(|p| p.record.addrs())?;
    timeout(CALL_TIMEOUT, dht.pool().request(peer, &addrs, req))
        .await
        .ok()?
        .ok()
}

/// Empreintes que `peer` tient pour `mailbox`, toutes pages lues.
async fn holdings_of(
    dht: &Dht,
    peer: NodeId,
    mailbox: MailboxId,
) -> Result<HashSet<[u8; 32]>, Outcome> {
    let mut have = HashSet::new();
    let mut cursor = None;
    for _ in 0..MAX_HOLDINGS_PAGES {
        let req = Request::FindValue { mailbox, cursor };
        match call(dht, peer, &req).await {
            Some(Response::Holdings { hashes, next }) => {
                if hashes.len() > MAX_HOLDINGS_PER_PAGE {
                    return Err(Outcome::Failed);
                }
                have.extend(hashes);
                match next {
                    None => return Ok(have),
                    // Un curseur qui n'avance pas ne finirait jamais.
                    Some(c) if cursor.is_some_and(|p| c <= p) => return Err(Outcome::Failed),
                    Some(c) => cursor = Some(c),
                }
            }
            Some(Response::Error(ErrorReason::RateLimited)) => return Err(Outcome::RateLimited),
            _ => return Err(Outcome::Failed),
        }
    }
    Err(Outcome::Failed)
}

/// Recopie vers `peer` ce qui lui manque de `items` (accusés d'abord).
async fn copy_to(
    dht: &Dht,
    peer: NodeId,
    mailbox: MailboxId,
    items: &[CopyItem],
    budget: &mut ByteBudget,
    now: u64,
    report: &mut PassReport,
) -> Outcome {
    let have = match holdings_of(dht, peer, mailbox).await {
        Ok(h) => h,
        Err(o) => return o,
    };
    for item in items.iter().filter(|i| !have.contains(&i.hash)) {
        if budget.exhausted(now) {
            return Outcome::Budget;
        }
        let len = item.bytes.len() as u64;
        budget.spend(now, len);
        report.bytes += len;
        let req = Request::Store {
            packet: item.bytes.clone(),
            pow: item.pow,
        };
        match call(dht, peer, &req).await {
            Some(Response::Ok) => report.sent += 1,
            Some(Response::Error(r)) => match r {
                ErrorReason::RateLimited => return Outcome::RateLimited,
                // Tables divergentes : rien d'autre pour ce pair avant la
                // passe suivante.
                ErrorReason::NotResponsible => {
                    report.not_responsible += 1;
                    return Outcome::Done;
                }
                ErrorReason::PowTooWeak => report.pow_too_weak += 1,
                ErrorReason::UnknownAckTarget => report.unknown_ack += 1,
                ErrorReason::MailboxFull | ErrorReason::NodeFull => {
                    report.refused += 1;
                    return Outcome::Done;
                }
                _ => report.refused += 1,
            },
            _ => return Outcome::Failed,
        }
    }
    Outcome::Done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_stops_after_limit_and_rolls_each_hour() {
        const T: u64 = 1_800_000_000;
        let mut b = ByteBudget::new(10);
        assert!(!b.exhausted(T));
        b.spend(T, 7);
        assert!(!b.exhausted(T + 1));
        b.spend(T + 1, 7);
        assert!(b.exhausted(T + 2));
        assert_eq!(b.window(), (T, 14));
        // Une heure après le début de la fenêtre : nouvelle fenêtre.
        assert!(!b.exhausted(T + 3600));
        assert_eq!(b.window(), (T + 3600, 0));
        // Reprise d'une fenêtre enregistrée.
        let mut r = ByteBudget::resume(10, T, 10);
        assert!(r.exhausted(T + 100));
        assert!(!r.exhausted(T + 3600));
    }

    #[test]
    fn queue_orders_queued_then_least_recent() {
        let m = |b: u8| MailboxId([b; 16]);
        let mut q = Queue::default();
        q.mark_done(m(1));
        q.mark_done(m(2));
        q.mark_done(m(3));
        // Jamais traitée d'abord, puis les plus anciennes.
        assert_eq!(
            q.order(vec![m(3), m(2), m(4), m(1)]),
            [m(4), m(1), m(2), m(3)]
        );
        // Une boîte en file passe devant ; la file est vidée.
        assert!(q.enqueue([m(3)]));
        assert!(!q.enqueue([m(3)]));
        assert_eq!(q.order(vec![m(1), m(2), m(3)]), [m(3), m(1), m(2)]);
        assert_eq!(q.order(vec![m(1), m(2), m(3)]), [m(1), m(2), m(3)]);
        // Une boîte qui n'est plus gardée est oubliée.
        assert_eq!(q.order(vec![m(2)]), [m(2)]);
        assert_eq!(q.known(), vec![m(2)]);
    }

    #[test]
    fn report_adds_and_prints_no_identifier() {
        let mut total = PassReport::default();
        let one = PassReport {
            mailboxes: 2,
            sent: 3,
            bytes: 100,
            not_responsible: 1,
            ..PassReport::default()
        };
        total.add(&one);
        total.add(&PassReport {
            budget_exhausted: true,
            ..one.clone()
        });
        assert_eq!((total.mailboxes, total.sent, total.bytes), (4, 6, 200));
        assert!(total.budget_exhausted);
        let line = total.to_string();
        assert!(
            line.contains("NotResponsible=2") && line.contains("plafond"),
            "{line}"
        );
    }
}
