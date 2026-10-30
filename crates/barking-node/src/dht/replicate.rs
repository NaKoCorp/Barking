//! Entretien des copies (spec §5.3) : chaque boîte gardée dont le nœud est
//! responsable est recopiée vers ses autres responsables, calculés dans sa
//! propre table.
//!
//! - **Ordre** : les boîtes mises en file (un nœud est entré parmi leurs 5
//!   plus proches) d'abord, puis celles jamais tentées, puis les moins
//!   récemment tentées. Une boîte tentée passe en fin d'ordre, même si un
//!   responsable l'a refusée : un pair qui refuse toujours ne la garde pas
//!   en tête. Tout cela n'est gardé qu'en mémoire.
//! - **Par responsable** : `FindValue` sur toutes les pages, puis `Store`
//!   de ce qui manque, accusés d'abord. Un message sans preuve gardée (ligne
//!   d'une base migrée, `pow = 0`) n'est pas envoyé : il serait refusé.
//! - **Bornes** : `MAX_MAILBOXES_PER_PEER` boîtes et `PEER_TIME_PER_PASS`
//!   par responsable et par passe ; `replication_bytes_per_hour` octets
//!   envoyés par heure (au-delà la passe s'arrête et reprend à la suivante),
//!   dont au plus un cinquième vers un même responsable.
//! - **Rythme** : au plus 10 requêtes par seconde vers un même responsable
//!   (`PEER_CALL_SPACING`), sous le seau de son groupe d'adresses (spec §5.2
//!   point 2) ; après un `RateLimited`, pause de `RATE_LIMIT_BACKOFF` puis
//!   reprise, dans le temps de la passe.
//! - **Preuve** : un message dont la preuve n'atteint pas la difficulté
//!   annoncée par le responsable (`Hello`) plus le palier ne lui est pas
//!   envoyé (compté `PowTooWeak`).
//! - **Refus et pannes** : la recopie ne compte jamais d'échec dans la
//!   table. Une réponse lisible marque le pair vivant (`mark_alive`).
//!   - Pas de réponse : pair sauté pour la passe, et contrôle de vie
//!     (`Dht::liveness_check`, au plus un par pair et par 10 min) ; c'est ce
//!     contrôle qui compte l'échec. S'il retire le pair, la boîte est
//!     recopiée au suivant dans la même passe.
//!   - Temps de la passe ou part horaire épuisés : pair sauté.
//!   - Réponse hors bornes ou inattendue, flux coupé, `MailboxFull`,
//!     `NodeFull`, `NotResponsible` : la boîte est sautée pour ce pair.
//!   - `PowTooWeak`, `UnknownAckTarget` : comptés, l'élément suivant part.
//! - **Cadence** : toutes les heures ; une boîte mise en file déclenche une
//!   passe 1 min plus tard au plus tôt, limitée aux boîtes en file. Avec
//!   `ServerConfig::dht_tick`, ces délais valent `dht_tick`.
//!
//! Les journaux ne donnent que des compteurs : ni adresse, ni boîte.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use barking_dht::{REPLICAS, distance, mailbox_key};
use barking_packet::MailboxId;
use barking_proto::client::ClientError;
use barking_proto::{ErrorReason, MAX_HOLDINGS_PER_PAGE, NodeId, Request, Response, pow};
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
/// Pages `Holdings` lues au plus par boîte et par responsable : au-delà, la
/// boîte est sautée pour ce pair.
pub const MAX_HOLDINGS_PAGES: usize = 16;
/// Temps passé au plus avec un même responsable dans une passe : au-delà,
/// il est sauté jusqu'à la passe suivante.
pub const PEER_TIME_PER_PASS: Duration = Duration::from_secs(60);
/// Écart minimal entre deux requêtes de recopie vers un même responsable
/// (10 par seconde) : sous le seau du groupe d'adresses de l'appelé (20
/// requêtes/s, spec §5.2 point 2), que partagent aussi l'entretien de la
/// table et un éventuel client sur la même IP.
pub const PEER_CALL_SPACING: Duration = Duration::from_millis(100);
/// Attente après un `RateLimited` avant de reprendre le même responsable.
pub const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(2);
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
    /// `RateLimited` reçus (chacun suivi d'une pause).
    pub rate_limited: usize,
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
        self.rate_limited += other.rate_limited;
        self.budget_exhausted |= other.budget_exhausted;
    }
}

impl fmt::Display for PassReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} boîtes, {} envois acceptés, {} octets, {} pairs sautés, refus : \
             NotResponsible={} PowTooWeak={} UnknownAckTarget={} autres={} RateLimited={}{}",
            self.mailboxes,
            self.sent,
            self.bytes,
            self.skipped_peers,
            self.not_responsible,
            self.pow_too_weak,
            self.unknown_ack,
            self.refused,
            self.rate_limited,
            if self.budget_exhausted {
                ", plafond horaire atteint"
            } else {
                ""
            }
        )
    }
}

/// Plafond d'octets recopiés par fenêtre d'une heure, et part de chaque
/// responsable : `limit / REPLICAS` (au moins 1 octet). Un responsable qui
/// prend tout (`Holdings` vides, `Ok` à chaque `Store`) n'épuise pas le
/// plafond des autres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteBudget {
    limit: u64,
    window_start: u64,
    used: u64,
    /// Octets envoyés à chaque responsable dans la fenêtre (mémoire seule).
    per_peer: HashMap<NodeId, u64>,
}

impl ByteBudget {
    pub fn new(limit: u64) -> ByteBudget {
        ByteBudget::resume(limit, 0, 0)
    }

    /// Reprend une fenêtre enregistrée (redémarrage dans l'heure).
    pub fn resume(limit: u64, window_start: u64, used: u64) -> ByteBudget {
        ByteBudget {
            limit,
            window_start,
            used,
            per_peer: HashMap::new(),
        }
    }

    fn roll(&mut self, now: u64) {
        if now.saturating_sub(self.window_start) >= BUDGET_WINDOW_SECS {
            self.window_start = now;
            self.used = 0;
            self.per_peer.clear();
        }
    }

    /// Part horaire d'un responsable.
    pub fn peer_share(&self) -> u64 {
        (self.limit / REPLICAS as u64).max(1)
    }

    /// Vrai si le plafond de la fenêtre courante est atteint.
    pub fn exhausted(&mut self, now: u64) -> bool {
        self.roll(now);
        self.used >= self.limit
    }

    /// Vrai si la part de `peer` dans la fenêtre courante est atteinte.
    pub fn peer_exhausted(&mut self, now: u64, peer: &NodeId) -> bool {
        self.roll(now);
        self.per_peer.get(peer).copied().unwrap_or(0) >= self.peer_share()
    }

    /// Compte `n` octets envoyés à `peer`.
    pub fn spend(&mut self, now: u64, peer: NodeId, n: u64) {
        self.roll(now);
        self.used = self.used.saturating_add(n);
        let p = self.per_peer.entry(peer).or_default();
        *p = p.saturating_add(n);
    }

    /// (début de la fenêtre, octets envoyés dans la fenêtre).
    pub fn window(&self) -> (u64, u64) {
        (self.window_start, self.used)
    }
}

/// Distance « infinie » : moins de `REPLICAS` responsables connus, tout
/// nouveau venu en devient un.
const FAR: [u8; 32] = [0xff; 32];

/// Une boîte gardée, en mémoire.
struct Entry {
    key: [u8; 32],
    /// Numéro de la dernière tentative, 0 si jamais tentée.
    seq: u64,
    /// Distance à la clé du plus loin de ses responsables (nous compris) à
    /// la dernière passe ; `None` si nous n'en sommes pas responsables. Un
    /// nouveau venu plus proche entre parmi eux.
    bound: Option<[u8; 32]>,
}

/// Ordre et file des boîtes, en mémoire seulement.
#[derive(Default)]
pub(crate) struct Queue {
    /// Numéro croissant de tentative.
    seq: u64,
    boxes: HashMap<MailboxId, Entry>,
    /// Boîtes à traiter en premier.
    queued: HashSet<MailboxId>,
}

impl Queue {
    /// Boîtes à traiter, avec leur clé, dans l'ordre : en file, puis jamais
    /// tentées, puis les moins récemment tentées. `queued_only` : seulement
    /// celles en file. Oublie les boîtes qui ne sont plus gardées et vide la
    /// file.
    fn order(&mut self, held: Vec<MailboxId>, queued_only: bool) -> Vec<(MailboxId, [u8; 32])> {
        let keep: HashSet<MailboxId> = held.iter().copied().collect();
        self.boxes.retain(|m, _| keep.contains(m));
        let queued = std::mem::take(&mut self.queued);
        let mut order: Vec<(bool, u64, MailboxId, [u8; 32])> = held
            .into_iter()
            .filter(|m| !queued_only || queued.contains(m))
            .map(|m| {
                let e = self.boxes.entry(m).or_insert_with(|| Entry {
                    key: mailbox_key(&m),
                    seq: 0,
                    bound: None,
                });
                (!queued.contains(&m), e.seq, m, e.key)
            })
            .collect();
        order.sort_by_key(|(q, seq, _, _)| (*q, *seq));
        order.into_iter().map(|(_, _, m, k)| (m, k)).collect()
    }

    /// La boîte a été tentée : elle passe en fin d'ordre.
    fn attempted(&mut self, m: &MailboxId) {
        self.seq += 1;
        if let Some(e) = self.boxes.get_mut(m) {
            e.seq = self.seq;
        }
    }

    fn set_bound(&mut self, m: &MailboxId, bound: Option<[u8; 32]>) {
        if let Some(e) = self.boxes.get_mut(m) {
            e.bound = bound;
        }
    }

    /// Met en file les boîtes dont `id` entre parmi les responsables, sans
    /// consulter la table ; vrai si la file en a gagné.
    pub(crate) fn enqueue_near(&mut self, id: &NodeId) -> bool {
        let before = self.queued.len();
        for (m, e) in &self.boxes {
            if e.bound.is_some_and(|b| distance(&id.0, &e.key) < b) {
                self.queued.insert(*m);
            }
        }
        self.queued.len() > before
    }
}

/// Distance à `key` du plus loin des responsables `targets` (nous compris
/// si nous en sommes) ; `FAR` s'il y en a moins de `REPLICAS`.
fn replica_bound(own: &NodeId, key: &[u8; 32], targets: &[NodeId]) -> [u8; 32] {
    let far = targets.iter().map(|t| distance(&t.0, key)).max();
    match targets.len() {
        n if n >= REPLICAS => far.unwrap_or(FAR),
        n if n + 1 == REPLICAS => far.unwrap_or(FAR).max(distance(&own.0, key)),
        _ => FAR,
    }
}

/// Issue de la recopie d'une boîte vers un responsable.
enum Outcome {
    Done,
    /// Pas de réponse (délai, connexion impossible ou perdue) : pair sauté
    /// pour la passe, contrôle de vie demandé.
    NoAnswer,
    /// Temps de la passe ou part horaire d'octets épuisés pour ce pair :
    /// sauté.
    Skip,
    /// Plafond horaire atteint : fin de la passe.
    Budget,
}

/// Réponse d'un appel.
enum Call {
    Answer(Response),
    /// Délai dépassé, connexion impossible ou perdue.
    NoAnswer,
    /// Réponse illisible ou flux coupé par le pair : il répond, mais pas à
    /// cette requête.
    Broken,
}

/// Bilan par pair dans une passe.
#[derive(Default)]
struct PeerPass {
    mailboxes: usize,
    spent: Duration,
    skipped: bool,
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
            // Passe complète à l'échéance ; une mise en file ne fait traiter
            // que les boîtes en file.
            let queued_only = tokio::select! {
                () = sleep_until(next) => false,
                () = dht.replication_wake().notified() => {
                    sleep(delay).await;
                    true
                }
            };
            let report = pass(&dht, &shared, &mut budget, unix_now(), queued_only).await;
            let (start, used) = budget.window();
            shared
                .with_store(true, None, move |s, _| s.set_replicated(start, used))
                .await;
            shared.stats().replicated(&report);
            tracing::debug!("recopie : {report}");
            if !queued_only {
                next = Instant::now() + every;
            }
        }
    };
    tokio::select! {
        () = work => {}
        _ = stop.changed() => {}
    }
}

/// Une passe de recopie sur les boîtes gardées (`queued_only` : celles en
/// file seulement).
pub(crate) async fn pass(
    dht: &Arc<Dht>,
    shared: &Arc<Shared>,
    budget: &mut ByteBudget,
    now: u64,
    queued_only: bool,
) -> PassReport {
    let mut report = PassReport::default();
    let held = match shared
        .with_store(true, None, |s, _| s.held_mailboxes())
        .await
    {
        Stored::Done(h) => h,
        Stored::Busy | Stored::Failed => return report,
    };
    let order = dht.replication_queue().order(held, queued_only);
    let own = dht.id();
    let mut peers: HashMap<NodeId, PeerPass> = HashMap::new();
    for (mailbox, key) in order {
        // Hors de la fenêtre de responsabilité : plus de recopie, rien
        // n'est effacé (spec §5.3, point 2).
        let Some(mut targets) = dht.table().replica_targets(&key) else {
            let mut q = dht.replication_queue();
            q.set_bound(&mailbox, None);
            q.attempted(&mailbox);
            continue;
        };
        dht.replication_queue()
            .set_bound(&mailbox, Some(replica_bound(&own, &key, &targets)));
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
            dht.replication_queue().attempted(&mailbox);
            continue;
        }
        report.mailboxes += 1;
        let mut tried: HashSet<NodeId> = HashSet::new();
        let mut attempted = false;
        // Un responsable retiré de la table par son contrôle de vie laisse
        // sa place au suivant, servi dans la même passe.
        for _ in 0..2 {
            let mut evicted = false;
            for peer in targets {
                if !tried.insert(peer) {
                    continue;
                }
                let st = peers.entry(peer).or_default();
                if st.skipped || st.mailboxes >= MAX_MAILBOXES_PER_PEER {
                    continue;
                }
                let Some(left) = PEER_TIME_PER_PASS.checked_sub(st.spent) else {
                    st.skipped = true;
                    report.skipped_peers += 1;
                    continue;
                };
                st.mailboxes += 1;
                attempted = true;
                let started = Instant::now();
                let outcome = timeout(
                    left,
                    copy_to(dht, peer, mailbox, &items, budget, now, &mut report),
                )
                .await
                .unwrap_or(Outcome::Skip);
                let gone = match outcome {
                    Outcome::Done => false,
                    Outcome::Skip => {
                        st.skipped = true;
                        report.skipped_peers += 1;
                        false
                    }
                    Outcome::NoAnswer => {
                        st.skipped = true;
                        report.skipped_peers += 1;
                        !dht.liveness_check(peer).await
                    }
                    Outcome::Budget => {
                        report.budget_exhausted = true;
                        dht.replication_queue().attempted(&mailbox);
                        return report;
                    }
                };
                st.spent += started.elapsed();
                evicted |= gone;
            }
            if !evicted {
                break;
            }
            match dht.table().replica_targets(&key) {
                Some(t) => targets = t,
                None => break,
            }
            dht.replication_queue()
                .set_bound(&mailbox, Some(replica_bound(&own, &key, &targets)));
        }
        if attempted {
            dht.replication_queue().attempted(&mailbox);
        }
    }
    report
}

/// Envoie `req` au pair `peer` (adresses de sa fiche dans la table), au
/// rythme de `PEER_CALL_SPACING`. Après un `RateLimited`, attend
/// `RATE_LIMIT_BACKOFF` et réessaie : seul le temps de la passe pour ce
/// pair borne l'attente. Une réponse lisible le marque vivant dans la table.
async fn call(dht: &Dht, peer: NodeId, req: &Request, report: &mut PassReport) -> Call {
    loop {
        sleep_until(dht.replication_slot(peer, PEER_CALL_SPACING)).await;
        match call_once(dht, peer, req).await {
            Call::Answer(Response::Error(ErrorReason::RateLimited)) => {
                report.rate_limited += 1;
                sleep(RATE_LIMIT_BACKOFF).await;
            }
            other => return other,
        }
    }
}

async fn call_once(dht: &Dht, peer: NodeId, req: &Request) -> Call {
    let Some(addrs) = dht.table().get(&peer).map(|p| p.record.addrs()) else {
        return Call::NoAnswer;
    };
    match timeout(CALL_TIMEOUT, dht.pool().request(peer, &addrs, req)).await {
        Ok(Ok(resp)) => {
            dht.table().mark_alive(&peer, unix_now());
            Call::Answer(resp)
        }
        Ok(Err(ClientError::Connect(_) | ClientError::Connection(_) | ClientError::Timeout))
        | Err(_) => Call::NoAnswer,
        Ok(Err(_)) => Call::Broken,
    }
}

/// Difficulté de base annoncée par `peer` dans `Hello`, si une connexion
/// vers lui est gardée.
fn peer_pow_bits(dht: &Dht, peer: NodeId) -> Option<u8> {
    let addrs = dht.table().get(&peer).map(|p| p.record.addrs())?;
    dht.pool().pow_bits(peer, &addrs)
}

/// Empreintes que `peer` tient pour `mailbox`, toutes pages lues. Une
/// réponse hors bornes (page trop longue, curseur qui n'avance pas, plus
/// de `MAX_HOLDINGS_PAGES` pages) ou inattendue fait sauter la boîte pour
/// ce pair (`Err(Outcome::Done)`), sans rien compter contre lui.
async fn holdings_of(
    dht: &Dht,
    peer: NodeId,
    mailbox: MailboxId,
    report: &mut PassReport,
) -> Result<HashSet<[u8; 32]>, Outcome> {
    let mut have = HashSet::new();
    let mut cursor = None;
    for _ in 0..MAX_HOLDINGS_PAGES {
        let req = Request::FindValue { mailbox, cursor };
        match call(dht, peer, &req, report).await {
            Call::Answer(Response::Holdings { hashes, next })
                if hashes.len() <= MAX_HOLDINGS_PER_PAGE =>
            {
                have.extend(hashes);
                match next {
                    None => return Ok(have),
                    Some(c) if cursor.is_some_and(|p| c <= p) => break,
                    Some(c) => cursor = Some(c),
                }
            }
            Call::NoAnswer => return Err(Outcome::NoAnswer),
            Call::Answer(_) | Call::Broken => break,
        }
    }
    report.refused += 1;
    Err(Outcome::Done)
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
    let have = match holdings_of(dht, peer, mailbox, report).await {
        Ok(h) => h,
        Err(o) => return o,
    };
    // Difficulté du pair (`Hello`) : un message dont la preuve ne l'atteint
    // pas serait refusé (`PowTooWeak`) à chaque passe, il n'est pas envoyé.
    let peer_bits = peer_pow_bits(dht, peer);
    for item in items.iter().filter(|i| !have.contains(&i.hash)) {
        if let Some(bits) = peer_bits
            && !item.is_ack
            && !pow::check(
                &item.hash,
                &mailbox,
                item.pow,
                rules::copy_pow_bits(bits, item.tier),
            )
        {
            report.pow_too_weak += 1;
            continue;
        }
        if budget.exhausted(now) {
            return Outcome::Budget;
        }
        if budget.peer_exhausted(now, &peer) {
            return Outcome::Skip;
        }
        let len = item.bytes.len() as u64;
        budget.spend(now, peer, len);
        report.bytes += len;
        let req = Request::Store {
            packet: item.bytes.clone(),
            pow: item.pow,
        };
        match call(dht, peer, &req, report).await {
            Call::Answer(Response::Ok) => report.sent += 1,
            Call::Answer(Response::Error(r)) => match r {
                // Tables divergentes : rien d'autre pour ce pair avant la
                // passe suivante.
                ErrorReason::NotResponsible => {
                    report.not_responsible += 1;
                    return Outcome::Done;
                }
                ErrorReason::PowTooWeak => report.pow_too_weak += 1,
                ErrorReason::UnknownAckTarget => report.unknown_ack += 1,
                _ => {
                    report.refused += 1;
                    return Outcome::Done;
                }
            },
            Call::NoAnswer => return Outcome::NoAnswer,
            // Réponse inattendue ou flux coupé : la boîte est sautée.
            Call::Answer(_) | Call::Broken => {
                report.refused += 1;
                return Outcome::Done;
            }
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
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let mut bud = ByteBudget::new(10);
        assert!(!bud.exhausted(T));
        bud.spend(T, a, 7);
        assert!(!bud.exhausted(T + 1));
        bud.spend(T + 1, b, 7);
        assert!(bud.exhausted(T + 2));
        assert_eq!(bud.window(), (T, 14));
        // Une heure après le début de la fenêtre : nouvelle fenêtre.
        assert!(!bud.exhausted(T + 3600));
        assert_eq!(bud.window(), (T + 3600, 0));
        assert!(!bud.peer_exhausted(T + 3600, &a));
        // Reprise d'une fenêtre enregistrée.
        let mut r = ByteBudget::resume(10, T, 10);
        assert!(r.exhausted(T + 100));
        assert!(!r.exhausted(T + 3600));
    }

    #[test]
    fn one_peer_cannot_take_the_whole_budget() {
        const T: u64 = 1_800_000_000;
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let mut bud = ByteBudget::new(1000);
        assert_eq!(bud.peer_share(), 200);
        bud.spend(T, a, 150);
        assert!(!bud.peer_exhausted(T, &a));
        bud.spend(T, a, 50);
        // `a` a pris sa part ; `b` et le plafond global restent ouverts.
        assert!(bud.peer_exhausted(T, &a));
        assert!(!bud.peer_exhausted(T, &b));
        assert!(!bud.exhausted(T));
        // Plafond minuscule : au moins un octet par responsable.
        assert_eq!(ByteBudget::new(1).peer_share(), 1);
    }

    #[test]
    fn queue_orders_queued_then_least_recent() {
        let m = |b: u8| MailboxId([b; 16]);
        let ids = |v: Vec<(MailboxId, [u8; 32])>| v.into_iter().map(|(m, _)| m).collect::<Vec<_>>();
        let mut q = Queue::default();
        q.order(vec![m(1), m(2), m(3)], false);
        q.attempted(&m(1));
        q.attempted(&m(2));
        q.attempted(&m(3));
        // Jamais tentée d'abord, puis les moins récemment tentées ; la clé
        // de chaque boîte est jointe.
        let order = q.order(vec![m(3), m(2), m(4), m(1)], false);
        assert_eq!(order[0].1, mailbox_key(&m(4)));
        assert_eq!(ids(order), [m(4), m(1), m(2), m(3)]);
        // Une boîte tentée, même refusée, passe en fin d'ordre.
        q.attempted(&m(4));
        q.attempted(&m(1));
        assert_eq!(
            ids(q.order(vec![m(1), m(2), m(3), m(4)], false)),
            [m(2), m(3), m(4), m(1)]
        );
        // Mise en file d'après la borne : seul un nœud plus proche de la clé
        // que le plus loin des responsables la fait entrer.
        let key = mailbox_key(&m(2));
        let mut bound = key;
        bound[0] ^= 0x10;
        let bound = distance(&key, &bound);
        q.set_bound(&m(2), Some(bound));
        let mut far = key;
        far[0] ^= 0x80;
        assert!(!q.enqueue_near(&NodeId(far)));
        let mut near = key;
        near[31] ^= 1;
        assert!(q.enqueue_near(&NodeId(near)));
        assert!(!q.enqueue_near(&NodeId(near)));
        // Sans borne (pas responsable) : jamais en file.
        q.set_bound(&m(3), None);
        assert!(!q.enqueue_near(&NodeId(mailbox_key(&m(3)))));
        // Passe limitée à la file, qui est ensuite vidée.
        assert_eq!(ids(q.order(vec![m(1), m(2), m(3)], true)), [m(2)]);
        assert!(q.order(vec![m(1), m(2), m(3)], true).is_empty());
        // Une boîte qui n'est plus gardée est oubliée.
        assert_eq!(ids(q.order(vec![m(2)], false)), [m(2)]);
        assert_eq!(q.boxes.len(), 1);
    }

    #[test]
    fn replica_bound_is_farthest_responsible() {
        let key = [0u8; 32];
        let id = |b: u8| {
            let mut x = [0u8; 32];
            x[0] = b;
            NodeId(x)
        };
        let d = |n: &NodeId| distance(&n.0, &key);
        let targets: Vec<NodeId> = (1..=5).map(id).collect();
        // Cinq responsables autres que nous : le plus loin d'entre eux.
        assert_eq!(replica_bound(&id(9), &key, &targets), d(&id(5)));
        // Quatre : nous en sommes, le plus loin des cinq.
        assert_eq!(replica_bound(&id(9), &key, &targets[..4]), d(&id(9)));
        assert_eq!(replica_bound(&id(0), &key, &targets[..4]), d(&id(4)));
        // Moins : tout nouveau venu entre.
        assert_eq!(replica_bound(&id(9), &key, &targets[..2]), FAR);
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
