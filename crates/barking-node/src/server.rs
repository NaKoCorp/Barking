//! Serveur QUIC du nœud (spec §3.2, §4, §5) : coquille réseau autour des
//! règles de `rules`.
//!
//! Choix documentés :
//! - **Base de données** : un seul `NodeStore` derrière un `Mutex`, chaque
//!   opération dans `spawn_blocking`. Écritures (et lectures) sérialisées sur
//!   une seule connexion SQLite : pas de course entre la vérification des
//!   quotas et l'insertion. La file est bornée : au plus `max_db_jobs` (64)
//!   opérations en cours ou en attente, `max(1, max_db_jobs / 16)` par
//!   groupe d'adresses (/64, /32) et `max(1, max_db_jobs / 8)` par /48 ou /24 ; au-delà `RateLimited`. Un dépôt passe d'abord
//!   `rules::precheck` (forme, expiration, preuve minimale) sans prendre de
//!   place. Le jeton est
//!   tenu par la tâche bloquante elle-même : abandonner la requête ne libère
//!   la place qu'une fois le travail fini.
//! - **Mémoire des réponses** : chaque requête réserve d'avance la taille
//!   maximale de sa réponse (pour `Fetch` : la page demandée par le client,
//!   entre 16 Kio et ~1 Mio, plus la marge d'encodage), ramenée ensuite à la
//!   taille encodée. Trois plafonds : une page par connexion (1 Mio), 1/16 du
//!   budget global par groupe d'adresses (`max_response_bytes_per_ip`, 4 Mio)
//!   et le budget global (`max_response_bytes_in_flight`, 64 Mio). Plafond
//!   atteint : `RateLimited`. La réserve est rendue quand le pair a acquitté
//!   toute la réponse, ou à l'échéance d'écriture (flux alors réinitialisé) :
//!   `request_timeout + taille / min_send_rate` (32 Kio/s), au plus 60 s.
//!   Mémoire réelle : environ deux fois le budget (éléments lus de la base,
//!   corps encodé, puis copie tenue par quinn jusqu'à l'acquittement).
//! - **Tâches** : les flux d'une connexion vivent dans un `JoinSet` de la
//!   connexion ; la place du limiteur n'est rendue qu'après leur fin
//!   (abandonnées à la fermeture).
//! - **Adresses** : une connexion n'est acceptée qu'après validation de
//!   l'adresse (jeton QUIC `Retry`), pour qu'une adresse usurpée ne réserve
//!   pas de place dans le limiteur. Le limiteur regroupe par IP (/64 en IPv6)
//!   avec des plafonds par /56, /48 et /24, en mémoire seulement ; aucune
//!   adresse n'est journalisée. Une connexion évincée (table pleine) est
//!   fermée avec le code `CLOSE_EVICTED`.
//! - **Délais** : poignée de main et `Hello` sous `hello_timeout` (5 s) ;
//!   connexion fermée sans nouvelle requête pendant `idle_timeout` (60 s, aussi
//!   le délai d'inactivité QUIC) ; lecture d'une requête sous
//!   `request_timeout` (10 s).
//! - **Flux** : au plus `max_streams` (4) flux bidirectionnels simultanés par
//!   connexion, aucun flux unidirectionnel ; fenêtres de réception (256 Kio)
//!   et d'envoi (2 Mio) réduites : mémoire bornée par connexion.
//! - **Trames** : une trame trop grande, tronquée ou trop lente ferme le flux
//!   sans réponse ; un corps illisible reçoit `Error(Malformed)`.
//! - **Débit** : chaque requête après `Hello` passe par le seau de jetons de son
//!   groupe d'adresses (`RateLimited` sinon ; une relève coûte `fetch_cost`) ;
//!   les octets de chaque réponse y sont
//!   débités qu'elle soit acquittée, coupée, arrêtée par le pair ou expirée.
//!   Après `MAX_CONSECUTIVE_REFUSALS` (20) refus de débit d'affilée, la
//!   connexion est fermée.
//! - **Purge** des expirés au démarrage puis toutes les 60 s.
//! - **Table de hachage** (`[dht]`, spec §3.3, §4) : l'identifiant d'un
//!   appelant qui présente un certificat de nœud est lu une fois par
//!   connexion et passé aux requêtes de la table (`dht`). Sans `[dht]`, elles
//!   reçoivent `Unsupported` et aucune tâche de la table ne démarre. Avec
//!   elle, deux tâches de fond : entretien de la table (`dht::maintain`) et
//!   recopie entre responsables (`dht::replicate`).

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_dht::DiversityLimits;
use barking_packet::Tier;
use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::{
    ErrorReason, Limits, MAX_HOLDINGS_PER_PAGE, NodeId, PROTOCOL_VERSION, Request, Response, tls,
};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::config::DhtConfig;
use crate::dht::replicate::{self, PassReport};
use crate::dht::{Dht, maintain};
use crate::limits::{ConnectionSlot, GroupDbJob, LimitConfig, Limiter};
use crate::rules::{self, MAX_MAILBOXES_PER_FETCH, Policy};
use crate::store::NodeStore;
use crate::{Error, Result};

/// Intervalle de purge des expirés.
pub const PURGE_INTERVAL: Duration = Duration::from_secs(60);
/// Octets de paquets par page de relève : la marge laisse la place à
/// l'encodage de la réponse (longueurs, curseur) sous `MAX_RESPONSE_BYTES`.
pub const FETCH_PAGE_BYTES: usize = MAX_RESPONSE_BYTES - 32 * 1024;
/// Fenêtre de réception par flux : une requête fait au plus 64 Kio.
const STREAM_WINDOW: u32 = 2 * MAX_REQUEST_BYTES as u32;
/// Octets de réponses non acquittés par connexion.
const SEND_WINDOW: u64 = 2 * MAX_RESPONSE_BYTES as u64;

/// Marge d'encodage d'une page (longueurs des éléments, curseur, en-tête).
const PAGE_OVERHEAD: usize = 8 * 1024;
/// Échéance d'écriture maximale d'une réponse.
pub const MAX_WRITE_DEADLINE: Duration = Duration::from_secs(60);
/// Réserve de réponse d'une requête autre que `Fetch`, `FindNode` et
/// `FindValue`.
const SMALL_RESPONSE_BYTES: usize = 4 * 1024;
/// Réserve d'une réponse `Nodes` (20 fiches de moins de 200 octets).
const NODES_RESPONSE_BYTES: usize = 8 * 1024;
/// Réserve d'une page `Holdings` : 1 024 empreintes et la marge d'encodage.
const HOLDINGS_RESPONSE_BYTES: usize = MAX_HOLDINGS_PER_PAGE * 32 + 1024;
/// Refus de débit consécutifs avant fermeture de la connexion.
pub const MAX_CONSECUTIVE_REFUSALS: u32 = 20;

/// Valeurs par défaut de la spec (reprises par la configuration).
pub const DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT: usize = 64 << 20;
pub const DEFAULT_MAX_RESPONSE_BYTES_PER_IP: usize = 4 << 20;
pub const DEFAULT_MIN_SEND_RATE: u64 = 32 * 1024;
pub const DEFAULT_MAX_DB_JOBS: usize = 64;

/// Codes de fermeture (application).
const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_IDLE: u32 = 2;
const CLOSE_ABUSE: u32 = 3;
const CLOSE_EVICTED: u32 = 4;
const STREAM_REFUSED: u32 = 1;

pub struct ServerConfig {
    /// Sockets UDP déjà liés (une par adresse d'écoute).
    pub sockets: Vec<UdpSocket>,
    /// Clé d'identité du nœud.
    pub key: SigningKey,
    pub limits: LimitConfig,
    pub hello_timeout: Duration,
    pub idle_timeout: Duration,
    pub request_timeout: Duration,
    pub max_streams: u32,
    /// Octets de réponses en vol (réservés, non acquittés), tous pairs confondus.
    pub max_response_bytes_in_flight: usize,
    /// Octets de réponses en vol par groupe d'adresses (/64 en IPv6).
    pub max_response_bytes_per_ip: usize,
    /// Débit minimal attendu d'un lecteur : allonge l'échéance d'écriture
    /// d'une réponse de `taille / min_send_rate`.
    pub min_send_rate: u64,
    /// Opérations de base en cours ou en attente, tous pairs confondus.
    pub max_db_jobs: usize,
    /// Part d'un /48 ou /24 ; `None` : `max_db_jobs / 8` (au moins 1). Celle
    /// d'un /64 ou /32 vaut `max_db_jobs / 16` (au moins 1).
    pub max_db_jobs_per_prefix: Option<usize>,
    /// Versions du protocole servies : `min_version..=version`.
    pub version: u16,
    pub min_version: u16,
    /// Jauges observables (tests, journaux agrégés).
    pub stats: Arc<ServerStats>,
    /// Table de hachage entre nœuds ; `None` : désactivée.
    pub dht: Option<DhtConfig>,
    /// Tests : ramène toutes les cadences d'entretien de la table et de la
    /// recopie à cette période. `None` : valeurs de la spec.
    pub dht_tick: Option<Duration>,
    /// Tests seulement, jamais lu de la configuration : limites de diversité
    /// des adresses de la table. Défaut : celles de la spec. Les tests réseau
    /// les lèvent, tous leurs nœuds partageant le /24 de 127.0.0.1.
    pub dht_diversity: DiversityLimits,
}

/// Jauge : valeur courante et maximum atteint.
#[derive(Debug, Default)]
pub struct Gauge {
    now: AtomicUsize,
    peak: AtomicUsize,
}

impl Gauge {
    pub fn now(&self) -> usize {
        self.now.load(Ordering::Relaxed)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Maximum atteint depuis le dernier appel, puis remise du pic à la valeur
    /// courante (rapports périodiques).
    pub fn take_peak(&self) -> usize {
        self.peak
            .swap(self.now.load(Ordering::Relaxed), Ordering::Relaxed)
    }

    fn add(&self, n: usize) {
        let v = self.now.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(v, Ordering::Relaxed);
    }

    fn sub(&self, n: usize) {
        self.now.fetch_sub(n, Ordering::Relaxed);
    }
}

/// Jauges du serveur (aucune donnée par pair).
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Opérations de base en cours ou en attente.
    pub db_jobs: Gauge,
    /// Octets de réponses réservés.
    pub response_bytes: Gauge,
    /// Connexions ouvertes.
    pub connections: Gauge,
    /// Dépôts acceptés (cumul depuis le dernier `drain`).
    deposits_ok: AtomicU64,
    /// Relèves servies.
    fetches: AtomicU64,
    /// Lignes expirées purgées.
    purged: AtomicU64,
    /// Refus par raison (indice : `reason_index`).
    refusals: [AtomicU64; REASONS.len()],
    /// Recopie : depuis le démarrage, et depuis le dernier `drain`.
    replication: Mutex<ReplicationStats>,
    replication_period: Mutex<ReplicationStats>,
}

/// Numéros des dernières passes qui ont recopié quelque chose, gardés.
const SENDING_PASSES_KEPT: usize = 64;

/// Passes de recopie : nombre, somme des bilans et dernier bilan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationStats {
    pub passes: u64,
    pub total: PassReport,
    pub last: Option<PassReport>,
    /// Numéros (1, 2…) des `SENDING_PASSES_KEPT` dernières passes dont au
    /// moins un envoi a été accepté.
    pub sending_passes: VecDeque<u64>,
}

impl ReplicationStats {
    fn record(&mut self, r: &PassReport) {
        self.passes += 1;
        self.total.add(r);
        self.last = Some(r.clone());
        if r.sent > 0 {
            if self.sending_passes.len() >= SENDING_PASSES_KEPT {
                self.sending_passes.pop_front();
            }
            self.sending_passes.push_back(self.passes);
        }
    }
}

/// Raisons d'erreur, dans l'ordre de `reason_index`.
const REASONS: [ErrorReason; 13] = [
    ErrorReason::VersionTooOld,
    ErrorReason::Malformed,
    ErrorReason::Expired,
    ErrorReason::TooFarInFuture,
    ErrorReason::WrongTier,
    ErrorReason::PowTooWeak,
    ErrorReason::UnknownAckTarget,
    ErrorReason::MailboxFull,
    ErrorReason::NodeFull,
    ErrorReason::RateLimited,
    ErrorReason::TooManyMailboxes,
    ErrorReason::Unsupported,
    ErrorReason::NotResponsible,
];

fn reason_index(r: ErrorReason) -> usize {
    // Sans joker : une nouvelle raison fait échouer la compilation ici.
    match r {
        ErrorReason::VersionTooOld => 0,
        ErrorReason::Malformed => 1,
        ErrorReason::Expired => 2,
        ErrorReason::TooFarInFuture => 3,
        ErrorReason::WrongTier => 4,
        ErrorReason::PowTooWeak => 5,
        ErrorReason::UnknownAckTarget => 6,
        ErrorReason::MailboxFull => 7,
        ErrorReason::NodeFull => 8,
        ErrorReason::RateLimited => 9,
        ErrorReason::TooManyMailboxes => 10,
        ErrorReason::Unsupported => 11,
        ErrorReason::NotResponsible => 12,
    }
}

impl ServerStats {
    /// Compte un refus (jamais d'adresse, de boîte ni d'identifiant de paquet).
    pub fn refuse(&self, reason: ErrorReason) {
        self.refusals[reason_index(reason)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn deposit_ok(&self) {
        self.deposits_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fetch_served(&self) {
        self.fetches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn purged(&self, n: usize) {
        self.purged.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Compte une passe de recopie.
    pub fn replicated(&self, r: &PassReport) {
        for m in [&self.replication, &self.replication_period] {
            m.lock().unwrap_or_else(PoisonError::into_inner).record(r);
        }
    }

    /// Passes de recopie depuis le démarrage.
    pub fn replication(&self) -> ReplicationStats {
        self.replication
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Relève les compteurs depuis le dernier appel (remis à zéro, pics
    /// ramenés à la valeur courante) : un rapport par période.
    pub fn drain(&self) -> Report {
        let take = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        Report {
            deposits_ok: take(&self.deposits_ok),
            fetches: take(&self.fetches),
            purged: take(&self.purged),
            refusals: REASONS
                .iter()
                .map(|r| (*r, take(&self.refusals[reason_index(*r)])))
                .filter(|(_, n)| *n > 0)
                .collect(),
            connections: self.connections.now(),
            connections_peak: self.connections.take_peak(),
            db_jobs_peak: self.db_jobs.take_peak(),
            response_bytes_peak: self.response_bytes.take_peak(),
            replication: std::mem::take(
                &mut *self
                    .replication_period
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
            ),
        }
    }
}

/// Compteurs agrégés d'une période (aucune donnée par pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub deposits_ok: u64,
    pub fetches: u64,
    pub purged: u64,
    /// Refus par raison (raisons nulles omises).
    pub refusals: Vec<(ErrorReason, u64)>,
    pub connections: usize,
    pub connections_peak: usize,
    pub db_jobs_peak: usize,
    pub response_bytes_peak: usize,
    /// Passes de recopie de la période (`last` : la dernière).
    pub replication: ReplicationStats,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dépôts acceptés : {}, relèves : {}, expirés purgés : {}, refus : ",
            self.deposits_ok, self.fetches, self.purged
        )?;
        if self.refusals.is_empty() {
            f.write_str("aucun")?;
        }
        for (i, (r, n)) in self.refusals.iter().enumerate() {
            write!(f, "{}{r:?}={n}", if i == 0 { "" } else { ", " })?;
        }
        write!(
            f,
            ", connexions ouvertes : {} (pic {}), pic d'opérations de base : {}, pic d'octets de réponse : {}",
            self.connections, self.connections_peak, self.db_jobs_peak, self.response_bytes_peak
        )?;
        if self.replication.passes > 0 {
            write!(
                f,
                ", recopie : {} passes, {}",
                self.replication.passes, self.replication.total
            )?;
        }
        Ok(())
    }
}

/// Journalise un rapport agrégé à chaque période (aucune adresse).
pub async fn report_loop(stats: Arc<ServerStats>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tick.tick().await;
        tracing::info!("{}", stats.drain());
    }
}

/// Budget global à jetons, reflété dans une jauge.
struct Budget {
    sem: Arc<Semaphore>,
    stats: Arc<ServerStats>,
    gauge: fn(&ServerStats) -> &Gauge,
}

impl Budget {
    fn new(cap: usize, stats: Arc<ServerStats>, gauge: fn(&ServerStats) -> &Gauge) -> Arc<Budget> {
        Arc::new(Budget {
            sem: Arc::new(Semaphore::new(cap)),
            stats,
            gauge,
        })
    }

    fn gauge(&self) -> &Gauge {
        (self.gauge)(&self.stats)
    }

    fn held(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> Held {
        self.gauge().add(permit.num_permits());
        Held {
            budget: Arc::clone(self),
            permit: Some(permit),
        }
    }

    /// Réserve `n` jetons sans attendre.
    fn try_take(self: &Arc<Self>, n: usize) -> Option<Held> {
        let n = u32::try_from(n).ok()?;
        let permit = Arc::clone(&self.sem).try_acquire_many_owned(n).ok()?;
        Some(self.held(permit))
    }

    /// Réserve `n` jetons en attendant (tâches internes).
    async fn take(self: &Arc<Self>, n: u32) -> Option<Held> {
        let permit = Arc::clone(&self.sem).acquire_many_owned(n).await.ok()?;
        Some(self.held(permit))
    }
}

/// Jetons réservés, rendus à la destruction.
struct Held {
    budget: Arc<Budget>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Held {
    /// Ramène la réserve à `keep` jetons.
    fn shrink(&mut self, keep: usize) {
        if let Some(p) = self.permit.as_mut() {
            let extra = p.num_permits().saturating_sub(keep);
            if let Some(e) = p.split(extra) {
                // Jauge décrémentée avant que les jetons redeviennent libres.
                self.budget.gauge().sub(e.num_permits());
                drop(e);
            }
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(p) = self.permit.take() {
            self.budget.gauge().sub(p.num_permits());
            drop(p);
        }
    }
}

impl ServerConfig {
    /// Valeurs de la spec.
    pub fn new(sockets: Vec<UdpSocket>, key: SigningKey) -> ServerConfig {
        ServerConfig {
            sockets,
            key,
            limits: LimitConfig::default(),
            hello_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            max_streams: 4,
            max_response_bytes_in_flight: DEFAULT_MAX_RESPONSE_BYTES_IN_FLIGHT,
            max_response_bytes_per_ip: DEFAULT_MAX_RESPONSE_BYTES_PER_IP,
            min_send_rate: DEFAULT_MIN_SEND_RATE,
            max_db_jobs: DEFAULT_MAX_DB_JOBS,
            max_db_jobs_per_prefix: None,
            version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION,
            stats: Arc::new(ServerStats::default()),
            dht: None,
            dht_tick: None,
            dht_diversity: DiversityLimits::SPEC,
        }
    }
}

/// État partagé par toutes les connexions.
pub(crate) struct Shared {
    store: Mutex<NodeStore>,
    pub(crate) policy: Policy,
    node_id: NodeId,
    version: u16,
    min_version: u16,
    hello_timeout: Duration,
    idle_timeout: Duration,
    request_timeout: Duration,
    limiter: Arc<Limiter>,
    db: Arc<Budget>,
    /// Opérations de base en cours ou en attente par groupe d'adresses.
    db_jobs_per_group: u32,
    /// Même chose par /48 (IPv6) ou /24 (IPv4).
    db_jobs_per_prefix: u32,
    responses: Arc<Budget>,
    response_bytes_per_ip: usize,
    min_send_rate: u64,
    stats: Arc<ServerStats>,
    /// Table de hachage, si `[dht]` est configurée.
    dht: Option<Arc<Dht>>,
}

impl Shared {
    pub(crate) fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Échéance d'écriture d'une réponse de `len` octets.
    fn write_deadline(&self, len: usize) -> Duration {
        write_deadline(self.request_timeout, len, self.min_send_rate)
    }
}

/// `request_timeout + len / rate`, au plus `MAX_WRITE_DEADLINE`.
pub fn write_deadline(request_timeout: Duration, len: usize, rate: u64) -> Duration {
    let extra = Duration::from_secs_f64(len as f64 / rate.max(1) as f64);
    request_timeout
        .saturating_add(extra)
        .min(MAX_WRITE_DEADLINE)
}

/// Taille de page servie pour une demande de `max_bytes`.
pub fn fetch_page_bytes(max_bytes: u32) -> usize {
    (max_bytes as usize).clamp(barking_proto::MIN_PAGE_BYTES as usize, FETCH_PAGE_BYTES)
}

/// Réserve de réponse d'une page : la page, ou un élément seul plus gros
/// (palier L), plus la marge d'encodage.
fn fetch_reserve(max_bytes: u32) -> usize {
    (fetch_page_bytes(max_bytes).max(Tier::L.size()) + PAGE_OVERHEAD).min(MAX_RESPONSE_BYTES)
}

/// Issue d'une opération de base.
pub(crate) enum Stored<T> {
    Done(T),
    /// File de base pleine.
    Busy,
    /// Erreur interne (journalisée).
    Failed,
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    /// Exécute `f` sur la base, hors de la boucle asynchrone. `wait` : attend
    /// une place dans la file (tâches internes) au lieu de répondre `Busy`.
    /// `group` : la requête vient de ce groupe d'adresses, qui n'a droit
    /// qu'à `db_jobs_per_group` places à la fois (`Busy` au-delà).
    pub(crate) async fn with_store<T: Send + 'static>(
        self: &Arc<Self>,
        wait: bool,
        group: Option<&ConnectionSlot>,
        f: impl FnOnce(&mut NodeStore, &Policy) -> Result<T> + Send + 'static,
    ) -> Stored<T> {
        let group_job: Option<GroupDbJob> = match group {
            Some(g) => match g.try_db_job(self.db_jobs_per_group, self.db_jobs_per_prefix) {
                Some(j) => Some(j),
                None => return Stored::Busy,
            },
            None => None,
        };
        let slot = if wait {
            self.db.take(1).await
        } else {
            self.db.try_take(1)
        };
        let Some(slot) = slot else {
            return Stored::Busy;
        };
        let me = Arc::clone(self);
        let r = tokio::task::spawn_blocking(move || {
            // Les places sont rendues à la fin du travail, même si la requête
            // a été abandonnée entre-temps.
            let _slot = slot;
            let _group_job = group_job;
            let mut store = me.store.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut store, &me.policy)
        })
        .await;
        match r {
            Ok(Ok(v)) => Stored::Done(v),
            Ok(Err(e)) => {
                tracing::error!("erreur interne de stockage : {e}");
                Stored::Failed
            }
            Err(_) => {
                tracing::error!("tâche de stockage interrompue");
                Stored::Failed
            }
        }
    }
}

/// Fait tourner le nœud jusqu'à `shutdown`.
pub async fn run(
    config: ServerConfig,
    store: NodeStore,
    policy: Policy,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    policy.validate()?;
    if config.min_version > config.version {
        return Err(Error::Config("min_version > version".into()));
    }
    if config.sockets.is_empty() {
        return Err(Error::Config("aucune adresse d'écoute".into()));
    }
    if config.max_db_jobs == 0
        || config.max_response_bytes_in_flight < MAX_RESPONSE_BYTES
        || config.max_response_bytes_per_ip < MAX_RESPONSE_BYTES
        || config.min_send_rate == 0
    {
        return Err(Error::Config(
            "max_db_jobs ou min_send_rate nul, ou budget de réponse sous 1 Mio".into(),
        ));
    }

    let mut qcfg = tls::quinn_server_config(&config.key);
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(config.max_streams.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(STREAM_WINDOW.into())
        // Mémoire tenue par connexion bornée : 256 Kio en réception, 2 Mio
        // de réponses en attente d'acquittement.
        .receive_window((2 * STREAM_WINDOW).into())
        .send_window(SEND_WINDOW)
        .max_idle_timeout(Some(
            config
                .idle_timeout
                .try_into()
                .map_err(|_| Error::Config("idle_timeout trop grand".into()))?,
        ));
    qcfg.transport_config(Arc::new(transport));
    qcfg.migration(false);

    let runtime =
        quinn::default_runtime().ok_or_else(|| Error::Config("pas de runtime tokio".into()))?;
    let mut endpoints = Vec::new();
    for socket in config.sockets {
        endpoints.push(Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(qcfg.clone()),
            socket,
            runtime.clone(),
        )?);
    }
    // Les appels sortants vers les pairs partent des mêmes endpoints, donc
    // du même port UDP (spec §3.3).
    // Sans adresse publique, la table est désactivée (spec §8).
    let dht_cfg = config.dht.filter(|d| {
        let has_addr = d.public_v4.is_some() || d.public_v6.is_some();
        if !has_addr {
            tracing::warn!("[dht] sans public_addr : table désactivée, simple relais");
        }
        has_addr
    });
    let dht = dht_cfg.map(|d| {
        Arc::new(Dht::new(
            config.key.clone(),
            d,
            endpoints.clone(),
            db_jobs_per_group(config.max_db_jobs),
            config.dht_tick,
            config.dht_diversity,
        ))
    });

    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        policy,
        node_id: NodeId::from_public_key(&config.key.verifying_key()),
        version: config.version,
        min_version: config.min_version,
        hello_timeout: config.hello_timeout,
        idle_timeout: config.idle_timeout,
        request_timeout: config.request_timeout,
        limiter: Limiter::new(config.limits),
        db: Budget::new(config.max_db_jobs, Arc::clone(&config.stats), |s| {
            &s.db_jobs
        }),
        db_jobs_per_group: db_jobs_per_group(config.max_db_jobs),
        db_jobs_per_prefix: config.max_db_jobs_per_prefix.map_or_else(
            || db_jobs_per_prefix(config.max_db_jobs),
            |n| u32::try_from(n.max(1)).unwrap_or(u32::MAX),
        ),
        responses: Budget::new(
            config.max_response_bytes_in_flight,
            Arc::clone(&config.stats),
            |s| &s.response_bytes,
        ),
        response_bytes_per_ip: config.max_response_bytes_per_ip,
        min_send_rate: config.min_send_rate,
        stats: Arc::clone(&config.stats),
        dht: dht.clone(),
    });

    if let Stored::Done(n) = shared
        .with_store(true, None, |s, _| s.purge_expired(unix_now()))
        .await
    {
        shared.stats.purged(n);
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    for ep in &endpoints {
        tasks.spawn(accept_loop(
            ep.clone(),
            Arc::clone(&shared),
            stop_rx.clone(),
        ));
    }
    tasks.spawn(purge_loop(Arc::clone(&shared), stop_rx.clone()));
    if let Some(d) = &dht {
        tasks.spawn(replicate::run(
            Arc::clone(d),
            Arc::clone(&shared),
            stop_rx.clone(),
        ));
    }
    // Entretien de la table, attendu à l'arrêt : il enregistre `peers`.
    let maintenance =
        dht.map(|d| tokio::spawn(maintain::run(d, Arc::clone(&shared), stop_rx.clone())));

    shutdown.await;
    let _ = stop_tx.send(true);
    if let Some(mut m) = maintenance
        && timeout(Duration::from_secs(10), &mut m).await.is_err()
    {
        m.abort();
    }
    for ep in &endpoints {
        ep.close(CLOSE_NORMAL.into(), b"arret");
    }
    for ep in &endpoints {
        let _ = timeout(Duration::from_secs(2), ep.wait_idle()).await;
    }
    tasks.shutdown().await;
    Ok(())
}

async fn purge_loop(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(PURGE_INTERVAL);
    tick.tick().await; // premier tic immédiat : la purge de démarrage est faite.
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Stored::Done(n) =
                    shared.with_store(true, None, |s, _| s.purge_expired(unix_now())).await
                {
                    shared.stats.purged(n);
                }
            }
            _ = stop.changed() => return,
        }
    }
}

async fn accept_loop(ep: Endpoint, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut conns = JoinSet::new();
    loop {
        let incoming = tokio::select! {
            i = ep.accept() => i,
            _ = stop.changed() => None,
        };
        let Some(incoming) = incoming else { break };
        // Ramasse les tâches terminées.
        while conns.try_join_next().is_some() {}
        admit(incoming, &shared, &mut conns, &stop);
    }
    conns.shutdown().await;
}

fn admit(
    incoming: Incoming,
    shared: &Arc<Shared>,
    conns: &mut JoinSet<()>,
    stop: &watch::Receiver<bool>,
) {
    if !incoming.remote_address_validated() {
        if incoming.may_retry() {
            // Jeton sans état : le client revient prouver son adresse.
            let _ = incoming.retry();
        } else {
            incoming.ignore();
        }
        return;
    }
    let Some(slot) = shared
        .limiter
        .try_acquire(incoming.remote_address().ip(), Instant::now())
    else {
        incoming.refuse();
        return;
    };
    let shared = Arc::clone(shared);
    let stop = stop.clone();
    conns.spawn(async move {
        shared.stats.connections.add(1);
        let _open = OpenConnection(Arc::clone(&shared.stats));
        serve_connection(incoming, slot, shared, stop).await;
    });
}

/// Décompte d'une connexion ouverte (même si sa tâche est abandonnée).
struct OpenConnection(Arc<ServerStats>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.connections.sub(1);
    }
}

async fn serve_connection(
    incoming: Incoming,
    slot: ConnectionSlot,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + shared.hello_timeout;
    let Ok(Ok(conn)) = tokio::time::timeout_at(deadline, async { incoming.accept()?.await }).await
    else {
        return;
    };
    match tokio::time::timeout_at(deadline, hello(&conn, &shared)).await {
        Ok(true) => {}
        _ => {
            conn.close(CLOSE_PROTOCOL.into(), b"hello");
            return;
        }
    }

    // Identifiant de l'appelant s'il a présenté un certificat de nœud.
    let peer = tls::peer_node_id(&conn);
    let conn_state = Arc::new(ConnState {
        peer,
        remote: conn.remote_address(),
        refusals: AtomicU32::new(0),
        conn: conn.clone(),
        reserved: AtomicUsize::new(0),
        slot,
    });
    // Flux de cette connexion : bornés par QUIC (`max_streams`), attendus ou
    // abandonnés avant de rendre la place du limiteur.
    let mut streams = JoinSet::new();
    loop {
        while streams.try_join_next().is_some() {}
        let next = tokio::select! {
            r = timeout(shared.idle_timeout, conn.accept_bi()) => r,
            _ = stop.changed() => {
                conn.close(CLOSE_NORMAL.into(), b"arret");
                break;
            }
            // Table des connexions pleine : place cédée à un autre groupe.
            _ = conn_state.slot.evicted().notified() => {
                conn.close(CLOSE_EVICTED.into(), b"evince");
                break;
            }
        };
        match next {
            Err(_) => {
                conn.close(CLOSE_IDLE.into(), b"inactif");
                break;
            }
            Ok(Err(_)) => break,
            Ok(Ok((send, recv))) => {
                streams.spawn(serve_stream(
                    send,
                    recv,
                    Arc::clone(&shared),
                    Arc::clone(&conn_state),
                ));
            }
        }
    }
    streams.shutdown().await;
}

/// État d'une connexion partagé par ses flux.
struct ConnState {
    /// Nœud appelant authentifié par son certificat (spec §3.3).
    peer: Option<NodeId>,
    /// Adresse source (en mémoire seulement, jamais journalisée) : le rappel
    /// d'une fiche `from` n'est fait que si elle l'annonce (spec §6.2).
    remote: SocketAddr,
    /// Refus de débit consécutifs.
    refusals: AtomicU32,
    conn: Connection,
    /// Octets de réponses réservés par cette connexion (au plus une page).
    reserved: AtomicUsize,
    /// Place du limiteur (et état du groupe d'adresses : seau de débit,
    /// réserves) : rendue quand la connexion et ses flux sont finis.
    slot: ConnectionSlot,
}

/// Réserve de réponse comptée à trois niveaux : connexion, groupe
/// d'adresses, budget global.
struct Reservation {
    held: Held,
    state: Arc<ConnState>,
    n: usize,
}

impl Reservation {
    fn try_new(shared: &Shared, state: &Arc<ConnState>, n: usize) -> Option<Reservation> {
        state
            .reserved
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                v.checked_add(n).filter(|t| *t <= MAX_RESPONSE_BYTES)
            })
            .ok()?;
        if !state
            .slot
            .try_reserve_bytes(n, shared.response_bytes_per_ip)
        {
            state.reserved.fetch_sub(n, Ordering::Relaxed);
            return None;
        }
        let Some(held) = shared.responses.try_take(n) else {
            state.slot.release_bytes(n);
            state.reserved.fetch_sub(n, Ordering::Relaxed);
            return None;
        };
        Some(Reservation {
            held,
            state: Arc::clone(state),
            n,
        })
    }

    /// Ramène la réserve à `keep` octets (jamais au-dessus de la réserve).
    fn shrink(&mut self, keep: usize) {
        let extra = self.n.saturating_sub(keep);
        self.held.shrink(keep);
        self.state.slot.release_bytes(extra);
        self.state.reserved.fetch_sub(extra, Ordering::Relaxed);
        self.n -= extra;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.slot.release_bytes(self.n);
        self.state.reserved.fetch_sub(self.n, Ordering::Relaxed);
    }
}

/// Lit une requête ; `None` si le flux a été fermé (trame trop grande,
/// tronquée, trop lente). Renvoie aussi la taille lue.
async fn read_request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    limit: Duration,
) -> Option<(core::result::Result<Request, ()>, usize)> {
    match timeout(
        limit,
        frame::read_counted::<Request>(recv, MAX_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok((req, size))) => Some((Ok(req), size)),
        Ok(Err(FrameError::Malformed)) => Some((Err(()), MAX_REQUEST_BYTES)),
        Ok(Err(_)) | Err(_) => {
            let _ = recv.stop(STREAM_REFUSED.into());
            let _ = send.reset(STREAM_REFUSED.into());
            None
        }
    }
}

/// Écrit la réponse et attend son acquittement complet, sous `limit` ; sinon
/// (délai, arrêt par le pair) le flux est réinitialisé. Vrai si acquittée.
async fn respond(send: &mut SendStream, bytes: &[u8], limit: Duration) -> bool {
    let sent = timeout(limit, async {
        send.write_all(bytes).await.ok()?;
        send.finish().ok()?;
        send.stopped().await.ok()
    })
    .await;
    match sent {
        Ok(Some(None)) => true,
        _ => {
            let _ = send.reset(STREAM_REFUSED.into());
            false
        }
    }
}

fn encode(resp: &Response) -> Vec<u8> {
    frame::encode(resp, MAX_RESPONSE_BYTES).unwrap_or_else(|_| {
        // Une page est bornée sous `MAX_RESPONSE_BYTES` : n'arrive pas.
        frame::encode(&Response::Error(ErrorReason::NodeFull), MAX_RESPONSE_BYTES)
            .unwrap_or_default()
    })
}

/// Premier flux : `Hello` obligatoire. Vrai si la connexion peut continuer.
async fn hello(conn: &Connection, shared: &Arc<Shared>) -> bool {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
        return false;
    };
    let Some((req, _)) = read_request(&mut send, &mut recv, shared.hello_timeout).await else {
        return false;
    };
    let (resp, ok) = match req {
        Ok(Request::Hello {
            version,
            min_version,
        }) if min_version <= version => {
            if !barking_proto::versions_overlap(
                min_version,
                version,
                shared.min_version,
                shared.version,
            ) {
                (Response::Error(ErrorReason::VersionTooOld), false)
            } else {
                (
                    Response::Hello {
                        version: shared.version,
                        min_version: shared.min_version,
                        node_id: shared.node_id,
                        pow_bits: shared.policy.pow_bits,
                        limits: Limits {
                            max_mailboxes_per_fetch: MAX_MAILBOXES_PER_FETCH as u16,
                            max_request_bytes: MAX_REQUEST_BYTES as u32,
                            max_response_bytes: MAX_RESPONSE_BYTES as u32,
                        },
                    },
                    true,
                )
            }
        }
        _ => (Response::Error(ErrorReason::Malformed), false),
    };
    if let Response::Error(r) = &resp {
        shared.stats.refuse(*r);
    }
    // Attend l'acquittement : la réponse arrive avant toute fermeture.
    respond(&mut send, &encode(&resp), shared.hello_timeout).await;
    ok
}

async fn serve_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    shared: Arc<Shared>,
    state: Arc<ConnState>,
) {
    let Some((req, size)) = read_request(&mut send, &mut recv, shared.request_timeout).await else {
        return;
    };
    let now = Instant::now();
    state.slot.touch(now);
    let cost = match &req {
        Ok(Request::Fetch { mailboxes, .. }) => fetch_cost(mailboxes.len()),
        _ => 1,
    };
    let admitted = state.slot.admit(cost, size, now);
    if !admitted {
        shared.stats.refuse(ErrorReason::RateLimited);
        let n = state.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_CONSECUTIVE_REFUSALS {
            state.conn.close(CLOSE_ABUSE.into(), b"debit");
            return;
        }
        let bytes = encode(&Response::Error(ErrorReason::RateLimited));
        respond(&mut send, &bytes, shared.write_deadline(bytes.len())).await;
        state.charge(bytes.len());
        return;
    }
    state.refusals.store(0, Ordering::Relaxed);

    // Réserve de réponse prise avant tout travail ; plafond atteint : refus.
    let reserve = match &req {
        Ok(Request::Fetch { max_bytes, .. }) => fetch_reserve(*max_bytes),
        // Sans table, ces requêtes reçoivent `Unsupported` : petite réserve.
        Ok(Request::FindNode { .. }) if shared.dht.is_some() => NODES_RESPONSE_BYTES,
        Ok(Request::FindValue { .. }) if shared.dht.is_some() => HOLDINGS_RESPONSE_BYTES,
        _ => SMALL_RESPONSE_BYTES,
    };
    let (bytes, held) = match Reservation::try_new(&shared, &state, reserve) {
        None => {
            shared.stats.refuse(ErrorReason::RateLimited);
            (encode(&Response::Error(ErrorReason::RateLimited)), None)
        }
        Some(mut held) => {
            let resp = match req {
                Err(()) => Response::Error(ErrorReason::Malformed),
                Ok(req) => match handle(req, &shared, &state).await {
                    Stored::Done(r) => r,
                    Stored::Busy => Response::Error(ErrorReason::RateLimited),
                    Stored::Failed => {
                        // Erreur interne (déjà journalisée) : flux fermé.
                        let _ = send.reset(STREAM_REFUSED.into());
                        return;
                    }
                },
            };
            if let Response::Error(r) = &resp {
                shared.stats.refuse(*r);
            }
            // La réserve couvre la réponse : page bornée par `fetch_reserve`.
            let bytes = encode(&resp);
            held.shrink(bytes.len());
            (bytes, Some(held))
        }
    };
    // Débit compté sur la taille envoyée, que la réponse soit acquittée,
    // coupée, arrêtée par le pair ou expirée.
    respond(&mut send, &bytes, shared.write_deadline(bytes.len())).await;
    drop(held);
    state.charge(bytes.len());
}

impl ConnState {
    fn charge(&self, bytes: usize) {
        self.slot.charge_bytes(bytes, Instant::now());
    }
}

/// Coût d'une relève en jetons de requêtes : 1, plus 1 par tranche de 8
/// boîtes (chaque boîte est une lecture d'index).
pub fn fetch_cost(mailboxes: usize) -> u32 {
    u32::try_from(1 + mailboxes.div_ceil(8)).unwrap_or(u32::MAX)
}

/// Part de la file de base d'un groupe d'adresses : 1/16, au moins 1.
pub fn db_jobs_per_group(max_db_jobs: usize) -> u32 {
    u32::try_from((max_db_jobs / 16).max(1)).unwrap_or(u32::MAX)
}

/// Part de la file de base d'un /48 ou /24 : 1/8, au moins 1.
pub fn db_jobs_per_prefix(max_db_jobs: usize) -> u32 {
    u32::try_from((max_db_jobs / 8).max(1)).unwrap_or(u32::MAX)
}

/// Traite une requête après `Hello` ; `peer` : nœud appelant authentifié.
async fn handle(req: Request, shared: &Arc<Shared>, state: &ConnState) -> Stored<Response> {
    let group = &state.slot;
    let to_resp = |r: core::result::Result<Response, ErrorReason>| match r {
        Ok(resp) => resp,
        Err(e) => Response::Error(e),
    };
    match req {
        Request::Hello { .. } => Stored::Done(Response::Error(ErrorReason::Malformed)),
        Request::Deposit { packet, pow } => {
            // Forme, expiration et preuve à la difficulté de base vérifiées
            // avant de prendre une place dans la file de la base.
            if let Err(r) = rules::precheck(&shared.policy, &packet, pow, unix_now()) {
                return Stored::Done(Response::Error(r));
            }
            match shared
                .with_store(false, Some(group), move |s, p| {
                    rules::deposit(s, p, &packet, pow, unix_now())
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(r.map(|()| {
                    shared.stats.deposit_ok();
                    Response::Ok
                }))),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Fetch {
            mailboxes,
            cursor,
            max_bytes,
        } => {
            let page = fetch_page_bytes(max_bytes);
            match shared
                .with_store(false, Some(group), move |s, _| {
                    rules::fetch(s, &mailboxes, cursor, page)
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(r.map(|(items, next)| {
                    shared.stats.fetch_served();
                    Response::Items { items, next }
                }))),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Ping { .. }
        | Request::FindNode { .. }
        | Request::Store { .. }
        | Request::FindValue { .. } => match &shared.dht {
            None => Stored::Done(Response::Error(ErrorReason::Unsupported)),
            Some(dht) => {
                dht.handle(req, state.peer, state.remote, shared, group)
                    .await
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_drains_counters_and_peaks() {
        let st = ServerStats::default();
        st.deposit_ok();
        st.deposit_ok();
        st.fetch_served();
        st.purged(3);
        st.refuse(ErrorReason::PowTooWeak);
        st.refuse(ErrorReason::PowTooWeak);
        st.refuse(ErrorReason::RateLimited);
        st.connections.add(5);
        st.connections.sub(3);
        let r = st.drain();
        assert_eq!((r.deposits_ok, r.fetches, r.purged), (2, 1, 3));
        assert_eq!(
            r.refusals,
            vec![(ErrorReason::PowTooWeak, 2), (ErrorReason::RateLimited, 1)]
        );
        assert_eq!((r.connections, r.connections_peak), (2, 5));
        let line = r.to_string();
        assert!(
            line.contains("PowTooWeak=2") && line.contains("pic 5"),
            "{line}"
        );
        // Période suivante : compteurs à zéro, pic ramené à la valeur courante.
        let r = st.drain();
        assert_eq!((r.deposits_ok, r.fetches, r.purged), (0, 0, 0));
        assert!(r.refusals.is_empty());
        assert_eq!((r.connections, r.connections_peak), (2, 2));
    }

    #[test]
    fn write_deadline_scales_with_size() {
        let t = Duration::from_secs(10);
        let r = 32 * 1024;
        assert_eq!(write_deadline(t, 0, r), t);
        assert_eq!(write_deadline(t, 32 * 1024, r), Duration::from_secs(11));
        assert_eq!(write_deadline(t, 1 << 20, r), Duration::from_secs(42));
        assert_eq!(write_deadline(t, 100 << 20, r), MAX_WRITE_DEADLINE);
    }

    #[test]
    fn fetch_page_and_reserve_bounds() {
        assert_eq!(fetch_page_bytes(0), 16 * 1024);
        assert_eq!(fetch_page_bytes(64 * 1024), 64 * 1024);
        assert_eq!(fetch_page_bytes(u32::MAX), FETCH_PAGE_BYTES);
        // Un élément L seul tient toujours dans la réserve.
        assert!(fetch_reserve(0) >= Tier::L.size() + PAGE_OVERHEAD);
        assert!(fetch_reserve(u32::MAX) <= MAX_RESPONSE_BYTES);
        assert!(fetch_reserve(u32::MAX) >= FETCH_PAGE_BYTES + PAGE_OVERHEAD);
    }
}
