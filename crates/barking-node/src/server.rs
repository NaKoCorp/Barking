//! Serveur QUIC du nœud (spec §3.2, §4, §5) : coquille réseau autour des
//! règles de `rules`.
//!
//! Choix documentés :
//! - **Base de données** : un seul `NodeStore` derrière un `Mutex`, chaque
//!   opération dans `spawn_blocking`. Écritures (et lectures) sérialisées sur
//!   une seule connexion SQLite : pas de course entre la vérification des
//!   quotas et l'insertion. La file est bornée : au plus `max_db_jobs` (64)
//!   opérations en cours ou en attente, au-delà `RateLimited`. Le jeton est
//!   tenu par la tâche bloquante elle-même : abandonner la requête ne libère
//!   la place qu'une fois le travail fini.
//! - **Mémoire des réponses** : chaque requête réserve d'avance la taille
//!   maximale de sa réponse (1 Mio pour `Fetch`) dans un budget global
//!   (`max_response_bytes_in_flight`, 64 Mio), ramenée ensuite à la taille
//!   encodée. La réserve est rendue quand le pair a acquitté toute la réponse,
//!   ou au bout de `request_timeout` (flux alors réinitialisé). Budget épuisé :
//!   `RateLimited`. Un lecteur lent ne retient donc ni mémoire ni flux au-delà
//!   de ce délai.
//! - **Tâches** : les flux d'une connexion vivent dans un `JoinSet` de la
//!   connexion ; la place du limiteur n'est rendue qu'après leur fin
//!   (abandonnées à la fermeture).
//! - **Adresses** : une connexion n'est acceptée qu'après validation de
//!   l'adresse (jeton QUIC `Retry`), pour qu'une adresse usurpée ne réserve
//!   pas de place dans le limiteur. Le limiteur regroupe par IP (/64 en IPv6),
//!   en mémoire seulement ; aucune adresse n'est journalisée.
//! - **Délais** : poignée de main et `Hello` sous `hello_timeout` (5 s) ;
//!   connexion fermée sans nouvelle requête pendant `idle_timeout` (60 s, aussi
//!   le délai d'inactivité QUIC) ; lecture d'une requête sous
//!   `request_timeout` (10 s).
//! - **Flux** : au plus `max_streams` (4) flux bidirectionnels simultanés par
//!   connexion, aucun flux unidirectionnel ; fenêtres de réception (256 Kio)
//!   et d'envoi (2 Mio) réduites : mémoire bornée par connexion.
//! - **Trames** : une trame trop grande, tronquée ou trop lente ferme le flux
//!   sans réponse ; un corps illisible reçoit `Error(Malformed)`.
//! - **Débit** : chaque requête après `Hello` passe par le seau de jetons de sa
//!   connexion (`RateLimited` sinon) ; les octets des réponses y sont débités.
//!   Après `MAX_CONSECUTIVE_REFUSALS` (20) refus de débit d'affilée, la
//!   connexion est fermée.
//! - **Purge** des expirés au démarrage puis toutes les 60 s.

use std::future::Future;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::{ErrorReason, Limits, NodeId, PROTOCOL_VERSION, Request, Response, tls};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::limits::{ConnBudget, LimitConfig, Limiter};
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

/// Réserve de réponse d'une requête autre que `Fetch`.
const SMALL_RESPONSE_BYTES: usize = 4 * 1024;
/// Refus de débit consécutifs avant fermeture de la connexion.
pub const MAX_CONSECUTIVE_REFUSALS: u32 = 20;

/// Codes de fermeture (application).
const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_IDLE: u32 = 2;
const CLOSE_ABUSE: u32 = 3;
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
    /// Opérations de base en cours ou en attente, tous pairs confondus.
    pub max_db_jobs: usize,
    /// Versions du protocole servies : `min_version..=version`.
    pub version: u16,
    pub min_version: u16,
    /// Jauges observables (tests, journaux agrégés).
    pub stats: Arc<ServerStats>,
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
            max_response_bytes_in_flight: 64 << 20,
            max_db_jobs: 64,
            version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION,
            stats: Arc::new(ServerStats::default()),
        }
    }
}

/// État partagé par toutes les connexions.
struct Shared {
    store: Mutex<NodeStore>,
    policy: Policy,
    node_id: NodeId,
    version: u16,
    min_version: u16,
    hello_timeout: Duration,
    idle_timeout: Duration,
    request_timeout: Duration,
    limiter: Arc<Limiter>,
    db: Arc<Budget>,
    responses: Arc<Budget>,
}

/// Issue d'une opération de base.
enum Stored<T> {
    Done(T),
    /// File de base pleine.
    Busy,
    /// Erreur interne (journalisée).
    Failed,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    /// Exécute `f` sur la base, hors de la boucle asynchrone. `wait` : attend
    /// une place dans la file (tâches internes) au lieu de répondre `Busy`.
    async fn with_store<T: Send + 'static>(
        self: &Arc<Self>,
        wait: bool,
        f: impl FnOnce(&mut NodeStore, &Policy) -> Result<T> + Send + 'static,
    ) -> Stored<T> {
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
            // La place est rendue à la fin du travail, même si la requête a
            // été abandonnée entre-temps.
            let _slot = slot;
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
    if config.max_db_jobs == 0 || config.max_response_bytes_in_flight < MAX_RESPONSE_BYTES {
        return Err(Error::Config(
            "max_db_jobs nul ou max_response_bytes_in_flight sous 1 Mio".into(),
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
        responses: Budget::new(
            config.max_response_bytes_in_flight,
            Arc::clone(&config.stats),
            |s| &s.response_bytes,
        ),
    });

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

    let _ = shared
        .with_store(true, |s, _| s.purge_expired(unix_now()))
        .await;

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

    shutdown.await;
    let _ = stop_tx.send(true);
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
                    shared.with_store(true, |s, _| s.purge_expired(unix_now())).await
                    && n > 0
                {
                    tracing::info!(purges = n, "expirés purgés");
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
    let Some(slot) = shared.limiter.try_acquire(incoming.remote_address().ip()) else {
        incoming.refuse();
        return;
    };
    let shared = Arc::clone(shared);
    let stop = stop.clone();
    conns.spawn(async move {
        let _slot = slot;
        serve_connection(incoming, shared, stop).await;
    });
}

async fn serve_connection(
    incoming: Incoming,
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

    let conn_state = Arc::new(ConnState {
        budget: Mutex::new(shared.limiter.budget(Instant::now())),
        refusals: AtomicU32::new(0),
        conn: conn.clone(),
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
    budget: Mutex<ConnBudget>,
    /// Refus de débit consécutifs.
    refusals: AtomicU32,
    conn: Connection,
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
/// le flux est réinitialisé. Renvoie les octets écrits.
async fn respond(send: &mut SendStream, bytes: &[u8], limit: Duration) -> usize {
    let sent = timeout(limit, async {
        send.write_all(bytes).await.ok()?;
        send.finish().ok()?;
        send.stopped().await.ok()
    })
    .await;
    match sent {
        Ok(Some(None)) => bytes.len(),
        _ => {
            let _ = send.reset(STREAM_REFUSED.into());
            0
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
    let admitted = state
        .budget
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(size, Instant::now());
    if !admitted {
        let n = state.refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_CONSECUTIVE_REFUSALS {
            state.conn.close(CLOSE_ABUSE.into(), b"debit");
            return;
        }
        let bytes = encode(&Response::Error(ErrorReason::RateLimited));
        respond(&mut send, &bytes, shared.request_timeout).await;
        return;
    }
    state.refusals.store(0, Ordering::Relaxed);

    // Réserve de réponse prise avant tout travail ; budget épuisé : refus.
    let reserve = match &req {
        Ok(Request::Fetch { .. }) => MAX_RESPONSE_BYTES,
        _ => SMALL_RESPONSE_BYTES,
    };
    let (bytes, held) = match shared.responses.try_take(reserve) {
        None => (encode(&Response::Error(ErrorReason::RateLimited)), None),
        Some(mut held) => {
            let resp = match req {
                Err(()) => Response::Error(ErrorReason::Malformed),
                Ok(req) => match handle(req, &shared).await {
                    Stored::Done(r) => r,
                    Stored::Busy => Response::Error(ErrorReason::RateLimited),
                    Stored::Failed => {
                        // Erreur interne (déjà journalisée) : flux fermé.
                        let _ = send.reset(STREAM_REFUSED.into());
                        return;
                    }
                },
            };
            let bytes = encode(&resp);
            held.shrink(bytes.len());
            (bytes, Some(held))
        }
    };
    let sent = respond(&mut send, &bytes, shared.request_timeout).await;
    drop(held);
    state
        .budget
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .charge_bytes(sent, Instant::now());
}

/// Traite une requête après `Hello`.
async fn handle(req: Request, shared: &Arc<Shared>) -> Stored<Response> {
    let to_resp = |r: core::result::Result<Response, ErrorReason>| match r {
        Ok(resp) => resp,
        Err(e) => Response::Error(e),
    };
    match req {
        Request::Hello { .. } => Stored::Done(Response::Error(ErrorReason::Malformed)),
        Request::Deposit { packet, pow } => {
            match shared
                .with_store(false, move |s, p| {
                    rules::deposit(s, p, &packet, pow, unix_now())
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(r.map(|()| Response::Ok))),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Fetch { mailboxes, cursor } => {
            match shared
                .with_store(false, move |s, _| {
                    rules::fetch(s, &mailboxes, cursor, FETCH_PAGE_BYTES)
                })
                .await
            {
                Stored::Done(r) => Stored::Done(to_resp(
                    r.map(|(items, next)| Response::Items { items, next }),
                )),
                Stored::Busy => Stored::Busy,
                Stored::Failed => Stored::Failed,
            }
        }
        Request::Ping
        | Request::FindNode { .. }
        | Request::Store { .. }
        | Request::FindValue { .. } => Stored::Done(Response::Error(ErrorReason::Unsupported)),
    }
}
