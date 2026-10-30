//! Serveur QUIC du nœud (spec §3.2, §4, §5) : coquille réseau autour des
//! règles de `rules`.
//!
//! Choix documentés :
//! - **Base de données** : un seul `NodeStore` derrière un `Mutex`, chaque
//!   opération dans `spawn_blocking`. Écritures (et lectures) sérialisées sur
//!   une seule connexion SQLite : pas de course entre la vérification des
//!   quotas et l'insertion.
//! - **Adresses** : une connexion n'est acceptée qu'après validation de
//!   l'adresse (jeton QUIC `Retry`), pour qu'une adresse usurpée ne réserve
//!   pas de place dans le limiteur. Le limiteur regroupe par IP (/64 en IPv6),
//!   en mémoire seulement ; aucune adresse n'est journalisée.
//! - **Délais** : poignée de main et `Hello` sous `hello_timeout` (5 s) ;
//!   connexion fermée sans nouvelle requête pendant `idle_timeout` (60 s, aussi
//!   le délai d'inactivité QUIC) ; lecture d'une requête sous
//!   `request_timeout` (10 s).
//! - **Flux** : au plus `max_streams` (8) flux bidirectionnels simultanés par
//!   connexion, aucun flux unidirectionnel ; fenêtres de réception (256 Kio)
//!   et d'envoi (2 Mio) réduites : mémoire bornée par connexion.
//! - **Trames** : une trame trop grande, tronquée ou trop lente ferme le flux
//!   sans réponse ; un corps illisible reçoit `Error(Malformed)`.
//! - **Débit** : chaque requête après `Hello` passe par le seau de jetons de sa
//!   connexion (`RateLimited` sinon) ; les octets des réponses y sont débités.
//! - **Purge** des expirés au démarrage puis toutes les 60 s.

use std::future::Future;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barking_proto::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use barking_proto::{ErrorReason, Limits, NodeId, PROTOCOL_VERSION, Request, Response, tls};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use tokio::sync::watch;
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

/// Codes de fermeture (application).
const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_IDLE: u32 = 2;
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
    /// Versions du protocole servies : `min_version..=version`.
    pub version: u16,
    pub min_version: u16,
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
            max_streams: 8,
            version: PROTOCOL_VERSION,
            min_version: PROTOCOL_VERSION,
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
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    /// Exécute `f` sur la base, hors de la boucle asynchrone.
    async fn with_store<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut NodeStore, &Policy) -> Result<T> + Send + 'static,
    ) -> Option<T> {
        let me = Arc::clone(self);
        let r = tokio::task::spawn_blocking(move || {
            let mut store = me.store.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut store, &me.policy)
        })
        .await;
        match r {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                tracing::error!("erreur interne de stockage : {e}");
                None
            }
            Err(_) => {
                tracing::error!("tâche de stockage interrompue");
                None
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

    shared.with_store(|s, _| s.purge_expired(unix_now())).await;

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
                if let Some(n) = shared.with_store(|s, _| s.purge_expired(unix_now())).await
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

    let budget = Arc::new(Mutex::new(shared.limiter.budget(Instant::now())));
    loop {
        let next = tokio::select! {
            r = timeout(shared.idle_timeout, conn.accept_bi()) => r,
            _ = stop.changed() => {
                conn.close(CLOSE_NORMAL.into(), b"arret");
                return;
            }
        };
        match next {
            Err(_) => {
                conn.close(CLOSE_IDLE.into(), b"inactif");
                return;
            }
            Ok(Err(_)) => return,
            Ok(Ok((send, recv))) => {
                // Le nombre de flux simultanés est borné par QUIC
                // (`max_streams`) : une tâche par flux.
                tokio::spawn(serve_stream(
                    send,
                    recv,
                    Arc::clone(&shared),
                    Arc::clone(&budget),
                ));
            }
        }
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

async fn respond(send: &mut SendStream, resp: &Response) -> usize {
    match frame::write(send, resp, MAX_RESPONSE_BYTES).await {
        Ok(size) => {
            let _ = send.finish();
            size
        }
        Err(_) => {
            let _ = send.reset(STREAM_REFUSED.into());
            0
        }
    }
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
    respond(&mut send, &resp).await;
    if !ok {
        // Laisse la réponse arriver avant de fermer la connexion.
        let _ = timeout(Duration::from_secs(2), send.stopped()).await;
    }
    ok
}

async fn serve_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    shared: Arc<Shared>,
    budget: Arc<Mutex<ConnBudget>>,
) {
    let Some((req, size)) = read_request(&mut send, &mut recv, shared.request_timeout).await else {
        return;
    };
    let admitted = budget
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(size, Instant::now());
    let resp = if !admitted {
        Response::Error(ErrorReason::RateLimited)
    } else {
        match req {
            Err(()) => Response::Error(ErrorReason::Malformed),
            Ok(req) => match handle(req, &shared).await {
                Some(r) => r,
                None => {
                    // Erreur interne (déjà journalisée) : flux fermé.
                    let _ = send.reset(STREAM_REFUSED.into());
                    return;
                }
            },
        }
    };
    let sent = respond(&mut send, &resp).await;
    budget
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .charge_bytes(sent, Instant::now());
}

/// Traite une requête après `Hello`. `None` : erreur interne.
async fn handle(req: Request, shared: &Arc<Shared>) -> Option<Response> {
    match req {
        Request::Hello { .. } => Some(Response::Error(ErrorReason::Malformed)),
        Request::Deposit { packet, pow } => {
            let r = shared
                .with_store(move |s, p| rules::deposit(s, p, &packet, pow, unix_now()))
                .await?;
            Some(match r {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            })
        }
        Request::Fetch { mailboxes, cursor } => {
            let r = shared
                .with_store(move |s, _| rules::fetch(s, &mailboxes, cursor, FETCH_PAGE_BYTES))
                .await?;
            Some(match r {
                Ok((items, next)) => Response::Items { items, next },
                Err(e) => Response::Error(e),
            })
        }
        Request::Ping
        | Request::FindNode { .. }
        | Request::Store { .. }
        | Request::FindValue { .. } => Some(Response::Error(ErrorReason::Unsupported)),
    }
}
