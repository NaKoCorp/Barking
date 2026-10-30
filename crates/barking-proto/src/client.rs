//! Client QUIC (spec §7.1) : connexion épinglée, `Hello`, dépôt et relève.
//!
//! Le client se méfie du nœud autant que le nœud se méfie de lui :
//! - une difficulté annoncée au-delà de `MAX_POW_BITS` est une erreur de
//!   protocole (un nœud hostile ne fait pas tourner le client sans fin) ;
//! - une relève s'arrête à `MAX_FETCH_ITEMS` éléments, `MAX_FETCH_BYTES`
//!   octets, `MAX_FETCH_PAGES` pages ou `FETCH_DEADLINE` par appel ; le reste attend la relève suivante (rien n'est supprimé
//!   à la lecture) et `Session::last_fetch_truncated` le signale ;
//! - le curseur de pagination doit croître strictement, et une page vide ne
//!   peut pas annoncer de suite ;
//! - chaque requête a un délai.
//!
//! Les éléments relevés sont rendus tels quels : un accusé dont le champ boîte
//! diffère de la boîte relevée n'est pas écarté (l'accusé est rangé dans
//! chaque boîte qui tenait le paquet).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use barking_packet::{Kind, MailboxId, Packet};
use quinn::{Connection, Endpoint};
use tokio::time::timeout;

use crate::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use crate::msg::{ErrorReason, Limits, Request, Response};
use crate::{NodeId, PROTOCOL_VERSION, pow, tls};

/// Plus ancienne version du protocole que ce client sait parler.
pub const MIN_PROTOCOL_VERSION: u16 = 0;
/// Nombre maximal d'éléments acceptés par appel à `fetch`.
pub const MAX_FETCH_ITEMS: usize = 10_000;
/// Nombre maximal d'octets acceptés par appel à `fetch`.
pub const MAX_FETCH_BYTES: usize = 64 << 20;
/// Nombre maximal de pages suivies par appel à `fetch`.
pub const MAX_FETCH_PAGES: usize = 1_000;
/// Durée maximale d'un appel à `fetch`.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(120);
/// Délai d'établissement de la connexion (poignée de main comprise).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Délai d'une requête (envoi et réponse).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Boîtes par requête `Fetch` au plus, quoi qu'annonce le nœud.
const MAX_MAILBOXES: usize = 64;
/// Hausse de difficulté après `PowTooWeak`.
const POW_RETRY_STEP: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connexion au nœud impossible : {0}")]
    Connect(String),
    #[error("connexion au nœud perdue : {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("version du protocole incompatible avec ce nœud")]
    Version,
    #[error("le nœud refuse : {}", .0.describe())]
    Refused(ErrorReason),
    #[error("réponse du nœud invalide : {0}")]
    Protocol(&'static str),
    #[error("trame : {0}")]
    Frame(#[from] FrameError),
    #[error("le nœud ne répond pas à temps")]
    Timeout,
}

pub type Result<T> = core::result::Result<T, ClientError>;

/// Ouvre une connexion QUIC épinglée sur `expected`, sans `Hello`. Le point
/// d'accès doit vivre aussi longtemps que la connexion.
pub async fn open_connection(addr: SocketAddr, expected: NodeId) -> Result<(Endpoint, Connection)> {
    let bind: SocketAddr = if addr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(bind).map_err(|e| ClientError::Connect(e.to_string()))?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls::client_config(expected))
        .map_err(|e| ClientError::Connect(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into());
    cfg.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(cfg);
    let connecting = endpoint
        .connect(addr, tls::CERT_NAME)
        .map_err(|e| ClientError::Connect(e.to_string()))?;
    let conn = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|e| ClientError::Connect(e.to_string()))?;
    Ok((endpoint, conn))
}

/// Envoie une requête sur un nouveau flux et lit l'unique réponse.
pub async fn request(conn: &Connection, req: &Request) -> Result<Response> {
    timeout(REQUEST_TIMEOUT, async {
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, req, MAX_REQUEST_BYTES).await?;
        // Le flux peut déjà être fermé par le nœud : la lecture le dira.
        let _ = send.finish();
        Ok(frame::read::<Response>(&mut recv, MAX_RESPONSE_BYTES).await?)
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Point d'entrée du client.
pub struct Client;

impl Client {
    /// Se connecte au nœud `expected` (identité vérifiée par TLS), envoie
    /// `Hello` et vérifie la version et les paramètres annoncés.
    pub async fn connect(addr: SocketAddr, expected: NodeId) -> Result<Session> {
        let (endpoint, conn) = open_connection(addr, expected).await?;
        let hello = Request::Hello {
            version: PROTOCOL_VERSION,
            min_version: MIN_PROTOCOL_VERSION,
        };
        match request(&conn, &hello).await? {
            Response::Hello {
                version,
                min_version,
                node_id,
                pow_bits,
                limits,
            } => {
                if node_id != expected {
                    return Err(ClientError::Protocol("identifiant annoncé différent"));
                }
                if min_version > version {
                    return Err(ClientError::Protocol("versions annoncées incohérentes"));
                }
                if !crate::versions_overlap(
                    min_version,
                    version,
                    MIN_PROTOCOL_VERSION,
                    PROTOCOL_VERSION,
                ) {
                    return Err(ClientError::Version);
                }
                if pow_bits > pow::MAX_POW_BITS {
                    return Err(ClientError::Protocol("preuve de travail exigée trop forte"));
                }
                if limits.max_mailboxes_per_fetch == 0 {
                    return Err(ClientError::Protocol("limite de relève nulle"));
                }
                Ok(Session {
                    endpoint,
                    conn,
                    node_id,
                    pow_bits,
                    limits,
                    truncated: false,
                })
            }
            Response::Error(ErrorReason::VersionTooOld) => Err(ClientError::Version),
            Response::Error(r) => Err(ClientError::Refused(r)),
            _ => Err(ClientError::Protocol("réponse inattendue à Hello")),
        }
    }
}

/// Connexion établie avec un nœud, après `Hello`.
pub struct Session {
    endpoint: Endpoint,
    conn: Connection,
    node_id: NodeId,
    pow_bits: u8,
    limits: Limits,
    truncated: bool,
}

impl Session {
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Difficulté de base annoncée par le nœud (au plus `MAX_POW_BITS`).
    pub fn pow_bits(&self) -> u8 {
        self.pow_bits
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Connexion QUIC sous-jacente (tests, diagnostics).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Requête brute sur cette connexion.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        request(&self.conn, req).await
    }

    /// Dépose un paquet encodé. Calcule la preuve de travail d'un message
    /// (pas d'un accusé) ; sur `PowTooWeak`, réessaie avec 2 bits de plus
    /// jusqu'à `MAX_POW_BITS`. `Ok(Err(raison))` : refus du nœud.
    pub async fn deposit(
        &mut self,
        packet: &[u8],
    ) -> Result<core::result::Result<(), ErrorReason>> {
        // Un paquet illisible part sans preuve : le nœud répondra `Malformed`.
        let target = match Packet::decode(packet) {
            Ok(p) if p.kind == Kind::Message => Some(p.mailbox),
            _ => None,
        };
        let Some(mailbox) = target else {
            return self.deposit_once(packet, 0).await;
        };
        let content = pow::content_hash(packet);
        let mut bits = self.pow_bits;
        loop {
            let nonce = solve(content, mailbox, bits).await?;
            match self.deposit_once(packet, nonce).await? {
                Err(ErrorReason::PowTooWeak) if bits < pow::MAX_POW_BITS => {
                    bits = bits.saturating_add(POW_RETRY_STEP).min(pow::MAX_POW_BITS);
                }
                other => return Ok(other),
            }
        }
    }

    async fn deposit_once(
        &self,
        packet: &[u8],
        pow: u64,
    ) -> Result<core::result::Result<(), ErrorReason>> {
        let req = Request::Deposit {
            packet: packet.to_vec(),
            pow,
        };
        match self.request(&req).await? {
            Response::Ok => Ok(Ok(())),
            Response::Error(r) => Ok(Err(r)),
            _ => Err(ClientError::Protocol("réponse inattendue à Deposit")),
        }
    }

    /// Relève paquets et accusés en attente pour `mailboxes` (découpage par
    /// 64 boîtes, pages suivies). S'arrête à `MAX_FETCH_ITEMS` éléments,
    /// `MAX_FETCH_BYTES` octets, `MAX_FETCH_PAGES` pages ou après
    /// `FETCH_DEADLINE` : voir `last_fetch_truncated`.
    pub async fn fetch(&mut self, mailboxes: &[MailboxId]) -> Result<Vec<Vec<u8>>> {
        self.truncated = false;
        let per = usize::from(self.limits.max_mailboxes_per_fetch).min(MAX_MAILBOXES);
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut pages = 0usize;
        let deadline = tokio::time::Instant::now() + FETCH_DEADLINE;
        for chunk in mailboxes.chunks(per) {
            let mut cursor: Option<u64> = None;
            loop {
                if pages >= MAX_FETCH_PAGES || tokio::time::Instant::now() >= deadline {
                    self.truncated = true;
                    return Ok(out);
                }
                pages += 1;
                let req = Request::Fetch {
                    mailboxes: chunk.to_vec(),
                    cursor,
                };
                let resp = match tokio::time::timeout_at(deadline, self.request(&req)).await {
                    Ok(r) => r?,
                    Err(_) => {
                        self.truncated = true;
                        return Ok(out);
                    }
                };
                let (items, next) = match resp {
                    Response::Items { items, next } => (items, next),
                    Response::Error(r) => return Err(ClientError::Refused(r)),
                    _ => return Err(ClientError::Protocol("réponse inattendue à Fetch")),
                };
                if next.is_some() && items.is_empty() {
                    return Err(ClientError::Protocol("page vide avec suite"));
                }
                if let (Some(n), Some(c)) = (next, cursor)
                    && n <= c
                {
                    return Err(ClientError::Protocol("curseur de relève non croissant"));
                }
                for it in items {
                    if out.len() >= MAX_FETCH_ITEMS || bytes + it.len() > MAX_FETCH_BYTES {
                        self.truncated = true;
                        return Ok(out);
                    }
                    bytes += it.len();
                    out.push(it);
                }
                match next {
                    Some(n) => cursor = Some(n),
                    None => break,
                }
            }
        }
        Ok(out)
    }

    /// Vrai si la dernière relève s'est arrêtée sur un plafond du client :
    /// d'autres éléments attendent sur le nœud.
    pub fn last_fetch_truncated(&self) -> bool {
        self.truncated
    }

    /// Ferme proprement la connexion.
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"fin");
        let _ = timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
    }
}

/// Recherche du nonce hors de la boucle asynchrone (calcul pur).
async fn solve(content: [u8; 32], mailbox: MailboxId, bits: u8) -> Result<u64> {
    tokio::task::spawn_blocking(move || pow::solve(&content, &mailbox, bits))
        .await
        .map_err(|_| ClientError::Protocol("calcul de preuve interrompu"))?
        .ok_or(ClientError::Protocol("preuve de travail exigée trop forte"))
}
