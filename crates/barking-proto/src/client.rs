//! Client QUIC (spec §7.1) : connexion épinglée, `Hello`, dépôt et relève.
//!
//! Le client se méfie du nœud autant que le nœud se méfie de lui :
//! - une difficulté annoncée au-delà de `MAX_POW_BITS` est une erreur de
//!   protocole (un nœud hostile ne fait pas tourner le client sans fin) ;
//! - une relève s'arrête à `MAX_FETCH_ITEMS` éléments, au budget d'octets
//!   de l'appel (`MAX_FETCH_BYTES` par défaut), `MAX_FETCH_PAGES` pages ou
//!   `FETCH_DEADLINE` par appel ; le reste attend la relève suivante (rien
//!   n'est supprimé à la lecture) et `Session::last_fetch_truncated` le
//!   signale. Une page est prise entière ou pas du tout ; `FetchResume`
//!   garde la position atteinte pour que la relève suivante reprenne là au
//!   lieu de relire le début (une boîte inondée ne bloque pas la suite) ;
//! - la preuve de travail d'un dépôt part de la difficulté de base plus le
//!   supplément du palier, monte de 2 bits sur `PowTooWeak`, et peut être
//!   bornée par un budget de travail (`Session::set_pow_budget`) ;
//! - le curseur de pagination doit croître strictement, et une page vide ne
//!   peut pas annoncer de suite ;
//! - chaque requête a un délai ;
//! - une page coupée en route (lien lent) est redemandée plus petite :
//!   1 Mio, 256 Kio, 64 Kio puis 16 Kio, avant d'abandonner.
//!
//! Les éléments relevés sont rendus tels quels : un accusé dont le champ boîte
//! diffère de la boîte relevée n'est pas écarté (l'accusé est rangé dans
//! chaque boîte qui tenait le paquet).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use barking_packet::{Kind, MailboxId, Packet};
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use tokio::time::timeout;

use crate::frame::{self, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use crate::msg::{ACK_CURSOR_BASE, ErrorReason, Limits, Request, Response};
use crate::{NodeId, PROTOCOL_VERSION, pow, tls};

/// Plus ancienne version du protocole que ce client sait parler.
pub const MIN_PROTOCOL_VERSION: u16 = 0;
/// Nombre maximal d'éléments acceptés par appel à `fetch`.
pub const MAX_FETCH_ITEMS: usize = 10_000;
/// Nombre maximal d'octets acceptés par appel à `fetch`.
pub const MAX_FETCH_BYTES: usize = 64 << 20;
/// Tailles de page demandées, de la plus grande à la plus petite : après un
/// flux coupé ou un délai dépassé sur une page (lien trop lent pour la page
/// dans le délai d'écriture du nœud), la même page est redemandée plus petite.
pub const FETCH_PAGE_SIZES: [u32; 4] = [1 << 20, 256 << 10, 64 << 10, crate::MIN_PAGE_BYTES];
/// Délai d'une page de relève : au-delà du délai d'écriture maximal du nœud
/// (60 s), pour que ce soit le nœud qui coupe un lien trop lent.
pub const FETCH_PAGE_TIMEOUT: Duration = Duration::from_secs(70);
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
    #[error("budget de preuve de travail épuisé pour cette synchronisation")]
    PowBudget,
}

/// Position de reprise d'une relève, par boîte : `seen[boîte] = n` dit que
/// tous les paquets de cette boîte de curseur `<= n` ont été reçus (`n` est
/// toujours un curseur de paquets, sous `ACK_CURSOR_BASE` : un curseur
/// d'accusés sauterait les paquets arrivés depuis). Une tranche reprend au
/// minimum des boîtes qu'elle contient (0 pour une boîte inconnue) : la
/// liste des boîtes peut changer d'une relève à l'autre sans tout relire.
/// Les boîtes sont regroupées en tranches selon leur position : les boîtes
/// sans position ensemble, les autres par position décroissante, pour qu'une
/// boîte nouvelle ne ramène pas une boîte avancée au début.
/// Ne vaut que pour un même nœud.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchResume {
    pub seen: HashMap<[u8; 16], u64>,
}

impl FetchResume {
    /// Curseur de départ d'une tranche.
    fn start(&self, chunk: &[MailboxId]) -> Option<u64> {
        let min = chunk
            .iter()
            .map(|m| self.seen.get(&m.0).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        (min > 0).then_some(min)
    }

    /// Une page de suite `n` a été prise pour `chunk`.
    fn advance(&mut self, chunk: &[MailboxId], n: u64) {
        if n >= ACK_CURSOR_BASE {
            return;
        }
        for m in chunk {
            let e = self.seen.entry(m.0).or_insert(0);
            *e = (*e).max(n);
        }
    }

    /// Tranches de `per` boîtes au plus : boîtes sans position d'abord, puis
    /// les autres par position décroissante.
    fn chunks(&self, mailboxes: &[MailboxId], per: usize) -> Vec<Vec<MailboxId>> {
        let at = |m: &MailboxId| self.seen.get(&m.0).copied().unwrap_or(0);
        let mut zero: Vec<MailboxId> = mailboxes.iter().filter(|m| at(m) == 0).copied().collect();
        zero.dedup();
        let mut known: Vec<MailboxId> = mailboxes.iter().filter(|m| at(m) > 0).copied().collect();
        known.sort_by_key(|m| core::cmp::Reverse(at(m)));
        known.dedup();
        zero.chunks(per)
            .chain(known.chunks(per))
            .map(<[MailboxId]>::to_vec)
            .collect()
    }

    /// Ne garde que ces boîtes.
    pub fn retain(&mut self, mailboxes: &[MailboxId]) {
        self.seen.retain(|k, _| mailboxes.iter().any(|m| m.0 == *k));
    }
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
    cfg.transport_config(Arc::new(no_incoming_streams()));
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
    request_within(conn, req, REQUEST_TIMEOUT).await
}

async fn request_within(conn: &Connection, req: &Request, limit: Duration) -> Result<Response> {
    timeout(limit, async {
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
        let (pow_bits, limits) = hello(&conn, expected).await?;
        Ok(Session {
            endpoint,
            conn,
            node_id: expected,
            pow_bits,
            limits,
            truncated: false,
            pow_budget: None,
            pow_spent: 0,
            fetch_deadline: FETCH_DEADLINE,
        })
    }
}

/// Se connecte depuis l'endpoint d'un nœud : identité du serveur épinglée sur
/// `expected`, certificat client de `key`, puis `Hello` et vérification de la
/// version comme `Client::connect`. Les requêtes passent ensuite par
/// `request(&conn, &req)`.
pub async fn connect_peer(
    endpoint: &Endpoint,
    addr: SocketAddr,
    expected: NodeId,
    key: &SigningKey,
) -> Result<Connection> {
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls::node_client_config(expected, key))
            .map_err(|e| ClientError::Connect(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(no_incoming_streams()));
    let connecting = endpoint
        .connect_with(cfg, addr, tls::CERT_NAME)
        .map_err(|e| ClientError::Connect(e.to_string()))?;
    let conn = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|e| ClientError::Connect(e.to_string()))?;
    // TLS 1.3 : le serveur juge le certificat client après la fin de la
    // poignée de main du client ; son refus n'apparaît qu'au premier flux,
    // sous forme d'une connexion fermée (erreur de flux ou de connexion selon
    // le moment). Une connexion fermée pendant `Hello` est donc un échec de
    // connexion.
    match hello(&conn, expected).await {
        Ok(_) => Ok(conn),
        // Seules les erreurs de transport sont remappées : `Version`,
        // `Refused` et `Protocol` sont des réponses du nœud, rendues telles
        // quelles même si la connexion se ferme juste après.
        Err(e @ (ClientError::Frame(_) | ClientError::Connection(_))) => {
            match conn.close_reason() {
                Some(reason) => Err(ClientError::Connect(reason.to_string())),
                None => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Transport d'un appelant : le serveur n'ouvre aucun flux vers lui.
fn no_incoming_streams() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into());
    transport
}

/// Envoie `Hello` et vérifie la version et les paramètres annoncés ; rend la
/// difficulté de base et les limites du nœud.
async fn hello(conn: &Connection, expected: NodeId) -> Result<(u8, Limits)> {
    let hello = Request::Hello {
        version: PROTOCOL_VERSION,
        min_version: MIN_PROTOCOL_VERSION,
    };
    match request(conn, &hello).await? {
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
            Ok((pow_bits, limits))
        }
        Response::Error(ErrorReason::VersionTooOld) => Err(ClientError::Version),
        Response::Error(r) => Err(ClientError::Refused(r)),
        _ => Err(ClientError::Protocol("réponse inattendue à Hello")),
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
    /// Travail de preuve permis (essais attendus), `None` : sans borne.
    pow_budget: Option<u64>,
    /// Travail de preuve dépensé (essais attendus, `2^bits` par preuve).
    pow_spent: u64,
    /// Durée maximale d'un appel à `fetch` / `fetch_resumable`.
    fetch_deadline: Duration,
}

impl Session {
    /// Borne le travail de preuve des dépôts suivants (en essais attendus,
    /// `2^bits` par preuve, compté avant de chercher) : au-delà, `deposit`
    /// renvoie `ClientError::PowBudget` sans calculer.
    pub fn set_pow_budget(&mut self, budget: Option<u64>) {
        self.pow_budget = budget;
    }

    /// Durée maximale des appels de relève suivants (défaut `FETCH_DEADLINE`) :
    /// au-delà, relève partielle avec ce qui a été pris.
    pub fn set_fetch_deadline(&mut self, d: Duration) {
        self.fetch_deadline = d;
    }

    /// Travail de preuve dépensé par cette session.
    pub fn pow_spent(&self) -> u64 {
        self.pow_spent
    }

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
    /// (pas d'un accusé), d'abord à la difficulté de base plus le supplément
    /// du palier ; sur `PowTooWeak`, réessaie avec 2 bits de plus jusqu'à
    /// `MAX_POW_BITS`. `Ok(Err(raison))` : refus du nœud.
    pub async fn deposit(
        &mut self,
        packet: &[u8],
    ) -> Result<core::result::Result<(), ErrorReason>> {
        // Un paquet illisible part sans preuve : le nœud répondra `Malformed`.
        let target = match Packet::decode(packet) {
            Ok(p) if p.kind == Kind::Message => Some((p.mailbox, p.tier)),
            _ => None,
        };
        let Some((mailbox, tier)) = target else {
            return self.deposit_once(packet, 0).await;
        };
        let content = pow::content_hash(packet);
        let mut bits = self
            .pow_bits
            .saturating_add(pow::tier_surcharge(tier))
            .min(pow::MAX_POW_BITS);
        loop {
            let work = pow::expected_work(bits);
            if self
                .pow_budget
                .is_some_and(|b| self.pow_spent.saturating_add(work) > b)
            {
                return Err(ClientError::PowBudget);
            }
            self.pow_spent = self.pow_spent.saturating_add(work);
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
    /// 64 boîtes, pages suivies), depuis le début. S'arrête à
    /// `MAX_FETCH_ITEMS` éléments, `MAX_FETCH_BYTES` octets, `MAX_FETCH_PAGES`
    /// pages ou après `FETCH_DEADLINE` : voir `last_fetch_truncated`.
    pub async fn fetch(&mut self, mailboxes: &[MailboxId]) -> Result<Vec<Vec<u8>>> {
        let mut resume = FetchResume::default();
        self.fetch_resumable(mailboxes, &mut resume, MAX_FETCH_BYTES)
            .await
    }

    /// Comme `fetch`, mais reprend chaque tranche de boîtes d'après `resume`
    /// (voir `FetchResume`) et s'arrête à `max_bytes` octets (au moins une
    /// page est prise). En sortie, `resume` donne où reprendre ; une erreur
    /// le laisse à la dernière page prise.
    pub async fn fetch_resumable(
        &mut self,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.truncated = false;
        let per = usize::from(self.limits.max_mailboxes_per_fetch).min(MAX_MAILBOXES);
        let chunks = resume.chunks(mailboxes, per.max(1));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut pages = 0usize;
        // Indice dans `FETCH_PAGE_SIZES` : ne remonte pas au cours d'un appel.
        let mut size = 0usize;
        let deadline = tokio::time::Instant::now() + self.fetch_deadline;
        for chunk in &chunks {
            let mut cursor: Option<u64> = resume.start(chunk);
            loop {
                if pages >= MAX_FETCH_PAGES || tokio::time::Instant::now() >= deadline {
                    self.truncated = true;
                    return Ok(out);
                }
                pages += 1;
                let req = Request::Fetch {
                    mailboxes: chunk.to_vec(),
                    cursor,
                    max_bytes: FETCH_PAGE_SIZES[size],
                };
                let page = request_within(&self.conn, &req, FETCH_PAGE_TIMEOUT);
                let resp = match tokio::time::timeout_at(deadline, page).await {
                    Err(_) => {
                        self.truncated = true;
                        return Ok(out);
                    }
                    // Flux coupé ou trop lent : même curseur, page plus petite.
                    Ok(Err(ClientError::Frame(_) | ClientError::Timeout))
                        if size + 1 < FETCH_PAGE_SIZES.len() =>
                    {
                        size += 1;
                        continue;
                    }
                    Ok(r) => r?,
                };
                let (mut items, next) = match resp {
                    Response::Items { items, next } => (items, next),
                    // Débit épuisé après des pages déjà prises : relève
                    // partielle, la suite au prochain appel.
                    Response::Error(ErrorReason::RateLimited) if !out.is_empty() => {
                        self.truncated = true;
                        return Ok(out);
                    }
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
                let page_bytes = items
                    .iter()
                    .map(Vec::len)
                    .fold(0usize, usize::saturating_add);
                let over_items = out.len().saturating_add(items.len()) > MAX_FETCH_ITEMS;
                let over_bytes = bytes.saturating_add(page_bytes) > max_bytes;
                if !out.is_empty() && (over_items || over_bytes) {
                    // Page laissée : reprise à `cursor` la prochaine fois.
                    self.truncated = true;
                    return Ok(out);
                }
                if over_items {
                    // Première page déjà au-delà du plafond d'éléments (nœud
                    // hostile) : tronquée, sans avancer le curseur.
                    self.truncated = true;
                    items.truncate(MAX_FETCH_ITEMS);
                    return Ok(items);
                }
                bytes += page_bytes;
                out.append(&mut items);
                if let Some(n) = next {
                    resume.advance(chunk, n);
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
