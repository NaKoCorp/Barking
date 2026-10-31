//! QUIC client (spec §7.1): pinned connection, `Hello`, deposit and pickup.
//!
//! The client distrusts the node as much as the node distrusts it:
//! - a difficulty announced beyond `MAX_POW_BITS` is a protocol
//!   error (a hostile node cannot make the client spin forever);
//! - a pickup stops at `MAX_FETCH_ITEMS` items, the byte budget
//!   of the call (`MAX_FETCH_BYTES` by default), `MAX_FETCH_PAGES` pages or
//!   `FETCH_DEADLINE` per call; the rest waits for the next pickup (nothing
//!   is deleted on read) and `Session::last_fetch_truncated` reports it,
//!   `Session::last_fetch_stop` saying why. A page is taken whole or not at all; `FetchResume`
//!   keeps the position reached so that the next pickup resumes there
//!   instead of rereading the beginning (a flooded mailbox does not block the rest);
//! - the proof of work of a deposit starts from the base difficulty plus the
//!   tier supplement, rises by 2 bits on `PowTooWeak`, and may be
//!   bounded by a work budget (`Session::set_pow_budget`);
//! - the pagination cursor must strictly increase, and an empty page cannot
//!   announce a continuation;
//! - each request has a timeout;
//! - a page cut off in transit (slow link) is requested again smaller:
//!   1 MiB, 256 KiB, 64 KiB then 16 KiB, before giving up.
//!
//! Picked-up items are returned as is: an acknowledgement whose mailbox field
//! differs from the mailbox picked up is not discarded (the acknowledgement is stored in
//! each mailbox that held the packet).

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

/// Oldest protocol version this client can speak.
pub const MIN_PROTOCOL_VERSION: u16 = 0;
/// Maximum number of items accepted per `fetch` call.
pub const MAX_FETCH_ITEMS: usize = 10_000;
/// Maximum number of bytes accepted per `fetch` call.
pub const MAX_FETCH_BYTES: usize = 64 << 20;
/// Page sizes requested, from largest to smallest: after a
/// stream cut off or a timeout on a page (link too slow for the page
/// within the node's write timeout), the same page is requested again smaller.
pub const FETCH_PAGE_SIZES: [u32; 4] = [1 << 20, 256 << 10, 64 << 10, crate::MIN_PAGE_BYTES];
/// Timeout for a pickup page: beyond the maximum write timeout of the node
/// (60 s), so that the node is the one to cut off a link that is too slow.
pub const FETCH_PAGE_TIMEOUT: Duration = Duration::from_secs(70);
/// Maximum number of pages followed per `fetch` call.
pub const MAX_FETCH_PAGES: usize = 1_000;
/// Maximum duration of a `fetch` call.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(120);
/// Timeout for establishing the connection (handshake included).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a request (send and response).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// At most this many mailboxes per `Fetch` request, whatever the node announces.
const MAX_MAILBOXES: usize = 64;
/// Difficulty increase after `PowTooWeak`.
const POW_RETRY_STEP: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot connect to the node: {0}")]
    Connect(String),
    #[error("connection to the node lost: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("protocol version incompatible with this node")]
    Version,
    #[error("the node refuses: {}", .0.describe())]
    Refused(ErrorReason),
    #[error("invalid response from the node: {0}")]
    Protocol(&'static str),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("the node does not respond in time")]
    Timeout,
    #[error("proof-of-work budget exhausted for this synchronization")]
    PowBudget,
}

/// Resume position of a pickup, per mailbox: `seen[mailbox] = n` says that
/// all packets of this mailbox with cursor `<= n` have been received (`n` is
/// always a packet cursor, below `ACK_CURSOR_BASE`: an acknowledgement
/// cursor would skip packets that arrived since). A slice resumes at the
/// minimum of the mailboxes it contains (0 for an unknown mailbox): the
/// list of mailboxes may change from one pickup to the next without rereading everything.
/// Mailboxes are grouped into slices by position: mailboxes
/// without a position together, the others by decreasing position, so that a
/// new mailbox does not bring an advanced mailbox back to the start.
/// Valid only for a single node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchResume {
    pub seen: HashMap<[u8; 16], u64>,
}

impl FetchResume {
    /// Starting cursor of a slice.
    fn start(&self, chunk: &[MailboxId]) -> Option<u64> {
        let min = chunk
            .iter()
            .map(|m| self.seen.get(&m.0).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        (min > 0).then_some(min)
    }

    /// A page with continuation `n` was taken for `chunk`.
    fn advance(&mut self, chunk: &[MailboxId], n: u64) {
        if n >= ACK_CURSOR_BASE {
            return;
        }
        for m in chunk {
            let e = self.seen.entry(m.0).or_insert(0);
            *e = (*e).max(n);
        }
    }

    /// Slices of at most `per` mailboxes: mailboxes without a position first, then
    /// the others by decreasing position.
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

    /// Keeps only these mailboxes.
    pub fn retain(&mut self, mailboxes: &[MailboxId]) {
        self.seen.retain(|k, _| mailboxes.iter().any(|m| m.0 == *k));
    }
}

/// Why a pickup returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchStop {
    /// Every mailbox read to its end.
    Complete,
    /// The node's rate limit, after pages already taken.
    RateLimited,
    /// A client cap: items, bytes or pages.
    ClientLimit,
    /// The call's deadline (`set_fetch_deadline`).
    Deadline,
    /// Connection lost, or a page given up at the smallest size, after pages
    /// already taken.
    Connection,
}

pub type Result<T> = core::result::Result<T, ClientError>;

/// Opens a QUIC connection pinned on `expected`, without `Hello`. The endpoint
/// must live as long as the connection.
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

/// Sends a request on a new stream and reads the single response.
pub async fn request(conn: &Connection, req: &Request) -> Result<Response> {
    request_within(conn, req, REQUEST_TIMEOUT).await
}

async fn request_within(conn: &Connection, req: &Request, limit: Duration) -> Result<Response> {
    timeout(limit, async {
        let (mut send, mut recv) = conn.open_bi().await?;
        frame::write(&mut send, req, MAX_REQUEST_BYTES).await?;
        // The stream may already be closed by the node: the read will tell.
        let _ = send.finish();
        Ok(frame::read::<Response>(&mut recv, MAX_RESPONSE_BYTES).await?)
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Client entry point.
pub struct Client;

impl Client {
    /// Connects to node `expected` (identity verified by TLS), sends
    /// `Hello` and checks the announced version and parameters.
    pub async fn connect(addr: SocketAddr, expected: NodeId) -> Result<Session> {
        let (endpoint, conn) = open_connection(addr, expected).await?;
        let (pow_bits, limits) = hello(&conn, expected).await?;
        Ok(Session {
            endpoint,
            conn,
            node_id: expected,
            pow_bits,
            limits,
            stop: FetchStop::Complete,
            pow_budget: None,
            pow_spent: 0,
            fetch_deadline: FETCH_DEADLINE,
        })
    }
}

/// Connects from a node's endpoint: server identity pinned on
/// `expected`, client certificate of `key`, then `Hello` and version
/// check like `Client::connect`. Requests then go through
/// `request(&conn, &req)`.
pub async fn connect_peer(
    endpoint: &Endpoint,
    addr: SocketAddr,
    expected: NodeId,
    key: &SigningKey,
) -> Result<Connection> {
    let identity = tls::NodeIdentity::new(key);
    Ok(connect_node(endpoint, addr, expected, &identity).await?.0)
}

/// Like `connect_peer`, with the node identity already built (once
/// for all its connections); also returns the base difficulty announced
/// by the called node in `Hello`.
pub async fn connect_node(
    endpoint: &Endpoint,
    addr: SocketAddr,
    expected: NodeId,
    identity: &tls::NodeIdentity,
) -> Result<(Connection, u8)> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls::node_client_config_for(
        expected, identity,
    ))
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
    // TLS 1.3: the server judges the client certificate after the end of the
    // client handshake; its rejection only appears on the first stream,
    // as a closed connection (stream or connection error depending on
    // timing). A connection closed during `Hello` is therefore a connection
    // failure.
    match hello(&conn, expected).await {
        Ok((pow_bits, _)) => Ok((conn, pow_bits)),
        // Only transport errors are remapped: `Version`,
        // `Refused` and `Protocol` are responses from the node, returned as
        // they are even if the connection closes right after.
        Err(e @ (ClientError::Frame(_) | ClientError::Connection(_))) => {
            match conn.close_reason() {
                Some(reason) => Err(ClientError::Connect(reason.to_string())),
                None => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Transport of a caller: the server opens no stream towards it.
fn no_incoming_streams() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into());
    transport
}

/// Sends `Hello` and checks the announced version and parameters; returns the
/// base difficulty and the node's limits.
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
                return Err(ClientError::Protocol("announced identifier differs"));
            }
            if min_version > version {
                return Err(ClientError::Protocol("inconsistent announced versions"));
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
                return Err(ClientError::Protocol("required proof of work too strong"));
            }
            if limits.max_mailboxes_per_fetch == 0 {
                return Err(ClientError::Protocol("pickup limit is zero"));
            }
            Ok((pow_bits, limits))
        }
        Response::Error(ErrorReason::VersionTooOld) => Err(ClientError::Version),
        Response::Error(r) => Err(ClientError::Refused(r)),
        _ => Err(ClientError::Protocol("unexpected response to Hello")),
    }
}

/// Connection established with a node, after `Hello`.
pub struct Session {
    endpoint: Endpoint,
    conn: Connection,
    node_id: NodeId,
    pow_bits: u8,
    limits: Limits,
    /// Why the last pickup stopped.
    stop: FetchStop,
    /// Permitted proof work (expected attempts), `None`: unbounded.
    pow_budget: Option<u64>,
    /// Proof work spent (expected attempts, `2^bits` per proof).
    pow_spent: u64,
    /// Maximum duration of a `fetch` / `fetch_resumable` call.
    fetch_deadline: Duration,
}

impl Session {
    /// Bounds the proof work of subsequent deposits (in expected attempts,
    /// `2^bits` per proof, counted before searching): beyond that, `deposit`
    /// returns `ClientError::PowBudget` without computing.
    pub fn set_pow_budget(&mut self, budget: Option<u64>) {
        self.pow_budget = budget;
    }

    /// Maximum duration of subsequent pickup calls (default `FETCH_DEADLINE`):
    /// beyond that, partial pickup with what was taken.
    pub fn set_fetch_deadline(&mut self, d: Duration) {
        self.fetch_deadline = d;
    }

    /// Proof work spent by this session.
    pub fn pow_spent(&self) -> u64 {
        self.pow_spent
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Base difficulty announced by the node (at most `MAX_POW_BITS`).
    pub fn pow_bits(&self) -> u8 {
        self.pow_bits
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Underlying QUIC connection (tests, diagnostics).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Raw request on this connection.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        request(&self.conn, req).await
    }

    /// Deposits an encoded packet. Computes the proof of work of a message
    /// (not of an acknowledgement), first at the base difficulty plus the
    /// tier supplement; on `PowTooWeak`, retries with 2 more bits up to
    /// `MAX_POW_BITS`. `Ok(Err(reason))`: refusal by the node.
    pub async fn deposit(
        &mut self,
        packet: &[u8],
    ) -> Result<core::result::Result<(), ErrorReason>> {
        // An unreadable packet goes out without proof: the node will answer `Malformed`.
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
            _ => Err(ClientError::Protocol("unexpected response to Deposit")),
        }
    }

    /// Picks up packets and acknowledgements pending for `mailboxes` (split into
    /// 64 mailboxes, pages followed), from the beginning. Stops at
    /// `MAX_FETCH_ITEMS` items, `MAX_FETCH_BYTES` bytes, `MAX_FETCH_PAGES`
    /// pages or after `FETCH_DEADLINE`: see `last_fetch_truncated`.
    pub async fn fetch(&mut self, mailboxes: &[MailboxId]) -> Result<Vec<Vec<u8>>> {
        let mut resume = FetchResume::default();
        self.fetch_resumable(mailboxes, &mut resume, MAX_FETCH_BYTES)
            .await
    }

    /// Like `fetch`, but resumes each slice of mailboxes from `resume`
    /// (see `FetchResume`) and stops at `max_bytes` bytes (at least one
    /// page is taken). On output, `resume` gives where to resume; an error
    /// leaves it at the last page taken.
    pub async fn fetch_resumable(
        &mut self,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.stop = FetchStop::Complete;
        let per = usize::from(self.limits.max_mailboxes_per_fetch).min(MAX_MAILBOXES);
        let chunks = resume.chunks(mailboxes, per.max(1));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut pages = 0usize;
        // Index into `FETCH_PAGE_SIZES`: does not go back up during a call.
        let mut size = 0usize;
        let deadline = tokio::time::Instant::now() + self.fetch_deadline;
        for chunk in &chunks {
            let mut cursor: Option<u64> = resume.start(chunk);
            loop {
                if pages >= MAX_FETCH_PAGES {
                    self.stop = FetchStop::ClientLimit;
                    return Ok(out);
                }
                if tokio::time::Instant::now() >= deadline {
                    self.stop = FetchStop::Deadline;
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
                        self.stop = FetchStop::Deadline;
                        return Ok(out);
                    }
                    // Stream cut off or too slow: same cursor, smaller page.
                    Ok(Err(ClientError::Frame(_) | ClientError::Timeout))
                        if size + 1 < FETCH_PAGE_SIZES.len() =>
                    {
                        size += 1;
                        continue;
                    }
                    // Connection lost or page given up after pages already
                    // taken: partial pickup, the rest on the next call.
                    Ok(Err(
                        ClientError::Frame(_) | ClientError::Timeout | ClientError::Connection(_),
                    )) if !out.is_empty() => {
                        self.stop = FetchStop::Connection;
                        return Ok(out);
                    }
                    Ok(r) => r?,
                };
                let (mut items, next) = match resp {
                    Response::Items { items, next } => (items, next),
                    // Throughput exhausted after pages already taken: partial
                    // pickup, the rest on the next call.
                    Response::Error(ErrorReason::RateLimited) if !out.is_empty() => {
                        self.stop = FetchStop::RateLimited;
                        return Ok(out);
                    }
                    Response::Error(r) => return Err(ClientError::Refused(r)),
                    _ => return Err(ClientError::Protocol("unexpected response to Fetch")),
                };
                if next.is_some() && items.is_empty() {
                    return Err(ClientError::Protocol("empty page with continuation"));
                }
                if let (Some(n), Some(c)) = (next, cursor)
                    && n <= c
                {
                    return Err(ClientError::Protocol("non-increasing pickup cursor"));
                }
                let page_bytes = items
                    .iter()
                    .map(Vec::len)
                    .fold(0usize, usize::saturating_add);
                let over_items = out.len().saturating_add(items.len()) > MAX_FETCH_ITEMS;
                let over_bytes = bytes.saturating_add(page_bytes) > max_bytes;
                if !out.is_empty() && (over_items || over_bytes) {
                    // Page left: resume at `cursor` next time.
                    self.stop = FetchStop::ClientLimit;
                    return Ok(out);
                }
                if over_items {
                    // First page already beyond the item cap (hostile
                    // node): truncated, without advancing the cursor.
                    self.stop = FetchStop::ClientLimit;
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

    /// True if the last pickup stopped at a client cap:
    /// more items are waiting on the node.
    pub fn last_fetch_truncated(&self) -> bool {
        self.stop != FetchStop::Complete
    }

    /// Why the last successful pickup stopped (meaningless after an error).
    pub fn last_fetch_stop(&self) -> FetchStop {
        self.stop
    }

    /// Closes the connection cleanly.
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"fin");
        let _ = timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
    }
}

/// Proof nonce search outside the async loop (pure computation).
async fn solve(content: [u8; 32], mailbox: MailboxId, bits: u8) -> Result<u64> {
    tokio::task::spawn_blocking(move || pow::solve(&content, &mailbox, bits))
        .await
        .map_err(|_| ClientError::Protocol("proof computation interrupted"))?
        .ok_or(ClientError::Protocol("required proof of work too strong"))
}
