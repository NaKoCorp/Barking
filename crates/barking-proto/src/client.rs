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
//! - the pagination cursor must strictly increase, an empty page cannot
//!   announce a continuation, and a page holding more than `MAX_PAGE_ITEMS`
//!   items is a protocol error;
//! - a node that paces its pages (continued pages far below the page size,
//!   or a continued page the next page's first item would have fitted in:
//!   an honest node fills its pages) until a cap or the call's deadline is
//!   reported as `FetchStop::Paced`;
//! - each request has a timeout;
//! - a page cut off in transit (slow link) is requested again smaller:
//!   1 MiB, 256 KiB, 64 KiB then 16 KiB, before giving up. The size reached
//!   is kept by the session for the next calls and grows again when full
//!   pages arrive fast. The size a caller may carry to a later session
//!   (`Session::page_bytes`) is never below `MIN_CARRIED_PAGE_BYTES` after
//!   a stream reset or garbage, which a node causes for free: only a page
//!   timeout at a measured low throughput carries a smaller size
//!   (`Session::page_confirmed`). A page is never asked bigger than what twice its
//!   timeout (or, once pages were measured, twice their expected time) lets
//!   fit in the time left: a short call on a slow link still makes progress.
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
use crate::msg::{ACK_CURSOR_BASE, ErrorReason, Limits, MAX_PAGE_ITEMS, Request, Response};
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
/// Longest timeout of a pickup page: beyond the maximum write timeout of
/// the node (60 s), so that the node is the one to cut off a link that is
/// too slow. Smaller pages get less (`page_timeout`).
pub const FETCH_PAGE_TIMEOUT: Duration = Duration::from_secs(70);
/// Smallest page size `Session::page_bytes` carries after a stream reset,
/// truncated or garbage bytes: a node causes those instantly, so they
/// prove nothing about the link. Only a page timeout at a measured
/// throughput too low for the page carries a smaller size.
pub const MIN_CARRIED_PAGE_BYTES: u32 = 64 << 10;
/// Index of `MIN_CARRIED_PAGE_BYTES` in `FETCH_PAGE_SIZES`.
const CARRIED_FLOOR: usize = 2;
const _: () = assert!(FETCH_PAGE_SIZES[CARRIED_FLOOR] == MIN_CARRIED_PAGE_BYTES);
/// Lowest throughput a page's timeout allows for (`page_timeout`).
pub const PAGE_TIMEOUT_RATE: u64 = 16 * 1024;
/// Part of a page's timeout that does not depend on its size.
pub const PAGE_TIMEOUT_BASE: Duration = Duration::from_secs(20);

/// Timeout of a pickup page of `bytes`: `PAGE_TIMEOUT_BASE` plus the time
/// it takes at `PAGE_TIMEOUT_RATE`, at most `FETCH_PAGE_TIMEOUT` (16 KiB:
/// 21 s, 64 KiB: 24 s, 256 KiB: 36 s, 1 MiB: 70 s).
pub fn page_timeout(bytes: u32) -> Duration {
    let transfer = Duration::from_secs_f64(f64::from(bytes) / PAGE_TIMEOUT_RATE as f64);
    PAGE_TIMEOUT_BASE
        .saturating_add(transfer)
        .min(FETCH_PAGE_TIMEOUT)
}

/// True if a page asked at `asked` bytes, holding `items` items of `bytes`
/// bytes in all, announced a continuation while far below what an honest
/// node puts in it: it fills a page until the next item would not fit
/// (`MAX_PACKET_LEN` at most) or `MAX_PAGE_ITEMS` items. The page size is
/// taken at half a response at most, so that a node with a smaller own limit
/// is not blamed.
fn underfilled(asked: u32, items: usize, bytes: usize) -> bool {
    let full = (asked as usize).min(MAX_RESPONSE_BYTES / 2);
    items < MAX_PAGE_ITEMS && bytes.saturating_add(barking_packet::fragment::MAX_PACKET_LEN) < full
}

/// True if a continued page asked at `asked` bytes, holding `items` items of
/// `bytes` bytes in all, was cut before the next page's first item, of
/// `next_len` bytes, although that item fitted in it: an honest node only
/// ends a page at `MAX_PAGE_ITEMS` items or when the next item does not fit.
/// The page size is taken at half a response at most (see `underfilled`).
/// At the smallest page size, where `underfilled` cannot tell, this still
/// catches a node pacing small items.
fn cut_early(asked: u32, items: usize, bytes: usize, next_len: usize) -> bool {
    let full = (asked as usize).min(MAX_RESPONSE_BYTES / 2);
    items < MAX_PAGE_ITEMS && bytes.saturating_add(next_len) <= full
}

/// Index in `FETCH_PAGE_SIZES` of the largest size not above `bytes` (the
/// smallest size below it).
fn size_index(bytes: u32) -> usize {
    FETCH_PAGE_SIZES
        .iter()
        .position(|&s| s <= bytes)
        .unwrap_or(FETCH_PAGE_SIZES.len() - 1)
}

/// True if a page of size `FETCH_PAGE_SIZES[i]` fits twice in `left`: twice
/// its expected time at the throughput `rate` measured in this call, or,
/// before any measure, twice its timeout.
fn page_fits(i: usize, left: Duration, rate: Option<f64>) -> bool {
    let bytes = FETCH_PAGE_SIZES[i];
    let need = match rate {
        Some(r) if r > 0.0 => Duration::from_secs_f64(f64::from(bytes) / r),
        _ => page_timeout(bytes),
    };
    need.saturating_mul(2) <= left
}

/// Size index a page is asked at: the session's `learned` one, smaller
/// while it does not fit in `left` (see `page_fits`), never below the
/// smallest.
fn page_for(learned: usize, left: Duration, rate: Option<f64>) -> usize {
    let mut i = learned.min(FETCH_PAGE_SIZES.len() - 1);
    while i + 1 < FETCH_PAGE_SIZES.len() && !page_fits(i, left, rate) {
        i += 1;
    }
    i
}

/// True if twice the expected time of a page of size `FETCH_PAGE_SIZES[i]`
/// at the throughput `rate` fits within its own timeout.
fn fits_timeout(i: usize, rate: f64) -> bool {
    let bytes = FETCH_PAGE_SIZES[i];
    rate > 0.0
        && Duration::from_secs_f64(f64::from(bytes) / rate).saturating_mul(2) <= page_timeout(bytes)
}

/// After a full page (one with a continuation) asked at size index `asked`,
/// with the session at `learned` and `rate` measured: the next size up if
/// twice its expected time fits within its own timeout, else `learned`.
fn grown(learned: usize, asked: usize, rate: Option<f64>) -> usize {
    match (asked.checked_sub(1), rate) {
        (Some(up), Some(r)) if asked <= learned && fits_timeout(up, r) => up,
        _ => learned,
    }
}

/// Page size learned on a link: the one the session asks (`page`), and
/// what of it a caller may carry to a later session (`carried`).
#[derive(Clone, Copy, Debug, Default)]
struct PageLearn {
    /// Index in `FETCH_PAGE_SIZES` of the size the next page starts from.
    page: usize,
    /// Smallest size (largest index) carried whatever the cause: the size
    /// set by the caller, or a shrink, at most down to `CARRIED_FLOOR`.
    kept: usize,
    /// Largest index of a page that timed out.
    timed_out: Option<usize>,
    /// Last throughput measured (bytes per second).
    rate: Option<f64>,
}

impl PageLearn {
    fn starting_at(page: usize) -> Self {
        PageLearn {
            page,
            kept: page,
            timed_out: None,
            rate: None,
        }
    }

    /// The page at size index `size` failed: the session goes on smaller,
    /// but only a timeout may carry a size below `CARRIED_FLOOR`.
    fn shrink(&mut self, size: usize, timeout: bool) {
        let next = (size + 1).min(FETCH_PAGE_SIZES.len() - 1);
        self.page = self.page.max(next);
        self.kept = self.kept.max(next.min(CARRIED_FLOOR));
        if timeout {
            self.timed_out = self.timed_out.max(Some(size));
        }
    }

    /// Size index a timeout carries: the one below the page that timed
    /// out, if that is not below `CARRIED_FLOOR` or if the throughput
    /// measured makes the page too large for its timeout.
    fn timeout_floor(&self) -> Option<usize> {
        let t = self.timed_out?;
        let next = (t + 1).min(FETCH_PAGE_SIZES.len() - 1);
        (next <= CARRIED_FLOOR || self.rate.is_some_and(|r| !fits_timeout(t, r))).then_some(next)
    }

    /// Size index a caller may carry: the session's, not below what the
    /// failures justify.
    fn carried(&self) -> usize {
        self.page
            .min(self.kept.max(self.timeout_floor().unwrap_or(0)))
    }

    /// True if a timeout justifies the carried size.
    fn confirmed(&self) -> bool {
        self.timeout_floor().is_some_and(|t| t >= self.carried())
    }
}
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
    /// The item or page cap, or the call's deadline, after the node sent a
    /// continued page far below the size asked, or one the next page's
    /// first item would have fitted in (an honest node fills its pages):
    /// the node's doing, not the link's.
    Paced,
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
            learn: PageLearn::default(),
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
    /// Page size reached on this link, kept from one call to the next.
    learn: PageLearn,
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

    /// Page size the next pickup starts from (one of `FETCH_PAGE_SIZES`,
    /// the largest not above `bytes`): typically the `page_bytes` of an
    /// earlier session with the same node. Starts the evidence of
    /// `page_bytes` and `page_confirmed` over.
    pub fn set_page_bytes(&mut self, bytes: u32) {
        self.learn = PageLearn::starting_at(size_index(bytes));
    }

    /// Page size to carry to a later session with this node (one of
    /// `FETCH_PAGE_SIZES`): the size reached on this link (smaller after
    /// pages cut off in transit, larger after full pages that came fast),
    /// but never below `MIN_CARRIED_PAGE_BYTES` (or the size set) unless a
    /// page timed out at a measured throughput too low for it. A reset or
    /// garbage costs a node nothing: it may shrink this session's pages,
    /// not the ones of the sessions to come.
    pub fn page_bytes(&self) -> u32 {
        FETCH_PAGE_SIZES[self.learn.carried()]
    }

    /// True if, since the session started or `set_page_bytes`, a page
    /// timeout (at a measured low throughput below `MIN_CARRIED_PAGE_BYTES`)
    /// justified `page_bytes`: a caller lets a carried size grow back when
    /// no timeout confirms it.
    pub fn page_confirmed(&self) -> bool {
        self.learn.confirmed()
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
        // Throughput of the last page that measured it (bytes per second).
        let mut rate: Option<f64> = None;
        // A continued page came far below the size asked, or without an
        // item that fitted in it.
        let mut paced = false;
        let node_cap = |paced: bool, client: FetchStop| {
            if paced { FetchStop::Paced } else { client }
        };
        let deadline = tokio::time::Instant::now() + self.fetch_deadline;
        for chunk in &chunks {
            let mut cursor: Option<u64> = resume.start(chunk);
            // Last continued page taken in this chunk: (size asked, items,
            // bytes).
            let mut continued: Option<(u32, usize, usize)> = None;
            loop {
                if pages >= MAX_FETCH_PAGES {
                    self.stop = node_cap(paced, FetchStop::ClientLimit);
                    return Ok(out);
                }
                if tokio::time::Instant::now() >= deadline {
                    self.stop = node_cap(paced, FetchStop::Deadline);
                    return Ok(out);
                }
                pages += 1;
                let sent = tokio::time::Instant::now();
                let size = page_for(
                    self.learn.page,
                    deadline.saturating_duration_since(sent),
                    rate,
                );
                let req = Request::Fetch {
                    mailboxes: chunk.to_vec(),
                    cursor,
                    max_bytes: FETCH_PAGE_SIZES[size],
                };
                let page = request_within(&self.conn, &req, page_timeout(FETCH_PAGE_SIZES[size]));
                let resp = match tokio::time::timeout_at(deadline, page).await {
                    Err(_) => {
                        self.stop = node_cap(paced, FetchStop::Deadline);
                        return Ok(out);
                    }
                    // Stream cut off or too slow: same cursor, smaller page,
                    // kept for the next pages and calls (carried to later
                    // sessions only as `PageLearn::shrink` allows).
                    Ok(Err(e @ (ClientError::Frame(_) | ClientError::Timeout)))
                        if size + 1 < FETCH_PAGE_SIZES.len() =>
                    {
                        self.learn.shrink(size, matches!(e, ClientError::Timeout));
                        rate = None;
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
                if items.len() > MAX_PAGE_ITEMS {
                    return Err(ClientError::Protocol("page beyond the item cap"));
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
                if next.is_some() && underfilled(FETCH_PAGE_SIZES[size], items.len(), page_bytes) {
                    paced = true;
                }
                if let (Some((asked, n, b)), Some(first)) = (continued, items.first())
                    && cut_early(asked, n, b, first.len())
                {
                    paced = true;
                }
                // A first page is never beyond the item cap (`MAX_PAGE_ITEMS`
                // is far below it).
                let over_items = out.len().saturating_add(items.len()) > MAX_FETCH_ITEMS;
                let over_bytes = bytes.saturating_add(page_bytes) > max_bytes;
                if !out.is_empty() && (over_items || over_bytes) {
                    // Page left: resume at `cursor` next time.
                    self.stop = if over_bytes {
                        FetchStop::ClientLimit
                    } else {
                        node_cap(paced, FetchStop::ClientLimit)
                    };
                    return Ok(out);
                }
                // Pages too small to measure more than the round trip
                // leave the estimate as it was.
                if page_bytes >= crate::MIN_PAGE_BYTES as usize / 2 {
                    let took = sent.elapsed().as_secs_f64().max(1e-3);
                    rate = Some(page_bytes as f64 / took);
                    self.learn.rate = rate;
                }
                if next.is_some() {
                    self.learn.page = grown(self.learn.page, size, rate);
                }
                continued = next.map(|_| (FETCH_PAGE_SIZES[size], items.len(), page_bytes));
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: f64 = 1_048_576.0;

    #[test]
    fn page_timeouts_grow_with_the_page() {
        let t: Vec<u64> = FETCH_PAGE_SIZES
            .iter()
            .map(|&b| page_timeout(b).as_secs())
            .collect();
        assert_eq!(t, [FETCH_PAGE_TIMEOUT.as_secs(), 36, 24, 21]);
    }

    #[test]
    fn first_page_fits_twice_in_the_time_left() {
        // No measure yet: twice the timeout.
        assert_eq!(page_for(0, Duration::from_secs(140), None), 0);
        assert_eq!(page_for(0, Duration::from_secs(90), None), 1);
        assert_eq!(page_for(0, Duration::from_secs(45), None), 3);
        // Never below the smallest, never above the learned size.
        assert_eq!(page_for(0, Duration::from_secs(1), None), 3);
        assert_eq!(page_for(2, Duration::from_secs(1_000), None), 2);
        // Once measured: twice the expected time.
        assert_eq!(page_for(0, Duration::from_secs(5), Some(MIB)), 0);
        assert_eq!(page_for(0, Duration::from_secs(5), Some(32.0 * 1024.0)), 2);
    }

    #[test]
    fn full_fast_pages_grow_the_size_one_step() {
        // 64 KiB pages at 32 KiB/s: 256 KiB would take 8 s, within half
        // its 36 s timeout.
        assert_eq!(grown(2, 2, Some(32.0 * 1024.0)), 1);
        // 256 KiB pages at 16 KiB/s: 1 MiB would take 64 s.
        assert_eq!(grown(1, 1, Some(16.0 * 1024.0)), 1);
        // A page asked smaller than learned (short time left) proves nothing.
        assert_eq!(grown(1, 3, Some(MIB)), 1);
        assert_eq!(grown(0, 0, Some(MIB)), 0);
        assert_eq!(grown(2, 2, None), 2);
    }

    #[test]
    fn continued_pages_far_below_the_size_are_underfilled() {
        use barking_packet::fragment::MAX_PACKET_LEN;
        let mib = FETCH_PAGE_SIZES[0];
        // An honest node stops when the next item would not fit.
        assert!(!underfilled(mib, 40, (512 << 10) - MAX_PACKET_LEN));
        assert!(underfilled(mib, 40, (512 << 10) - MAX_PACKET_LEN - 1));
        assert!(underfilled(64 << 10, 1, 8));
        // Or at `MAX_PAGE_ITEMS` items, however small.
        assert!(!underfilled(mib, MAX_PAGE_ITEMS, 8 * MAX_PAGE_ITEMS));
        // A 16 KiB page may hold a single item of any size.
        assert!(!underfilled(crate::MIN_PAGE_BYTES, 1, 8));
    }

    #[test]
    fn resets_carry_no_page_below_64_kib() {
        // Resets at every size: the session goes down to 16 KiB, what it
        // carries stops at 64 KiB.
        let mut l = PageLearn::default();
        for size in 0..3 {
            l.shrink(size, false);
        }
        assert_eq!(FETCH_PAGE_SIZES[l.page], crate::MIN_PAGE_BYTES);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], MIN_CARRIED_PAGE_BYTES);
        assert!(!l.confirmed());
        // Even with a low throughput measured afterwards.
        l.rate = Some(1024.0);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], MIN_CARRIED_PAGE_BYTES);
        // Above 64 KiB, a reset is carried as is.
        let mut l = PageLearn::default();
        l.shrink(0, false);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], 256 << 10);
        // A size set by the caller stays carried.
        let mut l = PageLearn::starting_at(3);
        l.shrink(3, false);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], crate::MIN_PAGE_BYTES);
    }

    #[test]
    fn only_a_timeout_at_a_measured_low_throughput_carries_16_kib() {
        // A 64 KiB timeout before any measure: 64 KiB carried.
        let mut l = PageLearn::starting_at(2);
        l.shrink(2, true);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], MIN_CARRIED_PAGE_BYTES);
        assert!(!l.confirmed());
        // A throughput at which 64 KiB fits twice in its timeout (24 s):
        // the timeout proves nothing about the link.
        l.rate = Some(8.0 * 1024.0);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], MIN_CARRIED_PAGE_BYTES);
        // 4 KiB/s: 64 KiB takes 16 s, twice that is beyond 24 s.
        l.rate = Some(4.0 * 1024.0);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], crate::MIN_PAGE_BYTES);
        assert!(l.confirmed());
        // Timeouts above 64 KiB carry their size and confirm it.
        let mut l = PageLearn::default();
        l.shrink(0, true);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], 256 << 10);
        assert!(l.confirmed());
        // A later reset below it is not confirmed by that timeout.
        l.shrink(1, false);
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], MIN_CARRIED_PAGE_BYTES);
        assert!(!l.confirmed());
        // Pages growing back: the larger size is carried.
        l.page = 1;
        assert_eq!(FETCH_PAGE_SIZES[l.carried()], 256 << 10);
        assert!(l.confirmed());
    }

    #[test]
    fn page_cut_before_an_item_that_fitted_is_cut_early() {
        let min = crate::MIN_PAGE_BYTES;
        // One 245-byte item per 16 KiB page: the next one fitted.
        assert!(cut_early(min, 1, 245, 245));
        assert!(cut_early(min, 10, 16_000, 384));
        // The honest node's two reasons to end a page (`rules::fetch`):
        // the next item does not fit, or the item cap.
        assert!(!cut_early(min, 16, 16 * 1024, 1024));
        assert!(!cut_early(min, 15, 15 * 1024 + 245, 1024));
        assert!(!cut_early(min, 1, 245, 16_384));
        assert!(!cut_early(
            1 << 20,
            MAX_PAGE_ITEMS,
            245 * MAX_PAGE_ITEMS,
            245
        ));
        // A single item larger than the page.
        assert!(!cut_early(min, 1, 16_384 + 245, 245));
        // Pages beyond half a response are taken at half a response: a
        // node whose own limit is that low is not blamed.
        assert!(!cut_early(1 << 20, 500, 512 << 10, 1));
    }

    #[test]
    fn set_page_bytes_takes_the_largest_size_not_above() {
        assert_eq!(size_index(u32::MAX), 0);
        assert_eq!(size_index(300 << 10), 1);
        assert_eq!(size_index(64 << 10), 2);
        assert_eq!(size_index(1), 3);
    }
}
