//! Network side of the sync: the traits a transport implements, the QUIC
//! implementation on a `Session` kept per node, and the dialer wrapper that
//! notes lookup and ping outcomes for the score.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use barking_packet::MailboxId;
use barking_proto::client::{Client, ClientError, FetchResume, FetchStop, Session};
use barking_proto::push::Subscription;
use barking_proto::{ErrorReason, NodeId, NodeRecord};

use crate::discover::{DIAL_TIMEOUT, DialError, Dialer, QuicDialer, dial_error};

/// Answer to a fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchReply {
    /// Items, and why the fetch stopped (`FetchStop::Complete`: ran to the end).
    Items {
        items: Vec<Vec<u8>>,
        stop: FetchStop,
    },
    /// Rate limit exhausted before the first page.
    RateLimited,
}

/// Fetch page size of the link to a node: on input, the size to start from;
/// on output, the size to carry to the next fetches (`Session::page_bytes`)
/// and whether a page timeout at a measured low throughput confirmed it
/// (`Session::page_confirmed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkPage {
    pub bytes: u32,
    pub confirmed: bool,
}

impl LinkPage {
    /// After a fetch that started from `self` (rounded down by the session
    /// to `start`, one of `FETCH_PAGE_SIZES`), the session carrying
    /// `reached`: `reached`, except that an unchanged and unconfirmed size
    /// keeps its exact value, so that a size growing back by doubling
    /// (`NetState::recover_page_bytes`) is not rounded down again at every
    /// sync.
    pub(crate) fn reached(self, start: u32, reached: u32, confirmed: bool) -> LinkPage {
        let bytes = if reached == start && !confirmed {
            self.bytes
        } else {
            reached
        };
        LinkPage { bytes, confirmed }
    }
}

/// What happened to a deposit that reached the node or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositOutcome {
    /// The node answered: accepted or refused.
    Answered(Result<(), ErrorReason>),
    /// Proof-of-work budget exhausted: nothing sent.
    PowBudget,
}

/// Answer to a deposit, with the proof work it spent (even on failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositReply {
    pub outcome: Result<DepositOutcome, DialError>,
    pub pow_spent: u64,
}

/// A connection to a node kept for the whole sync.
pub trait Connector {
    type Conn: Send;

    /// Connects pinned on `id` and says `Hello`: a success proves the node.
    fn connect(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<Self::Conn, DialError>> + Send;

    fn close(&self, conn: Self::Conn) -> impl Future<Output = ()> + Send;
}

/// Fetches on a kept connection (see `Session::fetch_resumable`).
pub trait Fetcher: Connector {
    /// Fetches `mailboxes` from `resume`, at most `max_bytes` bytes and
    /// `slice` long, starting with pages of `page.bytes` (see
    /// `Session::set_page_bytes`); `resume` gives where to resume
    /// afterwards, `page` the page size to carry (see `LinkPage`).
    fn fetch(
        &self,
        conn: &mut Self::Conn,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
        slice: Duration,
        page: &mut LinkPage,
    ) -> impl Future<Output = Result<FetchReply, DialError>> + Send;
}

/// Deposits on a kept connection (see `Session::deposit`).
pub trait Depositor: Connector {
    /// Deposits `packet`, spending at most `pow_left` proof work.
    fn deposit(
        &self,
        conn: &mut Self::Conn,
        packet: &[u8],
        pow_left: u64,
    ) -> impl Future<Output = DepositReply> + Send;
}

/// Answer to a subscription, with the proof work it spent (even on
/// failure). `DepositOutcome::Answered` carries the node's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribeReply {
    pub outcome: Result<DepositOutcome, DialError>,
    pub pow_spent: u64,
}

/// Wake subscriptions on a kept connection (see `Session::subscribe`).
pub trait Subscriber: Connector {
    /// The node announced that it accepts wake subscriptions.
    fn wake_supported(&self, conn: &Self::Conn) -> bool;

    /// Registers `sub`, spending at most `pow_left` proof work.
    fn subscribe(
        &self,
        conn: &mut Self::Conn,
        sub: &Subscription,
        pow_left: u64,
    ) -> impl Future<Output = SubscribeReply> + Send;

    /// Cancels the subscriptions of `mailbox` made with `cancel_secret`; a
    /// refusal is `DialError::Refused`.
    fn unsubscribe(
        &self,
        conn: &mut Self::Conn,
        mailbox: MailboxId,
        cancel_secret: [u8; 32],
    ) -> impl Future<Output = Result<(), DialError>> + Send;
}

impl Connector for QuicDialer {
    type Conn = Session;

    async fn connect(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Session, DialError> {
        let mut last = DialError::NoAddress;
        for &addr in addrs {
            match tokio::time::timeout(DIAL_TIMEOUT, Client::connect(addr, id)).await {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(e)) => last = dial_error(e),
                Err(_) => last = DialError::Timeout,
            }
        }
        Err(last)
    }

    async fn close(&self, conn: Session) {
        conn.close().await;
    }
}

impl Fetcher for QuicDialer {
    async fn fetch(
        &self,
        conn: &mut Session,
        mailboxes: &[MailboxId],
        resume: &mut FetchResume,
        max_bytes: usize,
        slice: Duration,
        page: &mut LinkPage,
    ) -> Result<FetchReply, DialError> {
        if mailboxes.is_empty() {
            return Ok(FetchReply::Items {
                items: Vec::new(),
                stop: FetchStop::Complete,
            });
        }
        conn.set_fetch_deadline(slice);
        conn.set_page_bytes(page.bytes);
        let start = conn.page_bytes();
        let r = conn.fetch_resumable(mailboxes, resume, max_bytes).await;
        *page = page.reached(start, conn.page_bytes(), conn.page_confirmed());
        match r {
            Ok(items) => Ok(FetchReply::Items {
                items,
                stop: conn.last_fetch_stop(),
            }),
            Err(ClientError::Refused(ErrorReason::RateLimited)) => Ok(FetchReply::RateLimited),
            Err(e) => Err(dial_error(e)),
        }
    }
}

impl Depositor for QuicDialer {
    async fn deposit(&self, conn: &mut Session, packet: &[u8], pow_left: u64) -> DepositReply {
        let before = conn.pow_spent();
        conn.set_pow_budget(Some(before.saturating_add(pow_left)));
        let outcome = match conn.deposit(packet).await {
            Ok(result) => Ok(DepositOutcome::Answered(result)),
            Err(ClientError::PowBudget) => Ok(DepositOutcome::PowBudget),
            Err(e) => Err(dial_error(e)),
        };
        DepositReply {
            outcome,
            pow_spent: conn.pow_spent().saturating_sub(before),
        }
    }
}

impl Subscriber for QuicDialer {
    fn wake_supported(&self, conn: &Session) -> bool {
        conn.wake_supported()
    }

    async fn subscribe(
        &self,
        conn: &mut Session,
        sub: &Subscription,
        pow_left: u64,
    ) -> SubscribeReply {
        let before = conn.pow_spent();
        conn.set_pow_budget(Some(before.saturating_add(pow_left)));
        let outcome = match conn.subscribe(sub).await {
            Ok(result) => Ok(DepositOutcome::Answered(result)),
            Err(ClientError::PowBudget) => Ok(DepositOutcome::PowBudget),
            Err(e) => Err(dial_error(e)),
        };
        SubscribeReply {
            outcome,
            pow_spent: conn.pow_spent().saturating_sub(before),
        }
    }

    async fn unsubscribe(
        &self,
        conn: &mut Session,
        mailbox: MailboxId,
        cancel_secret: [u8; 32],
    ) -> Result<(), DialError> {
        conn.unsubscribe(mailbox, cancel_secret)
            .await
            .map_err(dial_error)
    }
}

/// What became of one exchange made by discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Observation {
    Answered,
    Refused,
    Failed,
    /// Cut by a client cap shorter than the dial timeout: neither a failure
    /// nor an answer (see `Dialer::cut_short`).
    Cut,
}

/// A dialer that notes the outcome of every exchange, so that lookups and
/// pings feed the score like other requests.
pub(super) struct Observed<'a, D> {
    pub(super) inner: &'a D,
    pub(super) outcomes: Mutex<Vec<(NodeId, Observation)>>,
}

impl<'a, D> Observed<'a, D> {
    pub(super) fn new(inner: &'a D) -> Self {
        Observed {
            inner,
            outcomes: Mutex::new(Vec::new()),
        }
    }

    fn note<T>(&self, id: NodeId, r: &Result<T, DialError>) {
        let o = match r {
            Ok(_) => Observation::Answered,
            Err(DialError::Refused(_)) => Observation::Refused,
            // No address: nothing the node can be blamed for.
            Err(DialError::NoAddress) => return,
            Err(_) => Observation::Failed,
        };
        self.push(id, o);
    }

    /// `id`'s last answer turned out worthless (a record not its own): it
    /// stays an answer, but no successful request.
    pub(super) fn retract(&self, id: NodeId) {
        if let Ok(mut v) = self.outcomes.lock()
            && let Some(last) = v
                .iter_mut()
                .rev()
                .find(|(n, o)| *n == id && *o == Observation::Answered)
        {
            last.1 = Observation::Refused;
        }
    }

    pub(super) fn push(&self, id: NodeId, o: Observation) {
        if let Ok(mut v) = self.outcomes.lock() {
            v.push((id, o));
        }
    }
}

impl<D: Dialer + Sync> Dialer for Observed<'_, D> {
    fn ping(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<NodeRecord, DialError>> + Send {
        let fut = self.inner.ping(id, addrs);
        async move {
            let r = fut.await;
            self.note(id, &r);
            r
        }
    }

    fn find_node(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send {
        let fut = self.inner.find_node(id, addrs, target);
        async move {
            let r = fut.await;
            self.note(id, &r);
            r
        }
    }

    /// The exchange's future was dropped at its deadline before `note` ran:
    /// noted here as the timeout it is.
    fn timed_out(&self, id: NodeId) {
        self.note::<()>(id, &Err(DialError::Timeout));
    }

    fn cut_short(&self, id: NodeId) {
        self.push(id, Observation::Cut);
    }
}

#[cfg(test)]
mod tests {
    use super::LinkPage;

    #[test]
    fn unchanged_page_size_keeps_its_doubling_progress() {
        let start = LinkPage {
            bytes: 32 << 10,
            confirmed: false,
        };
        // The session started from 16 KiB and carried it unchanged: 32 KiB
        // stays, the next recovery making it 64 KiB.
        assert_eq!(start.reached(16 << 10, 16 << 10, false).bytes, 32 << 10);
        // Grown, shrunk, or confirmed by a timeout: the session's size.
        assert_eq!(start.reached(16 << 10, 64 << 10, false).bytes, 64 << 10);
        let p = start.reached(16 << 10, 16 << 10, true);
        assert_eq!((p.bytes, p.confirmed), (16 << 10, true));
        let big = LinkPage {
            bytes: 512 << 10,
            confirmed: false,
        };
        assert_eq!(big.reached(256 << 10, 64 << 10, false).bytes, 64 << 10);
    }
}
