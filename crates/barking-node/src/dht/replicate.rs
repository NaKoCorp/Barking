//! Copy maintenance (spec §5.3): each held mailbox for which the node is
//! responsible is replicated to its other responsible nodes, computed in its
//! own table.
//!
//! - **Order**: queued mailboxes (a node entered among their 5 closest)
//!   first, then those never attempted, then the least recently attempted.
//!   An attempted mailbox goes to the end of the order, even if a
//!   responsible node refused it: a peer that always refuses does not keep
//!   it at the head. All this is kept in memory only.
//! - **Per responsible node**: `FindValue` on all pages, then `Store` of
//!   what is missing, acknowledgements first. A message without a kept proof
//!   (row of a migrated database, `pow = 0` that does not pass the node's
//!   base difficulty) is not sent: it would be refused.
//! - **Bounds**: `MAX_MAILBOXES_PER_PEER` mailboxes and `PEER_TIME_PER_PASS`
//!   per responsible node and per pass; `replication_bytes_per_hour` bytes
//!   sent per hour (beyond that the pass stops and resumes at the next one),
//!   of which at most a fifth to the same responsible node.
//! - **Pacing**: at most 10 requests per second to the same responsible node
//!   (`PEER_CALL_SPACING`), under the bucket of its address group (spec
//!   §5.2 point 2); after a `RateLimited`, a pause of `RATE_LIMIT_BACKOFF`
//!   then resumption, within the pass time.
//! - **Proof**: a message whose proof does not reach the difficulty
//!   announced by the responsible node (`Hello`) plus the tier is not sent
//!   to it (counted as `PowTooWeak`).
//! - **Refusals and outages**: replication never counts a failure in the
//!   table. A readable answer marks the peer alive (`mark_alive`).
//!   - No answer: peer skipped for the pass, and liveness check
//!     (`Dht::liveness_check`, at most one per peer per 10 min); that check
//!     is what counts the failure. If it removes the peer, the mailbox is
//!     replicated to the next one in the same pass.
//!   - Pass time or hourly share exhausted: peer skipped.
//!   - Out-of-bounds or unexpected answer, broken stream, `MailboxFull`,
//!     `NodeFull`, `NotResponsible`: the mailbox is skipped for this peer.
//!   - `PowTooWeak`, `UnknownAckTarget`: counted, the next item is sent.
//! - **Cadence**: every hour; a queued mailbox triggers a pass 1 min later
//!   at the earliest, limited to queued mailboxes. With
//!   `ServerConfig::dht_tick`, these delays equal `dht_tick`.
//!
//! Logs give only counters: no address, no mailbox.

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

/// Full pass.
pub const PASS_EVERY: Duration = Duration::from_secs(3600);
/// Minimum delay between queueing and the pass it triggers.
pub const QUEUE_DELAY: Duration = Duration::from_secs(60);
/// At most this many mailboxes replicated per responsible node and per pass (spec §5.3).
pub const MAX_MAILBOXES_PER_PEER: usize = 64;
/// At most this many `Holdings` pages read per mailbox and per responsible
/// node: beyond that, the mailbox is skipped for this peer.
pub const MAX_HOLDINGS_PAGES: usize = 16;
/// At most this much time spent with the same responsible node in a pass:
/// beyond that, it is skipped until the next pass.
pub const PEER_TIME_PER_PASS: Duration = Duration::from_secs(60);
/// Minimum gap between two replication requests to the same responsible
/// node (10 per second): under the callee's address group bucket (20
/// requests/s, spec §5.2 point 2), which table maintenance and a possible
/// client on the same IP also share.
pub const PEER_CALL_SPACING: Duration = Duration::from_millis(100);
/// Wait after a `RateLimited` before resuming with the same responsible node.
pub const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(2);
/// Window of the replication cap.
const BUDGET_WINDOW_SECS: u64 = 3600;

/// Summary of a pass (or sum of passes), without per-peer data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Mailboxes replicated (the node is responsible and has something to send).
    pub mailboxes: usize,
    /// Items accepted by a responsible node.
    pub sent: usize,
    /// Bytes sent by `Store`, accepted or not.
    pub bytes: u64,
    /// Peers skipped until the next pass.
    pub skipped_peers: usize,
    pub not_responsible: usize,
    pub pow_too_weak: usize,
    pub unknown_ack: usize,
    /// Other `Store` refusals.
    pub refused: usize,
    /// `RateLimited` received (each followed by a pause).
    pub rate_limited: usize,
    /// The pass stopped at the hourly cap.
    pub budget_exhausted: bool,
}

impl PassReport {
    /// Adds `other` to this summary.
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
            "{} mailboxes, {} sends accepted, {} bytes, {} peers skipped, refusals: \
             NotResponsible={} PowTooWeak={} UnknownAckTarget={} other={} RateLimited={}{}",
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
                ", hourly cap reached"
            } else {
                ""
            }
        )
    }
}

/// Cap on bytes replicated per one-hour window, and share of each
/// responsible node: `limit / REPLICAS` (at least 1 byte). A responsible
/// node that takes everything (empty `Holdings`, `Ok` to every `Store`) does
/// not exhaust the others' cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteBudget {
    limit: u64,
    window_start: u64,
    used: u64,
    /// Bytes sent to each responsible node in the window (memory only).
    per_peer: HashMap<NodeId, u64>,
}

impl ByteBudget {
    pub fn new(limit: u64) -> ByteBudget {
        ByteBudget::resume(limit, 0, 0)
    }

    /// Resumes a saved window (restart within the hour).
    pub fn resume(limit: u64, window_start: u64, used: u64) -> ByteBudget {
        ByteBudget {
            limit,
            window_start,
            used,
            per_peer: HashMap::new(),
        }
    }

    fn roll(&mut self, now: u64) {
        // A window starting in the future (clock moved back) rolls over too.
        if self.window_start > now || now - self.window_start >= BUDGET_WINDOW_SECS {
            self.window_start = now;
            self.used = 0;
            self.per_peer.clear();
        }
    }

    /// Hourly share of a responsible node.
    pub fn peer_share(&self) -> u64 {
        (self.limit / REPLICAS as u64).max(1)
    }

    /// True if the cap of the current window is reached.
    pub fn exhausted(&mut self, now: u64) -> bool {
        self.roll(now);
        self.used >= self.limit
    }

    /// True if `peer`'s share in the current window is reached.
    pub fn peer_exhausted(&mut self, now: u64, peer: &NodeId) -> bool {
        self.roll(now);
        self.per_peer.get(peer).copied().unwrap_or(0) >= self.peer_share()
    }

    /// Counts `n` bytes sent to `peer`.
    pub fn spend(&mut self, now: u64, peer: NodeId, n: u64) {
        self.roll(now);
        self.used = self.used.saturating_add(n);
        let p = self.per_peer.entry(peer).or_default();
        *p = p.saturating_add(n);
    }

    /// (window start, bytes sent in the window).
    pub fn window(&self) -> (u64, u64) {
        (self.window_start, self.used)
    }
}

/// "Infinite" distance: fewer than `REPLICAS` known responsible nodes, any
/// newcomer becomes one.
const FAR: [u8; 32] = [0xff; 32];

/// A held mailbox, in memory.
struct Entry {
    key: [u8; 32],
    /// Number of the last attempt, 0 if never attempted.
    seq: u64,
    /// Distance to the key of the farthest of its responsible nodes (us
    /// included) at the last pass; `None` if we are not responsible for it.
    /// A closer newcomer enters among them.
    bound: Option<[u8; 32]>,
}

/// Order and queue of mailboxes, in memory only.
#[derive(Default)]
pub(crate) struct Queue {
    /// Increasing attempt number.
    seq: u64,
    boxes: HashMap<MailboxId, Entry>,
    /// Mailboxes to handle first.
    queued: HashSet<MailboxId>,
}

impl Queue {
    /// Mailboxes to handle, with their key, in order: queued, then never
    /// attempted, then the least recently attempted. `queued_only`: only the
    /// queued ones. Forgets mailboxes that are no longer held and empties
    /// the queue.
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

    /// The mailbox has been attempted: it goes to the end of the order.
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

    /// Queues the mailboxes among whose responsible nodes `id` enters,
    /// without consulting the table; true if the queue gained any.
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

/// Distance to `key` of the farthest of the responsible nodes `targets` (us
/// included if we are one); `FAR` if there are fewer than `REPLICAS`.
fn replica_bound(own: &NodeId, key: &[u8; 32], targets: &[NodeId]) -> [u8; 32] {
    let far = targets.iter().map(|t| distance(&t.0, key)).max();
    match targets.len() {
        n if n >= REPLICAS => far.unwrap_or(FAR),
        n if n + 1 == REPLICAS => far.unwrap_or(FAR).max(distance(&own.0, key)),
        _ => FAR,
    }
}

/// Outcome of replicating a mailbox to a responsible node.
enum Outcome {
    Done,
    /// No answer (timeout, connection impossible or lost): peer skipped for
    /// the pass, liveness check requested.
    NoAnswer,
    /// Pass time or hourly byte share exhausted for this peer: skipped.
    Skip,
    /// Hourly cap reached: end of the pass.
    Budget,
}

/// Answer to a call.
enum Call {
    Answer(Response),
    /// Timeout, connection impossible or lost.
    NoAnswer,
    /// Unreadable answer or stream cut by the peer: it answers, but not to
    /// this request.
    Broken,
}

/// Per-peer summary in a pass.
#[derive(Default)]
struct PeerPass {
    mailboxes: usize,
    spent: Duration,
    skipped: bool,
}

/// Runs passes until `stop`.
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
            // Full pass when due; a queueing makes only the queued
            // mailboxes be handled.
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
            tracing::debug!("replication: {report}");
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

/// A replication pass over the held mailboxes (`queued_only`: only the
/// queued ones).
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
        // Outside the responsibility window: no more replication, nothing
        // is erased (spec §5.3, point 2).
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
        // A message without a kept proof would be refused (`PowTooWeak`).
        let items: Vec<CopyItem> = items
            .into_iter()
            .filter(|i| sendable(i, &mailbox, shared.policy.pow_bits))
            .collect();
        if items.is_empty() {
            dht.replication_queue().attempted(&mailbox);
            continue;
        }
        report.mailboxes += 1;
        let mut tried: HashSet<NodeId> = HashSet::new();
        let mut attempted = false;
        // A responsible node removed from the table by its liveness check
        // leaves its place to the next one, served in the same pass.
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

/// True if `item` has a proof to send: an ack, or a message with a kept
/// proof. `pow = 0` marks a migrated row without one, but 0 is also the
/// first nonce `pow::solve` tries (a valid proof once in `2^bits`): such a
/// row is sent if 0 passes the node's own base difficulty (`pow_bits`).
fn sendable(item: &CopyItem, mailbox: &MailboxId, pow_bits: u8) -> bool {
    item.is_ack
        || item.pow != 0
        || pow::check(
            &item.hash,
            mailbox,
            0,
            rules::copy_pow_bits(pow_bits, item.tier),
        )
}

/// Sends `req` to peer `peer` (addresses of its record in the table), at the
/// pace of `PEER_CALL_SPACING`. After a `RateLimited`, waits
/// `RATE_LIMIT_BACKOFF` and retries: only the pass time for this peer bounds
/// the wait. A readable answer marks it alive in the table.
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

/// Base difficulty announced by `peer` in `Hello`, if a connection to it is
/// kept.
fn peer_pow_bits(dht: &Dht, peer: NodeId) -> Option<u8> {
    let addrs = dht.table().get(&peer).map(|p| p.record.addrs())?;
    dht.pool().pow_bits(peer, &addrs)
}

/// Hashes that `peer` holds for `mailbox`, all pages read. An out-of-bounds
/// answer (page too long, cursor that does not advance, more than
/// `MAX_HOLDINGS_PAGES` pages) or an unexpected one makes the mailbox be
/// skipped for this peer (`Err(Outcome::Done)`), counting nothing against
/// it.
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

/// Replicates to `peer` what it lacks of `items` (acknowledgements first).
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
    // Peer's difficulty (`Hello`): a message whose proof does not reach it
    // would be refused (`PowTooWeak`) at every pass, so it is not sent.
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
                // Diverging tables: nothing else for this peer before the
                // next pass.
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
            // Unexpected answer or broken stream: the mailbox is skipped.
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
        // One hour after the window start: new window.
        assert!(!bud.exhausted(T + 3600));
        assert_eq!(bud.window(), (T + 3600, 0));
        assert!(!bud.peer_exhausted(T + 3600, &a));
        // Resumption of a saved window.
        let mut r = ByteBudget::resume(10, T, 10);
        assert!(r.exhausted(T + 100));
        assert!(!r.exhausted(T + 3600));
    }

    /// A message item of tier S, without bytes, with proof `pow`.
    fn item(hash: [u8; 32], pow: u64) -> CopyItem {
        CopyItem {
            bytes: Vec::new(),
            pow,
            hash,
            is_ack: false,
            tier: barking_packet::Tier::S,
        }
    }

    #[test]
    fn nonce_zero_is_sent_only_when_it_is_a_proof() {
        const BITS: u8 = 8;
        let mb = MailboxId([7; 16]);
        // Fingerprints for which nonce 0 is (resp. is not) a valid proof at
        // `BITS`: `pow::solve` returns 0 for the first, once in 2^BITS.
        let hashes = (0..=u16::MAX).map(|n| {
            let mut h = [0; 32];
            h[..2].copy_from_slice(&n.to_le_bytes());
            h
        });
        let proof =
            |h: &[u8; 32]| pow::check(h, &mb, 0, rules::copy_pow_bits(BITS, item(*h, 0).tier));
        let zero_proof = hashes.clone().find(|h| proof(h)).unwrap();
        let no_proof = hashes.clone().find(|h| !proof(h)).unwrap();
        assert_eq!(pow::solve(&zero_proof, &mb, BITS), Some(0));
        // A proof found at nonce 0 is replicated like any other.
        assert!(sendable(&item(zero_proof, 0), &mb, BITS));
        // A migrated row (`pow = 0`, no kept proof) is not.
        assert!(!sendable(&item(no_proof, 0), &mb, BITS));
        // Any other nonce, and an ack, are left to the peer's check.
        assert!(sendable(&item(no_proof, 1), &mb, BITS));
        let ack = CopyItem {
            is_ack: true,
            ..item(no_proof, 0)
        };
        assert!(sendable(&ack, &mb, BITS));
    }

    #[test]
    fn budget_window_from_the_future_rolls_over() {
        const T: u64 = 1_800_000_000;
        let mut r = ByteBudget::resume(10, T + 7200, 10);
        assert!(!r.exhausted(T));
        assert_eq!(r.window(), (T, 0));
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
        // `a` has taken its share; `b` and the global cap stay open.
        assert!(bud.peer_exhausted(T, &a));
        assert!(!bud.peer_exhausted(T, &b));
        assert!(!bud.exhausted(T));
        // Tiny cap: at least one byte per responsible node.
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
        // Never attempted first, then the least recently attempted; each
        // mailbox's key is attached.
        let order = q.order(vec![m(3), m(2), m(4), m(1)], false);
        assert_eq!(order[0].1, mailbox_key(&m(4)));
        assert_eq!(ids(order), [m(4), m(1), m(2), m(3)]);
        // An attempted mailbox, even if refused, goes to the end of the order.
        q.attempted(&m(4));
        q.attempted(&m(1));
        assert_eq!(
            ids(q.order(vec![m(1), m(2), m(3), m(4)], false)),
            [m(2), m(3), m(4), m(1)]
        );
        // Queueing based on the bound: only a node closer to the key than
        // the farthest responsible node makes it enter.
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
        // Without a bound (not responsible): never queued.
        q.set_bound(&m(3), None);
        assert!(!q.enqueue_near(&NodeId(mailbox_key(&m(3)))));
        // Pass limited to the queue, which is then emptied.
        assert_eq!(ids(q.order(vec![m(1), m(2), m(3)], true)), [m(2)]);
        assert!(q.order(vec![m(1), m(2), m(3)], true).is_empty());
        // A mailbox that is no longer held is forgotten.
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
        // Five responsible nodes other than us: the farthest of them.
        assert_eq!(replica_bound(&id(9), &key, &targets), d(&id(5)));
        // Four: we are one, the farthest of the five.
        assert_eq!(replica_bound(&id(9), &key, &targets[..4]), d(&id(9)));
        assert_eq!(replica_bound(&id(0), &key, &targets[..4]), d(&id(4)));
        // Fewer: any newcomer enters.
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
            line.contains("NotResponsible=2") && line.contains("hourly cap"),
            "{line}"
        );
    }
}
