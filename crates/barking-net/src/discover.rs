//! Finding nodes (spec §3.2, §3.4, §4, §7): bootstrap, random lookups that
//! fill the view, the fallback lookup on a mailbox key, and the choice of the
//! node hints carried by my contact card.
//!
//! The network goes through a [`Dialer`]; every decision is made here, so the
//! logic runs against an in-memory double. A node becomes confirmed only after
//! it answered a connection pinned on its identifier (TLS): lookup responders
//! and pinged nodes. Records merely relayed by other nodes enter as
//! candidates, at most [`MAX_NEW_CANDIDATES`] per synchronization.
//!
//! Nothing is logged here: no address or mailbox can leak from this module.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use barking_core::contact::{MAX_CARD_NODES, MAX_NODE_HINT_BYTES};
use barking_dht::lookup::{LOOKUP_TIMEOUT_MS, REQUEST_TIMEOUT_MS};
use barking_dht::{BootstrapEntry, K, Lookup, PATHS, distance, filter_nodes, mailbox_key};
use barking_packet::MailboxId;
use barking_proto::client::{Client, ClientError};
use barking_proto::{ErrorReason, NodeId, NodeRecord, Request, Response};
use serde::{Deserialize, Serialize};

use crate::FALLBACK_COOLDOWN_SECS;
use crate::score::START_SCORE;
use crate::view::View;

/// Reachable nodes after which bootstrap stops.
pub const BOOTSTRAP_REACHABLE: usize = 3;
/// Nodes tried at most per bootstrap source: a cache full of dead nodes must
/// not keep the client from reaching the next sources.
pub const BOOTSTRAP_TRIES_PER_SOURCE: usize = 24;
/// New candidates accepted at most per synchronization, on top of the
/// `MAX_NODES_PER_RESPONSE` records of a response: blunts candidate floods.
pub const MAX_NEW_CANDIDATES: usize = 200;
/// Time given to each source's pings (all sent at once): with four sources
/// and the lookup that follows a built-in answer, bootstrap fits in 25 s.
pub const BOOTSTRAP_SOURCE_TIMEOUT: Duration = Duration::from_secs(3);
/// Longest exchange with a node at one address (connection, `Hello` and one
/// request); a node with two addresses may take twice as long. Callers bound
/// it further (lookup requests, bootstrap sources).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure of an exchange with a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DialError {
    #[error("no address to dial")]
    NoAddress,
    #[error("node unreachable")]
    Unreachable,
    #[error("the node does not respond in time")]
    Timeout,
    #[error("the node refuses: {}", .0.describe())]
    Refused(ErrorReason),
    #[error("invalid response from the node")]
    Protocol,
}

/// Exchanges with nodes, as an anonymous client. Implementations dial `addrs`
/// with TLS pinned on `id`: a success proves the answer comes from `id`.
pub trait Dialer {
    /// Connects, `Hello`, then `Ping`: returns the record the node signed.
    fn ping(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<NodeRecord, DialError>> + Send;

    /// Connects, `Hello`, then `FindNode { target, from: None }`.
    fn find_node(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> impl Future<Output = Result<Vec<NodeRecord>, DialError>> + Send;
}

/// The real dialer: `Client::connect` (no client certificate, so anonymous),
/// one request, then the connection is closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuicDialer;

impl QuicDialer {
    async fn exchange(
        id: NodeId,
        addrs: &[SocketAddr],
        req: &Request,
    ) -> Result<Response, DialError> {
        let mut last = DialError::NoAddress;
        for &addr in addrs {
            match tokio::time::timeout(DIAL_TIMEOUT, Self::exchange_at(addr, id, req)).await {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) => last = e,
                Err(_) => last = DialError::Timeout,
            }
        }
        Err(last)
    }

    async fn exchange_at(
        addr: SocketAddr,
        id: NodeId,
        req: &Request,
    ) -> Result<Response, DialError> {
        let session = Client::connect(addr, id).await.map_err(dial_error)?;
        let resp = session.request(req).await.map_err(dial_error);
        session.connection().close(0u32.into(), b"done");
        match resp? {
            Response::Error(reason) => Err(DialError::Refused(reason)),
            resp => Ok(resp),
        }
    }
}

fn dial_error(e: ClientError) -> DialError {
    match e {
        ClientError::Timeout => DialError::Timeout,
        ClientError::Refused(reason) => DialError::Refused(reason),
        ClientError::Connect(_) | ClientError::Connection(_) => DialError::Unreachable,
        _ => DialError::Protocol,
    }
}

impl Dialer for QuicDialer {
    async fn ping(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<NodeRecord, DialError> {
        match Self::exchange(id, addrs, &Request::Ping { from: None }).await? {
            Response::Pong { record } => Ok(record),
            _ => Err(DialError::Protocol),
        }
    }

    async fn find_node(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        target: [u8; 32],
    ) -> Result<Vec<NodeRecord>, DialError> {
        let req = Request::FindNode { target, from: None };
        match Self::exchange(id, addrs, &req).await? {
            Response::Nodes { records } => Ok(records),
            _ => Err(DialError::Protocol),
        }
    }
}

/// New candidates still accepted during this synchronization. One budget is
/// shared by every call of a synchronization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBudget {
    remaining: usize,
}

impl Default for CandidateBudget {
    fn default() -> Self {
        CandidateBudget {
            remaining: MAX_NEW_CANDIDATES,
        }
    }
}

impl CandidateBudget {
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

/// Dates of the last fallback lookups, by mailbox key (never the mailbox
/// itself). Kept in the encrypted state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackLog {
    last: HashMap<[u8; 32], u64>,
}

impl FallbackLog {
    /// True if no fallback lookup ran for this mailbox in the last
    /// `FALLBACK_COOLDOWN_SECS`. A date from the future counts as now.
    pub fn due(&self, mailbox: &MailboxId, now: u64) -> bool {
        self.last
            .get(&mailbox_key(mailbox))
            .is_none_or(|&t| now.saturating_sub(t.min(now)) >= FALLBACK_COOLDOWN_SECS)
    }

    fn note(&mut self, mailbox: &MailboxId, now: u64) {
        self.last.insert(mailbox_key(mailbox), now);
    }

    /// Drops the dates whose cooldown is over; dates from the future are
    /// brought back to `now`.
    pub fn prune(&mut self, now: u64) {
        self.last.retain(|_, t| {
            *t = (*t).min(now);
            now - *t < FALLBACK_COOLDOWN_SECS
        });
    }
}

/// Where bootstrap looked for nodes, in the order of spec §3.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapSource {
    /// The saved view (hand-added nodes excepted).
    Cache,
    /// Node hints of received contact cards.
    Cards,
    /// Nodes added by hand.
    Manual,
    /// The list built into the binary.
    Builtin,
}

/// Outcome of a bootstrap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapReport {
    /// Nodes that answered, in order.
    pub reachable: Vec<NodeId>,
    /// Sources tried, in order.
    pub sources: Vec<BootstrapSource>,
    /// Contact card hints dropped: undecodable or invalid records.
    pub invalid_hints: usize,
    /// Entries added to the view.
    pub added: usize,
}

impl BootstrapReport {
    /// True once `BOOTSTRAP_REACHABLE` nodes answered.
    pub fn bootstrapped(&self) -> bool {
        self.reachable.len() >= BOOTSTRAP_REACHABLE
    }
}

/// Bootstraps the view: tries the cache, the card hints (`core_hints`, from
/// `Core::contact_node_hints`), the hand-added nodes, then `builtin`
/// (`builtin_bootstrap()`), and stops as soon as `BOOTSTRAP_REACHABLE` nodes
/// answered. Valid card hints enter the view as candidates whether or not
/// they are tried. Built-in entries only have an identifier and an address:
/// once one answered, a random lookup brings real records.
///
/// Worst case, nothing answering in time: 4 sources × `BOOTSTRAP_SOURCE_TIMEOUT`
/// (12 s), plus, after a built-in answer, one lookup bounded by
/// `LOOKUP_TIMEOUT_MS` (10 s) and its last requests' `REQUEST_TIMEOUT_MS` cut
/// (3 s at most): about 25 s, well within the 3-minute synchronization.
pub async fn bootstrap<D: Dialer>(
    view: &mut View,
    core_hints: Vec<Vec<u8>>,
    builtin: &[BootstrapEntry],
    dialer: &D,
    rng: &mut impl rand_core::Rng,
    budget: &mut CandidateBudget,
    now: u64,
) -> BootstrapReport {
    let mut report = BootstrapReport::default();
    let cache: Vec<(NodeId, Vec<SocketAddr>)> = view
        .reachable_candidates_for_bootstrap()
        .into_iter()
        .filter(|(id, _)| view.get(id).is_some_and(|e| !e.manual))
        .collect();
    let (hints, invalid) = decode_hints(view, &core_hints, now);
    report.invalid_hints = invalid;
    let mut cards = Vec::with_capacity(hints.len());
    for (id, record) in hints {
        if admit_candidate(view, id, record.clone(), budget, now) {
            report.added += 1;
        }
        cards.push((id, record.addrs()));
    }
    let mut manual: Vec<(NodeId, Vec<SocketAddr>)> = view
        .entries()
        .filter(|(_, e)| e.manual)
        .map(|(id, e)| (*id, e.addrs()))
        .collect();
    manual.sort_by_key(|(id, _)| id.0);
    let builtin: Vec<(NodeId, Vec<SocketAddr>)> =
        builtin.iter().map(|b| (b.id, vec![b.addr])).collect();

    let mut tried = HashSet::new();
    for (source, list) in [
        (BootstrapSource::Cache, cache),
        (BootstrapSource::Cards, cards),
        (BootstrapSource::Manual, manual),
        (BootstrapSource::Builtin, builtin),
    ] {
        if report.bootstrapped() {
            break;
        }
        report.sources.push(source);
        let before = report.reachable.len();
        try_source(view, dialer, list, &mut tried, &mut report, now).await;
        if source == BootstrapSource::Builtin && report.reachable.len() > before {
            report.added += random_lookups(view, dialer, 1, rng, budget, now).await;
        }
    }
    report
}

/// Pings the first `BOOTSTRAP_TRIES_PER_SOURCE` nodes of one source all at
/// once, keeps answers as they land until `BOOTSTRAP_REACHABLE` nodes answered,
/// and drops the pings still pending then or at `BOOTSTRAP_SOURCE_TIMEOUT`.
async fn try_source<D: Dialer>(
    view: &mut View,
    dialer: &D,
    list: Vec<(NodeId, Vec<SocketAddr>)>,
    tried: &mut HashSet<NodeId>,
    report: &mut BootstrapReport,
    now: u64,
) {
    let deadline = tokio::time::Instant::now() + BOOTSTRAP_SOURCE_TIMEOUT;
    let mut pending: Vec<_> = list
        .into_iter()
        .filter(|(id, addrs)| !addrs.is_empty() && tried.insert(*id))
        .take(BOOTSTRAP_TRIES_PER_SOURCE)
        .map(|(id, addrs)| Box::pin(timed_ping(dialer, id, addrs, deadline)))
        .collect();
    while !report.bootstrapped() && !pending.is_empty() {
        let (id, answer) = next_ready(&mut pending).await;
        let Ok(record) = answer else { continue };
        match confirm_reached(view, id, record, now) {
            Some(new) => report.added += usize::from(new),
            // A hand-added node answered but its record does not fit the
            // view (e.g. a private address): it is still reachable.
            None if view.get(&id).is_some_and(|e| e.manual) => view.confirm(&id, now),
            None => continue,
        }
        report.reachable.push(id);
    }
}

async fn timed_ping<D: Dialer>(
    dialer: &D,
    id: NodeId,
    addrs: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
) -> (NodeId, Result<NodeRecord, DialError>) {
    let answer = tokio::time::timeout_at(deadline, dialer.ping(id, &addrs))
        .await
        .unwrap_or(Err(DialError::Timeout));
    (id, answer)
}

/// Decodes and verifies contact card hints; returns the valid ones (one per
/// node) and the number dropped.
fn decode_hints(view: &View, hints: &[Vec<u8>], now: u64) -> (Vec<(NodeId, NodeRecord)>, usize) {
    let policy = view.policy();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut invalid = 0;
    for bytes in hints {
        let decoded = (bytes.len() <= MAX_NODE_HINT_BYTES)
            .then(|| postcard::take_from_bytes::<NodeRecord>(bytes).ok())
            .flatten()
            .filter(|(_, rest)| rest.is_empty())
            .and_then(|(record, _)| Some((record.verify(now, &policy).ok()?, record)));
        match decoded {
            Some((id, record)) => {
                if seen.insert(id) {
                    out.push((id, record));
                }
            }
            None => invalid += 1,
        }
    }
    (out, invalid)
}

/// Runs `count` lookups of random identifiers; responders become confirmed,
/// the other records received enter as candidates. Returns the number of
/// entries added to the view.
pub async fn random_lookups<D: Dialer>(
    view: &mut View,
    dialer: &D,
    count: usize,
    rng: &mut impl rand_core::Rng,
    budget: &mut CandidateBudget,
    now: u64,
) -> usize {
    let mut added = 0;
    for _ in 0..count {
        let mut target = [0; 32];
        rng.fill_bytes(&mut target);
        let seeds = seeds(view, &target, now);
        added += run_lookup(view, dialer, target, seeds, budget, now)
            .await
            .added;
    }
    added
}

/// Fallback lookup on the key of `mailbox` (spec §4), at most once per
/// `FALLBACK_COOLDOWN_SECS` for the same mailbox. Its result enriches the
/// view; returns the closest nodes that answered (empty when not due or
/// when the view holds no node to start from).
pub async fn fallback_lookup<D: Dialer>(
    view: &mut View,
    dialer: &D,
    mailbox: &MailboxId,
    log: &mut FallbackLog,
    budget: &mut CandidateBudget,
    now: u64,
) -> Vec<NodeId> {
    let target = mailbox_key(mailbox);
    if !log.due(mailbox, now) {
        return Vec::new();
    }
    let seeds = seeds(view, &target, now);
    if seeds.is_empty() {
        return Vec::new();
    }
    log.note(mailbox, now);
    run_lookup(view, dialer, target, seeds, budget, now)
        .await
        .result
}

/// Up to `MAX_CARD_NODES` encoded records for my contact card, drawn at random
/// among confirmed nodes of score ≥ 0.5 that are not avoided, never among the
/// responsibles of `my_mailboxes` (spec §7).
pub fn choose_card_nodes(
    view: &View,
    my_mailboxes: &[MailboxId],
    rng: &mut impl rand_core::Rng,
    now: u64,
) -> Vec<Vec<u8>> {
    let excluded: HashSet<NodeId> = my_mailboxes
        .iter()
        .flat_map(|m| view.responsibles(m, now))
        .collect();
    let mut pool: Vec<(NodeId, Vec<u8>)> = view
        .entries()
        .filter(|(id, e)| {
            e.confirmed
                && e.score.value() >= START_SCORE
                && !e.avoided(now)
                && !excluded.contains(id)
        })
        .filter_map(|(id, e)| {
            let bytes = postcard::to_allocvec(e.record.as_ref()?).ok()?;
            (bytes.len() <= MAX_NODE_HINT_BYTES).then_some((*id, bytes))
        })
        .collect();
    // Sorted first so that the draw depends on the rng only.
    pool.sort_by_key(|(id, _)| id.0);
    let take = pool.len().min(MAX_CARD_NODES);
    for i in 0..take {
        let span = (pool.len() - i) as u64;
        let j = i + (rng.next_u64() % span) as usize;
        pool.swap(i, j);
    }
    pool.truncate(take);
    pool.into_iter().map(|(_, bytes)| bytes).collect()
}

/// Result of one lookup.
#[derive(Default)]
struct LookupOutcome {
    /// Closest nodes that answered.
    result: Vec<NodeId>,
    /// Entries added to the view.
    added: usize,
}

/// Starting points of a lookup: the entries with a record that are not
/// avoided, closest to the target first.
fn seeds(view: &View, target: &[u8; 32], now: u64) -> Vec<(NodeId, NodeRecord)> {
    let mut seeds: Vec<(NodeId, NodeRecord)> = view
        .entries()
        .filter(|(_, e)| !e.avoided(now))
        .filter_map(|(id, e)| Some((*id, e.record.clone()?)))
        .collect();
    seeds.sort_by_cached_key(|(id, _)| distance(&id.0, target));
    seeds.truncate(PATHS * K);
    seeds
}

/// Drives a `Lookup` over the dialer, then records what it learnt in the view.
/// Requests are issued as soon as an answer frees a slot; each one is bounded
/// by `REQUEST_TIMEOUT_MS` (a timeout counts as a failure) and the whole
/// lookup by `LOOKUP_TIMEOUT_MS`, after which pending requests are dropped.
async fn run_lookup<D: Dialer>(
    view: &mut View,
    dialer: &D,
    target: [u8; 32],
    seeds: Vec<(NodeId, NodeRecord)>,
    budget: &mut CandidateBudget,
    now: u64,
) -> LookupOutcome {
    if seeds.is_empty() {
        return LookupOutcome::default();
    }
    let policy = view.policy();
    let start = tokio::time::Instant::now();
    let lookup_end = start + Duration::from_millis(LOOKUP_TIMEOUT_MS);
    let clock = || {
        let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        now.saturating_mul(1000).saturating_add(elapsed)
    };
    let mut lookup = Lookup::new(target, seeds, policy, clock());
    let mut pending = Vec::new();
    let mut added = 0;
    loop {
        let t = clock();
        if lookup.is_done(t) {
            break;
        }
        let request_end = (tokio::time::Instant::now() + Duration::from_millis(REQUEST_TIMEOUT_MS))
            .min(lookup_end);
        for (id, record) in lookup.next_requests(t) {
            pending.push(Box::pin(timed_find(
                dialer,
                id,
                record.addrs(),
                target,
                request_end,
            )));
        }
        if pending.is_empty() {
            break;
        }
        let (id, answer) = next_ready(&mut pending).await;
        match answer {
            Ok(records) => {
                // A response with one invalid record is ignored whole.
                if let Ok(nodes) = filter_nodes(records.clone(), now, &policy) {
                    for (nid, record) in nodes {
                        if admit_candidate(view, nid, record, budget, now) {
                            added += 1;
                        }
                    }
                }
                lookup.on_response(&id, records, now);
            }
            Err(_) => lookup.on_failure(&id),
        }
    }
    for (id, record) in lookup.responders() {
        if confirm_reached(view, id, record, now) == Some(true) {
            added += 1;
        }
    }
    LookupOutcome {
        result: lookup.result().into_iter().map(|(id, _)| id).collect(),
        added,
    }
}

async fn timed_find<D: Dialer>(
    dialer: &D,
    id: NodeId,
    addrs: Vec<SocketAddr>,
    target: [u8; 32],
    deadline: tokio::time::Instant,
) -> (NodeId, Result<Vec<NodeRecord>, DialError>) {
    let answer = tokio::time::timeout_at(deadline, dialer.find_node(id, &addrs, target))
        .await
        .unwrap_or(Err(DialError::Timeout));
    (id, answer)
}

/// Adds a relayed record as a candidate. A known node is refreshed for free;
/// a new one spends the budget. Returns true if a new entry was added.
fn admit_candidate(
    view: &mut View,
    id: NodeId,
    record: NodeRecord,
    budget: &mut CandidateBudget,
    now: u64,
) -> bool {
    if view.get(&id).is_some() {
        view.insert(record, now);
        return false;
    }
    if budget.remaining == 0 || !view.insert(record, now) || view.get(&id).is_none() {
        return false;
    }
    budget.remaining -= 1;
    true
}

/// `id` answered a connection pinned on it with `record`: stores the record
/// if it verifies and belongs to `id`, then confirms the node. Returns
/// `Some(true)` for a new entry, `Some(false)` for a known one, `None` if
/// the record was refused.
fn confirm_reached(view: &mut View, id: NodeId, record: NodeRecord, now: u64) -> Option<bool> {
    if record.verify(now, &view.policy()).ok() != Some(id) {
        return None;
    }
    let known = view.get(&id).is_some();
    if known {
        view.set_record(&id, record, now);
    } else {
        view.insert(record, now);
    }
    view.get(&id)?;
    view.confirm(&id, now);
    Some(!known)
}

/// Waits for the first of `pending` to finish (the earliest in the list when
/// several are ready), removes it and returns its output. `pending` must not
/// be empty.
async fn next_ready<F: Future + Unpin>(pending: &mut Vec<F>) -> F::Output {
    std::future::poll_fn(|cx| {
        for i in 0..pending.len() {
            if let Poll::Ready(v) = Pin::new(&mut pending[i]).poll(cx) {
                pending.remove(i);
                return Poll::Ready(v);
            }
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests;
