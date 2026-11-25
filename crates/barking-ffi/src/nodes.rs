//! The Network screen's nodes (spec node transparency §6.4, §6.5): the list,
//! a node's detail and its report, nodes added by hand, blocked nodes and
//! the default nodes shipped with the app.
//!
//! **Lock.** Every call runs under the database lock. The calls that change
//! the network state (`add_node`, `block_node`, `unblock_node`,
//! `remove_node`, `add_default_nodes`, `reset_default_nodes`) take it like
//! any write (`Device::with_core`): during a sync of this process they wait
//! for it to end (up to the lock timeout, `Locked` past it), and the sync,
//! which saved its state before releasing the lock, cannot overwrite them.
//! The reads of the screen (`nodes`, `node_detail`, `blocked_nodes`,
//! `dismissed_defaults_count`, `usable_nodes_if_blocked`) do not wait for a
//! sync of this process: they join its lock (`Device::with_core_read`), so
//! the screen shows the nodes it knows while the sync runs.
//! `refresh_node_info` takes it the same way as the writes, twice and briefly: once to
//! read what the dial needs, once to save what came back. The dial itself
//! (up to some 40 s against dead addresses) runs without it, so that it
//! never holds up the notification extension or the other calls.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use barking_core::Core;
use barking_core::transparency::TransparencyEvent;
use barking_net::discover::DIAL_TIMEOUT;
use barking_net::geo::{IpDb, OriginVerdict, UnverifiableReason, verdict};
use barking_net::push::{PushConfig, PushState};
use barking_net::state::CachedInfo;
use barking_net::sync::short_id;
use barking_net::{Connector, NetState, NodeEntry, QuicDialer, nodes};
use barking_proto::{FillTier, NodeId, NodeInfoReport, NodeOrigin, PushLink};

use crate::device::{Device, now};
use crate::net::block_on;
use crate::{BarkingError, guard};

/// A node seen within this many seconds is in use.
const IN_USE_SECS: u64 = 7 * 86_400;
/// Transparency log entries read per page when looking for why nodes were
/// avoided.
const LOG_PAGE: usize = 500;

/// Why a node is set aside (`Reliability::Avoided`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AvoidReason {
    /// A message deposited there was lost.
    MessageLost,
    /// The node kept failing to answer.
    Unreachable,
}

impl From<barking_core::transparency::AvoidReason> for AvoidReason {
    fn from(r: barking_core::transparency::AvoidReason) -> Self {
        match r {
            barking_core::transparency::AvoidReason::MessageLost => AvoidReason::MessageLost,
            barking_core::transparency::AvoidReason::Unreachable => AvoidReason::Unreachable,
        }
    }
}

/// What the app shows of a node's score (spec §6.5).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Reliability {
    /// Never answered this phone yet.
    New,
    /// Score of 0.5 or more.
    Good,
    /// Score of 0.3 or more.
    Fair,
    /// Score under 0.3.
    Weak,
    /// Set aside until `until` (Unix seconds).
    Avoided { until: u64, reason: AvoidReason },
}

/// How a node came into the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NodeOriginKind {
    /// A default node shipped with the app.
    Bootstrap,
    /// Added by hand.
    Manual,
    /// Carried by a contact's card.
    FromCard,
    /// Found on the network.
    Discovered,
}

/// What the IP base says of the origin a node declares.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OriginVerdictView {
    Matches,
    /// Countries are 2-letter uppercase codes.
    Mismatch {
        declared_country: String,
        observed_country: String,
        declared_asn: u32,
        observed_asn: u32,
    },
    /// The node declares no origin.
    NotReported,
    /// The base has no data for the node's address (or there is no base).
    NotInBase,
    /// The node was not seen answering on an address of the family the
    /// origin describes (none recorded, or one of the other family).
    NoRecord,
}

/// The hosting a node declares, and the verdict of the IP base.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OriginView {
    pub asn: u32,
    pub as_name: String,
    /// 2-letter uppercase code.
    pub country: String,
    pub verdict: OriginVerdictView,
}

/// A node of the local view (the Network screen's relays).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NodeInfo {
    pub id: String,
    /// `ip:port`, the hand-entered one first; empty if unknown.
    pub addr: String,
    /// What the app shows.
    pub reliability: Reliability,
    /// Reliability, 0 to 1 (tests and the CLI).
    pub score: f32,
    /// Added by hand (a default node included).
    pub manual: bool,
    /// Carried by a contact's card.
    pub from_card: bool,
    /// Unix seconds (to the hour) the node was last seen, once it answered
    /// this phone; 0 if it never did (a node only heard of).
    pub last_seen: u64,
    /// Median of the last round trips, in milliseconds.
    pub latency_ms: Option<u32>,
    /// Added by hand or by default, holding one of my copies or wake
    /// subscriptions, or answered this phone and seen in the last 7 days.
    pub in_use: bool,
    /// The hosting its last report declared, checked against the IP base.
    pub origin: Option<OriginView>,
    /// My wake subscriptions (mailbox and kind) it holds.
    pub my_subscriptions: u32,
    pub kind: NodeOriginKind,
}

/// How full a node says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FillTierView {
    Low,
    Medium,
    High,
    Full,
}

impl From<FillTier> for FillTierView {
    fn from(t: FillTier) -> Self {
        match t {
            FillTier::Low => FillTierView::Low,
            FillTier::Medium => FillTierView::Medium,
            FillTier::High => FillTierView::High,
            FillTier::Full => FillTierView::Full,
        }
    }
}

/// How a node's link to the push relay goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PushLinkView {
    Ok,
    Failing,
    Unknown,
}

impl From<PushLink> for PushLinkView {
    fn from(l: PushLink) -> Self {
        match l {
            PushLink::Ok => PushLinkView::Ok,
            PushLink::Failing => PushLinkView::Failing,
            PushLink::Unknown => PushLinkView::Unknown,
        }
    }
}

/// A node's last self-report (`Info`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NodeReportView {
    pub software: String,
    pub protocol: u16,
    pub uptime_secs: u64,
    pub storage: FillTierView,
    pub wake: Option<FillTierView>,
    pub push_link: Option<PushLinkView>,
}

impl From<&NodeInfoReport> for NodeReportView {
    fn from(r: &NodeInfoReport) -> Self {
        NodeReportView {
            software: r.software.clone(),
            protocol: r.protocol,
            uptime_secs: r.uptime_secs,
            storage: r.storage.into(),
            wake: r.wake.map(Into::into),
            push_link: r.push_link.map(Into::into),
        }
    }
}

/// A node's detail.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NodeDetail {
    pub node: NodeInfo,
    /// Addresses of its signed record.
    pub v4: Option<String>,
    pub v6: Option<String>,
    /// Its last report; `None` if never fetched or if it speaks a protocol
    /// older than 5.
    pub report: Option<NodeReportView>,
    /// Unix seconds (to the hour) the report was fetched.
    pub fetched_at: Option<u64>,
    /// Protocol version it speaks: its report's, or the one the session
    /// of `refresh_node_info` negotiated.
    pub peer_version: Option<u16>,
}

/// A blocked node.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BlockedNode {
    pub id: String,
    /// Unix seconds (to the hour) of the block.
    pub at: u64,
    /// The hosting it declared when blocked, if known.
    pub origin: Option<OriginView>,
}

/// A default node shipped with the app.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DefaultNode {
    /// Base32 identifier.
    pub id: String,
    /// `ip:port`.
    pub addr: String,
}

/// Reliability of a node: `Avoided` if `avoided` (until, reason), `New` if
/// it never answered, else by score (spec §6.5).
fn reliability(confirmed: bool, score: f32, avoided: Option<(u64, AvoidReason)>) -> Reliability {
    if let Some((until, reason)) = avoided {
        return Reliability::Avoided { until, reason };
    }
    if !confirmed {
        Reliability::New
    } else if score >= 0.5 {
        Reliability::Good
    } else if score >= 0.3 {
        Reliability::Fair
    } else {
        Reliability::Weak
    }
}

/// In use: added by hand or by default, holding one of my copies or wake
/// subscriptions, or confirmed and seen within `IN_USE_SECS`. A node only
/// heard of (its record learned, never answered) is not in use.
fn in_use(e: &NodeEntry, is_default: bool, holder: bool, my_subscriptions: u32, now: u64) -> bool {
    let recent = e.confirmed && e.last_seen > 0 && now.saturating_sub(e.last_seen) < IN_USE_SECS;
    e.manual || is_default || holder || my_subscriptions > 0 || recent
}

/// Rank of a reliability in the list: Good, Fair, New, Weak, Avoided.
fn rank(r: &Reliability) -> u8 {
    match r {
        Reliability::Good => 0,
        Reliability::Fair => 1,
        Reliability::New => 2,
        Reliability::Weak => 3,
        Reliability::Avoided { .. } => 4,
    }
}

/// Order of the list: in use first, then by reliability, then by latency
/// (unknown last), then best score, then identifier.
fn list_order(a: &NodeInfo, b: &NodeInfo) -> Ordering {
    b.in_use
        .cmp(&a.in_use)
        .then_with(|| rank(&a.reliability).cmp(&rank(&b.reliability)))
        .then_with(|| match (a.latency_ms, b.latency_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| b.score.total_cmp(&a.score))
        .then_with(|| a.id.cmp(&b.id))
}

/// A 2-letter code in uppercase; never panics on bytes that are not ASCII.
fn country(c: [u8; 2]) -> String {
    String::from_utf8_lossy(&c).to_ascii_uppercase()
}

fn verdict_view(v: OriginVerdict) -> OriginVerdictView {
    match v {
        OriginVerdict::Matches => OriginVerdictView::Matches,
        OriginVerdict::Mismatch {
            declared_asn,
            declared_country,
            observed_asn,
            observed_country,
        } => OriginVerdictView::Mismatch {
            declared_country: country(declared_country),
            observed_country: country(observed_country),
            declared_asn,
            observed_asn,
        },
        OriginVerdict::Unverifiable(UnverifiableReason::NotReported) => {
            OriginVerdictView::NotReported
        }
        OriginVerdict::Unverifiable(UnverifiableReason::NotInBase) => OriginVerdictView::NotInBase,
        OriginVerdict::Unverifiable(UnverifiableReason::NoRecord) => OriginVerdictView::NoRecord,
    }
}

/// `origin` checked against `observed`, the address the node answered on
/// when it sent it (`CachedInfo::observed`), never against its record.
fn origin_view(db: Option<&IpDb>, origin: &NodeOrigin, observed: Option<IpAddr>) -> OriginView {
    OriginView {
        asn: origin.asn,
        as_name: origin.as_name.clone(),
        country: country(origin.country),
        verdict: verdict_view(verdict(db, Some(origin), observed)),
    }
}

/// A node identifier given by the app.
fn parse_id(id: &str) -> Result<NodeId, BarkingError> {
    id.trim()
        .to_ascii_uppercase()
        .parse()
        .map_err(|_| BarkingError::invalid("node identifier: 52-character base32 expected"))
}

/// A node identifier and address given by the app to add a node.
fn parse_node(id: &str, addr: &str) -> Result<(NodeId, SocketAddr), BarkingError> {
    let id = parse_id(id)?;
    if !id.puzzle_ok() {
        return Err(BarkingError::invalid(
            "node identifier does not solve the identity puzzle",
        ));
    }
    let addr: SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| BarkingError::invalid("node address: ip:port expected"))?;
    Ok((id, addr))
}

fn parse_defaults(entries: &[DefaultNode]) -> Result<Vec<(NodeId, SocketAddr)>, BarkingError> {
    entries.iter().map(|e| parse_node(&e.id, &e.addr)).collect()
}

/// Why each avoided node of `ids` (short identifiers) was set aside: the
/// newest `NodeAvoided` entry of the transparency log for it. The view
/// keeps no reason; a node whose entry is gone (purged log) is left out.
fn avoid_reasons(core: &Core, mut ids: HashSet<String>) -> HashMap<String, AvoidReason> {
    let mut out = HashMap::new();
    let mut before = None;
    while !ids.is_empty() {
        let Ok(page) = core.transparency_page(LOG_PAGE, before, false) else {
            break;
        };
        let Some(&(last, _, _)) = page.last() else {
            break;
        };
        for (_, _, e) in page {
            if let TransparencyEvent::NodeAvoided { node, reason } = e
                && ids.remove(&node)
            {
                out.insert(node, reason.into());
            }
        }
        before = Some(last);
    }
    out
}

/// Everything a node's line needs beside its entry, read once per call.
struct Context {
    state: NetState,
    from_cards: HashSet<NodeId>,
    /// Nodes holding one of my copies (deposit ledger).
    holders: HashSet<NodeId>,
    /// My wake subscriptions per node.
    subscriptions: HashMap<NodeId, u32>,
    avoid_reasons: HashMap<String, AvoidReason>,
    db: Option<Arc<IpDb>>,
    now: u64,
}

impl Context {
    /// Reads the network and push states of `core` (as `state`, if given).
    fn load(
        core: &mut Core,
        device: &Device,
        state: Option<NetState>,
        now: u64,
    ) -> Result<Context, BarkingError> {
        let state = match state {
            Some(s) => s,
            None => {
                NetState::load_checked(core, now, device.allow_private())
                    .map_err(BarkingError::storage)?
                    .0
            }
        };
        let hints = core.contact_node_hints().unwrap_or_default();
        let from_cards = barking_net::card_hint_ids(&state.view, &hints, now)
            .into_iter()
            .collect();
        let push = PushState::load(core)?;
        let mut subscriptions: HashMap<NodeId, u32> = HashMap::new();
        for subs in push.subs.values() {
            let nodes: HashSet<NodeId> = subs.nodes.iter().map(|(n, _)| *n).collect();
            for n in nodes {
                *subscriptions.entry(n).or_default() += 1;
            }
        }
        let avoided: HashSet<String> = state
            .view
            .entries()
            .filter(|(_, e)| e.avoided(now))
            .map(|(id, _)| short_id(id))
            .collect();
        let avoid_reasons = if avoided.is_empty() {
            HashMap::new()
        } else {
            avoid_reasons(core, avoided)
        };
        Ok(Context {
            holders: state.ledger.holder_nodes(),
            from_cards,
            subscriptions,
            avoid_reasons,
            db: device.ipdb(),
            state,
            now,
        })
    }

    fn info(&self, id: &NodeId, e: &NodeEntry) -> NodeInfo {
        let addr = e
            .manual_addr
            .map(|a| a.to_string())
            .or_else(|| {
                e.record
                    .as_ref()
                    .and_then(|r| r.v4.map(|a| a.to_string()).or(r.v6.map(|a| a.to_string())))
            })
            .unwrap_or_default();
        let avoided = e.avoided(self.now).then(|| {
            let reason = self
                .avoid_reasons
                .get(&short_id(id))
                .copied()
                // No log entry left: the scoring avoids for failures far
                // more often than for a loss.
                .unwrap_or(AvoidReason::Unreachable);
            (e.avoided_until.unwrap_or(0), reason)
        });
        let is_default = self.state.defaults.contains(id);
        let from_card = self.from_cards.contains(id);
        let kind = if is_default {
            NodeOriginKind::Bootstrap
        } else if e.manual {
            NodeOriginKind::Manual
        } else if from_card {
            NodeOriginKind::FromCard
        } else {
            NodeOriginKind::Discovered
        };
        let my_subscriptions = self.subscriptions.get(id).copied().unwrap_or(0);
        let in_use = in_use(
            e,
            is_default,
            self.holders.contains(id),
            my_subscriptions,
            self.now,
        );
        let origin = self.state.info.get(id).and_then(|c| {
            let o = c.report.origin.as_ref()?;
            Some(origin_view(self.db.as_deref(), o, c.observed))
        });
        NodeInfo {
            id: id.to_string(),
            addr,
            reliability: reliability(e.confirmed, e.score.value(), avoided),
            score: e.score.value(),
            manual: e.manual,
            from_card,
            // Learning a node's record moves `last_seen` too: only an
            // answer of the node itself counts here.
            last_seen: if e.confirmed { e.last_seen } else { 0 },
            latency_ms: self.state.median_latency(id),
            in_use,
            origin,
            my_subscriptions,
            kind,
        }
    }

    fn list(&self) -> Vec<NodeInfo> {
        let mut out: Vec<NodeInfo> = self
            .state
            .view
            .entries()
            .map(|(id, e)| self.info(id, e))
            .collect();
        out.sort_by(list_order);
        out
    }

    /// The detail of `id`; `NotFound` if it is not in the view (a blocked
    /// node never is).
    fn detail(&self, id: &NodeId) -> Result<NodeDetail, BarkingError> {
        let e = self.state.view.get(id).ok_or(BarkingError::NotFound)?;
        let cached: Option<&CachedInfo> = self.state.info.get(id);
        let record = e.record.as_ref();
        Ok(NodeDetail {
            node: self.info(id, e),
            v4: record.and_then(|r| r.v4).map(|a| a.to_string()),
            v6: record.and_then(|r| r.v6).map(|a| a.to_string()),
            report: cached.map(|c| NodeReportView::from(&c.report)),
            fetched_at: cached.map(|c| c.fetched_at),
            peer_version: cached.map(|c| c.report.protocol),
        })
    }
}

/// What a dial of `refresh_node_info` brought back.
struct Exchange {
    peer_version: u16,
    report: Option<NodeInfoReport>,
    rtt: Vec<std::time::Duration>,
    /// The address the pinned connection reached (`CachedInfo::observed`).
    observed: Option<IpAddr>,
}

/// What `refresh_node_info` reads under the lock before dialling.
struct DialPlan {
    addrs: Vec<SocketAddr>,
    /// The push relay to ask about, only to a node holding one of my
    /// subscriptions.
    relay: Option<NodeId>,
}

/// Connects to `id` at `addrs` (the sync's dialer) and asks its report,
/// about `relay` when push is on.
async fn exchange(
    id: NodeId,
    addrs: &[SocketAddr],
    relay: Option<NodeId>,
) -> Result<Exchange, BarkingError> {
    let network = |e: &dyn std::fmt::Display| BarkingError::Network {
        detail: e.to_string(),
    };
    let dialer = QuicDialer;
    let mut conn = dialer.connect(id, addrs).await.map_err(|e| network(&e))?;
    let peer_version = conn.peer_version();
    let observed = dialer.remote_addr(&conn).map(|a| a.ip());
    let report = tokio::time::timeout(DIAL_TIMEOUT, dialer.info(&mut conn, relay)).await;
    let rtt = dialer.rtt_samples(&conn);
    dialer.close(conn).await;
    let report = match report {
        Ok(Ok(report)) => report,
        Ok(Err(e)) => return Err(network(&e)),
        Err(_) => return Err(network(&"the node does not respond in time")),
    };
    Ok(Exchange {
        peer_version,
        report,
        rtt,
        observed,
    })
}

impl Device {
    /// `refresh_node_info` with `dial` doing the exchange, between two short
    /// holds of the lock: none while `dial` runs.
    fn refresh_with(
        &self,
        id: NodeId,
        dial: impl FnOnce(NodeId, &[SocketAddr], Option<NodeId>) -> Result<Exchange, BarkingError>,
    ) -> Result<NodeDetail, BarkingError> {
        let allow_private = self.allow_private();
        let plan = self.with_core(|core| {
            let (state, _) = NetState::load_checked(core, now(), allow_private)
                .map_err(BarkingError::storage)?;
            if state.blocked.contains_key(&id) {
                return Err(BarkingError::invalid("node is blocked"));
            }
            let addrs = state.view.get(&id).ok_or(BarkingError::NotFound)?.addrs();
            // The relay only to a node holding one of my subscriptions
            // (the others would learn which relay rings this device).
            let relay = PushConfig::effective(core)?
                .map(|c| c.relay.id)
                .filter(|_| {
                    PushState::load(core).is_ok_and(|p| p.subscribed_nodes().contains(&id))
                });
            Ok(DialPlan { addrs, relay })
        })?;
        let got = dial(id, &plan.addrs, plan.relay)?;
        self.with_core(|core| {
            // Read again: a sync, a block or a removal may have landed
            // during the dial, and saving the state read before it would
            // undo them.
            let t = now();
            let (mut state, _) =
                NetState::load_checked(core, t, allow_private).map_err(BarkingError::storage)?;
            if state.blocked.contains_key(&id) {
                return Err(BarkingError::invalid("node is blocked"));
            }
            if state.view.get(&id).is_none() {
                return Err(BarkingError::NotFound);
            }
            // The session proved the node: it answered as itself.
            state.view.confirm(&id, t);
            state.note_latency(id, &got.rtt);
            if let Some(report) = got.report {
                state.info.insert(
                    id,
                    CachedInfo {
                        report,
                        fetched_at: t,
                        observed: got.observed,
                    },
                );
            }
            state.save(core).map_err(BarkingError::storage)?;
            let mut detail = Context::load(core, self, Some(state), t)?.detail(&id)?;
            detail.peer_version = Some(got.peer_version);
            Ok(detail)
        })
    }
}

#[uniffi::export]
impl Device {
    /// Nodes of the local view: in use first, then by reliability (Good,
    /// Fair, New, Weak, Avoided), then by latency (unknown last).
    pub fn nodes(&self) -> Result<Vec<NodeInfo>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let ctx = Context::load(core, self, None, now())?;
                Ok(ctx.list())
            })
        })
    }

    /// Detail of a node of the view, from what is stored (no dial):
    /// `NotFound` if it is not in the view.
    pub fn node_detail(&self, id: String) -> Result<NodeDetail, BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            self.with_core_read(|core| Context::load(core, self, None, now())?.detail(&id))
        })
    }

    /// Dials the node, asks its report (about the push relay when push is
    /// on), records the round trips, the report and the address the node
    /// answered on, and returns the detail, with the protocol version the
    /// session negotiated. The lock is held only to read what the dial needs
    /// and to save its outcome, not during the dial (module documentation).
    /// A blocked node is refused (`InvalidInput`, "node is blocked"), before
    /// the dial or if it was blocked during it (the answer is then dropped);
    /// a node not in the view is `NotFound`; a node that does not answer is
    /// `Network`, what is stored unchanged.
    pub fn refresh_node_info(&self, id: String) -> Result<NodeDetail, BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            self.refresh_with(id, |id, addrs, relay| block_on(exchange(id, addrs, relay))?)
        })
    }

    /// Adds a node by hand (base32 identifier, `host:port` address). A
    /// blocked node is refused (`InvalidInput`, "node is blocked"). Waits
    /// for a sync in progress (module documentation).
    pub fn add_node(&self, id: String, addr: String) -> Result<(), BarkingError> {
        guard(|| {
            let (id, addr) = parse_node(&id, &addr)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                let t = now();
                let (mut state, _) = NetState::load_checked(core, t, allow_private)
                    .map_err(BarkingError::storage)?;
                if state.blocked.contains_key(&id) {
                    return Err(BarkingError::invalid("node is blocked"));
                }
                state.view.add_manual(id, addr, t);
                state.save(core).map_err(BarkingError::storage)
            })
        })
    }

    /// Removes a node added by hand or a default node (which is then not
    /// added again at launch). A node the network also knows stays as an
    /// ordinary entry. Waits for a sync in progress (module documentation).
    pub fn remove_node(&self, id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                nodes::remove_node_in_core(core, &id, now(), allow_private)
                    .map(|_| ())
                    .map_err(BarkingError::storage)
            })
        })
    }

    /// Blocks a node: it leaves the view and is never contacted again until
    /// unblocked (spec §6.4); logged. Waits for a sync in progress, which
    /// then cannot overwrite the block (module documentation).
    pub fn block_node(&self, id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                nodes::block_node_in_core(core, id, now(), allow_private)
                    .map_err(BarkingError::storage)
            })
        })
    }

    /// Unblocks a node: it comes back only by the normal ways; logged if it
    /// was blocked. Waits for a sync in progress (module documentation).
    pub fn unblock_node(&self, id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                nodes::unblock_node_in_core(core, &id, now(), allow_private)
                    .map(|_| ())
                    .map_err(BarkingError::storage)
            })
        })
    }

    /// Blocked nodes, most recent block first.
    pub fn blocked_nodes(&self) -> Result<Vec<BlockedNode>, BarkingError> {
        guard(|| {
            let allow_private = self.allow_private();
            self.with_core_read(|core| {
                let (state, _) = NetState::load_checked(core, now(), allow_private)
                    .map_err(BarkingError::storage)?;
                let db = self.ipdb();
                let mut out: Vec<BlockedNode> = state
                    .blocked
                    .iter()
                    .map(|(id, b)| BlockedNode {
                        id: id.to_string(),
                        at: b.at,
                        // The entry left the view with its record.
                        origin: b
                            .origin
                            .as_ref()
                            .map(|o| origin_view(db.as_deref(), o, None)),
                    })
                    .collect();
                out.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.id.cmp(&b.id)));
                Ok(out)
            })
        })
    }

    /// The default nodes shipped with the app, at launch: each one neither
    /// removed nor blocked is added by hand, marked as a default node.
    /// Waits for a sync in progress (module documentation).
    pub fn add_default_nodes(&self, entries: Vec<DefaultNode>) -> Result<(), BarkingError> {
        guard(|| {
            let entries = parse_defaults(&entries)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                nodes::add_default_nodes_in_core(core, &entries, now(), allow_private)
                    .map_err(BarkingError::storage)
            })
        })
    }

    /// Restores the default nodes the user removed, then adds `entries`;
    /// a blocked one stays blocked. Returns how many were restored. Waits
    /// for a sync in progress (module documentation).
    pub fn reset_default_nodes(&self, entries: Vec<DefaultNode>) -> Result<u32, BarkingError> {
        guard(|| {
            let entries = parse_defaults(&entries)?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                nodes::reset_default_nodes_in_core(core, &entries, now(), allow_private)
                    .map_err(BarkingError::storage)
            })
        })
    }

    /// Number of default nodes the user removed.
    pub fn dismissed_defaults_count(&self) -> Result<u32, BarkingError> {
        guard(|| {
            let allow_private = self.allow_private();
            self.with_core_read(|core| {
                let (state, _) = NetState::load_checked(core, now(), allow_private)
                    .map_err(BarkingError::storage)?;
                Ok(u32::try_from(state.dismissed_defaults.len()).unwrap_or(u32::MAX))
            })
        })
    }

    /// Nodes still usable (answered once, not avoided) if `id` were
    /// blocked: the app warns when it is below the copies a message gets
    /// (3).
    pub fn usable_nodes_if_blocked(&self, id: String) -> Result<u32, BarkingError> {
        guard(|| {
            let id = parse_id(&id)?;
            let allow_private = self.allow_private();
            self.with_core_read(|core| {
                let t = now();
                let (state, _) = NetState::load_checked(core, t, allow_private)
                    .map_err(BarkingError::storage)?;
                let usable = state
                    .view
                    .entries()
                    .filter(|(n, e)| **n != id && e.confirmed && !e.avoided(t))
                    .count();
                Ok(u32::try_from(usable).unwrap_or(u32::MAX))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(manual: bool, confirmed: bool, last_seen: u64) -> NodeEntry {
        NodeEntry {
            record: None,
            manual_addr: None,
            confirmed,
            manual,
            first_seen: 0,
            last_seen,
            score: Default::default(),
            avoided_until: None,
            decayed_at: 0,
        }
    }

    #[test]
    fn in_use_needs_a_reason_or_a_recent_answer() {
        let now = 1_800_000_000;
        let recent = now - 3_600;
        let old = now - IN_USE_SECS;
        // Each reason alone.
        assert!(
            in_use(&entry(true, false, 0), false, false, 0, now),
            "manual"
        );
        assert!(
            in_use(&entry(false, false, 0), true, false, 0, now),
            "default"
        );
        assert!(
            in_use(&entry(false, false, 0), false, true, 0, now),
            "holder"
        );
        assert!(
            in_use(&entry(false, false, 0), false, false, 1, now),
            "subscription"
        );
        assert!(
            in_use(&entry(false, true, recent), false, false, 0, now),
            "recent, confirmed"
        );
        // Only heard of: its record learned recently, never answered.
        assert!(
            !in_use(&entry(false, false, recent), false, false, 0, now),
            "recent, unconfirmed"
        );
        assert!(
            !in_use(&entry(false, true, old), false, false, 0, now),
            "confirmed, too old"
        );
        assert!(
            !in_use(&entry(false, true, 0), false, false, 0, now),
            "never seen"
        );
    }

    #[test]
    fn reliability_thresholds() {
        assert_eq!(reliability(true, 0.5, None), Reliability::Good);
        assert_eq!(reliability(true, 1.0, None), Reliability::Good);
        assert_eq!(reliability(true, 0.49, None), Reliability::Fair);
        assert_eq!(reliability(true, 0.3, None), Reliability::Fair);
        assert_eq!(reliability(true, 0.29, None), Reliability::Weak);
        // Never answered: new, whatever the score.
        assert_eq!(reliability(false, 0.5, None), Reliability::New);
        assert_eq!(reliability(false, 0.1, None), Reliability::New);
        // Avoided first.
        let avoided = Some((7_200, AvoidReason::MessageLost));
        let expect = Reliability::Avoided {
            until: 7_200,
            reason: AvoidReason::MessageLost,
        };
        assert_eq!(reliability(true, 0.9, avoided), expect);
        assert_eq!(reliability(false, 0.9, avoided), expect);
    }

    fn line(id: &str, in_use: bool, reliability: Reliability, latency_ms: Option<u32>) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            addr: String::new(),
            reliability,
            score: 0.5,
            manual: false,
            from_card: false,
            last_seen: 0,
            latency_ms,
            in_use,
            origin: None,
            my_subscriptions: 0,
            kind: NodeOriginKind::Discovered,
        }
    }

    #[test]
    fn list_order_in_use_then_reliability_then_latency() {
        let avoided = Reliability::Avoided {
            until: 1,
            reason: AvoidReason::Unreachable,
        };
        let mut lines = vec![
            line("a", false, Reliability::Good, Some(10)),
            line("b", true, avoided.clone(), Some(5)),
            line("c", true, Reliability::Weak, None),
            line("d", true, Reliability::New, Some(80)),
            line("e", true, Reliability::Fair, None),
            line("f", true, Reliability::Good, None),
            line("g", true, Reliability::Good, Some(70)),
            line("h", true, Reliability::Good, Some(20)),
            line("i", false, avoided, None),
        ];
        lines.sort_by(list_order);
        let order: String = lines.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(order, "hgfedcbai");
    }

    #[test]
    fn countries_are_uppercase_and_never_panic() {
        assert_eq!(country(*b"fr"), "FR");
        assert_eq!(country([0xFF, b'x']), "\u{FFFD}X");
        let v = verdict_view(OriginVerdict::Mismatch {
            declared_asn: 1,
            declared_country: *b"de",
            observed_asn: 2,
            observed_country: *b"NL",
        });
        assert_eq!(
            v,
            OriginVerdictView::Mismatch {
                declared_country: "DE".into(),
                observed_country: "NL".into(),
                declared_asn: 1,
                observed_asn: 2,
            }
        );
    }

    /// A device with node `n` added by hand, its lock never waited for:
    /// a held lock fails at once (`Locked`).
    fn device_with_node(dir: &tempfile::TempDir, n: usize) -> (Arc<Device>, NodeId) {
        let config = crate::DeviceConfig {
            db_path: dir.path().join("barking.db").display().to_string(),
            lock_path: dir.path().join("barking.lock").display().to_string(),
            db_key: vec![1; 32],
            lock_timeout_ms: 0,
            allow_private: true,
        };
        let d = Device::create(config, "a".into()).unwrap().device;
        let key = barking_node::testing::key(n);
        let id = NodeId::from_public_key(&key.verifying_key());
        d.add_node(id.to_string(), "127.0.0.1:9".into()).unwrap();
        (d, id)
    }

    fn answer(observed: &str) -> Exchange {
        Exchange {
            peer_version: 5,
            report: Some(NodeInfoReport {
                software: "barking-node 0.5.0".into(),
                protocol: 5,
                uptime_secs: 60,
                storage: FillTier::Low,
                wake: None,
                push_link: None,
                origin: None,
            }),
            rtt: vec![std::time::Duration::from_millis(30)],
            observed: Some(observed.parse().unwrap()),
        }
    }

    fn cached(d: &Device, id: &NodeId) -> Option<CachedInfo> {
        d.with_core(|core| {
            let (state, _) =
                NetState::load_checked(core, now(), true).map_err(BarkingError::storage)?;
            Ok(state.info.get(id).cloned())
        })
        .unwrap()
    }

    /// The dial runs without the lock: another call (here a write, with no
    /// wait allowed) goes through meanwhile; the answer, and the address it
    /// came from, are saved afterwards.
    #[test]
    fn refresh_dials_without_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (d, id) = device_with_node(&dir, 1);
        let detail = d
            .refresh_with(id, |_, addrs, relay| {
                assert_eq!(addrs, ["127.0.0.1:9".parse().unwrap()]);
                assert_eq!(relay, None);
                // Would be `Locked` if the refresh held the lock.
                d.add_node(id.to_string(), "127.0.0.1:10".into())?;
                Ok(answer("203.0.113.9"))
            })
            .unwrap();
        assert_eq!(detail.peer_version, Some(5));
        assert!(detail.report.is_some());
        assert_eq!(detail.node.latency_ms, Some(30));
        let c = cached(&d, &id).unwrap();
        assert_eq!(c.observed, Some("203.0.113.9".parse().unwrap()));
    }

    /// Blocked during the dial: the answer is dropped and the refresh says
    /// so as for a node blocked before; removed during it: `NotFound`.
    #[test]
    fn refresh_drops_the_answer_of_a_node_blocked_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let (d, id) = device_with_node(&dir, 1);
        let r = d.refresh_with(id, |id, _, _| {
            d.block_node(id.to_string())?;
            Ok(answer("203.0.113.9"))
        });
        assert!(
            matches!(&r, Err(BarkingError::InvalidInput { detail }) if detail.contains("node is blocked")),
            "{r:?}"
        );
        assert_eq!(cached(&d, &id), None);
        assert!(
            d.blocked_nodes()
                .unwrap()
                .iter()
                .any(|b| b.id == id.to_string())
        );
        // Blocked before: never dialled.
        let r = d.refresh_with(id, |_, _, _| panic!("a blocked node is dialled"));
        assert!(matches!(r, Err(BarkingError::InvalidInput { .. })));

        let dir = tempfile::tempdir().unwrap();
        let (d, id) = device_with_node(&dir, 2);
        let r = d.refresh_with(id, |id, _, _| {
            d.remove_node(id.to_string())?;
            Ok(answer("203.0.113.9"))
        });
        assert!(matches!(r, Err(BarkingError::NotFound)), "{r:?}");
        assert_eq!(cached(&d, &id), None);
    }
}
