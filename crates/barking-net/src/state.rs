//! State of the network client kept between synchronizations (spec §8): the
//! view, the deposit ledger, the fetch positions per node and mailbox, the
//! dates of the fallback lookups and the count of syncs in which a node never
//! let its session fetch complete. Encoded with postcard in the core's
//! encrypted database (`Core::transport_state("net")`), never in the clear.
//!
//! The old synchronization (`barking-cli`, key `"netsync"`) kept positions
//! and deposits per node in TOML; [`NetState::load`] migrates them, then
//! erases that key. Its format lives here ([`LegacyState`]); the CLI uses it
//! to move even older plaintext files to that key before loading.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use barking_core::{Core, CoreError};
use barking_packet::{MailboxId, Packet};
use barking_proto::client::{FETCH_PAGE_SIZES, FetchResume};
use barking_proto::pow::content_hash;
use barking_proto::{MIN_PAGE_BYTES, NodeId, NodeInfoReport, NodeOrigin};
use serde::{Deserialize, Serialize};

use crate::discover::FallbackLog;
use crate::plan::{Ledger, REDEPOSIT_AFTER_SECS};
use crate::view::{View, hour};

/// Key of the state in the core's database.
pub const STATE_KEY: &str = "net";
/// Key of the old synchronization's state, migrated then erased.
pub const LEGACY_STATE_KEY: &str = "netsync";
/// Nodes that failed in a sync that ended as network down are ranked last
/// for this long.
pub const DOWN_FAILED_SECS: u64 = 86_400;
/// Latency samples kept per node (the last ones).
pub const LATENCY_SAMPLES: usize = 8;
/// Version of the encoding written. Format 1 (`StoredV1`) still reads and is
/// migrated; any other value reads as an unreadable state. Both layouts are
/// frozen, as are the nested view and ledger encodings: any change to them
/// must bump `FORMAT` and migrate the older formats
/// (`format_1_bytes_are_frozen` and `format_2_bytes_are_frozen` hold their
/// bytes).
const FORMAT: u8 = 2;
/// Format 1, as first released: `StoredV1`.
const FORMAT_1: u8 = 1;

/// Everything the network client keeps between synchronizations.
#[derive(Clone, Debug)]
pub struct NetState {
    pub view: View,
    pub ledger: Ledger,
    /// Fetch position per (node, mailbox) (see `FetchResume`); absent: 0.
    pub positions: HashMap<(NodeId, MailboxId), u64>,
    /// Dates of the last fallback lookups, by mailbox key.
    pub fallbacks: FallbackLog,
    /// Consecutive syncs in which the node's session fetch never completed.
    pub unaudited: HashMap<NodeId, u32>,
    /// Date (hour) of the last loss audit of a mailbox on a node: a full
    /// read from the start of the mailbox.
    pub audited_at: HashMap<(NodeId, MailboxId), u64>,
    /// Date (hour) of the last audit re-read of a mailbox on a node, even one
    /// cut short: a re-read is not tried again before `AUDIT_EVERY_SECS`.
    pub reread_at: HashMap<(NodeId, MailboxId), u64>,
    /// Date (hour) of the last cross-check of a session mailbox on a node
    /// other than the one that served it (`CROSSCHECK_EVERY_SECS`).
    pub crosscheck_at: HashMap<(NodeId, MailboxId), u64>,
    /// Date (hour) a node failed in a sync that ended as network down: for
    /// `DOWN_FAILED_SECS` it ranks after every other node, so that the next
    /// sync dials other nodes first.
    pub down_failed: HashMap<NodeId, u64>,
    /// Fetch page size the link to a node reached (`Session::page_bytes`),
    /// carried to the next sync: a slow link does not start again from the
    /// largest page every time. It doubles back toward the default at each
    /// sync no page timeout confirmed it (`recover_page_bytes`), so that a
    /// forced shrink does not last. Absent: `FETCH_PAGE_SIZES[0]`.
    pub page_bytes: HashMap<NodeId, u32>,
    /// Last self-report of a node (`Info`), kept for nodes of the view only.
    pub info: HashMap<NodeId, CachedInfo>,
    /// Last round-trip times to a node, in milliseconds, oldest first (at
    /// most `LATENCY_SAMPLES`). Stays on the device, like the score.
    pub latency: HashMap<NodeId, Vec<u32>>,
    /// Nodes the user blocked: the view refuses them (`View::set_blocked`).
    pub blocked: HashMap<NodeId, BlockedEntry>,
    /// Default nodes shipped with the app, as added at launch.
    pub defaults: HashSet<NodeId>,
    /// Default nodes the user removed: not added again at launch.
    pub dismissed_defaults: HashSet<NodeId>,
}

/// A node's self-report and the date (hour) it was fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedInfo {
    pub report: NodeInfoReport,
    pub fetched_at: u64,
}

/// A blocked node: date (hour) of the block, and the origin it declared
/// then, if known (for the user to recognise it in the list).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedEntry {
    pub at: u64,
    pub origin: Option<NodeOrigin>,
}

/// Failure to read or write the state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("the network state cannot be encoded")]
    Encode,
}

/// Stored form, format 2: format 1's fields unchanged, then the new tables.
/// The view and the ledger are nested encodings so that their own `restore`
/// checks them again on load.
#[derive(Serialize, Deserialize)]
struct Stored {
    format: u8,
    view: Vec<u8>,
    ledger: Vec<u8>,
    positions: Vec<(NodeId, MailboxId, u64)>,
    fallbacks: FallbackLog,
    unaudited: Vec<(NodeId, u32)>,
    audited_at: Vec<(NodeId, MailboxId, u64)>,
    reread_at: Vec<(NodeId, MailboxId, u64)>,
    crosscheck_at: Vec<(NodeId, MailboxId, u64)>,
    down_failed: Vec<(NodeId, u64)>,
    page_bytes: Vec<(NodeId, u32)>,
    info: Vec<(NodeId, CachedInfo)>,
    latency: Vec<(NodeId, Vec<u32>)>,
    blocked: Vec<(NodeId, BlockedEntry)>,
    defaults: Vec<NodeId>,
    dismissed_defaults: Vec<NodeId>,
}

/// Stored form, format 1, as first released: read only, to migrate. Frozen.
#[derive(Serialize, Deserialize)]
struct StoredV1 {
    format: u8,
    view: Vec<u8>,
    ledger: Vec<u8>,
    positions: Vec<(NodeId, MailboxId, u64)>,
    fallbacks: FallbackLog,
    unaudited: Vec<(NodeId, u32)>,
    audited_at: Vec<(NodeId, MailboxId, u64)>,
    reread_at: Vec<(NodeId, MailboxId, u64)>,
    crosscheck_at: Vec<(NodeId, MailboxId, u64)>,
    down_failed: Vec<(NodeId, u64)>,
    page_bytes: Vec<(NodeId, u32)>,
}

impl From<StoredV1> for Stored {
    /// Format 1 migrated: every field kept, the new tables empty.
    fn from(v1: StoredV1) -> Stored {
        Stored {
            format: FORMAT,
            view: v1.view,
            ledger: v1.ledger,
            positions: v1.positions,
            fallbacks: v1.fallbacks,
            unaudited: v1.unaudited,
            audited_at: v1.audited_at,
            reread_at: v1.reread_at,
            crosscheck_at: v1.crosscheck_at,
            down_failed: v1.down_failed,
            page_bytes: v1.page_bytes,
            info: Vec::new(),
            latency: Vec::new(),
            blocked: Vec::new(),
            defaults: Vec::new(),
            dismissed_defaults: Vec::new(),
        }
    }
}

impl NetState {
    /// An empty state.
    pub fn new(allow_private: bool) -> NetState {
        NetState {
            view: View::new(allow_private),
            ledger: Ledger::default(),
            positions: HashMap::new(),
            fallbacks: FallbackLog::default(),
            unaudited: HashMap::new(),
            audited_at: HashMap::new(),
            reread_at: HashMap::new(),
            crosscheck_at: HashMap::new(),
            down_failed: HashMap::new(),
            page_bytes: HashMap::new(),
            info: HashMap::new(),
            latency: HashMap::new(),
            blocked: HashMap::new(),
            defaults: HashSet::new(),
            dismissed_defaults: HashSet::new(),
        }
    }

    /// Reads the state, migrating the old synchronization's state if there
    /// is one (it is then erased). An unreadable state gives an empty one,
    /// with a warning that carries no data. Only a database error fails:
    /// starting empty would then overwrite a good state.
    pub fn load(core: &mut Core, now: u64, allow_private: bool) -> Result<NetState, StateError> {
        Ok(NetState::load_checked(core, now, allow_private)?.0)
    }

    /// Like `load`, also telling whether a stored state was unreadable and
    /// replaced by an empty one (its nodes added by hand lost with it), for
    /// the caller to tell the user.
    pub fn load_checked(
        core: &mut Core,
        now: u64,
        allow_private: bool,
    ) -> Result<(NetState, bool), StateError> {
        let mut reset = false;
        let mut state = match core.transport_state(STATE_KEY)? {
            Some(bytes) => NetState::decode(&bytes, now, allow_private).unwrap_or_else(|| {
                tracing::warn!("unreadable network state: starting from an empty one");
                reset = true;
                NetState::new(allow_private)
            }),
            None => NetState::new(allow_private),
        };
        state.migrate_legacy(core, now)?;
        Ok((state, reset))
    }

    /// Writes the state to the core's encrypted database. A state that
    /// cannot be encoded is not written: the stored one stays.
    pub fn save(&self, core: &mut Core) -> Result<(), StateError> {
        Ok(core.set_transport_state(STATE_KEY, &self.encode()?)?)
    }

    /// Postcard encoding of the state.
    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        postcard::to_allocvec(&self.stored()?).map_err(|_| StateError::Encode)
    }

    /// Stored form, tables sorted by node so that the bytes are stable;
    /// dates rounded to the hour.
    fn stored(&self) -> Result<Stored, StateError> {
        let triples = |map: &HashMap<(NodeId, MailboxId), u64>| {
            let mut v: Vec<(NodeId, MailboxId, u64)> =
                map.iter().map(|(&(n, m), &s)| (n, m, s)).collect();
            v.sort_unstable_by_key(|(n, m, _)| (n.0, m.0));
            v
        };
        let mut unaudited: Vec<(NodeId, u32)> =
            self.unaudited.iter().map(|(&n, &c)| (n, c)).collect();
        unaudited.sort_unstable_by_key(|(n, _)| n.0);
        let mut down_failed: Vec<(NodeId, u64)> =
            self.down_failed.iter().map(|(&n, &t)| (n, t)).collect();
        down_failed.sort_unstable_by_key(|(n, _)| n.0);
        let mut page_bytes: Vec<(NodeId, u32)> =
            self.page_bytes.iter().map(|(&n, &b)| (n, b)).collect();
        page_bytes.sort_unstable_by_key(|(n, _)| n.0);
        let sorted = |set: &HashSet<NodeId>| {
            let mut v: Vec<NodeId> = set.iter().copied().collect();
            v.sort_unstable_by_key(|n| n.0);
            v
        };
        let mut info: Vec<(NodeId, CachedInfo)> = self
            .info
            .iter()
            .map(|(&n, c)| {
                let mut c = c.clone();
                c.fetched_at = hour(c.fetched_at);
                (n, c)
            })
            .collect();
        info.sort_unstable_by_key(|(n, _)| n.0);
        let mut latency: Vec<(NodeId, Vec<u32>)> =
            self.latency.iter().map(|(&n, l)| (n, l.clone())).collect();
        latency.sort_unstable_by_key(|(n, _)| n.0);
        let mut blocked: Vec<(NodeId, BlockedEntry)> = self
            .blocked
            .iter()
            .map(|(&n, b)| {
                let mut b = b.clone();
                b.at = hour(b.at);
                (n, b)
            })
            .collect();
        blocked.sort_unstable_by_key(|(n, _)| n.0);
        let encode_err = |_| StateError::Encode;
        Ok(Stored {
            format: FORMAT,
            view: postcard::to_allocvec(&self.view).map_err(encode_err)?,
            ledger: postcard::to_allocvec(&self.ledger).map_err(encode_err)?,
            positions: triples(&self.positions),
            fallbacks: self.fallbacks.clone(),
            unaudited,
            audited_at: triples(&self.audited_at),
            reread_at: triples(&self.reread_at),
            crosscheck_at: triples(&self.crosscheck_at),
            down_failed,
            page_bytes,
            info,
            latency,
            blocked,
            defaults: sorted(&self.defaults),
            dismissed_defaults: sorted(&self.dismissed_defaults),
        })
    }

    /// Encoding under format 1 (the new tables dropped), for the migration
    /// tests.
    #[cfg(test)]
    pub(crate) fn encode_format_1(&self) -> Result<Vec<u8>, StateError> {
        let s = self.stored()?;
        let v1 = StoredV1 {
            format: FORMAT_1,
            view: s.view,
            ledger: s.ledger,
            positions: s.positions,
            fallbacks: s.fallbacks,
            unaudited: s.unaudited,
            audited_at: s.audited_at,
            reread_at: s.reread_at,
            crosscheck_at: s.crosscheck_at,
            down_failed: s.down_failed,
            page_bytes: s.page_bytes,
        };
        postcard::to_allocvec(&v1).map_err(|_| StateError::Encode)
    }

    /// Rebuilds a state from `encode` output, under the current policy (see
    /// `View::restore`, `Ledger::restore`). Format 1 is migrated. `None` if
    /// unreadable.
    pub fn decode(bytes: &[u8], now: u64, allow_private: bool) -> Option<NetState> {
        // The format is the first byte: postcard writes a `u8` as is.
        let stored: Stored = match *bytes.first()? {
            FORMAT_1 => postcard::from_bytes::<StoredV1>(bytes).ok()?.into(),
            FORMAT => postcard::from_bytes(bytes).ok()?,
            _ => return None,
        };
        let mut fallbacks = stored.fallbacks;
        fallbacks.prune(now);
        let now_hour = hour(now);
        let blocked: HashMap<NodeId, BlockedEntry> = stored
            .blocked
            .into_iter()
            .map(|(n, mut b)| {
                b.at = hour(b.at).min(now_hour);
                (n, b)
            })
            .collect();
        let mut view = View::restore(&stored.view, allow_private, now).ok()?;
        view.set_blocked(blocked.keys().copied().collect());
        Some(NetState {
            info: stored
                .info
                .into_iter()
                .filter(|(n, _)| view.get(n).is_some())
                .map(|(n, mut c)| {
                    c.fetched_at = hour(c.fetched_at).min(now_hour);
                    (n, c)
                })
                .collect(),
            latency: stored
                .latency
                .into_iter()
                .filter(|(_, l)| !l.is_empty())
                .map(|(n, mut l)| {
                    l.drain(..l.len().saturating_sub(LATENCY_SAMPLES));
                    (n, l)
                })
                .collect(),
            blocked,
            defaults: stored.defaults.into_iter().collect(),
            dismissed_defaults: stored.dismissed_defaults.into_iter().collect(),
            view,
            ledger: Ledger::restore(&stored.ledger, now).ok()?,
            positions: stored
                .positions
                .into_iter()
                .filter(|(_, _, s)| *s > 0)
                .map(|(n, m, s)| ((n, m), s))
                .collect(),
            fallbacks,
            unaudited: stored.unaudited.into_iter().collect(),
            audited_at: dates(stored.audited_at, now),
            reread_at: dates(stored.reread_at, now),
            crosscheck_at: dates(stored.crosscheck_at, now),
            down_failed: stored
                .down_failed
                .into_iter()
                .map(|(n, t)| (n, hour(t).min(hour(now))))
                .filter(|(_, t)| now.saturating_sub(*t) < DOWN_FAILED_SECS)
                .collect(),
            page_bytes: stored
                .page_bytes
                .into_iter()
                .map(|(n, b)| (n, b.clamp(MIN_PAGE_BYTES, FETCH_PAGE_SIZES[0])))
                .collect(),
        })
    }

    /// Records round-trip times to `id`, in whole milliseconds (saturated),
    /// keeping the last `LATENCY_SAMPLES`.
    pub fn note_latency(&mut self, id: NodeId, samples: &[Duration]) {
        if samples.is_empty() {
            return;
        }
        let l = self.latency.entry(id).or_default();
        l.extend(
            samples
                .iter()
                .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
        );
        l.drain(..l.len().saturating_sub(LATENCY_SAMPLES));
    }

    /// Median of the latency samples of `id`, in milliseconds (the mean of
    /// the two middle ones for an even count, rounded down).
    pub fn median_latency(&self, id: &NodeId) -> Option<u32> {
        let mut l = self.latency.get(id)?.clone();
        if l.is_empty() {
            return None;
        }
        l.sort_unstable();
        let mid = l.len() / 2;
        if l.len() % 2 == 1 {
            return Some(l[mid]);
        }
        let mean = (u64::from(l[mid - 1]) + u64::from(l[mid])) / 2;
        Some(mean as u32)
    }

    /// Fetch page size to start from with `node` (see `page_bytes`).
    pub fn page_bytes(&self, node: &NodeId) -> u32 {
        self.page_bytes
            .get(node)
            .copied()
            .unwrap_or(FETCH_PAGE_SIZES[0])
    }

    /// Records the page size the link to `node` reached; forgets those of
    /// nodes no longer in the view.
    pub fn set_page_bytes(&mut self, node: &NodeId, bytes: u32) {
        self.page_bytes.insert(*node, bytes);
        let view = &self.view;
        self.page_bytes.retain(|n, _| view.get(n).is_some());
    }

    /// End of a sync: the page size of each node not in `confirmed` (no page
    /// timeout at a measured low throughput confirmed it in this sync)
    /// doubles, up to the default.
    pub fn recover_page_bytes(&mut self, confirmed: &HashSet<NodeId>) {
        for (node, bytes) in &mut self.page_bytes {
            if !confirmed.contains(node) {
                *bytes = bytes.saturating_mul(2).min(FETCH_PAGE_SIZES[0]);
            }
        }
    }

    /// Fetch positions of `mailboxes` on `node`.
    pub fn resume(&self, node: &NodeId, mailboxes: &[MailboxId]) -> FetchResume {
        let mut r = FetchResume::default();
        for m in mailboxes {
            if let Some(&s) = self.positions.get(&(*node, *m)) {
                r.seen.insert(m.0, s);
            }
        }
        r
    }

    /// Records the positions reached on `node` for `mailboxes`.
    pub fn set_positions(&mut self, node: &NodeId, mailboxes: &[MailboxId], resume: &FetchResume) {
        for m in mailboxes {
            match resume.seen.get(&m.0) {
                Some(&s) if s > 0 => {
                    self.positions.insert((*node, *m), s);
                }
                _ => {
                    self.positions.remove(&(*node, *m));
                }
            }
        }
    }

    /// Forgets the positions, audit and cross-check dates of mailboxes no
    /// longer watched.
    pub fn retain_positions(&mut self, watched: &HashSet<MailboxId>) {
        self.positions.retain(|(_, m), _| watched.contains(m));
        self.audited_at.retain(|(_, m), _| watched.contains(m));
        self.reread_at.retain(|(_, m), _| watched.contains(m));
        self.crosscheck_at.retain(|(_, m), _| watched.contains(m));
    }

    /// True if `mailbox` was not cross-checked on `node` in the last
    /// `every` seconds.
    pub fn crosscheck_due(&self, node: &NodeId, mailbox: &MailboxId, now: u64, every: u64) -> bool {
        self.crosscheck_at
            .get(&(*node, *mailbox))
            .is_none_or(|&t| now.saturating_sub(t) >= every)
    }

    /// `nodes` failed in a sync that ended as network down.
    pub fn note_down_failures(&mut self, nodes: impl IntoIterator<Item = NodeId>, now: u64) {
        for n in nodes {
            self.down_failed.insert(n, hour(now));
        }
    }

    /// Forgets the down failures older than `DOWN_FAILED_SECS`.
    pub fn prune_down_failed(&mut self, now: u64) {
        self.down_failed
            .retain(|_, t| now.saturating_sub(*t) < DOWN_FAILED_SECS);
    }

    /// `ids` (best first) with the nodes that failed in a recent
    /// network-down sync moved to the end, order kept otherwise.
    pub fn order_responsibles(&self, ids: Vec<NodeId>) -> Vec<NodeId> {
        let (mut ok, late): (Vec<NodeId>, Vec<NodeId>) = ids
            .into_iter()
            .partition(|id| !self.down_failed.contains_key(id));
        ok.extend(late);
        ok
    }

    /// A cross-check of `mailbox` on `node` was tried now.
    pub fn note_crosscheck(&mut self, node: &NodeId, mailbox: &MailboxId, now: u64) {
        self.crosscheck_at.insert((*node, *mailbox), hour(now));
    }

    /// True if `mailbox` was neither audited nor re-read on `node` in the
    /// last `every` seconds.
    pub fn audit_due(&self, node: &NodeId, mailbox: &MailboxId, now: u64, every: u64) -> bool {
        let key = (*node, *mailbox);
        [&self.audited_at, &self.reread_at].iter().all(|map| {
            map.get(&key)
                .is_none_or(|&t| now.saturating_sub(t) >= every)
        })
    }

    /// An audit re-read of `mailbox` on `node` was tried now.
    pub fn note_reread(&mut self, node: &NodeId, mailbox: &MailboxId, now: u64) {
        self.reread_at.insert((*node, *mailbox), hour(now));
    }

    /// `mailbox` was just audited on `node`.
    pub fn note_audit(&mut self, node: &NodeId, mailbox: &MailboxId, now: u64) {
        self.audited_at.insert((*node, *mailbox), hour(now));
    }

    /// Takes over the old synchronization's positions and deposit delays,
    /// keyed by node id (the addresses were in the CLI's `nodes.toml`, which
    /// the CLI migrates into the view as nodes added by hand). Saves the
    /// state, then erases the old key by writing an empty state.
    fn migrate_legacy(&mut self, core: &mut Core, now: u64) -> Result<(), StateError> {
        let bytes = match core.transport_state(LEGACY_STATE_KEY)? {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(()),
        };
        let legacy = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|t| toml::from_str::<LegacyState>(t).ok());
        match legacy {
            Some(legacy) => {
                let outbox = core.pending_outbox(now)?;
                self.absorb_legacy(legacy, &outbox, now);
            }
            None => tracing::warn!("unreadable old sync state: dropped"),
        }
        self.save(core)?;
        Ok(core.set_transport_state(LEGACY_STATE_KEY, &[])?)
    }

    fn absorb_legacy(&mut self, legacy: LegacyState, outbox: &[Vec<u8>], now: u64) {
        let by_id: HashMap<[u8; 16], [u8; 32]> = outbox
            .iter()
            .filter_map(|b| Some((Packet::decode(b).ok()?.id.0, content_hash(b))))
            .collect();
        let max_until = now.saturating_add(REDEPOSIT_AFTER_SECS);
        for node in legacy.nodes {
            let Ok(id) = node.id.trim().to_ascii_uppercase().parse::<NodeId>() else {
                continue;
            };
            let seen = to_resume(&node.sessions)
                .seen
                .into_iter()
                .chain(to_resume(&node.intro).seen);
            for (m, s) in seen {
                if s > 0 {
                    self.positions.entry((id, MailboxId(m))).or_insert(s);
                }
            }
            for d in node.deposited {
                let hash = data_encoding::HEXLOWER
                    .decode(d.id.as_bytes())
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                    .and_then(|pid| by_id.get(&pid));
                if let Some(&hash) = hash
                    && d.until > now
                {
                    self.ledger.hold_off(hash, id, d.until.min(max_until));
                }
            }
        }
    }
}

/// Dates rounded to the hour, those from the future brought back to now.
fn dates(v: Vec<(NodeId, MailboxId, u64)>, now: u64) -> HashMap<(NodeId, MailboxId), u64> {
    v.into_iter()
        .map(|(n, m, t)| ((n, m), hour(t).min(hour(now))))
        .collect()
}

/// Position of a mailbox on a node, as the old synchronization stored it
/// (see `FetchResume`): mailbox in lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub mailbox: String,
    pub seq: u64,
}

/// Packet deposited (accepted, refused or deferred) on a node by the old
/// synchronization: no new deposit before `until`. Packet id in lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposited {
    pub id: String,
    #[serde(alias = "at")]
    pub until: u64,
}

/// What the old synchronization kept per node (identifier in base32).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyNode {
    pub id: String,
    #[serde(default)]
    pub sessions: Vec<Seen>,
    #[serde(default)]
    pub intro: Vec<Seen>,
    #[serde(default)]
    pub deposited: Vec<Deposited>,
}

/// The old synchronization's state (TOML).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyState {
    #[serde(default, rename = "node")]
    pub nodes: Vec<LegacyNode>,
}

/// Fetch positions from their stored form; malformed entries are skipped.
pub fn to_resume(seen: &[Seen]) -> FetchResume {
    let mut r = FetchResume::default();
    for s in seen {
        if let Ok(b) = data_encoding::HEXLOWER.decode(s.mailbox.as_bytes())
            && let Ok(k) = <[u8; 16]>::try_from(b.as_slice())
        {
            r.seen.insert(k, s.seq);
        }
    }
    r
}

#[cfg(test)]
mod tests;
