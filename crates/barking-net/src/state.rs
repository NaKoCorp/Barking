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

use barking_core::{Core, CoreError};
use barking_packet::{MailboxId, Packet};
use barking_proto::client::{FETCH_PAGE_SIZES, FetchResume};
use barking_proto::pow::content_hash;
use barking_proto::{MIN_PAGE_BYTES, NodeId};
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
/// Version of the encoding: any other value reads as an unreadable state.
const FORMAT: u8 = 1;

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
    /// largest page every time. Absent: `FETCH_PAGE_SIZES[0]`.
    pub page_bytes: HashMap<NodeId, u32>,
}

/// Failure to read or write the state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("the network state cannot be encoded")]
    Encode,
}

/// Stored form. The view and the ledger are nested encodings so that their
/// own `restore` checks them again on load.
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
        }
    }

    /// Reads the state, migrating the old synchronization's state if there
    /// is one (it is then erased). An unreadable state gives an empty one,
    /// with a warning that carries no data. Only a database error fails:
    /// starting empty would then overwrite a good state.
    pub fn load(core: &mut Core, now: u64, allow_private: bool) -> Result<NetState, StateError> {
        let mut state = match core.transport_state(STATE_KEY)? {
            Some(bytes) => NetState::decode(&bytes, now, allow_private).unwrap_or_else(|| {
                tracing::warn!("unreadable network state: starting from an empty one");
                NetState::new(allow_private)
            }),
            None => NetState::new(allow_private),
        };
        state.migrate_legacy(core, now)?;
        Ok(state)
    }

    /// Writes the state to the core's encrypted database. A state that
    /// cannot be encoded is not written: the stored one stays.
    pub fn save(&self, core: &mut Core) -> Result<(), StateError> {
        Ok(core.set_transport_state(STATE_KEY, &self.encode()?)?)
    }

    /// Postcard encoding of the state.
    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
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
        let encode_err = |_| StateError::Encode;
        let stored = Stored {
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
        };
        postcard::to_allocvec(&stored).map_err(encode_err)
    }

    /// Rebuilds a state from `encode` output, under the current policy (see
    /// `View::restore`, `Ledger::restore`). `None` if unreadable.
    pub fn decode(bytes: &[u8], now: u64, allow_private: bool) -> Option<NetState> {
        let stored: Stored = postcard::from_bytes(bytes).ok()?;
        if stored.format != FORMAT {
            return None;
        }
        let mut fallbacks = stored.fallbacks;
        fallbacks.prune(now);
        Some(NetState {
            view: View::restore(&stored.view, allow_private, now).ok()?,
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
