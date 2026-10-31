//! State of the network client kept between synchronizations (spec §8): the
//! view, the deposit ledger, the fetch positions per node and mailbox, the
//! dates of the fallback lookups and the count of syncs in which a node never
//! let its session fetch complete. Encoded with postcard in the core's
//! encrypted database (`Core::transport_state("net")`), never in the clear.
//!
//! The old synchronization (`barking-cli`, key `"netsync"`) kept positions
//! and deposits per node in TOML; [`NetState::load`] migrates them, then
//! erases that key. Its format lives here ([`LegacyState`]) and the CLI
//! reuses it until it switches to this crate.

use std::collections::{HashMap, HashSet};

use barking_core::{Core, CoreError};
use barking_packet::{MailboxId, Packet};
use barking_proto::NodeId;
use barking_proto::client::FetchResume;
use barking_proto::pow::content_hash;
use serde::{Deserialize, Serialize};

use crate::discover::FallbackLog;
use crate::plan::{Ledger, REDEPOSIT_AFTER_SECS};
use crate::view::View;

/// Key of the state in the core's database.
pub const STATE_KEY: &str = "net";
/// Key of the old synchronization's state, migrated then erased.
pub const LEGACY_STATE_KEY: &str = "netsync";
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
        }
    }

    /// Reads the state, migrating the old synchronization's state if there
    /// is one (it is then erased). An unreadable state gives an empty one,
    /// with a warning that carries no data. Only a database error fails:
    /// starting empty would then overwrite a good state.
    pub fn load(core: &mut Core, now: u64, allow_private: bool) -> Result<NetState, CoreError> {
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

    /// Writes the state to the core's encrypted database.
    pub fn save(&self, core: &mut Core) -> Result<(), CoreError> {
        core.set_transport_state(STATE_KEY, &self.encode())
    }

    /// Postcard encoding of the state.
    pub fn encode(&self) -> Vec<u8> {
        let mut positions: Vec<(NodeId, MailboxId, u64)> = self
            .positions
            .iter()
            .map(|(&(n, m), &s)| (n, m, s))
            .collect();
        positions.sort_unstable_by_key(|(n, m, _)| (n.0, m.0));
        let mut unaudited: Vec<(NodeId, u32)> =
            self.unaudited.iter().map(|(&n, &c)| (n, c)).collect();
        unaudited.sort_unstable_by_key(|(n, _)| n.0);
        let stored = Stored {
            format: FORMAT,
            view: postcard::to_allocvec(&self.view).unwrap_or_default(),
            ledger: postcard::to_allocvec(&self.ledger).unwrap_or_default(),
            positions,
            fallbacks: self.fallbacks.clone(),
            unaudited,
        };
        postcard::to_allocvec(&stored).unwrap_or_default()
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
        })
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

    /// Forgets the positions of mailboxes no longer watched.
    pub fn retain_positions(&mut self, watched: &HashSet<MailboxId>) {
        self.positions.retain(|(_, m), _| watched.contains(m));
    }

    /// Takes over the old synchronization's positions and deposit delays,
    /// keyed by node id (the addresses are in the CLI's node list: those
    /// nodes enter the view when added by hand). Saves the state, then erases
    /// the old key by writing an empty state.
    fn migrate_legacy(&mut self, core: &mut Core, now: u64) -> Result<(), CoreError> {
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
        core.set_transport_state(LEGACY_STATE_KEY, &[])
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

/// Stored form of the positions of the `current` mailboxes only, in a
/// stable order, zero positions omitted.
pub fn from_resume(r: &FetchResume, current: &[MailboxId]) -> Vec<Seen> {
    let mut v: Vec<Seen> = current
        .iter()
        .filter_map(|m| {
            r.seen.get(&m.0).filter(|s| **s > 0).map(|s| Seen {
                mailbox: data_encoding::HEXLOWER.encode(&m.0),
                seq: *s,
            })
        })
        .collect();
    v.sort_by(|a, b| a.mailbox.cmp(&b.mailbox));
    v.dedup();
    v
}

#[cfg(test)]
mod tests;
