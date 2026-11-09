//! Network calls: nodes added by hand, full sync and the extension's quick
//! sync. Each call builds a single-threaded runtime for its own duration, as
//! the CLI does: one thread, a predictable memory use in the extension.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use barking_core::{Core, ReceiveOutcome};
use barking_net::push::PushConfig;
use barking_net::{NetState, QuicDialer, QuickOptions, SyncOptions, SyncReport};
use barking_proto::NodeId;

use crate::delivery::{DeliveryChange, changes_of};
use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// What a sync did, reduced to what the apps show.
#[derive(Debug, uniffi::Record)]
pub struct SyncSummary {
    pub items_received: u32,
    /// Messages deposited for the first time.
    pub sent: u32,
    /// New visible messages, in arrival order.
    pub new_messages: Vec<NewMessage>,
    /// Some node answered.
    pub network_up: bool,
    /// Local error that stopped the sync (logs only).
    pub error: Option<String>,
    /// Sent messages whose delivery changed during the sync (deposit,
    /// receipt, expiry, verdict), each once: the rows to refresh
    /// (`Device::deliveries_of`).
    #[uniffi(default = [])]
    pub delivery_changes: Vec<DeliveryChange>,
    /// Sent messages that became `NotDelivered` during the sync (expired
    /// before any deposit, verdict): the failure notification.
    #[uniffi(default = [])]
    pub failed: Vec<DeliveryChange>,
    /// Contacts a copy of a message I sent from another of my devices
    /// arrived for, each once: their conversations gain a row.
    #[uniffi(default = [])]
    pub synced_contacts: Vec<String>,
    /// Wake subscriptions a node accepted during the sync.
    #[uniffi(default = 0)]
    pub subscribed: u32,
    /// Wake subscriptions cancelled during the sync.
    #[uniffi(default = 0)]
    pub unsubscribed: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct NewMessage {
    /// Fingerprint of the sender.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    pub text: String,
}

/// Where the request to be removed stands (`Device::leave_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LeaveState {
    /// No request queued.
    NotQueued,
    /// Queued, not every copy accepted by a node yet.
    Waiting,
    /// Every copy accepted by a node (or acked): the app may wipe.
    Left,
    /// A copy expired before any node accepted it: call `leave` again.
    Expired,
}

impl From<barking_core::LeaveState> for LeaveState {
    fn from(s: barking_core::LeaveState) -> Self {
        match s {
            barking_core::LeaveState::NotQueued => LeaveState::NotQueued,
            barking_core::LeaveState::Waiting => LeaveState::Waiting,
            barking_core::LeaveState::Left => LeaveState::Left,
            barking_core::LeaveState::Expired => LeaveState::Expired,
        }
    }
}

/// Records in the core the copies of the request to be removed that a node
/// accepted (the deposit ledger), before the ledger forgets them (ack,
/// expiry): an expired copy is then told apart from one that left.
fn note_leave_deposits(core: &mut Core, now: u64, allow_private: bool) -> Result<(), BarkingError> {
    let waiting = core.leave_packets(now)?;
    if waiting.is_empty() {
        return Ok(());
    }
    let (state, _) =
        NetState::load_checked(core, now, allow_private).map_err(BarkingError::storage)?;
    let left: Vec<_> = waiting
        .into_iter()
        .filter(|(_, bytes)| {
            !state
                .ledger
                .holders(&barking_proto::pow::content_hash(bytes))
                .is_empty()
        })
        .map(|(id, _)| id)
        .collect();
    if !left.is_empty() {
        core.mark_leave_left(&left)?;
    }
    Ok(())
}

/// Time a runtime is given to close once the sync has returned.
const SHUTDOWN: Duration = Duration::from_secs(1);

fn block_on<F: Future>(f: F) -> Result<F::Output, BarkingError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(BarkingError::internal)?;
    let out = rt.block_on(f);
    rt.shutdown_timeout(SHUTDOWN);
    Ok(out)
}

/// What the apps show of `report`, with the delivery changes noted by
/// `core` during the sync (the same core: they live in memory only).
fn summary(core: &mut Core, mut report: SyncReport) -> SyncSummary {
    let contacts = core.contacts().unwrap_or_default();
    let received = std::mem::take(&mut report.received);
    let synced_contacts = synced_contacts(&received);
    let new_messages = received
        .into_iter()
        .filter_map(|o| match o {
            ReceiveOutcome::Message {
                from, alias, text, ..
            } => {
                let contact = from.to_string();
                let name = alias
                    .or_else(|| {
                        contacts
                            .iter()
                            .find(|c| c.fingerprint == from)
                            .map(|c| c.display_name.clone())
                    })
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| contact.chars().take(8).collect());
                Some(NewMessage {
                    contact,
                    name,
                    text,
                })
            }
            _ => None,
        })
        .collect();
    SyncSummary {
        items_received: u32::try_from(report.items_received).unwrap_or(u32::MAX),
        sent: u32::try_from(report.first_copies).unwrap_or(u32::MAX),
        new_messages,
        network_up: report.network_up,
        error: report.error,
        delivery_changes: changes_of(core.take_delivery_changes()),
        failed: changes_of(report.failed),
        synced_contacts,
        subscribed: u32::try_from(report.subscribed).unwrap_or(u32::MAX),
        unsubscribed: u32::try_from(report.unsubscribed).unwrap_or(u32::MAX),
    }
}

/// Contacts of the synced sent copies among `received`, in first-seen order.
fn synced_contacts(received: &[ReceiveOutcome]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for o in received {
        if let ReceiveOutcome::Synced {
            contact: Some(c), ..
        } = o
        {
            let c = c.to_string();
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// A node of the local view (the Network screen's relays).
#[derive(Debug, uniffi::Record)]
pub struct NodeInfo {
    pub id: String,
    /// `ip:port`, the hand-entered one first; empty if unknown.
    pub addr: String,
    /// Reliability, 0 to 1.
    pub score: f32,
    /// Added by hand.
    pub manual: bool,
    /// Carried by a contact's card.
    pub from_card: bool,
    /// Unix seconds; 0 if never.
    pub last_seen: u64,
}

#[uniffi::export]
impl Device {
    /// Nodes of the local view, best score first.
    pub fn nodes(&self) -> Result<Vec<NodeInfo>, BarkingError> {
        guard(|| {
            let allow_private = self.allow_private();
            self.with_core(|core| {
                let t = now();
                let (state, _) = NetState::load_checked(core, t, allow_private)
                    .map_err(BarkingError::storage)?;
                let hints = core.contact_node_hints().unwrap_or_default();
                let from_cards = barking_net::card_hint_ids(&state.view, &hints, t);
                let mut out: Vec<NodeInfo> = state
                    .view
                    .entries()
                    .map(|(id, e)| {
                        let addr = e
                            .manual_addr
                            .map(|a| a.to_string())
                            .or_else(|| {
                                e.record.as_ref().and_then(|r| {
                                    r.v4.map(|a| a.to_string()).or(r.v6.map(|a| a.to_string()))
                                })
                            })
                            .unwrap_or_default();
                        NodeInfo {
                            id: id.to_string(),
                            addr,
                            score: e.score.value(),
                            manual: e.manual,
                            from_card: from_cards.contains(id),
                            last_seen: e.last_seen,
                        }
                    })
                    .collect();
                out.sort_by(|a, b| b.score.total_cmp(&a.score));
                Ok(out)
            })
        })
    }

    /// Where the request to be removed (`leave`, `transfer_and_leave`)
    /// stands: the app wipes on `Left` only, and calls `leave` again on
    /// `Expired`.
    pub fn leave_state(&self) -> Result<LeaveState, BarkingError> {
        guard(|| {
            let allow_private = self.allow_private();
            self.with_core(|core| {
                let t = now();
                note_leave_deposits(core, t, allow_private)?;
                Ok(core.leave_state(t)?.into())
            })
        })
    }

    /// Adds a node by hand (base32 identifier, `host:port` address).
    pub fn add_node(&self, id: String, addr: String) -> Result<(), BarkingError> {
        guard(|| {
            let id: NodeId = id.trim().to_ascii_uppercase().parse().map_err(|_| {
                BarkingError::invalid("node identifier: 52-character base32 expected")
            })?;
            if !id.puzzle_ok() {
                return Err(BarkingError::invalid(
                    "node identifier does not solve the identity puzzle",
                ));
            }
            let addr: SocketAddr = addr
                .trim()
                .parse()
                .map_err(|_| BarkingError::invalid("node address: ip:port expected"))?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                let t = now();
                let (mut state, _) = NetState::load_checked(core, t, allow_private)
                    .map_err(BarkingError::storage)?;
                state.view.add_manual(id, addr, t);
                state.save(core).map_err(BarkingError::storage)
            })
        })
    }

    /// Full sync, for at most `deadline_ms`, with the wake-up settings last
    /// given to `set_push`.
    pub fn sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts_private = self.allow_private();
            self.with_core(|core| {
                let opts = SyncOptions {
                    deadline: Duration::from_millis(deadline_ms),
                    allow_private: opts_private,
                    push: PushConfig::load(core)?,
                    ..SyncOptions::default()
                };
                let report = block_on(barking_net::sync(core, &QuicDialer, opts))?;
                note_leave_deposits(core, now(), opts_private)?;
                Ok(summary(core, report))
            })
        })
    }

    /// Quick sync of the notification extension, for at most `deadline_ms`.
    pub fn quick_sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts_private = self.allow_private();
            let opts = QuickOptions {
                deadline: Duration::from_millis(deadline_ms),
                allow_private: self.allow_private(),
                ..QuickOptions::default()
            };
            self.with_core(|core| {
                let report = block_on(barking_net::quick_sync(core, &QuicDialer, opts))?;
                note_leave_deposits(core, now(), opts_private)?;
                Ok(summary(core, report))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use barking_core::SyncKind;
    use barking_core::identity::root::Fingerprint;

    use super::*;

    #[test]
    fn synced_sent_copy_names_its_contact() {
        let bob = Fingerprint([7; 32]);
        let sam = Fingerprint([9; 32]);
        let received = [
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                contact: Some(bob),
            },
            ReceiveOutcome::Synced {
                kind: SyncKind::Contact,
                contact: None,
            },
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                contact: Some(sam),
            },
            ReceiveOutcome::Synced {
                kind: SyncKind::Sent,
                contact: Some(bob),
            },
            ReceiveOutcome::Duplicate,
        ];
        assert_eq!(
            synced_contacts(&received),
            vec![bob.to_string(), sam.to_string()]
        );
    }
}
