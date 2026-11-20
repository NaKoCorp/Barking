//! Network calls: nodes added by hand, full sync and the extension's quick
//! sync. Each call builds a single-threaded runtime for its own duration, as
//! the CLI does: one thread, a predictable memory use in the extension.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use barking_core::identity::root::Fingerprint;
use barking_core::{Core, ReceiveOutcome, SyncKind};
use barking_net::push::PushConfig;
use barking_net::{NetState, QuicDialer, QuickOptions, SyncOptions, SyncReport};
use barking_proto::NodeId;

use crate::delivery::{DeliveryChange, changes_of};
use crate::device::{Device, now};
use crate::reactions::{NOTIFICATION_CHARS, NewReaction, excerpt};
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
    /// Reactions a contact added (never a removal), in arrival order: the
    /// notification.
    #[uniffi(default = [])]
    pub new_reactions: Vec<NewReaction>,
    /// Contacts whose conversation changed by a reaction (a contact's, or
    /// one of mine from another device, a removal included), each once:
    /// their open conversation reloads.
    #[uniffi(default = [])]
    pub reaction_contacts: Vec<String>,
    /// The sync read everything it meant to, brought something, and nothing
    /// of it shows (a removed reaction, content set aside): the wake-up that
    /// came for it has nothing to say (`nothing_to_show`).
    #[uniffi(default = false)]
    pub nothing_to_show: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct NewMessage {
    /// Fingerprint of the sender.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    /// Empty for a message this version cannot read (`needs_update`).
    pub text: String,
    /// Content of a kind this version does not know, shown as a line that
    /// asks for a newer version of the app.
    #[uniffi(default = false)]
    pub needs_update: bool,
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
    let reaction_contacts = reaction_contacts(&received);
    let name_of = |from: &Fingerprint, alias: Option<String>| -> String {
        alias
            .or_else(|| {
                contacts
                    .iter()
                    .find(|c| &c.fingerprint == from)
                    .map(|c| c.display_name.clone())
            })
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| from.to_string().chars().take(8).collect())
    };
    let mut new_messages = Vec::new();
    let mut new_reactions = Vec::new();
    let mut repeats = 0usize;
    for outcome in received {
        match outcome {
            ReceiveOutcome::Message {
                from, alias, text, ..
            } => new_messages.push(NewMessage {
                contact: from.to_string(),
                name: name_of(&from, alias),
                text,
                needs_update: false,
            }),
            // A placeholder row in the conversation: a line that asks for
            // a newer version, with no text.
            ReceiveOutcome::NeedsUpdate { from, alias } => new_messages.push(NewMessage {
                contact: from.to_string(),
                name: name_of(&from, alias),
                text: String::new(),
                needs_update: true,
            }),
            // Only what a contact adds is worth a notification; a removal
            // or a superseded set just reloads the conversation.
            ReceiveOutcome::Reaction {
                from,
                alias,
                target,
                added,
            } if !added.is_empty() => {
                let excerpt = core
                    .message_in(&from, target)
                    .ok()
                    .flatten()
                    .map(|row| excerpt(&row.body, NOTIFICATION_CHARS));
                new_reactions.push(NewReaction {
                    contact: from.to_string(),
                    name: name_of(&from, alias),
                    emojis: added,
                    excerpt,
                });
            }
            // A message already in its conversation, received again: no
            // new row, but the push may have come for it.
            ReceiveOutcome::DuplicateMessage => repeats += 1,
            // `Partial` lands here too and counts as nothing to show only
            // because the packet's last fragment is a deposit of its own,
            // which sends its own push: that wake-up shows the message.
            _ => {}
        }
    }
    let nothing_to_show =
        nothing_to_show(&report, new_messages.len(), new_reactions.len(), repeats);
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
        new_reactions,
        reaction_contacts,
        nothing_to_show,
    }
}

/// The wake-up that came for `report` has nothing to show: the sync read
/// every mailbox it meant to (`fetched_all`: so no message was cut off by a
/// deadline), brought items, and none of them is a visible message, a
/// reaction to notify, or a repeat of a message still shown (`repeats`,
/// `ReceiveOutcome::DuplicateMessage`: an earlier sync or another node may
/// have taken the message this push came for).
fn nothing_to_show(
    report: &SyncReport,
    new_messages: usize,
    new_reactions: usize,
    repeats: usize,
) -> bool {
    report.error.is_none()
        && report.network_up
        && report.fetched_all
        && report.items_received > 0
        && new_messages == 0
        && new_reactions == 0
        && repeats == 0
}

/// Contacts whose conversation a reaction changed (a contact's own, or a
/// copy of mine from another device), in first-seen order.
fn reaction_contacts(received: &[ReceiveOutcome]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for o in received {
        let from = match o {
            ReceiveOutcome::Reaction { from, .. } => from,
            ReceiveOutcome::Synced {
                kind: SyncKind::Reaction,
                contact: Some(c),
            } => c,
            _ => continue,
        };
        let c = from.to_string();
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
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
    /// given to `set_push`. It also follows the stored notification
    /// preferences: with instant notifications off, it holds no subscriptions.
    pub fn sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts_private = self.allow_private();
            self.with_core_sync(|core| {
                let opts = SyncOptions {
                    deadline: Duration::from_millis(deadline_ms),
                    allow_private: opts_private,
                    push: PushConfig::effective(core)?,
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
            self.with_core_sync(|core| {
                let report = block_on(barking_net::quick_sync(core, &QuicDialer, opts))?;
                note_leave_deposits(core, now(), opts_private)?;
                Ok(summary(core, report))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use barking_core::store::{Direction, MessageId, MessageInsert, MessageStatus, Queries, Store};

    use super::*;

    /// A core that knows Bob (alias "bob") and holds a message of his, "good
    /// morning, how are you today?", under `MessageId([5; 16])`.
    fn core_with_bob_message() -> (tempfile::TempDir, Core, Fingerprint) {
        let dir = tempfile::tempdir().unwrap();
        let (pa, pb) = (dir.path().join("a.db"), dir.path().join("b.db"));
        let key = [1u8; 32];
        let (bob, _) = Core::create(&pb, &key, "bob-phone", 1_000, &mut rand::rng()).unwrap();
        let card = bob.contact_card("Bob").unwrap();
        let from = bob.fingerprint();
        let (mut core, _) = Core::create(&pa, &key, "a-phone", 1_000, &mut rand::rng()).unwrap();
        core.add_contact(&card, Some("bob"), 1_000, &mut rand::rng())
            .unwrap();
        drop(core);
        Store::open(&pa, &key)
            .unwrap()
            .insert_message_row(&MessageInsert {
                contact_fp: from,
                direction: Direction::In,
                body: "good morning, how are you today?".into(),
                status: MessageStatus::Received,
                at: 1_500,
                message_id: MessageId([5; 16]),
                wire_id: Some([5; 16]),
                reply_to: None,
                reply_ref: None,
                placeholder: false,
            })
            .unwrap();
        let core = Core::open(&pa, &key, 2_000).unwrap();
        (dir, core, from)
    }

    fn reaction(from: Fingerprint, added: &[&str]) -> ReceiveOutcome {
        ReceiveOutcome::Reaction {
            from,
            alias: Some("bob".into()),
            target: MessageId([5; 16]),
            added: added.iter().map(|e| (*e).to_owned()).collect(),
        }
    }

    #[test]
    fn reaction_outcome_becomes_new_reaction() {
        let (_dir, mut core, bob) = core_with_bob_message();
        let report = SyncReport {
            items_received: 2,
            network_up: true,
            fetched_all: true,
            received: vec![reaction(bob, &["👍", "❤️"])],
            ..SyncReport::default()
        };
        let s = summary(&mut core, report);
        assert_eq!(
            s.new_reactions,
            vec![NewReaction {
                contact: bob.to_string(),
                name: "bob".into(),
                emojis: vec!["👍".into(), "❤️".into()],
                // The message reacted to, cut at 40 characters: this one fits.
                excerpt: Some("good morning, how are you today?".into()),
            }]
        );
        assert_eq!(s.reaction_contacts, vec![bob.to_string()]);
        assert!(s.new_messages.is_empty());
        // A notification to show.
        assert!(!s.nothing_to_show);
    }

    #[test]
    fn long_target_is_cut_for_the_notification() {
        let (_dir, mut core, bob) = core_with_bob_message();
        // A target that is gone has no excerpt.
        let gone = ReceiveOutcome::Reaction {
            from: bob,
            alias: None,
            target: MessageId([6; 16]),
            added: vec!["👍".into()],
        };
        let report = SyncReport {
            received: vec![gone],
            ..SyncReport::default()
        };
        let s = summary(&mut core, report);
        assert_eq!(s.new_reactions.len(), 1);
        assert_eq!(s.new_reactions[0].excerpt, None);
        // No alias: the contact's display name (set by its card).
        assert_eq!(s.new_reactions[0].name, "Bob");
    }

    #[test]
    fn removal_only_reloads() {
        let (_dir, mut core, bob) = core_with_bob_message();
        let sam = Fingerprint([9; 32]);
        let report = SyncReport {
            items_received: 3,
            network_up: true,
            fetched_all: true,
            received: vec![
                reaction(bob, &[]),
                // My other device's reaction, and Bob's again: each contact once.
                ReceiveOutcome::Synced {
                    kind: SyncKind::Reaction,
                    contact: Some(sam),
                },
                reaction(bob, &[]),
                ReceiveOutcome::Synced {
                    kind: SyncKind::Reaction,
                    contact: None,
                },
            ],
            ..SyncReport::default()
        };
        let s = summary(&mut core, report);
        assert!(s.new_reactions.is_empty());
        assert_eq!(s.reaction_contacts, vec![bob.to_string(), sam.to_string()]);
        // Items came, nothing shows: the wake-up has nothing to say.
        assert!(s.nothing_to_show);
    }

    #[test]
    fn unknown_content_that_asks_for_an_update_is_a_line() {
        let (_dir, mut core, bob) = core_with_bob_message();
        let report = SyncReport {
            items_received: 1,
            network_up: true,
            fetched_all: true,
            received: vec![ReceiveOutcome::NeedsUpdate {
                from: bob,
                alias: Some("bob".into()),
            }],
            ..SyncReport::default()
        };
        let s = summary(&mut core, report);
        assert_eq!(s.new_messages.len(), 1);
        let m = &s.new_messages[0];
        assert_eq!((m.text.as_str(), m.needs_update), ("", true));
        assert_eq!(
            (m.contact.as_str(), m.name.as_str()),
            (&*bob.to_string(), "bob")
        );
        assert!(!s.nothing_to_show);
        // Ignored content shows nothing at all.
        let ignored = SyncReport {
            items_received: 1,
            network_up: true,
            fetched_all: true,
            received: vec![ReceiveOutcome::Ignored],
            ..SyncReport::default()
        };
        let s = summary(&mut core, ignored);
        assert!(s.new_messages.is_empty() && s.nothing_to_show);
    }

    /// A message already stored (an earlier sync, another node serving it
    /// again) beside a removed reaction: the push may be for that message,
    /// so it is kept; other repeats (a reaction, an ack) still leave
    /// nothing to show.
    #[test]
    fn visible_duplicate_keeps_the_wake_up() {
        let (_dir, mut core, bob) = core_with_bob_message();
        let report = |received| SyncReport {
            items_received: 2,
            network_up: true,
            fetched_all: true,
            received,
            ..SyncReport::default()
        };
        let s = summary(
            &mut core,
            report(vec![ReceiveOutcome::DuplicateMessage, reaction(bob, &[])]),
        );
        assert!(s.new_messages.is_empty() && s.new_reactions.is_empty());
        assert!(!s.nothing_to_show);
        let s = summary(
            &mut core,
            report(vec![ReceiveOutcome::Duplicate, reaction(bob, &[])]),
        );
        assert!(s.nothing_to_show);
    }

    /// The wake-up is dropped only after a clean, complete sync that brought
    /// something and showed nothing (Review Focus 1): any doubt keeps it.
    #[test]
    fn nothing_to_show_needs_a_clean_sync() {
        let clean = SyncReport {
            items_received: 1,
            network_up: true,
            fetched_all: true,
            ..SyncReport::default()
        };
        assert!(nothing_to_show(&clean, 0, 0, 0));
        let cases = [
            (
                "error",
                SyncReport {
                    error: Some("x".into()),
                    ..clean_copy(&clean)
                },
                0,
                0,
            ),
            (
                "network down",
                SyncReport {
                    network_up: false,
                    ..clean_copy(&clean)
                },
                0,
                0,
            ),
            (
                "no item",
                SyncReport {
                    items_received: 0,
                    ..clean_copy(&clean)
                },
                0,
                0,
            ),
            // One ack opened, then the deadline cut the fetch: a message may
            // have been left behind.
            (
                "cut by the deadline",
                SyncReport {
                    fetched_all: false,
                    ..clean_copy(&clean)
                },
                0,
                0,
            ),
            ("new message", clean_copy(&clean), 1, 0),
            ("new reaction", clean_copy(&clean), 0, 1),
        ];
        for (what, report, messages, reactions) in cases {
            assert!(!nothing_to_show(&report, messages, reactions, 0), "{what}");
        }
        assert!(!nothing_to_show(&clean, 0, 0, 1), "a visible repeat");
    }

    fn clean_copy(r: &SyncReport) -> SyncReport {
        SyncReport {
            items_received: r.items_received,
            network_up: r.network_up,
            fetched_all: r.fetched_all,
            ..SyncReport::default()
        }
    }

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
