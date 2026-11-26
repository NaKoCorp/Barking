//! Network calls: nodes added by hand, full sync and the extension's quick
//! sync. Each call builds a single-threaded runtime for its own duration, as
//! the CLI does: one thread, a predictable memory use in the extension.

use std::future::Future;
use std::sync::PoisonError;
use std::time::Duration;

use barking_core::identity::root::Fingerprint;
use barking_core::{Core, ReceiveOutcome, SyncKind};
use barking_net::push::{PushConfig, PushPrefs};
use barking_net::{NetState, QuicDialer, QuickOptions, SyncOptions, SyncReport};

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
    /// Ephemeral messages the sync erased, as it started (they were due):
    /// the rows to drop (`Message::id`).
    #[uniffi(default = [])]
    pub expired: Vec<i64>,
    /// Contact requests to notify, in arrival order: the core allows one
    /// per requester per 24 hours, and none when the user turned
    /// invitation notifications off (`NotificationPrefs::invites`).
    #[uniffi(default = [])]
    pub new_requests: Vec<NewRequest>,
    /// Requesters whose request moved during the sync (notified or not),
    /// each once, in arrival order: the requests list reloads.
    #[uniffi(default = [])]
    pub request_contacts: Vec<String>,
}

/// A contact request to notify.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NewRequest {
    /// Fingerprint of the requester.
    pub contact: String,
    /// Its declared display name, otherwise the start of the fingerprint.
    pub name: String,
    /// The request already existed (a new invite from the same person).
    pub resent: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct NewMessage {
    /// Fingerprint of the sender.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    /// Empty for a message this version cannot read (`needs_update`), and
    /// for an ephemeral one (`ephemeral`).
    pub text: String,
    /// Content of a kind this version does not know, shown as a line that
    /// asks for a newer version of the app.
    #[uniffi(default = false)]
    pub needs_update: bool,
    /// An ephemeral message: its notification never carries the text,
    /// whatever the preview setting.
    #[uniffi(default = false)]
    pub ephemeral: bool,
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

pub(crate) fn block_on<F: Future>(f: F) -> Result<F::Output, BarkingError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(BarkingError::internal)?;
    let out = rt.block_on(f);
    rt.shutdown_timeout(SHUTDOWN);
    Ok(out)
}

/// What the apps show of `report`, with the delivery changes noted by
/// `core` during the sync (the same core: they live in memory only) and the
/// rows the sync's expiry erased first (`expired`).
fn summary(core: &mut Core, mut report: SyncReport, expired: Vec<i64>) -> SyncSummary {
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
    let request_contacts = request_contacts(&received);
    // An unreadable preference reads as the default (on), as `load` does.
    let notify_invites = PushPrefs::load(core).map_or(true, |p| p.invites);
    let requests = core.requests().unwrap_or_default();
    let mut new_messages = Vec::new();
    let mut new_reactions = Vec::new();
    let mut new_requests = Vec::new();
    let mut repeats = 0usize;
    for outcome in received {
        match outcome {
            // The text of an ephemeral never leaves for a notification.
            ReceiveOutcome::Message {
                from,
                alias,
                text,
                ephemeral,
                ..
            } => new_messages.push(NewMessage {
                contact: from.to_string(),
                name: name_of(&from, alias),
                text: if ephemeral { String::new() } else { text },
                needs_update: false,
                ephemeral,
            }),
            // A placeholder row in the conversation: a line that asks for
            // a newer version, with no text.
            ReceiveOutcome::NeedsUpdate { from, alias } => new_messages.push(NewMessage {
                contact: from.to_string(),
                name: name_of(&from, alias),
                text: String::new(),
                needs_update: true,
                ephemeral: false,
            }),
            // Only what a contact adds is worth a notification; a removal
            // or a superseded set just reloads the conversation.
            ReceiveOutcome::Reaction {
                from,
                alias,
                target,
                added,
            } if !added.is_empty() => {
                let target = core.message_in(&from, target, now()).ok().flatten();
                // An ephemeral target gives no excerpt: its text never
                // leaves for a notification.
                let on_ephemeral = target.as_ref().is_some_and(|r| r.ttl_secs.is_some());
                let excerpt = target
                    .filter(|_| !on_ephemeral)
                    .map(|row| excerpt(&row.body, NOTIFICATION_CHARS));
                new_reactions.push(NewReaction {
                    contact: from.to_string(),
                    name: name_of(&from, alias),
                    emojis: added,
                    excerpt,
                    on_ephemeral,
                });
            }
            // A message already in its conversation, received again: no
            // new row, but the push may have come for it.
            ReceiveOutcome::DuplicateMessage => repeats += 1,
            // The core notifies a requester at most once per 24 hours; the
            // user may turn these notifications off.
            ReceiveOutcome::ContactRequest {
                contact,
                resent,
                notify,
            } if notify && notify_invites => new_requests.push(NewRequest {
                contact: contact.to_string(),
                name: requests
                    .iter()
                    .find(|r| r.fingerprint == contact)
                    .map(|r| r.display_name.clone())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| contact.to_string().chars().take(8).collect()),
                resent,
            }),
            // `Partial` lands here too and counts as nothing to show only
            // because the packet's last fragment is a deposit of its own,
            // which sends its own push: that wake-up shows the message.
            _ => {}
        }
    }
    let nothing_to_show = nothing_to_show(
        &report,
        new_messages.len(),
        new_reactions.len(),
        new_requests.len(),
        repeats,
    );
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
        expired,
        new_requests,
        request_contacts,
    }
}

/// The wake-up that came for `report` has nothing to show: the sync read
/// every mailbox it meant to (`fetched_all`: so no message was cut off by a
/// deadline), brought items, and none of them is a visible message, a
/// reaction or a contact request to notify (a request not notified counts
/// as nothing), or a repeat of a message still shown (`repeats`,
/// `ReceiveOutcome::DuplicateMessage`: an earlier sync or another node may
/// have taken the message this push came for).
fn nothing_to_show(
    report: &SyncReport,
    new_messages: usize,
    new_reactions: usize,
    new_requests: usize,
    repeats: usize,
) -> bool {
    report.error.is_none()
        && report.network_up
        && report.fetched_all
        && report.items_received > 0
        && new_messages == 0
        && new_reactions == 0
        && new_requests == 0
        && repeats == 0
}

/// Requesters of the contact requests among `received`, notified or not,
/// in first-seen order.
fn request_contacts(received: &[ReceiveOutcome]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for o in received {
        if let ReceiveOutcome::ContactRequest { contact, .. } = o {
            let c = contact.to_string();
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// What the list and the page of a request show of it: a change in any of
/// these, or the request gone, reloads them. `hidden` and `unseen` change
/// by the user's own hand here, which reloads already.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestStamp {
    fp: Fingerprint,
    display_name: String,
    last_seen: u64,
    invite_count: u32,
    pending_messages: u32,
}

/// The stamps of `core`'s requests; nil when they cannot be read (no
/// report then: a reload too few, never a sync failed for it).
fn request_stamps(core: &Core) -> Option<Vec<RequestStamp>> {
    let list = core.requests().ok()?;
    Some(
        list.into_iter()
            .map(|r| RequestStamp {
                fp: r.fingerprint,
                display_name: r.display_name,
                last_seen: r.last_seen,
                invite_count: r.invite_count,
                pending_messages: r.pending_messages,
            })
            .collect(),
    )
}

/// Requesters whose request is new, changed or gone from `before` to
/// `after`: those of `after` in its order, then those gone.
fn moved_requests(before: &[RequestStamp], after: &[RequestStamp]) -> Vec<String> {
    let changed = after.iter().filter(|a| !before.contains(a)).map(|a| a.fp);
    let gone = before
        .iter()
        .filter(|b| !after.iter().any(|a| a.fp == b.fp))
        .map(|b| b.fp);
    changed.chain(gone).map(|fp| fp.to_string()).collect()
}

/// Adds `moved` to `s.request_contacts`, after the requesters already
/// there, each once.
fn add_moved(s: &mut SyncSummary, moved: Vec<String>) {
    for fp in moved {
        if !s.request_contacts.contains(&fp) {
            s.request_contacts.push(fp);
        }
    }
}

impl Device {
    /// Runs `sync` on `core`, then adds to its `request_contacts` the
    /// requests that moved since this device's previous sync ended (since
    /// `sync` began, on the first): a message held for a request, a
    /// decision synced from another of my devices, a request expired
    /// (purged as the core opens, before `sync` begins). None of these is a
    /// `ReceiveOutcome::ContactRequest`. Changes made here between two
    /// syncs are reported too: one reload more.
    fn tracking_requests(
        &self,
        core: &mut Core,
        sync: impl FnOnce(&mut Core) -> Result<SyncSummary, BarkingError>,
    ) -> Result<SyncSummary, BarkingError> {
        let remembered = self
            .requests_seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let before = remembered.or_else(|| request_stamps(core));
        let mut s = sync(core)?;
        let after = request_stamps(core);
        if let (Some(before), Some(after)) = (&before, &after) {
            add_moved(&mut s, moved_requests(before, after));
        }
        *self
            .requests_seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = after;
        Ok(s)
    }
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

#[uniffi::export]
impl Device {
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

    /// Full sync, for at most `deadline_ms`, with the wake-up settings last
    /// given to `set_push`. It also follows the stored notification
    /// preferences: with instant notifications off, it holds no subscriptions.
    /// It first erases the ephemeral messages due (`SyncSummary::expired`).
    pub fn sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts_private = self.allow_private();
            self.with_core_sync(|core| {
                self.tracking_requests(core, |core| {
                    let expired = core.expire_ephemeral(now())?;
                    let opts = SyncOptions {
                        deadline: Duration::from_millis(deadline_ms),
                        allow_private: opts_private,
                        push: PushConfig::effective(core)?,
                        ..SyncOptions::default()
                    };
                    let report = block_on(barking_net::sync(core, &QuicDialer, opts))?;
                    note_leave_deposits(core, now(), opts_private)?;
                    Ok(summary(core, report, expired))
                })
            })
        })
    }

    /// Quick sync of the notification extension, for at most `deadline_ms`.
    /// It first erases the ephemeral messages due (`SyncSummary::expired`):
    /// a sweep that reads ids only, never a text, within the extension's
    /// memory budget.
    pub fn quick_sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts_private = self.allow_private();
            let opts = QuickOptions {
                deadline: Duration::from_millis(deadline_ms),
                allow_private: self.allow_private(),
                ..QuickOptions::default()
            };
            self.with_core_sync(|core| {
                self.tracking_requests(core, |core| {
                    let expired = core.expire_ephemeral(now())?;
                    let report = block_on(barking_net::quick_sync(core, &QuicDialer, opts))?;
                    note_leave_deposits(core, now(), opts_private)?;
                    Ok(summary(core, report, expired))
                })
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
                ttl_secs: None,
                seen_at: None,
                expire_at: None,
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
        let s = summary(&mut core, report, Vec::new());
        assert_eq!(
            s.new_reactions,
            vec![NewReaction {
                contact: bob.to_string(),
                name: "bob".into(),
                emojis: vec!["👍".into(), "❤️".into()],
                // The message reacted to, cut at 40 characters: this one fits.
                excerpt: Some("good morning, how are you today?".into()),
                on_ephemeral: false,
            }]
        );
        assert_eq!(s.reaction_contacts, vec![bob.to_string()]);
        assert!(s.new_messages.is_empty());
        // A notification to show.
        assert!(!s.nothing_to_show);
    }

    /// A reaction to a live ephemeral says so, without a word of it.
    #[test]
    fn reaction_on_ephemeral_has_no_excerpt() {
        let (dir, mut core, bob) = core_with_bob_message();
        drop(core);
        let path = dir.path().join("a.db");
        Store::open(&path, &[1u8; 32])
            .unwrap()
            .insert_message_row(&MessageInsert {
                contact_fp: bob,
                direction: Direction::In,
                body: "burn after reading".into(),
                status: MessageStatus::Received,
                at: 1_600,
                message_id: MessageId([6; 16]),
                wire_id: Some([6; 16]),
                reply_to: None,
                reply_ref: None,
                placeholder: false,
                ttl_secs: Some(300),
                seen_at: None,
                expire_at: Some(u64::from(u32::MAX) * 2),
            })
            .unwrap();
        core = Core::open(&path, &[1u8; 32], 2_000).unwrap();
        let on = |target: u8| ReceiveOutcome::Reaction {
            from: bob,
            alias: Some("bob".into()),
            target: MessageId([target; 16]),
            added: vec!["👍".into()],
        };
        let report = SyncReport {
            received: vec![on(6), on(5)],
            ..SyncReport::default()
        };
        let s = summary(&mut core, report, Vec::new());
        assert_eq!(s.new_reactions.len(), 2);
        let (eph, plain) = (&s.new_reactions[0], &s.new_reactions[1]);
        assert_eq!((eph.excerpt.as_deref(), eph.on_ephemeral), (None, true));
        assert_eq!(
            (plain.excerpt.as_deref(), plain.on_ephemeral),
            (Some("good morning, how are you today?"), false)
        );
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
        let s = summary(&mut core, report, Vec::new());
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
        let s = summary(&mut core, report, Vec::new());
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
        let s = summary(&mut core, report, Vec::new());
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
        let s = summary(&mut core, ignored, Vec::new());
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
            Vec::new(),
        );
        assert!(s.new_messages.is_empty() && s.new_reactions.is_empty());
        assert!(!s.nothing_to_show);
        let s = summary(
            &mut core,
            report(vec![ReceiveOutcome::Duplicate, reaction(bob, &[])]),
            Vec::new(),
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
        assert!(nothing_to_show(&clean, 0, 0, 0, 0));
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
            assert!(
                !nothing_to_show(&report, messages, reactions, 0, 0),
                "{what}"
            );
        }
        assert!(!nothing_to_show(&clean, 0, 0, 0, 1), "a visible repeat");
        assert!(!nothing_to_show(&clean, 0, 0, 1, 0), "a new request");
    }

    /// Clock of the invitation tests.
    const T: u64 = 1_800_000_000;

    /// Alice ("Alice") knows Bob and invites him at `at`. Returns Alice's
    /// core, Bob's, Alice's fingerprint and the invite.
    fn alice_invites_bob(
        dir: &tempfile::TempDir,
        at: u64,
    ) -> (Core, Core, Fingerprint, barking_core::packet::Packet) {
        let mut rng = rand::rng();
        let (pa, pb) = (dir.path().join("a.db"), dir.path().join("b.db"));
        let (mut a, _) = Core::create(&pa, &[1; 32], "a-phone", at, &mut rng).unwrap();
        let (b, _) = Core::create(&pb, &[2; 32], "b-phone", at, &mut rng).unwrap();
        a.contact_card("Alice").unwrap();
        a.add_contact(&b.contact_card("Bob").unwrap(), None, at, &mut rng)
            .unwrap();
        let mut out = a.invite(&b.fingerprint(), at, &mut rng).unwrap();
        assert_eq!(out.len(), 1);
        let fa = a.fingerprint();
        (a, b, fa, out.remove(0))
    }

    /// A clean, complete sync that brought `received`.
    fn clean_report(received: Vec<ReceiveOutcome>) -> SyncReport {
        SyncReport {
            items_received: received.len(),
            network_up: true,
            fetched_all: true,
            received,
            ..SyncReport::default()
        }
    }

    /// Bob receives Alice's invite at `T`: the outcome and Bob's core.
    fn bob_receives_invite(dir: &tempfile::TempDir) -> (Core, Fingerprint, ReceiveOutcome) {
        let (_a, mut b, fa, p) = alice_invites_bob(dir, T);
        let got = b.receive(&p.encode(), "t", T, &mut rand::rng()).unwrap();
        (b, fa, got)
    }

    #[test]
    fn sync_summary_lists_new_request() {
        let dir = tempfile::tempdir().unwrap();
        let (mut b, fa, got) = bob_receives_invite(&dir);
        let s = summary(&mut b, clean_report(vec![got]), Vec::new());
        assert_eq!(
            s.new_requests,
            vec![NewRequest {
                contact: fa.to_string(),
                name: "Alice".into(),
                resent: false,
            }]
        );
        assert_eq!(s.request_contacts, vec![fa.to_string()]);
        assert!(!s.nothing_to_show);
    }

    #[test]
    fn request_only_wake_without_notify_is_nothing_to_show() {
        let dir = tempfile::tempdir().unwrap();
        let (mut b, fa, got) = bob_receives_invite(&dir);
        PushPrefs {
            invites: false,
            ..PushPrefs::default()
        }
        .store(&mut b)
        .unwrap();
        let s = summary(&mut b, clean_report(vec![got]), Vec::new());
        assert!(s.new_requests.is_empty());
        assert_eq!(s.request_contacts, vec![fa.to_string()]);
        assert!(s.nothing_to_show);
    }

    /// A second invite less than 24 hours after the first was received
    /// (the first arrived late): listed for reload, not notified.
    #[test]
    fn resend_within_day_not_notified() {
        let dir = tempfile::tempdir().unwrap();
        let (mut a, mut b, fa, first) = alice_invites_bob(&dir, T);
        let mut rng = rand::rng();
        let got = b
            .receive(&first.encode(), "t", T + 86_000, &mut rng)
            .unwrap();
        let s = summary(&mut b, clean_report(vec![got]), Vec::new());
        assert_eq!(s.new_requests.len(), 1);
        let again = T + 86_401;
        let second = a.invite(&b.fingerprint(), again, &mut rng).unwrap();
        let got = b
            .receive(&second[0].encode(), "t", again + 99, &mut rng)
            .unwrap();
        assert!(matches!(
            got,
            ReceiveOutcome::ContactRequest {
                resent: true,
                notify: false,
                ..
            }
        ));
        let s = summary(&mut b, clean_report(vec![got]), Vec::new());
        assert!(s.new_requests.is_empty());
        assert_eq!(s.request_contacts, vec![fa.to_string()]);
        assert!(s.nothing_to_show);
    }

    /// Several outcomes for one requester: listed once, in arrival order;
    /// no declared name: the start of the fingerprint.
    #[test]
    fn request_contacts_once_in_arrival_order() {
        let (_dir, mut core, _bob) = core_with_bob_message();
        let (x, y) = (Fingerprint([3; 32]), Fingerprint([4; 32]));
        let req = |contact, notify| ReceiveOutcome::ContactRequest {
            contact,
            resent: false,
            notify,
        };
        let s = summary(
            &mut core,
            clean_report(vec![req(y, true), req(x, false), req(y, false)]),
            Vec::new(),
        );
        assert_eq!(s.request_contacts, vec![y.to_string(), x.to_string()]);
        assert_eq!(
            s.new_requests,
            vec![NewRequest {
                contact: y.to_string(),
                name: y.to_string().chars().take(8).collect(),
                resent: false,
            }]
        );
    }

    fn stamp(b: u8, last_seen: u64, pending_messages: u32) -> RequestStamp {
        RequestStamp {
            fp: Fingerprint([b; 32]),
            display_name: "x".into(),
            last_seen,
            invite_count: 1,
            pending_messages,
        }
    }

    /// New, changed, then gone (an expiry, a decision from another
    /// device); an unchanged request is not reported; nor twice a requester
    /// the outcomes already named.
    #[test]
    fn moved_requests_new_changed_then_gone() {
        let before = [stamp(1, 10, 0), stamp(2, 10, 0), stamp(3, 10, 0)];
        let after = [stamp(4, 30, 0), stamp(2, 20, 1), stamp(3, 10, 0)];
        let moved = moved_requests(&before, &after);
        let fp = |b: u8| Fingerprint([b; 32]).to_string();
        assert_eq!(moved, vec![fp(4), fp(2), fp(1)]);
        let (_dir, mut core, _bob) = core_with_bob_message();
        let mut s = summary(&mut core, clean_report(Vec::new()), Vec::new());
        s.request_contacts = vec![fp(2)];
        add_moved(&mut s, moved);
        assert_eq!(s.request_contacts, vec![fp(2), fp(4), fp(1)]);
        assert!(moved_requests(&after, &after).is_empty());
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
