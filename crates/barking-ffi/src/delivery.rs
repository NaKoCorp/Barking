//! Delivery of sent messages (spec Lot M §5.10): states with their times,
//! the message sheet, the "Sent" groups, deletion, retry and the pending
//! packets. Each read expires the due packets first (`Core::expire_due`),
//! so a message that expired while the app slept never shows `Pending`.
//!
//! The core is reopened on every call: the changes it notes
//! (`take_delivery_changes`, `take_failed_notices`) only live inside one
//! call. The syncs return them in `SyncSummary`, a deletion in
//! `DeleteOutcome::changes`; for a retry the app reloads what it shows.

use barking_core::core::ContactSummary;
use barking_core::identity::root::Fingerprint;
use barking_core::store::{self, DeliverySummary, MessageStatus};
use barking_core::{Core, CoreError};

use crate::device::{Device, now};
use crate::identity::to_hex;
use crate::{BarkingError, guard};

/// State of a sent message, or of one of its deliveries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryState {
    /// Queued here: no node accepted it yet.
    Pending,
    /// A node accepted it; no receipt yet.
    OnNetwork,
    /// A receipt is verified.
    Received,
    /// Expired before any deposit, or deposited then lost (verdict).
    NotDelivered,
}

/// Delivery summary of a sent message (its deliveries to the contact's
/// devices). Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Delivery {
    pub state: DeliveryState,
    pub sealed_at: u64,
    pub deposited_at: Option<u64>,
    pub received_at: Option<u64>,
    /// Set for every `NotDelivered` message: the latest expiry of its
    /// contact packets. `deposited_at` tells the two cases apart: `None`,
    /// it expired here before any deposit; set, it was deposited and then
    /// lost (verdict).
    pub expired_at: Option<u64>,
    /// Contact devices it was sealed for (devices skipped at sealing are not counted).
    pub devices: u32,
    pub devices_received: u32,
    /// On the network or received.
    pub devices_left: u32,
    /// Still pending but a deposit was tried: a node may have it, so a
    /// deletion counts it as left (spec §14.1). Included in `devices_pending`.
    #[uniffi(default = 0)]
    pub devices_tried: u32,
    /// Still waiting on this iPhone (not deposited, not expired).
    pub devices_pending: u32,
    /// On the network and still checked by the syncs: its ack, and past
    /// its expiry its verdict (spec §15.5). False once the app let it go
    /// unconfirmed (past the nodes' ack grace, or a migrated delivery
    /// without a queue row): the relays can no longer confirm it, and it
    /// stays `OnNetwork`.
    #[uniffi(default = false)]
    pub awaiting_verdict: bool,
}

/// One delivery of a sent message to a contact device.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceDelivery {
    /// Hex device id.
    pub device: String,
    /// Name from the contact's card; empty if the device left the card.
    pub name: String,
    pub state: DeliveryState,
    pub sealed_at: u64,
    pub deposited_at: Option<u64>,
    /// Short id of the first node that accepted it.
    pub node: Option<String>,
    pub received_at: Option<u64>,
    pub expired_at: Option<u64>,
}

/// A node that accepted at least one of the contact packets.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RelayHop {
    /// Short node id.
    pub node: String,
    /// First acceptance there, Unix seconds.
    pub at: u64,
    /// Packet bytes (0 if unknown).
    pub size: u32,
}

/// Copies of a sent message for my other devices.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OwnCopies {
    pub total: u32,
    /// On the network or received.
    pub left: u32,
    /// Still waiting on this iPhone.
    pub waiting: u32,
}

/// The message sheet.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MessageDelivery {
    pub message_id: i64,
    pub delivery: Delivery,
    /// Deliveries to the contact's devices, by sealing date.
    pub devices: Vec<DeviceDelivery>,
    /// First acceptance first.
    pub relays: Vec<RelayHop>,
    pub own_copies: OwnCopies,
}

/// Sent messages to a contact per state (the "Sent" group titles).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryCounts {
    pub pending: u32,
    pub on_network: u32,
    pub received: u32,
    pub not_delivered: u32,
}

/// One line of a "Sent" group page.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryRowInfo {
    pub message_id: i64,
    pub body: String,
    /// Unix seconds.
    pub at: u64,
    pub delivery: Delivery,
}

/// Fresh delivery of one message (`Device::deliveries_of`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryUpdate {
    pub message_id: i64,
    /// `None`: no summary (a received message, one sent from another of my
    /// devices) or the message is gone (`removed`).
    pub delivery: Option<Delivery>,
    /// The message no longer exists (deleted, or an unknown id): the app
    /// drops its row.
    pub removed: bool,
}

/// What a deletion really did (spec §5.5).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeleteOutcome {
    pub deleted: u32,
    /// Messages nobody will receive: every contact packet was still here.
    pub cancelled: u32,
    /// Messages with some packets cancelled and some already gone.
    pub partly_cancelled: u32,
    /// Messages fully gone before the delete (on the network or received).
    pub already_left: u32,
    /// Display names of contacts who will still receive at least one message.
    pub still_receiving: Vec<String>,
    /// At least one copy for my other devices left or keeps going.
    pub own_copies_kept: bool,
    /// One sent message deleted: its contact devices already left (they
    /// keep it). 0 for several messages or a received one.
    pub devices_left: u32,
    /// One sent message deleted: its contact devices left or cancelled.
    pub devices_total: u32,
    /// Messages whose delivery changed during the call, the deleted ones
    /// included: the conversations to reload.
    pub changes: Vec<DeliveryChange>,
}

/// Sort of a pending packet that is not one of my messages to a contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PendingKind {
    /// A receipt for a message I received.
    Ack,
    /// A copy of one of my sent messages for my other devices.
    OwnCopy,
    /// Synchronisation for my devices (contacts, device list, leaving).
    DeviceSync,
    /// My card update for a contact's device.
    CardUpdate,
}

/// One of my messages with packets to the contact still waiting here.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingMessage {
    pub message_id: i64,
    /// Contact fingerprint.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    pub body: String,
    pub sealed_at: u64,
    /// Earliest expiry of its pending packets.
    pub expires_at: u64,
    /// Its pending packets.
    pub packets: u32,
    /// Its contact deliveries.
    pub devices: u32,
    /// Its contact deliveries on the network or received.
    pub devices_left: u32,
    /// Its contact deliveries pending whose deposit was tried: a node may
    /// have them (spec §14.1).
    #[uniffi(default = 0)]
    pub devices_tried: u32,
}

/// Pending packets of one sort (the "Synchronisation" section).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingSync {
    pub kind: PendingKind,
    pub packets: u32,
    /// Names of the contacts concerned, when known.
    pub names: Vec<String>,
}

/// Packets no node accepted yet that have not expired (spec §5.7).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingPackets {
    /// Oldest expiry first.
    pub messages: Vec<PendingMessage>,
    pub sync: Vec<PendingSync>,
    /// Both sections together.
    pub packets: u32,
}

/// A sent message whose delivery changed (`contact` = its fingerprint).
#[derive(Clone, Debug, PartialEq, Eq, Hash, uniffi::Record)]
pub struct DeliveryChange {
    pub contact: String,
    pub message_id: i64,
}

pub(crate) fn state_of(s: MessageStatus) -> DeliveryState {
    match s {
        MessageStatus::Pending => DeliveryState::Pending,
        MessageStatus::OnNetwork => DeliveryState::OnNetwork,
        MessageStatus::Received => DeliveryState::Received,
        MessageStatus::NotDelivered => DeliveryState::NotDelivered,
    }
}

fn status_of(s: DeliveryState) -> MessageStatus {
    match s {
        DeliveryState::Pending => MessageStatus::Pending,
        DeliveryState::OnNetwork => MessageStatus::OnNetwork,
        DeliveryState::Received => MessageStatus::Received,
        DeliveryState::NotDelivered => MessageStatus::NotDelivered,
    }
}

pub(crate) fn delivery_of(s: DeliverySummary) -> Delivery {
    Delivery {
        state: state_of(s.state),
        sealed_at: s.sealed_at,
        deposited_at: s.deposited_at,
        received_at: s.received_at,
        expired_at: s.expired_at,
        devices: s.devices,
        devices_received: s.devices_received,
        devices_left: s.devices_left,
        devices_tried: s.devices_tried,
        devices_pending: s.devices_pending,
        awaiting_verdict: s.awaiting_verdict,
    }
}

pub(crate) fn changes_of(list: Vec<(Fingerprint, i64)>) -> Vec<DeliveryChange> {
    list.into_iter()
        .map(|(fp, id)| DeliveryChange {
            contact: fp.to_string(),
            message_id: id,
        })
        .collect()
}

/// Alias, otherwise display name, otherwise the start of the fingerprint.
pub(crate) fn contact_name(contacts: &[ContactSummary], fp: &Fingerprint) -> String {
    contacts
        .iter()
        .find(|c| c.fingerprint == *fp)
        .and_then(|c| {
            c.alias
                .clone()
                .filter(|a| !a.is_empty())
                .or_else(|| Some(c.display_name.clone()))
        })
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| fp.to_string().chars().take(8).collect())
}

fn kind_of(k: store::PendingKind) -> PendingKind {
    match k {
        store::PendingKind::Ack => PendingKind::Ack,
        store::PendingKind::OwnCopy => PendingKind::OwnCopy,
        store::PendingKind::DeviceSync => PendingKind::DeviceSync,
        store::PendingKind::CardUpdate => PendingKind::CardUpdate,
    }
}

fn outcome_of(
    core: &mut Core,
    o: barking_core::core::DeleteOutcome,
) -> Result<DeleteOutcome, BarkingError> {
    let contacts = core.contacts()?;
    Ok(DeleteOutcome {
        deleted: o.deleted,
        cancelled: o.cancelled,
        partly_cancelled: o.partly_cancelled,
        already_left: o.already_left,
        still_receiving: o
            .still_receiving
            .iter()
            .map(|fp| contact_name(&contacts, fp))
            .collect(),
        own_copies_kept: o.own_copies_kept,
        devices_left: o.devices_left,
        devices_total: o.devices_total,
        changes: changes_of(core.take_delivery_changes()),
    })
}

fn detail_of(
    core: &Core,
    d: store::MessageDeliveryDetail,
) -> Result<MessageDelivery, BarkingError> {
    // A contact removed since keeps its rows: its devices have no name.
    let names = match core.contact_devices(&d.contact) {
        Ok(devices) => devices,
        Err(CoreError::UnknownContact) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let devices = d
        .deliveries
        .into_iter()
        .filter(|r| !r.own)
        .map(|r| DeviceDelivery {
            device: to_hex(&r.device.0),
            name: names
                .iter()
                .find(|(id, _, _)| *id == r.device)
                .map(|(_, name, _)| name.clone())
                .unwrap_or_default(),
            state: state_of(r.state),
            sealed_at: r.sealed_at,
            deposited_at: r.deposited_at,
            node: r.node,
            received_at: r.received_at,
            expired_at: r.expired_at,
        })
        .collect();
    Ok(MessageDelivery {
        message_id: d.row_id,
        delivery: delivery_of(d.summary),
        devices,
        relays: d
            .relays
            .into_iter()
            .map(|h| RelayHop {
                node: h.node,
                at: h.at,
                size: h.size,
            })
            .collect(),
        own_copies: OwnCopies {
            total: d.own_copies.total,
            left: d.own_copies.left,
            waiting: d.own_copies.waiting,
        },
    })
}

fn pending_of(core: &Core, p: store::PendingPackets) -> Result<PendingPackets, BarkingError> {
    let contacts = core.contacts()?;
    Ok(PendingPackets {
        messages: p
            .messages
            .into_iter()
            .map(|m| PendingMessage {
                message_id: m.row_id,
                name: contact_name(&contacts, &m.contact),
                contact: m.contact.to_string(),
                body: m.body,
                sealed_at: m.sealed_at,
                expires_at: m.expires_at,
                packets: m.packets,
                devices: m.devices,
                devices_left: m.devices_left,
                devices_tried: m.devices_tried,
            })
            .collect(),
        sync: p
            .sync
            .into_iter()
            .map(|s| PendingSync {
                kind: kind_of(s.kind),
                packets: s.packets,
                names: s
                    .contacts
                    .iter()
                    .map(|fp| contact_name(&contacts, fp))
                    .collect(),
            })
            .collect(),
        packets: p.packets,
    })
}

#[uniffi::export]
impl Device {
    /// Fresh deliveries of the messages `ids`, in the order given, for
    /// patching the rows on screen (`SyncSummary::delivery_changes`). A
    /// deleted or unknown id comes back `removed`.
    pub fn deliveries_of(&self, ids: Vec<i64>) -> Result<Vec<DeliveryUpdate>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let found = core.deliveries_of(&ids, now())?;
                let mut found = found.into_iter().peekable();
                Ok(ids
                    .iter()
                    .map(|id| match found.next_if(|(f, _)| f == id) {
                        Some((_, s)) => DeliveryUpdate {
                            message_id: *id,
                            delivery: s.map(delivery_of),
                            removed: false,
                        },
                        None => DeliveryUpdate {
                            message_id: *id,
                            delivery: None,
                            removed: true,
                        },
                    })
                    .collect())
            })
        })
    }

    /// The message sheet of the sent message `message_id`; `None` if
    /// unknown, received, or without a delivery to the contact.
    pub fn message_delivery(
        &self,
        message_id: i64,
    ) -> Result<Option<MessageDelivery>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                core.message_delivery(message_id, now())?
                    .map(|d| detail_of(core, d))
                    .transpose()
            })
        })
    }

    /// Sent messages to `contact` (fingerprint or alias) per state.
    pub fn delivery_counts(&self, contact: String) -> Result<DeliveryCounts, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                let [pending, on_network, received, not_delivered] =
                    core.delivery_counts(&fp, now())?;
                Ok(DeliveryCounts {
                    pending,
                    on_network,
                    received,
                    not_delivered,
                })
            })
        })
    }

    /// One page of the sent messages to `contact` in `state`, newest first.
    pub fn delivery_page(
        &self,
        contact: String,
        state: DeliveryState,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<DeliveryRowInfo>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core
                    .delivery_page(&fp, status_of(state), limit, offset, now())?
                    .into_iter()
                    .map(|(m, s)| DeliveryRowInfo {
                        message_id: m.id,
                        body: m.body,
                        at: m.at,
                        delivery: delivery_of(s),
                    })
                    .collect())
            })
        })
    }

    /// Deletes one message (spec §5.5); an unknown one counts nothing.
    pub fn delete_message(&self, message_id: i64) -> Result<DeleteOutcome, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let o = core.delete_message(message_id, now())?;
                outcome_of(core, o)
            })
        })
    }

    /// Deletes the messages `ids` in one transaction.
    pub fn delete_messages(&self, ids: Vec<i64>) -> Result<DeleteOutcome, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let o = core.delete_messages(&ids, now())?;
                outcome_of(core, o)
            })
        })
    }

    /// Deletes every sent message still `Pending`, all contacts ("Cancel all").
    pub fn cancel_all_pending(&self) -> Result<DeleteOutcome, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let o = core.cancel_all_pending(now())?;
                outcome_of(core, o)
            })
        })
    }

    /// Sends a `NotDelivered` message again (same identifier, same row);
    /// the next sync deposits it. `NothingToRetry` if it is not
    /// `NotDelivered`. The due packets expire first, as for a read.
    pub fn retry_message(&self, message_id: i64) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let t = now();
                core.expire_due(t)?;
                core.retry_message(message_id, t, &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// Sends every `NotDelivered` message to `contact` again; returns how
    /// many. The due packets expire first, as for a read.
    pub fn retry_all(&self, contact: String) -> Result<u32, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                let t = now();
                core.expire_due(t)?;
                Ok(core.retry_all(&fp, t, &mut rand::rng())?)
            })
        })
    }

    /// The pending packets screen.
    pub fn pending_packets(&self) -> Result<PendingPackets, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let p = core.pending_packets(now())?;
                pending_of(core, p)
            })
        })
    }

    /// Packets of `pending_packets`: the network screen's count.
    pub fn pending_count(&self) -> Result<u32, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.pending_count(now())?)))
    }
}
