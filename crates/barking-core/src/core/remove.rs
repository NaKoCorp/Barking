//! Removing one of my devices from my account.
//!
//! The administrator signs my device list at `version + 1` without the
//! device and sends it like a link does: `SyncDevices` to my other devices,
//! the removed one included (it learns it at once, `removed.rs` on its
//! side), and `CardUpdate` to my contacts, which stop encrypting for it. No
//! new packet format between contacts: the list travels in the existing
//! cards.
//!
//! A linked device leaves by sending `Body::RemoveMe` to my other devices:
//! only the one holding the root acts on it (same removal, plus
//! `RemoveRequested`), the others ack it without effect. The administrator
//! leaves through `transfer_and_leave` (`admin.rs`), which sends `RemoveMe`
//! to the new holder at the transfer's ack. Once `RemoveMe` is queued,
//! `leave_ready` lets the app wipe the device.

use rand_core::CryptoRng;

use super::link::{META_OWN_CARD, rebuild_card};
use super::send::{SealTime, Target, seal_for};
use super::{Core, META_DEVICE_LIST, META_LINKED_BUNDLES, OwnDevices, admin, log, sync};
use crate::envelope::{self, Body};
use crate::handshake::{PrekeyBundle, PrekeySecrets};
use crate::identity::{DeviceId, DeviceKeys, DeviceList, RootIdentity};
use crate::packet::{Packet, PacketId};
use crate::store::{MessageId, Queries};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// `RemoveMe` was queued on this device: it may be wiped.
const META_LEAVE_SENT: &str = "leave_sent";

/// A removal written by [`remove_in`].
pub(super) struct Removal {
    /// `SyncDevices` for my devices (the removed one included), then
    /// `CardUpdate` for my contacts.
    pub packets: Vec<Packet>,
    pub devices: DeviceList,
    /// Key packets of my other devices still listed.
    pub linked: Vec<PrekeyBundle>,
    /// Name of the removed device.
    pub name: String,
}

/// Removes `target` from my list, in the caller's transaction, on the
/// administrator (`root`; `my_bundle`: this device's key packet). Every
/// refusal precedes the first write: a pending admin transfer
/// (`AdminTransferPending`), this device or a device not in my list
/// (`Malformed`). Logs `DeviceRemoved`.
pub(super) fn remove_in(
    q: &impl Queries,
    me: &DeviceKeys,
    my_bundle: PrekeyBundle,
    root: &RootIdentity,
    target: DeviceId,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Removal> {
    admin::purge_expired(q, now)?;
    admin::ensure_none_pending(q, now)?;
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    if target == me.public().id() {
        return Err(CoreError::Malformed("cannot remove this device"));
    }
    let name = own
        .list
        .certs
        .iter()
        .find(|c| c.device.id() == target)
        .ok_or(CoreError::Malformed("unknown device"))?
        .name
        .clone();
    let version = own.list.version.checked_add(1).ok_or(CoreError::TooLarge)?;
    let certs = own
        .list
        .certs
        .iter()
        .filter(|c| c.device.id() != target)
        .cloned()
        .collect();
    let devices = DeviceList::sign(root, version, certs)?;
    let linked: Vec<PrekeyBundle> = own
        .bundles
        .into_iter()
        .filter(|b| devices.certs.iter().any(|c| c.device == b.device))
        .collect();
    let mut bundles = vec![my_bundle];
    bundles.extend(linked.iter().cloned());
    let card = rebuild_card(q, root, &devices, bundles)?;
    if !envelope::fits_in_packet(&Body::CardUpdate(Box::new(card.clone()))) {
        return Err(CoreError::TooLarge);
    }

    // Sealed before writing the new list: the stored one still lists the
    // removed device, which thus gets it too.
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let devices_body = Body::SyncDevices {
        card: Box::new(card.clone()),
    };
    let mut packets = sync::seal_to_own(
        q,
        me,
        &devices_body,
        SyncKind::Devices,
        MessageId(id),
        SealTime::at(now),
        rng,
    )?;
    q.put_meta(META_DEVICE_LIST, &devices)?;
    q.put_meta(META_LINKED_BUNDLES, &linked)?;
    q.put_meta(META_OWN_CARD, &card)?;
    sync::purge_removed_own_sessions(q, &devices)?;
    log(
        q,
        now,
        None,
        &TransparencyEvent::DeviceRemoved {
            device: target,
            name: name.clone(),
        },
    )?;
    packets.extend(sync::send_card_update(q, me, &card, now, rng)?);
    Ok(Removal {
        packets,
        devices,
        linked,
        name,
    })
}

/// `RemoveMe` from `sender`, one of my listed devices, received in the
/// transaction `q`. On the administrator (`admin`: my root and key-packet
/// secrets), removes it and logs `RemoveRequested`: `true`. Elsewhere, or
/// when the removal is refused (a pending admin transfer), nothing: the
/// caller acks it without effect, `false`.
pub(super) fn on_remove_me(
    q: &impl Queries,
    device: &DeviceKeys,
    admin: Option<(&RootIdentity, &PrekeySecrets)>,
    sender: DeviceId,
    packet: Option<PacketId>,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<bool> {
    let Some((root, prekeys)) = admin else {
        return Ok(false);
    };
    let removal = match remove_in(
        q,
        device,
        prekeys.bundle(device, false),
        root,
        sender,
        now,
        rng,
    ) {
        Ok(removal) => removal,
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => return Err(e),
        Err(_) => return Ok(false),
    };
    log(
        q,
        now,
        packet,
        &TransparencyEvent::RemoveRequested {
            device: sender,
            name: removal.name,
        },
    )?;
    Ok(true)
}

/// Seals `RemoveMe` for `target` (my other devices, or the new holder of
/// the root) and records that it is queued (`leave_ready`). Returns the
/// packets; none if no device could be reached, and then nothing recorded.
pub(super) fn send_remove_me(
    q: &impl Queries,
    device: &DeviceKeys,
    target: &Target,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Packet>> {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let message_id = MessageId(id);
    let sealed = seal_for(
        q,
        device,
        target,
        &Body::RemoveMe,
        message_id,
        SealTime::at(now),
        rng,
    )?;
    for (packet, peer) in &sealed {
        q.add_delivery(message_id, packet.id, *peer, true)?;
    }
    if !sealed.is_empty() {
        q.put_meta(META_LEAVE_SENT, &true)?;
    }
    Ok(sealed.into_iter().map(|(p, _)| p).collect())
}

impl Core {
    /// Removes my device `device` from my account (administrator only):
    /// my list signed at `version + 1` without it, sent to my other devices
    /// and to the removed one (`SyncDevices`), and to my contacts
    /// (`CardUpdate`); these packets are returned. Refused without the root
    /// (`NotAdmin`), while an admin transfer is pending
    /// (`AdminTransferPending`), for this device (use `transfer_and_leave`)
    /// or a device not in my list (`Malformed`).
    pub fn remove_device(
        &mut self,
        device: DeviceId,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        let Core {
            store,
            device: me,
            root,
            prekeys,
            ..
        } = self;
        let root = root.as_ref().ok_or(CoreError::NotAdmin)?;
        let my_bundle = prekeys.bundle(me, false);
        let removal =
            store.transaction(|tx| remove_in(tx, me, my_bundle, root, device, now, rng))?;
        self.devices = removal.devices;
        self.linked_bundles = removal.linked;
        Ok(removal.packets)
    }

    /// A linked device leaves my account: `RemoveMe` sealed to my other
    /// devices, of which the administrator removes this one (the others
    /// ignore it). Returns the packets; `leave_ready` is then true and the
    /// app may wipe. Refused on the administrator (`IsAdmin`: use
    /// `transfer_and_leave`), and without any reachable device (`NoSession`).
    pub fn leave(&mut self, now: u64, rng: &mut impl CryptoRng) -> Result<Vec<Packet>> {
        self.ensure_active()?;
        if self.root.is_some() {
            return Err(CoreError::IsAdmin);
        }
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let packets = send_remove_me(tx, device, &Target::OwnDevices, now, rng)?;
            if packets.is_empty() {
                return Err(CoreError::NoSession);
            }
            Ok(packets)
        })
    }

    /// `RemoveMe` is queued (`leave`, or `transfer_and_leave` after the
    /// transfer's ack): the app may wipe this device.
    pub fn leave_ready(&self) -> Result<bool> {
        Ok(self
            .store
            .get_meta::<bool>(META_LEAVE_SENT)?
            .unwrap_or(false))
    }
}
