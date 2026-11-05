//! Synchronization between my own devices: copies of my sent
//! messages (`SyncSent`), operations on contacts (`SyncContact`) and
//! new device list (`SyncDevices`).
//!
//! Sending: through the double ratchet sessions with my other devices
//! (`Target::OwnDevices`), one delivery per packet so that their acks
//! drain the send queue. Receiving: only from one of my devices
//! (checked by the caller), with the same checks as the local operation.
//! A refused content is quarantined, never an `Err`.

use std::collections::HashSet;

use rand_core::CryptoRng;

use super::link::META_OWN_CARD;
use super::send::{SealTime, Target, seal_for};
use super::{META_DEVICE_LIST, META_LINKED_BUNDLES, OwnDevices, contacts, load_card, log};
use crate::contact::ContactCard;
use crate::envelope::{self, Body, Envelope, SyncOp};
use crate::handshake::PrekeyBundle;
use crate::identity::{DeviceId, DeviceKeys, DeviceList, DevicePublic, Fingerprint};
use crate::packet::Packet;
use crate::store::{ContactClock, Direction, MessageId, MessageStatus, Queries};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

// Quarantine reasons: fixed texts.
pub(super) const R_NOT_MINE: &str = "synchronization from a device that is not mine";
pub(super) const R_SYNC_REFUSED: &str = "synchronization refused";
pub(super) const R_DEVICES_REFUSED: &str = "device list refused";

/// Seals `body` for each of my other devices; each packet is
/// recorded as an `own` delivery of `message_id` (its ack does not make
/// the message "delivered"). Without another device, nothing is done.
///
/// A content too large for a packet is not sent: the local
/// operation succeeds anyway, and `SyncSkipped` is logged. The size is
/// checked before `seal_for`, which already writes sessions and log.
pub(super) fn seal_to_own(
    q: &impl Queries,
    device: &DeviceKeys,
    body: &Body,
    kind: SyncKind,
    message_id: MessageId,
    time: SealTime,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Packet>> {
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    if own.others(&device.public()).is_empty() {
        return Ok(Vec::new());
    }
    if !envelope::fits_in_packet(body) {
        log(q, time.now, None, &TransparencyEvent::SyncSkipped { kind })?;
        return Ok(Vec::new());
    }
    let sealed = seal_for(q, device, &Target::OwnDevices, body, message_id, time, rng)?;
    for (packet, peer) in &sealed {
        q.add_delivery(message_id, packet.id, *peer, true)?;
    }
    Ok(sealed.into_iter().map(|(p, _)| p).collect())
}

/// Queues my new card (`CardUpdate`) for each reachable device
/// of each of my contacts, one delivery per packet (without a message
/// row, under a fresh identifier per contact). Size checked before
/// any sealing: a card too large for a packet (impossible with the
/// device cap) makes the call fail (`TooLarge`) without writing anything.
pub(super) fn send_card_update(
    q: &impl Queries,
    device: &DeviceKeys,
    card: &ContactCard,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Packet>> {
    let body = Body::CardUpdate(Box::new(card.clone()));
    if !envelope::fits_in_packet(&body) {
        return Err(CoreError::TooLarge);
    }
    let mut out = Vec::new();
    for row in q.list_contacts()? {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let message_id = MessageId(id);
        let target = Target::Contact(row.fp);
        let sealed = seal_for(
            q,
            device,
            &target,
            &body,
            message_id,
            SealTime::at(now),
            rng,
        )?;
        for (packet, peer) in sealed {
            q.add_delivery(message_id, packet.id, peer, false)?;
            out.push(packet);
        }
    }
    Ok(out)
}

/// My stored card. The `own_card` entry of a home created by an earlier
/// build holds the plain postcard of the old card: read the current form
/// first, then `ContactCard::decode`; an unreadable entry counts as none
/// (the callers must never fail because of it).
pub(super) fn own_card(q: &impl Queries) -> Result<Option<ContactCard>> {
    let Some(raw) = q.get_meta_raw(META_OWN_CARD)? else {
        return Ok(None);
    };
    Ok(postcard::from_bytes::<ContactCard>(&raw)
        .ok()
        .or_else(|| ContactCard::decode(&raw).ok()))
}

/// Queues my current card (`CardUpdate`) for only the `devices`
/// of contact `fp`: its new devices, learned through an update of
/// its card. They may have been linked with a copy of my card older
/// than the one I sent to its other devices (two crossed
/// linkings); without this, they would only learn about my new devices at the
/// next change of my list. An already known card is a duplicate
/// acked on their side.
///
/// Without a stored card (no linking on this account: my contacts have the
/// card I gave them) or a card too large for a packet, nothing
/// is sent: the receipt must never fail because of it.
pub(super) fn send_own_card(
    q: &impl Queries,
    device: &DeviceKeys,
    fp: Fingerprint,
    devices: &[DeviceId],
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    if devices.is_empty() {
        return Ok(());
    }
    let Some(card) = own_card(q)? else {
        return Ok(());
    };
    let body = Body::CardUpdate(Box::new(card));
    if !envelope::fits_in_packet(&body) {
        return Ok(());
    }
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let message_id = MessageId(id);
    let target = Target::ContactDevices(fp, devices.to_vec());
    let sealed = seal_for(
        q,
        device,
        &target,
        &body,
        message_id,
        SealTime::at(now),
        rng,
    )?;
    for (packet, peer) in sealed {
        q.add_delivery(message_id, packet.id, peer, false)?;
    }
    Ok(())
}

/// Queues operation `op` for each of my other devices, under a fresh
/// message identifier (without a message row). `time.sent_at` is
/// the operation date (contact's clock, see [`touch`]).
pub(super) fn send_op(
    q: &impl Queries,
    device: &DeviceKeys,
    op: SyncOp,
    time: SealTime,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let body = Body::SyncContact(op);
    seal_to_own(
        q,
        device,
        &body,
        SyncKind::Contact,
        MessageId(id),
        time,
        rng,
    )?;
    Ok(())
}

/// Queues the stored state of contact `fp` (`SyncOp::Upsert`).
pub(super) fn send_state(
    q: &impl Queries,
    device: &DeviceKeys,
    fp: Fingerprint,
    time: SealTime,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    let op = SyncOp::UpsertV2 {
        card: Box::new(load_card(&row.card)?),
        alias: row.alias.clone(),
        verified: row.verified,
        verified_at: q.verified_at(fp)?,
    };
    send_op(q, device, op, time, rng)
}

/// Local operation of device `me` on contact `fp` at `now`:
/// the contact's clock advances strictly (a local operation wins
/// over everything this device already knows), and `removed` sets or clears the
/// tombstone. Returns the dates for sealing its copy: `sent_at`
/// is the operation date, `now` remains the wall clock.
pub(super) fn touch(
    q: &impl Queries,
    fp: Fingerprint,
    now: u64,
    removed: bool,
    me: DeviceId,
) -> Result<SealTime> {
    let at = match q.contact_clock(fp)? {
        Some(last) if last.at >= now => last.at.saturating_add(1),
        _ => now,
    };
    let clock = ContactClock {
        at,
        removed,
        writer: me,
    };
    q.set_contact_clock(fp, &clock)?;
    Ok(SealTime { now, sent_at: at })
}

/// Applies an authenticated sync content, coming from one of my
/// devices. Every check precedes the first write: a refusal
/// (`Ok(Err(reason))`) leaves nothing written. `Err`: local failure only.
/// `Ok(Ok(None))`: valid content but already superseded (an authentic
/// device list older than mine), nothing written, to be acked like
/// a duplicate.
///
/// `sender`: the device (among mine) that authenticated the content; it
/// breaks the tie between two operations with the same date on a contact.
pub(super) fn apply(
    q: &impl Queries,
    me: &DevicePublic,
    sender: DeviceId,
    env: &Envelope,
) -> Result<core::result::Result<Option<SyncKind>, &'static str>> {
    match &env.body {
        Body::Text(_) | Body::CardUpdate(_) => Ok(Err(R_SYNC_REFUSED)),
        Body::SyncSent { to, text } => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
            if *to == own.list.root.fingerprint() {
                return Ok(Err(R_SYNC_REFUSED));
            }
            // Raw identifier, outgoing direction: the same as on the device
            // that sent it. Already present (imported history): nothing to do.
            q.insert_message(
                *to,
                Direction::Out,
                text,
                MessageStatus::Sent,
                env.sent_at,
                MessageId(env.message_id),
            )?;
            Ok(Ok(Some(SyncKind::Sent)))
        }
        Body::SyncContact(op) => {
            Ok(content(apply_op(q, op, env.sent_at, sender))?.map(|()| Some(SyncKind::Contact)))
        }
        Body::SyncDevices { card } => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
            if card.devices.root == own.list.root && card.devices.version <= own.list.version {
                return Ok(older_devices(&own.list, me, card));
            }
            if !devices_ok(q, &own.list, me, card)? {
                return Ok(Err(R_DEVICES_REFUSED));
            }
            let others: Vec<PrekeyBundle> = card
                .bundles
                .iter()
                .filter(|b| b.device != *me)
                .cloned()
                .collect();
            q.put_meta(META_DEVICE_LIST, &card.devices)?;
            q.put_meta(META_LINKED_BUNDLES, &others)?;
            q.put_meta(META_OWN_CARD, card)?;
            purge_removed_own_sessions(q, &card.devices)?;
            Ok(Ok(Some(SyncKind::Devices)))
        }
    }
}

/// List received with a version lower than or equal to mine. Authentic (card
/// and list signed by my root) and containing this device: already superseded,
/// duplicate acked (a delayed copy, as for `CardUpdate`). Same
/// version but different list: root equivocation, refusal; likewise
/// for an invalid card or one that does not contain me.
fn older_devices(
    current: &DeviceList,
    me: &DevicePublic,
    card: &ContactCard,
) -> core::result::Result<Option<SyncKind>, &'static str> {
    let equivocation = card.devices.version == current.version && card.devices != *current;
    if equivocation || card.verify().is_err() || !card.devices.certs.iter().any(|c| c.device == *me)
    {
        return Err(R_DEVICES_REFUSED);
    }
    Ok(None)
}

/// Error due to the content → refusal; storage error → propagated.
fn content<T>(r: Result<T>) -> Result<core::result::Result<T, &'static str>> {
    match r {
        Ok(v) => Ok(Ok(v)),
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => Err(e),
        Err(_) => Ok(Err(R_SYNC_REFUSED)),
    }
}

/// State of a contact, last writer wins per fingerprint, on
/// `(at, deleted, author)` ([`ContactClock`]): `at` is the authenticated
/// timestamp of the envelope, `sender` the device that sent it. An
/// operation that does not beat the last known one has no effect
/// (accepted and acked). On equal dates, a deletion beats a present
/// state, then the device with the greatest identifier: all my devices
/// decide the same way, whatever the arrival order. The tombstone of a
/// deletion prevents an older state from resurrecting the contact; a
/// more recent state clears it.
fn apply_op(q: &impl Queries, op: &SyncOp, at: u64, sender: DeviceId) -> Result<()> {
    let (fp, removing) = match op {
        SyncOp::Upsert { card, .. } | SyncOp::UpsertV2 { card, .. } => (card.fingerprint(), false),
        SyncOp::Remove(fp) => (*fp, true),
    };
    // The verified status is its own register: merged whatever the clock of
    // the contact's other operations.
    let register = match op {
        SyncOp::Upsert { verified, .. } => Some((*verified, 0)),
        SyncOp::UpsertV2 {
            verified,
            verified_at,
            ..
        } => Some((*verified, *verified_at)),
        SyncOp::Remove(_) => None,
    };
    if let Some((verified, at)) = register {
        contacts::merge_verified(q, fp, verified, at)?;
    }
    let clock = ContactClock {
        at,
        removed: removing,
        writer: sender,
    };
    if !clock.newer_than(q.contact_clock(fp)?.as_ref()) {
        return Ok(());
    }
    match op {
        SyncOp::Upsert {
            card,
            alias,
            verified,
        } => contacts::upsert_in(q, card, alias, *verified, &clock)?,
        SyncOp::UpsertV2 {
            card,
            alias,
            verified,
            verified_at,
        } => {
            let new = q.get_contact(fp)?.is_none();
            contacts::upsert_in(q, card, alias, *verified, &clock)?;
            if new {
                q.set_verified(fp, *verified, *verified_at)?;
            }
        }
        SyncOp::Remove(fp) => {
            if q.get_contact(*fp)?.is_some() {
                q.delete_contact(*fp)?;
            }
        }
    }
    q.set_contact_clock(fp, &clock)
}

/// Acceptable new card: list signed by my root, with a strictly
/// greater version, containing this device; verified card, with a
/// key packet for this device; no new device claimed by a
/// contact.
fn devices_ok(
    q: &impl Queries,
    current: &DeviceList,
    me: &DevicePublic,
    card: &ContactCard,
) -> Result<bool> {
    let devices = &card.devices;
    if !devices.supersedes(current)
        || card.verify().is_err()
        || !devices.certs.iter().any(|c| c.device == *me)
        || !card.bundles.iter().any(|b| b.device == *me)
    {
        return Ok(false);
    }
    let added: Vec<DevicePublic> = devices
        .certs
        .iter()
        .map(|c| c.device)
        .filter(|d| !current.certs.iter().any(|c| c.device == *d))
        .collect();
    Ok(!contacts::claimed_by_contact(q, None, &added)?)
}
/// Removes the sessions filed under my fingerprint with a device absent
/// from `list` (my new list).
pub(super) fn purge_removed_own_sessions(q: &impl Queries, list: &DeviceList) -> Result<()> {
    let fp = list.root.fingerprint();
    let kept: HashSet<DeviceId> = list.certs.iter().map(|c| c.device.id()).collect();
    let mut removed: Vec<DeviceId> = q
        .all_sessions()?
        .iter()
        .filter(|s| s.contact_fp == fp && !kept.contains(&s.contact_device))
        .map(|s| s.contact_device)
        .collect();
    removed.dedup();
    for id in removed {
        q.delete_sessions_for_device(fp, id)?;
    }
    Ok(())
}
