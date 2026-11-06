//! Receiving: bytes coming from outside, never a panic nor an `Err`
//! because of their content. `Err` is reserved for local failures (storage).

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::log_limit::{LogLimiter, log_limited};
use super::route::{self, RouteStep};
use super::{
    Core, MAX_AGE_SECS, MAX_FUTURE_SECS, META_PREKEYS, OwnDevices, ReceiveOutcome,
    SEEN_RETENTION_SECS, admin, contacts, de_state, load_card, log, remove, removed, ser_state,
    session_ad, session_id, sync,
};
use crate::contact::ContactCard;
use crate::envelope::{self, Body, Envelope, Wire, parse_wire};
use crate::handshake::PrekeySecrets;
use crate::handshake::pqxdh::{self, InitialMessage};
use crate::identity::{DeviceKeys, DeviceList, DevicePublic, Fingerprint, RootIdentity};
use crate::mailbox::{day_of, intro_mailbox, session_mailbox};
use crate::packet::{Kind, Packet, PacketId, ack};
use crate::ratchet::{RatchetMessage, RatchetState};
use crate::store::{Direction, MessageId, MessageStatus, Queries, SessionRow};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

// Quarantine reasons: fixed texts, never content nor key.
pub const R_UNREADABLE: &str = "unreadable content";
pub const R_UNEXPECTED: &str = "unexpected content for this mailbox";
pub const R_UNDECRYPTABLE: &str = "decryption impossible";
pub const R_UNKNOWN_SENDER: &str = "unknown sender";
pub const R_AMBIGUOUS_SENDER: &str = "ambiguous sender";
pub const R_HANDSHAKE: &str = "session opening impossible";
pub const R_BAD_CONTENT: &str = "authenticated but malformed content";
pub const R_ID_MISMATCH: &str = "inconsistent packet identifier";
pub const R_STALE: &str = "message too old or dated in the future";
pub const R_ID_REUSED: &str = "packet identifier already used";

/// Maximum number of sessions kept per remote device.
const MAX_SESSIONS_PER_DEVICE: usize = 2;

/// Output of a receive transaction: the result, and the new
/// key-packet secrets if a session was opened (applied in
/// memory only after the commit).
type RxOut = (ReceiveOutcome, Option<PrekeySecrets>);

/// Session that authenticated the message.
struct Opened {
    row: SessionRow,
    ratchet: RatchetState,
    pt: Zeroizing<Vec<u8>>,
    /// Session opened by this packet, not yet stored.
    new_session: Option<PrekeySecrets>,
    first_contact: bool,
}

impl Core {
    /// Handles a packet received by `transport` (free text noted in the log).
    pub fn receive(
        &mut self,
        bytes: &[u8],
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        // Local state (not the packet content): a device awaiting
        // link has neither a device list nor contacts.
        self.ensure_linked()?;
        let Ok(packet) = Packet::decode(bytes) else {
            return Ok(ReceiveOutcome::NotForUs);
        };
        if u64::from(packet.expires_at) < now {
            return Ok(ReceiveOutcome::Expired);
        }
        match packet.kind {
            Kind::Ack => self.receive_ack(&packet, now, rng),
            Kind::Message => {
                let outcome = self.receive_message(&packet, transport, now, rng)?;
                match outcome {
                    // A list may also remove this device: its root goes.
                    ReceiveOutcome::Synced {
                        kind: SyncKind::Devices,
                    } => {
                        self.reload_own_devices()?;
                        self.reload_root()?;
                    }
                    ReceiveOutcome::Synced {
                        kind: SyncKind::Admin,
                    }
                    | ReceiveOutcome::Removed => self.reload_root()?,
                    _ => {}
                }
                Ok(outcome)
            }
        }
    }

    fn receive_ack(
        &mut self,
        packet: &Packet,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        // Ack payload: exactly `acked.id(16) || secret(16)`.
        let Ok(payload) = <&[u8; 32]>::try_from(packet.payload.as_slice()) else {
            return Ok(ReceiveOutcome::NotForUs);
        };
        let mut acked = [0u8; 16];
        acked.copy_from_slice(&payload[..16]);
        let acked = PacketId(acked);
        let mut secret = [0u8; 16];
        secret.copy_from_slice(&payload[16..]);
        if !ack::verify(&acked, &secret) {
            return Ok(ReceiveOutcome::NotForUs);
        }
        let Core {
            store,
            device,
            log_limiter,
            ..
        } = self;
        let (outcome, transferred) = store.transaction(|tx| {
            // A delivery is always one of my sent packets: a
            // message for a contact, or a sync for one of my
            // devices (without a message row for `SyncContact`/`SyncDevices`).
            if !tx.is_my_packet(acked)? {
                return Ok((ReceiveOutcome::NotForUs, false));
            }
            if tx.delivery_acked(acked)? {
                // A replayed ack (identifier and expiry rewritten at
                // will): grouped in the log.
                log_limited(
                    tx,
                    log_limiter,
                    now,
                    Some(packet.id),
                    &TransparencyEvent::DuplicateIgnored {
                        packet_id: packet.id,
                    },
                )?;
                return Ok((ReceiveOutcome::Duplicate, false));
            }
            // The ack of one of my devices (`SyncSent` copy, `own`
            // delivery) does not make the message delivered: only that of a
            // contact's device counts.
            tx.mark_delivered_by_packet(acked)?;
            route::record(tx, acked, RouteStep::AckVerified, now, None)?;
            tx.outbox_remove(acked)?;
            // An acked request to be removed has left, whatever the transport saw.
            super::remove::note_left(tx, &[acked])?;
            log(
                tx,
                now,
                Some(acked),
                &TransparencyEvent::AckVerified { for_packet: acked },
            )?;
            // Ack of an admin transfer: the root leaves this device (and
            // `RemoveMe` follows after `transfer_and_leave`).
            let transferred = admin::on_ack(tx, device, acked, now, rng)?;
            Ok((
                ReceiveOutcome::AckReceived { packet_id: acked },
                transferred,
            ))
        })?;
        if transferred {
            self.reload_root()?;
        }
        Ok(outcome)
    }

    fn receive_message(
        &mut self,
        packet: &Packet,
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        let my_fp = self.fingerprint();
        let Core {
            store,
            device,
            prekeys,
            root,
            log_limiter,
            ..
        } = self;
        let me = device.public();
        let my_id = me.id();
        let days = accepted_days(now);
        let to_intro = days
            .iter()
            .any(|d| intro_mailbox(&me, *d) == packet.mailbox);

        let (outcome, new_prekeys) = store.transaction(|tx| -> Result<RxOut> {
            let mut matching: Vec<SessionRow> = tx
                .all_sessions()?
                .into_iter()
                .filter(|s| {
                    days.iter()
                        .any(|d| session_mailbox(&s.mailbox_secret, &my_id, *d) == packet.mailbox)
                })
                .collect();
            if !to_intro && matching.is_empty() {
                return Ok((ReceiveOutcome::NotForUs, None));
            }
            tx.purge_seen(now.saturating_sub(SEEN_RETENTION_SECS))?;
            // Verified without being recorded: only an authenticated packet is
            // marked seen, otherwise a fake packet carrying the same identifier
            // would make the original pass for a duplicate.
            if tx.is_seen(packet.id)? {
                log_limited(
                    tx,
                    log_limiter,
                    now,
                    Some(packet.id),
                    &TransparencyEvent::DuplicateIgnored {
                        packet_id: packet.id,
                    },
                )?;
                return Ok((ReceiveOutcome::Duplicate, None));
            }
            let opened = match parse_wire(&packet.payload) {
                Err(_) => Err(R_UNREADABLE),
                Ok(Wire::Initial {
                    ek,
                    sealed_init,
                    msg,
                }) if to_intro => open_initial(tx, device, prekeys, &ek, &sealed_init, &msg, now)?,
                Ok(Wire::Normal { msg }) if !matching.is_empty() => {
                    // Sessions that received most recently first.
                    matching.sort_by_key(|s| core::cmp::Reverse((s.last_rx, s.created_at)));
                    open_normal(matching, &msg, now)?
                }
                Ok(_) => Err(R_UNEXPECTED),
            };
            match opened {
                Err(reason) => quarantine(tx, log_limiter, packet, now, reason),
                Ok(o) => accept(
                    tx,
                    log_limiter,
                    packet,
                    o,
                    device,
                    root.as_ref().map(|r| (r, &*prekeys)),
                    &my_fp,
                    transport,
                    now,
                    rng,
                ),
            }
        })?;
        if let Some(p) = new_prekeys {
            *prekeys = p;
        }
        Ok(outcome)
    }
}

/// Days for which a mailbox (session or introduction) is accepted at
/// receive time: the whole freshness window, from the day of `now - MAX_AGE_SECS`
/// to the day after `now`. A packet's mailbox is fixed at the day of its
/// sealing; a packet delivered late (7-day send queue) must
/// remain readable. `watched_mailboxes` (poll) covers from the last poll
/// to the next day, 9 days at most.
fn accepted_days(now: u64) -> Vec<u32> {
    let first = day_of(now.saturating_sub(MAX_AGE_SECS));
    let last = day_of(now).saturating_add(1);
    (first..=last).collect()
}

/// Copy of the key-packet secrets (round trip through the stored form):
/// `respond` modifies it, and the original changes only after the commit.
fn copy_prekeys(p: &PrekeySecrets) -> Result<PrekeySecrets> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(p).map_err(|_| CoreError::Store("serialization".into()))?,
    );
    postcard::from_bytes(&bytes).map_err(|_| CoreError::Store("serialization".into()))
}

/// Device of a known contact, or one of my other devices (returned with
/// my own fingerprint), whose identity X25519 key is `ik`. This device
/// (`me`) is never a sender.
///
/// Requires a unique match: if two contacts (or a contact and one of
/// my devices) claimed the same key (`add_contact` and
/// `claimed_by_other` forbid it), the sender would be ambiguous and the packet
/// refused rather than attributed to the first one found.
fn find_sender(
    q: &impl Queries,
    ik: &[u8; 32],
    me: &DevicePublic,
) -> Result<core::result::Result<(Fingerprint, DevicePublic), &'static str>> {
    let mut found = None;
    if let Some(own) = OwnDevices::read(q)? {
        let my_fp = own.list.root.fingerprint();
        for (d, _) in own.others(me).into_iter().filter(|(d, _)| d.dh == *ik) {
            if found.is_some() {
                return Ok(Err(R_AMBIGUOUS_SENDER));
            }
            found = Some((my_fp, d));
        }
    }
    for row in q.list_contacts()? {
        let card = load_card(&row.card)?;
        for c in card.devices.certs.iter().filter(|c| c.device.dh == *ik) {
            if found.is_some() {
                return Ok(Err(R_AMBIGUOUS_SENDER));
            }
            found = Some((row.fp, c.device));
        }
    }
    Ok(found.ok_or(R_UNKNOWN_SENDER))
}

/// `Wire::Initial`: opens the sealed initial message, identifies the sender,
/// then decrypts in the existing session (Initial returned) or in a
/// new responder session. Nothing is written here.
fn open_initial(
    q: &impl Queries,
    device: &DeviceKeys,
    prekeys: &PrekeySecrets,
    ek: &[u8; 32],
    sealed_init: &[u8],
    msg: &RatchetMessage,
    now: u64,
) -> Result<core::result::Result<Opened, &'static str>> {
    let Ok(init) = envelope::open_initial(device, ek, sealed_init) else {
        return Ok(Err(R_UNDECRYPTABLE));
    };
    // No contact requests in v0: only a device of a known contact,
    // or one of my other devices, can open a session.
    let (contact_fp, peer) = match find_sender(q, &init.ik, &device.public())? {
        Ok(found) => found,
        Err(reason) => return Ok(Err(reason)),
    };
    let peer_id = peer.id();
    let sid = session_id(&init.ek);
    if let Some(row) = q
        .sessions_for(contact_fp, peer_id)?
        .into_iter()
        .find(|s| s.session_id == sid)
    {
        // Unreadable row: refusal, without error or new session (reopening
        // the session from a replayable Initial is not a repair).
        let Ok(mut ratchet) = de_state(&row.state) else {
            return Ok(Err(R_UNDECRYPTABLE));
        };
        if !ratchet.could_open(msg) {
            return Ok(Err(R_UNDECRYPTABLE));
        }
        return Ok(match ratchet.decrypt(msg, &row.ad, now) {
            Ok(pt) => Ok(Opened {
                row,
                ratchet,
                pt: Zeroizing::new(pt),
                new_session: None,
                first_contact: true,
            }),
            Err(_) => Err(R_UNDECRYPTABLE),
        });
    }
    open_new_session(device, prekeys, &init, contact_fp, peer_id, sid, msg, now)
}

#[allow(clippy::too_many_arguments)]
/// New responder session on a copy of the key-packet secrets.
fn open_new_session(
    device: &DeviceKeys,
    prekeys: &PrekeySecrets,
    init: &InitialMessage,
    contact_fp: Fingerprint,
    peer_id: crate::identity::DeviceId,
    sid: [u8; 16],
    msg: &RatchetMessage,
    now: u64,
) -> Result<core::result::Result<Opened, &'static str>> {
    let mut pk = copy_prekeys(prekeys)?;
    let Ok(secrets) = pqxdh::respond(device, &mut pk, init) else {
        return Ok(Err(R_HANDSHAKE));
    };
    let mut ratchet = RatchetState::init_responder(&secrets.sk, pk.spk());
    let ad = session_ad(&secrets.ad, &peer_id, &device.public().id());
    if !ratchet.could_open(msg) {
        return Ok(Err(R_UNDECRYPTABLE));
    }
    let Ok(pt) = ratchet.decrypt(msg, &ad, now) else {
        return Ok(Err(R_UNDECRYPTABLE));
    };
    let row = SessionRow {
        contact_device: peer_id,
        contact_fp,
        session_id: sid,
        state: Vec::new(),
        mailbox_secret: secrets.mailbox_secret,
        ad,
        pending_initial: None,
        last_rx: now,
        created_at: now,
    };
    Ok(Ok(Opened {
        row,
        ratchet,
        pt: Zeroizing::new(pt),
        new_session: Some(pk),
        first_contact: true,
    }))
}

/// `Wire::Normal`: tries each session with a matching candidate mailbox.
fn open_normal(
    candidates: Vec<SessionRow>,
    msg: &RatchetMessage,
    now: u64,
) -> Result<core::result::Result<Opened, &'static str>> {
    for row in candidates {
        // An unreadable row is ignored (as in `sweep_skipped`).
        let Ok(mut ratchet) = de_state(&row.state) else {
            continue;
        };
        if !ratchet.could_open(msg) {
            continue;
        }
        if let Ok(pt) = ratchet.decrypt(msg, &row.ad, now) {
            return Ok(Ok(Opened {
                row,
                ratchet,
                pt: Zeroizing::new(pt),
                new_session: None,
                first_contact: false,
            }));
        }
    }
    Ok(Err(R_UNDECRYPTABLE))
}

/// Refusal without decryption: no session state changes. In the log,
/// grouped by reason (noise toward my introduction mailbox is free).
fn quarantine(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    now: u64,
    reason: &'static str,
) -> Result<RxOut> {
    log_limited(
        q,
        limiter,
        now,
        Some(packet.id),
        &TransparencyEvent::DecryptFailed {
            packet_id: packet.id,
            reason: reason.to_owned(),
        },
    )?;
    Ok((
        ReceiveOutcome::Quarantined {
            reason: reason.to_owned(),
        },
        None,
    ))
}

/// Message authenticated by a session: verifies the content, then records.
///
/// Message identifier: the envelope's, bound to the sender's
/// fingerprint (`MessageId::incoming`). The same message received a second
/// time (resend, new packet) is not reinserted: `Duplicate`, but the
/// session advances and the ack of this new packet is still emitted
/// (queued for sending), so that the sender stops resending it.
///
/// A text is accepted only from a contact, a synchronization only from one of
/// my devices (`accept_sync`).
#[allow(clippy::too_many_arguments)]
fn accept(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    device: &DeviceKeys,
    admin: Option<(&RootIdentity, &PrekeySecrets)>,
    my_fp: &Fingerprint,
    transport: &str,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let env = match envelope::decode(&o.pt) {
        // No authenticated ack secret: nothing to mark as seen.
        Err(_) => return reject_authenticated(q, limiter, packet, o, now, R_BAD_CONTENT, None),
        Ok(env) => env,
    };
    // Only the identifier derived from the authenticated content is marked seen, never
    // the plaintext header identifier (which a relay can rewrite).
    let authenticated_id = ack::packet_id_for(&env.ack_secret);
    if let Err(reason) = check_envelope(q, packet, &env, now)? {
        return reject_authenticated(q, limiter, packet, o, now, reason, Some(authenticated_id));
    }
    let from_me = o.row.contact_fp == *my_fp;
    let text = match (&env.body, from_me) {
        // My own card relayed by a contact that dropped this device.
        (Body::CardUpdate(card), false) if card.devices.root.fingerprint() == *my_fp => {
            return accept_own_card(q, limiter, packet, o, &env, card, device, now, rng);
        }
        (Body::CardUpdate(card), false) => {
            return accept_card_update(q, limiter, packet, o, &env, card, device, now, rng);
        }
        // My own card circulates through `SyncDevices`, never through `CardUpdate`.
        (Body::CardUpdate(_), true) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, R_UNEXPECTED, id);
        }
        (Body::Text(t), false) => t.clone(),
        // My devices do not exchange texts with each other: a text coming from me
        // is unexpected (copies go through `SyncSent`).
        (Body::Text(_), true) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, R_UNEXPECTED, id);
        }
        (_, false) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, sync::R_NOT_MINE, id);
        }
        (_, true) => {
            return accept_sync(q, limiter, packet, o, &env, device, admin, my_fp, now, rng);
        }
    };
    let (row, new_prekeys, first_contact) = commit_session(q, o, now)?;
    // Before `insert_message` (unique packet identifier).
    q.mark_seen(packet.id, now)?;
    let message_id = MessageId::incoming(&row.contact_fp, &env.message_id);
    let inserted = q.insert_message(
        row.contact_fp,
        Direction::In,
        &text,
        MessageStatus::Delivered,
        now,
        message_id,
    )?;
    // Packet → message: found again through the emitted ack (`delete_contact`).
    q.record_inbound(packet.id, message_id)?;
    route::record(q, packet.id, RouteStep::Opened, now, None)?;
    if inserted {
        log(
            q,
            now,
            Some(packet.id),
            &TransparencyEvent::PacketOpened {
                packet_id: packet.id,
                sender: row.contact_fp,
                transport: transport.to_owned(),
                first_contact,
            },
        )?;
    } else {
        log_limited(
            q,
            limiter,
            now,
            Some(packet.id),
            &TransparencyEvent::DuplicateIgnored {
                packet_id: packet.id,
            },
        )?;
    }
    let ack = emit_ack(q, packet, env.ack_secret, now, rng)?;
    let alias = Core::alias_in(q, row.contact_fp)?;
    if !inserted {
        return Ok((ReceiveOutcome::Duplicate, new_prekeys));
    }
    Ok((
        ReceiveOutcome::Message {
            from: row.contact_fp,
            alias,
            text,
            ack,
        },
        new_prekeys,
    ))
}

/// New card from a contact, authenticated by a session with one of its
/// devices (spec §3.2). Verified without writing anything (`verify_card_update`);
/// refusal: quarantine, ratchet kept. Accepted: the session is written, then
/// the card replaced and the sessions of removed devices deleted (including
/// the sender's if it is removed), in the
/// receive transaction. A card with the same root already known or older
/// (superseded): duplicate, acked; other root or other fingerprint: refusal.
///
/// New devices of the contact: my current card is sent to them
/// (`sync::send_own_card`, crossed linkings).
#[allow(clippy::too_many_arguments)]
fn accept_card_update(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    card: &ContactCard,
    device: &DeviceKeys,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let fp = o.row.contact_fp;
    let id = Some(ack::packet_id_for(&env.ack_secret));
    let Some(current) = q.get_contact(fp)? else {
        return reject_authenticated(q, limiter, packet, o, now, contacts::R_CARD_REFUSED, id);
    };
    let verified = match contacts::verify_card_update(q, &current, card)? {
        Err(reason) => {
            return reject_authenticated(q, limiter, packet, o, now, reason, id);
        }
        Ok(contacts::CardUpdate::Superseded) => None,
        Ok(contacts::CardUpdate::Newer(v)) => Some(v),
    };
    let (_, new_prekeys, _) = commit_session(q, o, now)?;
    q.mark_seen(packet.id, now)?;
    q.record_inbound(packet.id, MessageId::incoming(&fp, &env.message_id))?;
    let Some(verified) = verified else {
        // Card already known or superseded: acked so that the sender
        // stops resending it, nothing is written.
        log_limited(
            q,
            limiter,
            now,
            Some(packet.id),
            &TransparencyEvent::DuplicateIgnored {
                packet_id: packet.id,
            },
        )?;
        emit_ack(q, packet, env.ack_secret, now, rng)?;
        return Ok((ReceiveOutcome::Duplicate, new_prekeys));
    };
    let (added, removed) =
        contacts::apply_card_update(q, device, &current, card, verified, now, rng)?;
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::ContactCardUpdated {
            contact: fp,
            alias: current.alias.clone(),
            added: u32::try_from(added.len()).unwrap_or(u32::MAX),
            removed,
        },
    )?;
    emit_ack(q, packet, env.ack_secret, now, rng)?;
    sync::send_own_card(q, device, fp, &added, now, rng)?;
    let alias = Core::alias_in(q, fp)?;
    Ok((ReceiveOutcome::CardUpdated { from: fp, alias }, new_prekeys))
}

/// A card of my own identity relayed by a contact (`sync::notify_revoked` on
/// its side): a valid card whose newer list no longer contains this device
/// removes it (`removed.rs`); any other valid card (older, already known,
/// containing me) is acked without effect; an invalid one is quarantined.
#[allow(clippy::too_many_arguments)]
fn accept_own_card(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    card: &ContactCard,
    device: &DeviceKeys,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let fp = o.row.contact_fp;
    if card.verify().is_err() {
        let id = Some(ack::packet_id_for(&env.ack_secret));
        return reject_authenticated(q, limiter, packet, o, now, contacts::R_CARD_REFUSED, id);
    }
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    let removal = removed::is_removal(&own.list, &device.public(), card);
    let (_, new_prekeys, _) = commit_session(q, o, now)?;
    q.mark_seen(packet.id, now)?;
    q.record_inbound(packet.id, MessageId::incoming(&fp, &env.message_id))?;
    if removal && removed::enter(q, device, card, now, rng)? {
        emit_ack(q, packet, env.ack_secret, now, rng)?;
        return Ok((ReceiveOutcome::Removed, new_prekeys));
    }
    log_limited(
        q,
        limiter,
        now,
        Some(packet.id),
        &TransparencyEvent::DuplicateIgnored {
            packet_id: packet.id,
        },
    )?;
    emit_ack(q, packet, env.ack_secret, now, rng)?;
    Ok((ReceiveOutcome::Duplicate, new_prekeys))
}

/// Authenticated synchronization coming from one of my devices: applied with
/// the checks of the local operation (refusal: quarantine, ratchet kept),
/// only once per envelope identifier (`inbound` table, identifier
/// derived from my fingerprint). Acked like a message. `RemoveMe` is
/// handled once the session is written, so that the removed sender's
/// `SyncDevices` is sealed on its current state (`remove.rs`).
#[allow(clippy::too_many_arguments)]
fn accept_sync(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    device: &DeviceKeys,
    admin: Option<(&RootIdentity, &PrekeySecrets)>,
    my_fp: &Fingerprint,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    // The sending device must be in my current list (not just
    // have kept a session from before its removal).
    let listed = OwnDevices::read(q)?.is_some_and(|own| {
        own.list
            .certs
            .iter()
            .any(|c| c.device.id() == o.row.contact_device)
    });
    if !listed {
        let id = Some(ack::packet_id_for(&env.ack_secret));
        return reject_authenticated(q, limiter, packet, o, now, sync::R_NOT_MINE, id);
    }
    let sync_id = MessageId::incoming(my_fp, &env.message_id);
    // My list before applying, to log its change.
    let before = OwnDevices::read(q)?.map(|own| own.list);
    let already = q.inbound_has_message(sync_id)?;
    let mut kind = if already {
        None
    } else {
        match sync::apply(q, device, o.row.contact_device, env, now, rng)? {
            Ok(kind) => kind,
            Err(reason) => {
                let id = Some(ack::packet_id_for(&env.ack_secret));
                return reject_authenticated(q, limiter, packet, o, now, reason, id);
            }
        }
    };
    let sender = o.row.contact_device;
    let (_, new_prekeys, _) = commit_session(q, o, now)?;
    if !already
        && env.body == Body::RemoveMe
        && remove::on_remove_me(q, device, admin, sender, Some(packet.id), now, rng)?
    {
        kind = Some(SyncKind::Devices);
    }
    let mut devices_change = None;
    if kind == Some(SyncKind::Devices) {
        // The new list may remove the sending device: its session,
        // which `commit_session` has just rewritten, disappears too.
        if let Some(own) = OwnDevices::read(q)? {
            sync::purge_removed_own_sessions(q, &own.list)?;
            devices_change = before.map(|old| device_diff(&old, &own.list));
        }
    }
    q.mark_seen(packet.id, now)?;
    q.record_inbound(packet.id, sync_id)?;
    route::record(q, packet.id, RouteStep::Opened, now, None)?;
    match kind {
        Some(kind) => log(
            q,
            now,
            Some(packet.id),
            &TransparencyEvent::SyncApplied { kind },
        )?,
        None => log_limited(
            q,
            limiter,
            now,
            Some(packet.id),
            &TransparencyEvent::DuplicateIgnored {
                packet_id: packet.id,
            },
        )?,
    }
    if kind == Some(SyncKind::Admin) {
        log(q, now, Some(packet.id), &TransparencyEvent::AdminReceived)?;
    }
    if let Some((added, removed)) = devices_change.filter(|c| *c != (0, 0)) {
        // Security proof, like a link seen from the admin.
        log(
            q,
            now,
            Some(packet.id),
            &TransparencyEvent::OwnDevicesUpdated { added, removed },
        )?;
    }
    emit_ack(q, packet, env.ack_secret, now, rng)?;
    let outcome = match kind {
        Some(kind) => ReceiveOutcome::Synced { kind },
        None => ReceiveOutcome::Duplicate,
    };
    Ok((outcome, new_prekeys))
}

/// Number of devices added and removed between two of my lists.
fn device_diff(old: &DeviceList, new: &DeviceList) -> (u32, u32) {
    let count = |from: &DeviceList, other: &DeviceList| {
        let n = from
            .certs
            .iter()
            .filter(|c| !other.certs.iter().any(|o| o.device.id() == c.device.id()))
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    };
    (count(new, old), count(old, new))
}

/// Records the session that authenticated the message: new session
/// (key packets consumed, excess sessions deleted) or advanced state.
/// Returns the written row, the new key-packet secrets and
/// "first message of a session".
fn commit_session(
    q: &impl Queries,
    o: Opened,
    now: u64,
) -> Result<(SessionRow, Option<PrekeySecrets>, bool)> {
    let Opened {
        mut row,
        ratchet,
        new_session,
        first_contact,
        ..
    } = o;
    let new_prekeys = match new_session {
        Some(pk) => {
            prune_sessions(q, &row)?;
            q.put_meta(META_PREKEYS, &pk)?;
            log(
                q,
                now,
                None,
                &TransparencyEvent::SessionEstablished {
                    contact: row.contact_fp,
                    device: row.contact_device,
                    initiator: false,
                    post_quantum: true,
                },
            )?;
            Some(pk)
        }
        None => None,
    };
    row.state = ser_state(&ratchet)?;
    row.pending_initial = None;
    row.last_rx = now;
    q.put_session(&row)?;
    Ok((row, new_prekeys, first_contact))
}

/// Receipt ack of the packet, queued for sending. In the message's
/// mailbox: answering elsewhere would link the two directions of the
/// conversation, and the nodes that keep the message would not see it.
fn emit_ack(
    q: &impl Queries,
    packet: &Packet,
    ack_secret: [u8; 16],
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Packet> {
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::AckEmitted {
            for_packet: packet.id,
        },
    )?;
    let mut ack = Packet::ack(packet, ack_secret, now, rng);
    // Same granularity as sealed messages.
    ack.expires_at = crate::envelope::sealed_expiry(now);
    q.outbox_put(
        ack.id,
        &ack.encode(),
        ack.kind,
        u64::from(ack.expires_at),
        now,
    )?;
    Ok(ack)
}

/// Checks of an authenticated content: identifier bound to the ack secret,
/// timestamp freshness, identifier not already used by one of my messages.
fn check_envelope(
    q: &impl Queries,
    packet: &Packet,
    env: &Envelope,
    now: u64,
) -> Result<core::result::Result<(), &'static str>> {
    if !ack::verify(&packet.id, &env.ack_secret) {
        return Ok(Err(R_ID_MISMATCH));
    }
    if env.sent_at.saturating_add(MAX_AGE_SECS) < now
        || env.sent_at > now.saturating_add(MAX_FUTURE_SECS)
    {
        return Ok(Err(R_STALE));
    }
    if q.is_my_packet(packet.id)? {
        return Ok(Err(R_ID_REUSED));
    }
    Ok(Ok(()))
}

/// Authenticated content but refused. The ratchet advanced: this state is kept
/// (an existing session is updated) and the message is
/// quarantined, never "retried later". A session that this packet
/// was opening is not created.
fn reject_authenticated(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    now: u64,
    reason: &'static str,
    seen: Option<PacketId>,
) -> Result<RxOut> {
    if o.new_session.is_none() {
        let mut row = o.row;
        row.state = ser_state(&o.ratchet)?;
        q.put_session(&row)?;
    }
    if let Some(id) = seen {
        q.mark_seen(id, now)?;
    }
    quarantine(q, limiter, packet, now, reason)
}

/// Keeps at most `MAX_SESSIONS_PER_DEVICE` sessions with the device of `new`,
/// counting `new`: first deletes those without recent receipt.
fn prune_sessions(q: &impl Queries, new: &SessionRow) -> Result<()> {
    let mut others: Vec<SessionRow> = q
        .sessions_for(new.contact_fp, new.contact_device)?
        .into_iter()
        .filter(|s| s.session_id != new.session_id)
        .collect();
    others.sort_by_key(|s| (s.last_rx, s.created_at));
    while others.len() >= MAX_SESSIONS_PER_DEVICE {
        let oldest = others.remove(0);
        q.delete_session(oldest.contact_fp, oldest.contact_device, &oldest.session_id)?;
    }
    Ok(())
}
