//! Receiving: bytes coming from outside, never a panic nor an `Err`
//! because of their content. `Err` is reserved for local failures (storage).

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::delivery;
use super::log_limit::{LogLimiter, log_limited};
use super::route::{self, RouteStep};
use super::{
    Core, MAX_AGE_SECS, MAX_FUTURE_SECS, META_PREKEYS, OwnDevices, ReceiveOutcome,
    SEEN_RETENTION_SECS, admin, contacts, de_state, ephemeral, load_card, log, reactions, remove,
    removed, ser_state, session_ad, session_id, sync,
};
use crate::contact::ContactCard;
use crate::content::{ExtContent, MessageRef, UNSEEN_CEILING_SECS, UnknownPolicy};
use crate::envelope::{self, Body, Envelope, Wire, parse_wire};
use crate::handshake::PrekeySecrets;
use crate::handshake::pqxdh::{self, InitialMessage};
use crate::identity::{DeviceKeys, DeviceList, DevicePublic, Fingerprint, RootIdentity};
use crate::mailbox::{day_of, intro_mailbox, session_mailbox};
use crate::packet::{ACK_GRACE_SECS, Kind, Packet, PacketId, ack};
use crate::ratchet::{RatchetMessage, RatchetState};
use crate::store::{Direction, MessageId, MessageInsert, MessageStatus, Queries, SessionRow};
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
pub const R_BLOCKED: &str = "blocked contact";

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
        // A receipt's expiry is checked against the packet it acknowledges
        // (`receive_ack`): nodes keep it until the later of the two, plus
        // `ACK_GRACE_SECS`.
        if packet.kind == Kind::Message && u64::from(packet.expires_at) < now {
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
                        ..
                    } => {
                        self.reload_own_devices()?;
                        self.reload_root()?;
                    }
                    ReceiveOutcome::Synced {
                        kind: SyncKind::Admin,
                        ..
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
        let (outcome, transferred, change) = store.transaction(|tx| {
            // A delivery is always one of my sent packets: a
            // message for a contact, or a sync for one of my
            // devices (without a message row for `SyncContact`/`SyncDevices`).
            if !tx.is_my_packet(acked)? {
                // A superseded reaction packet (no delivery, no state):
                // received, it only leaves the send queue.
                reactions::drop_acked_superseded(tx, acked)?;
                return Ok((ReceiveOutcome::NotForUs, false, None));
            }
            // Nodes keep a receipt until `max(its expiry, the acknowledged
            // packet's) + ACK_GRACE_SECS`: so long it still proves the
            // delivery, even when the recipient's clock was behind and
            // gave the receipt an earlier expiry.
            let own = u64::from(packet.expires_at);
            let acked_expiry = delivery::acked_expiry(tx, acked)?.unwrap_or(own);
            if own.max(acked_expiry).saturating_add(ACK_GRACE_SECS) < now {
                return Ok((ReceiveOutcome::Expired, false, None));
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
                return Ok((ReceiveOutcome::Duplicate, false, None));
            }
            // The ack of one of my devices (`SyncSent` copy, `own`
            // delivery) does not make the message `Received`: only that of a
            // contact's device counts.
            let change = match tx.mark_delivered_by_packet(acked, now)? {
                Some(message_id) => {
                    delivery::recompute_message_status(tx, message_id)?;
                    delivery::change_of(tx, message_id)?
                }
                None => None,
            };
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
                change,
            ))
        })?;
        self.note_changes(change);
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
                return Ok((repeat_outcome(tx, packet.id)?, None));
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

/// What a repeat of the received packet `packet_id` is: `DuplicateMessage`
/// when the message it carried (text, reply or update placeholder) is still
/// a row of the conversation, `Duplicate` otherwise (a reaction, a sync, a
/// card, content set aside, or a message deleted since).
fn repeat_outcome(q: &impl Queries, packet_id: PacketId) -> Result<ReceiveOutcome> {
    let shown = q
        .message_by_packet(packet_id)?
        .is_some_and(|m| m.direction == Direction::In);
    Ok(if shown {
        ReceiveOutcome::DuplicateMessage
    } else {
        ReceiveOutcome::Duplicate
    })
}

/// Days for which a mailbox (session or introduction) is accepted at
/// receive time: the whole freshness window, from the day of `now - MAX_AGE_SECS`
/// to the day after `now`. A packet's mailbox is fixed at the day of its
/// sealing; a packet delivered late (sealed offline, deposited within its
/// lifetime) must remain readable. `watched_mailboxes` (poll) covers
/// `MAX_POLL_BACK_DAYS` back to the next day, a superset of this window.
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
        // A blocked contact's text: dropped like a refused packet (ratchet
        // kept, marked seen, no ack), so its sender sees it undelivered.
        (Body::Text(_), false) if q.block_state(o.row.contact_fp)?.drops(env.sent_at) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, R_BLOCKED, id);
        }
        (Body::Text(t), false) => t.clone(),
        // My devices do not exchange texts with each other: a text coming from me
        // is unexpected (copies go through `SyncSent`).
        (Body::Text(_), true) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, R_UNEXPECTED, id);
        }
        // Extensible contents: replies, ephemeral messages and reactions,
        // and kinds this version does not know (`accept_ext`).
        (
            Body::Ext {
                kind,
                unknown,
                data,
            },
            _,
        ) => {
            let ext = Ext {
                kind: *kind,
                unknown: *unknown,
                data,
            };
            return accept_ext(
                q, limiter, packet, o, &env, &ext, from_me, device, admin, my_fp, transport, now,
                rng,
            );
        }
        (_, false) => {
            let id = Some(authenticated_id);
            return reject_authenticated(q, limiter, packet, o, now, sync::R_NOT_MINE, id);
        }
        (_, true) => {
            return accept_sync(q, limiter, packet, o, &env, device, admin, my_fp, now, rng);
        }
    };
    record_message(
        q, limiter, packet, o, &env, text, None, None, transport, now, rng,
    )
}

/// A text (or a reply, `reply_ref`, or an ephemeral, `ttl_secs`) from a
/// contact, once accepted: session written, message recorded, ack emitted.
/// An ephemeral is not seen yet: it is erased `UNSEEN_CEILING_SECS` after
/// `now` unless one of my devices shows it first.
#[allow(clippy::too_many_arguments)]
fn record_message(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    text: String,
    reply_ref: Option<MessageRef>,
    ttl_secs: Option<u32>,
    transport: &str,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let (row, new_prekeys, first_contact) = commit_session(q, o, now)?;
    // Before `insert_message` (unique packet identifier).
    q.mark_seen(packet.id, now)?;
    let message_id = MessageId::incoming(&row.contact_fp, &env.message_id);
    // A message already received once (`inbound`, never purged) stays as
    // it is: a resend or a retry of it, even one I deleted since, is a
    // duplicate.
    let inserted = !q.inbound_has_message(message_id)?
        && q.insert_message_row(&MessageInsert {
            contact_fp: row.contact_fp,
            direction: Direction::In,
            body: text.clone(),
            status: MessageStatus::Received,
            at: now,
            message_id,
            wire_id: Some(env.message_id),
            reply_to: reply_ref.map(|r| r.resolve(false, &row.contact_fp)),
            reply_ref,
            placeholder: false,
            ttl_secs,
            seen_at: None,
            expire_at: ttl_secs.map(|_| now.saturating_add(UNSEEN_CEILING_SECS)),
        })?;
    // Packet → message: found again through the emitted ack (`delete_contact`).
    q.record_inbound(packet.id, message_id, row.contact_fp)?;
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
        return Ok((repeat_outcome(q, packet.id)?, new_prekeys));
    }
    // An ephemeral born due (an earlier "seen" from another of my devices,
    // `pending_seen`, already ran out): never openable, so never notified.
    // Erased and tombstoned at once, as the sweep would; acked all the same.
    if ttl_secs.is_some() && ephemeral::erase_if_due(q, message_id, now)? {
        return Ok((ReceiveOutcome::Ignored, new_prekeys));
    }
    Ok((
        ReceiveOutcome::Message {
            from: row.contact_fp,
            alias,
            text,
            ack,
            ephemeral: ttl_secs.is_some(),
        },
        new_prekeys,
    ))
}

/// The content of a `Body::Ext`, as received.
struct Ext<'a> {
    kind: u16,
    unknown: UnknownPolicy,
    data: &'a [u8],
}

/// `Body::Ext` authenticated by a session. Sender x kind:
///
/// | Sender | `Reply` / `Message` / `Reaction` | `SyncReply` / `SyncMessage` / `SyncReaction` / `SyncDelete` / `SyncSeen` / `SyncInvite` | Unknown |
/// |---|---|---|---|
/// | A contact | accepted | `R_NOT_MINE` | `unknown` policy |
/// | One of my devices | `R_UNEXPECTED` | the sync path | `unknown` policy |
///
/// Every `Ext` from my own fingerprint first requires the sending device to
/// be in my current list. A `Reply` or a `Message` is recorded like a text,
/// a `Reaction` applied as the contact's (`accept_reaction`); `SyncReply`,
/// `SyncMessage`, `SyncReaction`, `SyncDelete`, `SyncSeen` and `SyncInvite`
/// go through the sync path
/// (`accept_sync`).
/// An unknown kind is acknowledged like a message (the sender stops
/// resending it) and, per its `unknown` policy, ignored or shown as a
/// placeholder asking for an update (never for my own devices: they would
/// show it twice).
#[allow(clippy::too_many_arguments)]
fn accept_ext(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    ext: &Ext<'_>,
    from_me: bool,
    device: &DeviceKeys,
    admin: Option<(&RootIdentity, &PrekeySecrets)>,
    my_fp: &Fingerprint,
    transport: &str,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let id = Some(ack::packet_id_for(&env.ack_secret));
    if from_me && !sync::sender_is_listed(q, o.row.contact_device)? {
        return reject_authenticated(q, limiter, packet, o, now, sync::R_NOT_MINE, id);
    }
    let content = match ExtContent::decode(ext.kind, ext.data) {
        Ok(content) => content,
        Err(_) => return reject_authenticated(q, limiter, packet, o, now, R_BAD_CONTENT, id),
    };
    let Some(content) = content else {
        return accept_unknown(q, limiter, packet, o, env, ext, from_me, now, rng);
    };
    let reason = match (content, from_me) {
        (ExtContent::Reply { text, reply_to }, false) => {
            // Blocked: dropped like a text (ratchet kept, no ack).
            if q.block_state(o.row.contact_fp)?.drops(env.sent_at) {
                return reject_authenticated(q, limiter, packet, o, now, R_BLOCKED, id);
            }
            return record_message(
                q,
                limiter,
                packet,
                o,
                env,
                text,
                Some(reply_to),
                None,
                transport,
                now,
                rng,
            );
        }
        (
            ExtContent::Message {
                text,
                reply_to,
                ttl_secs,
            },
            false,
        ) => {
            // Blocked: dropped like a text (ratchet kept, no ack).
            if q.block_state(o.row.contact_fp)?.drops(env.sent_at) {
                return reject_authenticated(q, limiter, packet, o, now, R_BLOCKED, id);
            }
            return record_message(
                q, limiter, packet, o, env, text, reply_to, ttl_secs, transport, now, rng,
            );
        }
        (ExtContent::Reaction { target, emojis }, false) => {
            // Blocked: dropped like a text (ratchet kept, no ack).
            if q.block_state(o.row.contact_fp)?.drops(env.sent_at) {
                return reject_authenticated(q, limiter, packet, o, now, R_BLOCKED, id);
            }
            return accept_reaction(
                q, limiter, packet, o, env, target, emojis, transport, now, rng,
            );
        }
        (
            ExtContent::SyncReply { .. }
            | ExtContent::SyncMessage { .. }
            | ExtContent::SyncReaction { .. }
            | ExtContent::SyncDelete { .. }
            | ExtContent::SyncSeen { .. }
            | ExtContent::SyncInvite { .. },
            true,
        ) => {
            return accept_sync(q, limiter, packet, o, env, device, admin, my_fp, now, rng);
        }
        (
            ExtContent::SyncReply { .. }
            | ExtContent::SyncMessage { .. }
            | ExtContent::SyncReaction { .. }
            | ExtContent::SyncDelete { .. }
            | ExtContent::SyncSeen { .. }
            | ExtContent::SyncInvite { .. },
            false,
        ) => sync::R_NOT_MINE,
        _ => R_UNEXPECTED,
    };
    reject_authenticated(q, limiter, packet, o, now, reason, id)
}

/// A contact's `Reaction`, once accepted: session written, packet marked
/// seen, the set applied as the contact's (`reactions::apply`), ack emitted.
/// Deduplicated by envelope identifier (`inbound`), like a text. A target
/// deleted here or of another conversation is ignored: nothing written,
/// acked, `Ignored` (nothing to notify).
#[allow(clippy::too_many_arguments)]
fn accept_reaction(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    target: MessageRef,
    emojis: Vec<String>,
    transport: &str,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let (row, new_prekeys, first_contact) = commit_session(q, o, now)?;
    q.mark_seen(packet.id, now)?;
    let from = row.contact_fp;
    let received = MessageId::incoming(&from, &env.message_id);
    let already = q.inbound_has_message(received)?;
    q.record_inbound(packet.id, received, from)?;
    route::record(q, packet.id, RouteStep::Opened, now, None)?;
    if already {
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
    }
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::PacketOpened {
            packet_id: packet.id,
            sender: from,
            transport: transport.to_owned(),
            first_contact,
        },
    )?;
    let target = target.resolve(false, &from);
    let applied = reactions::apply(q, from, from.0, target, emojis, env.sent_at, env.message_id)?;
    emit_ack(q, packet, env.ack_secret, now, rng)?;
    let Some(added) = applied else {
        return Ok((ReceiveOutcome::Ignored, new_prekeys));
    };
    let alias = Core::alias_in(q, from)?;
    Ok((
        ReceiveOutcome::Reaction {
            from,
            alias,
            target,
            added,
        },
        new_prekeys,
    ))
}

/// Unknown kind of `Body::Ext`: see `accept_ext`.
#[allow(clippy::too_many_arguments)]
fn accept_unknown(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    packet: &Packet,
    o: Opened,
    env: &Envelope,
    ext: &Ext<'_>,
    from_me: bool,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let id = Some(ack::packet_id_for(&env.ack_secret));
    // A blocked contact's content is dropped like its texts.
    if !from_me && q.block_state(o.row.contact_fp)?.drops(env.sent_at) {
        return reject_authenticated(q, limiter, packet, o, now, R_BLOCKED, id);
    }
    let (row, new_prekeys, _) = commit_session(q, o, now)?;
    q.mark_seen(packet.id, now)?;
    // For my own devices `row.contact_fp` is my fingerprint, as in `accept_sync`.
    let message_id = MessageId::incoming(&row.contact_fp, &env.message_id);
    let already = q.inbound_has_message(message_id)?;
    q.record_inbound(packet.id, message_id, row.contact_fp)?;
    route::record(q, packet.id, RouteStep::Opened, now, None)?;
    if already {
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
        return Ok((repeat_outcome(q, packet.id)?, new_prekeys));
    }
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::UnknownContent {
            packet_id: packet.id,
            kind: ext.kind,
        },
    )?;
    let show = ext.unknown == UnknownPolicy::ShowUpdate && !from_me;
    let inserted = show
        && q.insert_message_row(&MessageInsert {
            contact_fp: row.contact_fp,
            direction: Direction::In,
            body: String::new(),
            status: MessageStatus::Received,
            at: now,
            message_id,
            wire_id: Some(env.message_id),
            reply_to: None,
            reply_ref: None,
            placeholder: true,
            ttl_secs: None,
            seen_at: None,
            expire_at: None,
        })?;
    emit_ack(q, packet, env.ack_secret, now, rng)?;
    if !inserted {
        // Ignored, or a placeholder deleted since (tombstone).
        let outcome = if show {
            ReceiveOutcome::Duplicate
        } else {
            ReceiveOutcome::Ignored
        };
        return Ok((outcome, new_prekeys));
    }
    let alias = Core::alias_in(q, row.contact_fp)?;
    Ok((
        ReceiveOutcome::NeedsUpdate {
            from: row.contact_fp,
            alias,
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
    q.record_inbound(packet.id, MessageId::incoming(&fp, &env.message_id), fp)?;
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
    q.record_inbound(packet.id, MessageId::incoming(&fp, &env.message_id), fp)?;
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
    if !sync::sender_is_listed(q, o.row.contact_device)? {
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
    q.record_inbound(packet.id, sync_id, *my_fp)?;
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
        Some(kind) => ReceiveOutcome::Synced {
            kind,
            contact: match &env.body {
                body if matches!(kind, SyncKind::Sent | SyncKind::Reaction) => sync::sent_to(body),
                _ => None,
            },
        },
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
        Some(packet.id),
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
