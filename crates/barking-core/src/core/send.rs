//! Sending: encrypting a content for each device of a contact, or
//! for each of my other devices.

use rand_core::CryptoRng;

use super::{
    Core, OwnDevices, de_init, de_state, load_card, log, ser_init, ser_state, session_ad,
    session_id, sync,
};
use crate::envelope::{self, Body, Envelope, MAX_TEXT_LEN};
use crate::handshake::{PrekeyBundle, pqxdh};
use crate::identity::{DeviceId, DeviceKeys, DevicePublic, Fingerprint};
use crate::mailbox::{day_of, intro_mailbox, session_mailbox};
use crate::packet::{Packet, ack};
use crate::ratchet::RatchetState;
use crate::store::{Direction, MessageId, MessageStatus, Queries, SessionRow};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// Recipients of a send.
pub(super) enum Target {
    /// Every device in the contact's card.
    Contact(Fingerprint),
    /// Only these devices of the contact's card (its new
    /// devices, see `sync::send_own_card`).
    ContactDevices(Fingerprint, Vec<DeviceId>),
    /// Each of my other devices (my list, minus this device). The
    /// sessions are filed under my own fingerprint. Used by the
    /// sync contents (`Sync*`, see `sync.rs`).
    OwnDevices,
}

/// Dates of a sealing: `now` (wall clock) sets the mailbox day,
/// the packet expiry, the creation of a session, the send queue and the
/// log; `sent_at` is the only date carried by the envelope. They
/// differ only for a contact sync copy, dated with
/// the contact's clock (which may exceed `now` by a few seconds).
#[derive(Clone, Copy, Debug)]
pub(super) struct SealTime {
    pub now: u64,
    pub sent_at: u64,
}

impl SealTime {
    /// Envelope dated with the wall clock.
    pub fn at(now: u64) -> Self {
        SealTime { now, sent_at: now }
    }
}

fn new_message_id(rng: &mut impl CryptoRng) -> MessageId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    MessageId(id)
}

/// Logs a device skipped by `seal_for` because of its keys (routine
/// class: capped with the other routine entries).
fn log_seal_skipped(
    q: &impl Queries,
    now: u64,
    contact: Fingerprint,
    device: DeviceId,
) -> Result<()> {
    log(
        q,
        now,
        None,
        &TransparencyEvent::SealSkipped { contact, device },
    )
}

/// Encrypts `body` for each reachable device of `target`: one packet per
/// device, all carrying `message_id`. Sessions (new or advanced),
/// send queue and log are written to `q`; it is up to the caller
/// to record the message itself. A device with neither a session nor a key
/// packet is skipped (unreachable for now), as is a device whose
/// public keys make the handshake or the sealing fail
/// (low-order prekey, invalid ML-KEM key, signed by the contact
/// itself): a booby-trapped card must make neither the send to its
/// other devices nor the receipt that reveals it fail. Only
/// storage errors are propagated.
pub(super) fn seal_for(
    q: &impl Queries,
    device: &DeviceKeys,
    target: &Target,
    body: &Body,
    message_id: MessageId,
    time: SealTime,
    rng: &mut impl CryptoRng,
) -> Result<Vec<(Packet, DeviceId)>> {
    let SealTime { now, sent_at } = time;
    let me = device.public();
    let (fp, peers): (Fingerprint, Vec<(DevicePublic, Option<PrekeyBundle>)>) = match target {
        Target::Contact(fp) | Target::ContactDevices(fp, _) => {
            let contact = q.get_contact(*fp)?.ok_or(CoreError::UnknownContact)?;
            // Card verified when added (`add_contact`): each key packet
            // is tied to a device certified by the contact's root.
            let card = load_card(&contact.card)?;
            let peers = card
                .devices
                .certs
                .iter()
                .filter(|c| match target {
                    Target::ContactDevices(_, only) => only.contains(&c.device.id()),
                    _ => true,
                })
                .map(|c| {
                    let bundle = card.bundles.iter().find(|b| b.device == c.device).cloned();
                    (c.device, bundle)
                })
                .collect();
            (*fp, peers)
        }
        Target::OwnDevices => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
            (own.list.root.fingerprint(), own.others(&me))
        }
    };
    let day = day_of(now);
    let mut out = Vec::with_capacity(peers.len());
    for (peer, bundle) in peers {
        let peer_id = peer.id();
        let sessions = q.sessions_for(fp, peer_id)?;
        // Most recently received session, otherwise most recently created.
        let chosen = sessions
            .into_iter()
            .max_by_key(|s| (s.last_rx, s.created_at));
        let (mut row, mut ratchet, init, opened_here) = match chosen {
            Some(row) => {
                let ratchet = de_state(&row.state)?;
                let init = row.pending_initial.as_deref().map(de_init).transpose()?;
                (row, ratchet, init, false)
            }
            None => {
                let Some(bundle) = bundle else {
                    continue;
                };
                let opened = pqxdh::initiate(device, &bundle, rng).and_then(|(secrets, init)| {
                    let ratchet = RatchetState::init_initiator(&secrets.sk, bundle.spk, rng)?;
                    Ok((secrets, init, ratchet))
                });
                let (secrets, init, ratchet) = match opened {
                    Ok(v) => v,
                    Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => return Err(e),
                    Err(_) => {
                        log_seal_skipped(q, now, fp, peer_id)?;
                        continue;
                    }
                };
                let row = SessionRow {
                    contact_device: peer_id,
                    contact_fp: fp,
                    session_id: session_id(&init.ek),
                    state: Vec::new(),
                    mailbox_secret: secrets.mailbox_secret,
                    ad: session_ad(&secrets.ad, &me.id(), &peer_id),
                    pending_initial: Some(ser_init(&init)?),
                    last_rx: 0,
                    created_at: now,
                };
                (row, ratchet, Some(init), true)
            }
        };
        let first_contact = init.is_some();
        let mailbox = if first_contact {
            intro_mailbox(&peer, day)
        } else {
            session_mailbox(&row.mailbox_secret, &peer_id, day)
        };
        let env = Envelope {
            sent_at,
            ack_secret: ack::new_secret(rng),
            message_id: message_id.0,
            body: body.clone(),
        };
        let packet = match envelope::seal(
            &env,
            &mut ratchet,
            &row.ad,
            init.as_ref().map(|i| (i, &peer.dh)),
            mailbox,
            now,
            rng,
        ) {
            Ok(p) => p,
            Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => return Err(e),
            // Nothing was written for this device.
            Err(_) => {
                log_seal_skipped(q, now, fp, peer_id)?;
                continue;
            }
        };
        // Session opened by this sealing: logged once sealed.
        if opened_here {
            log(
                q,
                now,
                None,
                &TransparencyEvent::SessionEstablished {
                    contact: fp,
                    device: peer_id,
                    initiator: true,
                    post_quantum: true,
                },
            )?;
        }
        row.state = ser_state(&ratchet)?;
        q.put_session(&row)?;
        q.outbox_put(
            packet.id,
            &packet.encode(),
            packet.kind,
            u64::from(packet.expires_at),
            now,
        )?;
        let size = u32::try_from(packet.tier.size()).unwrap_or(u32::MAX);
        log(
            q,
            now,
            Some(packet.id),
            &TransparencyEvent::PacketSealed {
                packet_id: packet.id,
                tier: packet.tier,
                size,
                mailbox: packet.mailbox,
                expires_at: packet.expires_at,
                recipient_device: peer_id,
                first_contact,
            },
        )?;
        out.push((packet, peer_id));
    }
    Ok(out)
}

impl Core {
    /// Encrypts `text` for each device in the contact's list; one packet
    /// per reachable device. A single message (a randomly drawn
    /// identifier), one delivery per packet. A `SyncSent` copy, with the same
    /// identifier, is also encrypted for each of my other devices
    /// (packets returned after the contact's). Everything is written in a single
    /// transaction, including the advanced ratchet state, before the packets
    /// are returned.
    pub fn send_text(
        &mut self,
        to: &Fingerprint,
        text: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        self.ensure_linked()?;
        if text.len() > MAX_TEXT_LEN {
            return Err(CoreError::TooLarge);
        }
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let message_id = new_message_id(rng);
            let body = Body::Text(text.to_owned());
            let sealed = seal_for(
                tx,
                device,
                &Target::Contact(*to),
                &body,
                message_id,
                SealTime::at(now),
                rng,
            )?;
            if sealed.is_empty() {
                return Err(CoreError::NoSession);
            }
            // Identifier drawn on 128 bits: a collision is a local failure.
            if !tx.insert_message(
                *to,
                Direction::Out,
                text,
                MessageStatus::Sent,
                now,
                message_id,
            )? {
                return Err(CoreError::Store("duplicate message identifier".into()));
            }
            for (packet, peer_id) in &sealed {
                tx.add_delivery(message_id, packet.id, *peer_id, false)?;
            }
            let copy = Body::SyncSent {
                to: *to,
                text: text.to_owned(),
            };
            let mine = sync::seal_to_own(
                tx,
                device,
                &copy,
                SyncKind::Sent,
                message_id,
                SealTime::at(now),
                rng,
            )?;
            let mut out: Vec<Packet> = sealed.into_iter().map(|(p, _)| p).collect();
            out.extend(mine);
            Ok(out)
        })
    }
}
