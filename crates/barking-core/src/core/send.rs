//! Envoi : chiffrement d'un contenu pour chaque appareil d'un contact, ou
//! pour chacun de mes autres appareils.

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

/// Destinataires d'un envoi.
pub(super) enum Target {
    /// Chaque appareil de la carte du contact.
    Contact(Fingerprint),
    /// Chacun de mes autres appareils (ma liste, sauf cet appareil). Les
    /// sessions sont rangées sous ma propre empreinte. Utilisé par les
    /// contenus de synchronisation (`Sync*`, voir `sync.rs`).
    OwnDevices,
}

/// Dates d'un scellement : `now` (horloge murale) fixe le jour de la boîte,
/// l'expiration du paquet, la création d'une session, la file d'envoi et le
/// journal ; `sent_at` est la seule date portée par l'enveloppe. Elles ne
/// diffèrent que pour une copie de synchronisation de contact, datée de
/// l'horloge du contact (qui peut dépasser `now` de quelques secondes).
#[derive(Clone, Copy, Debug)]
pub(super) struct SealTime {
    pub now: u64,
    pub sent_at: u64,
}

impl SealTime {
    /// Enveloppe datée de l'horloge murale.
    pub fn at(now: u64) -> Self {
        SealTime { now, sent_at: now }
    }
}

fn new_message_id(rng: &mut impl CryptoRng) -> MessageId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    MessageId(id)
}

/// Chiffre `body` pour chaque appareil joignable de `target` : un paquet par
/// appareil, tous porteurs de `message_id`. Sessions (nouvelles ou avancées),
/// file d'envoi et journal sont écrits dans `q` ; c'est à l'appelant
/// d'enregistrer le message lui-même. Un appareil sans session ni paquet de
/// clés est ignoré (injoignable pour l'instant).
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
        Target::Contact(fp) => {
            let contact = q.get_contact(*fp)?.ok_or(CoreError::UnknownContact)?;
            // Carte vérifiée à l'ajout (`add_contact`) : chaque paquet de clés
            // est lié à un appareil certifié par la racine du contact.
            let card = load_card(&contact.card)?;
            let peers = card
                .devices
                .certs
                .iter()
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
        // Session reçue le plus récemment, sinon créée le plus récemment.
        let chosen = sessions
            .into_iter()
            .max_by_key(|s| (s.last_rx, s.created_at));
        let (mut row, mut ratchet, init) = match chosen {
            Some(row) => {
                let ratchet = de_state(&row.state)?;
                let init = row.pending_initial.as_deref().map(de_init).transpose()?;
                (row, ratchet, init)
            }
            None => {
                let Some(bundle) = bundle else {
                    continue;
                };
                let (secrets, init) = pqxdh::initiate(device, &bundle, rng)?;
                let ratchet = RatchetState::init_initiator(&secrets.sk, bundle.spk, rng)?;
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
                (row, ratchet, Some(init))
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
        let packet = envelope::seal(
            &env,
            &mut ratchet,
            &row.ad,
            init.as_ref().map(|i| (i, &peer.dh)),
            mailbox,
            now,
            rng,
        )?;
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
    /// Chiffre `text` pour chaque appareil de la liste du contact ; un paquet
    /// par appareil joignable. Un seul message (un identifiant tiré au
    /// hasard), une livraison par paquet. Une copie `SyncSent`, de même
    /// identifiant, est aussi chiffrée pour chacun de mes autres appareils
    /// (paquets rendus après ceux du contact). Tout est écrit dans une seule
    /// transaction, y compris l'état du ratchet avancé, avant que les paquets
    /// ne soient rendus.
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
            // Identifiant tiré sur 128 bits : une collision est une panne locale.
            if !tx.insert_message(
                *to,
                Direction::Out,
                text,
                MessageStatus::Sent,
                now,
                message_id,
            )? {
                return Err(CoreError::Store("identifiant de message en double".into()));
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
