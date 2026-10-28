//! Envoi d'un texte vers chaque appareil d'un contact.

use rand_core::CryptoRng;

use super::{Core, de_init, de_state, load_card, log, ser_init, ser_state, session_id};
use crate::envelope::{self, Body, Envelope, MAX_TEXT_LEN};
use crate::handshake::pqxdh;
use crate::identity::Fingerprint;
use crate::mailbox::{day_of, intro_mailbox, session_mailbox};
use crate::packet::{Packet, ack};
use crate::ratchet::RatchetState;
use crate::store::{Direction, MessageStatus, Queries, SessionRow};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

impl Core {
    /// Chiffre `text` pour chaque appareil de la liste du contact ; un paquet
    /// par appareil joignable. Tout est écrit dans une seule transaction, y
    /// compris l'état du ratchet avancé, avant que les paquets ne soient rendus.
    pub fn send_text(
        &mut self,
        to: &Fingerprint,
        text: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Packet>> {
        if text.len() > MAX_TEXT_LEN {
            return Err(CoreError::TooLarge);
        }
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let contact = tx.get_contact(*to)?.ok_or(CoreError::UnknownContact)?;
            // Carte vérifiée à l'ajout (`add_contact`) : chaque paquet de clés est
            // lié à un appareil certifié par la racine du contact.
            let card = load_card(&contact.card)?;
            let day = day_of(now);
            let mut out = Vec::with_capacity(card.devices.certs.len());
            for cert in &card.devices.certs {
                let peer = cert.device;
                let peer_id = peer.id();
                let sessions = tx.sessions_for(peer_id)?;
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
                        let Some(bundle) = card.bundles.iter().find(|b| b.device == peer) else {
                            // Appareil sans paquet de clés : injoignable pour l'instant.
                            continue;
                        };
                        let (secrets, init) = pqxdh::initiate(device, bundle, rng)?;
                        let ratchet = RatchetState::init_initiator(&secrets.sk, bundle.spk, rng)?;
                        let row = SessionRow {
                            contact_device: peer_id,
                            contact_fp: *to,
                            session_id: session_id(&init.ek),
                            state: Vec::new(),
                            mailbox_secret: secrets.mailbox_secret,
                            ad: secrets.ad.clone(),
                            pending_initial: Some(ser_init(&init)?),
                            last_rx: 0,
                            created_at: now,
                        };
                        log(
                            tx,
                            now,
                            None,
                            &TransparencyEvent::SessionEstablished {
                                contact: *to,
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
                    sent_at: now,
                    ack_secret: ack::new_secret(rng),
                    body: Body::Text(text.to_owned()),
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
                tx.put_session(&row)?;
                tx.insert_message(
                    *to,
                    Direction::Out,
                    text,
                    MessageStatus::Sent,
                    now,
                    Some(packet.id),
                )?;
                let size = u32::try_from(packet.tier.size()).unwrap_or(u32::MAX);
                log(
                    tx,
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
                out.push(packet);
            }
            if out.is_empty() {
                return Err(CoreError::NoSession);
            }
            Ok(out)
        })
    }
}
