//! Réception : octets venus de l'extérieur, jamais de panique ni d'`Err` à
//! cause de leur contenu. `Err` est réservé aux échecs locaux (stockage).

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{
    Core, MAX_AGE_SECS, MAX_FUTURE_SECS, META_PREKEYS, ReceiveOutcome, SEEN_RETENTION_SECS,
    de_state, load_card, log, ser_state, session_ad, session_id,
};
use crate::envelope::{self, Body, Envelope, Wire, parse_wire};
use crate::handshake::PrekeySecrets;
use crate::handshake::pqxdh::{self, InitialMessage};
use crate::identity::{DeviceKeys, DevicePublic, Fingerprint};
use crate::mailbox::{day_of, intro_mailbox, session_mailbox};
use crate::packet::{Kind, Packet, PacketId, ack};
use crate::ratchet::{RatchetMessage, RatchetState};
use crate::store::{Direction, MessageStatus, Queries, SessionRow};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

// Raisons de quarantaine : textes fixes, jamais de contenu ni de clé.
const R_UNREADABLE: &str = "contenu illisible";
const R_UNEXPECTED: &str = "contenu inattendu pour cette boîte aux lettres";
const R_UNDECRYPTABLE: &str = "déchiffrement impossible";
const R_UNKNOWN_SENDER: &str = "expéditeur inconnu";
const R_AMBIGUOUS_SENDER: &str = "expéditeur ambigu";
const R_HANDSHAKE: &str = "ouverture de session impossible";
const R_BAD_CONTENT: &str = "contenu authentifié mais mal formé";
const R_ID_MISMATCH: &str = "identifiant de paquet incohérent";
const R_STALE: &str = "message trop ancien ou daté du futur";
const R_ID_REUSED: &str = "identifiant de paquet déjà utilisé";

/// Nombre maximal de sessions gardées par appareil distant.
const MAX_SESSIONS_PER_DEVICE: usize = 2;

/// Sortie d'une transaction de réception : le résultat, et les nouveaux
/// secrets de paquets de clés si une session a été ouverte (appliqués en
/// mémoire seulement après le commit).
type RxOut = (ReceiveOutcome, Option<PrekeySecrets>);

/// Session qui a authentifié le message.
struct Opened {
    row: SessionRow,
    ratchet: RatchetState,
    pt: Zeroizing<Vec<u8>>,
    /// Session ouverte par ce paquet, pas encore stockée.
    new_session: Option<PrekeySecrets>,
    first_contact: bool,
}

impl Core {
    /// Traite un paquet reçu par `transport` (texte libre noté au journal).
    pub fn receive(
        &mut self,
        bytes: &[u8],
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        let Ok(packet) = Packet::decode(bytes) else {
            return Ok(ReceiveOutcome::NotForUs);
        };
        if u64::from(packet.expires_at) < now {
            return Ok(ReceiveOutcome::Expired);
        }
        match packet.kind {
            Kind::Ack => self.receive_ack(&packet, now),
            Kind::Message => self.receive_message(&packet, transport, now, rng),
        }
    }

    fn receive_ack(&mut self, packet: &Packet, now: u64) -> Result<ReceiveOutcome> {
        // Charge d'accusé : exactement `acked.id(16) || secret(16)`.
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
        self.store.transaction(|tx| {
            let Some(msg) = tx.message_by_packet(acked)? else {
                return Ok(ReceiveOutcome::NotForUs);
            };
            if msg.direction != Direction::Out {
                return Ok(ReceiveOutcome::NotForUs);
            }
            if msg.status == MessageStatus::Delivered {
                log(
                    tx,
                    now,
                    Some(packet.id),
                    &TransparencyEvent::DuplicateIgnored {
                        packet_id: packet.id,
                    },
                )?;
                return Ok(ReceiveOutcome::Duplicate);
            }
            tx.set_status_by_packet(acked, MessageStatus::Delivered)?;
            tx.outbox_remove(acked)?;
            log(
                tx,
                now,
                Some(acked),
                &TransparencyEvent::AckVerified { for_packet: acked },
            )?;
            Ok(ReceiveOutcome::AckReceived { packet_id: acked })
        })
    }

    fn receive_message(
        &mut self,
        packet: &Packet,
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        let Core {
            store,
            device,
            prekeys,
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
            // Vérifié sans être enregistré : seul un paquet authentifié est
            // marqué vu, sinon un faux paquet portant le même identifiant
            // ferait passer l'original pour un doublon.
            if tx.is_seen(packet.id)? {
                log(
                    tx,
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
                    // Les sessions ayant reçu le plus récemment d'abord.
                    matching.sort_by_key(|s| core::cmp::Reverse((s.last_rx, s.created_at)));
                    open_normal(matching, &msg, now)?
                }
                Ok(_) => Err(R_UNEXPECTED),
            };
            match opened {
                Err(reason) => quarantine(tx, packet, now, reason),
                Ok(o) => accept(tx, packet, o, transport, now, rng),
            }
        })?;
        if let Some(p) = new_prekeys {
            *prekeys = p;
        }
        Ok(outcome)
    }
}

/// Jours dont une boîte (session ou introduction) est acceptée à la
/// réception : toute la fenêtre de fraîcheur, du jour de `now - MAX_AGE_SECS`
/// au lendemain de `now`. La boîte d'un paquet est fixée au jour de son
/// scellement ; un paquet livré en retard (file d'envoi de 7 jours) doit
/// rester lisible. `watched_mailboxes` (relève) garde trois jours.
fn accepted_days(now: u64) -> Vec<u32> {
    let first = day_of(now.saturating_sub(MAX_AGE_SECS));
    let last = day_of(now).saturating_add(1);
    (first..=last).collect()
}

/// Copie des secrets de paquets de clés (aller-retour par la forme stockée) :
/// `respond` la modifie, et l'original ne change qu'après le commit.
fn copy_prekeys(p: &PrekeySecrets) -> Result<PrekeySecrets> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(p).map_err(|_| CoreError::Store("sérialisation".into()))?,
    );
    postcard::from_bytes(&bytes).map_err(|_| CoreError::Store("sérialisation".into()))
}

/// Appareil d'un contact connu dont la clé X25519 d'identité est `ik`.
///
/// Exige une correspondance unique : si deux contacts revendiquaient la même
/// clé (`add_contact` l'interdit), l'expéditeur serait ambigu et le paquet refusé
/// plutôt qu'attribué au premier trouvé.
fn find_sender(
    q: &impl Queries,
    ik: &[u8; 32],
) -> Result<core::result::Result<(Fingerprint, DevicePublic), &'static str>> {
    let mut found = None;
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

/// `Wire::Initial` : ouvre le message initial scellé, identifie l'expéditeur,
/// puis déchiffre dans la session existante (Initial renvoyé) ou dans une
/// nouvelle session répondeur. Rien n'est écrit ici.
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
    // Pas de demandes de contact en v0 : seul un appareil d'un contact connu
    // peut ouvrir une session.
    let (contact_fp, peer) = match find_sender(q, &init.ik)? {
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
        let mut ratchet = de_state(&row.state)?;
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
/// Nouvelle session répondeur sur une copie des secrets de paquets de clés.
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

/// `Wire::Normal` : essaie chaque session dont une boîte candidate correspond.
fn open_normal(
    candidates: Vec<SessionRow>,
    msg: &RatchetMessage,
    now: u64,
) -> Result<core::result::Result<Opened, &'static str>> {
    for row in candidates {
        let mut ratchet = de_state(&row.state)?;
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

/// Refus sans déchiffrement : aucun état de session ne change.
fn quarantine(q: &impl Queries, packet: &Packet, now: u64, reason: &'static str) -> Result<RxOut> {
    log(
        q,
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

/// Message authentifié par une session : vérifie le contenu, puis enregistre.
fn accept(
    q: &impl Queries,
    packet: &Packet,
    o: Opened,
    transport: &str,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<RxOut> {
    let env = match envelope::decode(&o.pt) {
        // Pas de secret d'accusé authentifié : rien à marquer comme vu.
        Err(_) => return reject_authenticated(q, packet, o, now, R_BAD_CONTENT, None),
        Ok(env) => env,
    };
    // Seul l'identifiant dérivé du contenu authentifié est marqué vu, jamais
    // l'identifiant de l'en-tête en clair (qu'un relais peut réécrire).
    let authenticated_id = ack::packet_id_for(&env.ack_secret);
    if let Err(reason) = check_envelope(q, packet, &env, now)? {
        return reject_authenticated(q, packet, o, now, reason, Some(authenticated_id));
    }
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
    // Avant `insert_message` (identifiant de paquet unique).
    q.mark_seen(packet.id, now)?;
    let Body::Text(text) = env.body;
    q.insert_message(
        row.contact_fp,
        Direction::In,
        &text,
        MessageStatus::Delivered,
        now,
        Some(packet.id),
    )?;
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
    log(
        q,
        now,
        Some(packet.id),
        &TransparencyEvent::AckEmitted {
            for_packet: packet.id,
        },
    )?;
    let alias = Core::alias_in(q, row.contact_fp)?;
    let ack = Packet::ack(packet, env.ack_secret, now, rng);
    q.outbox_put(
        ack.id,
        &ack.encode(),
        ack.kind,
        u64::from(ack.expires_at),
        now,
    )?;
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

/// Contrôles d'un contenu authentifié : identifiant lié au secret d'accusé,
/// fraîcheur de l'horodatage, identifiant pas déjà utilisé par un de mes messages.
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
    if q.message_by_packet(packet.id)?.is_some() {
        return Ok(Err(R_ID_REUSED));
    }
    Ok(Ok(()))
}

/// Contenu authentifié mais refusé. Le ratchet a avancé : on garde cet état
/// (une session existante est mise à jour) et le message est mis en
/// quarantaine, jamais « réessayé plus tard ». Une session que ce paquet
/// ouvrait n'est pas créée.
fn reject_authenticated(
    q: &impl Queries,
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
    quarantine(q, packet, now, reason)
}

/// Garde au plus `MAX_SESSIONS_PER_DEVICE` sessions avec l'appareil de `new`,
/// en comptant `new` : supprime d'abord celles sans réception récente.
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
