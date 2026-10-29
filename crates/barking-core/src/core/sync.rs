//! Synchronisation entre mes propres appareils : copies de mes messages
//! envoyés (`SyncSent`), opérations sur les contacts (`SyncContact`) et
//! nouvelle liste d'appareils (`SyncDevices`).
//!
//! Envoi : par les sessions double ratchet avec mes autres appareils
//! (`Target::OwnDevices`), une livraison par paquet pour que leurs accusés
//! vident la file d'envoi. Réception : seulement depuis un de mes appareils
//! (vérifié par l'appelant), avec les mêmes contrôles que l'opération locale.
//! Un contenu refusé est mis en quarantaine, jamais une `Err`.

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

// Raisons de quarantaine : textes fixes.
pub(super) const R_NOT_MINE: &str = "synchronisation d'un appareil qui n'est pas à moi";
pub(super) const R_SYNC_REFUSED: &str = "synchronisation refusée";
pub(super) const R_DEVICES_REFUSED: &str = "liste d'appareils refusée";

/// Scelle `body` pour chacun de mes autres appareils ; chaque paquet est
/// enregistré comme livraison `own` de `message_id` (son accusé ne rend pas
/// le message « livré »). Sans autre appareil, rien n'est fait.
///
/// Un contenu trop volumineux pour un paquet n'est pas envoyé : l'opération
/// locale réussit quand même, et `SyncSkipped` est journalisé. La taille est
/// vérifiée avant `seal_for`, qui écrit déjà sessions et journal.
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

/// Met en file ma nouvelle carte (`CardUpdate`) pour chaque appareil
/// joignable de chacun de mes contacts, une livraison par paquet (sans ligne
/// de message, sous un identifiant neuf par contact). Taille vérifiée avant
/// tout scellement : une carte trop grande pour un paquet (impossible avec le
/// plafond d'appareils) fait échouer l'appel (`TooLarge`) sans rien écrire.
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

/// Met en file ma carte actuelle (`CardUpdate`) pour les seuls appareils
/// `devices` du contact `fp` : ses nouveaux appareils, appris par une mise à
/// jour de sa carte. Ils ont pu être liés avec une copie de ma carte plus
/// ancienne que celle que j'ai envoyée à ses autres appareils (deux liaisons
/// croisées) ; sans cela, ils ne connaîtraient mes nouveaux appareils qu'au
/// prochain changement de ma liste. Une carte déjà connue est un doublon
/// accusé chez eux.
///
/// Sans carte stockée (aucune liaison sur ce compte : mes contacts ont la
/// carte que je leur ai donnée) ou carte trop grande pour un paquet, rien
/// n'est envoyé : la réception ne doit jamais échouer pour autant.
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
    let Some(card) = q.get_meta::<ContactCard>(META_OWN_CARD)? else {
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

/// Met en file l'opération `op` pour chacun de mes autres appareils, sous un
/// identifiant de message neuf (sans ligne de message). `time.sent_at` est
/// la date de l'opération (horloge du contact, voir [`touch`]).
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

/// Met en file l'état stocké du contact `fp` (`SyncOp::Upsert`).
pub(super) fn send_state(
    q: &impl Queries,
    device: &DeviceKeys,
    fp: Fingerprint,
    time: SealTime,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    let op = SyncOp::Upsert {
        card: Box::new(load_card(&row.card)?),
        alias: row.alias.clone(),
        verified: row.verified,
    };
    send_op(q, device, op, time, rng)
}

/// Opération locale de l'appareil `me` sur le contact `fp` à `now` :
/// l'horloge du contact avance strictement (une opération locale l'emporte
/// sur tout ce que cet appareil connaît déjà), et `removed` pose ou lève la
/// pierre tombale. Renvoie les dates du scellement de sa copie : `sent_at`
/// est la date de l'opération, `now` reste l'horloge murale.
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

/// Applique un contenu de synchronisation authentifié, venu d'un de mes
/// appareils. Toute vérification précède la première écriture : un refus
/// (`Ok(Err(raison))`) ne laisse rien d'écrit. `Err` : échec local seulement.
///
/// `sender` : l'appareil (des miens) qui a authentifié le contenu ; il
/// départage deux opérations de même date sur un contact.
pub(super) fn apply(
    q: &impl Queries,
    me: &DevicePublic,
    sender: DeviceId,
    env: &Envelope,
) -> Result<core::result::Result<SyncKind, &'static str>> {
    match &env.body {
        Body::Text(_) | Body::CardUpdate(_) => Ok(Err(R_SYNC_REFUSED)),
        Body::SyncSent { to, text } => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
            if *to == own.list.root.fingerprint() {
                return Ok(Err(R_SYNC_REFUSED));
            }
            // Identifiant brut, sens sortant : le même que sur l'appareil
            // qui a envoyé. Déjà présent (historique importé) : rien à faire.
            q.insert_message(
                *to,
                Direction::Out,
                text,
                MessageStatus::Sent,
                env.sent_at,
                MessageId(env.message_id),
            )?;
            Ok(Ok(SyncKind::Sent))
        }
        Body::SyncContact(op) => {
            Ok(content(apply_op(q, op, env.sent_at, sender))?.map(|()| SyncKind::Contact))
        }
        Body::SyncDevices { card } => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
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
            Ok(Ok(SyncKind::Devices))
        }
    }
}

/// Erreur due au contenu → refus ; erreur du stockage → propagée.
fn content<T>(r: Result<T>) -> Result<core::result::Result<T, &'static str>> {
    match r {
        Ok(v) => Ok(Ok(v)),
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => Err(e),
        Err(_) => Ok(Err(R_SYNC_REFUSED)),
    }
}

/// État d'un contact, dernier écrivain gagnant par empreinte, sur
/// `(at, supprimé, auteur)` ([`ContactClock`]) : `at` est l'horodatage
/// authentifié de l'enveloppe, `sender` l'appareil qui l'a envoyée. Une
/// opération qui ne l'emporte pas sur la dernière connue est sans effet
/// (acceptée et accusée). À date égale, une suppression l'emporte sur un état
/// présent, puis l'appareil d'identifiant le plus grand : tous mes appareils
/// tranchent pareil, quel que soit l'ordre d'arrivée. La pierre tombale d'une
/// suppression empêche un état plus ancien de ressusciter le contact ; un
/// état plus récent la lève.
fn apply_op(q: &impl Queries, op: &SyncOp, at: u64, sender: DeviceId) -> Result<()> {
    let (fp, removing) = match op {
        SyncOp::Upsert { card, .. } => (card.fingerprint(), false),
        SyncOp::Remove(fp) => (*fp, true),
    };
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
        SyncOp::Remove(fp) => {
            if q.get_contact(*fp)?.is_some() {
                q.delete_contact(*fp)?;
            }
        }
    }
    q.set_contact_clock(fp, &clock)
}

/// Nouvelle carte acceptable : liste signée par ma racine, de version
/// strictement supérieure, contenant cet appareil ; carte vérifiée, avec un
/// paquet de clés pour cet appareil ; aucun nouvel appareil revendiqué par un
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
/// Supprime les sessions rangées sous mon empreinte avec un appareil absent
/// de `list` (ma nouvelle liste).
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
