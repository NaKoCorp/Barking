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
use super::send::{Target, seal_for};
use super::{META_DEVICE_LIST, META_LINKED_BUNDLES, OwnDevices, contacts};
use crate::contact::ContactCard;
use crate::envelope::{Body, Envelope, SyncOp};
use crate::handshake::PrekeyBundle;
use crate::identity::{DeviceId, DeviceKeys, DeviceList, DevicePublic};
use crate::packet::Packet;
use crate::store::{Direction, MessageId, MessageStatus, Queries};
use crate::transparency::SyncKind;
use crate::{CoreError, Result};

// Raisons de quarantaine : textes fixes.
pub(super) const R_NOT_MINE: &str = "synchronisation d'un appareil qui n'est pas à moi";
pub(super) const R_SYNC_REFUSED: &str = "synchronisation refusée";
pub(super) const R_DEVICES_REFUSED: &str = "liste d'appareils refusée";

/// Scelle `body` pour chacun de mes autres appareils ; chaque paquet est
/// enregistré comme livraison de `message_id` (à destination d'un de mes
/// appareils : son accusé ne rend pas le message « livré »). Sans autre
/// appareil, rien n'est fait.
pub(super) fn seal_to_own(
    q: &impl Queries,
    device: &DeviceKeys,
    body: &Body,
    message_id: MessageId,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Packet>> {
    let sealed = seal_for(q, device, &Target::OwnDevices, body, message_id, now, rng)?;
    for (packet, peer) in &sealed {
        q.add_delivery(message_id, packet.id, *peer)?;
    }
    Ok(sealed.into_iter().map(|(p, _)| p).collect())
}

/// Met en file l'opération `op` pour chacun de mes autres appareils, sous un
/// identifiant de message neuf (sans ligne de message).
pub(super) fn send_op(
    q: &impl Queries,
    device: &DeviceKeys,
    op: SyncOp,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    seal_to_own(q, device, &Body::SyncContact(op), MessageId(id), now, rng)?;
    Ok(())
}

/// Applique un contenu de synchronisation authentifié, venu d'un de mes
/// appareils. Toute vérification précède la première écriture : un refus
/// (`Ok(Err(raison))`) ne laisse rien d'écrit. `Err` : échec local seulement.
pub(super) fn apply(
    q: &impl Queries,
    me: &DevicePublic,
    env: &Envelope,
) -> Result<core::result::Result<SyncKind, &'static str>> {
    match &env.body {
        Body::Text(_) => Ok(Err(R_SYNC_REFUSED)),
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
        Body::SyncContact(op) => Ok(content(apply_op(q, op))?.map(|()| SyncKind::Contact)),
        Body::SyncDevices {
            devices,
            card,
            own_bundles,
        } => {
            let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
            if !devices_ok(q, &own.list, me, devices, card, own_bundles)? {
                return Ok(Err(R_DEVICES_REFUSED));
            }
            q.put_meta(META_DEVICE_LIST, devices)?;
            q.put_meta(META_LINKED_BUNDLES, own_bundles)?;
            q.put_meta(META_OWN_CARD, card)?;
            purge_removed_own_sessions(q, devices)?;
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

fn apply_op(q: &impl Queries, op: &SyncOp) -> Result<()> {
    match op {
        SyncOp::Add { card, alias } => {
            contacts::add_in(q, card, Some(alias.as_str()).filter(|a| !a.is_empty()))?;
            Ok(())
        }
        SyncOp::Remove(fp) => contacts::remove_in(q, *fp),
        SyncOp::SetAlias(fp, alias) => contacts::set_alias_in(q, *fp, alias).map(|_| ()),
        SyncOp::MarkVerified(fp) => contacts::verify_in(q, *fp),
    }
}

/// Nouvelle liste acceptable : signée par ma racine, de version strictement
/// supérieure, contenant cet appareil ; carte cohérente ; paquets de clés de
/// mes autres appareils valides ; aucun nouvel appareil revendiqué par un contact.
fn devices_ok(
    q: &impl Queries,
    current: &DeviceList,
    me: &DevicePublic,
    devices: &DeviceList,
    card: &ContactCard,
    own_bundles: &[PrekeyBundle],
) -> Result<bool> {
    if !devices.supersedes(current)
        || devices.verify().is_err()
        || !devices.certs.iter().any(|c| c.device == *me)
        || card.verify().is_err()
        || card.devices != *devices
    {
        return Ok(false);
    }
    let mut seen = HashSet::new();
    for b in own_bundles {
        if b.verify().is_err()
            || b.device == *me
            || b.opk.is_some()
            || !seen.insert(b.device.id())
            || !devices.certs.iter().any(|c| c.device == b.device)
        {
            return Ok(false);
        }
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
