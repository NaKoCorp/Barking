//! Contacts : ajout d'une carte, alias, résolution, liste.

use std::collections::HashSet;

use rand_core::CryptoRng;

use super::{Core, OwnDevices, load_card, log, sync};
use crate::contact::ContactCard;
use crate::envelope::SyncOp;
use crate::identity::{DeviceId, DevicePublic, Fingerprint};
use crate::store::{ContactClock, ContactRow, Queries};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

/// Taille maximale d'un alias, en octets.
pub const MAX_ALIAS_LEN: usize = 64;

/// Vue d'un contact pour l'interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSummary {
    pub fingerprint: Fingerprint,
    pub alias: Option<String>,
    pub display_name: String,
    pub verified: bool,
}

/// Alias stocké : la chaîne vide signifie « pas d'alias ».
fn alias_of(stored: &str) -> Option<String> {
    (!stored.is_empty()).then(|| stored.to_owned())
}

impl Core {
    /// Ajoute (ou met à jour) un contact à partir de sa carte signée.
    ///
    /// - La carte est entièrement vérifiée (racine, liste d'appareils, paquets de clés).
    /// - Empreinte déjà connue : la liste d'appareils doit être identique ou la
    ///   remplacer (`supersedes`) ; les sessions des appareils retirés sont supprimées.
    /// - Alias déjà pris par une autre empreinte : événement `ContactKeyChanged`,
    ///   l'ancien contact est remplacé et le nouveau n'est pas vérifié.
    ///
    /// L'état obtenu (et la suppression du contact remplacé) est mis en file
    /// pour chacun de mes autres appareils (`SyncContact`), dans la même
    /// transaction.
    pub fn add_contact(
        &mut self,
        card: &ContactCard,
        alias: Option<&str>,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<Fingerprint> {
        self.ensure_linked()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let me = device.public().id();
            let (fp, replaced) = add_in(tx, card, alias)?;
            if let Some(old) = replaced {
                let time = sync::touch(tx, old, now, true, me)?;
                sync::send_op(tx, device, SyncOp::Remove(old), time, rng)?;
            }
            let time = sync::touch(tx, fp, now, false, me)?;
            sync::send_state(tx, device, fp, time, rng)?;
            Ok(fp)
        })
    }

    /// Supprime un contact, ses sessions, sa carte stockée et ses paquets en
    /// file d'envoi, en une seule transaction. L'historique des messages est
    /// conservé. Sert à se débloquer après l'ajout d'une carte frauduleuse
    /// qui revendiquait les clés d'un vrai contact. Inconnu : `UnknownContact`.
    /// Synchronisé avec mes autres appareils.
    pub fn remove_contact(
        &mut self,
        contact: &Fingerprint,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.ensure_linked()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            remove_in(tx, *contact)?;
            let time = sync::touch(tx, *contact, now, true, device.public().id())?;
            sync::send_op(tx, device, SyncOp::Remove(*contact), time, rng)
        })
    }

    /// Marque le contact comme vérifié (code de sécurité comparé).
    /// Synchronisé avec mes autres appareils.
    pub fn mark_verified(
        &mut self,
        contact: &Fingerprint,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.ensure_linked()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            verify_in(tx, *contact)?;
            let time = sync::touch(tx, *contact, now, false, device.public().id())?;
            sync::send_state(tx, device, *contact, time, rng)
        })
    }

    /// Change l'alias d'un contact connu ; un alias vide le retire. Alias
    /// trop long : `TooLarge` ; déjà pris par un autre contact : refusé.
    /// Synchronisé avec mes autres appareils.
    pub fn set_alias(
        &mut self,
        contact: &Fingerprint,
        alias: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.ensure_linked()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            set_alias_in(tx, *contact, alias)?;
            let time = sync::touch(tx, *contact, now, false, device.public().id())?;
            sync::send_state(tx, device, *contact, time, rng)
        })
    }

    /// Trouve un contact par alias, sinon par empreinte (forme affichée, avec
    /// ou sans tirets). Inconnu : `UnknownContact`.
    pub fn resolve(&self, fp_or_alias: &str) -> Result<Fingerprint> {
        let s = fp_or_alias.trim();
        if !s.is_empty()
            && let Some(c) = self.store.find_contact_by_alias(s)?
        {
            return Ok(c.fp);
        }
        if let Some(fp) = parse_fingerprint(s)
            && self.store.get_contact(fp)?.is_some()
        {
            return Ok(fp);
        }
        Err(CoreError::UnknownContact)
    }

    /// Tous les contacts, triés par alias.
    pub fn contacts(&self) -> Result<Vec<ContactSummary>> {
        self.store
            .list_contacts()?
            .into_iter()
            .map(|row| {
                let card = load_card(&row.card)?;
                Ok(ContactSummary {
                    fingerprint: row.fp,
                    alias: alias_of(&row.alias),
                    display_name: card.display_name,
                    verified: row.verified,
                })
            })
            .collect()
    }

    /// Alias d'un contact connu, s'il en a un.
    pub(super) fn alias_in(q: &impl Queries, fp: Fingerprint) -> Result<Option<String>> {
        Ok(q.get_contact(fp)?.and_then(|c| alias_of(&c.alias)))
    }
}

/// Carte vérifiée, prête à être écrite.
struct Checked {
    fp: Fingerprint,
    bytes: Vec<u8>,
    /// Horodatage du journal : celui de la liste (aucune horloge ici).
    at: u64,
    /// Appareils retirés par rapport à la carte connue.
    revoked: Vec<DeviceId>,
    old: Option<ContactRow>,
}

/// Toutes les vérifications d'une carte de contact, sans rien écrire :
/// signature, pas mon identité ni un de mes appareils, aucun appareil d'un
/// autre contact, liste identique ou plus récente que celle connue.
fn check_card(q: &impl Queries, card: &ContactCard) -> Result<Checked> {
    card.verify()?;
    let fp = card.fingerprint();
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    if fp == own.list.root.fingerprint() {
        return Err(CoreError::Malformed("carte de ma propre identité"));
    }
    let claimed: Vec<DevicePublic> = card.devices.certs.iter().map(|c| c.device).collect();
    if own
        .list
        .certs
        .iter()
        .any(|mine| claimed.iter().any(|d| overlaps(d, &mine.device)))
    {
        return Err(CoreError::Malformed(
            "carte revendiquant un de mes appareils",
        ));
    }
    let bytes = postcard::to_allocvec(card).map_err(|_| CoreError::Malformed("carte"))?;
    let at = card
        .devices
        .certs
        .iter()
        .map(|c| c.issued_at)
        .max()
        .unwrap_or(0);
    // Un appareil (identifiant, clé de signature ou clé X25519) n'appartient
    // qu'à un seul contact : sinon un contact pourrait se faire attribuer
    // les messages d'un autre.
    if claimed_by_contact(q, Some(fp), &claimed)? {
        return Err(CoreError::Malformed(
            "appareil déjà associé à un autre contact",
        ));
    }
    let old = q.get_contact(fp)?;
    let mut revoked = Vec::new();
    if let Some(old) = &old {
        let old_card = load_card(&old.card)?;
        if card.devices != old_card.devices {
            if !card.devices.supersedes(&old_card.devices) {
                return Err(CoreError::Malformed(
                    "liste d'appareils plus ancienne ou divergente",
                ));
            }
            let kept: HashSet<DeviceId> =
                card.devices.certs.iter().map(|c| c.device.id()).collect();
            revoked = old_card
                .devices
                .certs
                .iter()
                .map(|c| c.device.id())
                .filter(|id| !kept.contains(id))
                .collect();
        }
    }
    Ok(Checked {
        fp,
        bytes,
        at,
        revoked,
        old,
    })
}

/// Normalise un alias : sans espaces autour, au plus `MAX_ALIAS_LEN` octets.
fn clean_alias(alias: &str) -> Result<&str> {
    let alias = alias.trim();
    if alias.len() > MAX_ALIAS_LEN {
        return Err(CoreError::TooLarge);
    }
    Ok(alias)
}

/// Ajout (ou mise à jour) d'un contact dans `q`, avec toutes les
/// vérifications d'`add_contact`. Toute vérification précède la première
/// écriture. Renvoie l'empreinte et le contact remplacé (même alias, autre
/// empreinte), s'il y en a un.
pub(super) fn add_in(
    q: &impl Queries,
    card: &ContactCard,
    alias: Option<&str>,
) -> Result<(Fingerprint, Option<Fingerprint>)> {
    let alias = alias
        .map(clean_alias)
        .transpose()?
        .filter(|a| !a.is_empty());
    let c = check_card(q, card)?;
    let fp = c.fp;
    let mut verified = c.old.as_ref().is_some_and(|o| o.verified);
    let stored_alias = match (alias, &c.old) {
        (Some(a), _) => a.to_owned(),
        (None, Some(old)) => old.alias.clone(),
        (None, None) => String::new(),
    };
    for id in &c.revoked {
        // Appareil révoqué : plus aucune session avec lui.
        q.delete_sessions_for_device(fp, *id)?;
    }
    let mut replaced = None;
    if let Some(a) = alias
        && let Some(other) = q.find_contact_by_alias(a)?
        && other.fp != fp
    {
        log(
            q,
            c.at,
            None,
            &TransparencyEvent::ContactKeyChanged {
                alias: a.to_owned(),
                old: other.fp,
                new: fp,
            },
        )?;
        q.delete_contact(other.fp)?;
        replaced = Some(other.fp);
        verified = false;
    }
    q.upsert_contact(fp, &c.bytes, &stored_alias, verified)?;
    Ok((fp, replaced))
}

/// État d'un contact reçu d'un de mes appareils (`SyncOp::Upsert`) : carte
/// (gardée si la carte connue est plus récente), alias exact (vide : aucun),
/// statut vérifié fusionné par « ou ». Toute vérification précède la
/// première écriture.
///
/// Alias porté par un autre contact : si l'opération (`clock`) l'emporte sur
/// la dernière opération connue sur cet autre contact, il le perd ; sinon
/// l'alias reçu est abandonné (le contact n'en a plus). Ainsi l'alias va à
/// l'opération la plus récente sur tous mes appareils, quel que soit l'ordre
/// d'arrivée.
pub(super) fn upsert_in(
    q: &impl Queries,
    card: &ContactCard,
    alias: &str,
    verified: bool,
    clock: &ContactClock,
) -> Result<()> {
    let mut alias = clean_alias(alias)?;
    let fp = card.fingerprint();
    let known = q.get_contact(fp)?;
    // Carte connue plus récente (déjà mise à jour) : seul l'état change.
    let keep_known = match &known {
        Some(old) => {
            card.verify().is_ok() && load_card(&old.card)?.devices.supersedes(&card.devices)
        }
        None => false,
    };
    let (bytes, revoked, old) = if keep_known {
        let old = known.ok_or(CoreError::UnknownContact)?;
        (old.card.clone(), Vec::new(), Some(old))
    } else {
        let c = check_card(q, card)?;
        (c.bytes, c.revoked, c.old)
    };
    let mut strip = None;
    if !alias.is_empty()
        && let Some(other) = q.find_contact_by_alias(alias)?
        && other.fp != fp
    {
        if clock.newer_than(q.contact_clock(other.fp)?.as_ref()) {
            strip = Some(other);
        } else {
            alias = "";
        }
    }
    for id in &revoked {
        q.delete_sessions_for_device(fp, *id)?;
    }
    if let Some(other) = strip {
        q.upsert_contact(other.fp, &other.card, "", other.verified)?;
    }
    let verified = verified || old.is_some_and(|o| o.verified);
    q.upsert_contact(fp, &bytes, alias, verified)
}

/// Raison de quarantaine d'une mise à jour de carte refusée (texte fixe).
pub(super) const R_CARD_REFUSED: &str = "mise à jour de carte refusée";

/// Vérifie la nouvelle carte `card` d'un contact connu (`current`), reçue de
/// lui (`Body::CardUpdate`) : même racine, liste d'appareils de version
/// strictement supérieure, et toutes les vérifications d'`add_contact`
/// (`check_card`, partagée : signatures, aucun de mes appareils, aucun
/// appareil d'un autre contact). N'écrit rien. Refus : `Ok(Err(raison))` ;
/// `Err` : échec du stockage seulement.
pub(super) fn verify_card_update(
    q: &impl Queries,
    current: &ContactRow,
    card: &ContactCard,
) -> Result<core::result::Result<(), &'static str>> {
    Ok(check_update(q, current, card)?.map(|_| ()))
}

fn check_update(
    q: &impl Queries,
    current: &ContactRow,
    card: &ContactCard,
) -> Result<core::result::Result<Checked, &'static str>> {
    if card.fingerprint() != current.fp {
        return Ok(Err(R_CARD_REFUSED));
    }
    let old = load_card(&current.card)?;
    if card.devices.root != old.devices.root || card.devices.version <= old.devices.version {
        return Ok(Err(R_CARD_REFUSED));
    }
    match check_card(q, card) {
        Ok(c) => Ok(Ok(c)),
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => Err(e),
        Err(_) => Ok(Err(R_CARD_REFUSED)),
    }
}

/// Applique une mise à jour de carte vérifiée par [`verify_card_update`] :
/// la carte est remplacée (alias et statut vérifié gardés : même racine) et
/// les sessions des appareils retirés sont supprimées, y compris celle de
/// l'appareil qui l'a envoyée s'il en fait partie. Renvoie le nombre
/// d'appareils ajoutés et retirés. À appeler dans la transaction de la
/// réception, après l'écriture de la session.
pub(super) fn apply_card_update(
    q: &impl Queries,
    current: &ContactRow,
    card: &ContactCard,
) -> Result<(u32, u32)> {
    let c = check_update(q, current, card)?.map_err(CoreError::Malformed)?;
    let old = load_card(&current.card)?;
    let added = card
        .devices
        .certs
        .iter()
        .filter(|n| {
            !old.devices
                .certs
                .iter()
                .any(|o| o.device.id() == n.device.id())
        })
        .count();
    for id in &c.revoked {
        q.delete_sessions_for_device(c.fp, *id)?;
    }
    q.upsert_contact(c.fp, &c.bytes, &current.alias, current.verified)?;
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    Ok((count(added), count(c.revoked.len())))
}

/// Supprime un contact connu de `q` (voir `remove_contact`).
pub(super) fn remove_in(q: &impl Queries, fp: Fingerprint) -> Result<()> {
    q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    q.delete_contact(fp)
}

/// Marque vérifié un contact connu de `q`.
pub(super) fn verify_in(q: &impl Queries, fp: Fingerprint) -> Result<()> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    q.upsert_contact(row.fp, &row.card, &row.alias, true)
}

/// Change l'alias d'un contact connu de `q` ; renvoie l'alias stocké.
pub(super) fn set_alias_in(q: &impl Queries, fp: Fingerprint, alias: &str) -> Result<String> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    let alias = clean_alias(alias)?;
    if !alias.is_empty()
        && q.find_contact_by_alias(alias)?
            .is_some_and(|other| other.fp != fp)
    {
        return Err(CoreError::Malformed(
            "alias déjà utilisé par un autre contact",
        ));
    }
    q.upsert_contact(row.fp, &row.card, alias, row.verified)?;
    Ok(alias.to_owned())
}

/// Deux appareils partagent-ils un identifiant ou une clé publique ?
pub(super) fn overlaps(a: &DevicePublic, b: &DevicePublic) -> bool {
    a.id() == b.id() || a.dh == b.dh || a.sig == b.sig
}

/// Vrai si un contact autre que `except`, ou si ma propre liste d'appareils
/// (lue dans la base, sur l'administrateur comme sur un appareil lié),
/// revendique l'un de ces appareils. Mes appareils ouvrent des sessions entre
/// eux : un contact qui en revendiquait un pourrait se faire passer pour moi.
pub(super) fn claimed_by_other(
    q: &impl Queries,
    except: Option<Fingerprint>,
    devices: &[DevicePublic],
) -> Result<bool> {
    if let Some(own) = OwnDevices::read(q)?
        && own
            .list
            .certs
            .iter()
            .any(|c| devices.iter().any(|d| overlaps(d, &c.device)))
    {
        return Ok(true);
    }
    claimed_by_contact(q, except, devices)
}

/// Vrai si un contact autre que `except` revendique l'un de ces appareils.
pub(super) fn claimed_by_contact(
    q: &impl Queries,
    except: Option<Fingerprint>,
    devices: &[DevicePublic],
) -> Result<bool> {
    for row in q.list_contacts()? {
        if Some(row.fp) == except {
            continue;
        }
        let card = load_card(&row.card)?;
        if card
            .devices
            .certs
            .iter()
            .any(|c| devices.iter().any(|d| overlaps(d, &c.device)))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Inverse de `Display` pour `Fingerprint` : base32 minuscule, groupes séparés par `-`.
fn parse_fingerprint(s: &str) -> Option<Fingerprint> {
    let compact: String = s
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = data_encoding::BASE32_NOPAD
        .decode(compact.as_bytes())
        .ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Fingerprint(arr))
}
