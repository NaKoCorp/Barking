//! Contacts : ajout d'une carte, alias, résolution, liste.

use std::collections::HashSet;

use super::{Core, load_card, log};
use crate::contact::ContactCard;
use crate::identity::{DeviceId, DevicePublic, Fingerprint};
use crate::store::Queries;
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
    pub fn add_contact(&mut self, card: &ContactCard, alias: Option<&str>) -> Result<Fingerprint> {
        card.verify()?;
        let fp = card.fingerprint();
        if fp == self.fingerprint() {
            return Err(CoreError::Malformed("carte de ma propre identité"));
        }
        let claimed: Vec<DevicePublic> = card.devices.certs.iter().map(|c| c.device).collect();
        if self
            .devices
            .certs
            .iter()
            .any(|mine| claimed.iter().any(|d| overlaps(d, &mine.device)))
        {
            return Err(CoreError::Malformed(
                "carte revendiquant un de mes appareils",
            ));
        }
        let alias = alias.map(str::trim).filter(|a| !a.is_empty());
        if alias.is_some_and(|a| a.len() > MAX_ALIAS_LEN) {
            return Err(CoreError::TooLarge);
        }
        let bytes = postcard::to_allocvec(card).map_err(|_| CoreError::Malformed("carte"))?;
        // Horodatage du journal : aucune horloge ici, on reprend celui de la liste.
        let at = card
            .devices
            .certs
            .iter()
            .map(|c| c.issued_at)
            .max()
            .unwrap_or(0);
        self.store.transaction(|tx| {
            // Un appareil (identifiant, clé de signature ou clé X25519) n'appartient
            // qu'à un seul contact : sinon un contact pourrait se faire attribuer
            // les messages d'un autre.
            if claimed_by_other(tx, Some(fp), &claimed)? {
                return Err(CoreError::Malformed(
                    "appareil déjà associé à un autre contact",
                ));
            }
            let mut verified = false;
            let mut stored_alias = alias.unwrap_or("").to_owned();
            if let Some(old) = tx.get_contact(fp)? {
                let old_card = load_card(&old.card)?;
                if card.devices != old_card.devices {
                    if !card.devices.supersedes(&old_card.devices) {
                        return Err(CoreError::Malformed(
                            "liste d'appareils plus ancienne ou divergente",
                        ));
                    }
                    let kept: HashSet<DeviceId> =
                        card.devices.certs.iter().map(|c| c.device.id()).collect();
                    for c in &old_card.devices.certs {
                        let id = c.device.id();
                        if !kept.contains(&id) {
                            // Appareil révoqué : plus aucune session avec lui.
                            tx.delete_sessions_for_device(fp, id)?;
                        }
                    }
                }
                verified = old.verified;
                if alias.is_none() {
                    stored_alias = old.alias.clone();
                }
            }
            if let Some(a) = alias
                && let Some(other) = tx.find_contact_by_alias(a)?
                && other.fp != fp
            {
                log(
                    tx,
                    at,
                    None,
                    &TransparencyEvent::ContactKeyChanged {
                        alias: a.to_owned(),
                        old: other.fp,
                        new: fp,
                    },
                )?;
                tx.delete_contact(other.fp)?;
                verified = false;
            }
            tx.upsert_contact(fp, &bytes, &stored_alias, verified)?;
            Ok(fp)
        })
    }

    /// Supprime un contact, ses sessions, sa carte stockée et ses paquets en
    /// file d'envoi, en une seule transaction. L'historique des messages est
    /// conservé. Sert à se
    /// débloquer après l'ajout d'une carte frauduleuse qui revendiquait les
    /// clés d'un vrai contact. Inconnu : `UnknownContact`.
    pub fn remove_contact(&mut self, contact: &Fingerprint) -> Result<()> {
        self.store.transaction(|tx| {
            tx.get_contact(*contact)?.ok_or(CoreError::UnknownContact)?;
            tx.delete_contact(*contact)
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

/// Deux appareils partagent-ils un identifiant ou une clé publique ?
fn overlaps(a: &DevicePublic, b: &DevicePublic) -> bool {
    a.id() == b.id() || a.dh == b.dh || a.sig == b.sig
}

/// Vrai si un contact autre que `except` revendique l'un de ces appareils.
pub(super) fn claimed_by_other(
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
