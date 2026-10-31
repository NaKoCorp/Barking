//! Contacts: adding a card, alias, resolution, list.

use std::collections::HashSet;

use rand_core::CryptoRng;

use super::{Core, OwnDevices, load_card, log, sync};
use crate::contact::ContactCard;
use crate::envelope::SyncOp;
use crate::identity::{DeviceId, DevicePublic, Fingerprint};
use crate::store::{ContactClock, ContactRow, Queries};
use crate::transparency::TransparencyEvent;
use crate::{CoreError, Result};

/// Maximum size of an alias, in bytes.
pub const MAX_ALIAS_LEN: usize = 64;

/// View of a contact for the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSummary {
    pub fingerprint: Fingerprint,
    pub alias: Option<String>,
    pub display_name: String,
    pub verified: bool,
}

/// Stored alias: the empty string means "no alias".
fn alias_of(stored: &str) -> Option<String> {
    (!stored.is_empty()).then(|| stored.to_owned())
}

impl Core {
    /// Adds (or updates) a contact from its signed card.
    ///
    /// - The card is fully verified (root, device list, key packets).
    /// - Fingerprint already known: the device list must be identical or
    ///   replace the known one (`supersedes`); the sessions of removed devices are deleted.
    /// - Alias already taken by another fingerprint: `ContactKeyChanged` event,
    ///   the old contact is replaced and the new one is not verified.
    ///
    /// The resulting state (and the deletion of the replaced contact) is queued
    /// for each of my other devices (`SyncContact`), in the same
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
            // The new state goes out before the deletion of the replaced contact:
            // received in that order, the alias moves from one fingerprint to the other
            // on my other devices, which log the same
            // `ContactKeyChanged` (in the reverse order, the final state is the
            // same, without the warning).
            let time = sync::touch(tx, fp, now, false, me)?;
            sync::send_state(tx, device, fp, time, rng)?;
            if let Some(old) = replaced {
                let time = sync::touch(tx, old, now, true, me)?;
                sync::send_op(tx, device, SyncOp::Remove(old), time, rng)?;
            }
            Ok(fp)
        })
    }

    /// Deletes a contact, its sessions, its stored card and its packets in the
    /// send queue, in a single transaction. The message history is
    /// kept. Used to get unstuck after adding a fraudulent card
    /// that claimed the keys of a real contact. Unknown: `UnknownContact`.
    /// Synchronized with my other devices.
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

    /// Marks the contact as verified (security code compared).
    /// Synchronized with my other devices.
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

    /// Changes the alias of a known contact; an empty alias removes it. Alias
    /// too long: `TooLarge`; already taken by another contact: refused.
    /// Synchronized with my other devices.
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

    /// Finds a contact by alias, otherwise by fingerprint (displayed form, with
    /// or without dashes). Unknown: `UnknownContact`.
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

    /// All contacts, sorted by alias.
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

    /// Alias of a known contact, if it has one.
    pub(super) fn alias_in(q: &impl Queries, fp: Fingerprint) -> Result<Option<String>> {
        Ok(q.get_contact(fp)?.and_then(|c| alias_of(&c.alias)))
    }
}

/// Verified card, ready to be written.
struct Checked {
    fp: Fingerprint,
    bytes: Vec<u8>,
    /// Log timestamp: the list's (no clock here).
    at: u64,
    /// Devices removed relative to the known card.
    revoked: Vec<DeviceId>,
    old: Option<ContactRow>,
}

/// All the checks of a contact card, without writing anything:
/// signature, not my identity nor one of my devices, no device of
/// another contact, list identical to or newer than the known one.
fn check_card(q: &impl Queries, card: &ContactCard) -> Result<Checked> {
    card.verify()?;
    let fp = card.fingerprint();
    let own = OwnDevices::read(q)?.ok_or(CoreError::LinkPending)?;
    if fp == own.list.root.fingerprint() {
        return Err(CoreError::Malformed("card of my own identity"));
    }
    let claimed: Vec<DevicePublic> = card.devices.certs.iter().map(|c| c.device).collect();
    if own
        .list
        .certs
        .iter()
        .any(|mine| claimed.iter().any(|d| overlaps(d, &mine.device)))
    {
        return Err(CoreError::Malformed("card claiming one of my devices"));
    }
    let bytes = card.encode();
    let at = card
        .devices
        .certs
        .iter()
        .map(|c| c.issued_at)
        .max()
        .unwrap_or(0);
    // A device (identifier, signing key or X25519 key) belongs to
    // a single contact only: otherwise a contact could get itself attributed
    // another's messages.
    if claimed_by_contact(q, Some(fp), &claimed)? {
        return Err(CoreError::Malformed(
            "device already associated with another contact",
        ));
    }
    let old = q.get_contact(fp)?;
    let mut revoked = Vec::new();
    if let Some(old) = &old {
        let old_card = load_card(&old.card)?;
        if card.devices != old_card.devices {
            if !card.devices.supersedes(&old_card.devices) {
                return Err(CoreError::Malformed(
                    "device list older than or diverging from the known one",
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

/// Normalizes an alias: no surrounding whitespace, at most `MAX_ALIAS_LEN` bytes.
fn clean_alias(alias: &str) -> Result<&str> {
    let alias = alias.trim();
    if alias.len() > MAX_ALIAS_LEN {
        return Err(CoreError::TooLarge);
    }
    Ok(alias)
}

/// Adds (or updates) a contact in `q`, with all the
/// checks of `add_contact`. Every check precedes the first
/// write. Returns the fingerprint and the replaced contact (same alias, other
/// fingerprint), if there is one.
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
        // Revoked device: no more sessions with it.
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

/// State of a contact received from one of my devices (`SyncOp::Upsert`): card
/// (kept if the known card is newer), exact alias (empty: none),
/// verified status merged by "or". Every check precedes the
/// first write.
///
/// Alias held by another contact: if the operation (`clock`) beats
/// the last known operation on that other contact, it loses it; otherwise
/// the received alias is dropped (the contact no longer has one). Thus the alias goes to
/// the most recent operation on all my devices, whatever the
/// arrival order.
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
    // Known card is newer (already updated): only the state changes.
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
            // The alias moves to another fingerprint: same warning as a local
            // add (`add_in`).
            log(
                q,
                clock.at,
                None,
                &TransparencyEvent::ContactKeyChanged {
                    alias: alias.to_owned(),
                    old: other.fp,
                    new: fp,
                },
            )?;
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

/// Quarantine reason for a refused card update (fixed text).
pub(super) const R_CARD_REFUSED: &str = "card update refused";

/// Outcome of verifying an acceptable card update.
pub(super) enum CardUpdate {
    /// Valid card, with the same root, with a version lower than or identical to the known one:
    /// already superseded, nothing to write (duplicate acked).
    Superseded,
    /// Newer and verified: to apply with [`apply_card_update`].
    Newer(VerifiedCard),
}

/// New card, fully verified, ready to be written.
pub(super) struct VerifiedCard {
    checked: Checked,
    /// Devices absent from the known card.
    added: Vec<DeviceId>,
}

/// Verifies the new card `card` of a known contact (`current`), received from
/// it (`Body::CardUpdate`): same fingerprint and same root (otherwise refusal);
/// valid card with a lower version, or same version and same list:
/// superseded; same version and different list: refusal; newer: all
/// the checks of `add_contact` (`check_card`, shared: signatures,
/// none of my devices, no device of another contact). Writes nothing.
/// Refusal: `Ok(Err(reason))`; `Err`: storage failure only.
pub(super) fn verify_card_update(
    q: &impl Queries,
    current: &ContactRow,
    card: &ContactCard,
) -> Result<core::result::Result<CardUpdate, &'static str>> {
    let old = load_card(&current.card)?;
    if card.fingerprint() != current.fp || card.devices.root != old.devices.root {
        return Ok(Err(R_CARD_REFUSED));
    }
    let version = card.devices.version;
    if version < old.devices.version
        || (version == old.devices.version && card.devices == old.devices)
    {
        // Acked only if valid: the ack never covers
        // a forged card.
        if card.verify().is_err() {
            return Ok(Err(R_CARD_REFUSED));
        }
        return Ok(Ok(CardUpdate::Superseded));
    }
    if version == old.devices.version {
        // Two different lists signed at the same version: root
        // equivocation, never masked.
        return Ok(Err(R_CARD_REFUSED));
    }
    let checked = match check_card(q, card) {
        Ok(c) => c,
        Err(e @ (CoreError::Store(_) | CoreError::StoreLocked)) => return Err(e),
        Err(_) => return Ok(Err(R_CARD_REFUSED)),
    };
    let added = card
        .devices
        .certs
        .iter()
        .map(|n| n.device.id())
        .filter(|id| !old.devices.certs.iter().any(|o| o.device.id() == *id))
        .collect();
    Ok(Ok(CardUpdate::Newer(VerifiedCard { checked, added })))
}

/// Applies a card update verified by [`verify_card_update`]:
/// the card is replaced (alias and verified status kept: same root) and
/// the sessions of removed devices are deleted, including that of
/// the device that sent it if it is one of them. Returns the added devices
/// and the number of removed devices. To be called in the receive
/// transaction, after the session is written. No error due to the content.
pub(super) fn apply_card_update(
    q: &impl Queries,
    current: &ContactRow,
    verified: VerifiedCard,
) -> Result<(Vec<DeviceId>, u32)> {
    let c = verified.checked;
    for id in &c.revoked {
        q.delete_sessions_for_device(c.fp, *id)?;
    }
    q.upsert_contact(c.fp, &c.bytes, &current.alias, current.verified)?;
    let removed = u32::try_from(c.revoked.len()).unwrap_or(u32::MAX);
    Ok((verified.added, removed))
}

/// Deletes a known contact from `q` (see `remove_contact`).
pub(super) fn remove_in(q: &impl Queries, fp: Fingerprint) -> Result<()> {
    q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    q.delete_contact(fp)
}

/// Marks a known contact of `q` as verified.
pub(super) fn verify_in(q: &impl Queries, fp: Fingerprint) -> Result<()> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    q.upsert_contact(row.fp, &row.card, &row.alias, true)
}

/// Changes the alias of a known contact of `q`; returns the stored alias.
pub(super) fn set_alias_in(q: &impl Queries, fp: Fingerprint, alias: &str) -> Result<String> {
    let row = q.get_contact(fp)?.ok_or(CoreError::UnknownContact)?;
    let alias = clean_alias(alias)?;
    if !alias.is_empty()
        && q.find_contact_by_alias(alias)?
            .is_some_and(|other| other.fp != fp)
    {
        return Err(CoreError::Malformed(
            "alias already used by another contact",
        ));
    }
    q.upsert_contact(row.fp, &row.card, alias, row.verified)?;
    Ok(alias.to_owned())
}

/// Do two devices share an identifier or a public key?
pub(super) fn overlaps(a: &DevicePublic, b: &DevicePublic) -> bool {
    a.id() == b.id() || a.dh == b.dh || a.sig == b.sig
}

/// True if a contact other than `except`, or if my own device list
/// (read from the database, on the admin as on a linked device),
/// claims one of these devices. My devices open sessions between
/// themselves: a contact claiming one could impersonate me.
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

/// True if a contact other than `except` claims one of these devices.
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

/// Inverse of `Display` for `Fingerprint`: lowercase base32, groups separated by `-`.
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
