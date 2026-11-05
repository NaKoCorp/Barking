//! Contacts: card in binary (QR code), verification, alias, removal, safety code.

use barking_core::CoreError;
use barking_core::contact::ContactCard;

use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// What a scanned or opened card says, before adding it.
#[derive(Debug, uniffi::Record)]
pub struct CardPreview {
    pub fingerprint: String,
    pub display_name: String,
}

fn not_a_card(_: CoreError) -> BarkingError {
    BarkingError::invalid("not a card")
}

fn preview(card: &ContactCard) -> Result<CardPreview, BarkingError> {
    card.verify().map_err(not_a_card)?;
    Ok(CardPreview {
        fingerprint: card.fingerprint().to_string(),
        display_name: card.display_name.clone(),
    })
}

/// Reads a card in binary (QR code) without adding it.
#[uniffi::export]
pub fn inspect_card(bytes: Vec<u8>) -> Result<CardPreview, BarkingError> {
    guard(move || preview(&ContactCard::decode(&bytes).map_err(not_a_card)?))
}

/// Reads a card in text form (link) without adding it.
#[uniffi::export]
pub fn inspect_card_text(text: String) -> Result<CardPreview, BarkingError> {
    guard(move || preview(&ContactCard::from_text(&text).map_err(not_a_card)?))
}

#[uniffi::export]
impl Device {
    /// My card in binary, signed with my display name (QR code).
    /// Only the device holding the root can sign it (`Internal` otherwise,
    /// from `CoreError::NotAdmin`).
    pub fn contact_card_bytes(&self) -> Result<Vec<u8>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let name = core.display_name()?;
                Ok(core.contact_card(&name)?.encode())
            })
        })
    }

    /// Adds a contact from a card in binary; returns its fingerprint. My own
    /// card: `InvalidInput { detail: "own card" }`.
    pub fn add_contact_bytes(
        &self,
        card: Vec<u8>,
        alias: Option<String>,
    ) -> Result<String, BarkingError> {
        guard(|| {
            let card = ContactCard::decode(&card).map_err(not_a_card)?;
            self.with_core(|core| {
                if card.fingerprint() == core.fingerprint() {
                    return Err(BarkingError::invalid("own card"));
                }
                let fp = core
                    .add_contact(&card, alias.as_deref(), now(), &mut rand::rng())
                    .map_err(|e| match e {
                        CoreError::InvalidSignature
                        | CoreError::Malformed(_)
                        | CoreError::TooLarge => not_a_card(e),
                        other => other.into(),
                    })?;
                Ok(fp.to_string())
            })
        })
    }

    pub fn set_alias(&self, contact: String, alias: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.set_alias(&fp, &alias, now(), &mut rand::rng())?)
            })
        })
    }

    /// Removes a contact and its sessions; the history is kept.
    pub fn remove_contact(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.remove_contact(&fp, now(), &mut rand::rng())?)
            })
        })
    }

    pub fn mark_verified(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.mark_verified(&fp, now(), &mut rand::rng())?)
            })
        })
    }

    pub fn unmark_verified(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.unmark_verified(&fp, now(), &mut rand::rng())?)
            })
        })
    }

    /// The safety code: 12 groups of 5 digits, the same on both sides.
    pub fn safety_number(&self, contact: String) -> Result<Vec<String>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core
                    .safety_number(&fp)?
                    .split(' ')
                    .map(str::to_owned)
                    .collect())
            })
        })
    }
}
