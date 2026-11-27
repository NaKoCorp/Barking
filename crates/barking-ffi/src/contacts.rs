//! Contacts: card in binary (QR code), verification, alias, removal, safety code.

use barking_core::contact::ContactCard;
use barking_core::core::{ContactAvatar as CoreAvatar, MAX_AVATAR_PHOTO_LEN};
use barking_core::{CoreError, parse_fingerprint};

use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// What a scanned or opened card says, before adding it.
#[derive(Debug, uniffi::Record)]
pub struct CardPreview {
    pub fingerprint: String,
    pub display_name: String,
}

/// The picture I gave a contact: synchronized with my other devices (the
/// latest change wins), never sent to the contact.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ContactAvatar {
    /// At most 64 bytes, not blank, no control character.
    Emoji { value: String },
    /// A JPEG file of at most `avatar_photo_max_bytes()` bytes.
    Photo { jpeg: Vec<u8> },
}

/// Largest avatar photo `set_contact_avatar` accepts, in bytes: the app
/// encodes its JPEG to fit (it travels to my other devices in one packet).
#[uniffi::export]
pub fn avatar_photo_max_bytes() -> u32 {
    u32::try_from(MAX_AVATAR_PHOTO_LEN).unwrap_or(u32::MAX)
}

/// One contact's avatar, by the fingerprint `Contact.fingerprint` shows.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContactAvatarEntry {
    pub fingerprint: String,
    pub avatar: ContactAvatar,
}

impl From<ContactAvatar> for CoreAvatar {
    fn from(a: ContactAvatar) -> Self {
        match a {
            ContactAvatar::Emoji { value } => CoreAvatar::Emoji(value),
            ContactAvatar::Photo { jpeg } => CoreAvatar::Photo(jpeg),
        }
    }
}

impl From<CoreAvatar> for ContactAvatar {
    fn from(a: CoreAvatar) -> Self {
        match a {
            CoreAvatar::Emoji(value) => ContactAvatar::Emoji { value },
            CoreAvatar::Photo(jpeg) => ContactAvatar::Photo { jpeg },
        }
    }
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

    /// Keeps the unsent text of a conversation (blank deletes it); it
    /// survives relaunches, stays on this device and is never sent.
    pub fn set_draft(&self, contact: String, text: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.set_draft(&fp, &text, now())?)
            })
        })
    }

    /// The unsent text kept for a conversation, if any (a read: it does not
    /// wait for a sync in flight).
    pub fn draft(&self, contact: String) -> Result<Option<String>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.draft(&fp)?)
            })
        })
    }

    /// Sets (Some) or clears (None) the avatar of a contact, and queues the
    /// change for my other devices (never for the contact). Not an emoji or
    /// a JPEG the app can show, or too large: `InvalidInput`; unknown
    /// contact: `NotFound`.
    pub fn set_contact_avatar(
        &self,
        contact: String,
        avatar: Option<ContactAvatar>,
    ) -> Result<(), BarkingError> {
        guard(|| {
            let avatar = avatar.map(CoreAvatar::from);
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.set_contact_avatar(&fp, avatar.as_ref(), now(), &mut rand::rng())?)
            })
        })
    }

    /// Every contact's avatar (a read: it does not wait for a sync in
    /// flight). Another of my devices may change it: reload after a sync
    /// that received something (`SyncSummary::items_received`).
    pub fn contact_avatars(&self) -> Result<Vec<ContactAvatarEntry>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                Ok(core
                    .contact_avatars()?
                    .into_iter()
                    .map(|(fp, avatar)| ContactAvatarEntry {
                        fingerprint: fp.to_string(),
                        avatar: avatar.into(),
                    })
                    .collect())
            })
        })
    }

    /// Blocks a contact: its messages are dropped without an ack, nothing is
    /// sent to it, and it leaves the contact and chat lists (its history
    /// stays stored). Synchronized with my other devices.
    pub fn block_contact(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core.block_contact(&fp, now(), &mut rand::rng())?)
            })
        })
    }

    /// Lifts a block. Messages sent while blocked stay dropped. `contact`:
    /// a contact (fingerprint or alias), or the bare fingerprint of a
    /// blocked stranger (`blocked_fingerprints`).
    pub fn unblock_contact(&self, contact: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = match core.resolve(&contact) {
                    Ok(fp) => fp,
                    Err(CoreError::UnknownContact) => {
                        parse_fingerprint(&contact).ok_or(BarkingError::NotFound)?
                    }
                    Err(e) => return Err(e.into()),
                };
                Ok(core.unblock_contact(&fp, now(), &mut rand::rng())?)
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
            self.with_core_read(|core| {
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
