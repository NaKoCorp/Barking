//! Replies (the quote under a message) and emoji reactions (the chips under
//! it), as the apps see them (spec reply/reactions §5).

use barking_core::Core;
use barking_core::store::{Direction, MessageRow};

use crate::device::{Device, now, shown_text};
use crate::{BarkingError, guard};

/// Characters of the original a quote shows.
pub(crate) const QUOTE_CHARS: usize = 200;
/// Characters of the original a reaction notification shows.
pub(crate) const NOTIFICATION_CHARS: usize = 40;

/// What a reply quotes. The text of the original never travelled: it is read
/// here, from the original's row, so a message deleted here does not come
/// back through a quote.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Quote {
    /// Row of the original in this conversation (`Message::id`); `None` when
    /// it is absent (deleted, not received yet).
    #[uniffi(default = None)]
    pub id: Option<i64>,
    /// The original is mine (it stays known after the original is gone).
    pub author_is_me: bool,
    /// Start of the original's text (`excerpt`, 200 characters); `None`
    /// exactly when `id` is.
    #[uniffi(default = None)]
    pub excerpt: Option<String>,
}

/// One emoji under a message, with the number of people who chose it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ReactionChip {
    pub emoji: String,
    pub count: u32,
    /// I am among them, from any of my devices.
    pub mine: bool,
}

impl From<barking_core::core::ReactionChip> for ReactionChip {
    fn from(c: barking_core::core::ReactionChip) -> Self {
        ReactionChip {
            emoji: c.emoji,
            count: c.count,
            mine: c.mine,
        }
    }
}

/// A contact's new reaction, for the notification: the emoji its newer set
/// adds, never a removal.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NewReaction {
    /// Fingerprint of the reactor.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    /// The emoji added, in the order of the reactor's set.
    pub emojis: Vec<String>,
    /// Start of the message reacted to (`excerpt`, 40 characters); `None` if
    /// it is gone, or ephemeral (`on_ephemeral`).
    #[uniffi(default = None)]
    pub excerpt: Option<String>,
    /// The message reacted to is ephemeral: the notification never shows a
    /// word of it.
    #[uniffi(default = false)]
    pub on_ephemeral: bool,
}

/// The first `max_chars` characters of `text`, then "…" when it was cut.
/// Cuts by character (Unicode scalar), never inside one.
pub fn excerpt(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

/// The quote under `m`, if it is a reply: `None` for any other message.
///
/// The original is looked up in the conversation of `m` by its stored
/// identifier (`Core::message_in`: a row of another conversation is not
/// found). Whether it is mine comes from the reference the reply carries,
/// which both sides keep, so it holds after the original is deleted: the
/// reference says "written by the sealer of the packet", the sealer of a
/// reply of mine being me and of a received reply, the contact.
pub(crate) fn quote_of(core: &Core, m: &MessageRow) -> Result<Option<Quote>, BarkingError> {
    let Some(original) = m.reply_to else {
        return Ok(None);
    };
    let found = core.message_in(&m.contact_fp, original, now())?;
    let sealed_by_me = m.direction == Direction::Out;
    let author_is_me = match (&m.reply_ref, &found) {
        (Some(r), _) => r.by_sender == sealed_by_me,
        (None, Some(row)) => row.direction == Direction::Out,
        (None, None) => false,
    };
    Ok(Some(Quote {
        id: found.as_ref().map(|row| row.id),
        author_is_me,
        excerpt: found.map(|row| excerpt(&shown_text(&row), QUOTE_CHARS)),
    }))
}

/// The chips under `m`.
pub(crate) fn chips_of(core: &Core, m: &MessageRow) -> Result<Vec<ReactionChip>, BarkingError> {
    Ok(core
        .reaction_chips(&m.contact_fp, m.message_id)?
        .into_iter()
        .map(ReactionChip::from)
        .collect())
}

#[uniffi::export]
impl Device {
    /// Replaces my reactions on the message of row `message` with `emojis`
    /// (empty: removes mine). The packets leave with the next sync.
    /// `MessageNotFound`, `TooManyEmoji` (over 20), `InvalidEmoji` (not one
    /// emoji each), `ContactBlocked`; `NotFound` for a contact removed since.
    pub fn set_reactions(&self, message: i64, emojis: Vec<String>) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                core.set_reactions(message, &emojis, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }
}
