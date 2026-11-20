//! Contents carried by `Body::Ext`: replies and reactions.
//!
//! `Body::Ext { kind, unknown, data }` is the extensible envelope: `data` is
//! the postcard of the kind's fields. A receiver that does not know a kind
//! applies the `unknown` policy chosen by the sender instead of refusing the
//! packet.

use core::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::emoji;
use crate::envelope::{Body, MAX_TEXT_LEN};
use crate::identity::Fingerprint;
use crate::store::MessageId;
use crate::{CoreError, Result};

/// Kind number of [`ExtContent::Reply`].
pub const KIND_REPLY: u16 = 1;
/// Kind number of [`ExtContent::SyncReply`].
pub const KIND_SYNC_REPLY: u16 = 2;
/// Kind number of [`ExtContent::Reaction`].
pub const KIND_REACTION: u16 = 3;
/// Kind number of [`ExtContent::SyncReaction`].
pub const KIND_SYNC_REACTION: u16 = 4;

/// What a receiver does with a kind it does not know.
///
/// A future kind must never be dangerous to ignore: `Ignore` means that
/// dropping the content silently loses nothing the user must see, and a kind
/// for which that is false must use `ShowUpdate`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum UnknownPolicy {
    /// Acknowledge and drop silently.
    Ignore,
    /// Show a placeholder asking the user to update the app.
    ShowUpdate,
}

/// Reference to a message, never its text (a message deleted here never comes
/// back through a quote).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MessageRef {
    /// Envelope identifier of the message, chosen by its sender.
    pub id: [u8; 16],
    /// The message was written by the account that sealed this packet.
    pub by_sender: bool,
}

impl MessageRef {
    /// Stored identifier of the referenced message, in the conversation with
    /// `contact`. `sealer_is_me`: the packet carrying the reference was
    /// sealed by my account.
    #[must_use]
    pub fn resolve(&self, sealer_is_me: bool, contact: &Fingerprint) -> MessageId {
        if self.by_sender == sealer_is_me {
            MessageId(self.id)
        } else {
            MessageId::incoming(contact, &self.id)
        }
    }
}

/// A known content of `Body::Ext`.
#[derive(Clone, PartialEq, Eq)]
pub enum ExtContent {
    /// Text answering `reply_to` (kind 1).
    Reply { text: String, reply_to: MessageRef },
    /// Copy of a reply I sent to `to` from another of my devices (kind 2).
    SyncReply {
        to: Fingerprint,
        text: String,
        reply_to: MessageRef,
    },
    /// The whole set of emoji the sender holds on `target` (kind 3).
    Reaction {
        target: MessageRef,
        emojis: Vec<String>,
    },
    /// Copy of a reaction I sent to `to` from another of my devices (kind 4).
    SyncReaction {
        to: Fingerprint,
        target: MessageRef,
        emojis: Vec<String>,
    },
}

impl fmt::Debug for ExtContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sizes only: no text, no emoji, no identifier.
        match self {
            ExtContent::Reply { text, .. } => write!(f, "Reply(<{} bytes>)", text.len()),
            ExtContent::SyncReply { text, .. } => write!(f, "SyncReply(<{} bytes>)", text.len()),
            ExtContent::Reaction { emojis, .. } => write!(f, "Reaction(<{} emoji>)", emojis.len()),
            ExtContent::SyncReaction { emojis, .. } => {
                write!(f, "SyncReaction(<{} emoji>)", emojis.len())
            }
        }
    }
}

/// Postcard of `value`, which cannot fail for these types (strings, byte
/// arrays and vectors serialized to memory).
fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).unwrap_or_default()
}

fn parse<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    let (value, rest) =
        postcard::take_from_bytes(data).map_err(|_| CoreError::Malformed("extension content"))?;
    if !rest.is_empty() {
        return Err(CoreError::Malformed("extra bytes in the extension content"));
    }
    Ok(value)
}

fn check_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_LEN {
        return Err(CoreError::TooLarge);
    }
    Ok(())
}

impl ExtContent {
    /// The `Body::Ext` carrying this content.
    #[must_use]
    pub fn to_body(&self) -> Body {
        let (kind, unknown, data) = match self {
            ExtContent::Reply { text, reply_to } => (
                KIND_REPLY,
                UnknownPolicy::ShowUpdate,
                encode(&(text, reply_to)),
            ),
            ExtContent::SyncReply { to, text, reply_to } => (
                KIND_SYNC_REPLY,
                UnknownPolicy::Ignore,
                encode(&(to, text, reply_to)),
            ),
            ExtContent::Reaction { target, emojis } => (
                KIND_REACTION,
                UnknownPolicy::Ignore,
                encode(&(target, emojis)),
            ),
            ExtContent::SyncReaction { to, target, emojis } => (
                KIND_SYNC_REACTION,
                UnknownPolicy::Ignore,
                encode(&(to, target, emojis)),
            ),
        };
        Body::Ext {
            kind,
            unknown,
            data,
        }
    }

    /// Reads the content of kind `kind`; `None` for a kind this version does
    /// not know. The content is validated (text length, emoji set).
    ///
    /// # Errors
    /// `Malformed` on bad or trailing bytes, `TooLarge` for a long text,
    /// `TooManyEmoji` or `InvalidEmoji` for a bad emoji set.
    pub fn decode(kind: u16, data: &[u8]) -> Result<Option<ExtContent>> {
        let content = match kind {
            KIND_REPLY => {
                let (text, reply_to) = parse(data)?;
                ExtContent::Reply { text, reply_to }
            }
            KIND_SYNC_REPLY => {
                let (to, text, reply_to) = parse(data)?;
                ExtContent::SyncReply { to, text, reply_to }
            }
            KIND_REACTION => {
                let (target, emojis) = parse(data)?;
                ExtContent::Reaction { target, emojis }
            }
            KIND_SYNC_REACTION => {
                let (to, target, emojis) = parse(data)?;
                ExtContent::SyncReaction { to, target, emojis }
            }
            _ => return Ok(None),
        };
        content.validate()?;
        Ok(Some(content))
    }

    fn validate(&self) -> Result<()> {
        match self {
            ExtContent::Reply { text, .. } | ExtContent::SyncReply { text, .. } => check_text(text),
            ExtContent::Reaction { emojis, .. } | ExtContent::SyncReaction { emojis, .. } => {
                emoji::check_set(emojis)
            }
        }
    }
}
