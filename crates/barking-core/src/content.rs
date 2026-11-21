//! Contents carried by `Body::Ext`: replies, reactions, deletions synced
//! to my other devices, and ephemeral messages.
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
/// Kind number of [`ExtContent::SyncDelete`].
pub const KIND_SYNC_DELETE: u16 = 5;
/// Kind number of [`ExtContent::Message`].
pub const KIND_MESSAGE: u16 = 6;
/// Kind number of [`ExtContent::SyncMessage`].
pub const KIND_SYNC_MESSAGE: u16 = 7;

/// Shortest ephemeral delay: one minute.
pub const MIN_TTL_SECS: u32 = 60;
/// Longest ephemeral delay: seven days.
pub const MAX_TTL_SECS: u32 = 604_800;
/// An ephemeral never shown on a device is erased this long after it was
/// inserted there (seven days).
pub const UNSEEN_CEILING_SECS: u64 = 604_800;

/// Most identifiers in one `SyncDelete`: 32 × 16 bytes keep it in tier M
/// (1 024 bytes). A larger deletion goes in several packets.
pub const MAX_SYNC_DELETE_IDS: usize = 32;

/// What a receiver does with a kind it does not know.
///
/// A future kind must never be dangerous to ignore: `Ignore` means that
/// dropping the content silently loses nothing the user must see, and a kind
/// for which that is false must use `ShowUpdate`.
///
/// On the wire: one raw byte (`0` Ignore, `1` ShowUpdate), inside the frozen
/// `Body::Ext`. A value this version does not know (a policy added later)
/// reads as `ShowUpdate`, never as an error: the envelope still decodes and
/// the user is asked to update rather than losing the content silently.
/// A kind never gains fields: new fields need a new kind (`ExtContent`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnknownPolicy {
    /// Acknowledge and drop silently.
    Ignore,
    /// Show a placeholder asking the user to update the app.
    ShowUpdate,
}

impl UnknownPolicy {
    const IGNORE: u8 = 0;
    const SHOW_UPDATE: u8 = 1;
}

impl Serialize for UnknownPolicy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_u8(match self {
            UnknownPolicy::Ignore => Self::IGNORE,
            UnknownPolicy::ShowUpdate => Self::SHOW_UPDATE,
        })
    }
}

impl<'de> Deserialize<'de> for UnknownPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        Ok(match u8::deserialize(d)? {
            Self::IGNORE => UnknownPolicy::Ignore,
            // `SHOW_UPDATE` and any later value.
            _ => UnknownPolicy::ShowUpdate,
        })
    }
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
///
/// A kind never gains fields: its `data` is parsed with no trailing byte
/// allowed (`parse`), so an older reader would refuse the longer form. New
/// fields need a new kind.
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
    /// Messages I deleted on another of my devices (kind 5): 1 to
    /// [`MAX_SYNC_DELETE_IDS`] identifiers, the same on all my devices.
    SyncDelete { ids: Vec<MessageId> },
    /// A text, answering `reply_to` or not, erased `ttl_secs` after it is
    /// seen when that is set (kind 6). Only ephemeral sends use it: plain
    /// texts and replies keep `Text` and `Reply`.
    Message {
        text: String,
        reply_to: Option<MessageRef>,
        ttl_secs: Option<u32>,
    },
    /// Copy of a `Message` I sent to `to` from another of my devices
    /// (kind 7).
    SyncMessage {
        to: Fingerprint,
        text: String,
        reply_to: Option<MessageRef>,
        ttl_secs: Option<u32>,
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
            ExtContent::SyncDelete { ids } => write!(f, "SyncDelete(<{} ids>)", ids.len()),
            ExtContent::Message { text, .. } => write!(f, "Message(<{} bytes>)", text.len()),
            ExtContent::SyncMessage { text, .. } => {
                write!(f, "SyncMessage(<{} bytes>)", text.len())
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

/// Each emoji of `emojis` in its canonical spelling.
fn canonical(emojis: &[String]) -> Vec<String> {
    emojis.iter().map(|e| emoji::canonical(e)).collect()
}

fn check_text(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_LEN {
        return Err(CoreError::TooLarge);
    }
    Ok(())
}

/// `ttl_secs` is absent or within `MIN_TTL_SECS..=MAX_TTL_SECS`.
#[must_use]
pub fn ttl_in_bounds(ttl_secs: Option<u32>) -> bool {
    ttl_secs.is_none_or(|t| (MIN_TTL_SECS..=MAX_TTL_SECS).contains(&t))
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
            ExtContent::SyncDelete { ids } => (
                KIND_SYNC_DELETE,
                UnknownPolicy::Ignore,
                encode(&ids.iter().map(|id| id.0).collect::<Vec<_>>()),
            ),
            ExtContent::Message {
                text,
                reply_to,
                ttl_secs,
            } => (
                KIND_MESSAGE,
                UnknownPolicy::ShowUpdate,
                encode(&(text, reply_to, ttl_secs)),
            ),
            // `Ignore` like `SyncReply`: an unknown kind from my own devices
            // is never shown.
            ExtContent::SyncMessage {
                to,
                text,
                reply_to,
                ttl_secs,
            } => (
                KIND_SYNC_MESSAGE,
                UnknownPolicy::Ignore,
                encode(&(to, text, reply_to, ttl_secs)),
            ),
        };
        Body::Ext {
            kind,
            unknown,
            data,
        }
    }

    /// Reads the content of kind `kind`; `None` for a kind this version does
    /// not know. The content is validated (text length, emoji set), its emoji
    /// in their canonical spelling (`emoji::canonical`): two spellings of
    /// one emoji in a set are a duplicate.
    ///
    /// # Errors
    /// `Malformed` on bad or trailing bytes, for a `SyncDelete` without
    /// identifier or with too many and for a delay out of
    /// `MIN_TTL_SECS..=MAX_TTL_SECS`, `TooLarge` for a long text,
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
                let (target, emojis): (_, Vec<String>) = parse(data)?;
                ExtContent::Reaction {
                    target,
                    emojis: canonical(&emojis),
                }
            }
            KIND_SYNC_REACTION => {
                let (to, target, emojis): (_, _, Vec<String>) = parse(data)?;
                ExtContent::SyncReaction {
                    to,
                    target,
                    emojis: canonical(&emojis),
                }
            }
            KIND_SYNC_DELETE => {
                let ids: Vec<[u8; 16]> = parse(data)?;
                ExtContent::SyncDelete {
                    ids: ids.into_iter().map(MessageId).collect(),
                }
            }
            KIND_MESSAGE => {
                let (text, reply_to, ttl_secs) = parse(data)?;
                ExtContent::Message {
                    text,
                    reply_to,
                    ttl_secs,
                }
            }
            KIND_SYNC_MESSAGE => {
                let (to, text, reply_to, ttl_secs) = parse(data)?;
                ExtContent::SyncMessage {
                    to,
                    text,
                    reply_to,
                    ttl_secs,
                }
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
            ExtContent::SyncDelete { ids } => {
                if (1..=MAX_SYNC_DELETE_IDS).contains(&ids.len()) {
                    Ok(())
                } else {
                    Err(CoreError::Malformed("number of deleted messages"))
                }
            }
            ExtContent::Message { text, ttl_secs, .. }
            | ExtContent::SyncMessage { text, ttl_secs, .. } => {
                check_text(text)?;
                if ttl_in_bounds(*ttl_secs) {
                    Ok(())
                } else {
                    Err(CoreError::Malformed("ephemeral delay"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_one_byte_and_unknown_values_ask_for_an_update() {
        assert_eq!(postcard::to_allocvec(&UnknownPolicy::Ignore).unwrap(), [0]);
        assert_eq!(
            postcard::to_allocvec(&UnknownPolicy::ShowUpdate).unwrap(),
            [1]
        );
        let read = |b: u8| postcard::from_bytes::<UnknownPolicy>(&[b]).unwrap();
        assert_eq!(read(0), UnknownPolicy::Ignore);
        assert_eq!(read(1), UnknownPolicy::ShowUpdate);
        for b in [2, 7, 0x7f, 0x80, 0xff] {
            assert_eq!(read(b), UnknownPolicy::ShowUpdate, "{b}");
        }
    }

    fn ids(n: usize) -> Vec<MessageId> {
        (0..n)
            .map(|i| MessageId([u8::try_from(i).unwrap(); 16]))
            .collect()
    }

    #[test]
    fn message_kinds_round_trip() {
        let to = Fingerprint([3; 32]);
        let quote = MessageRef {
            id: [1; 16],
            by_sender: false,
        };
        for reply_to in [None, Some(quote)] {
            for ttl_secs in [None, Some(MIN_TTL_SECS), Some(300), Some(MAX_TTL_SECS)] {
                let message = ExtContent::Message {
                    text: "hi".into(),
                    reply_to,
                    ttl_secs,
                };
                let copy = ExtContent::SyncMessage {
                    to,
                    text: "hi".into(),
                    reply_to,
                    ttl_secs,
                };
                for (content, kind, policy) in [
                    (message, KIND_MESSAGE, UnknownPolicy::ShowUpdate),
                    (copy, KIND_SYNC_MESSAGE, UnknownPolicy::Ignore),
                ] {
                    let Body::Ext {
                        kind: k,
                        unknown,
                        data,
                    } = content.to_body()
                    else {
                        panic!("Ext expected");
                    };
                    assert_eq!((k, unknown), (kind, policy));
                    assert_eq!(ExtContent::decode(k, &data).unwrap(), Some(content));
                    let mut trailing = data.clone();
                    trailing.push(0);
                    assert!(matches!(
                        ExtContent::decode(k, &trailing),
                        Err(CoreError::Malformed(_))
                    ));
                }
            }
        }
        let long = ExtContent::Message {
            text: "a".repeat(MAX_TEXT_LEN + 1),
            reply_to: None,
            ttl_secs: Some(300),
        };
        let Body::Ext { kind, data, .. } = long.to_body() else {
            panic!("Ext expected");
        };
        assert_eq!(ExtContent::decode(kind, &data), Err(CoreError::TooLarge));
        assert_eq!(
            format!("{long:?}"),
            format!("Message(<{} bytes>)", MAX_TEXT_LEN + 1)
        );
    }

    #[test]
    fn ttl_bounds_on_decode() {
        let to = Fingerprint([3; 32]);
        let raw = |ttl: u32| {
            let message = postcard::to_allocvec(&("hi", None::<MessageRef>, Some(ttl))).unwrap();
            let copy = postcard::to_allocvec(&(to, "hi", None::<MessageRef>, Some(ttl))).unwrap();
            [(KIND_MESSAGE, message), (KIND_SYNC_MESSAGE, copy)]
        };
        for ttl in [59, 604_801, 0, u32::MAX] {
            for (kind, data) in raw(ttl) {
                assert!(
                    matches!(
                        ExtContent::decode(kind, &data),
                        Err(CoreError::Malformed(_))
                    ),
                    "{kind} {ttl}"
                );
            }
        }
        for ttl in [60, 604_800] {
            for (kind, data) in raw(ttl) {
                assert!(
                    ExtContent::decode(kind, &data).unwrap().is_some(),
                    "{kind} {ttl}"
                );
            }
        }
    }

    /// The largest message and its copy (longest text, a quote, the longest
    /// delay) still fit in a packet.
    #[test]
    fn largest_message_fits_in_a_packet() {
        let reply_to = Some(MessageRef {
            id: [1; 16],
            by_sender: true,
        });
        let text = "a".repeat(MAX_TEXT_LEN);
        let ttl_secs = Some(MAX_TTL_SECS);
        for content in [
            ExtContent::Message {
                text: text.clone(),
                reply_to,
                ttl_secs,
            },
            ExtContent::SyncMessage {
                to: Fingerprint([3; 32]),
                text: text.clone(),
                reply_to,
                ttl_secs,
            },
        ] {
            assert!(crate::envelope::fits_in_packet(&content.to_body()));
        }
    }

    #[test]
    fn sync_delete_round_trips_and_refuses_bad_sizes() {
        let full = ExtContent::SyncDelete {
            ids: ids(MAX_SYNC_DELETE_IDS),
        };
        let Body::Ext {
            kind,
            unknown,
            data,
        } = full.to_body()
        else {
            panic!("Ext expected");
        };
        assert_eq!((kind, unknown), (KIND_SYNC_DELETE, UnknownPolicy::Ignore));
        assert_eq!(ExtContent::decode(kind, &data).unwrap(), Some(full));
        assert_eq!(
            format!("{:?}", ExtContent::SyncDelete { ids: ids(3) }),
            "SyncDelete(<3 ids>)"
        );
        let raw = |n: usize| {
            let ids: Vec<[u8; 16]> = ids(n).iter().map(|m| m.0).collect();
            postcard::to_allocvec(&ids).unwrap()
        };
        for n in [0, MAX_SYNC_DELETE_IDS + 1] {
            assert!(
                matches!(
                    ExtContent::decode(KIND_SYNC_DELETE, &raw(n)),
                    Err(CoreError::Malformed(_))
                ),
                "{n} ids"
            );
        }
        let mut trailing = raw(1);
        trailing.push(0);
        assert!(matches!(
            ExtContent::decode(KIND_SYNC_DELETE, &trailing),
            Err(CoreError::Malformed(_))
        ));
    }
}
