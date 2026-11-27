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

use crate::contact::ContactCard;
use crate::emoji;
use crate::envelope::{Body, MAX_TEXT_LEN};
use crate::gif::{GifProviderId, GifRef, GifSettings, MAX_GIF_ID_LEN};
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
/// Kind number of [`ExtContent::SyncSeen`].
pub const KIND_SYNC_SEEN: u16 = 8;
/// Kind number of [`ExtContent::ContactRequest`].
pub const KIND_CONTACT_REQUEST: u16 = 9;
/// Kind number of [`ExtContent::RequestAccepted`].
pub const KIND_REQUEST_ACCEPTED: u16 = 10;
/// Kind number of [`ExtContent::SyncInvite`].
pub const KIND_SYNC_INVITE: u16 = 11;
/// Kind number of [`ExtContent::SyncRefused`].
pub const KIND_SYNC_REFUSED: u16 = 12;
/// Kind number of [`ExtContent::Gif`].
pub const KIND_GIF: u16 = 13;
/// Kind number of [`ExtContent::SyncGif`].
pub const KIND_SYNC_GIF: u16 = 14;
/// Kind number of [`ExtContent::SyncGifSettings`].
pub const KIND_SYNC_GIF_SETTINGS: u16 = 15;

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

/// Most entries in one `SyncSeen`: each takes 49 bytes plus its date (5
/// bytes today, 10 at most: identifier, contact, date), and 14 keep the
/// packet in tier M (1 024 bytes) whatever the dates
/// (`sync_seen_cap_fits_tier_m`); 15 fit only with today's dates, 16 never.
/// More go in several packets.
pub const MAX_SYNC_SEEN: usize = 14;

/// Most messages replayed in one `RequestAccepted`.
pub const MAX_REPLAYED: usize = 4;

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

/// One ephemeral message shown on one of my devices (`SyncSeen`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeenEntry {
    /// Stored identifier of the message, the same on all my devices.
    pub id: MessageId,
    /// The conversation it belongs to: a block or a removal of this contact
    /// drops the entries still waiting for their message (`pending_seen`).
    pub contact: Fingerprint,
    /// When it was first shown, on the sealer's clock.
    pub at: u64,
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
    /// Ephemeral messages shown on another of my devices (kind 8): 1 to
    /// [`MAX_SYNC_SEEN`] entries.
    SyncSeen { seen: Vec<SeenEntry> },
    /// A contact request: my card, sent to someone who has not accepted me
    /// yet (kind 9).
    ContactRequest { card: Box<ContactCard> },
    /// The request I received was accepted (kind 10): 0 to [`MAX_REPLAYED`]
    /// identifiers of the messages sent while it was pending, replayed.
    RequestAccepted { replayed: Vec<MessageId> },
    /// An invitation I sent to `to` at `at`, copied to my other devices
    /// (kind 11).
    SyncInvite { to: Fingerprint, at: u64 },
    /// A request from `fp` that I refused at `at` on another of my devices
    /// (kind 12).
    SyncRefused { fp: Fingerprint, at: u64 },
    /// A GIF, answering `reply_to` or not, erased `ttl_secs` after it is
    /// seen when that is set (kind 13).
    Gif {
        gif: GifRef,
        reply_to: Option<MessageRef>,
        ttl_secs: Option<u32>,
    },
    /// Copy of a `Gif` I sent to `to` from another of my devices (kind 14).
    SyncGif {
        to: Fingerprint,
        gif: GifRef,
        reply_to: Option<MessageRef>,
        ttl_secs: Option<u32>,
    },
    /// My GIF settings as of `at`, copied to my other devices (kind 15).
    SyncGifSettings { settings: GifSettings, at: u64 },
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
            ExtContent::SyncSeen { seen } => write!(f, "SyncSeen(<{} entries>)", seen.len()),
            ExtContent::ContactRequest { card } => {
                write!(f, "ContactRequest(<{} devices>)", card.devices.certs.len())
            }
            ExtContent::RequestAccepted { replayed } => {
                write!(f, "RequestAccepted(<{} ids>)", replayed.len())
            }
            ExtContent::SyncInvite { .. } => write!(f, "SyncInvite"),
            ExtContent::SyncRefused { .. } => write!(f, "SyncRefused"),
            ExtContent::Gif { gif, .. } => {
                write!(f, "Gif(<{}x{}>)", gif.width, gif.height)
            }
            ExtContent::SyncGif { gif, .. } => {
                write!(f, "SyncGif(<{}x{}>)", gif.width, gif.height)
            }
            ExtContent::SyncGifSettings { settings, .. } => {
                write!(f, "SyncGifSettings(<{} providers>)", settings.enabled.len())
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

/// A GIF reference with a provider number other than 0 and an identifier of
/// 1 to [`MAX_GIF_ID_LEN`] printable ASCII bytes; Klipy's are `[a-z0-9-]`.
pub(crate) fn check_gif(gif: &GifRef) -> Result<()> {
    if gif.provider == 0 {
        return Err(CoreError::Malformed("GIF provider"));
    }
    if gif.id.is_empty() || gif.id.len() > MAX_GIF_ID_LEN {
        return Err(CoreError::Malformed("GIF identifier length"));
    }
    if !gif.id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(CoreError::Malformed("GIF identifier"));
    }
    if GifProviderId::from_u8(gif.provider) == Some(GifProviderId::Klipy)
        && !gif
            .id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(CoreError::Malformed("Klipy GIF identifier"));
    }
    Ok(())
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
            ExtContent::SyncSeen { seen } => (
                KIND_SYNC_SEEN,
                UnknownPolicy::Ignore,
                encode(
                    &seen
                        .iter()
                        .map(|e| (e.id.0, e.contact, e.at))
                        .collect::<Vec<_>>(),
                ),
            ),
            ExtContent::ContactRequest { card } => {
                (KIND_CONTACT_REQUEST, UnknownPolicy::Ignore, encode(&card))
            }
            ExtContent::RequestAccepted { replayed } => (
                KIND_REQUEST_ACCEPTED,
                UnknownPolicy::Ignore,
                encode(&replayed.iter().map(|id| id.0).collect::<Vec<_>>()),
            ),
            ExtContent::SyncInvite { to, at } => {
                (KIND_SYNC_INVITE, UnknownPolicy::Ignore, encode(&(to, at)))
            }
            ExtContent::SyncRefused { fp, at } => {
                (KIND_SYNC_REFUSED, UnknownPolicy::Ignore, encode(&(fp, at)))
            }
            ExtContent::Gif {
                gif,
                reply_to,
                ttl_secs,
            } => (
                KIND_GIF,
                UnknownPolicy::ShowUpdate,
                encode(&(gif, reply_to, ttl_secs)),
            ),
            // Shown like the `Gif` it copies: an old client that cannot
            // decode it must not lose track of my own message.
            ExtContent::SyncGif {
                to,
                gif,
                reply_to,
                ttl_secs,
            } => (
                KIND_SYNC_GIF,
                UnknownPolicy::ShowUpdate,
                encode(&(to, gif, reply_to, ttl_secs)),
            ),
            ExtContent::SyncGifSettings { settings, at } => (
                KIND_SYNC_GIF_SETTINGS,
                UnknownPolicy::Ignore,
                encode(&(settings, at)),
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
    /// identifier or with too many, for a `SyncSeen` without entry or with
    /// too many, for a `RequestAccepted` with more than [`MAX_REPLAYED`]
    /// identifiers, and for a delay out of
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
            KIND_SYNC_SEEN => {
                let seen: Vec<([u8; 16], Fingerprint, u64)> = parse(data)?;
                ExtContent::SyncSeen {
                    seen: seen
                        .into_iter()
                        .map(|(id, contact, at)| SeenEntry {
                            id: MessageId(id),
                            contact,
                            at,
                        })
                        .collect(),
                }
            }
            KIND_CONTACT_REQUEST => ExtContent::ContactRequest { card: parse(data)? },
            KIND_REQUEST_ACCEPTED => {
                let replayed: Vec<[u8; 16]> = parse(data)?;
                ExtContent::RequestAccepted {
                    replayed: replayed.into_iter().map(MessageId).collect(),
                }
            }
            KIND_SYNC_INVITE => {
                let (to, at) = parse(data)?;
                ExtContent::SyncInvite { to, at }
            }
            KIND_SYNC_REFUSED => {
                let (fp, at) = parse(data)?;
                ExtContent::SyncRefused { fp, at }
            }
            KIND_GIF => {
                let (gif, reply_to, ttl_secs) = parse(data)?;
                ExtContent::Gif {
                    gif,
                    reply_to,
                    ttl_secs,
                }
            }
            KIND_SYNC_GIF => {
                let (to, gif, reply_to, ttl_secs) = parse(data)?;
                ExtContent::SyncGif {
                    to,
                    gif,
                    reply_to,
                    ttl_secs,
                }
            }
            KIND_SYNC_GIF_SETTINGS => {
                let (settings, at) = parse(data)?;
                ExtContent::SyncGifSettings { settings, at }
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
            ExtContent::SyncSeen { seen } => {
                if (1..=MAX_SYNC_SEEN).contains(&seen.len()) {
                    Ok(())
                } else {
                    Err(CoreError::Malformed("number of seen messages"))
                }
            }
            ExtContent::RequestAccepted { replayed } => {
                if replayed.len() <= MAX_REPLAYED {
                    Ok(())
                } else {
                    Err(CoreError::Malformed("number of replayed messages"))
                }
            }
            ExtContent::Gif { gif, ttl_secs, .. } | ExtContent::SyncGif { gif, ttl_secs, .. } => {
                check_gif(gif)?;
                if ttl_in_bounds(*ttl_secs) {
                    Ok(())
                } else {
                    Err(CoreError::Malformed("ephemeral delay"))
                }
            }
            ExtContent::ContactRequest { .. }
            | ExtContent::SyncInvite { .. }
            | ExtContent::SyncRefused { .. }
            | ExtContent::SyncGifSettings { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::ContactCard;

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
    fn card() -> ContactCard {
        use crate::identity::{DeviceCertificate, DeviceKeys, DeviceList, RootIdentity};
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let (root, _) = RootIdentity::generate(&mut rng);
        let device = DeviceKeys::generate(&mut rng);
        let cert = DeviceCertificate::issue(&root, &device, "phone", 1).unwrap();
        let list = DeviceList::sign(&root, 1, vec![cert]).unwrap();
        let bundle = crate::handshake::PrekeySecrets::generate(&mut rng, 0).bundle(&device, false);
        ContactCard::sign(&root, "Alice", list, vec![bundle], Vec::new()).unwrap()
    }

    fn request_contents() -> [(ExtContent, u16); 4] {
        [
            (
                ExtContent::ContactRequest {
                    card: Box::new(card()),
                },
                KIND_CONTACT_REQUEST,
            ),
            (
                ExtContent::RequestAccepted { replayed: ids(2) },
                KIND_REQUEST_ACCEPTED,
            ),
            (
                ExtContent::SyncInvite {
                    to: Fingerprint([3; 32]),
                    at: 1_700_000_000,
                },
                KIND_SYNC_INVITE,
            ),
            (
                ExtContent::SyncRefused {
                    fp: Fingerprint([4; 32]),
                    at: 1_700_000_001,
                },
                KIND_SYNC_REFUSED,
            ),
        ]
    }

    #[test]
    fn request_kinds_roundtrip_and_are_ignored_when_unknown() {
        for (content, kind) in request_contents() {
            let Body::Ext {
                kind: k,
                unknown,
                data,
            } = content.to_body()
            else {
                panic!("Ext expected");
            };
            assert_eq!((k, unknown), (kind, UnknownPolicy::Ignore));
            assert_eq!(ExtContent::decode(k, &data).unwrap(), Some(content));
        }
    }

    #[test]
    fn request_accepted_caps_replayed() {
        let raw = |n: usize| {
            let ids: Vec<[u8; 16]> = ids(n).iter().map(|m| m.0).collect();
            postcard::to_allocvec(&ids).unwrap()
        };
        assert!(matches!(
            ExtContent::decode(KIND_REQUEST_ACCEPTED, &raw(MAX_REPLAYED + 1)),
            Err(CoreError::Malformed(_))
        ));
        assert!(
            ExtContent::decode(KIND_REQUEST_ACCEPTED, &raw(MAX_REPLAYED))
                .unwrap()
                .is_some()
        );
        assert!(
            ExtContent::decode(KIND_REQUEST_ACCEPTED, &raw(0))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn request_kinds_reject_trailing_bytes() {
        for (content, kind) in request_contents() {
            let Body::Ext { mut data, .. } = content.to_body() else {
                panic!("Ext expected");
            };
            data.push(0);
            assert!(
                matches!(
                    ExtContent::decode(kind, &data),
                    Err(CoreError::Malformed(_))
                ),
                "{kind}"
            );
        }
    }

    #[test]
    fn request_kinds_debug_shows_sizes_only() {
        let [(request, _), (accepted, _), (invite, _), (refused, _)] = request_contents();
        assert_eq!(format!("{request:?}"), "ContactRequest(<1 devices>)");
        assert_eq!(format!("{accepted:?}"), "RequestAccepted(<2 ids>)");
        assert_eq!(format!("{invite:?}"), "SyncInvite");
        assert_eq!(format!("{refused:?}"), "SyncRefused");
    }

    fn gif_ref(provider: u8, id: &str) -> crate::gif::GifRef {
        crate::gif::GifRef {
            provider,
            id: id.into(),
            width: 480,
            height: 270,
        }
    }

    #[test]
    fn gif_round_trips() {
        let c = ExtContent::Gif {
            gif: gif_ref(1, "hello-hi-662"),
            reply_to: None,
            ttl_secs: Some(3600),
        };
        let Body::Ext {
            kind,
            unknown,
            data,
        } = c.to_body()
        else {
            panic!()
        };
        assert_eq!((kind, unknown), (KIND_GIF, UnknownPolicy::ShowUpdate));
        assert_eq!(ExtContent::decode(kind, &data).unwrap(), Some(c));
    }

    #[test]
    fn sync_gif_is_show_update() {
        let c = ExtContent::SyncGif {
            to: Fingerprint([3; 32]),
            gif: gif_ref(1, "hello-hi-662"),
            reply_to: Some(MessageRef {
                id: [4; 16],
                by_sender: false,
            }),
            ttl_secs: None,
        };
        let Body::Ext {
            kind,
            unknown,
            data,
        } = c.to_body()
        else {
            panic!()
        };
        assert_eq!((kind, unknown), (KIND_SYNC_GIF, UnknownPolicy::ShowUpdate));
        assert_eq!(ExtContent::decode(kind, &data).unwrap(), Some(c));
    }

    #[test]
    fn sync_gif_settings_is_ignored_by_old_clients() {
        let mut enabled = std::collections::BTreeMap::new();
        enabled.insert(
            1u8,
            crate::gif::GifConsent {
                warning_version: 1,
                device: crate::identity::DeviceId([5; 16]),
                at: 1_700_000_000,
            },
        );
        let c = ExtContent::SyncGifSettings {
            settings: crate::gif::GifSettings {
                enabled,
                auto_load: true,
            },
            at: 1_700_000_001,
        };
        let Body::Ext {
            kind,
            unknown,
            data,
        } = c.to_body()
        else {
            panic!()
        };
        assert_eq!(
            (kind, unknown),
            (KIND_SYNC_GIF_SETTINGS, UnknownPolicy::Ignore)
        );
        assert_eq!(ExtContent::decode(kind, &data).unwrap(), Some(c));
    }

    #[test]
    fn gif_id_rules() {
        let decode_id = |provider: u8, id: &str| {
            let c = ExtContent::Gif {
                gif: gif_ref(provider, id),
                reply_to: None,
                ttl_secs: None,
            };
            let Body::Ext { kind, data, .. } = c.to_body() else {
                panic!()
            };
            ExtContent::decode(kind, &data)
        };
        let bad = |r: Result<Option<ExtContent>>| matches!(r, Err(CoreError::Malformed(_)));
        assert!(bad(decode_id(0, "abc")), "provider 0");
        assert!(bad(decode_id(1, "")), "empty id");
        assert!(bad(decode_id(2, "")), "empty id, unknown provider");
        assert!(bad(decode_id(1, &"a".repeat(65))), "65 bytes");
        assert!(decode_id(1, &"a".repeat(64)).unwrap().is_some(), "64 bytes");
        assert!(bad(decode_id(2, "ab\u{e9}")), "non ASCII");
        assert!(bad(decode_id(2, "a b")), "space");
        assert!(bad(decode_id(2, "a\u{7f}")), "DEL");
        assert!(decode_id(2, "ABC_x").unwrap().is_some(), "unknown provider");
        assert!(bad(decode_id(1, "ABC")), "Klipy is lowercase only");
        assert!(bad(decode_id(1, "a_b")), "Klipy has no underscore");
        assert!(decode_id(1, "a-b-9").unwrap().is_some());
    }

    #[test]
    fn gif_debug_hides_the_id() {
        let c = ExtContent::Gif {
            gif: gif_ref(1, "secret-id"),
            reply_to: None,
            ttl_secs: None,
        };
        assert!(!format!("{c:?}").contains("secret"));
    }
}
