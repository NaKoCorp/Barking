//! Errors seen by the apps. The detail goes to the logs, never to the
//! interface (spec §11.1): it holds no message content.

use barking_core::CoreError;
use barking_net::gif::GifError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BarkingError {
    /// The database lock was not obtained in time (the other process holds it).
    #[error("database locked by another process")]
    Locked,
    #[error("not found")]
    NotFound,
    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },
    #[error("storage error: {detail}")]
    Storage { detail: String },
    #[error("network error: {detail}")]
    Network { detail: String },
    #[error("internal error: {detail}")]
    Internal { detail: String },
    /// Device linking refused; the reason is a stable code, never text.
    #[error("link refused: {reason:?}")]
    LinkRefused { reason: LinkReason },
    /// The root key was sent to another device and its receipt is not yet
    /// acknowledged: no linking and no second transfer meanwhile.
    #[error("admin transfer pending")]
    AdminTransferPending,
    /// This device was removed from the account by a newer device list: it
    /// can only receive and read.
    #[error("device removed from the account")]
    DeviceRemoved,
    /// The administrator cannot leave on its own: it hands the root key to
    /// another device first (`transfer_and_leave`).
    #[error("this device is the administrator")]
    IsAdmin,
    /// The message is not `NotDelivered` (it left or is still waiting):
    /// nothing to send again.
    #[error("nothing to retry")]
    NothingToRetry,
    /// No session with any device of the contact (every device left their
    /// card): the message cannot be sealed again. Added last.
    #[error("no session")]
    NoSession,
    /// The contact is blocked: nothing is sent to it, and its card is not
    /// added again until it is unblocked. Added last.
    #[error("contact blocked")]
    ContactBlocked,
    /// A set of reactions over the limit of 20 emoji. Added last.
    #[error("too many emoji")]
    TooManyEmoji,
    /// A reaction that is not one emoji (several, text, too long, empty).
    /// Added last.
    #[error("invalid emoji")]
    InvalidEmoji,
    /// No such message in a conversation: a reply or a reaction to a row that
    /// is gone, never existed, or has no identifier the other side knows.
    /// Added last.
    #[error("message not found")]
    MessageNotFound,
    /// Refused until `retry_at` (Unix seconds): an invite to the same person
    /// less than 24 hours after the last one. Added last.
    #[error("too soon")]
    TooSoon { retry_at: u64 },
    /// A GIF call failed: `kind` says what the interface shows;
    /// `retry_after_secs` is the wait for `RateLimited`, 0 otherwise.
    /// Added last.
    #[error("GIF error: {kind:?}")]
    Gif {
        kind: GifErrorKind,
        retry_after_secs: u32,
    },
}

/// Why a GIF call failed (spec GIF §6.6, §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GifErrorKind {
    /// GIFs are not turned on for this provider: nothing was sent.
    NotEnabled,
    /// No key for this provider in this build, or the provider refuses it.
    NotConfigured,
    Offline,
    Unreachable,
    /// The provider's quota: retry after `retry_after_secs`.
    RateLimited,
    /// Removed, above the content filter, or an unknown provider.
    NotFound,
    TooLarge,
    /// A reply this client does not understand.
    Malformed,
}

impl From<GifError> for BarkingError {
    fn from(e: GifError) -> Self {
        let (kind, retry_after_secs) = match e {
            GifError::NotEnabled => (GifErrorKind::NotEnabled, 0),
            GifError::NotConfigured => (GifErrorKind::NotConfigured, 0),
            GifError::Offline => (GifErrorKind::Offline, 0),
            GifError::Unreachable => (GifErrorKind::Unreachable, 0),
            GifError::RateLimited { retry_after_secs } => {
                (GifErrorKind::RateLimited, retry_after_secs)
            }
            GifError::NotFound => (GifErrorKind::NotFound, 0),
            GifError::TooLarge => (GifErrorKind::TooLarge, 0),
            GifError::Malformed => (GifErrorKind::Malformed, 0),
        };
        BarkingError::Gif {
            kind,
            retry_after_secs,
        }
    }
}

/// Why a link step was refused (spec iOS messaging §5.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LinkReason {
    /// The offer is older than its 10 minutes.
    Expired,
    /// The offer was already used, or replaced by a newer one.
    Used,
    /// The request or bundle does not belong to this offer or identity.
    Mismatch,
    /// Not a link file, or too large.
    Unreadable,
    /// This device is not waiting for a link.
    NoPending,
    /// Only the device holding the root can link new ones.
    NotAdmin,
}

impl BarkingError {
    /// A core error met during a link step.
    pub(crate) fn from_link(e: CoreError) -> Self {
        let reason = match e {
            CoreError::Link("offer expired") => LinkReason::Expired,
            CoreError::Link("offer missing or already used") => LinkReason::Used,
            CoreError::Link(
                "unreadable link file" | "link file too large" | "link bundle too large",
            ) => LinkReason::Unreadable,
            CoreError::Link("no pending link") => LinkReason::NoPending,
            CoreError::NotAdmin => LinkReason::NotAdmin,
            CoreError::Link(_) | CoreError::InvalidSignature | CoreError::Malformed(_) => {
                LinkReason::Mismatch
            }
            other => return other.into(),
        };
        BarkingError::LinkRefused { reason }
    }
}

impl BarkingError {
    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        BarkingError::InvalidInput {
            detail: detail.into(),
        }
    }

    pub(crate) fn storage(detail: impl ToString) -> Self {
        BarkingError::Storage {
            detail: detail.to_string(),
        }
    }

    pub(crate) fn internal(detail: impl ToString) -> Self {
        BarkingError::Internal {
            detail: detail.to_string(),
        }
    }
}

impl From<CoreError> for BarkingError {
    fn from(e: CoreError) -> Self {
        let detail = e.to_string();
        match e {
            CoreError::Malformed("alias already used by another contact") => {
                BarkingError::invalid("alias taken")
            }
            CoreError::InvalidSignature
            | CoreError::Malformed(_)
            | CoreError::TooLarge
            | CoreError::InvalidTtl
            | CoreError::InvalidPhrase => BarkingError::InvalidInput { detail },
            CoreError::UnknownContact => BarkingError::NotFound,
            CoreError::StoreLocked | CoreError::Store(_) => BarkingError::Storage { detail },
            CoreError::AdminTransferPending => BarkingError::AdminTransferPending,
            CoreError::DeviceRemoved => BarkingError::DeviceRemoved,
            CoreError::IsAdmin => BarkingError::IsAdmin,
            CoreError::NothingToRetry => BarkingError::NothingToRetry,
            CoreError::NoSession => BarkingError::NoSession,
            CoreError::ContactBlocked => BarkingError::ContactBlocked,
            CoreError::TooManyEmoji => BarkingError::TooManyEmoji,
            CoreError::InvalidEmoji => BarkingError::InvalidEmoji,
            CoreError::MessageNotFound => BarkingError::MessageNotFound,
            CoreError::TooSoon { retry_at } => BarkingError::TooSoon { retry_at },
            _ => BarkingError::Internal { detail },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gif_errors_keep_their_kind_and_wait() {
        assert!(matches!(
            BarkingError::from(GifError::RateLimited {
                retry_after_secs: 42
            }),
            BarkingError::Gif {
                kind: GifErrorKind::RateLimited,
                retry_after_secs: 42
            }
        ));
        assert!(matches!(
            BarkingError::from(GifError::NotFound),
            BarkingError::Gif {
                kind: GifErrorKind::NotFound,
                retry_after_secs: 0
            }
        ));
    }

    /// The apps recognize a card too large for an invitation by this exact
    /// detail (Swift `BarkingError.isCardTooLarge`).
    #[test]
    fn too_large_is_invalid_input_data_too_large() {
        assert!(matches!(
            BarkingError::from(CoreError::TooLarge),
            BarkingError::InvalidInput { detail } if detail == "data too large"
        ));
    }
}
