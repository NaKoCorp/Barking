//! Errors seen by the apps. The detail goes to the logs, never to the
//! interface (spec §11.1): it holds no message content.

use barking_core::CoreError;

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
            CoreError::InvalidSignature
            | CoreError::Malformed(_)
            | CoreError::TooLarge
            | CoreError::InvalidPhrase => BarkingError::InvalidInput { detail },
            CoreError::UnknownContact => BarkingError::NotFound,
            CoreError::StoreLocked | CoreError::Store(_) => BarkingError::Storage { detail },
            CoreError::AdminTransferPending => BarkingError::AdminTransferPending,
            CoreError::DeviceRemoved => BarkingError::DeviceRemoved,
            CoreError::IsAdmin => BarkingError::IsAdmin,
            CoreError::NothingToRetry => BarkingError::NothingToRetry,
            CoreError::NoSession => BarkingError::NoSession,
            _ => BarkingError::Internal { detail },
        }
    }
}
