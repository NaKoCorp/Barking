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
            _ => BarkingError::Internal { detail },
        }
    }
}
