//! Core errors. No external input may cause a panic.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("cryptographic error")]
    Crypto,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("data too large")]
    TooLarge,
    #[error("unknown contact")]
    UnknownContact,
    #[error("no session")]
    NoSession,
    #[error("expired")]
    Expired,
    #[error("database locked")]
    StoreLocked,
    #[error("storage error: {0}")]
    Store(String),
    #[error("invalid recovery phrase")]
    InvalidPhrase,
    #[error("this device does not hold the root key")]
    NotAdmin,
    /// Device awaiting linking (`begin_link` without `finish_link`):
    /// local state, never caused by the content of a packet.
    #[error("device awaiting linking")]
    LinkPending,
    /// Linking refused; the reason is a fixed text. No state modified.
    #[error("linking refused: {0}")]
    Link(&'static str),
}

impl From<barking_packet::PacketError> for CoreError {
    fn from(e: barking_packet::PacketError) -> Self {
        match e {
            barking_packet::PacketError::Malformed(m) => CoreError::Malformed(m),
            barking_packet::PacketError::TooLarge => CoreError::TooLarge,
        }
    }
}

pub type Result<T> = core::result::Result<T, CoreError>;
