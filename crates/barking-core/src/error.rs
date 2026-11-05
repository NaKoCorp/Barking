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
    /// The root key was sent to another of my devices and its receipt is
    /// not yet acknowledged: no linking and no second transfer meanwhile.
    #[error("admin transfer pending")]
    AdminTransferPending,
    /// A newer device list signed by my root no longer contains this
    /// device: it can only receive and read.
    #[error("this device was removed from the account")]
    DeviceRemoved,
    /// The administrator cannot leave on its own: it hands the root key to
    /// another device first (`transfer_and_leave`).
    #[error("this device is the administrator")]
    IsAdmin,
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
