//! Errors of the packet module. No external input may cause a panic.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("data too large")]
    TooLarge,
}

pub type Result<T> = core::result::Result<T, PacketError>;
