//! Erreurs du module paquet. Aucune entrée extérieure ne doit provoquer de panique.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("données mal formées : {0}")]
    Malformed(&'static str),
    #[error("données trop volumineuses")]
    TooLarge,
}

pub type Result<T> = core::result::Result<T, PacketError>;
