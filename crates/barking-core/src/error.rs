//! Erreurs du cœur. Aucune entrée extérieure ne doit provoquer de panique.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("erreur cryptographique")]
    Crypto,
    #[error("signature invalide")]
    InvalidSignature,
    #[error("données mal formées : {0}")]
    Malformed(&'static str),
    #[error("données trop volumineuses")]
    TooLarge,
    #[error("contact inconnu")]
    UnknownContact,
    #[error("aucune session")]
    NoSession,
    #[error("expiré")]
    Expired,
    #[error("base verrouillée")]
    StoreLocked,
    #[error("erreur de stockage : {0}")]
    Store(String),
    #[error("phrase de récupération invalide")]
    InvalidPhrase,
    #[error("cet appareil ne détient pas la clé racine")]
    NotAdmin,
}

pub type Result<T> = core::result::Result<T, CoreError>;
