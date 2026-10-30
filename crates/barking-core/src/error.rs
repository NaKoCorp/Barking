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
    /// Appareil en attente de liaison (`begin_link` sans `finish_link`) :
    /// état local, jamais causé par le contenu d'un paquet.
    #[error("appareil en attente de liaison")]
    LinkPending,
    /// Liaison refusée ; la raison est un texte fixe. Aucun état modifié.
    #[error("liaison refusée : {0}")]
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
