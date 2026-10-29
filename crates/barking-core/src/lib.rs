//! barking-core : cœur de la messagerie Barking (sans réseau ni plateforme).

pub mod contact;
pub mod core;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod fragment;
pub mod handshake;
pub mod identity;
pub mod mailbox;
pub mod packet;
pub mod ratchet;
pub mod store;
pub mod transparency;

pub use self::core::{
    ContactSummary, Core, HistoryArchive, LinkBundle, LinkOffer, LinkOutcome, LinkRequest,
    ReceiveOutcome, SyncKind,
};
pub use self::core::{MAX_ARCHIVE_BYTES, MAX_LINK_BUNDLE_BYTES, MAX_LINK_FILE_BYTES};
pub use error::{CoreError, Result};
