//! barking-core: core of the Barking messenger (no network, no platform).

pub mod contact;
pub mod core;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod fragment {
    //! Fragmentation: re-exported from `barking-packet`.
    pub use barking_packet::fragment::*;
}
pub mod handshake;
pub mod identity;
pub mod mailbox;
pub mod packet {
    //! Universal packet: re-exported from `barking-packet`.
    pub use barking_packet::*;
}
pub mod ratchet;
pub mod store;
pub mod transparency;

pub use self::core::{
    ContactSummary, Core, HistoryArchive, LeaveState, LinkBundle, LinkOffer, LinkOutcome,
    LinkRequest, MyDevice, ReceiveOutcome, SyncKind, WatchedMailboxes,
};
pub use self::core::{MAX_ARCHIVE_BYTES, MAX_LINK_BUNDLE_BYTES, MAX_LINK_FILE_BYTES};
pub use error::{CoreError, Result};
