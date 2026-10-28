//! barking-core : cœur de la messagerie Barking (sans réseau ni plateforme).

pub mod contact;
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

pub use error::{CoreError, Result};
