//! barking-core : cœur de la messagerie Barking (sans réseau ni plateforme).

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod fragment;
pub mod handshake;
pub mod identity;
pub mod mailbox;
pub mod packet;
pub mod ratchet;

pub use error::{CoreError, Result};
