//! barking-core : cœur de la messagerie Barking (sans réseau ni plateforme).

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod ratchet;

pub use error::{CoreError, Result};
