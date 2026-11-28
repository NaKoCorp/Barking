//! GIF types shared by the message contents and the stored settings.
//!
//! A GIF travels as a reference (provider, identifier, size), never as
//! bytes: each device loads the image from the provider itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::DeviceId;

/// What a notification of a received GIF shows in place of a text.
pub const GIF_PREVIEW: &str = "GIF";

/// Longest GIF identifier, in bytes.
pub const MAX_GIF_ID_LEN: usize = 64;

/// A GIF provider this client knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GifProviderId {
    Klipy = 1,
}

impl GifProviderId {
    /// The provider numbered `value`, if this client knows it.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Klipy),
            _ => None,
        }
    }

    /// Number of the provider on the wire.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Name shown to the user.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Klipy => "Klipy",
        }
    }
}

/// Oldest version of a provider's warning that still counts as consent:
/// an older accepted version is treated as not enabled until the user
/// accepts the current text.
pub const MIN_GIF_WARNING_VERSION: u16 = 1;

/// Reference to a GIF held by a provider.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GifRef {
    /// Raw provider number, kept as is so an unknown provider survives.
    pub provider: u8,
    /// Identifier at the provider.
    pub id: String,
    pub width: u16,
    pub height: u16,
}

/// Consent given for one provider.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GifConsent {
    /// Version of the warning the user accepted.
    pub warning_version: u16,
    /// Device on which it was accepted.
    pub device: DeviceId,
    /// Date of the consent (seconds since the epoch).
    pub at: u64,
}

/// GIF settings of the account, synced between my devices.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct GifSettings {
    /// Consent per provider number.
    pub enabled: BTreeMap<u8, GifConsent>,
    /// Load GIFs without a tap.
    pub auto_load: bool,
}
