//! Wake-up settings: the relay the app was built with and the APNs token iOS
//! gave it. Kept in the core's encrypted database, read by every full sync.

use barking_net::push::PushConfig;
use barking_proto::NodeId;
use barking_proto::push::{ApnsEnv, MAX_APNS_TOKEN, RelayRef};

use crate::device::Device;
use crate::{BarkingError, guard};

/// The relay to wake this device through, and its APNs token.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PushSettings {
    /// DNS name or public IP of the relay.
    pub relay_host: String,
    pub relay_port: u16,
    /// Node identifier of the relay (52-character base32).
    pub relay_id: String,
    /// Identifier of the relay's sealing key.
    pub seal_key_id: u8,
    /// X25519 public sealing key of the relay (32 bytes).
    pub seal_public: Vec<u8>,
    /// APNs device token.
    pub apns_token: Vec<u8>,
    /// Token of the APNs sandbox (development builds).
    pub sandbox: bool,
}

impl TryFrom<PushSettings> for PushConfig {
    type Error = BarkingError;

    fn try_from(s: PushSettings) -> Result<Self, BarkingError> {
        let id: NodeId = s
            .relay_id
            .trim()
            .to_ascii_uppercase()
            .parse()
            .map_err(|_| BarkingError::invalid("relay identifier: 52-character base32 expected"))?;
        let relay = RelayRef {
            host: s.relay_host.trim().to_ascii_lowercase(),
            port: s.relay_port,
            id,
        };
        if !relay.well_formed() {
            return Err(BarkingError::invalid(
                "relay address: a DNS name or a public IP, and a port, expected",
            ));
        }
        let seal_public: [u8; 32] = s
            .seal_public
            .try_into()
            .map_err(|_| BarkingError::invalid("sealing key: 32 bytes expected"))?;
        if s.apns_token.is_empty() || s.apns_token.len() > MAX_APNS_TOKEN {
            return Err(BarkingError::invalid(format!(
                "APNs token: 1 to {MAX_APNS_TOKEN} bytes expected"
            )));
        }
        Ok(PushConfig {
            relay,
            seal_public,
            seal_key_id: s.seal_key_id,
            apns_token: s.apns_token,
            env: if s.sandbox {
                ApnsEnv::Sandbox
            } else {
                ApnsEnv::Production
            },
        })
    }
}

#[uniffi::export]
impl Device {
    /// Sets the wake-up settings (`None`: push off). The next full sync
    /// subscribes with them, or cancels the subscriptions held.
    pub fn set_push(&self, settings: Option<PushSettings>) -> Result<(), BarkingError> {
        guard(|| {
            let cfg = settings.map(PushConfig::try_from).transpose()?;
            self.with_core(|core| Ok(PushConfig::store(core, cfg.as_ref())?))
        })
    }
}
