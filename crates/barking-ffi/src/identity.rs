//! Identity: recovery from the 24 words, display name, my devices.

use std::sync::Arc;

use barking_core::Core;

use crate::device::{Device, DeviceConfig, now};
use crate::{BarkingError, guard};

/// One of my devices.
#[derive(Debug, uniffi::Record)]
pub struct MyDeviceInfo {
    pub name: String,
    /// Unix seconds.
    pub issued_at: u64,
    pub this_device: bool,
    /// Holds the root key: can link new devices.
    pub admin: bool,
}

/// Recovers an identity on this device from its 24 words. Contacts and
/// history are not restored (core behaviour).
#[uniffi::export]
pub fn recover_device(
    config: DeviceConfig,
    phrase: String,
    device_name: String,
) -> Result<Arc<Device>, BarkingError> {
    guard(move || {
        let device = Device::init(config, |path, key| {
            Core::recover(
                path,
                key,
                phrase.trim(),
                &device_name,
                now(),
                &mut rand::rng(),
            )
        })
        .map_err(|e| match e {
            BarkingError::InvalidInput { .. } => BarkingError::invalid("phrase"),
            other => other,
        })?;
        Ok(Arc::new(device))
    })
}

/// The English BIP-39 list, for the autocompletion of the recovery words.
#[uniffi::export]
pub fn bip39_words() -> Vec<String> {
    bip39::Language::English
        .word_list()
        .iter()
        .map(|w| (*w).to_owned())
        .collect()
}

#[uniffi::export]
impl Device {
    pub fn display_name(&self) -> Result<String, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.display_name()?)))
    }

    /// At most 64 bytes.
    pub fn set_display_name(&self, name: String) -> Result<(), BarkingError> {
        guard(|| self.with_core(|core| Ok(core.set_display_name(name.trim())?)))
    }

    pub fn my_devices(&self) -> Result<Vec<MyDeviceInfo>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core
                    .my_devices()
                    .into_iter()
                    .map(|d| MyDeviceInfo {
                        name: d.name,
                        issued_at: d.issued_at,
                        this_device: d.this_device,
                        admin: d.admin,
                    })
                    .collect())
            })
        })
    }
}
