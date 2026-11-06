//! Identity: recovery from the 24 words, display name, my devices.

use std::sync::Arc;

use barking_core::Core;
use barking_core::identity::DeviceId;

use crate::device::{Device, DeviceConfig, now};
use crate::{BarkingError, guard};

/// One of my devices.
#[derive(Debug, uniffi::Record)]
pub struct MyDeviceInfo {
    /// Device identifier, 32 lowercase hex characters (`transfer_admin`).
    pub id: String,
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
                        id: to_hex(&d.id.0),
                        name: d.name,
                        issued_at: d.issued_at,
                        this_device: d.this_device,
                        admin: d.admin,
                    })
                    .collect())
            })
        })
    }

    /// Devices of `contact` (alias or fingerprint) as its card lists them.
    /// `this_device` and `admin` are always false: they are about my devices.
    pub fn contact_devices(&self, contact: String) -> Result<Vec<MyDeviceInfo>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core
                    .contact_devices(&fp)?
                    .into_iter()
                    .map(|(id, name, issued_at)| MyDeviceInfo {
                        id: to_hex(&id.0),
                        name,
                        issued_at,
                        this_device: false,
                        admin: false,
                    })
                    .collect())
            })
        })
    }

    /// Hands the root key to my device `device_id` (hex, from `my_devices`).
    /// This device keeps it until the target acknowledges it.
    pub fn transfer_admin(&self, device_id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = device_id_from_hex(&device_id)?;
            self.with_core(|core| Ok(core.transfer_admin(id, now(), &mut rand::rng())?))
        })
    }

    /// Hex identifier of the device a root key transfer awaits the ack of.
    pub fn admin_transfer_pending(&self) -> Result<Option<String>, BarkingError> {
        guard(|| {
            self.with_core(|core| Ok(core.admin_transfer_pending(now())?.map(|id| to_hex(&id.0))))
        })
    }

    /// Removes my device `device_id` (hex, from `my_devices`) from my account
    /// (administrator only). The new list goes out at the next sync. This
    /// device is refused (`InvalidInput`: use `transfer_and_leave`).
    pub fn remove_device(&self, device_id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = device_id_from_hex(&device_id)?;
            // The packets are in the outbox: the next sync sends them.
            self.with_core(|core| {
                core.remove_device(id, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// A linked device leaves the account: asks my other devices to remove
    /// it. Refused on the administrator (`IsAdmin`). `leave_ready` is then
    /// true: once a sync has sent the request, the app may wipe.
    pub fn leave(&self) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                core.leave(now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    /// The administrator leaves: hands the root key to `device_id`, then, at
    /// its ack, asks it to remove this device (`leave_ready`). If the
    /// transfer expires, nothing is sent and the root stays here.
    pub fn transfer_and_leave(&self, device_id: String) -> Result<(), BarkingError> {
        guard(|| {
            let id = device_id_from_hex(&device_id)?;
            self.with_core(|core| Ok(core.transfer_and_leave(id, now(), &mut rand::rng())?))
        })
    }

    /// The request to be removed is queued (`leave`, or `transfer_and_leave`
    /// after the ack): the app may wipe once a sync has sent it.
    pub fn leave_ready(&self) -> Result<bool, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.leave_ready()?)))
    }

    /// Set once a newer device list has removed this device from the account.
    pub fn removed(&self) -> Result<Option<RemovedInfo>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core.removed()?.map(|r| RemovedInfo {
                    version: r.version,
                    at: r.at,
                }))
            })
        })
    }
}

/// This device was removed from the account.
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct RemovedInfo {
    /// Version of the list that no longer contains it.
    pub version: u64,
    /// When this device learned it (Unix seconds).
    pub at: u64,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn device_id_from_hex(s: &str) -> Result<DeviceId, BarkingError> {
    let bad = || BarkingError::invalid("device identifier");
    if s.len() != 32 || !s.is_ascii() {
        return Err(bad());
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(DeviceId(id))
}
