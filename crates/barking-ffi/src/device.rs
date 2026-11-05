//! `Device`: one identity on this device. Each call takes the lock, opens the
//! core, works, closes the core and releases the lock (spec iOS foundations
//! §3.3): the app never holds the database while suspended.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::contact::ContactCard;
use barking_core::store::{Direction, MessageStatus};
use barking_core::{Core, CoreError};

use crate::lock::DbLock;
use crate::{BarkingError, guard};

/// Where the database lives and how to open it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceConfig {
    /// SQLCipher database, in the shared container.
    pub db_path: String,
    /// Lock file, next to the database.
    pub lock_path: String,
    /// 32-byte database key (from the keychain).
    pub db_key: Vec<u8>,
    /// Longest wait for the lock: 2 s in the extension, 10 s in the app.
    pub lock_timeout_ms: u64,
    /// Accept non-routable node addresses (development builds only).
    pub allow_private: bool,
}

/// A new identity and its recovery phrase, shown once.
#[derive(uniffi::Record)]
pub struct CreatedDevice {
    pub device: Arc<Device>,
    pub recovery_phrase: String,
}

#[derive(Debug, uniffi::Record)]
pub struct Contact {
    pub fingerprint: String,
    pub alias: Option<String>,
    pub display_name: String,
    pub verified: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct Message {
    /// Stable, increasing: retries and unread marks refer to it.
    pub id: i64,
    pub outgoing: bool,
    pub body: String,
    /// `queued`, `sent`, `delivered` or `failed`.
    pub status: String,
    /// Unix time, in seconds.
    pub at: u64,
    /// Expired before its ack: can be sent again.
    pub failed: bool,
}

#[derive(uniffi::Object)]
pub struct Device {
    config: DeviceConfig,
    key: [u8; 32],
}

/// New identity (`Device::create`). A free function: UniFFI constructors
/// return the object itself, not a record.
#[uniffi::export]
pub fn create_device(
    config: DeviceConfig,
    device_name: String,
) -> Result<CreatedDevice, BarkingError> {
    Device::create(config, device_name)
}

/// A database file is present (whether its key is right or not).
#[uniffi::export]
pub fn device_exists(config: DeviceConfig) -> bool {
    Path::new(&config.db_path).exists()
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Device {
    fn new(config: DeviceConfig) -> Result<Device, BarkingError> {
        let key: [u8; 32] = config
            .db_key
            .as_slice()
            .try_into()
            .map_err(|_| BarkingError::invalid("database key must be 32 bytes"))?;
        Ok(Device { config, key })
    }

    fn lock(&self) -> Result<DbLock, BarkingError> {
        DbLock::acquire(
            Path::new(&self.config.lock_path),
            Duration::from_millis(self.config.lock_timeout_ms),
        )
    }

    /// New identity. An existing database is never touched: `InvalidInput`.
    /// A creation that fails removes the file it started, so that the next
    /// attempt starts clean.
    pub fn create(
        config: DeviceConfig,
        device_name: String,
    ) -> Result<CreatedDevice, BarkingError> {
        guard(move || {
            let mut phrase = String::new();
            let device = Device::init(config, |path, key| {
                let (core, p) = Core::create(path, key, &device_name, now(), &mut rand::rng())?;
                phrase = p.as_str().to_owned();
                Ok::<_, CoreError>(core)
            })?;
            Ok(CreatedDevice {
                device: Arc::new(device),
                recovery_phrase: phrase,
            })
        })
    }

    /// Creates the database with `make`, under the lock, never over an
    /// existing one; removes the file if `make` fails.
    pub(crate) fn init<E: Into<BarkingError>>(
        config: DeviceConfig,
        make: impl FnOnce(&Path, &[u8; 32]) -> Result<Core, E>,
    ) -> Result<Device, BarkingError> {
        let device = Device::new(config)?;
        let lock = device.lock()?;
        // Checked under the lock: two creations cannot both pass.
        if device_exists(device.config.clone()) {
            return Err(BarkingError::invalid("database already exists"));
        }
        let path = PathBuf::from(&device.config.db_path);
        match make(&path, &device.key) {
            Ok(core) => drop(core),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(e.into());
            }
        }
        drop(lock);
        Ok(device)
    }

    pub(crate) fn allow_private(&self) -> bool {
        self.config.allow_private
    }

    /// Runs `f` on the opened core, under the lock. The core is closed before
    /// the lock is released.
    pub(crate) fn with_core<T>(
        &self,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let _lock = self.lock()?;
        let mut core = Core::open(&PathBuf::from(&self.config.db_path), &self.key, now())?;
        let out = f(&mut core);
        drop(core);
        out
    }
}

#[uniffi::export]
impl Device {
    /// Opens an existing identity: `NotFound` without a database, `Storage`
    /// if it does not open with this key.
    #[uniffi::constructor]
    pub fn open(config: DeviceConfig) -> Result<Arc<Device>, BarkingError> {
        guard(move || {
            if !device_exists(config.clone()) {
                return Err(BarkingError::NotFound);
            }
            let device = Device::new(config)?;
            device.with_core(|_| Ok(()))?;
            Ok(Arc::new(device))
        })
    }

    /// The existing identity, without opening it: no lock taken, nothing
    /// read. For the extension, whose time and lock budget go to the quick
    /// sync alone (spec iOS foundations §5.3). A wrong key shows at the first
    /// call (`Storage`).
    #[uniffi::constructor]
    pub fn at(config: DeviceConfig) -> Result<Arc<Device>, BarkingError> {
        guard(move || {
            if !device_exists(config.clone()) {
                return Err(BarkingError::NotFound);
            }
            Ok(Arc::new(Device::new(config)?))
        })
    }

    pub fn fingerprint(&self) -> Result<String, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.fingerprint().to_string())))
    }

    /// Signed contact card, as text (`ContactCard::to_text`).
    pub fn contact_card(&self, display_name: String) -> Result<String, BarkingError> {
        guard(|| self.with_core(|core| Ok(core.contact_card(&display_name)?.to_text())))
    }

    /// Adds a contact from its card; returns its fingerprint.
    pub fn add_contact(&self, card: String, alias: Option<String>) -> Result<String, BarkingError> {
        guard(|| {
            let card = ContactCard::from_text(&card).map_err(card_error)?;
            self.with_core(|core| {
                let fp = core
                    .add_contact(&card, alias.as_deref(), now(), &mut rand::rng())
                    .map_err(card_error)?;
                Ok(fp.to_string())
            })
        })
    }

    pub fn contacts(&self) -> Result<Vec<Contact>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core
                    .contacts()?
                    .into_iter()
                    .map(|c| Contact {
                        fingerprint: c.fingerprint.to_string(),
                        alias: c.alias,
                        display_name: c.display_name,
                        verified: c.verified,
                    })
                    .collect())
            })
        })
    }

    /// Queues a text for `contact` (fingerprint or alias); the next sync sends it.
    pub fn send_text(&self, contact: String, text: String) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                core.send_text(&fp, &text, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    pub fn messages_with(&self, contact: String) -> Result<Vec<Message>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                Ok(core
                    .messages_with(&fp)?
                    .into_iter()
                    .map(message_of)
                    .collect())
            })
        })
    }
}

/// A card that does not decode or verify is the caller's input.
fn card_error(e: CoreError) -> BarkingError {
    match e {
        CoreError::InvalidSignature | CoreError::Malformed(_) | CoreError::TooLarge => {
            BarkingError::invalid(format!("invalid contact card: {e}"))
        }
        other => other.into(),
    }
}

pub(crate) fn message_of(m: barking_core::store::MessageRow) -> Message {
    Message {
        id: m.id,
        failed: m.status == MessageStatus::Failed,
        outgoing: m.direction == Direction::Out,
        body: m.body,
        status: status_name(m.status).to_owned(),
        at: m.at,
    }
}

fn status_name(s: MessageStatus) -> &'static str {
    match s {
        MessageStatus::Queued => "queued",
        MessageStatus::Sent => "sent",
        MessageStatus::Delivered => "delivered",
        MessageStatus::Failed => "failed",
    }
}
