//! `Device`: one identity on this device. Each call takes the lock, opens the
//! core, works, closes the core and releases the lock (spec iOS foundations
//! §3.3): the app never holds the database while suspended.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use barking_core::contact::ContactCard;
use barking_core::core::GifUse;
use barking_core::gif::GIF_PREVIEW;
use barking_core::store::{DeliverySummary, Direction};
use barking_core::{Core, CoreError};
use barking_net::geo::IpDb;
use barking_net::gif::{GifKeys, HttpsTransport};
use zeroize::Zeroize;

use crate::delivery::{Delivery, DeliveryState, delivery_of, state_of};
use crate::gif::GifInfo;
use crate::lock::DbLock;
use crate::reactions::{Quote, ReactionChip, chips_of, quote_of};
use crate::{BarkingError, guard};

/// Where the database lives and how to open it.
#[derive(Clone, uniffi::Record)]
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

/// Never prints the key.
impl std::fmt::Debug for DeviceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceConfig")
            .field("db_path", &self.db_path)
            .field("lock_path", &self.lock_path)
            .field("db_key", &"<redacted>")
            .field("lock_timeout_ms", &self.lock_timeout_ms)
            .field("allow_private", &self.allow_private)
            .finish()
    }
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
    /// Blocked: left out of `contacts` and `chat_summaries`, listed by
    /// `blocked_contacts`.
    #[uniffi(default = false)]
    pub blocked: bool,
}

impl From<barking_core::ContactSummary> for Contact {
    fn from(c: barking_core::ContactSummary) -> Self {
        Contact {
            fingerprint: c.fingerprint.to_string(),
            alias: c.alias,
            display_name: c.display_name,
            verified: c.verified,
            blocked: c.blocked,
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct Message {
    /// Stable, increasing: retries and unread marks refer to it.
    pub id: i64,
    pub outgoing: bool,
    pub body: String,
    /// Unix time, in seconds.
    pub at: u64,
    /// Delivery of a sent message; `None` for a received message, or one
    /// sent from another of my devices.
    #[uniffi(default = None)]
    pub delivery: Option<Delivery>,
    /// Route badge: `internet:N` (N distinct relay nodes), `None` while
    /// none is recorded.
    #[uniffi(default = None)]
    pub route: Option<String>,
    /// What this message answers, if it is a reply.
    #[uniffi(default = None)]
    pub reply_to: Option<Quote>,
    /// The emoji under it, in first-seen order (spec reply/reactions §5.4).
    #[uniffi(default = [])]
    pub reactions: Vec<ReactionChip>,
    /// Send state of my reactions toward the contact; `None` when I have no
    /// tracked send (nothing sent, or no session when I last changed them).
    #[uniffi(default = None)]
    pub my_reaction_state: Option<DeliveryState>,
    /// A placeholder for content this version cannot read (`body` is empty):
    /// the row asks for a newer version of the app.
    #[uniffi(default = false)]
    pub needs_update: bool,
    /// Delay of an ephemeral message, in seconds: it is erased that long
    /// after it is seen. `None` for a plain message.
    #[uniffi(default = None)]
    pub ttl_secs: Option<u32>,
    /// Unix seconds an ephemeral was first seen on one of my devices;
    /// `None` while it was never shown (or for a plain message). Until it
    /// is set, `expire_at` is only the "never shown" ceiling.
    #[uniffi(default = None)]
    pub seen_at: Option<u64>,
    /// Unix seconds an ephemeral is erased at (`seen_at + ttl_secs`, or the
    /// "never shown" ceiling); `None` for a plain message.
    #[uniffi(default = None)]
    pub expire_at: Option<u64>,
    /// The GIF this message is; `body` then reads "GIF" (never its title).
    /// `None` for a text.
    #[uniffi(default = None)]
    pub gif: Option<GifInfo>,
}

#[derive(uniffi::Object)]
pub struct Device {
    config: DeviceConfig,
    key: [u8; 32],
    /// The embedded IP base (`set_ipdb_path`), opened at its first use.
    ipdb: Mutex<IpDbSlot>,
    /// The requests as the last sync of this device left them (in memory
    /// only): the next sync reports those that moved since, whatever moved
    /// them (`net::RequestStamp`).
    pub(crate) requests_seen: Mutex<Option<Vec<crate::net::RequestStamp>>>,
    /// The app's GIF provider keys (`configure_gifs`), in memory only.
    pub(crate) gif_keys: Mutex<GifKeys>,
    /// The HTTPS client of the GIF calls, built at the first one.
    pub(crate) gif_transport: Mutex<Option<Arc<HttpsTransport>>>,
    /// GIF uses not counted yet: the database was busy (a sync) when the
    /// call ended. Counted with the next use (`gif::DeviceGate`).
    pub(crate) gif_uncounted: Mutex<Vec<(GifUse, u64)>>,
}

/// Where the IP base is and, once opened, the base. An open that failed is
/// not tried again until a new path is given.
#[derive(Default)]
struct IpDbSlot {
    path: Option<PathBuf>,
    db: Option<Arc<IpDb>>,
    tried: bool,
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
pub fn device_exists(mut config: DeviceConfig) -> bool {
    config.db_key.zeroize();
    db_exists(&config.db_path)
}

fn db_exists(db_path: &str) -> bool {
    Path::new(db_path).exists()
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Device {
    /// Takes the key out of `config` (spec §7.1): it lives once, in
    /// `Device::key`, zeroized when the device goes. Each call reopens the
    /// database, so the key stays for the device's lifetime. The copies made
    /// on the way in (Swift, the UniFFI buffer) are outside this crate.
    fn new(mut config: DeviceConfig) -> Result<Device, BarkingError> {
        let key: Result<[u8; 32], _> = config.db_key.as_slice().try_into();
        config.db_key.zeroize();
        let key = key.map_err(|_| BarkingError::invalid("database key must be 32 bytes"))?;
        Ok(Device {
            config,
            key,
            ipdb: Mutex::default(),
            requests_seen: Mutex::default(),
            gif_keys: Mutex::default(),
            gif_transport: Mutex::default(),
            gif_uncounted: Mutex::default(),
        })
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
        if db_exists(&device.config.db_path) {
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

    /// The IP base given to `set_ipdb_path`, opened at the first call that
    /// needs it and kept. `None` without a path, or if it does not open (a
    /// warning, once, without the path: origins then read as not in the
    /// base).
    pub(crate) fn ipdb(&self) -> Option<Arc<IpDb>> {
        let mut slot = self.ipdb.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.db.is_none() && !slot.tried {
            slot.tried = true;
            let path = slot.path.clone()?;
            match IpDb::open(&path) {
                Ok(db) => slot.db = Some(Arc::new(db)),
                Err(_) => tracing::warn!("the IP base does not open: origins are not checked"),
            }
        }
        slot.db.clone()
    }

    /// Runs `f` on the opened core, under the lock. The core is closed before
    /// the lock is released.
    pub(crate) fn with_core<T>(
        &self,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let lock = self.lock()?;
        self.run_on_core(lock, f)
    }

    /// Runs `f` like `with_core`, waiting at most `wait` for the lock (and
    /// never longer than the configured wait).
    pub(crate) fn with_core_within<T>(
        &self,
        wait: Duration,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let wait = wait.min(Duration::from_millis(self.config.lock_timeout_ms));
        let lock = DbLock::acquire(Path::new(&self.config.lock_path), wait)?;
        self.run_on_core(lock, f)
    }

    /// Runs the sync `f` like `with_core`, its lock open to the reads of
    /// this process (`with_core_read`) for its whole run.
    pub(crate) fn with_core_sync<T>(
        &self,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let lock = DbLock::acquire_for_sync(
            Path::new(&self.config.lock_path),
            Duration::from_millis(self.config.lock_timeout_ms),
        )?;
        self.run_on_core(lock, f)
    }

    /// Runs `f`, a read, on the opened core. During a sync of this process it
    /// does not wait for the sync: it joins its lock and reads through a
    /// read-only connection, beside the sync's (the core then leaves the due
    /// packets to the sync to expire, `Core::expire_due`). Otherwise as
    /// `with_core`. A write in `f` fails while it joins (`Storage`).
    pub(crate) fn with_core_read<T>(
        &self,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let lock = DbLock::acquire_read(
            Path::new(&self.config.lock_path),
            Duration::from_millis(self.config.lock_timeout_ms),
        )?;
        if !lock.joined() {
            return self.run_on_core(lock, f);
        }
        let mut core = Core::open_read(&PathBuf::from(&self.config.db_path), &self.key)?;
        let out = f(&mut core);
        drop(core);
        drop(lock);
        out
    }

    /// Runs `f` on the core opened under `lock`; the core is closed before
    /// the lock is released.
    fn run_on_core<T>(
        &self,
        lock: DbLock,
        f: impl FnOnce(&mut Core) -> Result<T, BarkingError>,
    ) -> Result<T, BarkingError> {
        let mut core = Core::open(&PathBuf::from(&self.config.db_path), &self.key, now())?;
        let out = f(&mut core);
        drop(core);
        drop(lock);
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
            let device = Device::new(config)?;
            if !db_exists(&device.config.db_path) {
                return Err(BarkingError::NotFound);
            }
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
            let device = Device::new(config)?;
            if !db_exists(&device.config.db_path) {
                return Err(BarkingError::NotFound);
            }
            Ok(Arc::new(device))
        })
    }

    /// Path of the embedded IP base (spec node transparency §6.3), which
    /// checks the origins the nodes declare. Read lazily, at the first call
    /// that shows an origin; nothing is checked before it is given. A new
    /// path replaces the base.
    pub fn set_ipdb_path(&self, path: String) {
        let mut slot = self.ipdb.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = IpDbSlot {
            path: Some(PathBuf::from(path)),
            ..IpDbSlot::default()
        };
    }

    pub fn fingerprint(&self) -> Result<String, BarkingError> {
        guard(|| self.with_core_read(|core| Ok(core.fingerprint().to_string())))
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

    /// Contacts, blocked ones left out (see `blocked_contacts`).
    pub fn contacts(&self) -> Result<Vec<Contact>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                Ok(core
                    .contacts()?
                    .into_iter()
                    .filter(|c| !c.blocked)
                    .map(Contact::from)
                    .collect())
            })
        })
    }

    /// Blocked contacts, for the list where they are unblocked.
    pub fn blocked_contacts(&self) -> Result<Vec<Contact>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                Ok(core
                    .contacts()?
                    .into_iter()
                    .filter(|c| c.blocked)
                    .map(Contact::from)
                    .collect())
            })
        })
    }

    /// Blocked fingerprints that are no contact (a blocked requester, or a
    /// blocked contact deleted since), sorted: `blocked_contacts` does not
    /// list them, and `unblock_contact` takes them.
    pub fn blocked_fingerprints(&self) -> Result<Vec<String>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                Ok(core
                    .blocked_strangers()?
                    .iter()
                    .map(ToString::to_string)
                    .collect())
            })
        })
    }

    /// Queues a text for `contact` (fingerprint or alias); the next sync sends it.
    /// `reply_to`: the row (`Message::id`) of a message of this conversation
    /// the text answers; `MessageNotFound` if it is not one (or is not
    /// quotable), nothing queued.
    /// `ttl_secs`: an ephemeral message, erased that long after it is seen
    /// (60 to 604 800 seconds, else `InvalidInput`, nothing queued); `None`
    /// for a plain one.
    #[uniffi::method(default(ttl_secs = None))]
    pub fn send_text(
        &self,
        contact: String,
        text: String,
        reply_to: Option<i64>,
        ttl_secs: Option<u32>,
    ) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                // The packets are queued by the core in its transaction.
                core.send_message(&fp, &text, reply_to, ttl_secs, now(), &mut rand::rng())?;
                Ok(())
            })
        })
    }

    pub fn messages_with(&self, contact: String) -> Result<Vec<Message>, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let fp = core.resolve(&contact)?;
                core.messages_with_delivery(&fp, now())?
                    .into_iter()
                    .map(|(m, d)| message_of(core, m, d))
                    .collect()
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

pub(crate) fn message_of(
    core: &Core,
    m: barking_core::store::MessageRow,
    delivery: Option<DeliverySummary>,
) -> Result<Message, BarkingError> {
    Ok(Message {
        route: crate::route::route_hint(core, m.id)?,
        reply_to: quote_of(core, &m)?,
        reactions: chips_of(core, &m)?,
        my_reaction_state: core.my_reaction_state(m.id)?.map(state_of),
        needs_update: m.placeholder,
        ttl_secs: m.ttl_secs,
        seen_at: m.seen_at,
        expire_at: m.expire_at,
        id: m.id,
        outgoing: m.direction == Direction::Out,
        body: shown_text(&m),
        gif: m.gif.map(GifInfo::from),
        at: m.at,
        delivery: delivery.map(delivery_of),
    })
}

/// The text the apps show for a message row: "GIF" for a GIF (its body is
/// empty, its title never shown outside the bubble), else its body.
pub(crate) fn shown_text(m: &barking_core::store::MessageRow) -> String {
    if m.gif.is_some() {
        GIF_PREVIEW.to_owned()
    } else {
        m.body.clone()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(key: Vec<u8>) -> DeviceConfig {
        DeviceConfig {
            db_path: "/nonexistent/barking.db".into(),
            lock_path: "/nonexistent/barking.lock".into(),
            db_key: key,
            lock_timeout_ms: 0,
            allow_private: false,
        }
    }

    /// The key handed over by the app lives once, in `Device::key`: the
    /// config's copy is zeroized as soon as it is taken (spec §7.1).
    #[test]
    fn config_key_zeroized_once_taken() {
        let device = Device::new(config(vec![7; 32])).unwrap();
        assert!(device.config.db_key.iter().all(|b| *b == 0));
        assert_eq!(device.key, [7; 32]);
    }

    /// Logs and panics never carry the key.
    #[test]
    fn debug_never_prints_the_key() {
        let shown = format!("{:?}", config(vec![0xAB; 32]));
        assert!(!shown.contains("171"), "{shown}");
    }
}
