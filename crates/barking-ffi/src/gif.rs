//! GIFs (spec GIF §6.6): the provider, the consent and its settings, search,
//! trending, the media of a received GIF, sending one, and the usage
//! counters of the Transparency screen.
//!
//! The requests run without the core: consent is read right before each
//! request and a use is counted after it (`DeviceGate`), each by opening
//! the core for that moment only. A request lasts up to the transport's
//! timeout; the database stays free for every other call meanwhile.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use barking_core::MyDevice;
use barking_core::core::GifUse;
use barking_core::gif::{GifRef, GifSettings};
use barking_core::identity::DeviceId;
use barking_net::gif::{
    self as net, ACTIVE_GIF_PROVIDER, GifError, GifGate, GifKeys, GifPage, GifTransport,
    HttpsTransport, klipy,
};

use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// Longest wait for the database to count a use: a sync holds it for its
/// whole run, and the result of a GIF call is not kept waiting for it.
const COUNT_WAIT: Duration = Duration::from_millis(200);

/// A GIF as a message carries it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifInfo {
    /// Provider number (1: Klipy).
    pub provider: u8,
    /// Identifier at the provider.
    pub id: String,
    /// Size of the rendition: the bubble reserves it before loading.
    pub width: u16,
    pub height: u16,
}

impl From<GifRef> for GifInfo {
    fn from(g: GifRef) -> Self {
        GifInfo {
            provider: g.provider,
            id: g.id,
            width: g.width,
            height: g.height,
        }
    }
}

impl From<GifInfo> for GifRef {
    fn from(g: GifInfo) -> Self {
        GifRef {
            provider: g.provider,
            id: g.id,
            width: g.width,
            height: g.height,
        }
    }
}

/// One search or trending result.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifResultInfo {
    /// What `send_gif` takes.
    pub gif: GifInfo,
    /// For accessibility in the picker only, never sent.
    pub title: String,
    /// Small MP4 for the picker grid, valid for this display only: never
    /// stored.
    pub preview_mp4_url: String,
}

/// One page of results.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifPageInfo {
    pub results: Vec<GifResultInfo>,
    /// Next page, if the provider has one.
    pub next: Option<u32>,
}

impl From<GifPage> for GifPageInfo {
    fn from(p: GifPage) -> Self {
        GifPageInfo {
            results: p
                .results
                .into_iter()
                .map(|r| GifResultInfo {
                    gif: GifInfo {
                        provider: r.provider,
                        id: r.id,
                        width: r.width,
                        height: r.height,
                    },
                    title: r.title,
                    preview_mp4_url: r.preview_mp4.into(),
                })
                .collect(),
            next: p.next,
        }
    }
}

/// A received GIF, for the bubble that shows it. Never stored.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifMediaInfo {
    pub mp4: Vec<u8>,
    /// Attribution, when the provider gives one.
    pub author: Option<String>,
    /// Accessibility label after loading ("GIF: {title}"), never shown
    /// outside the bubble.
    pub title: String,
}

/// The active provider, for the warning sheet and Settings › GIFs.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifProviderInfo {
    pub id: u8,
    pub name: String,
    /// Version of the warning shown now: what `enable_gif_provider` takes
    /// once the user accepted it.
    pub warning_version: u16,
    pub privacy_url: String,
}

/// The GIF settings for the active provider.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifSettingsInfo {
    /// Turned on, with a warning version still accepted.
    pub enabled: bool,
    /// Play GIFs automatically (kept while GIFs are off).
    pub auto_load: bool,
    /// While enabled and turned on from another of my devices still listed
    /// with a name: that name. `None` otherwise (turned on here, or see
    /// `enabled_from_unlisted_device`). Never empty.
    pub enabled_from_other_device: Option<String>,
    /// While enabled, when it was turned on (Unix seconds).
    pub enabled_at: Option<u64>,
    /// A consent for the active provider is stored, but for a warning older
    /// than `MIN_GIF_WARNING_VERSION`: GIFs are off (`enabled` is false) and
    /// the warning shows again marked "Updated".
    pub consent_outdated: bool,
    /// While enabled: turned on from another device of mine that is no
    /// longer listed (or has no name). The app says "another device" in its
    /// own language. Added last.
    pub enabled_from_unlisted_device: bool,
}

/// Counters of one day. `day` is the device's local date when the uses
/// happened, as days since 1970-01-01: `(unix + utc_offset_secs) / 86 400`,
/// the offset given with each call. Read it as a calendar date (its UTC
/// components), not as an instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GifUsageDayInfo {
    pub day: u32,
    pub searches: u32,
    pub shown: u32,
    pub sent: u32,
    /// Picker previews fetched.
    pub previews: u32,
}

/// Most GIF uses kept in memory while the database is busy; beyond it,
/// the oldest is dropped.
const UNCOUNTED_MAX: usize = 256;

/// Where consent was given, for "Turned on from {name}".
#[derive(Clone, Debug, PartialEq, Eq)]
enum ConsentOrigin {
    ThisDevice,
    /// A listed device of mine, with its name.
    Named(String),
    /// A device no longer listed, or listed without a name.
    Unlisted,
}

fn consent_origin(devices: &[MyDevice], from: DeviceId) -> ConsentOrigin {
    if devices.iter().any(|d| d.this_device && d.id == from) {
        return ConsentOrigin::ThisDevice;
    }
    devices
        .iter()
        .find(|d| d.id == from)
        .map(|d| d.name.clone())
        .filter(|n| !n.is_empty())
        .map_or(ConsentOrigin::Unlisted, ConsentOrigin::Named)
}

/// What `gif_settings` gives for `provider`, `enabled` being the core's
/// `gif_allowed`.
fn settings_info(
    settings: &GifSettings,
    provider: u8,
    enabled: bool,
    devices: &[MyDevice],
) -> GifSettingsInfo {
    let stored = settings.enabled.get(&provider);
    let consent_outdated =
        stored.is_some_and(|c| c.warning_version < barking_core::gif::MIN_GIF_WARNING_VERSION);
    let consent = stored.filter(|_| enabled);
    let origin = consent.map(|c| consent_origin(devices, c.device));
    let enabled_from_unlisted_device = origin == Some(ConsentOrigin::Unlisted);
    let enabled_from_other_device = match origin {
        Some(ConsentOrigin::Named(name)) => Some(name),
        _ => None,
    };
    GifSettingsInfo {
        enabled,
        auto_load: settings.auto_load,
        enabled_from_other_device,
        enabled_at: consent.map(|c| c.at),
        consent_outdated,
        enabled_from_unlisted_device,
    }
}

/// A use waiting to be counted: what, when (Unix seconds), and the
/// device's UTC offset then (seconds), which picks its local day.
type Uncounted = (GifUse, u64, i32);

/// Adds a waiting use, dropping the oldest beyond [`UNCOUNTED_MAX`].
fn push_uncounted(buf: &mut Vec<Uncounted>, item: Uncounted) {
    if buf.len() >= UNCOUNTED_MAX {
        let extra = buf.len() + 1 - UNCOUNTED_MAX;
        buf.drain(..extra);
    }
    buf.push(item);
}

/// Consent and counters of a GIF call, from the core opened for each one.
struct DeviceGate<'a> {
    device: &'a Device,
    /// The device's UTC offset at the call, in seconds: a use counts on
    /// that local day.
    utc_offset_secs: i32,
    /// Why the core could not answer a consent check, if it could not: the
    /// call is refused (fail closed) and reports this error rather than
    /// `NotEnabled`.
    error: Mutex<Option<BarkingError>>,
}

impl<'a> DeviceGate<'a> {
    fn new(device: &'a Device, utc_offset_secs: i32) -> Self {
        Self {
            device,
            utc_offset_secs,
            error: Mutex::default(),
        }
    }

    /// The call's result for the app: a refusal caused by a core that could
    /// not answer becomes that core's error.
    fn finish<T>(self, r: Result<T, GifError>) -> Result<T, BarkingError> {
        let error = self
            .error
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        match (r, error) {
            (Err(GifError::NotEnabled), Some(e)) => Err(e),
            (r, _) => r.map_err(Into::into),
        }
    }
}

impl GifGate for DeviceGate<'_> {
    /// A core that cannot answer (lock, storage) refuses; its error is kept
    /// for `finish`.
    fn allowed(&self, provider: u8) -> bool {
        match self
            .device
            .with_core_read(|core| Ok(core.gif_allowed(provider)?))
        {
            Ok(allowed) => allowed,
            Err(e) => {
                *self.error.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
                false
            }
        }
    }

    /// Counts `use_` with the uses left waiting before (`flush_uncounted`).
    fn record(&self, use_: GifUse) {
        self.device
            .flush_uncounted(Some((use_, now(), self.utc_offset_secs)));
    }
}

impl Device {
    /// Counts the waiting uses, `new` added. If the database stays busy
    /// past `COUNT_WAIT`, they keep waiting, in memory and capped. A use
    /// the core refuses to count is dropped: it never holds up the others.
    fn flush_uncounted(&self, new: Option<Uncounted>) {
        let mut uncounted = self
            .gif_uncounted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(item) = new {
            push_uncounted(&mut uncounted, item);
        }
        if uncounted.is_empty() {
            return;
        }
        let todo = std::mem::take(&mut *uncounted);
        let done = self.with_core_within(COUNT_WAIT, |core| {
            for (u, at, offset) in &todo {
                // Best effort: counters never fail a call.
                let _ = core.record_gif_use(*u, *at, *offset);
            }
            Ok(())
        });
        if done.is_err() {
            *uncounted = todo;
        }
    }

    fn gif_keys(&self) -> GifKeys {
        self.gif_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The HTTPS client, built at the first GIF call (no connection made).
    fn gif_transport(&self) -> Result<Arc<HttpsTransport>, BarkingError> {
        let mut slot = self
            .gif_transport
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(t) = slot.as_ref() {
            return Ok(Arc::clone(t));
        }
        let t = Arc::new(HttpsTransport::new()?);
        *slot = Some(Arc::clone(&t));
        Ok(t)
    }

    pub(crate) fn search_with(
        &self,
        t: &impl GifTransport,
        query: &str,
        page: u32,
        utc_offset_secs: i32,
    ) -> Result<GifPageInfo, BarkingError> {
        let keys = self.gif_keys();
        let gate = DeviceGate::new(self, utc_offset_secs);
        let r = crate::net::block_on(net::search(&gate, &keys, t, query, page))?;
        Ok(gate.finish(r)?.into())
    }

    fn trending_with(
        &self,
        t: &impl GifTransport,
        page: u32,
        utc_offset_secs: i32,
    ) -> Result<GifPageInfo, BarkingError> {
        let keys = self.gif_keys();
        let gate = DeviceGate::new(self, utc_offset_secs);
        let r = crate::net::block_on(net::trending(&gate, &keys, t, page))?;
        Ok(gate.finish(r)?.into())
    }

    pub(crate) fn preview_with(
        &self,
        t: &impl GifTransport,
        url: &str,
        utc_offset_secs: i32,
    ) -> Result<Vec<u8>, BarkingError> {
        let gate = DeviceGate::new(self, utc_offset_secs);
        let r = crate::net::block_on(net::preview(&gate, t, url))?;
        gate.finish(r)
    }

    fn data_with(
        &self,
        t: &impl GifTransport,
        provider: u8,
        id: &str,
        utc_offset_secs: i32,
    ) -> Result<GifMediaInfo, BarkingError> {
        let keys = self.gif_keys();
        let gate = DeviceGate::new(self, utc_offset_secs);
        let r = crate::net::block_on(net::data(&gate, &keys, t, provider, id))?;
        let media = gate.finish(r)?;
        Ok(GifMediaInfo {
            mp4: media.mp4,
            author: media.author,
            title: media.title,
        })
    }
}

#[uniffi::export]
impl Device {
    /// The app's provider keys, given at each start. Kept in memory only,
    /// never stored or logged. `None` or empty: that provider's calls give
    /// `NotConfigured`.
    pub fn configure_gifs(&self, klipy_key: Option<String>) {
        *self.gif_keys.lock().unwrap_or_else(PoisonError::into_inner) =
            GifKeys { klipy: klipy_key };
    }

    /// The active provider: what the warning sheet names and links.
    pub fn gif_provider(&self) -> GifProviderInfo {
        let p = klipy();
        debug_assert_eq!(p.id(), ACTIVE_GIF_PROVIDER);
        GifProviderInfo {
            id: ACTIVE_GIF_PROVIDER.as_u8(),
            name: p.name().to_owned(),
            warning_version: p.warning_version(),
            privacy_url: p.privacy_url().to_owned(),
        }
    }

    /// The settings for the active provider.
    pub fn gif_settings(&self) -> Result<GifSettingsInfo, BarkingError> {
        guard(|| {
            self.with_core_read(|core| {
                let provider = ACTIVE_GIF_PROVIDER.as_u8();
                let settings = core.gif_settings()?;
                let enabled = core.gif_allowed(provider)?;
                Ok(settings_info(
                    &settings,
                    provider,
                    enabled,
                    &core.my_devices(),
                ))
            })
        })
    }

    /// Turns `provider` on, once the user accepted version
    /// `warning_version` of its warning. Synchronized with my other
    /// devices. An unknown provider: `InvalidInput`.
    pub fn enable_gif_provider(
        &self,
        provider: u8,
        warning_version: u16,
    ) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core.enable_gif_provider(provider, warning_version, now(), &mut rand::rng())?)
            })
        })
    }

    /// Turns `provider` off, at once. Synchronized with my other devices.
    pub fn disable_gif_provider(&self, provider: u8) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core.disable_gif_provider(provider, now(), &mut rand::rng())?)
            })
        })
    }

    /// Plays GIFs without a tap, or not. Synchronized with my other devices.
    pub fn set_gif_auto_load(&self, on: bool) -> Result<(), BarkingError> {
        guard(|| self.with_core(|core| Ok(core.set_gif_auto_load(on, now(), &mut rand::rng())?)))
    }

    /// One page of search results from the active provider. Refused
    /// (`Gif { NotEnabled }`) without consent: nothing is sent.
    /// `utc_offset_secs`, the device's UTC offset now (seconds east of
    /// UTC), picks the local day the request counts on (`gif_usage`); the
    /// same for every GIF call.
    pub fn gif_search(
        &self,
        query: String,
        page: u32,
        utc_offset_secs: i32,
    ) -> Result<GifPageInfo, BarkingError> {
        guard(|| self.search_with(&*self.gif_transport()?, &query, page, utc_offset_secs))
    }

    /// One page of trending GIFs from the active provider, as `gif_search`.
    pub fn gif_trending(
        &self,
        page: u32,
        utc_offset_secs: i32,
    ) -> Result<GifPageInfo, BarkingError> {
        guard(|| self.trending_with(&*self.gif_transport()?, page, utc_offset_secs))
    }

    /// The MP4 of a received GIF, from the provider its message names.
    /// `NotEnabled` without consent for that provider (nothing is sent),
    /// `NotFound` for an unknown provider or a GIF gone.
    pub fn gif_data(
        &self,
        provider: u8,
        id: String,
        utc_offset_secs: i32,
    ) -> Result<GifMediaInfo, BarkingError> {
        guard(|| self.data_with(&*self.gif_transport()?, provider, &id, utc_offset_secs))
    }

    /// The small MP4 of a picker result (`GifResultInfo::preview_mp4_url`,
    /// as given), fetched by the core: consent checked right before the
    /// request, the provider's hosts only, counted in `gif_usage`. Kept
    /// nowhere. `Gif { NotEnabled }` without consent and
    /// `Gif { Malformed }` for another URL: nothing is sent.
    pub fn gif_preview(&self, url: String, utc_offset_secs: i32) -> Result<Vec<u8>, BarkingError> {
        guard(|| self.preview_with(&*self.gif_transport()?, &url, utc_offset_secs))
    }

    /// Queues the GIF `gif` for `contact` (fingerprint or alias), as
    /// `send_text` a text: the same `reply_to` and `ttl_secs` rules. Only
    /// the reference leaves; no provider is contacted. An invalid reference:
    /// `InvalidInput`, nothing queued. Counted as sent on the local day
    /// `utc_offset_secs` gives, as `gif_search`.
    #[uniffi::method(default(ttl_secs = None))]
    pub fn send_gif(
        &self,
        contact: String,
        gif: GifInfo,
        utc_offset_secs: i32,
        reply_to: Option<i64>,
        ttl_secs: Option<u32>,
    ) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                let gif = gif.into();
                core.send_gif(
                    &fp,
                    gif,
                    reply_to,
                    ttl_secs,
                    now(),
                    utc_offset_secs,
                    &mut rand::rng(),
                )?;
                Ok(())
            })
        })
    }

    /// Usage counters of the last `days` local days with a use, newest
    /// first (this device only). Counts the uses left waiting first, if the
    /// database is free.
    pub fn gif_usage(&self, days: u8) -> Result<Vec<GifUsageDayInfo>, BarkingError> {
        guard(|| {
            self.flush_uncounted(None);
            self.with_core_read(|core| {
                Ok(core
                    .gif_usage(days)?
                    .into_iter()
                    .map(|d| GifUsageDayInfo {
                        day: d.day,
                        searches: d.searches,
                        shown: d.shown,
                        sent: d.sent,
                        previews: d.previews,
                    })
                    .collect())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use url::Url;

    use super::*;
    use crate::device::{CreatedDevice, DeviceConfig};
    use crate::error::GifErrorKind;

    const SEARCH: &[u8] = include_bytes!("../../barking-net/tests/fixtures/klipy/search.json");

    fn config(dir: &tempfile::TempDir, key_byte: u8) -> DeviceConfig {
        DeviceConfig {
            db_path: dir.path().join("barking.db").display().to_string(),
            lock_path: dir.path().join("barking.lock").display().to_string(),
            db_key: vec![key_byte; 32],
            lock_timeout_ms: 1_000,
            allow_private: true,
        }
    }

    fn device(dir: &tempfile::TempDir, key_byte: u8, name: &str) -> Arc<Device> {
        let CreatedDevice { device, .. } =
            Device::create(config(dir, key_byte), format!("{name}-phone")).unwrap();
        device.set_display_name(name.to_owned()).unwrap();
        device
    }

    /// Alice and Bob know each other's card; no network.
    fn paired(da: &tempfile::TempDir, db: &tempfile::TempDir) -> (Arc<Device>, String) {
        let alice = device(da, 1, "Alice");
        let bob = device(db, 2, "Bob");
        let fb = alice
            .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
            .unwrap();
        bob.add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
            .unwrap();
        (alice, fb)
    }

    fn hello() -> GifInfo {
        GifInfo {
            provider: 1,
            id: "hello-hi-662".into(),
            width: 480,
            height: 270,
        }
    }

    fn is_gif_error(r: Result<impl std::fmt::Debug, BarkingError>, want: GifErrorKind) -> bool {
        matches!(r, Err(BarkingError::Gif { kind, retry_after_secs: 0 }) if kind == want)
    }

    #[test]
    fn ffi_gif_search_without_consent_is_not_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.configure_gifs(Some("KEY".into()));
        assert!(is_gif_error(
            d.gif_search("x".into(), 1, 0),
            GifErrorKind::NotEnabled
        ));
        assert!(is_gif_error(d.gif_trending(1, 0), GifErrorKind::NotEnabled));
        assert!(is_gif_error(
            d.gif_data(1, "hello-hi-662".into(), 0),
            GifErrorKind::NotEnabled
        ));
        assert!(d.gif_usage(7).unwrap().is_empty());
    }

    #[test]
    fn ffi_gif_without_key_is_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.enable_gif_provider(1, 1).unwrap();
        assert!(is_gif_error(
            d.gif_search("x".into(), 1, 0),
            GifErrorKind::NotConfigured
        ));
        d.configure_gifs(Some(String::new()));
        assert!(is_gif_error(
            d.gif_trending(1, 0),
            GifErrorKind::NotConfigured
        ));
    }

    #[test]
    fn ffi_gif_settings_default() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        assert_eq!(
            d.gif_settings().unwrap(),
            GifSettingsInfo {
                enabled: false,
                auto_load: false,
                enabled_from_other_device: None,
                enabled_at: None,
                consent_outdated: false,
                enabled_from_unlisted_device: false,
            }
        );
    }

    #[test]
    fn ffi_gif_settings_follow_changes() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.enable_gif_provider(1, 1).unwrap();
        d.set_gif_auto_load(true).unwrap();
        let s = d.gif_settings().unwrap();
        assert!(s.enabled && s.auto_load && !s.consent_outdated);
        // Turned on here: no other device to name.
        assert_eq!(s.enabled_from_other_device, None);
        assert!(!s.enabled_from_unlisted_device);
        assert!(s.enabled_at.is_some());
        d.disable_gif_provider(1).unwrap();
        let s = d.gif_settings().unwrap();
        // Auto-load is kept while GIFs are off.
        assert!(!s.enabled && s.auto_load && s.enabled_at.is_none());
        // Turned off is not outdated: the warning shows without "Updated".
        assert!(!s.consent_outdated);
        // A stale warning version is not consent, and says so.
        d.enable_gif_provider(1, 0).unwrap();
        let s = d.gif_settings().unwrap();
        assert!(!s.enabled && s.consent_outdated);
        assert_eq!(s.enabled_at, None);
        // Accepting the current text clears it.
        d.enable_gif_provider(1, barking_core::gif::MIN_GIF_WARNING_VERSION)
            .unwrap();
        let s = d.gif_settings().unwrap();
        assert!(s.enabled && !s.consent_outdated);
        assert!(matches!(
            d.enable_gif_provider(0, 1),
            Err(BarkingError::InvalidInput { .. })
        ));
    }

    #[test]
    fn ffi_gif_provider_is_klipy() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        let p = d.gif_provider();
        assert_eq!(p.id, 1);
        assert_eq!(p.name, "Klipy");
        assert!(p.warning_version >= barking_core::gif::MIN_GIF_WARNING_VERSION);
        assert_eq!(p.privacy_url, "https://klipy.com/support/privacy-policy");
    }

    #[test]
    fn ffi_message_exposes_gif() {
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (alice, fb) = paired(&da, &db);
        alice.send_gif(fb.clone(), hello(), 0, None, None).unwrap();
        let last = alice.messages_with(fb.clone()).unwrap().pop().unwrap();
        assert_eq!(last.gif, Some(hello()));
        assert_eq!(last.body, "GIF");
        assert_eq!(alice.gif_usage(1).unwrap()[0].sent, 1);
        // An invalid reference queues nothing.
        let bad = GifInfo {
            id: "Bad Id!".into(),
            ..hello()
        };
        assert!(matches!(
            alice.send_gif(fb.clone(), bad, 0, None, None),
            Err(BarkingError::InvalidInput { .. })
        ));
        assert_eq!(alice.messages_with(fb).unwrap().len(), 1);
    }

    /// A GIF shows as "GIF" wherever a message becomes text: the chat
    /// list, a quote, the pending list.
    #[test]
    fn ffi_gif_reads_gif_in_summaries_and_quotes() {
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (alice, fb) = paired(&da, &db);
        alice.send_gif(fb.clone(), hello(), 0, None, None).unwrap();
        let summaries = alice.chat_summaries().unwrap();
        let last = summaries[0].last.as_ref().unwrap();
        assert_eq!(last.body, "GIF");
        let gif_row = last.id;
        alice
            .send_text(fb.clone(), "nice".into(), Some(gif_row), None)
            .unwrap();
        let reply = alice.messages_with(fb).unwrap().pop().unwrap();
        let quote = reply.reply_to.unwrap();
        assert_eq!(quote.id, Some(gif_row));
        assert_eq!(quote.excerpt.as_deref(), Some("GIF"));
        let pending = alice.pending_packets().unwrap();
        let bodies: Vec<_> = pending.messages.iter().map(|m| m.body.as_str()).collect();
        assert!(bodies.contains(&"GIF"), "{bodies:?}");
    }

    #[test]
    fn ffi_log_variants_cover_gif_consent() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        assert!(crate::log_keys().contains(&"log.gif_consent".to_owned()));
        d.enable_gif_provider(1, 1).unwrap();
        let log = d.transparency_log(50, None, false).unwrap();
        assert!(log.iter().any(|e| e.key == "log.gif_consent"));
    }

    /// Transport that checks, during its request, that the core is free:
    /// other calls (a read and a write) go through while it runs.
    struct CoreFreeTransport {
        device: Arc<Device>,
    }

    impl GifTransport for CoreFreeTransport {
        async fn get(&self, _url: &Url, _max: usize) -> Result<Vec<u8>, GifError> {
            self.device
                .gif_settings()
                .expect("read during a GIF request");
            self.device
                .set_gif_auto_load(true)
                .expect("write during a GIF request");
            Ok(SEARCH.to_vec())
        }
    }

    #[test]
    fn ffi_gif_request_does_not_hold_the_core() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.enable_gif_provider(1, 1).unwrap();
        d.configure_gifs(Some("KEY".into()));
        let t = CoreFreeTransport { device: d.clone() };
        let page = d.search_with(&t, "hi", 1, 0).unwrap();
        assert!(!page.results.is_empty());
        assert!(d.gif_settings().unwrap().auto_load);
        assert_eq!(d.gif_usage(1).unwrap()[0].searches, 1);
    }

    /// A use that finds the database busy (a sync) is not lost: it is
    /// counted with the next use.
    #[test]
    fn ffi_gif_use_counted_later_when_the_database_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.with_core_sync(|_| {
            DeviceGate::new(&d, 0).record(GifUse::Search);
            Ok(())
        })
        .unwrap();
        assert_eq!(d.gif_uncounted.lock().unwrap().len(), 1);
        DeviceGate::new(&d, 0).record(GifUse::Shown);
        assert!(d.gif_uncounted.lock().unwrap().is_empty());
        let day = d.gif_usage(1).unwrap()[0];
        assert_eq!((day.searches, day.shown), (1, 1));
    }

    /// A transport that answers every request with `body`, recording URLs.
    struct Answer {
        body: Vec<u8>,
        urls: std::sync::Mutex<Vec<String>>,
    }

    impl GifTransport for Answer {
        async fn get(&self, url: &Url, _max: usize) -> Result<Vec<u8>, GifError> {
            self.urls.lock().unwrap().push(url.to_string());
            Ok(self.body.clone())
        }
    }

    const PREVIEW: &str = "https://static.klipy.com/ii/abc/preview.mp4";

    /// A preview goes only with consent, and counts as a preview.
    #[test]
    fn ffi_gif_preview_gated_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        let t = Answer {
            body: b"MP4".to_vec(),
            urls: std::sync::Mutex::default(),
        };
        assert!(is_gif_error(
            d.preview_with(&t, PREVIEW, 0),
            GifErrorKind::NotEnabled
        ));
        assert!(is_gif_error(
            d.gif_preview(PREVIEW.into(), 0),
            GifErrorKind::NotEnabled
        ));
        assert!(t.urls.lock().unwrap().is_empty());
        d.enable_gif_provider(1, 1).unwrap();
        assert_eq!(d.preview_with(&t, PREVIEW, 0).unwrap(), b"MP4".to_vec());
        assert!(is_gif_error(
            d.preview_with(&t, "https://cdn.example.com/a.mp4", 0),
            GifErrorKind::Malformed
        ));
        assert_eq!(t.urls.lock().unwrap().len(), 1);
        let day = d.gif_usage(1).unwrap()[0];
        assert_eq!((day.previews, day.searches), (1, 0));
        // Turned off again: nothing more is sent.
        d.disable_gif_provider(1).unwrap();
        assert!(is_gif_error(
            d.preview_with(&t, PREVIEW, 0),
            GifErrorKind::NotEnabled
        ));
        assert_eq!(t.urls.lock().unwrap().len(), 1);
    }

    fn my_device(id: u8, name: &str, this_device: bool) -> barking_core::MyDevice {
        barking_core::MyDevice {
            id: barking_core::identity::DeviceId([id; 16]),
            name: name.into(),
            issued_at: 0,
            this_device,
            admin: false,
        }
    }

    /// Turned on here: no name; on a listed device: its name; on a device
    /// no longer listed, or without a name: unlisted, which the app words
    /// in its own language. No English text crosses the FFI.
    #[test]
    fn ffi_gif_consent_origin_names_the_device_or_falls_back() {
        use barking_core::identity::DeviceId;
        let devices = [
            my_device(1, "iPhone", true),
            my_device(2, "iPad", false),
            my_device(3, "", false),
        ];
        assert_eq!(
            consent_origin(&devices, DeviceId([1; 16])),
            ConsentOrigin::ThisDevice
        );
        assert_eq!(
            consent_origin(&devices, DeviceId([2; 16])),
            ConsentOrigin::Named("iPad".into())
        );
        for unlisted in [3, 9] {
            assert_eq!(
                consent_origin(&devices, DeviceId([unlisted; 16])),
                ConsentOrigin::Unlisted
            );
        }
    }

    /// The settings carry the origin as data: a listed device by its
    /// name, one no longer listed by the flag alone; neither while off.
    #[test]
    fn ffi_gif_settings_name_the_origin_as_data() {
        use barking_core::gif::{GifConsent, MIN_GIF_WARNING_VERSION};
        use barking_core::identity::DeviceId;
        let devices = [my_device(1, "iPhone", true), my_device(2, "iPad", false)];
        let from = |id: u8| {
            let mut s = GifSettings::default();
            s.enabled.insert(
                1,
                GifConsent {
                    warning_version: MIN_GIF_WARNING_VERSION,
                    device: DeviceId([id; 16]),
                    at: 5,
                },
            );
            s
        };
        let named = settings_info(&from(2), 1, true, &devices);
        assert_eq!(named.enabled_from_other_device.as_deref(), Some("iPad"));
        assert!(!named.enabled_from_unlisted_device);
        let gone = settings_info(&from(9), 1, true, &devices);
        assert_eq!(gone.enabled_from_other_device, None);
        assert!(gone.enabled_from_unlisted_device);
        assert_eq!(gone.enabled_at, Some(5));
        let here = settings_info(&from(1), 1, true, &devices);
        assert_eq!(here.enabled_from_other_device, None);
        assert!(!here.enabled_from_unlisted_device);
        let off = settings_info(&from(9), 1, false, &devices);
        assert!(!off.enabled_from_unlisted_device && off.enabled_at.is_none());
    }

    /// A use counts on the local day of the offset given with its call:
    /// 19:00 at UTC-8 is the next day in UTC, still its own date here.
    #[test]
    fn ffi_gif_use_counts_on_the_local_day() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        let pst = -8 * 3600;
        let evening = 1_795_834_800;
        d.flush_uncounted(Some((GifUse::Search, evening, pst)));
        d.flush_uncounted(Some((GifUse::Shown, evening, 0)));
        let days = d.gif_usage(7).unwrap();
        let local = barking_core::core::local_day(evening, pst);
        assert_eq!(local + 1, barking_core::core::local_day(evening, 0));
        assert_eq!(
            days.iter()
                .map(|u| (u.day, u.searches, u.shown))
                .collect::<Vec<_>>(),
            [(local + 1, 0, 1), (local, 1, 0)]
        );
    }

    /// `gif_usage` counts the uses left waiting before it reads.
    #[test]
    fn ffi_gif_usage_shows_buffered_use() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.with_core_sync(|_| {
            DeviceGate::new(&d, 0).record(GifUse::Search);
            Ok(())
        })
        .unwrap();
        assert_eq!(d.gif_uncounted.lock().unwrap().len(), 1);
        assert_eq!(d.gif_usage(1).unwrap()[0].searches, 1);
        assert!(d.gif_uncounted.lock().unwrap().is_empty());
    }

    /// The waiting uses are capped: the oldest goes first.
    #[test]
    fn ffi_gif_uncounted_buffer_is_capped() {
        let mut buf = Vec::new();
        push_uncounted(&mut buf, (GifUse::Sent, 0, 0));
        for at in 1..=UNCOUNTED_MAX as u64 {
            push_uncounted(&mut buf, (GifUse::Search, at, 0));
        }
        assert_eq!(buf.len(), UNCOUNTED_MAX);
        assert_eq!(buf[0], (GifUse::Search, 1, 0));
        assert_eq!(
            buf[UNCOUNTED_MAX - 1],
            (GifUse::Search, UNCOUNTED_MAX as u64, 0)
        );
        assert_eq!(UNCOUNTED_MAX, 256);
    }

    /// A core that cannot answer refuses the request, with its own error:
    /// the interface must not say "GIFs are off" to a user who turned them
    /// on.
    #[test]
    fn ffi_gif_core_error_is_not_not_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let d = device(&dir, 1, "Alice");
        d.enable_gif_provider(1, 1).unwrap();
        // The same database under a wrong key: every read fails.
        let wrong = Device::at(config(&dir, 2)).unwrap();
        wrong.configure_gifs(Some("KEY".into()));
        assert!(matches!(
            wrong.gif_search("x".into(), 1, 0),
            Err(BarkingError::Storage { .. })
        ));
        assert!(matches!(
            wrong.gif_data(1, "hello-hi-662".into(), 0),
            Err(BarkingError::Storage { .. })
        ));
        // Without consent it still reads NotEnabled.
        let dir2 = tempfile::tempdir().unwrap();
        let off = device(&dir2, 1, "Bob");
        assert!(is_gif_error(
            off.gif_trending(1, 0),
            GifErrorKind::NotEnabled
        ));
    }
}
