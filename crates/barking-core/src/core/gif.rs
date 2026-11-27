//! GIF settings of the account (spec §6.4, §6.5): which providers the user
//! turned on, after accepting their warning, and whether GIFs play without
//! a tap.
//!
//! A register, last writer wins: stored as `(settings, at, author)` under
//! [`META_GIF_SETTINGS`]. Each local change dates it `at` (strictly after
//! the stored date) and sends it whole to my other devices
//! (`SyncGifSettings`); a received register replaces mine only if
//! `(at, author)` is greater, the larger device identifier breaking a tie.
//! A provider this client does not know is kept as received and sent on,
//! never allowed.

use rand_core::CryptoRng;

use super::send::SealTime;
use super::{Core, MAX_FUTURE_SECS, META_GIF_SETTINGS, log, sync};
use crate::content::ExtContent;
use crate::gif::{GifConsent, GifProviderId, GifSettings, MIN_GIF_WARNING_VERSION};
use crate::identity::{DeviceId, DeviceKeys};
use crate::store::{MessageId, Queries};
use crate::transparency::{SyncKind, TransparencyEvent};
use crate::{CoreError, Result};

/// The stored register: settings, date of the change, device that made it.
type Register = (GifSettings, u64, DeviceId);

/// The register; never written: the defaults, dated 0.
fn read(q: &impl Queries) -> Result<Register> {
    Ok(q.get_meta::<Register>(META_GIF_SETTINGS)?
        .unwrap_or_else(|| (GifSettings::default(), 0, DeviceId([0; 16]))))
}

/// Whether a consent lets this build contact its provider: the provider is
/// known and the accepted warning is current.
fn effective(provider: u8, consent: &GifConsent) -> bool {
    GifProviderId::from_u8(provider).is_some() && consent.warning_version >= MIN_GIF_WARNING_VERSION
}

/// Logs a `GifConsent` for each provider turned on or off between `old` and
/// `new` (a renewed consent counts as turned on). Only what is effective is
/// logged: a stale or unknown-provider consent never claims that the
/// provider receives data.
fn log_changes(
    q: &impl Queries,
    old: &GifSettings,
    new: &GifSettings,
    remote: bool,
    now: u64,
) -> Result<()> {
    let providers = old.enabled.keys().chain(new.enabled.keys());
    let mut seen = std::collections::BTreeSet::new();
    for provider in providers {
        if !seen.insert(*provider) {
            continue;
        }
        let before = old.enabled.get(provider);
        let after = new.enabled.get(provider);
        if before == after {
            continue;
        }
        let was = before.is_some_and(|c| effective(*provider, c));
        let is = after.is_some_and(|c| effective(*provider, c));
        if !was && !is {
            continue;
        }
        let event = TransparencyEvent::GifConsent {
            provider: *provider,
            enabled: is,
            remote,
        };
        log(q, now, None, &event)?;
    }
    Ok(())
}

/// Queues the stored register for my other devices (`SyncGifSettings`),
/// under a fresh message identifier. Never written (date 0): nothing to
/// send. Too large for a packet: `SyncSkipped` (see `seal_to_own`).
pub(super) fn send_settings(
    q: &impl Queries,
    device: &DeviceKeys,
    now: u64,
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let (settings, at, _) = read(q)?;
    if at == 0 {
        return Ok(());
    }
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let body = ExtContent::SyncGifSettings { settings, at }.to_body();
    sync::seal_to_own(
        q,
        device,
        &body,
        SyncKind::GifSettings,
        MessageId(id),
        SealTime::at(now),
        rng,
    )
    .map(drop)
}

/// Applies a register received from `sender`, one of my listed devices
/// (checked by the caller): kept only if `(at, sender)` is greater than the
/// stored `(at, author)`. Returns whether it was applied.
pub(super) fn apply_settings(
    q: &impl Queries,
    sender: DeviceId,
    settings: GifSettings,
    at: u64,
    now: u64,
) -> Result<bool> {
    let (old, stored_at, author) = read(q)?;
    // A date far ahead of my clock would win over every later change.
    if at > now.saturating_add(MAX_FUTURE_SECS) {
        return Ok(false);
    }
    if (at, sender) <= (stored_at, author) {
        return Ok(false);
    }
    log_changes(q, &old, &settings, true, now)?;
    q.put_meta(META_GIF_SETTINGS, &(settings, at, sender))?;
    Ok(true)
}

/// A provider number accepted by the local operations: known to this
/// client (provider 0 never is).
fn known(provider: u8) -> Result<GifProviderId> {
    GifProviderId::from_u8(provider).ok_or(CoreError::Malformed("GIF provider"))
}

impl Core {
    /// The GIF settings of the account (as last written here or received
    /// from another of my devices). Never written: nothing enabled, no
    /// automatic playing.
    pub fn gif_settings(&self) -> Result<GifSettings> {
        Ok(read(&self.store)?.0)
    }

    /// Whether this client may contact `provider`: known, enabled, and with
    /// an accepted warning at least `MIN_GIF_WARNING_VERSION`.
    pub fn gif_allowed(&self, provider: u8) -> Result<bool> {
        if GifProviderId::from_u8(provider).is_none() {
            return Ok(false);
        }
        Ok(self
            .gif_settings()?
            .enabled
            .get(&provider)
            .is_some_and(|c| c.warning_version >= MIN_GIF_WARNING_VERSION))
    }

    /// Turns `provider` on, once the user accepted version
    /// `warning_version` of its warning: the consent records this device
    /// and `now`. Synchronized with my other devices, logged. A provider
    /// this client does not know (0 included): `Malformed`.
    pub fn enable_gif_provider(
        &mut self,
        provider: u8,
        warning_version: u16,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        let provider = known(provider)?.as_u8();
        let consent = GifConsent {
            warning_version,
            device: self.device.public().id(),
            at: now,
        };
        self.change_gif_settings(now, rng, |s| {
            s.enabled.insert(provider, consent);
        })
    }

    /// Turns `provider` off, at once. Synchronized with my other devices
    /// even if it was not on here (a later change than one still on its
    /// way), logged if it was. Provider 0: `Malformed`.
    pub fn disable_gif_provider(
        &mut self,
        provider: u8,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        if provider == 0 {
            return Err(CoreError::Malformed("GIF provider"));
        }
        self.change_gif_settings(now, rng, |s| {
            s.enabled.remove(&provider);
        })
    }

    /// Plays GIFs without a tap (`on`) or not. Kept while GIFs are off.
    /// Synchronized with my other devices.
    pub fn set_gif_auto_load(
        &mut self,
        on: bool,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<()> {
        self.change_gif_settings(now, rng, |s| s.auto_load = on)
    }

    /// A local change: applied to the stored settings (an unknown provider
    /// stays), dated strictly after the stored register so that it wins
    /// over everything this device already knows, authored by this device,
    /// logged, and sent to my other devices, in one transaction. Always
    /// dated and sent, even when nothing changes here.
    fn change_gif_settings(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRng,
        change: impl FnOnce(&mut GifSettings),
    ) -> Result<()> {
        self.ensure_active()?;
        let Core { store, device, .. } = self;
        store.transaction(|tx| {
            let (old, stored_at, _) = read(tx)?;
            let mut settings = old.clone();
            change(&mut settings);
            let at = if stored_at >= now {
                stored_at.saturating_add(1)
            } else {
                now
            };
            log_changes(tx, &old, &settings, false, now)?;
            tx.put_meta(META_GIF_SETTINGS, &(settings, at, device.public().id()))?;
            send_settings(tx, device, now, rng)
        })
    }
}
