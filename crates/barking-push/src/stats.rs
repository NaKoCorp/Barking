//! Relay counters: totals since the last report, logged and reset every
//! `log_interval_secs`. Counts only; nothing identifies a device or a node.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use tokio::sync::watch;

/// APNs error codes counted individually (spec §4); any other code, and a
/// failure without a status (network error, timeout), goes in the last slot.
pub const APNS_CODES: [u16; 9] = [400, 403, 404, 405, 410, 413, 429, 500, 503];
/// Slots of the per-code table: the known codes, then "other".
pub const APNS_SLOTS: usize = APNS_CODES.len() + 1;

fn apns_slot(code: u16) -> usize {
    APNS_CODES
        .iter()
        .position(|c| *c == code)
        .unwrap_or(APNS_CODES.len())
}

#[derive(Default)]
pub struct RelayStats {
    /// Sealed items received in `Wake` requests.
    pub wakes_in: AtomicU64,
    /// Items that did not open (garbage, unknown key, wrong key).
    pub invalid: AtomicU64,
    /// Opened items whose expiry day is past.
    pub expired: AtomicU64,
    /// Items dropped by the per-token limit.
    pub limited: AtomicU64,
    /// Items dropped because every push permit was taken.
    pub shed: AtomicU64,
    pub sent: AtomicU64,
    pub unregistered: AtomicU64,
    /// Failed pushes, all codes.
    pub failed: AtomicU64,
    /// Failed pushes by APNs code (`APNS_CODES`, then other/none).
    pub apns_errors: [AtomicU64; APNS_SLOTS],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub wakes_in: u64,
    pub invalid: u64,
    pub expired: u64,
    pub limited: u64,
    pub shed: u64,
    pub sent: u64,
    pub unregistered: u64,
    pub failed: u64,
    pub apns_errors: [u64; APNS_SLOTS],
}

impl RelayStats {
    /// Counts one failed push with APNs status `code` (0: no status).
    pub fn record_failure(&self, code: u16) {
        self.failed.fetch_add(1, Relaxed);
        self.apns_errors[apns_slot(code)].fetch_add(1, Relaxed);
    }

    /// Current values, counters untouched.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            wakes_in: self.wakes_in.load(Relaxed),
            invalid: self.invalid.load(Relaxed),
            expired: self.expired.load(Relaxed),
            limited: self.limited.load(Relaxed),
            shed: self.shed.load(Relaxed),
            sent: self.sent.load(Relaxed),
            unregistered: self.unregistered.load(Relaxed),
            failed: self.failed.load(Relaxed),
            apns_errors: std::array::from_fn(|i| self.apns_errors[i].load(Relaxed)),
        }
    }

    /// Current values; counters back to zero.
    pub fn take(&self) -> StatsSnapshot {
        StatsSnapshot {
            wakes_in: self.wakes_in.swap(0, Relaxed),
            invalid: self.invalid.swap(0, Relaxed),
            expired: self.expired.swap(0, Relaxed),
            limited: self.limited.swap(0, Relaxed),
            shed: self.shed.swap(0, Relaxed),
            sent: self.sent.swap(0, Relaxed),
            unregistered: self.unregistered.swap(0, Relaxed),
            failed: self.failed.swap(0, Relaxed),
            apns_errors: std::array::from_fn(|i| self.apns_errors[i].swap(0, Relaxed)),
        }
    }
}

/// Logs and resets the counters every `every` until `stop` turns true (or its
/// sender is dropped). A final report is logged on stop.
pub async fn report_loop(stats: Arc<RelayStats>, every: Duration, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // first tick is immediate
    loop {
        tokio::select! {
            _ = tick.tick() => log(&stats.take()),
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    log(&stats.take());
                    return;
                }
            }
        }
    }
}

fn log(s: &StatsSnapshot) {
    tracing::info!(
        wakes_in = s.wakes_in,
        invalid = s.invalid,
        expired = s.expired,
        limited = s.limited,
        shed = s.shed,
        sent = s.sent,
        unregistered = s.unregistered,
        failed = s.failed,
        "relay stats"
    );
    // Apple errors by code; only non-zero ones are logged.
    for (i, n) in s.apns_errors.iter().enumerate().filter(|(_, n)| **n > 0) {
        match APNS_CODES.get(i) {
            Some(code) => tracing::info!(code, count = *n, "apns errors"),
            None => tracing::info!(code = "other", count = *n, "apns errors"),
        }
    }
}
