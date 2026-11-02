//! Relay counters: totals since the last report, logged and reset every
//! `log_interval_secs`. Counts only; nothing identifies a device or a node.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use tokio::sync::watch;

#[derive(Default)]
pub struct RelayStats {
    /// Sealed items received in `Wake` requests.
    pub wakes_in: AtomicU64,
    /// Items that did not open (garbage, unknown key, wrong key).
    pub invalid: AtomicU64,
    /// Opened items whose expiry day is past.
    pub expired: AtomicU64,
    /// Items dropped by the per-token limit or because 256 pushes are in flight.
    pub limited: AtomicU64,
    pub sent: AtomicU64,
    pub unregistered: AtomicU64,
    pub failed: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub wakes_in: u64,
    pub invalid: u64,
    pub expired: u64,
    pub limited: u64,
    pub sent: u64,
    pub unregistered: u64,
    pub failed: u64,
}

impl RelayStats {
    /// Current values, counters untouched.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            wakes_in: self.wakes_in.load(Relaxed),
            invalid: self.invalid.load(Relaxed),
            expired: self.expired.load(Relaxed),
            limited: self.limited.load(Relaxed),
            sent: self.sent.load(Relaxed),
            unregistered: self.unregistered.load(Relaxed),
            failed: self.failed.load(Relaxed),
        }
    }

    /// Current values; counters back to zero.
    pub fn take(&self) -> StatsSnapshot {
        StatsSnapshot {
            wakes_in: self.wakes_in.swap(0, Relaxed),
            invalid: self.invalid.swap(0, Relaxed),
            expired: self.expired.swap(0, Relaxed),
            limited: self.limited.swap(0, Relaxed),
            sent: self.sent.swap(0, Relaxed),
            unregistered: self.unregistered.swap(0, Relaxed),
            failed: self.failed.swap(0, Relaxed),
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
        sent = s.sent,
        unregistered = s.unregistered,
        failed = s.failed,
        "relay stats"
    );
}
