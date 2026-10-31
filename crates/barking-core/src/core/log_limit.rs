//! Log-write limiter for events a third party can trigger at will
//! (rejected frames, undecryptable packets, duplicates):
//! at most one entry per type and per reason every
//! `NOISY_EVENT_LOG_INTERVAL_SECS`. In memory only: a reopen
//! starts from zero.

use super::log;
use crate::Result;
use crate::packet::PacketId;
use crate::store::Queries;
use crate::transparency::TransparencyEvent;

/// Minimum interval, per noisy event type and per reason, between
/// two log entries.
pub const NOISY_EVENT_LOG_INTERVAL_SECS: u64 = 60;

/// Last log write per key (type, reason). The reasons are fixed
/// core texts: the number of keys is bounded.
#[derive(Default)]
pub(super) struct LogLimiter {
    last: Vec<(u8, String, u64)>,
}

/// Grouping key of a noisy event; `None`: never grouped.
fn key(e: &TransparencyEvent) -> Option<(u8, &str)> {
    match e {
        TransparencyEvent::FrameRejected { reason } => Some((0, reason)),
        TransparencyEvent::DecryptFailed { reason, .. } => Some((1, reason)),
        TransparencyEvent::DuplicateIgnored { .. } => Some((2, "")),
        _ => None,
    }
}

impl LogLimiter {
    /// `true` if `e` must be written at `now`; the write is then counted
    /// (if the transaction writing it fails, the entry is lost: at most
    /// one per interval).
    fn admit(&mut self, e: &TransparencyEvent, now: u64) -> bool {
        let Some((kind, reason)) = key(e) else {
            return true;
        };
        match self
            .last
            .iter_mut()
            .find(|(k, r, _)| *k == kind && r == reason)
        {
            Some((_, _, last)) => {
                if now.saturating_sub(*last) < NOISY_EVENT_LOG_INTERVAL_SECS {
                    return false;
                }
                *last = now;
            }
            None => self.last.push((kind, reason.to_owned(), now)),
        }
        true
    }
}

/// Logs `e`, unless it is noisy and an entry of the same type and
/// same reason was written less than one interval ago.
pub(super) fn log_limited(
    q: &impl Queries,
    limiter: &mut LogLimiter,
    at: u64,
    packet: Option<PacketId>,
    e: &TransparencyEvent,
) -> Result<()> {
    if limiter.admit(e, at) {
        log(q, at, packet, e)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(reason: &str) -> TransparencyEvent {
        TransparencyEvent::DecryptFailed {
            packet_id: PacketId([0; 16]),
            reason: reason.into(),
        }
    }

    #[test]
    fn one_entry_per_kind_and_reason_per_interval() {
        let mut l = LogLimiter::default();
        assert!(l.admit(&failed("a"), 100));
        assert!(!l.admit(&failed("a"), 159));
        assert!(l.admit(&failed("b"), 159));
        assert!(l.admit(&failed("a"), 160));
        let rejected = TransparencyEvent::FrameRejected { reason: "a".into() };
        assert!(l.admit(&rejected, 160));
        let opened = TransparencyEvent::AckVerified {
            for_packet: PacketId([0; 16]),
        };
        assert!(l.admit(&opened, 160));
        assert!(l.admit(&opened, 160));
    }
}
