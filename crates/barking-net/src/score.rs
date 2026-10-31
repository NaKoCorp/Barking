//! Reliability score of a node: the events that move it, the avoidance of a
//! node that falls below a threshold, and the slow recovery towards the
//! starting value so that a passing outage does not ban a node forever.
//!
//! The score never leaves the device.

use barking_core::transparency::AvoidReason;
use serde::{Deserialize, Serialize};

use crate::AVOID_SECS;
use crate::view::{NodeEntry, hour};

/// Starting score, and the value the recovery climbs back to.
pub const START_SCORE: f32 = 0.5;
/// A message the node had accepted is missing there.
pub const LOST_DELTA: f32 = -0.3;
/// Connection failure or timeout while another node answered.
pub const FAILURE_DELTA: f32 = -0.1;
/// A message the node had accepted is still there.
pub const FOUND_DELTA: f32 = 0.05;
/// A request succeeded.
pub const SUCCESS_DELTA: f32 = 0.02;
/// Below this score the node is avoided for `AVOID_SECS`.
pub const AVOID_BELOW: f32 = 0.2;
/// Recovery per elapsed day, up to `START_SCORE`.
pub const RECOVERY_PER_DAY: f32 = 0.05;

const DAY: u64 = 86_400;

/// Reputation of a node in `[0, 1]`, starting at 0.5.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score(pub(crate) f32);

impl Default for Score {
    fn default() -> Self {
        Score(START_SCORE)
    }
}

impl Score {
    /// A score clamped to `[0, 1]` and rounded to the thousandth, so that
    /// sums of deltas compare exactly with the thresholds; NaN gives the
    /// default.
    pub(crate) fn new(value: f32) -> Score {
        if value.is_nan() {
            Score::default()
        } else {
            Score((value.clamp(0.0, 1.0) * 1000.0).round() / 1000.0)
        }
    }

    pub fn value(self) -> f32 {
        self.0
    }
}

/// What happened with a node, as far as its score is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScoreEvent {
    /// A message it had accepted is missing (−0.3).
    Lost,
    /// Connection failure or timeout (−0.1, only if the network is up).
    Failure,
    /// A message it had accepted is still there (+0.05).
    Found,
    /// A request succeeded (+0.02).
    Success,
    /// No effect (`RateLimited`, `NodeFull`, `MailboxFull`, other refusals).
    Neutral,
}

impl ScoreEvent {
    fn delta(self) -> f32 {
        match self {
            ScoreEvent::Lost => LOST_DELTA,
            ScoreEvent::Failure => FAILURE_DELTA,
            ScoreEvent::Found => FOUND_DELTA,
            ScoreEvent::Success => SUCCESS_DELTA,
            ScoreEvent::Neutral => 0.0,
        }
    }

    fn avoid_reason(self) -> Option<AvoidReason> {
        match self {
            ScoreEvent::Lost => Some(AvoidReason::MessageLost),
            ScoreEvent::Failure => Some(AvoidReason::Unreachable),
            _ => None,
        }
    }
}

/// Applies `event` to the node's score. `network_up` is false when no node
/// answered during this synchronization: the client's own connection is at
/// fault and no score goes down. A negative event (`Lost`, `Failure`) that
/// leaves the score below `AVOID_BELOW` avoids the node for `AVOID_SECS` and
/// the reason is returned (once, when the avoidance starts); its score is
/// kept, not reset. Other events never start an avoidance.
pub fn apply(
    entry: &mut NodeEntry,
    event: ScoreEvent,
    now: u64,
    network_up: bool,
) -> Option<AvoidReason> {
    let delta = event.delta();
    if delta < 0.0 {
        if !network_up {
            return None;
        }
        // Recovery counts from the last drop.
        entry.decayed_at = hour(now);
    }
    entry.score = Score::new(entry.score.0 + delta);
    // Only a negative event starts an avoidance, so one always has a reason
    // to report.
    let reason = event.avoid_reason()?;
    if entry.score.0 < AVOID_BELOW && !entry.avoided(now) {
        entry.avoided_until = Some(hour(now.saturating_add(AVOID_SECS)));
        return Some(reason);
    }
    None
}

/// Recovery: +`RECOVERY_PER_DAY` per elapsed day for a score below
/// `START_SCORE`, up to it; ends the avoidance once its date is reached,
/// even with a score still below `AVOID_BELOW` (the next negative event
/// avoids it again, with its reason).
pub fn decay(entry: &mut NodeEntry, now: u64) {
    // A date from the future (clock gone back) restarts the count now.
    entry.decayed_at = entry.decayed_at.min(hour(now));
    let days = (now - entry.decayed_at) / DAY;
    if days > 0 {
        if entry.score.0 < START_SCORE {
            let gain = RECOVERY_PER_DAY * days.min(100) as f32;
            entry.score = Score::new((entry.score.0 + gain).min(START_SCORE));
        }
        entry.decayed_at += days * DAY;
    }
    if entry.avoided_until.is_some_and(|t| t <= now) {
        entry.avoided_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::record;

    const NOW: u64 = 1_800_000_000 - 1_800_000_000 % DAY;

    fn entry() -> NodeEntry {
        NodeEntry::new(record(0, NOW), NOW)
    }

    fn score(e: &NodeEntry) -> f32 {
        e.score.value()
    }

    #[test]
    fn score_events_apply_spec_values() {
        let mut e = entry();
        assert_eq!(score(&e), 0.5);
        assert_eq!(apply(&mut e, ScoreEvent::Success, NOW, true), None);
        assert_eq!(score(&e), 0.52);
        apply(&mut e, ScoreEvent::Found, NOW, true);
        assert_eq!(score(&e), 0.57);
        apply(&mut e, ScoreEvent::Failure, NOW, true);
        assert_eq!(score(&e), 0.47);
        apply(&mut e, ScoreEvent::Neutral, NOW, true);
        assert_eq!(score(&e), 0.47);
        apply(&mut e, ScoreEvent::Lost, NOW, true);
        assert_eq!(score(&e), 0.17);
        // Bounded to [0, 1].
        apply(&mut e, ScoreEvent::Lost, NOW, true);
        assert_eq!(score(&e), 0.0);
        for _ in 0..100 {
            apply(&mut e, ScoreEvent::Found, NOW, true);
        }
        assert_eq!(score(&e), 1.0);
        // One loss from the start is not below the threshold (0.2 exactly).
        let mut e = entry();
        assert_eq!(apply(&mut e, ScoreEvent::Lost, NOW, true), None);
        assert_eq!(score(&e), 0.2);
        assert!(!e.avoided(NOW));
    }

    #[test]
    fn network_down_lowers_no_score() {
        let mut e = entry();
        assert_eq!(apply(&mut e, ScoreEvent::Failure, NOW, false), None);
        assert_eq!(apply(&mut e, ScoreEvent::Lost, NOW, false), None);
        assert_eq!(score(&e), 0.5);
        // Gains still count.
        apply(&mut e, ScoreEvent::Success, NOW, false);
        assert_eq!(score(&e), 0.52);
    }

    #[test]
    fn below_threshold_avoided_seven_days_then_decays_back() {
        let mut e = entry();
        apply(&mut e, ScoreEvent::Lost, NOW, true);
        assert_eq!(
            apply(&mut e, ScoreEvent::Failure, NOW, true),
            Some(AvoidReason::Unreachable)
        );
        assert_eq!(score(&e), 0.1, "the score is kept, not reset");
        assert_eq!(e.avoided_until, Some(NOW + AVOID_SECS));
        assert!(e.avoided(NOW));
        // Already avoided: no second report, no extension.
        assert_eq!(apply(&mut e, ScoreEvent::Failure, NOW + 3600, true), None);
        assert_eq!(e.avoided_until, Some(NOW + AVOID_SECS));
        assert_eq!(score(&e), 0.0);
        // Recovery counts from the last drop: nothing within the first day.
        decay(&mut e, NOW + 3600 + DAY - 1);
        assert_eq!(score(&e), 0.0);
        decay(&mut e, NOW + 3600 + 6 * DAY);
        assert_eq!(score(&e), 0.3);
        assert!(e.avoided(NOW + 6 * DAY + 3600));
        decay(&mut e, NOW + AVOID_SECS);
        assert_eq!(e.avoided_until, None, "avoidance over");
        decay(&mut e, NOW + 3600 + 30 * DAY);
        assert_eq!(score(&e), 0.5, "recovery stops at the starting score");
        // A loss gives its own reason.
        let mut e = entry();
        e.score = Score::new(0.3);
        assert_eq!(
            apply(&mut e, ScoreEvent::Lost, NOW, true),
            Some(AvoidReason::MessageLost)
        );
        // A score above the start does not decay down.
        let mut e = entry();
        e.score = Score::new(0.9);
        decay(&mut e, NOW + 10 * DAY);
        assert_eq!(score(&e), 0.9);
    }

    #[test]
    fn only_negative_events_start_avoidance() {
        // The avoidance ran out while the score is still low.
        let mut e = entry();
        apply(&mut e, ScoreEvent::Lost, NOW, true);
        apply(&mut e, ScoreEvent::Lost, NOW, true);
        assert_eq!(score(&e), 0.0);
        // A loss late in the avoidance keeps the score low past its end.
        decay(&mut e, NOW + AVOID_SECS - DAY);
        assert_eq!(
            apply(&mut e, ScoreEvent::Lost, NOW + AVOID_SECS - DAY, true),
            None
        );
        decay(&mut e, NOW + AVOID_SECS);
        assert_eq!(e.avoided_until, None);
        assert!(score(&e) < AVOID_BELOW, "decay does not re-avoid silently");
        // Positive or neutral events never start an avoidance.
        for ev in [ScoreEvent::Success, ScoreEvent::Found, ScoreEvent::Neutral] {
            assert_eq!(apply(&mut e, ev, NOW + AVOID_SECS, true), None);
            assert_eq!(e.avoided_until, None);
        }
        // The next negative event does, with its reason.
        assert_eq!(
            apply(&mut e, ScoreEvent::Failure, NOW + AVOID_SECS, true),
            Some(AvoidReason::Unreachable)
        );
        assert!(e.avoided(NOW + AVOID_SECS));
    }

    #[test]
    fn decay_survives_clock_going_back() {
        let mut e = entry();
        e.score = Score::new(0.1);
        decay(&mut e, NOW - 30 * DAY);
        assert_eq!(score(&e), 0.1);
        decay(&mut e, NOW - 29 * DAY);
        assert_eq!(score(&e), 0.15);
    }
}
