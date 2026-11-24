//! APNs health of this relay, from the relay's own point of view. Replicas
//! share one identity: one whose sends fail on its side (bad credentials,
//! no route to APNs, APNs down) declares itself unavailable so nodes go to
//! another replica. Pure state machine; the clock is passed in.

use std::time::{Duration, Instant};

use barking_proto::push::ApnsEnv;

use crate::server::PushOutcome;

/// Consecutive relay-side failures that make the relay unavailable.
pub const FAULT_STREAK: u32 = 5;
/// Unavailable when relay faults keep coming this long after the first one
/// of an uninterrupted run (bound inclusive). Idle time does not count.
pub const NO_SUCCESS_FOR: Duration = Duration::from_secs(60);
/// How often an unavailable relay probes APNs to see if it recovered.
pub const PROBE_EVERY: Duration = Duration::from_secs(30);

/// True when the failure is ours (timeout, auth, APNs 5xx) rather than the
/// device's or the request's: those must not make the relay step down.
pub fn is_relay_fault(o: PushOutcome) -> bool {
    matches!(o, PushOutcome::Failed(0 | 403 | 500..=599))
}

/// Decided when an outcome is recorded, never by the clock alone: a quiet
/// relay whose last push failed stays available until more faults come.
#[derive(Debug)]
pub struct ApnsHealth {
    /// Relay faults in a row.
    streak: u32,
    /// First relay fault of the current run; `None` after a non-fault.
    failing_since: Option<Instant>,
    /// Set by a fault recorded `NO_SUCCESS_FOR` or more into a run.
    stale: bool,
    fault_env: ApnsEnv,
}

impl ApnsHealth {
    pub fn new(_now: Instant) -> Self {
        Self {
            streak: 0,
            failing_since: None,
            stale: false,
            fault_env: ApnsEnv::Production,
        }
    }

    pub fn record(&mut self, o: PushOutcome, env: ApnsEnv, now: Instant) {
        if is_relay_fault(o) {
            self.streak = self.streak.saturating_add(1);
            let since = *self.failing_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= NO_SUCCESS_FOR {
                self.stale = true;
            }
            self.fault_env = env;
        } else {
            // Any outcome that is not ours (including a probe answered 400,
            // 410 or 429) shows APNs takes our requests.
            self.streak = 0;
            self.failing_since = None;
            self.stale = false;
        }
    }

    /// Reads the state left by `record`; `now` is kept for callers and
    /// does not change the answer.
    pub fn available(&self, _now: Instant) -> bool {
        self.streak < FAULT_STREAK && !self.stale
    }

    /// Environment of the most recent relay fault: the one to probe.
    pub fn probe_env(&self) -> ApnsEnv {
        self.fault_env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn five_relay_faults_make_it_unavailable() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        for _ in 0..4 {
            h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
        }
        assert!(h.available(t0));
        h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
        assert!(!h.available(t0));
    }

    #[test]
    fn token_errors_do_not_count() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        for _ in 0..10 {
            h.record(PushOutcome::Unregistered, ApnsEnv::Production, t0);
            h.record(PushOutcome::Failed(400), ApnsEnv::Production, t0);
        }
        assert!(h.available(t0));
        for code in [413, 429, 404] {
            assert!(!is_relay_fault(PushOutcome::Failed(code)));
        }
        for code in [0, 403, 500, 503, 599] {
            assert!(is_relay_fault(PushOutcome::Failed(code)));
        }
        assert!(!is_relay_fault(PushOutcome::Sent));
    }

    #[test]
    fn a_non_relay_outcome_resets_the_streak() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        for interrupt in [PushOutcome::Failed(400), PushOutcome::Unregistered] {
            for _ in 0..4 {
                h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
            }
            h.record(interrupt, ApnsEnv::Production, t0);
            for _ in 0..4 {
                h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
            }
            assert!(h.available(t0));
            h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
            assert!(!h.available(t0));
            h.record(PushOutcome::Sent, ApnsEnv::Production, t0);
        }
    }

    #[test]
    fn a_success_restores_it() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        for _ in 0..5 {
            h.record(PushOutcome::Failed(0), ApnsEnv::Production, t0);
        }
        assert!(!h.available(t0));
        h.record(PushOutcome::Sent, ApnsEnv::Production, t0);
        assert!(h.available(t0));
    }

    #[test]
    fn a_single_fault_on_a_quiet_relay_keeps_it_available() {
        // Quiet relay: the last success is long gone, yet one fault alone
        // must not take it out of service.
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Sent, ApnsEnv::Production, t0);
        let t1 = t0 + secs(3600);
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t1);
        assert!(h.available(t1));
        // Also right after startup, with no success yet.
        let mut fresh = ApnsHealth::new(t0);
        fresh.record(PushOutcome::Failed(0), ApnsEnv::Production, t0 + secs(61));
        assert!(fresh.available(t0 + secs(61)));
    }

    #[test]
    fn faults_spanning_sixty_seconds_make_it_unavailable() {
        // The bound is inclusive: a fault recorded at exactly
        // `failing_since + NO_SUCCESS_FOR` takes the relay out.
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0);
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0 + secs(59));
        assert!(h.available(t0 + secs(59)));
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0 + secs(60));
        assert!(!h.available(t0 + secs(60)));
    }

    #[test]
    fn idle_time_after_a_fault_never_makes_it_unavailable() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Failed(403), ApnsEnv::Production, t0);
        assert!(h.available(t0 + secs(61)));
        assert!(h.available(t0 + secs(86_400)));
    }

    #[test]
    fn a_non_fault_between_faults_restarts_the_failing_run() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0);
        h.record(PushOutcome::Failed(400), ApnsEnv::Production, t0 + secs(30));
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0 + secs(40));
        // 70 s after the first fault, but only 30 s into the new run.
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0 + secs(70));
        assert!(h.available(t0 + secs(70)));
        h.record(
            PushOutcome::Failed(503),
            ApnsEnv::Production,
            t0 + secs(100),
        );
        assert!(!h.available(t0 + secs(100)));
    }

    #[test]
    fn a_probe_that_is_not_a_relay_fault_restores_a_stale_run() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Failed(0), ApnsEnv::Production, t0);
        h.record(PushOutcome::Failed(0), ApnsEnv::Production, t0 + secs(60));
        assert!(!h.available(t0 + secs(60)));
        h.record(PushOutcome::Failed(400), ApnsEnv::Production, t0 + secs(90));
        assert!(h.available(t0 + secs(90)));
    }

    #[test]
    fn idle_relay_stays_available() {
        let t0 = Instant::now();
        let h = ApnsHealth::new(t0);
        assert!(h.available(t0 + secs(600)));
    }

    #[test]
    fn probe_env_follows_last_fault() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        assert_eq!(h.probe_env(), ApnsEnv::Production);
        h.record(PushOutcome::Failed(403), ApnsEnv::Sandbox, t0);
        assert_eq!(h.probe_env(), ApnsEnv::Sandbox);
        h.record(PushOutcome::Failed(0), ApnsEnv::Production, t0);
        assert_eq!(h.probe_env(), ApnsEnv::Production);
    }
}
