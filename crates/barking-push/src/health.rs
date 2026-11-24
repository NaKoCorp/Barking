//! APNs health of this relay, from the relay's own point of view. Replicas
//! share one identity: one whose sends fail on its side (bad credentials,
//! no route to APNs, APNs down) declares itself unavailable so nodes go to
//! another replica. Pure state machine; the clock is passed in.

use std::time::{Duration, Instant};

use barking_proto::push::ApnsEnv;

use crate::server::PushOutcome;

/// Consecutive relay-side failures that make the relay unavailable.
pub const FAULT_STREAK: u32 = 5;
/// Unavailable when this long without a success while pushes are attempted.
pub const NO_SUCCESS_FOR: Duration = Duration::from_secs(60);
/// How often an unavailable relay probes APNs to see if it recovered.
pub const PROBE_EVERY: Duration = Duration::from_secs(30);

/// True when the failure is ours (timeout, auth, APNs 5xx) rather than the
/// device's or the request's: those must not make the relay step down.
pub fn is_relay_fault(o: PushOutcome) -> bool {
    matches!(o, PushOutcome::Failed(0 | 403 | 500..=599))
}

#[derive(Debug)]
pub struct ApnsHealth {
    streak: u32,
    /// Last success, or creation time when there was none yet.
    last_success: Instant,
    /// A push was recorded since `last_success`.
    tried_since: bool,
    fault_env: ApnsEnv,
}

impl ApnsHealth {
    pub fn new(now: Instant) -> Self {
        Self {
            streak: 0,
            last_success: now,
            tried_since: false,
            fault_env: ApnsEnv::Production,
        }
    }

    pub fn record(&mut self, o: PushOutcome, env: ApnsEnv, now: Instant) {
        if is_relay_fault(o) {
            self.streak = self.streak.saturating_add(1);
            self.tried_since = true;
            self.fault_env = env;
        } else {
            self.streak = 0;
            self.last_success = now;
            self.tried_since = false;
        }
    }

    pub fn available(&self, now: Instant) -> bool {
        if self.streak >= FAULT_STREAK {
            return false;
        }
        let stale = now.saturating_duration_since(self.last_success) > NO_SUCCESS_FOR;
        !(self.tried_since && stale)
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
    fn sixty_seconds_without_success_while_trying() {
        let t0 = Instant::now();
        let mut h = ApnsHealth::new(t0);
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t0);
        assert!(h.available(t0));
        let t1 = t0 + secs(61);
        assert!(!h.available(t1));
        h.record(PushOutcome::Failed(503), ApnsEnv::Production, t1);
        assert!(!h.available(t1));
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
