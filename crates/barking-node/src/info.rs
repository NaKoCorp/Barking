//! Public self-report of the node (`Request::Info`, protocol 5). A background
//! task measures the node every `INFO_PERIOD`: fill of the storage and of the
//! subscription table, uptime, active subscriptions per push relay and the
//! link state of each such relay. A request only reads that precomputed
//! report from memory: no database read at request time, nothing is logged
//! per request, and a link state changes for callers once per period only
//! (no second-level timing of the wake-ups).
//!
//! `Info` is unauthenticated. The push link of a relay is therefore only
//! reported once at least `PUSH_LINK_MIN_SUBS` active subscriptions of this
//! node name it (below, `Unknown`, like a relay never contacted), and only
//! for the relay the caller names: the node never lists relays.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use barking_proto::{
    FillTier, MAX_SOFTWARE_LEN, NodeId, NodeInfoReport, NodeOrigin, PUSH_LINK_MIN_SUBS, PushLink,
};
use tokio::sync::watch;

use crate::server::unix_now;
use crate::wake::sender::LinkStates;
use crate::wake::{self, WakeConfig};
use crate::{NodeStore, Result, store};

/// Period of the measurements.
pub const INFO_PERIOD: Duration = Duration::from_secs(60);

/// What one round of measurements read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Measures {
    /// Bytes of stored packets and acknowledgements.
    pub stored_bytes: u64,
    /// Subscriptions held (what `max_subscriptions` caps).
    pub subscriptions: u64,
    /// Unexpired subscriptions per relay identity.
    pub per_relay: HashMap<NodeId, u64>,
}

/// The report as of the last round.
struct Precomputed {
    uptime_secs: u64,
    storage: FillTier,
    wake: Option<FillTier>,
    /// Relays with at least `PUSH_LINK_MIN_SUBS` active subscriptions, with
    /// their link state as of the round.
    busy_relays: HashMap<NodeId, PushLink>,
    origin: Option<NodeOrigin>,
}

/// Shared state of the `Info` report.
pub struct InfoState {
    started: Instant,
    storage_max_bytes: u64,
    /// `Some(max_subscriptions)` when the node takes subscriptions.
    wake_max: Option<u64>,
    protocol: u16,
    links: Option<Arc<LinkStates>>,
    report: Mutex<Precomputed>,
}

/// `CARGO_PKG_VERSION`, at most `MAX_SOFTWARE_LEN` bytes.
fn software() -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut end = v.len().min(MAX_SOFTWARE_LEN);
    while !v.is_char_boundary(end) {
        end -= 1;
    }
    v[..end].to_string()
}

impl InfoState {
    /// `storage_max_bytes`: the storage quota; `wake`: the `[wake]` section
    /// (cap on subscriptions, whether they are taken); `protocol`: highest
    /// protocol version served; `links`: link states of the wake sender, if
    /// any. Until the first `update`, the node reads as empty.
    pub fn new(
        storage_max_bytes: u64,
        wake: &WakeConfig,
        protocol: u16,
        links: Option<Arc<LinkStates>>,
    ) -> InfoState {
        let wake_max = wake.enabled.then_some(wake.max_subscriptions);
        InfoState {
            started: Instant::now(),
            storage_max_bytes,
            wake_max,
            protocol,
            links,
            report: Mutex::new(Precomputed {
                uptime_secs: 0,
                storage: FillTier::of(0, storage_max_bytes),
                wake: wake_max.map(|m| FillTier::of(0, m)),
                busy_relays: HashMap::new(),
                origin: None,
            }),
        }
    }

    fn report(&self) -> std::sync::MutexGuard<'_, Precomputed> {
        self.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the measurements of one round, with the link state of each
    /// busy relay as of now; the uptime is rounded down to the hour.
    pub fn update(&self, m: Measures) {
        let busy: HashMap<NodeId, PushLink> = m
            .per_relay
            .into_iter()
            .filter(|(_, n)| *n >= PUSH_LINK_MIN_SUBS)
            .map(|(id, _)| {
                let link = self
                    .links
                    .as_ref()
                    .map_or(PushLink::Unknown, |l| l.state(&id));
                (id, link)
            })
            .collect();
        let mut r = self.report();
        r.uptime_secs = self.started.elapsed().as_secs() / 3600 * 3600;
        r.storage = FillTier::of(m.stored_bytes, self.storage_max_bytes);
        r.wake = self.wake_max.map(|max| FillTier::of(m.subscriptions, max));
        r.busy_relays = busy;
    }

    /// Network origin of the node, once known.
    pub fn set_origin(&self, origin: Option<NodeOrigin>) {
        self.report().origin = origin;
    }

    /// The report; `relay`: the push relay whose link is asked about. The
    /// precomputed report only, link states included.
    pub fn snapshot(&self, relay: Option<NodeId>) -> NodeInfoReport {
        let r = self.report();
        let push_link = match (self.wake_max, relay) {
            (Some(_), Some(id)) => {
                Some(r.busy_relays.get(&id).copied().unwrap_or(PushLink::Unknown))
            }
            _ => None,
        };
        NodeInfoReport {
            software: software(),
            protocol: self.protocol,
            uptime_secs: r.uptime_secs,
            storage: r.storage,
            wake: r.wake,
            push_link,
            origin: r.origin.clone(),
        }
    }
}

/// Reads the measurements.
pub fn measure(store: &NodeStore, now: u64) -> Result<Measures> {
    Ok(Measures {
        stored_bytes: store::stored_bytes(store.conn())?,
        subscriptions: wake::count_subscriptions(store)?,
        per_relay: wake::count_by_relay(store, now)?,
    })
}

/// Measures the node now, then every `INFO_PERIOD`, until `stop`. `store`: a
/// read connection. A failed read keeps the previous report.
pub async fn info_loop(state: Arc<InfoState>, store: NodeStore, mut stop: watch::Receiver<bool>) {
    let mut store = Some(store);
    let mut tick = tokio::time::interval(INFO_PERIOD);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let Some(s) = store.take() else { return };
        let joined = tokio::task::spawn_blocking(move || {
            let m = measure(&s, unix_now());
            (s, m)
        })
        .await;
        let Ok((s, m)) = joined else { return };
        store = Some(s);
        match m {
            Ok(m) => state.update(m),
            Err(e) => tracing::warn!("info: storage read failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use barking_proto::{FillTier, NodeId, PUSH_LINK_MIN_SUBS, PushLink};

    use super::*;
    use crate::wake::WakeConfig;
    use crate::wake::sender::LinkStates;

    const R: NodeId = NodeId([7; 32]);

    fn measures(stored: u64, relay_subs: u64) -> Measures {
        Measures {
            stored_bytes: stored,
            subscriptions: relay_subs,
            per_relay: HashMap::from([(R, relay_subs)]),
        }
    }

    fn state(links: &Arc<LinkStates>) -> InfoState {
        InfoState::new(
            1000,
            &WakeConfig {
                enabled: true,
                max_subscriptions: 100,
            },
            5,
            Some(Arc::clone(links)),
        )
    }

    #[test]
    fn snapshot_uses_precomputed_tiers() {
        let links = Arc::new(LinkStates::default());
        let s = state(&links);
        s.update(measures(600, 60));
        let r = s.snapshot(None);
        assert_eq!(r.storage, FillTier::Medium);
        assert_eq!(r.wake, Some(FillTier::Medium));
        assert_eq!(r.protocol, 5);
        assert_eq!(r.software, env!("CARGO_PKG_VERSION"));
        assert_eq!(r.uptime_secs % 3600, 0);
        assert_eq!(r.push_link, None, "no relay asked, none reported");
        assert_eq!(r.origin, None);
        // Nothing is read at request time: a later change shows after a tick only.
        s.update(measures(960, 10));
        assert_eq!(s.snapshot(None).storage, FillTier::Full);
    }

    #[test]
    fn push_link_unknown_below_min_subs() {
        let links = Arc::new(LinkStates::default());
        let s = state(&links);
        links.record_ok(R);
        s.update(measures(0, PUSH_LINK_MIN_SUBS - 1));
        assert_eq!(s.snapshot(Some(R)).push_link, Some(PushLink::Unknown));
        s.update(measures(0, PUSH_LINK_MIN_SUBS));
        assert_eq!(s.snapshot(Some(R)).push_link, Some(PushLink::Ok));
        // A relay the node never heard of is `Unknown`, like a silent one.
        assert_eq!(
            s.snapshot(Some(NodeId([9; 32]))).push_link,
            Some(PushLink::Unknown)
        );
    }

    #[test]
    fn push_link_failing_in_backoff() {
        let links = Arc::new(LinkStates::default());
        let s = state(&links);
        links.record_ok(R);
        links.record_backoff(
            R,
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        );
        s.update(measures(0, PUSH_LINK_MIN_SUBS));
        assert_eq!(s.snapshot(Some(R)).push_link, Some(PushLink::Failing));
    }

    /// A link state change shows at the next round only, never at once:
    /// `Info` cannot time a wake-up to the second.
    #[test]
    fn push_link_changes_show_at_the_next_round_only() {
        let links = Arc::new(LinkStates::default());
        let s = state(&links);
        links.record_ok(R);
        s.update(measures(0, PUSH_LINK_MIN_SUBS));
        assert_eq!(s.snapshot(Some(R)).push_link, Some(PushLink::Ok));
        links.record_backoff(
            R,
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
        );
        assert_eq!(
            s.snapshot(Some(R)).push_link,
            Some(PushLink::Ok),
            "not before the round"
        );
        s.update(measures(0, PUSH_LINK_MIN_SUBS));
        assert_eq!(s.snapshot(Some(R)).push_link, Some(PushLink::Failing));
    }

    #[test]
    fn wake_disabled_reports_none() {
        let s = InfoState::new(
            1000,
            &WakeConfig {
                enabled: false,
                max_subscriptions: 100,
            },
            5,
            None,
        );
        s.update(measures(0, 50));
        let r = s.snapshot(Some(R));
        assert_eq!((r.wake, r.push_link), (None, None));
    }

    #[test]
    fn set_origin_is_reported() {
        let s = InfoState::new(1000, &WakeConfig::default(), 5, None);
        let o = barking_proto::NodeOrigin {
            asn: 64496,
            as_name: "EXAMPLE".into(),
            country: *b"FR",
            for_v6: false,
        };
        s.set_origin(Some(o.clone()));
        assert_eq!(s.snapshot(None).origin, Some(o));
    }
}
