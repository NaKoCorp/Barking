//! Push link probes, for the public `Info` report (spec §5.2). Every
//! `PROBE_PERIOD`, the node connects to each push relay listed in
//! `[info] probe_relays`, checks the relay's identity (`Hello` on a session
//! pinned on `RelayRef::id`) and closes the session; no wake-up is sent.
//!
//! The list comes from the operator only, never from subscriptions: a relay
//! is probed whether or not a user of this node subscribes through it, so
//! the reported state tells nothing of who uses which relay. A relay not
//! listed is never probed and reads `Unknown`, whether or not subscriptions
//! name it. The state depends on the relay only, never on when users
//! receive messages.
//!
//! A relay reads `Failing` only once one of its hosts has answered since the
//! start; a relay down from the start reads `Unknown`.
//!
//! Bounds: at most `MAX_PROBE_RELAYS` configured entries, at most
//! `MAX_HOSTS_PER_RELAY` hosts per relay identity, `PROBE_CONCURRENCY`
//! relays at once, the round cut at `ROUND_LIMIT`. Nothing here logs a
//! relay, a host or an address.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use barking_proto::push::RelayRef;
use barking_proto::{NodeId, PushLink};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::info::InfoState;

/// Period of the probe rounds.
pub const PROBE_PERIOD: Duration = Duration::from_secs(300);
/// Delay of the first round after the start (the first measurements of
/// `info_loop` come first).
const FIRST_ROUND_DELAY: Duration = Duration::from_secs(10);
/// Entries of `[info] probe_relays` at most.
pub const MAX_PROBE_RELAYS: usize = 32;
/// Hosts per relay identity in `[info] probe_relays` at most.
pub const MAX_HOSTS_PER_RELAY: usize = 4;
/// Relays probed at once.
pub const PROBE_CONCURRENCY: usize = 8;
/// A round still running after this is cut: relays not done keep no state
/// and read `Unknown`. Each probe is bounded (10 s) and the hosts of one
/// relay are tried in turn, so a full round needs at most `MAX_PROBE_RELAYS
/// * 10 s / PROBE_CONCURRENCY + MAX_HOSTS_PER_RELAY * 10 s` = 80 s.
pub const ROUND_LIMIT: Duration = Duration::from_secs(250);

/// Whether a relay answers with its identity.
pub trait RelayProbe: Send + Sync + 'static {
    fn reachable(&self, relay: &RelayRef) -> impl Future<Output = bool> + Send;
}

/// Probe rounds over the configured relays.
pub struct Prober<P> {
    probe: Arc<P>,
    /// Configured relays: each identity with its hosts, in configuration
    /// order.
    targets: Vec<(NodeId, Vec<RelayRef>)>,
    /// Relay identities that answered at least once since the start.
    reached: HashSet<NodeId>,
}

impl<P: RelayProbe> Prober<P> {
    /// `relays`: the `[info] probe_relays` entries, grouped here by
    /// identity.
    pub fn new(probe: P, relays: &[RelayRef]) -> Prober<P> {
        let mut targets: Vec<(NodeId, Vec<RelayRef>)> = Vec::new();
        for r in relays {
            match targets.iter_mut().find(|(id, _)| *id == r.id) {
                Some((_, hosts)) => {
                    if !hosts.contains(r) {
                        hosts.push(r.clone());
                    }
                }
                None => targets.push((r.id, vec![r.clone()])),
            }
        }
        Prober {
            probe: Arc::new(probe),
            targets,
            reached: HashSet::new(),
        }
    }

    /// One round over the configured relays: the state of each. `Ok` if a
    /// host answered; `Failing` if none did and the relay answered before;
    /// else (never answered, or cut by `ROUND_LIMIT`) not in the map, read
    /// `Unknown`.
    pub async fn round(&mut self) -> HashMap<NodeId, PushLink> {
        let sem = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
        let mut set = JoinSet::new();
        for (id, hosts) in self.targets.clone() {
            let probe = Arc::clone(&self.probe);
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    return (id, false);
                };
                for h in hosts {
                    if probe.reachable(&h).await {
                        return (id, true);
                    }
                }
                (id, false)
            });
        }
        let mut found = Vec::new();
        let _ = tokio::time::timeout(ROUND_LIMIT, async {
            while let Some(r) = set.join_next().await {
                if let Ok(x) = r {
                    found.push(x);
                }
            }
        })
        .await;
        set.abort_all();
        let mut states = HashMap::new();
        for (id, up) in found {
            if up {
                self.reached.insert(id);
                states.insert(id, PushLink::Ok);
            } else if self.reached.contains(&id) {
                states.insert(id, PushLink::Failing);
            }
        }
        states
    }
}

/// Probes `relays` (the `[info] probe_relays` entries) every
/// `PROBE_PERIOD`, until `stop`. The results are handed to `state`, which
/// publishes them at its next round (`InfoState::update`), never as a probe
/// ends.
pub async fn probe_loop<P: RelayProbe>(
    state: Arc<InfoState>,
    probe: P,
    relays: Vec<RelayRef>,
    mut stop: watch::Receiver<bool>,
) {
    let mut prober = Prober::new(probe, &relays);
    let start = tokio::time::Instant::now() + FIRST_ROUND_DELAY;
    let mut tick = tokio::time::interval_at(start, PROBE_PERIOD);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let states = tokio::select! {
            s = prober.round() => s,
            _ = stop.changed() => return,
        };
        state.set_probed(states);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::*;

    const R: NodeId = NodeId([7; 32]);

    pub(crate) fn at(host: &str, id: NodeId) -> RelayRef {
        RelayRef {
            host: host.into(),
            port: 4433,
            id,
        }
    }

    /// Answers for the hosts in `up` only; records every probe.
    #[derive(Clone, Default)]
    pub(crate) struct Fake {
        up: Arc<Mutex<HashSet<String>>>,
        calls: Arc<Mutex<Vec<RelayRef>>>,
    }

    impl Fake {
        pub(crate) fn set_up(&self, hosts: &[&str]) {
            *self.up.lock().unwrap() = hosts.iter().map(|h| (*h).to_string()).collect();
        }
        pub(crate) fn calls(&self) -> Vec<RelayRef> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl RelayProbe for Fake {
        fn reachable(&self, relay: &RelayRef) -> impl Future<Output = bool> + Send {
            self.calls.lock().unwrap().push(relay.clone());
            let up = self.up.lock().unwrap().contains(&relay.host);
            async move { up }
        }
    }

    #[tokio::test]
    async fn nothing_configured_nothing_probed() {
        let fake = Fake::default();
        fake.set_up(&["relay.example"]);
        let mut p = Prober::new(fake.clone(), &[]);
        assert!(p.round().await.is_empty());
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn configured_relay_is_probed_and_reported() {
        let fake = Fake::default();
        fake.set_up(&["relay.example"]);
        let mut p = Prober::new(fake.clone(), &[at("relay.example", R)]);
        assert_eq!(p.round().await.get(&R), Some(&PushLink::Ok));
        assert_eq!(fake.calls(), vec![at("relay.example", R)]);
    }

    #[tokio::test]
    async fn never_reached_is_unknown_then_failing_once_reached() {
        let fake = Fake::default();
        let mut p = Prober::new(fake.clone(), &[at("relay.example", R)]);
        assert!(p.round().await.is_empty(), "never reached: Unknown");
        fake.set_up(&["relay.example"]);
        assert_eq!(p.round().await.get(&R), Some(&PushLink::Ok));
        fake.set_up(&[]);
        assert_eq!(p.round().await.get(&R), Some(&PushLink::Failing));
    }

    /// The hosts of one identity are tried in configuration order, up to the
    /// first that answers; duplicates are probed once.
    #[tokio::test]
    async fn hosts_of_one_relay_in_order() {
        let fake = Fake::default();
        fake.set_up(&["b.example"]);
        let relays = [
            at("a.example", R),
            at("b.example", R),
            at("a.example", R),
            at("c.example", R),
        ];
        let mut p = Prober::new(fake.clone(), &relays);
        assert_eq!(p.round().await.get(&R), Some(&PushLink::Ok));
        let hosts: Vec<String> = fake.calls().into_iter().map(|r| r.host).collect();
        assert_eq!(hosts, ["a.example", "b.example"]);
    }

    #[tokio::test]
    async fn every_configured_relay_is_probed() {
        let fake = Fake::default();
        let relays: Vec<RelayRef> = (0..MAX_PROBE_RELAYS as u8)
            .map(|i| at("h.example", NodeId([i; 32])))
            .collect();
        let mut p = Prober::new(fake.clone(), &relays);
        p.round().await;
        let ids: HashSet<NodeId> = fake.calls().iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), MAX_PROBE_RELAYS);
    }
}
