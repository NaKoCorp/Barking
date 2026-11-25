//! Push link probes, for the public `Info` report (spec §5.2). Every
//! `PROBE_PERIOD`, the node connects to each push relay its live
//! subscriptions name, checks the relay's identity (`Hello` on a session
//! pinned on `RelayRef::id`) and closes the session; no wake-up is sent. The
//! state therefore depends on the relay only, never on when users receive
//! messages, and needs no subscription threshold.
//!
//! The host of a relay comes from whoever posted the subscription. A host
//! that once answered with the right identity is "proven" for that relay:
//! proven hosts are always probed first and outside the caps, and only they
//! can make a relay read `Failing`. A forged subscription naming a relay's
//! identity with a dead host, however many rows it buys, can at worst leave
//! a never-proven relay `Unknown`.
//!
//! Bounds: at most `MAX_PROBED_RELAYS` relay identities per round (proven
//! ones first, then by live subscriptions), at most `MAX_PROVEN_HOSTS` +
//! `MAX_NEW_HOSTS` hosts each, `PROBE_CONCURRENCY` relays at once, the round
//! cut at `ROUND_LIMIT`. Nothing here logs a relay, a host or an address.

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
/// Relay identities probed per round at most.
pub const MAX_PROBED_RELAYS: usize = 32;
/// Proven hosts kept per relay identity (most recently proven first).
pub const MAX_PROVEN_HOSTS: usize = 4;
/// Hosts never proven tried per relay identity and round (most live
/// subscriptions first).
pub const MAX_NEW_HOSTS: usize = 2;
/// Relays probed at once.
pub const PROBE_CONCURRENCY: usize = 8;
/// A round still running after this is cut: relays not done read `Unknown`.
/// Each probe is bounded (10 s), so a full round needs at most
/// `MAX_PROBED_RELAYS / PROBE_CONCURRENCY * (MAX_PROVEN_HOSTS +
/// MAX_NEW_HOSTS) * 10 s` = 240 s.
pub const ROUND_LIMIT: Duration = Duration::from_secs(250);

/// Whether a relay answers with its identity.
pub trait RelayProbe: Send + Sync + 'static {
    fn reachable(&self, relay: &RelayRef) -> impl Future<Output = bool> + Send;
}

/// Probe rounds, with the hosts proven so far.
pub struct Prober<P> {
    probe: Arc<P>,
    /// Hosts that answered with the right identity, per relay identity, most
    /// recently proven first.
    proven: HashMap<NodeId, Vec<RelayRef>>,
}

/// Live subscriptions of one relay identity: total, and per address.
type PerId<'a> = (u64, Vec<(&'a RelayRef, u64)>);

/// What one relay identity's probe found.
enum Outcome {
    /// This host answered.
    Reached(RelayRef),
    /// No host answered.
    Silent,
}

impl<P: RelayProbe> Prober<P> {
    pub fn new(probe: P) -> Prober<P> {
        Prober {
            probe: Arc::new(probe),
            proven: HashMap::new(),
        }
    }

    /// One round over `relays` (live subscriptions per relay address): the
    /// state of each relay identity probed. `Ok` if a host answered;
    /// `Failing` if none did and the relay has a proven host; else (never
    /// proven, or cut by `ROUND_LIMIT`) not in the map, read `Unknown`.
    pub async fn round(&mut self, relays: &[(RelayRef, u64)]) -> HashMap<NodeId, PushLink> {
        let targets = self.targets(relays);
        let sem = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
        let mut set = JoinSet::new();
        for (id, hosts) in targets {
            let probe = Arc::clone(&self.probe);
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    return (id, Outcome::Silent);
                };
                for h in hosts {
                    if probe.reachable(&h).await {
                        return (id, Outcome::Reached(h));
                    }
                }
                (id, Outcome::Silent)
            });
        }
        let mut found = HashMap::new();
        let _ = tokio::time::timeout(ROUND_LIMIT, async {
            while let Some(r) = set.join_next().await {
                if let Ok((id, o)) = r {
                    found.insert(id, o);
                }
            }
        })
        .await;
        set.abort_all();
        let mut states = HashMap::new();
        for (id, o) in found {
            match o {
                Outcome::Reached(h) => {
                    let p = self.proven.entry(id).or_default();
                    p.retain(|x| *x != h);
                    p.insert(0, h);
                    p.truncate(MAX_PROVEN_HOSTS);
                    states.insert(id, PushLink::Ok);
                }
                Outcome::Silent => {
                    if self.proven.contains_key(&id) {
                        states.insert(id, PushLink::Failing);
                    }
                }
            }
        }
        states
    }

    /// Relays to probe this round, each with its hosts in order. Forgets the
    /// proven hosts no live subscription names any more.
    fn targets(&mut self, relays: &[(RelayRef, u64)]) -> Vec<(NodeId, Vec<RelayRef>)> {
        let live: HashSet<&RelayRef> = relays.iter().map(|(r, _)| r).collect();
        self.proven.retain(|_, hosts| {
            hosts.retain(|h| live.contains(h));
            !hosts.is_empty()
        });
        let mut per_id: HashMap<NodeId, PerId<'_>> = HashMap::new();
        for (r, n) in relays {
            let e = per_id.entry(r.id).or_default();
            e.0 = e.0.saturating_add(*n);
            e.1.push((r, *n));
        }
        let mut ids: Vec<(NodeId, bool, u64)> = per_id
            .iter()
            .map(|(id, (total, _))| (*id, self.proven.contains_key(id), *total))
            .collect();
        // Proven relays first, then by live subscriptions, then by identity
        // (a fixed order for equal counts).
        ids.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.0.cmp(&b.0.0)));
        ids.truncate(MAX_PROBED_RELAYS);
        ids.into_iter()
            .map(|(id, _, _)| {
                let proven = self.proven.get(&id).cloned().unwrap_or_default();
                let mut fresh: Vec<(&RelayRef, u64)> = per_id
                    .remove(&id)
                    .map(|(_, h)| h)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(h, _)| !proven.contains(h))
                    .collect();
                fresh.sort_unstable_by(|a, b| {
                    b.1.cmp(&a.1)
                        .then_with(|| (&a.0.host, a.0.port).cmp(&(&b.0.host, b.0.port)))
                });
                let hosts = proven
                    .into_iter()
                    .chain(
                        fresh
                            .into_iter()
                            .take(MAX_NEW_HOSTS)
                            .map(|(h, _)| h.clone()),
                    )
                    .collect();
                (id, hosts)
            })
            .collect()
    }
}

/// Probes the relays of `state`'s last measurements every `PROBE_PERIOD`,
/// until `stop`. The results are handed to `state`, which publishes them at
/// its next round (`InfoState::update`), never as a probe ends.
pub async fn probe_loop<P: RelayProbe>(
    state: Arc<InfoState>,
    probe: P,
    mut stop: watch::Receiver<bool>,
) {
    let mut prober = Prober::new(probe);
    let start = tokio::time::Instant::now() + FIRST_ROUND_DELAY;
    let mut tick = tokio::time::interval_at(start, PROBE_PERIOD);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let relays = state.relays_in_use();
        let states = tokio::select! {
            s = prober.round(&relays) => s,
            _ = stop.changed() => return,
        };
        state.set_probed(states);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::*;

    const R: NodeId = NodeId([7; 32]);

    fn at(host: &str, id: NodeId) -> RelayRef {
        RelayRef {
            host: host.into(),
            port: 4433,
            id,
        }
    }

    /// Answers for the hosts in `up` only; records every probe.
    #[derive(Clone, Default)]
    struct Fake {
        up: Arc<Mutex<HashSet<String>>>,
        calls: Arc<Mutex<Vec<RelayRef>>>,
    }

    impl Fake {
        fn set_up(&self, hosts: &[&str]) {
            *self.up.lock().unwrap() = hosts.iter().map(|h| (*h).to_string()).collect();
        }
        fn calls(&self) -> Vec<RelayRef> {
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
    async fn one_subscription_is_enough_and_none_is_unknown() {
        let fake = Fake::default();
        fake.set_up(&["relay.example"]);
        let mut p = Prober::new(fake.clone());
        let s = p.round(&[(at("relay.example", R), 1)]).await;
        assert_eq!(s.get(&R), Some(&PushLink::Ok));
        // No live subscription names the relay any more: not probed, and
        // the proven host is forgotten.
        let s = p.round(&[]).await;
        assert!(s.is_empty());
        assert_eq!(fake.calls().len(), 1);
        assert!(p.proven.is_empty());
    }

    #[tokio::test]
    async fn never_proven_is_unknown_then_failing_once_proven() {
        let fake = Fake::default();
        let mut p = Prober::new(fake.clone());
        let live = [(at("relay.example", R), 3)];
        assert!(p.round(&live).await.is_empty(), "never proven: Unknown");
        fake.set_up(&["relay.example"]);
        assert_eq!(p.round(&live).await.get(&R), Some(&PushLink::Ok));
        fake.set_up(&[]);
        assert_eq!(p.round(&live).await.get(&R), Some(&PushLink::Failing));
    }

    /// The forgery: subscriptions naming the relay's identity with dead
    /// hosts, more of them than the real host has, cannot make it `Failing`,
    /// before or after the real host is proven.
    #[tokio::test]
    async fn forged_dead_hosts_do_not_make_the_relay_failing() {
        let fake = Fake::default();
        fake.set_up(&["relay.example"]);
        let mut p = Prober::new(fake.clone());
        let mut live = vec![(at("relay.example", R), 2)];
        assert_eq!(p.round(&live).await.get(&R), Some(&PushLink::Ok));
        // Then many dead hosts, each with far more rows than the real one.
        for i in 0..10 {
            live.push((at(&format!("dead{i}.example"), R), 500));
        }
        fake.calls();
        assert_eq!(p.round(&live).await.get(&R), Some(&PushLink::Ok));
        assert_eq!(fake.calls()[0].host, "relay.example", "proven host first");
        // A node that has not proven the real host yet: it falls out of the
        // new hosts tried, the relay reads `Unknown`, never `Failing`.
        let mut fresh = Prober::new(fake.clone());
        assert!(!fresh.round(&live).await.contains_key(&R));
        assert_eq!(fake.calls().len(), MAX_NEW_HOSTS);
    }

    #[tokio::test]
    async fn caps_on_relays_and_hosts() {
        let fake = Fake::default();
        let mut p = Prober::new(fake.clone());
        let mut live = Vec::new();
        for i in 0..(MAX_PROBED_RELAYS as u8 + 5) {
            for h in 0..5 {
                live.push((at(&format!("h{h}.example"), NodeId([i; 32])), u64::from(i)));
            }
        }
        p.round(&live).await;
        let calls = fake.calls();
        let ids: HashSet<NodeId> = calls.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), MAX_PROBED_RELAYS);
        assert!(
            !ids.contains(&NodeId([0; 32])),
            "fewest subscriptions left out"
        );
        assert_eq!(calls.len(), MAX_PROBED_RELAYS * MAX_NEW_HOSTS);
    }

    #[tokio::test]
    async fn proven_relays_keep_their_place() {
        let fake = Fake::default();
        fake.set_up(&["relay.example"]);
        let mut p = Prober::new(fake.clone());
        let mut live = vec![(at("relay.example", R), 1)];
        p.round(&live).await;
        // Many busier relays (never answering) arrive: the proven one is
        // still probed.
        for i in 0..(MAX_PROBED_RELAYS as u8 + 5) {
            live.push((at("busy.example", NodeId([100 + i; 32])), 1000));
        }
        assert_eq!(p.round(&live).await.get(&R), Some(&PushLink::Ok));
    }
}
