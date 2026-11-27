use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use barking_dht::BootstrapEntry;
use barking_proto::{ErrorReason, FillTier, NodeId, NodeInfoReport, NodeRecord};
use rand::{SeedableRng, rngs::StdRng};

use super::*;
use crate::test_support::{id_of, record};

const NOW: u64 = 1_800_000_000;

/// In-memory network: who lists whom, who is down, who is a plain relay.
#[derive(Default)]
struct Net {
    tables: HashMap<NodeId, Vec<usize>>,
    down: HashSet<NodeId>,
    plain: HashSet<NodeId>,
    old: HashSet<NodeId>,
}

fn report() -> NodeInfoReport {
    NodeInfoReport {
        software: "barking-node 0.7.0".into(),
        protocol: 5,
        uptime_secs: 3600,
        storage: FillTier::Low,
        wake: None,
        push_link: None,
        origin: None,
    }
}

impl Dialer for Net {
    async fn ping(&self, _id: NodeId, _addrs: &[SocketAddr]) -> Result<NodeRecord, DialError> {
        Err(DialError::Unreachable)
    }

    async fn find_node(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
        _target: [u8; 32],
    ) -> Result<Vec<NodeRecord>, DialError> {
        if addrs.is_empty() {
            return Err(DialError::NoAddress);
        }
        if self.down.contains(&id) {
            return Err(DialError::Unreachable);
        }
        if self.plain.contains(&id) {
            return Err(DialError::Refused(ErrorReason::Malformed));
        }
        Ok(self.tables[&id].iter().map(|&n| record(n, NOW)).collect())
    }
}

impl Prober for Net {
    async fn probe(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Probe, DialError> {
        if self.down.contains(&id) {
            return Err(DialError::Unreachable);
        }
        let observed = *addrs.first().ok_or(DialError::NoAddress)?;
        let report = (!self.old.contains(&id)).then(report);
        Ok(Probe { report, observed })
    }
}

fn seed(n: usize) -> BootstrapEntry {
    let r = record(n, NOW);
    BootstrapEntry {
        id: id_of(n),
        addr: SocketAddr::V4(r.v4.unwrap()),
    }
}

fn opts() -> CensusOptions {
    CensusOptions {
        allow_private: true,
        ..CensusOptions::default()
    }
}

async fn run(net: &Net, seeds: &[BootstrapEntry], opts: CensusOptions) -> Census {
    let mut rng = StdRng::seed_from_u64(7);
    census(net, seeds, opts, &mut rng, NOW).await
}

fn by_id(c: &Census, n: usize) -> &CensusNode {
    c.nodes.iter().find(|x| x.id == id_of(n)).unwrap()
}

#[tokio::test]
async fn walks_the_table_and_probes_every_node() {
    let mut net = Net::default();
    net.tables.insert(id_of(1), vec![2, 3]);
    net.tables.insert(id_of(2), vec![1, 4]);
    net.tables.insert(id_of(3), vec![]);
    net.tables.insert(id_of(4), vec![2]);
    net.down.insert(id_of(3));
    net.old.insert(id_of(4));

    let c = run(&net, &[seed(1)], opts()).await;

    assert!(!c.truncated);
    assert_eq!(c.nodes.len(), 4);
    assert!(by_id(&c, 1).in_table, "listed by node 2");
    assert!(by_id(&c, 2).reachable());
    assert!(!by_id(&c, 3).reachable(), "down: listed but not answering");
    let old = by_id(&c, 4).probe.as_ref().unwrap();
    assert_eq!(old.report, None, "protocol older than 5");
    assert_eq!(by_id(&c, 2).probe.as_ref().unwrap().report, Some(report()));
}

#[tokio::test]
async fn a_seed_running_as_plain_relay_is_kept_outside_the_table() {
    let mut net = Net::default();
    net.plain.insert(id_of(5));
    net.tables.insert(id_of(1), vec![]);

    let c = run(&net, &[seed(5), seed(1)], opts()).await;

    let plain = by_id(&c, 5);
    assert!(!plain.in_table);
    assert!(plain.reachable(), "answers Info even without a table");
}

#[tokio::test]
async fn stops_at_the_node_cap() {
    let mut net = Net::default();
    net.tables.insert(id_of(1), vec![2, 3, 4, 5]);
    for n in 2..=5 {
        net.tables.insert(id_of(n), vec![]);
    }

    let c = run(
        &net,
        &[seed(1)],
        CensusOptions {
            max_nodes: 3,
            ..opts()
        },
    )
    .await;

    assert!(c.truncated);
    assert_eq!(c.nodes.len(), 3);
}

#[tokio::test]
async fn private_addresses_are_refused_on_the_network() {
    let mut net = Net::default();
    net.tables.insert(id_of(1), vec![2]);
    net.tables.insert(id_of(2), vec![]);

    let c = run(
        &net,
        &[seed(1)],
        CensusOptions {
            allow_private: false,
            ..opts()
        },
    )
    .await;

    assert_eq!(c.nodes.len(), 1, "the 10.x record of node 2 is dropped");
}

#[tokio::test]
async fn the_deadline_bounds_the_census() {
    let mut net = Net::default();
    net.tables.insert(id_of(1), vec![]);

    let c = run(
        &net,
        &[seed(1)],
        CensusOptions {
            deadline: Duration::ZERO,
            ..opts()
        },
    )
    .await;

    assert!(c.truncated);
    assert!(!by_id(&c, 1).reachable());
}
