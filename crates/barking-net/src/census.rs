//! Network census: walks the hash table from a few seeds and asks every node
//! it finds for its public report (`Info`, protocol 5). Feeds the public map
//! of the nodes; runs without an identity, as an anonymous client.
//!
//! The walk is bounded: at most [`CensusOptions::max_nodes`] identifiers and
//! a global deadline, since the records it follows come from untrusted
//! nodes. Records go through `filter_nodes` (signature, identity puzzle,
//! routable addresses) before anything is dialed.
//!
//! Nothing is logged here. Addresses stay in memory: [`Probe::observed`] is
//! the address a node answered on, kept only so that the caller can place
//! the node with an IP base, never written out.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use barking_dht::{BootstrapEntry, filter_nodes};
use barking_proto::client::Client;
use barking_proto::{NodeId, NodeInfoReport, NodeRecord, RecordPolicy};
use tokio::time::Instant;

use crate::discover::{DIAL_TIMEOUT, DialError, Dialer, QuicDialer, dial_error};

/// Default cap on the identifiers the walk keeps.
pub const MAX_CENSUS_NODES: usize = 512;
/// Default global deadline of a census.
pub const CENSUS_DEADLINE: Duration = Duration::from_secs(10 * 60);
/// Random `FindNode` targets sent to each node, on top of its own identifier.
pub const RANDOM_TARGETS: usize = 3;

/// Bounds of a census.
#[derive(Clone, Copy, Debug)]
pub struct CensusOptions {
    pub max_nodes: usize,
    pub deadline: Duration,
    /// Accepts non-routable addresses (local test networks only).
    pub allow_private: bool,
}

impl Default for CensusOptions {
    fn default() -> Self {
        CensusOptions {
            max_nodes: MAX_CENSUS_NODES,
            deadline: CENSUS_DEADLINE,
            allow_private: false,
        }
    }
}

/// What a node answered to `Info`, and on which address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    /// `None` if the node speaks a protocol older than 5 or refused.
    pub report: Option<NodeInfoReport>,
    /// Remote address of the pinned connection that brought the answer.
    pub observed: SocketAddr,
}

/// Exchanges a census needs: the lookups of [`Dialer`] plus `Info`.
pub trait Prober: Dialer {
    /// Connects (TLS pinned on `id`), `Hello`, then `Info`.
    fn probe(
        &self,
        id: NodeId,
        addrs: &[SocketAddr],
    ) -> impl Future<Output = Result<Probe, DialError>> + Send;
}

impl Prober for QuicDialer {
    async fn probe(&self, id: NodeId, addrs: &[SocketAddr]) -> Result<Probe, DialError> {
        let mut last = DialError::NoAddress;
        for &addr in addrs {
            let attempt = async {
                let session = Client::connect(addr, id).await.map_err(dial_error)?;
                let observed = session.connection().remote_address();
                let report = session.info(None).await.map_err(dial_error);
                session.connection().close(0u32.into(), b"done");
                Ok::<_, DialError>(Probe {
                    report: report?,
                    observed,
                })
            };
            match tokio::time::timeout(DIAL_TIMEOUT, attempt).await {
                Ok(Ok(probe)) => return Ok(probe),
                Ok(Err(e)) => last = e,
                Err(_) => last = DialError::Timeout,
            }
        }
        Err(last)
    }
}

/// One node of the census.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CensusNode {
    pub id: NodeId,
    /// Listed by at least one node of the table (a seed running as a plain
    /// relay is not).
    pub in_table: bool,
    /// `None` if the node did not answer.
    pub probe: Option<Probe>,
}

impl CensusNode {
    pub fn reachable(&self) -> bool {
        self.probe.is_some()
    }

    /// Address the node answered on, without the port.
    pub fn observed_ip(&self) -> Option<IpAddr> {
        self.probe.as_ref().map(|p| p.observed.ip().to_canonical())
    }
}

/// Result of a census, in identifier order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Census {
    pub nodes: Vec<CensusNode>,
    /// The walk stopped at `max_nodes` or at the deadline.
    pub truncated: bool,
}

struct Known {
    addrs: Vec<SocketAddr>,
    in_table: bool,
}

fn record_addrs(record: &NodeRecord) -> Vec<SocketAddr> {
    let mut addrs = Vec::with_capacity(2);
    if let Some(v4) = record.v4 {
        addrs.push(SocketAddr::V4(v4));
    }
    if let Some(v6) = record.v6 {
        addrs.push(SocketAddr::V6(v6));
    }
    addrs
}

/// Walks the table from `seeds`, then probes every node found.
pub async fn census<P: Prober>(
    prober: &P,
    seeds: &[BootstrapEntry],
    opts: CensusOptions,
    rng: &mut impl rand_core::Rng,
    now: u64,
) -> Census {
    let deadline = Instant::now() + opts.deadline;
    let policy = RecordPolicy::network(opts.allow_private);
    let mut known: BTreeMap<NodeId, Known> = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut truncated = false;

    for seed in seeds {
        if !known.contains_key(&seed.id) && known.len() >= opts.max_nodes {
            truncated = true;
            break;
        }
        let entry = known.entry(seed.id).or_insert_with(|| {
            queue.push_back(seed.id);
            Known {
                addrs: Vec::new(),
                in_table: false,
            }
        });
        if !entry.addrs.contains(&seed.addr) {
            entry.addrs.push(seed.addr);
        }
    }

    while let Some(id) = queue.pop_front() {
        if Instant::now() >= deadline {
            truncated = true;
            break;
        }
        let addrs = known[&id].addrs.clone();
        let mut targets = vec![id.0];
        for _ in 0..RANDOM_TARGETS {
            let mut t = [0; 32];
            rng.fill_bytes(&mut t);
            targets.push(t);
        }
        for target in targets {
            let Ok(Ok(records)) =
                tokio::time::timeout_at(deadline, prober.find_node(id, &addrs, target)).await
            else {
                // Unreachable, refusing (a plain relay) or out of time: the
                // other targets would fail the same way.
                break;
            };
            let Ok(valid) = filter_nodes(records, now, &policy) else {
                continue;
            };
            for (nid, record) in valid {
                if let Some(entry) = known.get_mut(&nid) {
                    entry.in_table = true;
                    for addr in record_addrs(&record) {
                        if !entry.addrs.contains(&addr) {
                            entry.addrs.push(addr);
                        }
                    }
                } else if known.len() < opts.max_nodes {
                    known.insert(
                        nid,
                        Known {
                            addrs: record_addrs(&record),
                            in_table: true,
                        },
                    );
                    queue.push_back(nid);
                } else {
                    truncated = true;
                }
            }
        }
    }

    let mut nodes = Vec::with_capacity(known.len());
    for (id, entry) in known {
        let probe = if Instant::now() < deadline {
            tokio::time::timeout_at(deadline, prober.probe(id, &entry.addrs))
                .await
                .ok()
                .and_then(Result::ok)
        } else {
            truncated = true;
            None
        };
        nodes.push(CensusNode {
            id,
            in_table: entry.in_table,
            probe,
        });
    }
    Census { nodes, truncated }
}

#[cfg(test)]
mod tests;
