//! Table maintenance (spec §6.1):
//! - **startup**: `peers` reloaded and pinged; fewer than 3 nodes reached:
//!   built-in list, then the config's `bootstrap`; then a lookup of our own
//!   identifier;
//! - **every 10 min**: ping of the head of each bucket not seen for 15 min,
//!   new bootstrap if the table has fewer than 3 nodes, and saving of
//!   `peers`;
//! - **every hour**: refresh of buckets without a lookup for 1 h;
//! - **every 24 h**: new record;
//! - **at shutdown**: saving of `peers`.
//!
//! `ServerConfig::dht_tick` reduces all these cadences to a single period
//! (network tests).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use barking_dht::builtin_bootstrap;
use barking_proto::{NodeId, NodeRecord};
use tokio::sync::watch;
use tokio::time::{Instant, interval_at};

use super::Dht;
use crate::server::{Shared, Stored, unix_now};

/// Maintenance cycle: pings and saving.
pub const MAINTAIN_EVERY: Duration = Duration::from_secs(600);
/// Bucket refresh.
pub const REFRESH_EVERY: Duration = Duration::from_secs(3600);
/// Record republication.
pub const REPUBLISH_EVERY: Duration = Duration::from_secs(86_400);
/// Below this number of nodes reached, the bootstrap list is tried.
pub const MIN_BOOTSTRAP_PEERS: usize = 3;
/// At most this many simultaneous contacts during bootstrap and pings.
const PARALLEL_CONTACTS: usize = 16;

/// Runs maintenance until `stop`, then saves `peers`.
pub(crate) async fn run(dht: Arc<Dht>, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let work = async {
        startup(&dht, &shared).await;
        let every = |d: Duration| dht.tick().unwrap_or(d);
        let start = Instant::now();
        let tick = |d: Duration| interval_at(start + every(d), every(d));
        let (mut maintain, mut refresh, mut republish) = (
            tick(MAINTAIN_EVERY),
            tick(REFRESH_EVERY),
            tick(REPUBLISH_EVERY),
        );
        loop {
            tokio::select! {
                _ = maintain.tick() => cycle(&dht, &shared).await,
                _ = refresh.tick() => refresh_buckets(&dht).await,
                _ = republish.tick() => dht.republish(unix_now()),
            }
        }
    };
    tokio::select! {
        () = work => {}
        _ = stop.changed() => {}
    }
    save(&dht, &shared).await;
}

/// Startup: `peers`, bootstrap if needed, self lookup.
async fn startup(dht: &Arc<Dht>, shared: &Arc<Shared>) {
    let rows = match shared.with_store(true, None, |s, _| s.load_peers()).await {
        Stored::Done(rows) => rows,
        Stored::Busy | Stored::Failed => Vec::new(),
    };
    let now = unix_now();
    let policy = barking_proto::RecordPolicy::network(dht.config().allow_private_addrs);
    // A row that is unreadable, invalid or for another identifier is discarded.
    let saved: Vec<(NodeId, Vec<SocketAddr>)> = rows
        .iter()
        .filter_map(|row| {
            let record: NodeRecord = postcard::from_bytes(&row.record).ok()?;
            let id = record.verify(now, &policy).ok()?;
            (id.0 == row.node_id).then(|| (id, record.addrs()))
        })
        .collect();
    let mut reached = dht.contact_all(saved, PARALLEL_CONTACTS).await;
    if reached < MIN_BOOTSTRAP_PEERS {
        reached += bootstrap(dht).await;
    }
    tracing::info!("table: {reached} peers reached at startup");
    dht.lookup(dht.id().0).await;
    tracing::info!("table: {} peers after the self lookup", dht.table().len());
}

/// Contacts the built-in list then the config's; number of nodes
/// reached.
async fn bootstrap(dht: &Arc<Dht>) -> usize {
    let entries = builtin_bootstrap()
        .into_iter()
        .chain(dht.config().bootstrap.iter().copied())
        .map(|e| (e.id, vec![e.addr]))
        .collect();
    dht.contact_all(entries, PARALLEL_CONTACTS).await
}

/// 10 min cycle: old bucket heads, bootstrap of a too-small table,
/// saving.
async fn cycle(dht: &Arc<Dht>, shared: &Arc<Shared>) {
    let stale = dht.table().stale_heads(unix_now());
    let mut set = tokio::task::JoinSet::new();
    for chunk in stale.chunks(PARALLEL_CONTACTS) {
        for id in chunk.iter().copied() {
            let dht = Arc::clone(dht);
            set.spawn(async move { dht.refresh_peer(id).await });
        }
        while set.join_next().await.is_some() {}
    }
    if dht.table().len() < MIN_BOOTSTRAP_PEERS {
        bootstrap(dht).await;
    }
    save(dht, shared).await;
}

/// Refreshes each bucket without a lookup for 1 h by looking up an
/// identifier drawn in that bucket.
async fn refresh_buckets(dht: &Arc<Dht>) {
    let buckets = dht.table().buckets_to_refresh(unix_now());
    for b in buckets {
        let target = dht.table().random_id_in_bucket(b, &mut rand::rng());
        dht.lookup(target).await;
        dht.table().mark_refreshed(b, unix_now());
    }
}

async fn save(dht: &Dht, shared: &Arc<Shared>) {
    let rows = dht.peer_rows();
    if let Stored::Done(()) = shared
        .with_store(true, None, move |s, _| s.save_peers(&rows))
        .await
    {
        tracing::debug!("table: peers saved");
    }
}
