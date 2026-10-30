//! Entretien de la table (spec §6.1) :
//! - **démarrage** : `peers` rechargée et pingée ; moins de 3 nœuds joints :
//!   liste intégrée puis `bootstrap` de la config ; puis recherche de notre
//!   propre identifiant ;
//! - **toutes les 10 min** : ping de la tête de chaque compartiment non vue
//!   depuis 15 min, nouvel amorçage si la table compte moins de 3 nœuds, et
//!   sauvegarde de `peers` ;
//! - **toutes les heures** : rafraîchissement des compartiments sans
//!   recherche depuis 1 h ;
//! - **toutes les 24 h** : nouvelle fiche ;
//! - **à l'arrêt** : sauvegarde de `peers`.
//!
//! `ServerConfig::dht_tick` ramène toutes ces cadences à une seule période
//! (tests réseau).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use barking_dht::builtin_bootstrap;
use barking_proto::{NodeId, NodeRecord};
use tokio::sync::watch;
use tokio::time::{Instant, interval_at};

use super::Dht;
use crate::server::{Shared, Stored, unix_now};

/// Cycle d'entretien : pings et sauvegarde.
pub const MAINTAIN_EVERY: Duration = Duration::from_secs(600);
/// Rafraîchissement des compartiments.
pub const REFRESH_EVERY: Duration = Duration::from_secs(3600);
/// Republication de la fiche.
pub const REPUBLISH_EVERY: Duration = Duration::from_secs(86_400);
/// En dessous de ce nombre de nœuds joints, la liste d'amorçage est essayée.
pub const MIN_BOOTSTRAP_PEERS: usize = 3;
/// Contacts simultanés au plus pendant l'amorçage et les pings.
const PARALLEL_CONTACTS: usize = 16;

/// Fait tourner l'entretien jusqu'à `stop`, puis enregistre `peers`.
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

/// Démarrage : `peers`, amorçage si besoin, recherche de soi.
async fn startup(dht: &Arc<Dht>, shared: &Arc<Shared>) {
    let rows = match shared.with_store(true, None, |s, _| s.load_peers()).await {
        Stored::Done(rows) => rows,
        Stored::Busy | Stored::Failed => Vec::new(),
    };
    let now = unix_now();
    let policy = barking_proto::RecordPolicy::network(dht.config().allow_private_addrs);
    // Une ligne illisible, invalide ou d'un autre identifiant est écartée.
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
    tracing::info!("table : {reached} pairs joints au démarrage");
    dht.lookup(dht.id().0).await;
    tracing::info!(
        "table : {} pairs après la recherche de soi",
        dht.table().len()
    );
}

/// Contacte la liste intégrée puis celle de la config ; nombre de nœuds
/// joints.
async fn bootstrap(dht: &Arc<Dht>) -> usize {
    let entries = builtin_bootstrap()
        .into_iter()
        .chain(dht.config().bootstrap.iter().copied())
        .map(|e| (e.id, vec![e.addr]))
        .collect();
    dht.contact_all(entries, PARALLEL_CONTACTS).await
}

/// Cycle de 10 min : têtes de compartiment anciennes, amorçage d'une table
/// trop petite, sauvegarde.
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

/// Rafraîchit chaque compartiment sans recherche depuis 1 h par la
/// recherche d'un identifiant tiré dans ce compartiment.
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
        tracing::debug!("table : peers enregistrée");
    }
}
