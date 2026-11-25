//! What the user does to the nodes (spec §6.4): block, unblock, remove a
//! node added by hand, add the default nodes shipped with the app, and
//! restore the default nodes removed.
//!
//! The pure functions work on a loaded [`NetState`] (and [`PushState`]);
//! the `*_in_core` wrappers load the states from the core, apply, save and,
//! for a block or an unblock, write the transparency log. A block is
//! immediate and total: the node leaves the view and is refused from then
//! on, and everything kept about it goes. The FFI holds the database lock
//! for the whole call, as a sync does for its whole run: a block waits for
//! the sync in progress, which saved before, so it cannot be overwritten.

use std::net::SocketAddr;

use barking_core::Core;
use barking_core::transparency::TransparencyEvent;
use barking_proto::NodeId;

use crate::push::PushState;
use crate::state::{BlockedEntry, NetState, StateError};
use crate::sync::short_id;
use crate::view::hour;

/// Blocks `id`: its entry leaves the view and every way back is refused
/// (discovery, `Nodes` answers, contact cards, manual add); the deposit
/// ledger forgets its acceptances and retry delays (the copies it held are
/// planned elsewhere); the push state forgets its subscriptions without
/// unsubscribing (they expire by themselves); its fetch positions, audit,
/// re-read and cross-check dates, completion and down records, page size,
/// cached report and latency go. The origin its cached report declared is
/// kept with the block, for the user to recognise it.
pub fn block_node(state: &mut NetState, push: &mut PushState, id: NodeId, now: u64) {
    let origin = state.info.get(&id).and_then(|c| c.report.origin.clone());
    state.block(
        id,
        BlockedEntry {
            at: hour(now),
            origin,
        },
    );
    state.ledger.forget_node(&id);
    push.forget_node(&id);
    state.positions.retain(|(n, _), _| *n != id);
    state.audited_at.retain(|(n, _), _| *n != id);
    state.reread_at.retain(|(n, _), _| *n != id);
    state.crosscheck_at.retain(|(n, _), _| *n != id);
    state.unaudited.remove(&id);
    state.down_failed.remove(&id);
    state.page_bytes.remove(&id);
    state.info.remove(&id);
    state.latency.remove(&id);
}

/// Unblocks `id`: it comes back only by the normal ways (discovery, manual
/// add, the default nodes at the next launch). False if it was not blocked.
pub fn unblock_node(state: &mut NetState, id: &NodeId) -> bool {
    state.unblock(id)
}

/// Removes a node added by hand or a default node: its manual address and
/// status go (a node the DHT also knows stays as an ordinary entry). A
/// default node is remembered as dismissed: `add_default_nodes` no longer
/// adds it. False if nothing changed.
pub fn remove_node(state: &mut NetState, id: &NodeId) -> bool {
    let removed = state.view.remove_manual(id);
    let dismissed = state.defaults.contains(id) && state.dismissed_defaults.insert(*id);
    removed || dismissed
}

/// The default nodes shipped with the app, at launch: `entries` becomes the
/// default list, and each one neither blocked nor dismissed is added by
/// hand.
pub fn add_default_nodes(state: &mut NetState, entries: &[(NodeId, SocketAddr)], now: u64) {
    add_defaults(state, entries, now);
}

/// Restores the default nodes the user removed: `dismissed_defaults` is
/// emptied, then `entries` added again. A blocked one stays blocked (only
/// `unblock_node` undoes a block). Returns how many entries were actually
/// restored.
pub fn reset_default_nodes(
    state: &mut NetState,
    entries: &[(NodeId, SocketAddr)],
    now: u64,
) -> u32 {
    state.dismissed_defaults.clear();
    add_defaults(state, entries, now)
}

/// `add_default_nodes`; returns how many entries the view took or changed.
fn add_defaults(state: &mut NetState, entries: &[(NodeId, SocketAddr)], now: u64) -> u32 {
    state.defaults = entries.iter().map(|(id, _)| *id).collect();
    let mut added = 0;
    for &(id, addr) in entries {
        if state.dismissed_defaults.contains(&id) || state.blocked.contains_key(&id) {
            continue;
        }
        // The view refuses a blocked node too.
        if state.view.add_manual(id, addr, now) {
            added += 1;
        }
    }
    added
}

/// `block_node` on the states stored in `core`, saved, then logged
/// (`NodeBlocked`). The network state is saved first: a failure to save the
/// push state after it still leaves the node blocked.
pub fn block_node_in_core(
    core: &mut Core,
    id: NodeId,
    now: u64,
    allow_private: bool,
) -> Result<(), StateError> {
    let (mut state, _) = NetState::load_checked(core, now, allow_private)?;
    let mut push = PushState::load(core)?;
    block_node(&mut state, &mut push, id, now);
    state.save(core)?;
    push.save(core)?;
    core.log_transport_event(
        TransparencyEvent::NodeBlocked {
            id_short: short_id(&id),
        },
        now,
    )?;
    Ok(())
}

/// `unblock_node` on the state stored in `core`; saved and logged
/// (`NodeUnblocked`) only if the node was blocked.
pub fn unblock_node_in_core(
    core: &mut Core,
    id: &NodeId,
    now: u64,
    allow_private: bool,
) -> Result<bool, StateError> {
    let (mut state, _) = NetState::load_checked(core, now, allow_private)?;
    if !unblock_node(&mut state, id) {
        return Ok(false);
    }
    state.save(core)?;
    core.log_transport_event(
        TransparencyEvent::NodeUnblocked {
            id_short: short_id(id),
        },
        now,
    )?;
    Ok(true)
}

/// `remove_node` on the state stored in `core`, saved if it changed.
pub fn remove_node_in_core(
    core: &mut Core,
    id: &NodeId,
    now: u64,
    allow_private: bool,
) -> Result<bool, StateError> {
    let (mut state, _) = NetState::load_checked(core, now, allow_private)?;
    let changed = remove_node(&mut state, id);
    if changed {
        state.save(core)?;
    }
    Ok(changed)
}

/// `add_default_nodes` on the state stored in `core`, saved.
pub fn add_default_nodes_in_core(
    core: &mut Core,
    entries: &[(NodeId, SocketAddr)],
    now: u64,
    allow_private: bool,
) -> Result<(), StateError> {
    let (mut state, _) = NetState::load_checked(core, now, allow_private)?;
    add_default_nodes(&mut state, entries, now);
    state.save(core)
}

/// `reset_default_nodes` on the state stored in `core`, saved.
pub fn reset_default_nodes_in_core(
    core: &mut Core,
    entries: &[(NodeId, SocketAddr)],
    now: u64,
    allow_private: bool,
) -> Result<u32, StateError> {
    let (mut state, _) = NetState::load_checked(core, now, allow_private)?;
    let restored = reset_default_nodes(&mut state, entries, now);
    state.save(core)?;
    Ok(restored)
}

#[cfg(test)]
mod tests;
