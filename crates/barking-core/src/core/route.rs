//! Route of a message: the steps each of its packets went through (sealed,
//! deposited on a node, fetched from a node, opened, acknowledged, copied to
//! one of my devices). Kept in the encrypted database, never synchronized
//! between my devices, purged with the transparency log (30 days).

use super::Core;
use crate::identity::DeviceId;
use crate::packet::{Packet, PacketId};
use crate::store::{Queries, RouteRow};
use crate::{CoreError, Result};

/// A step of a packet's route. Stored as `u8` in this fixed order:
/// additions go at the end (the mesh steps, block 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteStep {
    /// Sealed for a contact's device (by the core, at sending).
    Sealed,
    /// Deposited on a node (by the network client).
    Deposited,
    /// Fetched from a node (by the network client).
    Fetched,
    /// Opened (by the core, at receipt).
    Opened,
    /// Its acknowledgement verified (by the core).
    AckVerified,
    /// Copy sealed for one of my other devices (by the core, at sending).
    OwnCopy,
}

impl RouteStep {
    fn to_u8(self) -> u8 {
        match self {
            RouteStep::Sealed => 0,
            RouteStep::Deposited => 1,
            RouteStep::Fetched => 2,
            RouteStep::Opened => 3,
            RouteStep::AckVerified => 4,
            RouteStep::OwnCopy => 5,
        }
    }

    /// Order of the steps of one packet within a same second: the network
    /// client records `Deposited` and `Fetched` at the end of a sync, after
    /// the core already wrote `Opened` or `AckVerified`.
    fn rank(self) -> u8 {
        match self {
            RouteStep::Sealed | RouteStep::OwnCopy => 0,
            RouteStep::Deposited => 1,
            RouteStep::Fetched => 2,
            RouteStep::Opened => 3,
            RouteStep::AckVerified => 4,
        }
    }

    fn from_u8(v: u8) -> Option<RouteStep> {
        Some(match v {
            0 => RouteStep::Sealed,
            1 => RouteStep::Deposited,
            2 => RouteStep::Fetched,
            3 => RouteStep::Opened,
            4 => RouteStep::AckVerified,
            5 => RouteStep::OwnCopy,
            _ => return None,
        })
    }
}

/// A step of a message's route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// Date of the step (Unix seconds).
    pub at: u64,
    pub step: RouteStep,
    /// Short identifier of the node (`Deposited`, `Fetched`).
    pub node: Option<String>,
    /// Packet bytes (`Sealed`).
    pub size: Option<u32>,
    /// Recipient device of the packet (sent messages only).
    pub device: Option<DeviceId>,
    /// The packet is a copy for one of my devices.
    pub own: bool,
}

/// Length of a node's short identifier (the first characters of its
/// base32 identifier).
const NODE_SHORT_ID_LEN: usize = 8;

/// Records a step written by the core itself, in the caller's transaction.
pub(super) fn record(
    q: &impl Queries,
    packet: PacketId,
    step: RouteStep,
    now: u64,
    size: Option<u32>,
) -> Result<()> {
    q.add_route_step(packet, now, step.to_u8(), None, size)
}

/// `Sealed` step of `packet`, with its size.
pub(super) fn record_sealed(q: &impl Queries, packet: &Packet, now: u64) -> Result<()> {
    let size = super::delivery::packet_size(packet);
    record(q, packet.id, RouteStep::Sealed, now, Some(size))
}

impl Core {
    /// Records a transport step of `packet` on the node `node` (its short
    /// identifier, never an address): only `Deposited` and `Fetched` are
    /// accepted, the other steps are written by the core. A packet that
    /// carries none of my messages (a receipt, junk) is ignored, and so is
    /// a step that is not part of the packet's way: `Deposited` for a
    /// received packet, `Fetched` for one I sent (an audit reading back
    /// what I deposited).
    pub fn record_route(
        &mut self,
        packet: PacketId,
        step: RouteStep,
        node: &str,
        now: u64,
    ) -> Result<()> {
        if !matches!(step, RouteStep::Deposited | RouteStep::Fetched) {
            return Err(CoreError::Malformed("route step"));
        }
        if node.len() != NODE_SHORT_ID_LEN || !node.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(CoreError::Malformed("route node"));
        }
        self.store.transaction(|tx| {
            let (sent, received) = tx.packet_has_message(packet)?;
            let on_its_way = match step {
                RouteStep::Deposited => sent,
                _ => received,
            };
            if !on_its_way {
                return Ok(());
            }
            tx.add_route_step(packet, now, step.to_u8(), Some(node), None)
        })
    }

    /// Route of the message whose row is `row_id` (`MessageRow::id`): the
    /// steps of all its packets, by date (within a second, in the order a
    /// packet goes through them). Empty for an unknown message.
    pub fn message_route(&self, row_id: i64) -> Result<Vec<RouteEntry>> {
        let mut route: Vec<RouteEntry> = self
            .store
            .route_of_message(row_id)?
            .into_iter()
            .filter_map(entry)
            .collect();
        // Stable: equal keys keep their insertion order.
        route.sort_by_key(|e| (e.at, e.step.rank()));
        Ok(route)
    }
}

/// A stored step; `None` for a step unknown to this version.
fn entry(r: RouteRow) -> Option<RouteEntry> {
    Some(RouteEntry {
        at: r.at,
        step: RouteStep::from_u8(r.step)?,
        node: r.node,
        size: r.size,
        device: r.device,
        own: r.own,
    })
}
