//! Route of a message (path screen, spec block 2b §4.2) and its short hint
//! (route badges in bubbles and the chats list).

use std::collections::BTreeSet;

use barking_core::{Core, RouteEntry, RouteStep};

use crate::device::Device;
use crate::{BarkingError, guard};

/// A step of a message's route.
#[derive(Debug, uniffi::Record)]
pub struct RouteStepInfo {
    /// Unix seconds.
    pub at: u64,
    /// `sealed`, `deposited`, `fetched`, `opened`, `ack_verified` or
    /// `own_copy`.
    pub step: String,
    /// Short identifier of the node (`deposited`, `fetched`).
    pub node: Option<String>,
    /// Packet bytes (`sealed`).
    pub size: Option<u32>,
    /// Name of my device the copy went to (`own_copy`), from my device list.
    pub device_name: Option<String>,
    /// The packet is a copy for one of my devices.
    pub own: bool,
}

fn step_name(s: RouteStep) -> &'static str {
    match s {
        RouteStep::Sealed => "sealed",
        RouteStep::Deposited => "deposited",
        RouteStep::Fetched => "fetched",
        RouteStep::Opened => "opened",
        RouteStep::AckVerified => "ack_verified",
        RouteStep::OwnCopy => "own_copy",
    }
}

/// Badge of a route: `internet:N`, N the distinct relay nodes it went
/// through; `None` while it went through none. The copies to my other
/// devices are not part of the way to the contact: their relays are left
/// out.
pub(crate) fn hint_of(route: &[RouteEntry]) -> Option<String> {
    let nodes: BTreeSet<&str> = route
        .iter()
        .filter(|e| !e.own)
        .filter_map(|e| e.node.as_deref())
        .collect();
    (!nodes.is_empty()).then(|| format!("internet:{}", nodes.len()))
}

/// Route hint of the message whose row is `row_id`.
pub(crate) fn route_hint(core: &Core, row_id: i64) -> Result<Option<String>, BarkingError> {
    Ok(hint_of(&core.message_route(row_id)?))
}

#[uniffi::export]
impl Device {
    /// Steps of the message `message_id` (`Message::id`), by date. Empty
    /// when nothing was recorded (an old or purged message).
    pub fn message_route(&self, message_id: i64) -> Result<Vec<RouteStepInfo>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let mine = core.my_devices();
                Ok(core
                    .message_route(message_id)?
                    .into_iter()
                    .map(|e| RouteStepInfo {
                        at: e.at,
                        step: step_name(e.step).to_owned(),
                        device_name: (e.step == RouteStep::OwnCopy)
                            .then(|| {
                                mine.iter()
                                    .find(|d| Some(d.id) == e.device)
                                    .map(|d| d.name.clone())
                            })
                            .flatten(),
                        node: e.node,
                        size: e.size,
                        own: e.own,
                    })
                    .collect())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(node: Option<&str>) -> RouteEntry {
        RouteEntry {
            at: 1,
            step: if node.is_some() {
                RouteStep::Fetched
            } else {
                RouteStep::Opened
            },
            node: node.map(str::to_owned),
            size: None,
            device: None,
            own: false,
        }
    }

    #[test]
    fn hint_leaves_out_copies_to_my_devices() {
        let mut copy = step(Some("BBBBBBBB"));
        copy.step = RouteStep::Deposited;
        copy.own = true;
        let mut to_contact = step(Some("AAAAAAAA"));
        to_contact.step = RouteStep::Deposited;
        assert_eq!(
            hint_of(&[to_contact, copy.clone()]),
            Some("internet:1".into())
        );
        assert_eq!(hint_of(&[copy]), None);
    }

    #[test]
    fn hint_counts_distinct_nodes() {
        assert_eq!(hint_of(&[]), None);
        assert_eq!(hint_of(&[step(None)]), None);
        assert_eq!(
            hint_of(&[step(Some("AAAAAAAA")), step(Some("AAAAAAAA")), step(None)]),
            Some("internet:1".into())
        );
        assert_eq!(
            hint_of(&[step(Some("AAAAAAAA")), step(Some("BBBBBBBB"))]),
            Some("internet:2".into())
        );
    }
}
