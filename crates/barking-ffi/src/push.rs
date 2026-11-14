//! Wake-up settings: the relay the app was built with and the APNs token iOS
//! gave it. Kept in the core's encrypted database, read by every full sync.

use std::collections::BTreeMap;
use std::panic::UnwindSafe;

use barking_net::push::{Preview, PushConfig, PushPrefs, PushState, expires_day};
use barking_proto::NodeId;
use barking_proto::push::{ApnsEnv, MAX_APNS_TOKEN, RelayRef, SubKind};

use crate::device::Device;
use crate::{BarkingError, guard};

/// The relay to wake this device through, and its APNs token.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PushSettings {
    /// DNS name or public IP of the relay.
    pub relay_host: String,
    pub relay_port: u16,
    /// Node identifier of the relay (52-character base32).
    pub relay_id: String,
    /// Identifier of the relay's sealing key.
    pub seal_key_id: u8,
    /// X25519 public sealing key of the relay (32 bytes).
    pub seal_public: Vec<u8>,
    /// APNs device token.
    pub apns_token: Vec<u8>,
    /// Token of the APNs sandbox (development builds).
    pub sandbox: bool,
}

impl TryFrom<PushSettings> for PushConfig {
    type Error = BarkingError;

    fn try_from(s: PushSettings) -> Result<Self, BarkingError> {
        let id: NodeId = s
            .relay_id
            .trim()
            .to_ascii_uppercase()
            .parse()
            .map_err(|_| BarkingError::invalid("relay identifier: 52-character base32 expected"))?;
        let relay = RelayRef {
            host: s.relay_host.trim().to_ascii_lowercase(),
            port: s.relay_port,
            id,
        };
        if !relay.well_formed() {
            return Err(BarkingError::invalid(
                "relay address: a DNS name or a public IP, and a port, expected",
            ));
        }
        let seal_public: [u8; 32] = s
            .seal_public
            .try_into()
            .map_err(|_| BarkingError::invalid("sealing key: 32 bytes expected"))?;
        if s.apns_token.is_empty() || s.apns_token.len() > MAX_APNS_TOKEN {
            return Err(BarkingError::invalid("APNs token: 1 to 64 bytes expected"));
        }
        Ok(PushConfig {
            relay,
            seal_public,
            seal_key_id: s.seal_key_id,
            apns_token: s.apns_token,
            env: if s.sandbox {
                ApnsEnv::Sandbox
            } else {
                ApnsEnv::Production
            },
        })
    }
}

#[uniffi::export]
impl Device {
    /// Sets the wake-up settings (`None`: push off). The next full sync
    /// subscribes with them, or cancels the subscriptions held.
    pub fn set_push(&self, settings: Option<PushSettings>) -> Result<(), BarkingError> {
        guard(|| {
            let cfg = settings.map(PushConfig::try_from).transpose()?;
            self.with_core(|core| Ok(PushConfig::store(core, cfg.as_ref())?))
        })
    }

    /// The notification preferences (defaults on a new device).
    pub fn notification_prefs(&self) -> Result<NotificationPrefs, BarkingError> {
        guard(|| self.with_core(|core| Ok(PushPrefs::load(core)?.into())))
    }

    /// Turns instant notifications on or off. The next full sync subscribes
    /// to push or cancels the subscriptions held; the wake-up settings given
    /// to `set_push` are kept.
    pub fn set_instant(&self, on: bool) -> Result<(), BarkingError> {
        self.update_prefs(|p| p.instant = on)
    }

    /// Sets how much of a message a notification shows.
    pub fn set_preview(&self, preview: PushPreview) -> Result<(), BarkingError> {
        self.update_prefs(|p| p.preview = preview.into())
    }

    /// Records that a push woke the app at `at_secs` (Unix seconds).
    pub fn note_wake(&self, at_secs: u64) -> Result<(), BarkingError> {
        self.update_prefs(|p| p.last_wake = Some(at_secs))
    }

    /// Where the wake subscriptions stand: whether the settings are set, and
    /// the nodes holding a subscription for this device.
    pub fn wake_status(&self) -> Result<WakeStatus, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let config_set = PushConfig::load(core)?.is_some();
                let state = PushState::load(core)?;
                Ok(WakeStatus {
                    config_set,
                    nodes: wake_nodes(&state),
                })
            })
        })
    }
}

impl Device {
    fn update_prefs(
        &self,
        change: impl FnOnce(&mut PushPrefs) + UnwindSafe,
    ) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let mut prefs = PushPrefs::load(core)?;
                change(&mut prefs);
                Ok(prefs.store(core)?)
            })
        })
    }
}

/// How much of a message a notification shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PushPreview {
    NameAndText,
    NameOnly,
    Generic,
}

impl From<Preview> for PushPreview {
    fn from(p: Preview) -> Self {
        match p {
            Preview::NameAndText => PushPreview::NameAndText,
            Preview::NameOnly => PushPreview::NameOnly,
            Preview::Generic => PushPreview::Generic,
        }
    }
}

impl From<PushPreview> for Preview {
    fn from(p: PushPreview) -> Self {
        match p {
            PushPreview::NameAndText => Preview::NameAndText,
            PushPreview::NameOnly => Preview::NameOnly,
            PushPreview::Generic => Preview::Generic,
        }
    }
}

/// The user's notification preferences on this device.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NotificationPrefs {
    /// Instant notifications on: the sync subscribes to push.
    pub instant: bool,
    pub preview: PushPreview,
    /// When a push last woke the app (Unix seconds), if ever.
    pub last_wake: Option<u64>,
}

impl From<PushPrefs> for NotificationPrefs {
    fn from(p: PushPrefs) -> Self {
        NotificationPrefs {
            instant: p.instant,
            preview: p.preview.into(),
            last_wake: p.last_wake,
        }
    }
}

/// A node holding wake subscriptions for this device.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WakeNode {
    /// First 8 hex characters of the node identifier.
    pub node: String,
    /// Subscriptions held there (a mailbox counts once per kind).
    pub mailboxes: u32,
    /// Holds a subscription for messages.
    pub messages: bool,
    /// Holds a subscription for receipts.
    pub acks: bool,
    /// Last day any of these subscriptions is valid.
    pub expires_day: u32,
}

/// The wake subscriptions as the settings screen shows them.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WakeStatus {
    /// The relay and APNs token are set.
    pub config_set: bool,
    /// Sorted by `node`.
    pub nodes: Vec<WakeNode>,
}

/// The subscriptions of `state`, grouped by node and sorted by node.
fn wake_nodes(state: &PushState) -> Vec<WakeNode> {
    let mut by_node: BTreeMap<String, WakeNode> = BTreeMap::new();
    for ((_, kind), subs) in &state.subs {
        let expires = expires_day(subs.day, *kind);
        for (id, _) in &subs.nodes {
            let name: String = id.0[..4].iter().map(|b| format!("{b:02x}")).collect();
            let n = by_node.entry(name.clone()).or_insert_with(|| WakeNode {
                node: name,
                mailboxes: 0,
                messages: false,
                acks: false,
                expires_day: 0,
            });
            n.mailboxes += 1;
            match kind {
                SubKind::Messages => n.messages = true,
                SubKind::Acks => n.acks = true,
            }
            n.expires_day = n.expires_day.max(expires);
        }
    }
    by_node.into_values().collect()
}

#[cfg(test)]
mod tests {
    use barking_core::mailbox::MailboxId;
    use barking_net::push::BoxSubs;
    use barking_proto::NodeId;

    use super::*;

    fn held(day: u32, nodes: &[u8]) -> BoxSubs {
        BoxSubs {
            day,
            collapse: [0; 16],
            nodes: nodes.iter().map(|&n| (NodeId([n; 32]), [0; 32])).collect(),
        }
    }

    #[test]
    fn wake_status_groups_by_node() {
        let day = 20_000;
        let mut state = PushState::default();
        for m in [1u8, 2] {
            state
                .subs
                .insert((MailboxId([m; 16]), SubKind::Messages), held(day, &[0xaa]));
        }
        state.subs.insert(
            (MailboxId([1; 16]), SubKind::Acks),
            held(day + 1, &[0xaa, 0xbb]),
        );
        let nodes = wake_nodes(&state);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].node, "aaaaaaaa");
        assert_eq!(nodes[0].mailboxes, 3);
        assert!(nodes[0].messages && nodes[0].acks);
        assert_eq!(
            nodes[0].expires_day,
            expires_day(day, SubKind::Messages).max(expires_day(day + 1, SubKind::Acks))
        );
        assert_eq!(nodes[1].node, "bbbbbbbb");
        assert_eq!(nodes[1].mailboxes, 1);
        assert!(!nodes[1].messages && nodes[1].acks);
    }
}
