//! Transparency log for the app (spec block 2b §5): each event becomes a
//! `key` and `args` the app translates, never the English text of
//! `describe()`. The args hold no more than the event already stores:
//! short node and device identifiers, contact names, counts, dates.

use std::collections::HashMap;

use barking_core::Core;
use barking_core::identity::root::Fingerprint;
use barking_core::packet::Tier;
use barking_core::transparency::{AvoidReason, SyncKind, TransparencyEvent};

use crate::device::Device;
use crate::{BarkingError, guard};

/// One line of the transparency log.
#[derive(Debug, uniffi::Record)]
pub struct LogEntry {
    /// Unix seconds.
    pub at: u64,
    /// `session`, `packet`, `device`, `node` or `security`: the icon.
    pub family: String,
    /// One of `log_keys()`: the app's text.
    pub key: String,
    /// Values of the text, in order. An arg starting with `@` is a token
    /// (see `log_arg_tokens()`) the app translates; the others are
    /// shown as they are (names, counts, short identifiers, Unix seconds).
    pub args: Vec<String>,
    /// Security class of the log.
    pub security: bool,
}

/// Every key `LogEntry::key` can take, one per `TransparencyEvent` variant.
const KEYS: [&str; 26] = [
    "log.session_established",
    "log.packet_sealed",
    "log.packet_opened",
    "log.ack_emitted",
    "log.ack_verified",
    "log.decrypt_failed",
    "log.duplicate_ignored",
    "log.contact_key_changed",
    "log.frame_rejected",
    "log.device_linked",
    "log.link_finished",
    "log.sync_applied",
    "log.sync_skipped",
    "log.contact_card_updated",
    "log.history_imported",
    "log.own_devices_updated",
    "log.node_deposit",
    "log.node_fetch",
    "log.node_avoided",
    "log.seal_skipped",
    "log.admin_transfer_started",
    "log.admin_transferred",
    "log.admin_received",
    "log.this_device_removed",
    "log.device_removed",
    "log.remove_requested",
];

/// Every token an arg can take (without its `@`); the app has a text
/// `log.arg.<token>` for each.
const TOKENS: [&str; 15] = [
    "initiator",
    "responder",
    "post_quantum",
    "no_post_quantum",
    "tier_small",
    "tier_medium",
    "tier_large",
    "sync_sent",
    "sync_contact",
    "sync_devices",
    "sync_admin",
    "node_lost",
    "node_unreachable",
    "intro_mailbox",
    "daily_mailbox",
];

/// Keys of the log, for the app's translation check.
#[uniffi::export]
pub fn log_keys() -> Vec<String> {
    KEYS.iter().map(|k| (*k).to_owned()).collect()
}

/// Arg tokens of the log (without `@`), for the app's translation check.
#[uniffi::export]
pub fn log_arg_tokens() -> Vec<String> {
    TOKENS.iter().map(|t| (*t).to_owned()).collect()
}

fn hex4(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn token(t: &str) -> String {
    format!("@{t}")
}

fn sync_token(k: SyncKind) -> String {
    token(match k {
        SyncKind::Sent => "sync_sent",
        SyncKind::Contact => "sync_contact",
        SyncKind::Devices => "sync_devices",
        SyncKind::Admin => "sync_admin",
    })
}

/// Family, key and args of an event. `name` gives the name a contact is
/// shown under.
///
/// No wildcard: a new event variant must get its key here.
fn parts(
    e: &TransparencyEvent,
    name: &dyn Fn(&Fingerprint) -> String,
) -> (String, String, Vec<String>) {
    use TransparencyEvent as E;
    let n = |v: u32| v.to_string();
    let (family, key, args): (&str, &str, Vec<String>) = match e {
        E::SessionEstablished {
            contact,
            device,
            initiator,
            post_quantum,
        } => (
            "session",
            "log.session_established",
            vec![
                name(contact),
                hex4(&device.0),
                token(if *initiator { "initiator" } else { "responder" }),
                token(if *post_quantum {
                    "post_quantum"
                } else {
                    "no_post_quantum"
                }),
            ],
        ),
        E::PacketSealed {
            tier,
            size,
            expires_at,
            first_contact,
            ..
        } => (
            "packet",
            "log.packet_sealed",
            vec![
                size.to_string(),
                token(match tier {
                    Tier::S => "tier_small",
                    Tier::M => "tier_medium",
                    Tier::L => "tier_large",
                }),
                expires_at.to_string(),
                token(if *first_contact {
                    "intro_mailbox"
                } else {
                    "daily_mailbox"
                }),
            ],
        ),
        E::PacketOpened {
            sender,
            transport,
            first_contact,
            ..
        } => (
            "packet",
            "log.packet_opened",
            vec![
                name(sender),
                transport.clone(),
                if *first_contact {
                    token("intro_mailbox")
                } else {
                    String::new()
                },
            ],
        ),
        E::AckEmitted { for_packet } => ("packet", "log.ack_emitted", vec![hex4(&for_packet.0)]),
        E::AckVerified { for_packet } => ("packet", "log.ack_verified", vec![hex4(&for_packet.0)]),
        E::DecryptFailed { packet_id, reason } => (
            "packet",
            "log.decrypt_failed",
            vec![hex4(&packet_id.0), reason.clone()],
        ),
        E::DuplicateIgnored { packet_id } => {
            ("packet", "log.duplicate_ignored", vec![hex4(&packet_id.0)])
        }
        E::ContactKeyChanged { alias, old, new } => (
            "security",
            "log.contact_key_changed",
            vec![alias.clone(), old.to_string(), new.to_string()],
        ),
        E::FrameRejected { reason } => ("packet", "log.frame_rejected", vec![reason.clone()]),
        E::DeviceLinked { name, .. } => ("device", "log.device_linked", vec![name.clone()]),
        E::LinkFinished {
            device_count,
            contacts,
        } => (
            "device",
            "log.link_finished",
            vec![n(*device_count), n(*contacts)],
        ),
        E::SyncApplied { kind } => ("device", "log.sync_applied", vec![sync_token(*kind)]),
        E::SyncSkipped { kind } => ("device", "log.sync_skipped", vec![sync_token(*kind)]),
        E::ContactCardUpdated {
            contact,
            alias,
            added,
            removed,
        } => (
            "device",
            "log.contact_card_updated",
            vec![
                if alias.is_empty() {
                    name(contact)
                } else {
                    alias.clone()
                },
                n(*added),
                n(*removed),
            ],
        ),
        E::HistoryImported { count } => ("device", "log.history_imported", vec![n(*count)]),
        E::OwnDevicesUpdated { added, removed } => (
            "device",
            "log.own_devices_updated",
            vec![n(*added), n(*removed)],
        ),
        E::NodeDeposit {
            node,
            count,
            refused,
        } => (
            "node",
            "log.node_deposit",
            vec![node.clone(), n(*count), n(*refused)],
        ),
        E::NodeFetch {
            node,
            mailboxes,
            received,
        } => (
            "node",
            "log.node_fetch",
            vec![node.clone(), n(*mailboxes), n(*received)],
        ),
        E::NodeAvoided { node, reason } => (
            "node",
            "log.node_avoided",
            vec![
                node.clone(),
                token(match reason {
                    AvoidReason::MessageLost => "node_lost",
                    AvoidReason::Unreachable => "node_unreachable",
                }),
            ],
        ),
        E::SealSkipped { contact, device } => (
            "session",
            "log.seal_skipped",
            vec![name(contact), hex4(&device.0)],
        ),
        E::AdminTransferStarted { device } => (
            "device",
            "log.admin_transfer_started",
            vec![hex4(&device.0)],
        ),
        E::AdminTransferred { device } => {
            ("device", "log.admin_transferred", vec![hex4(&device.0)])
        }
        E::AdminReceived => ("device", "log.admin_received", vec![]),
        E::ThisDeviceRemoved { version } => (
            "security",
            "log.this_device_removed",
            vec![version.to_string()],
        ),
        E::DeviceRemoved { device, name } => (
            "device",
            "log.device_removed",
            vec![name.clone(), hex4(&device.0)],
        ),
        E::RemoveRequested { device, name } => (
            "device",
            "log.remove_requested",
            vec![name.clone(), hex4(&device.0)],
        ),
    };
    (family.to_owned(), key.to_owned(), args)
}

/// Entry of an event, with contacts shown under their alias, otherwise their
/// display name, otherwise their fingerprint.
pub(crate) fn entry_of(
    at: u64,
    e: &TransparencyEvent,
    names: &HashMap<Fingerprint, String>,
) -> LogEntry {
    let (family, key, args) = parts(e, &|fp| {
        names.get(fp).cloned().unwrap_or_else(|| fp.to_string())
    });
    LogEntry {
        at,
        family,
        key,
        args,
        security: e.is_security(),
    }
}

fn contact_names(core: &Core) -> Result<HashMap<Fingerprint, String>, BarkingError> {
    Ok(core
        .contacts()?
        .into_iter()
        .map(|c| {
            let shown = c.alias.filter(|a| !a.is_empty()).unwrap_or(c.display_name);
            (c.fingerprint, shown)
        })
        .collect())
}

#[uniffi::export]
impl Device {
    /// A page of the log, newest first: `limit` entries after the first
    /// `offset`. `security_only` keeps the security class only.
    pub fn transparency_log(
        &self,
        limit: u32,
        offset: u32,
        security_only: bool,
    ) -> Result<Vec<LogEntry>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let names = contact_names(core)?;
                Ok(core
                    .transparency_page(limit as usize, offset as usize, security_only)?
                    .iter()
                    .map(|(at, e)| entry_of(*at, e, &names))
                    .collect())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use barking_core::identity::DeviceId;
    use barking_core::mailbox::MailboxId;
    use barking_core::packet::PacketId;

    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint([b; 32])
    }

    /// Position of a variant: no wildcard, so a variant added without a
    /// sample here stops this test from compiling.
    fn index(e: &TransparencyEvent) -> usize {
        use TransparencyEvent as E;
        match e {
            E::SessionEstablished { .. } => 0,
            E::PacketSealed { .. } => 1,
            E::PacketOpened { .. } => 2,
            E::AckEmitted { .. } => 3,
            E::AckVerified { .. } => 4,
            E::DecryptFailed { .. } => 5,
            E::DuplicateIgnored { .. } => 6,
            E::ContactKeyChanged { .. } => 7,
            E::FrameRejected { .. } => 8,
            E::DeviceLinked { .. } => 9,
            E::LinkFinished { .. } => 10,
            E::SyncApplied { .. } => 11,
            E::SyncSkipped { .. } => 12,
            E::ContactCardUpdated { .. } => 13,
            E::HistoryImported { .. } => 14,
            E::OwnDevicesUpdated { .. } => 15,
            E::NodeDeposit { .. } => 16,
            E::NodeFetch { .. } => 17,
            E::NodeAvoided { .. } => 18,
            E::SealSkipped { .. } => 19,
            E::AdminTransferStarted { .. } => 20,
            E::AdminTransferred { .. } => 21,
            E::AdminReceived => 22,
            E::ThisDeviceRemoved { .. } => 23,
            E::DeviceRemoved { .. } => 24,
            E::RemoveRequested { .. } => 25,
        }
    }

    fn samples() -> Vec<TransparencyEvent> {
        use TransparencyEvent as E;
        let pid = PacketId([0xab; 16]);
        let dev = DeviceId([2; 16]);
        vec![
            E::SessionEstablished {
                contact: fp(1),
                device: dev,
                initiator: true,
                post_quantum: true,
            },
            E::PacketSealed {
                packet_id: pid,
                tier: Tier::M,
                size: 1024,
                mailbox: MailboxId([1; 16]),
                expires_at: 1_700_000_000,
                recipient_device: dev,
                first_contact: true,
            },
            E::PacketOpened {
                packet_id: pid,
                sender: fp(3),
                transport: "file".into(),
                first_contact: false,
            },
            E::AckEmitted { for_packet: pid },
            E::AckVerified { for_packet: pid },
            E::DecryptFailed {
                packet_id: pid,
                reason: "bad tag".into(),
            },
            E::DuplicateIgnored { packet_id: pid },
            E::ContactKeyChanged {
                alias: "Bob".into(),
                old: fp(4),
                new: fp(5),
            },
            E::FrameRejected {
                reason: "size".into(),
            },
            E::DeviceLinked {
                device: dev,
                name: "iPad".into(),
            },
            E::LinkFinished {
                device_count: 2,
                contacts: 3,
            },
            E::SyncApplied {
                kind: SyncKind::Sent,
            },
            E::SyncSkipped {
                kind: SyncKind::Admin,
            },
            E::ContactCardUpdated {
                contact: fp(6),
                alias: String::new(),
                added: 1,
                removed: 0,
            },
            E::HistoryImported { count: 7 },
            E::OwnDevicesUpdated {
                added: 1,
                removed: 1,
            },
            E::NodeDeposit {
                node: "abcd2345".into(),
                count: 2,
                refused: 0,
            },
            E::NodeFetch {
                node: "abcd2345".into(),
                mailboxes: 3,
                received: 1,
            },
            E::NodeAvoided {
                node: "abcd2345".into(),
                reason: AvoidReason::Unreachable,
            },
            E::SealSkipped {
                contact: fp(7),
                device: dev,
            },
            E::AdminTransferStarted { device: dev },
            E::AdminTransferred { device: dev },
            E::AdminReceived,
            E::ThisDeviceRemoved { version: 4 },
            E::DeviceRemoved {
                device: dev,
                name: "iPad".into(),
            },
            E::RemoveRequested {
                device: dev,
                name: "iPad".into(),
            },
        ]
    }

    #[test]
    fn every_variant_maps_to_a_listed_key() {
        let samples = samples();
        let keys = log_keys();
        // One sample and one key per variant, no duplicates.
        let indexes: HashSet<usize> = samples.iter().map(index).collect();
        assert_eq!(indexes, (0..keys.len()).collect::<HashSet<_>>());
        assert_eq!(samples.len(), keys.len());
        assert_eq!(keys.iter().collect::<HashSet<_>>().len(), keys.len());
        let tokens: HashSet<String> = log_arg_tokens().into_iter().map(|t| token(&t)).collect();
        let names = HashMap::from([(fp(1), "Alice".to_owned())]);
        let mut seen = HashSet::new();
        for e in &samples {
            let entry = entry_of(10, e, &names);
            assert!(keys.contains(&entry.key), "{} not listed", entry.key);
            assert!(seen.insert(entry.key.clone()), "{} twice", entry.key);
            assert!(
                ["session", "packet", "device", "node", "security"]
                    .contains(&entry.family.as_str())
            );
            assert_eq!(entry.security, e.is_security());
            // Every token used is listed.
            for a in entry.args.iter().filter(|a| a.starts_with('@')) {
                assert!(tokens.contains(a), "token {a} not listed");
            }
        }
    }

    #[test]
    fn args_carry_names_and_no_addresses() {
        let names = HashMap::from([(fp(1), "Alice".to_owned())]);
        let e = entry_of(1, &samples()[0], &names);
        assert_eq!(e.args[0], "Alice");
        assert_eq!(e.args[1], "02020202");
        // Unknown contact: the fingerprint it is known by.
        let e = entry_of(1, &samples()[2], &names);
        assert_eq!(e.args[0], fp(3).to_string());
    }
}
