//! Network calls: nodes added by hand, full sync and the extension's quick
//! sync. Each call builds a single-threaded runtime for its own duration, as
//! the CLI does: one thread, a predictable memory use in the extension.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use barking_core::{Core, ReceiveOutcome};
use barking_net::{NetState, QuicDialer, QuickOptions, SyncOptions, SyncReport};
use barking_proto::NodeId;

use crate::device::{Device, now};
use crate::{BarkingError, guard};

/// What a sync did, reduced to what the apps show.
#[derive(Debug, uniffi::Record)]
pub struct SyncSummary {
    pub items_received: u32,
    /// New visible messages, in arrival order.
    pub new_messages: Vec<NewMessage>,
    /// Some node answered.
    pub network_up: bool,
    /// Local error that stopped the sync (logs only).
    pub error: Option<String>,
}

#[derive(Debug, uniffi::Record)]
pub struct NewMessage {
    /// Fingerprint of the sender.
    pub contact: String,
    /// Alias, otherwise display name, otherwise the start of the fingerprint.
    pub name: String,
    pub text: String,
}

/// Time a runtime is given to close once the sync has returned.
const SHUTDOWN: Duration = Duration::from_secs(1);

fn block_on<F: Future>(f: F) -> Result<F::Output, BarkingError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(BarkingError::internal)?;
    let out = rt.block_on(f);
    rt.shutdown_timeout(SHUTDOWN);
    Ok(out)
}

fn summary(core: &Core, mut report: SyncReport) -> SyncSummary {
    let contacts = core.contacts().unwrap_or_default();
    let new_messages = std::mem::take(&mut report.received)
        .into_iter()
        .filter_map(|o| match o {
            ReceiveOutcome::Message {
                from, alias, text, ..
            } => {
                let contact = from.to_string();
                let name = alias
                    .or_else(|| {
                        contacts
                            .iter()
                            .find(|c| c.fingerprint == from)
                            .map(|c| c.display_name.clone())
                    })
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| contact.chars().take(8).collect());
                Some(NewMessage {
                    contact,
                    name,
                    text,
                })
            }
            _ => None,
        })
        .collect();
    SyncSummary {
        items_received: u32::try_from(report.items_received).unwrap_or(u32::MAX),
        new_messages,
        network_up: report.network_up,
        error: report.error,
    }
}

#[uniffi::export]
impl Device {
    /// Adds a node by hand (base32 identifier, `host:port` address).
    pub fn add_node(&self, id: String, addr: String) -> Result<(), BarkingError> {
        guard(|| {
            let id: NodeId = id.trim().to_ascii_uppercase().parse().map_err(|_| {
                BarkingError::invalid("node identifier: 52-character base32 expected")
            })?;
            if !id.puzzle_ok() {
                return Err(BarkingError::invalid(
                    "node identifier does not solve the identity puzzle",
                ));
            }
            let addr: SocketAddr = addr
                .trim()
                .parse()
                .map_err(|_| BarkingError::invalid("node address: ip:port expected"))?;
            let allow_private = self.allow_private();
            self.with_core(|core| {
                let t = now();
                let (mut state, _) = NetState::load_checked(core, t, allow_private)
                    .map_err(BarkingError::storage)?;
                state.view.add_manual(id, addr, t);
                state.save(core).map_err(BarkingError::storage)
            })
        })
    }

    /// Full sync, for at most `deadline_ms`.
    pub fn sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts = SyncOptions {
                deadline: Duration::from_millis(deadline_ms),
                allow_private: self.allow_private(),
                ..SyncOptions::default()
            };
            self.with_core(|core| {
                let report = block_on(barking_net::sync(core, &QuicDialer, opts))?;
                Ok(summary(core, report))
            })
        })
    }

    /// Quick sync of the notification extension, for at most `deadline_ms`.
    pub fn quick_sync(&self, deadline_ms: u64) -> Result<SyncSummary, BarkingError> {
        guard(|| {
            let opts = QuickOptions {
                deadline: Duration::from_millis(deadline_ms),
                allow_private: self.allow_private(),
                ..QuickOptions::default()
            };
            self.with_core(|core| {
                let report = block_on(barking_net::quick_sync(core, &QuicDialer, opts))?;
                Ok(summary(core, report))
            })
        })
    }
}
