//! Client-side view of the Barking network: the local node view, the
//! selection of the nodes responsible for a mailbox, node reliability scores
//! and the deposit plan, the state kept between synchronizations and the
//! synchronization itself (the only part doing I/O, through traits).

pub mod discover;
pub mod plan;
pub mod score;
pub mod state;
pub mod sync;
pub mod view;

#[cfg(test)]
mod test_support;

pub use discover::{
    BootstrapReport, BootstrapSource, CandidateBudget, DialError, Dialer, FallbackLog, QuicDialer,
    bootstrap, choose_card_nodes, fallback_lookup, random_lookups,
};
pub use plan::{Ledger, PlannedDeposit};
pub use score::{Score, ScoreEvent};
pub use state::NetState;
pub use sync::{
    Connector, DepositOutcome, DepositReply, Depositor, FetchReply, FetchStop, Fetcher,
    SyncOptions, SyncReport, sync,
};
pub use view::{NodeEntry, View};

/// Maximum number of node entries kept in the view.
pub const MAX_VIEW: usize = 2048;
/// Longest avoidance of a node, from the current time.
pub const AVOID_SECS: u64 = 7 * 86_400;
/// Entries not seen for this long are dropped (manual nodes excepted).
pub const VIEW_TTL_SECS: u64 = 7 * 86_400;
/// Number of responsible nodes selected for a mailbox.
pub const RESPONSIBLES: usize = 5;
/// Maximum responsibles sharing an address block (/24 or /48).
pub const MAX_PER_PREFIX: usize = 2;
/// Below this many entries the view is too small and a fallback lookup is due.
pub const SMALL_VIEW: usize = 20;
/// While the view is below this size, lookups fill it more aggressively.
pub const BOOTSTRAP_VIEW: usize = 50;
/// Minimum delay between two fallback lookups for the same mailbox.
pub const FALLBACK_COOLDOWN_SECS: u64 = 86_400;
