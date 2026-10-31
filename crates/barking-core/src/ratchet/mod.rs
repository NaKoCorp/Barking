//! Double ratchet with encrypted headers (Signal Double Ratchet spec, §3.5 and §4).
//!
//! Deliberate implementation deviation: `decrypt` does not receive a random
//! generator. The "send" half of the DH step (new `DHs` pair, then
//! `KDF_RK` for `CKs` and `NHKs`) is therefore deferred to the next `encrypt`.
//! The old `DHs` private key is erased upon reception, as in
//! Signal; the resulting sequence of keys is identical.

mod header;
mod state;

#[cfg(test)]
mod tests;

pub use header::RatchetMessage;
pub use state::RatchetState;
#[cfg(test)]
pub(crate) use state::STATE_CLONES;

/// Maximum number of skipped message keys within a single chain.
pub const MAX_SKIP: u32 = 1000;

/// Maximum number of skipped keys kept in total; beyond that, the oldest are dropped.
pub const MAX_SKIPPED_TOTAL: usize = 2000;

/// Retention time of a skipped key (spec §11: 7 days at most),
/// counted from when it was set aside.
pub const MAX_SKIPPED_AGE_SECS: u64 = 7 * 86_400;
