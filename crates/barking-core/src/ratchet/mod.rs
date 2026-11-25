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

pub(crate) use header::ENC_HEADER_LEN;
pub use header::RatchetMessage;
pub use state::RatchetState;

/// Authentication tag the body encryption adds to the plaintext
/// (ChaCha20-Poly1305, `state::seal_body`): `ct.len() == pt.len() + 16`.
pub(crate) const BODY_TAG_LEN: usize = 16;
#[cfg(test)]
pub(crate) use state::STATE_CLONES;

/// Maximum number of skipped message keys within a single chain.
pub const MAX_SKIP: u32 = 1000;

/// Maximum number of skipped keys kept in total; beyond that, the oldest are dropped.
pub const MAX_SKIPPED_TOTAL: usize = 2000;

/// Retention time of a skipped key, counted from when it was set aside:
/// 8 days, the 7-day message lifetime plus a day of clock skew, so that a
/// message delivered late within its lifetime still decrypts.
pub const MAX_SKIPPED_AGE_SECS: u64 = 8 * 86_400;
