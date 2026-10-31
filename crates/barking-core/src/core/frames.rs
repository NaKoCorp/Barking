//! Fragmentation and reassembly: `frames` splits a packet for a
//! small-MTU transport, `receive_frame` glues received frames back together.

use rand_core::CryptoRng;

use super::log_limit::{NOISY_EVENT_LOG_INTERVAL_SECS, log_limited};
use super::{Core, ReceiveOutcome};
use crate::Result;
use crate::fragment::{REASON_BAD_HASH, REASON_CONTRADICTORY, fragment};
use crate::transparency::TransparencyEvent;

/// Maximum number of incomplete packets kept in memory.
pub const MAX_PENDING_FRAMES: usize = 64;

/// Lifetime, in seconds, of an incomplete packet.
pub const FRAME_TTL_SECS: u64 = 3600;

/// Minimum interval, per reason, between two `FrameRejected` log entries
/// (the same as for all noisy events).
pub const FRAME_REJECT_LOG_INTERVAL_SECS: u64 = NOISY_EVENT_LOG_INTERVAL_SECS;

impl Core {
    /// Splits an encoded packet into frames of at most `mtu` bytes.
    pub fn frames(&self, packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
        Ok(fragment(packet, mtu)?)
    }

    /// Number of incomplete packets waiting for frames (diagnostics).
    pub fn pending_frames(&self) -> usize {
        self.frames.pending()
    }

    /// Handles a frame received by `transport`. `Partial` while the packet
    /// is incomplete; an invalid frame is logged then ignored
    /// (`NotForUs`): its content is never kept.
    pub fn receive_frame(
        &mut self,
        frame: &[u8],
        transport: &str,
        now: u64,
        rng: &mut impl CryptoRng,
    ) -> Result<ReceiveOutcome> {
        self.ensure_linked()?;
        match self.frames.push(frame, now) {
            Ok(None) => Ok(ReceiveOutcome::Partial),
            Ok(Some(bytes)) => self.receive(&bytes, transport, now, rng),
            Err(barking_packet::PacketError::Malformed(r)) => {
                // Only a wrong hash and contradictory frames are
                // logged, and at most once per reason per minute:
                // the rest (header noise) is ignored without writing.
                if r != REASON_BAD_HASH && r != REASON_CONTRADICTORY {
                    return Ok(ReceiveOutcome::NotForUs);
                }
                let event = TransparencyEvent::FrameRejected {
                    reason: r.to_owned(),
                };
                let Core {
                    store, log_limiter, ..
                } = self;
                store.transaction(|tx| log_limited(tx, log_limiter, now, None, &event))?;
                Ok(ReceiveOutcome::NotForUs)
            }
            Err(e) => Err(e.into()),
        }
    }
}
