//! Rotating mailboxes: a 16-byte identifier that changes
//! every day and that only the two correspondents can compute.

use crate::crypto::labels;
use crate::identity::{DeviceId, DevicePublic};

pub use barking_packet::MailboxId;

fn truncate(full: &[u8; 32]) -> MailboxId {
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    MailboxId(out)
}

/// Day number (`now / 86400`).
pub fn day_of(now: u64) -> u32 {
    u32::try_from(now / 86400).unwrap_or(u32::MAX)
}

/// Previous day, current day and next day, saturating at 0.
pub fn candidate_days(now: u64) -> [u32; 3] {
    let d = day_of(now);
    [d.saturating_sub(1), d, d.saturating_add(1)]
}

/// Session mailbox of a recipient for a given day.
pub fn session_mailbox(secret: &[u8; 32], recipient: &DeviceId, day: u32) -> MailboxId {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(labels::MAILBOX);
    h.update(&recipient.0);
    h.update(&day.to_be_bytes());
    truncate(h.finalize().as_bytes())
}

/// Introduction mailbox, for the first message.
pub fn intro_mailbox(recipient: &DevicePublic, day: u32) -> MailboxId {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(&recipient.dh);
    input[32..].copy_from_slice(&day.to_be_bytes());
    truncate(&blake3::derive_key(labels::INTRO_MAILBOX_CONTEXT, &input))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: DeviceId = DeviceId([1; 16]);
    const B: DeviceId = DeviceId([2; 16]);

    #[test]
    fn same_for_both_parties() {
        let s = [7u8; 32];
        assert_eq!(session_mailbox(&s, &A, 5), session_mailbox(&s, &A, 5));
    }

    #[test]
    fn changes_every_day() {
        let s = [7u8; 32];
        assert_ne!(session_mailbox(&s, &A, 5), session_mailbox(&s, &A, 6));
        let p = DevicePublic {
            sig: [3; 32],
            dh: [4; 32],
        };
        assert_ne!(intro_mailbox(&p, 5), intro_mailbox(&p, 6));
    }

    #[test]
    fn direction_matters() {
        let s = [7u8; 32];
        assert_ne!(session_mailbox(&s, &A, 5), session_mailbox(&s, &B, 5));
        assert_ne!(
            session_mailbox(&s, &A, 5),
            session_mailbox(&[8u8; 32], &A, 5)
        );
    }

    #[test]
    fn intro_depends_on_dh_key() {
        let p = DevicePublic {
            sig: [3; 32],
            dh: [4; 32],
        };
        let q = DevicePublic {
            sig: [3; 32],
            dh: [5; 32],
        };
        assert_ne!(intro_mailbox(&p, 5), intro_mailbox(&q, 5));
    }

    #[test]
    fn candidates_cover_skew() {
        assert_eq!(candidate_days(86400 * 10 + 5), [9, 10, 11]);
        assert_eq!(candidate_days(0), [0, 0, 1]);
        assert_eq!(day_of(86399), 0);
        assert_eq!(day_of(86400), 1);
    }
}
