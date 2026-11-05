//! Unread marks (kept in the encrypted database, never in clear settings)
//! and key changes to warn about.

use barking_core::Core;
use barking_core::identity::root::Fingerprint;
use barking_core::store::Direction;
use barking_core::transparency::TransparencyEvent;

use crate::device::Device;
use crate::{BarkingError, guard};

/// Key of the unread marks in the core's state store.
const READ_KEY: &str = "app-read";
/// Format version of the marks.
const READ_VERSION: u8 = 1;
/// Transparency events read for key changes.
const LOG_LIMIT: usize = 10_000;

#[derive(Debug, uniffi::Record)]
pub struct UnreadCount {
    pub contact: String,
    pub count: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct KeyChange {
    /// Fingerprint of the new key.
    pub contact: String,
    /// Unix seconds.
    pub at: u64,
}

type Marks = Vec<([u8; 32], i64)>;

fn load_marks(core: &Core) -> Result<Marks, BarkingError> {
    let Some(bytes) = core.transport_state(READ_KEY)? else {
        return Ok(Vec::new());
    };
    match postcard::from_bytes::<(u8, Marks)>(&bytes) {
        Ok((READ_VERSION, marks)) => Ok(marks),
        // Unknown or damaged: start over (unread counts only).
        _ => Ok(Vec::new()),
    }
}

fn save_marks(core: &mut Core, marks: &Marks) -> Result<(), BarkingError> {
    let bytes = postcard::to_allocvec(&(READ_VERSION, marks)).map_err(BarkingError::internal)?;
    Ok(core.set_transport_state(READ_KEY, &bytes)?)
}

fn mark_of(marks: &Marks, fp: &Fingerprint) -> i64 {
    marks
        .iter()
        .find(|(k, _)| k == &fp.0)
        .map_or(0, |(_, v)| *v)
}

#[uniffi::export]
impl Device {
    /// Messages of `contact` up to `up_to` (a message id) are read.
    pub fn mark_read(&self, contact: String, up_to: i64) -> Result<(), BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let fp = core.resolve(&contact)?;
                let mut marks = load_marks(core)?;
                match marks.iter_mut().find(|(k, _)| k == &fp.0) {
                    Some((_, v)) => *v = (*v).max(up_to),
                    None => marks.push((fp.0, up_to)),
                }
                save_marks(core, &marks)
            })
        })
    }

    /// Received messages after the last read one, per contact (none: absent).
    pub fn unread_counts(&self) -> Result<Vec<UnreadCount>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                let marks = load_marks(core)?;
                let mut out = Vec::new();
                for c in core.contacts()? {
                    let mark = mark_of(&marks, &c.fingerprint);
                    let count = core
                        .messages_with(&c.fingerprint)?
                        .iter()
                        .filter(|m| m.direction == Direction::In && m.id > mark)
                        .count();
                    if count > 0 {
                        out.push(UnreadCount {
                            contact: c.fingerprint.to_string(),
                            count: u32::try_from(count).unwrap_or(u32::MAX),
                        });
                    }
                }
                Ok(out)
            })
        })
    }

    /// Contact key changes logged after `since` (Unix seconds).
    pub fn key_changes(&self, since: u64) -> Result<Vec<KeyChange>, BarkingError> {
        guard(|| {
            self.with_core(|core| {
                Ok(core
                    .transparency_log(LOG_LIMIT)?
                    .into_iter()
                    .filter(|(at, _)| *at >= since)
                    .filter_map(|(at, e)| match e {
                        TransparencyEvent::ContactKeyChanged { new, .. } => Some(KeyChange {
                            contact: new.to_string(),
                            at,
                        }),
                        _ => None,
                    })
                    .collect())
            })
        })
    }
}
