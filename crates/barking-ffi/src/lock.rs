//! One process at a time in the database (spec iOS push §6.1): an exclusive
//! `flock` on a file of the shared container, held for one call only (spec
//! iOS foundations §3.3). `flock` belongs to the open file description, so two
//! lockers in the same process exclude each other too.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::BarkingError;

/// Pause between two attempts.
const RETRY: Duration = Duration::from_millis(20);

/// Held lock, released on drop (closing the file releases the `flock`).
pub(crate) struct DbLock {
    _file: File,
}

impl DbLock {
    /// Takes the lock, retrying until `timeout`; `Locked` afterwards.
    pub(crate) fn acquire(path: &Path, timeout: Duration) -> Result<DbLock, BarkingError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(BarkingError::storage)?;
        let deadline = Instant::now() + timeout;
        loop {
            // SAFETY: `flock` on a descriptor owned by `file`, alive here.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(DbLock { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(BarkingError::storage(err));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(BarkingError::Locked);
            }
            thread::sleep(RETRY.min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_locker_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.lock");
        let _first = DbLock::acquire(&path, Duration::from_millis(100)).unwrap();
        let start = Instant::now();
        let second = DbLock::acquire(&path, Duration::from_millis(300));
        assert!(matches!(second, Err(BarkingError::Locked)));
        assert!(start.elapsed() >= Duration::from_millis(300));
    }

    #[test]
    fn lock_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.lock");
        drop(DbLock::acquire(&path, Duration::from_millis(100)).unwrap());
        assert!(DbLock::acquire(&path, Duration::from_millis(100)).is_ok());
    }
}
