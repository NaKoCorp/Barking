//! One process at a time in the database (spec iOS push §6.1): an exclusive
//! `flock` on a file of the shared container, held for one call only (spec
//! iOS foundations §3.3). `flock` belongs to the open file description, so two
//! lockers in the same process exclude each other too.
//!
//! A sync holds the lock for its whole run, network waits included. It opens
//! it to the reads of its own process (`DbLock::acquire_read`): they join its
//! lock instead of waiting for it, and read on their own read-only
//! connection. The lock stays one `flock`, so other processes (the
//! notification extension) and the writes of this process still wait; it is
//! released once the sync and the reads that joined it are all done.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::BarkingError;

/// Pause between two attempts.
const RETRY: Duration = Duration::from_millis(20);

/// Lock files held by a sync of this process that reads may join, by path.
static OPEN_TO_READS: Mutex<Option<HashMap<PathBuf, Weak<File>>>> = Mutex::new(None);

/// Held lock, released on drop: closing the file releases the `flock`, once
/// every holder of the file (a sync and the reads that joined it) is gone.
pub(crate) struct DbLock {
    file: Arc<File>,
    /// Set for a sync's lock: its entry of `OPEN_TO_READS`, removed on drop.
    open_to_reads: Option<PathBuf>,
    /// This lock was joined: a sync of this process may be writing.
    joined: bool,
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
                return Ok(DbLock {
                    file: Arc::new(file),
                    open_to_reads: None,
                    joined: false,
                });
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

    /// Takes the lock for a sync (`acquire`), and opens it to the reads of
    /// this process until it is dropped.
    pub(crate) fn acquire_for_sync(path: &Path, timeout: Duration) -> Result<DbLock, BarkingError> {
        let mut lock = DbLock::acquire(path, timeout)?;
        let key = path.to_path_buf();
        table(|t| t.insert(key.clone(), Arc::downgrade(&lock.file)));
        lock.open_to_reads = Some(key);
        Ok(lock)
    }

    /// For a call that only reads: joins at once the lock of a sync of this
    /// process if one holds it, otherwise takes it (`acquire`).
    pub(crate) fn acquire_read(path: &Path, timeout: Duration) -> Result<DbLock, BarkingError> {
        if let Some(file) = table(|t| t.get(path).and_then(Weak::upgrade)) {
            return Ok(DbLock {
                file,
                open_to_reads: None,
                joined: true,
            });
        }
        DbLock::acquire(path, timeout)
    }

    /// Joined a sync's lock: the sync may be writing, so the read goes
    /// through a separate read-only connection.
    pub(crate) fn joined(&self) -> bool {
        self.joined
    }
}

impl Drop for DbLock {
    /// A sync's lock first stops taking reads; the `flock` itself goes with
    /// the last holder of the file.
    fn drop(&mut self) {
        if let Some(key) = self.open_to_reads.take() {
            let mine = Arc::downgrade(&self.file);
            table(|t| {
                if t.get(&key).is_some_and(|w| w.ptr_eq(&mine)) {
                    t.remove(&key);
                }
            });
        }
    }
}

fn table<T>(f: impl FnOnce(&mut HashMap<PathBuf, Weak<File>>) -> T) -> T {
    let mut guard = OPEN_TO_READS.lock().unwrap_or_else(PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
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

    #[test]
    fn read_joins_a_sync_lock_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.lock");
        let _sync = DbLock::acquire_for_sync(&path, Duration::from_millis(100)).unwrap();
        let start = Instant::now();
        let read = DbLock::acquire_read(&path, Duration::from_millis(300)).unwrap();
        assert!(read.joined());
        assert!(start.elapsed() < Duration::from_millis(100));
        // The writes of this process still wait.
        assert!(matches!(
            DbLock::acquire(&path, Duration::from_millis(50)),
            Err(BarkingError::Locked)
        ));
    }

    #[test]
    fn read_waits_for_a_plain_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.lock");
        let _write = DbLock::acquire(&path, Duration::from_millis(100)).unwrap();
        assert!(matches!(
            DbLock::acquire_read(&path, Duration::from_millis(50)),
            Err(BarkingError::Locked)
        ));
    }

    #[test]
    fn joined_read_keeps_the_lock_past_the_sync() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barking.lock");
        let sync = DbLock::acquire_for_sync(&path, Duration::from_millis(100)).unwrap();
        let read = DbLock::acquire_read(&path, Duration::from_millis(100)).unwrap();
        drop(sync);
        // The sync is over: no new read joins, and the read that did still
        // holds the lock.
        assert!(matches!(
            DbLock::acquire_read(&path, Duration::from_millis(50)),
            Err(BarkingError::Locked)
        ));
        drop(read);
        let next = DbLock::acquire_read(&path, Duration::from_millis(100)).unwrap();
        assert!(!next.joined());
    }
}
