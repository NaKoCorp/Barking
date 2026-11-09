//! Single writer of the node database, with group commit (spec SQLite
//! throughput §3).
//!
//! A dedicated thread owns the write connection. Operations arrive through a
//! channel; the thread opens a transaction, runs the first operation and then
//! every operation already waiting (at most `max_batch`), and commits once:
//! one fsync for the whole batch. There is no artificial wait: under low load
//! a batch holds a single operation, under load the operations that arrived
//! during the previous fsync form the next batch.
//!
//! Each operation runs in its own savepoint: a storage error or a panic only
//! undoes that operation. Results are handed back only after the commit, so
//! an `Ok` is never sent for a write that a power cut could still lose. If
//! SQLite rolls back the whole transaction (`SQLITE_FULL`, I/O error), or the
//! commit fails, no operation of the batch gets a result.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::oneshot;

use crate::Result;
use crate::rules::Policy;
use crate::store::NodeStore;

/// Operations committed together at most.
pub(crate) const MAX_BATCH: usize = 256;

/// Hands an operation's result to its caller (or drops it).
type Deliver = Box<dyn FnOnce() + Send>;
/// Runs an operation; `true` if it succeeded (its savepoint is kept).
type Job = Box<dyn FnOnce(&mut NodeStore, &Policy) -> (bool, Deliver) + Send>;

/// Handle on the writer thread; the thread stops once every handle is
/// dropped and the queued operations are done.
#[derive(Clone)]
pub(crate) struct Writer {
    jobs: mpsc::Sender<Job>,
    #[cfg(test)]
    commits: Arc<AtomicU64>,
}

impl Writer {
    pub(crate) fn spawn(store: NodeStore, policy: Policy, max_batch: usize) -> Result<Writer> {
        let (jobs, rx) = mpsc::channel::<Job>();
        #[cfg(test)]
        let commits = Arc::new(AtomicU64::new(0));
        #[cfg(test)]
        let counter = Arc::clone(&commits);
        std::thread::Builder::new()
            .name("barking-db-writer".into())
            .spawn(move || {
                let on_commit = || {
                    #[cfg(test)]
                    counter.fetch_add(1, Ordering::Relaxed);
                };
                writer_loop(store, policy, max_batch.max(1), &rx, on_commit);
            })?;
        Ok(Writer {
            jobs,
            #[cfg(test)]
            commits,
        })
    }

    /// Runs `f` in the next batch. `hold` (queue slots) is dropped just before
    /// the result is handed back, or when the operation is abandoned. `None`: the
    /// operation panicked, its batch was not committed (logged by the
    /// writer), or the writer has stopped.
    pub(crate) async fn run<T, F, H>(&self, f: F, hold: H) -> Option<Result<T>>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeStore, &Policy) -> Result<T> + Send + 'static,
        H: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let job: Job = Box::new(move |store, policy| {
            let r = f(store, policy);
            let ok = r.is_ok();
            let deliver: Deliver = Box::new(move || {
                // Slots first: a caller that sends its next request on this
                // result must find them free.
                drop(hold);
                let _ = tx.send(r);
            });
            (ok, deliver)
        });
        self.jobs.send(job).ok()?;
        rx.await.ok()
    }

    /// Transactions committed so far.
    #[cfg(test)]
    pub(crate) fn commits(&self) -> u64 {
        self.commits.load(Ordering::Relaxed)
    }
}

fn writer_loop(
    mut store: NodeStore,
    policy: Policy,
    max_batch: usize,
    jobs: &mpsc::Receiver<Job>,
    on_commit: impl Fn(),
) {
    while let Ok(first) = jobs.recv() {
        // Results of the operations of the open transaction, handed back
        // after the commit.
        let mut done: Vec<Deliver> = Vec::new();
        let mut open = false;
        let mut taken = 0;
        let mut next = Some(first);
        while let Some(job) = next.take() {
            taken += 1;
            if !open {
                match store.conn().execute_batch("BEGIN IMMEDIATE") {
                    Ok(()) => open = true,
                    Err(e) => tracing::error!("database transaction not opened: {e}"),
                }
            }
            if open {
                run_job(&mut store, &policy, job, &mut done);
                if store.conn().is_autocommit() {
                    tracing::error!("database transaction rolled back, batch dropped");
                    done.clear();
                    open = false;
                }
            }
            if taken < max_batch {
                next = jobs.try_recv().ok();
            }
        }
        if open {
            match store.conn().execute_batch("COMMIT") {
                Ok(()) => {
                    on_commit();
                    done.into_iter().for_each(|d| d());
                }
                Err(e) => {
                    tracing::error!("database commit failed, batch dropped: {e}");
                    let _ = store.conn().execute_batch("ROLLBACK");
                }
            }
        }
    }
}

/// Runs `job` in a savepoint of the open transaction. A success waits for the
/// commit in `done`; a failure is undone and its error handed back at once
/// (nothing of it is written); a panic is undone and dropped.
fn run_job(store: &mut NodeStore, policy: &Policy, job: Job, done: &mut Vec<Deliver>) {
    if let Err(e) = store.conn().execute_batch("SAVEPOINT job") {
        tracing::error!("database savepoint not opened: {e}");
        return;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| job(store, policy)));
    let kept =
        matches!(outcome, Ok((true, _))) && store.conn().execute_batch("RELEASE job").is_ok();
    if !kept {
        let _ = store.conn().execute_batch("ROLLBACK TO job; RELEASE job");
    }
    match outcome {
        Ok((true, deliver)) if kept => done.push(deliver),
        Ok((false, deliver)) => deliver(),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
