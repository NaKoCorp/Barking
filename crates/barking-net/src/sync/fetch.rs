//! Fetch stage of the sync: grouping by best responsible, the move to the
//! next responsible, positions, and the loss audit of session fetches.

use std::collections::{BTreeMap, HashMap, HashSet};

use barking_packet::MailboxId;
use barking_proto::client::MAX_FETCH_BYTES;
use barking_proto::{ErrorReason, NodeId};
use tokio::time::Instant;

use super::io::{Depositor, FetchReply, Fetcher};
use super::{
    INTRO_FETCH_BYTES, Run, SESSION_FETCH_SLICE, UNAUDITED_SYNCS, intro_slice, receive_all,
};
use crate::discover::{DialError, Dialer};
use crate::plan::{detect_losses, found_messages};
use crate::score::ScoreEvent;

/// How one group fetch ended.
pub(super) enum GroupEnd {
    /// Fetched in full.
    Complete,
    /// Failed, refused, rate limited or truncated: try the next responsible.
    Incomplete { truncated: bool },
    /// Deadline or slice over: stop the stage.
    Stop,
}

impl<D> Run<'_, D>
where
    D: Dialer + Depositor + Fetcher + Sync,
{
    /// Fetches `mailboxes`, grouped by best responsible, moving the
    /// mailboxes of a failed or truncated group to their next responsible
    /// (introductions: on failure only). Returns true if every mailbox was
    /// fetched in full and processed.
    pub(super) async fn fetch_stage(&mut self, mailboxes: &[MailboxId], intro: bool) -> bool {
        let now = self.now;
        let slice = if intro {
            intro_slice()
        } else {
            SESSION_FETCH_SLICE
        };
        let slice_end = (Instant::now() + slice).min(self.deadline);
        let ranked: HashMap<MailboxId, Vec<NodeId>> = mailboxes
            .iter()
            .map(|m| (*m, self.state.view.responsibles_by_score(m, now)))
            .collect();
        // Next responsible to try, by mailbox; `None`: given up.
        let mut next: HashMap<MailboxId, Option<usize>> =
            mailboxes.iter().map(|m| (*m, Some(0))).collect();
        let mut done: HashSet<MailboxId> = HashSet::new();
        let mut all_processed = true;
        let mut bytes_left = if intro {
            INTRO_FETCH_BYTES
        } else {
            MAX_FETCH_BYTES
        };
        // Per node: did all its session fetches of this sync complete?
        let mut complete_by_node: HashMap<NodeId, bool> = HashMap::new();
        'rounds: loop {
            let mut groups: BTreeMap<[u8; 32], (NodeId, Vec<MailboxId>)> = BTreeMap::new();
            for m in mailboxes {
                if done.contains(m) {
                    continue;
                }
                let Some(Some(from)) = next.get(m).copied() else {
                    continue;
                };
                let list = &ranked[m];
                let pick = (from..list.len())
                    .find(|&i| !self.failed.contains(&list[i]) && !self.limited.contains(&list[i]));
                next.insert(*m, pick);
                if let Some(i) = pick {
                    groups
                        .entry(list[i].0)
                        .or_insert_with(|| (list[i], Vec::new()))
                        .1
                        .push(*m);
                }
            }
            if groups.is_empty() {
                break;
            }
            for (_, (node, group)) in groups {
                if Instant::now() >= slice_end || (intro && bytes_left == 0) {
                    break 'rounds;
                }
                let max_bytes = if intro { bytes_left } else { MAX_FETCH_BYTES };
                let (end, bytes, processed) = self
                    .fetch_group(node, &group, intro, max_bytes, slice_end)
                    .await;
                bytes_left = bytes_left.saturating_sub(bytes);
                all_processed &= processed;
                match end {
                    GroupEnd::Complete => {
                        complete_by_node.entry(node).or_insert(true);
                        done.extend(group.iter().copied());
                        self.report.mailboxes_polled += group.len();
                    }
                    GroupEnd::Incomplete { truncated } => {
                        // Only a node that answered without completing
                        // escapes the audit; a dead one already failed.
                        if truncated {
                            complete_by_node.insert(node, false);
                        }
                        for m in &group {
                            let step = if intro && truncated {
                                // A flooded introduction mailbox is not
                                // worth fetching twice.
                                None
                            } else {
                                next[m].map(|i| i + 1)
                            };
                            next.insert(*m, step);
                        }
                    }
                    GroupEnd::Stop => {
                        break 'rounds;
                    }
                }
            }
        }
        if !intro {
            self.note_audits(complete_by_node);
        }
        all_processed && mailboxes.iter().all(|m| done.contains(m))
    }

    /// Counts the syncs in which a node's session fetch never completed;
    /// from `UNAUDITED_SYNCS` on, one failure per sync.
    fn note_audits(&mut self, complete_by_node: HashMap<NodeId, bool>) {
        for (node, complete) in complete_by_node {
            if complete {
                self.state.unaudited.remove(&node);
                continue;
            }
            let count = self.state.unaudited.entry(node).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= UNAUDITED_SYNCS {
                self.score(node, ScoreEvent::Failure);
            }
        }
        self.save();
    }

    /// One fetch of `group` from `node`. Returns how it ended, the bytes
    /// received and whether every item was processed.
    async fn fetch_group(
        &mut self,
        node: NodeId,
        group: &[MailboxId],
        intro: bool,
        max_bytes: usize,
        slice_end: Instant,
    ) -> (GroupEnd, usize, bool) {
        let Some(mut conn) = self.take_conn(node).await else {
            let end = if self.over() {
                GroupEnd::Stop
            } else {
                GroupEnd::Incomplete { truncated: false }
            };
            return (end, 0, true);
        };
        let mut resume = self.state.resume(&node, group);
        // Mailboxes read from their very start: the only ones a loss audit
        // may rely on (a resumed fetch skips the items already seen).
        let from_start: Vec<MailboxId> = group
            .iter()
            .filter(|m| resume.seen.get(&m.0).copied().unwrap_or(0) == 0)
            .copied()
            .collect();
        let slice = slice_end.saturating_duration_since(Instant::now());
        let fetch = self
            .dialer
            .fetch(&mut conn, group, &mut resume, max_bytes, slice);
        let reply = match tokio::time::timeout_at(self.deadline, fetch).await {
            Err(_) => return (GroupEnd::Stop, 0, true),
            Ok(r) => r,
        };
        let (items, complete) = match reply {
            Ok(FetchReply::Items { items, complete }) => (items, complete),
            Ok(FetchReply::RateLimited) | Err(DialError::Refused(ErrorReason::RateLimited)) => {
                self.answered();
                self.limited.insert(node);
                self.conns.insert(node, conn);
                return (GroupEnd::Incomplete { truncated: true }, 0, true);
            }
            Err(DialError::Refused(_)) => {
                self.answered();
                self.conns.insert(node, conn);
                return (GroupEnd::Incomplete { truncated: false }, 0, true);
            }
            Err(_) => {
                self.fail(node);
                return (GroupEnd::Incomplete { truncated: false }, 0, true);
            }
        };
        self.answered();
        self.score(node, ScoreEvent::Success);
        self.conns.insert(node, conn);
        let bytes = items
            .iter()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add);
        let mut received = Vec::new();
        let mut errors = 0;
        let processed = receive_all(self.core, &items, self.now, |r| match r {
            Ok(o) => received.push(o),
            Err(_) => errors += 1,
        });
        self.report.received.append(&mut received);
        self.report.receive_errors += errors;
        self.report.items_received += items.len();
        if processed {
            self.state.set_positions(&node, group, &resume);
        }
        if !intro {
            self.audit(node, &items, if complete { &from_start } else { &[] });
        }
        let s = self.stats(node);
        s.fetched = true;
        s.mailboxes = s
            .mailboxes
            .saturating_add(u32::try_from(group.len()).unwrap_or(u32::MAX));
        s.received = s
            .received
            .saturating_add(u32::try_from(items.len()).unwrap_or(u32::MAX));
        self.save();
        let end = if complete {
            GroupEnd::Complete
        } else {
            GroupEnd::Incomplete { truncated: true }
        };
        (end, bytes, processed)
    }

    /// Loss audit of a session fetch from `node`: `audited` are the
    /// mailboxes read in full from their start. The send queue is read after
    /// the items were processed, so that receipts just fetched took their
    /// messages out of it.
    fn audit(&mut self, node: NodeId, items: &[Vec<u8>], audited: &[MailboxId]) {
        if !audited.is_empty()
            && let Ok(outbox) = self.core.pending_outbox(self.now)
        {
            let lost = detect_losses(
                &mut self.state.ledger,
                &node,
                audited,
                items,
                &outbox,
                self.now,
            );
            for _ in lost {
                self.score(node, ScoreEvent::Lost);
            }
        }
        if !self.found.contains(&node)
            && !found_messages(&self.state.ledger, &node, items).is_empty()
        {
            self.found.insert(node);
            self.score(node, ScoreEvent::Found);
        }
    }
}
