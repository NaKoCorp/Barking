//! Fetch stage of the sync: grouping by best responsible, the move to the
//! next responsible, positions, and the loss audit of session fetches.

use std::collections::{BTreeMap, HashMap, HashSet};

use barking_packet::{Kind, MailboxId, Packet};
use barking_proto::client::MAX_FETCH_BYTES;
use barking_proto::pow::content_hash;
use barking_proto::{ErrorReason, NodeId};
use tokio::time::Instant;

use super::io::{Depositor, FetchReply, Fetcher};
use super::{
    AUDIT_EVERY_SECS, INTRO_FETCH_BYTES, Run, SESSION_FETCH_SLICE, UNAUDITED_SYNCS, intro_slice,
    receive_all,
};
use crate::discover::{DialError, Dialer};
use crate::plan::{detect_losses, found_messages};
use crate::score::ScoreEvent;

/// How one group fetch ended.
pub(super) enum GroupEnd {
    /// Fetched in full.
    Complete,
    /// Failed, refused, rate limited or truncated: try the next responsible.
    /// `counts`: the node answered and did not complete for a reason of its
    /// own (not a rate limit, not the client's slice or deadline running out).
    Incomplete { truncated: bool, counts: bool },
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
        // Per node: did any of its session fetches complete this sync?
        // Only raised; a node enters only once it completed, or answered
        // without completing for a reason of its own.
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
                        complete_by_node.insert(node, true);
                        done.extend(group.iter().copied());
                        self.report.mailboxes_polled += group.len();
                    }
                    GroupEnd::Incomplete { truncated, counts } => {
                        // A dead node already failed; a rate limit or the
                        // client's own slow link is not the node's doing.
                        if counts {
                            complete_by_node.entry(node).or_insert(false);
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

    /// Counts the syncs in which none of a node's session fetches completed;
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
                GroupEnd::Incomplete {
                    truncated: false,
                    counts: false,
                }
            };
            return (end, 0, true);
        };
        let mut resume = self.state.resume(&node, group);
        // Mailboxes holding a message this node accepted, not audited there
        // for `AUDIT_EVERY_SECS`: read again from their start (without a
        // position they get their own slices, so the others keep theirs).
        let mut reread: Vec<(MailboxId, u64)> = Vec::new();
        if !intro {
            for m in self.audit_targets(node, group) {
                if let Some(old) = resume.seen.remove(&m.0)
                    && old > 0
                {
                    reread.push((m, old));
                }
            }
        }
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
                let end = GroupEnd::Incomplete {
                    truncated: true,
                    counts: false,
                };
                return (end, 0, true);
            }
            Err(DialError::Refused(_)) => {
                self.answered();
                self.conns.insert(node, conn);
                let end = GroupEnd::Incomplete {
                    truncated: false,
                    counts: false,
                };
                return (end, 0, true);
            }
            Err(_) => {
                self.fail(node);
                let end = GroupEnd::Incomplete {
                    truncated: false,
                    counts: false,
                };
                return (end, 0, true);
            }
        };
        // Truncated while the client's slice or deadline ran out: a slow
        // link, not a node that never lets itself be read to the end.
        let cut_by_client = Instant::now() >= slice_end;
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
            if !complete {
                // A cut re-read does not take a mailbox back.
                for (m, old) in &reread {
                    let seen = resume.seen.entry(m.0).or_insert(0);
                    *seen = (*seen).max(*old);
                }
            }
            self.state.set_positions(&node, group, &resume);
        }
        if !intro {
            // A truncated fetch audits nothing.
            let audited: &[MailboxId] = if complete { &from_start } else { &[] };
            self.audit(node, &items, audited);
            for m in audited {
                self.state.note_audit(&node, m, self.now);
            }
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
            GroupEnd::Incomplete {
                truncated: true,
                counts: !cut_by_client,
            }
        };
        (end, bytes, processed)
    }

    /// Mailboxes of `group` holding one of my pending messages that `node`
    /// accepted, whose last audit on `node` is `AUDIT_EVERY_SECS` old.
    fn audit_targets(&mut self, node: NodeId, group: &[MailboxId]) -> Vec<MailboxId> {
        let Ok(outbox) = self.core.pending_outbox(self.now) else {
            return Vec::new();
        };
        let mut out: Vec<MailboxId> = outbox
            .iter()
            .filter_map(|b| {
                let p = Packet::decode(b).ok()?;
                (p.kind == Kind::Message
                    && group.contains(&p.mailbox)
                    && self.state.ledger.holders(&content_hash(b)).contains(&node)
                    && self
                        .state
                        .audit_due(&node, &p.mailbox, self.now, AUDIT_EVERY_SECS))
                .then_some(p.mailbox)
            })
            .collect();
        out.sort_unstable_by_key(|m| m.0);
        out.dedup();
        out
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
