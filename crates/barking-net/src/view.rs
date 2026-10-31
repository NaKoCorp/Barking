//! Local view of the network: signed node records the client knows, with
//! their confirmation state, score and avoidance, and the selection of the
//! nodes responsible for a mailbox.
//!
//! Dates are Unix seconds. The wall clock may jump: dates from the future
//! are clamped to `now` and a single `expire` call never drops more than half
//! of the view, so a clock error cannot wipe the view or ban a node forever.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::SocketAddr;

use barking_dht::{Prefix, distance, mailbox_key, prefixes};
use barking_packet::MailboxId;
use barking_proto::{NodeId, NodeRecord, RecordPolicy};
use serde::{Deserialize, Serialize};

use crate::{MAX_PER_PREFIX, MAX_VIEW, RESPONSIBLES, SMALL_VIEW, VIEW_TTL_SECS};

/// Longest avoidance of a node, from the current time.
const MAX_AVOID_SECS: u64 = 7 * 86_400;

/// Reputation of a node in `[0, 1]`, starting at 0.5.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score(f32);

impl Default for Score {
    fn default() -> Self {
        Score(0.5)
    }
}

impl Score {
    /// A score clamped to `[0, 1]`; NaN gives the default.
    #[cfg(test)]
    pub(crate) fn new(value: f32) -> Score {
        if value.is_nan() {
            Score::default()
        } else {
            Score(value.clamp(0.0, 1.0))
        }
    }

    pub fn value(self) -> f32 {
        self.0
    }
}

/// A node of the view. Nodes added by hand or migrated from the old state
/// may have no signed record yet: they only have an address.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeEntry {
    /// Signed record, once known. Distance-based logic ignores entries without.
    pub record: Option<NodeRecord>,
    /// Address given by hand, used while there is no record.
    pub manual_addr: Option<SocketAddr>,
    /// Seen answering as the node it claims to be; never goes back to false.
    pub confirmed: bool,
    /// Added by hand: never aged out nor evicted.
    pub manual: bool,
    pub first_seen: u64,
    pub last_seen: u64,
    pub score: Score,
    pub avoided_until: Option<u64>,
}

impl NodeEntry {
    pub(crate) fn manual_only(addr: SocketAddr, now: u64) -> NodeEntry {
        NodeEntry {
            record: None,
            manual_addr: Some(addr),
            confirmed: false,
            manual: true,
            first_seen: now,
            last_seen: now,
            score: Score::default(),
            avoided_until: None,
        }
    }

    fn new(record: NodeRecord, now: u64, confirmed: bool) -> NodeEntry {
        NodeEntry {
            record: Some(record),
            manual_addr: None,
            confirmed,
            manual: false,
            first_seen: now,
            last_seen: now,
            score: Score::default(),
            avoided_until: None,
        }
    }

    /// Addresses to dial: the record's, then the manual one if different.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut out = self.record.as_ref().map(|r| r.addrs()).unwrap_or_default();
        if let Some(a) = self.manual_addr
            && !out.contains(&a)
        {
            out.push(a);
        }
        out
    }

    fn avoided(&self, now: u64) -> bool {
        self.avoided_until
            .is_some_and(|t| t.min(now.saturating_add(MAX_AVOID_SECS)) > now)
    }
}

/// The client's view of the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    /// Accepts non-routable addresses in records (tests, private networks).
    allow_private: bool,
    pub(crate) entries: HashMap<NodeId, NodeEntry>,
}

impl View {
    pub fn new(allow_private: bool) -> View {
        View {
            allow_private,
            entries: HashMap::new(),
        }
    }

    fn policy(&self) -> RecordPolicy {
        RecordPolicy::network(self.allow_private)
    }

    /// Adds or updates a node from a signed record. An invalid record is
    /// ignored; a newer one replaces the old; an older one only counts for
    /// confirmation. Returns true if the view changed.
    pub fn insert(&mut self, record: NodeRecord, now: u64, confirmed: bool) -> bool {
        match record.verify(now, &self.policy()) {
            Ok(id) => self.upsert(id, record, now, confirmed),
            Err(_) => false,
        }
    }

    /// Fills the record of an entry that has none (or refreshes it). The
    /// record must verify and belong to `id`.
    pub fn set_record(&mut self, id: &NodeId, record: NodeRecord, now: u64) -> bool {
        if !self.entries.contains_key(id) {
            return false;
        }
        match record.verify(now, &self.policy()) {
            Ok(rid) if rid == *id => self.upsert(rid, record, now, false),
            _ => false,
        }
    }

    fn upsert(&mut self, id: NodeId, record: NodeRecord, now: u64, confirmed: bool) -> bool {
        let Some(e) = self.entries.get_mut(&id) else {
            self.entries
                .insert(id, NodeEntry::new(record, now, confirmed));
            self.evict_to_capacity();
            return self.entries.contains_key(&id);
        };
        let mut changed = false;
        let older = e
            .record
            .as_ref()
            .is_some_and(|old| record.issued_at < old.issued_at);
        let newer = e
            .record
            .as_ref()
            .is_none_or(|old| record.issued_at > old.issued_at);
        if newer {
            e.record = Some(record);
            changed = true;
        }
        if confirmed && !e.confirmed {
            e.confirmed = true;
            changed = true;
        }
        // A stale record does not keep a node alive, unless confirmed.
        if !older || confirmed {
            e.last_seen = now;
        }
        changed
    }

    /// Adds a node by hand, by identifier and address. It never expires.
    pub fn add_manual(&mut self, id: NodeId, addr: SocketAddr, now: u64) -> bool {
        match self.entries.get_mut(&id) {
            Some(e) => {
                let changed = !e.manual || e.manual_addr != Some(addr);
                e.manual = true;
                e.manual_addr = Some(addr);
                changed
            }
            None => {
                self.entries.insert(id, NodeEntry::manual_only(addr, now));
                true
            }
        }
    }

    /// Removes a hand-added node: dropped if it has no record, otherwise it
    /// stays as a normal node. Returns false if it was not hand-added.
    pub fn remove_manual(&mut self, id: &NodeId) -> bool {
        let Some(e) = self.entries.get_mut(id) else {
            return false;
        };
        if !e.manual {
            return false;
        }
        if e.record.is_none() {
            self.entries.remove(id);
        } else {
            e.manual = false;
            e.manual_addr = None;
        }
        true
    }

    /// Marks a node as confirmed (it answered) and seen now.
    pub fn confirm(&mut self, id: &NodeId, now: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.confirmed = true;
            e.last_seen = now;
        }
    }

    /// Marks a node as seen now.
    pub fn touch(&mut self, id: &NodeId, now: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.last_seen = now;
        }
    }

    /// Avoids a node until `until`, at most 7 days from `now`.
    pub fn avoid(&mut self, id: &NodeId, until: u64, now: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.avoided_until = Some(until.min(now.saturating_add(MAX_AVOID_SECS)));
        }
    }

    #[cfg(test)]
    pub(crate) fn set_score(&mut self, id: &NodeId, value: f32) {
        if let Some(e) = self.entries.get_mut(id) {
            e.score = Score::new(value);
        }
    }

    /// Drops entries not seen for `VIEW_TTL_SECS`, hand-added ones excepted.
    /// Never drops more than half of the view in one call (stalest first).
    /// Dates from the future are brought back to `now`. Returns the count.
    pub fn expire(&mut self, now: u64) -> usize {
        for e in self.entries.values_mut() {
            e.first_seen = e.first_seen.min(now);
            e.last_seen = e.last_seen.min(now);
            if let Some(t) = &mut e.avoided_until {
                *t = (*t).min(now.saturating_add(MAX_AVOID_SECS));
            }
        }
        let mut stale: Vec<(u64, NodeId)> = self
            .entries
            .iter()
            .filter(|(_, e)| !e.manual && now - e.last_seen > VIEW_TTL_SECS)
            .map(|(id, e)| (e.last_seen, *id))
            .collect();
        stale.sort_by_key(|&(seen, id)| (seen, id.0));
        stale.truncate(self.entries.len() / 2);
        for (_, id) in &stale {
            self.entries.remove(id);
        }
        stale.len()
    }

    /// Brings the view down to `MAX_VIEW`: oldest candidates first, then the
    /// confirmed nodes with the lowest score; never a hand-added node.
    pub fn evict_to_capacity(&mut self) {
        self.evict_to(MAX_VIEW);
    }

    pub(crate) fn evict_to(&mut self, capacity: usize) {
        let excess = self.entries.len().saturating_sub(capacity);
        if excess == 0 {
            return;
        }
        let mut victims: Vec<(&NodeId, &NodeEntry)> =
            self.entries.iter().filter(|(_, e)| !e.manual).collect();
        victims.sort_by(|(ia, a), (ib, b)| eviction_order(a, b).then(ia.0.cmp(&ib.0)));
        let ids: Vec<NodeId> = victims
            .into_iter()
            .take(excess)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.entries.remove(&id);
        }
    }

    /// The `RESPONSIBLES` entries closest to the mailbox key, at most
    /// `MAX_PER_PREFIX` per address block. Avoided nodes only complete the
    /// list when too few others exist. Entries without a record are skipped.
    pub fn responsibles(&self, mailbox: &MailboxId, now: u64) -> Vec<NodeId> {
        let key = mailbox_key(mailbox);
        let mut ranked: Vec<(&NodeId, &NodeEntry, &NodeRecord)> = self
            .entries
            .iter()
            .filter_map(|(id, e)| e.record.as_ref().map(|r| (id, e, r)))
            .collect();
        ranked.sort_by_key(|(id, _, _)| distance(&id.0, &key));
        let mut out = Vec::with_capacity(RESPONSIBLES);
        let mut per_prefix: HashMap<Prefix, usize> = HashMap::new();
        for pass_avoided in [false, true] {
            for (id, e, record) in &ranked {
                if out.len() == RESPONSIBLES {
                    return out;
                }
                if e.avoided(now) != pass_avoided {
                    continue;
                }
                let blocks = prefixes(record);
                if blocks
                    .iter()
                    .any(|p| per_prefix.get(p).copied().unwrap_or(0) >= MAX_PER_PREFIX)
                {
                    continue;
                }
                for p in blocks {
                    *per_prefix.entry(p).or_default() += 1;
                }
                out.push(**id);
            }
        }
        out
    }

    /// True if the view is too small to trust: a fallback lookup is due.
    pub fn needs_fallback(&self) -> bool {
        self.entries.len() < SMALL_VIEW
    }

    pub fn get(&self, id: &NodeId) -> Option<&NodeEntry> {
        self.entries.get(id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&NodeId, &NodeEntry)> {
        self.entries.iter()
    }

    /// Nodes to try first when bootstrapping, with their addresses:
    /// confirmed nodes first, best score first, then the most recently seen.
    pub fn reachable_candidates_for_bootstrap(&self) -> Vec<(NodeId, Vec<SocketAddr>)> {
        let mut all: Vec<(&NodeId, &NodeEntry)> = self.entries.iter().collect();
        all.sort_by(|(ia, a), (ib, b)| {
            b.confirmed
                .cmp(&a.confirmed)
                .then(b.score.0.total_cmp(&a.score.0))
                .then(b.last_seen.cmp(&a.last_seen))
                .then(ia.0.cmp(&ib.0))
        });
        all.into_iter()
            .map(|(id, e)| (*id, e.addrs()))
            .filter(|(_, addrs)| !addrs.is_empty())
            .collect()
    }
}

/// Eviction order: candidates before confirmed nodes, then oldest first for
/// candidates and lowest score first for confirmed ones.
fn eviction_order(a: &NodeEntry, b: &NodeEntry) -> Ordering {
    a.confirmed.cmp(&b.confirmed).then_with(|| {
        if a.confirmed {
            a.score
                .0
                .total_cmp(&b.score.0)
                .then(a.last_seen.cmp(&b.last_seen))
        } else {
            a.last_seen.cmp(&b.last_seen)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{addr, id_of, record, record_at};
    use crate::{MAX_VIEW, SMALL_VIEW, VIEW_TTL_SECS};
    use barking_packet::MailboxId;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn view() -> View {
        View::new(true)
    }

    fn mailbox(n: u8) -> MailboxId {
        MailboxId([n; 16])
    }

    fn sorted_by_distance(ids: &mut [NodeId], mb: &MailboxId) {
        let key = mailbox_key(mb);
        ids.sort_by_key(|id| distance(&id.0, &key));
    }

    #[test]
    fn insert_newer_replaces_older_ignored() {
        let mut v = view();
        let old = record(0, NOW - 7200);
        let new = record(0, NOW);
        assert!(v.insert(old.clone(), NOW, false));
        assert!(v.insert(new.clone(), NOW, false));
        assert_eq!(v.get(&id_of(0)).unwrap().record.as_ref(), Some(&new));
        // An older record is ignored.
        assert!(!v.insert(old, NOW, false));
        assert_eq!(v.get(&id_of(0)).unwrap().record.as_ref(), Some(&new));
        assert_eq!(v.len(), 1);
        // An invalid record (tampered address) is rejected.
        let mut bad = record(1, NOW);
        bad.v4 = Some(addr(7, 7, 7));
        assert!(!v.insert(bad, NOW, false));
        assert_eq!(v.len(), 1);
        // Strict network policy rejects private addresses.
        let mut strict = View::new(false);
        assert!(!strict.insert(record(2, NOW), NOW, false));
    }

    #[test]
    fn candidate_becomes_confirmed_never_back() {
        let mut v = view();
        v.insert(record(0, NOW), NOW, false);
        assert!(!v.get(&id_of(0)).unwrap().confirmed);
        v.confirm(&id_of(0), NOW);
        assert!(v.get(&id_of(0)).unwrap().confirmed);
        // A later candidate sighting, even with a newer record, stays confirmed.
        v.insert(record(0, NOW + 3600), NOW + 3600, false);
        assert!(v.get(&id_of(0)).unwrap().confirmed);
        // Inserting directly as confirmed upgrades a candidate.
        v.insert(record(1, NOW), NOW, false);
        assert!(v.insert(record(1, NOW), NOW, true));
        assert!(v.get(&id_of(1)).unwrap().confirmed);
    }

    #[test]
    fn expire_after_ttl_except_manual() {
        let mut v = view();
        v.insert(record(0, NOW), NOW, false);
        v.insert(record(1, NOW), NOW, false);
        v.add_manual(id_of(2), addr(9, 9, 9).into(), NOW);
        v.add_manual(id_of(4), addr(8, 8, 8).into(), NOW);
        v.set_record(&id_of(4), record(4, NOW), NOW);
        let later = NOW + VIEW_TTL_SECS;
        v.touch(&id_of(1), later);
        // Exactly at the TTL nothing expires; one second later node 0 does.
        assert_eq!(v.expire(later), 0);
        assert_eq!(v.expire(later + 1), 1);
        assert!(v.get(&id_of(0)).is_none());
        assert!(v.get(&id_of(1)).is_some());
        // Manual entries, with or without a record, survive.
        assert!(v.get(&id_of(2)).is_some());
        assert!(v.get(&id_of(4)).is_some());
        // The record-less manual entry is filled by a record, id must match.
        assert!(v.get(&id_of(2)).unwrap().record.is_none());
        assert!(!v.set_record(&id_of(2), record(5, NOW), NOW));
        assert!(v.set_record(&id_of(2), record(2, NOW), NOW));
        assert!(v.get(&id_of(2)).unwrap().record.is_some());
        assert!(v.get(&id_of(2)).unwrap().manual);
    }

    #[test]
    fn evict_order_candidates_then_low_score_never_manual() {
        let mut v = view();
        // 0: confirmed, 1: candidate seen late, 2: candidate seen early,
        // 3: confirmed with a low score, 4: manual candidate.
        v.insert(record(0, NOW), NOW, true);
        v.insert(record(1, NOW), NOW + 20, false);
        v.insert(record(2, NOW), NOW + 10, false);
        v.insert(record(3, NOW), NOW, true);
        v.set_score(&id_of(3), 0.1);
        v.set_score(&id_of(0), 0.9);
        v.add_manual(id_of(4), addr(9, 9, 9).into(), NOW);
        assert_eq!(v.len(), 5);
        v.evict_to(4);
        assert!(v.get(&id_of(2)).is_none(), "oldest candidate goes first");
        v.evict_to(3);
        assert!(v.get(&id_of(1)).is_none());
        v.evict_to(2);
        assert!(v.get(&id_of(3)).is_none(), "then the lowest score");
        assert!(v.get(&id_of(0)).is_some());
        // Never a manual node, even when over capacity.
        v.evict_to(0);
        assert_eq!(v.len(), 1);
        assert!(v.get(&id_of(4)).is_some());
    }

    #[test]
    fn remove_manual_semantics() {
        let mut v = view();
        v.add_manual(id_of(0), addr(9, 9, 9).into(), NOW);
        v.add_manual(id_of(1), addr(8, 8, 8).into(), NOW);
        v.set_record(&id_of(1), record(1, NOW), NOW);
        v.insert(record(2, NOW), NOW, false);
        assert!(v.remove_manual(&id_of(0)));
        assert!(v.get(&id_of(0)).is_none());
        // With a record the node stays, as a normal one.
        assert!(v.remove_manual(&id_of(1)));
        let e = v.get(&id_of(1)).unwrap();
        assert!(!e.manual && e.manual_addr.is_none() && e.record.is_some());
        assert!(!v.remove_manual(&id_of(2)));
        assert!(!v.remove_manual(&id_of(1)));
    }

    #[test]
    fn insert_over_capacity_stays_bounded() {
        let mut v = view();
        v.entries.extend((0..MAX_VIEW).map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            (
                NodeId(id),
                NodeEntry::manual_only(addr(1, 1, 1).into(), NOW),
            )
        }));
        // All manual: nothing to evict, but a new candidate is evicted at once.
        v.insert(record(0, NOW), NOW, false);
        assert_eq!(v.len(), MAX_VIEW);
        assert!(v.get(&id_of(0)).is_none());
    }

    #[test]
    fn responsibles_are_five_closest() {
        let mut v = view();
        let mut ids = Vec::new();
        for n in 0..10 {
            v.insert(record(n, NOW), NOW, n % 2 == 0);
            ids.push(id_of(n));
        }
        // A record-less manual node never counts.
        v.add_manual(id_of(10), addr(9, 9, 9).into(), NOW);
        for m in 0..8 {
            let mb = mailbox(m);
            sorted_by_distance(&mut ids, &mb);
            let got = v.responsibles(&mb, NOW);
            assert_eq!(got, ids[..RESPONSIBLES].to_vec(), "mailbox {m}");
        }
    }

    #[test]
    fn responsibles_respect_prefix_cap() {
        let mb = mailbox(3);
        let mut ids: Vec<NodeId> = (0..8).map(id_of).collect();
        sorted_by_distance(&mut ids, &mb);
        let mut v = view();
        for n in 0..8 {
            let rank = ids.iter().position(|i| *i == id_of(n)).unwrap();
            // The four closest share a /24, the others have their own.
            let at = if rank < 4 {
                addr(5, 5, n as u8 + 1)
            } else {
                addr(6, n as u8, 1)
            };
            v.insert(record_at(n, at, NOW), NOW, true);
        }
        let got = v.responsibles(&mb, NOW);
        let mut expected = ids[..2].to_vec();
        expected.extend_from_slice(&ids[4..7]);
        assert_eq!(got, expected);
    }

    #[test]
    fn avoided_used_only_to_complete() {
        let mb = mailbox(9);
        let mut ids: Vec<NodeId> = (0..7).map(id_of).collect();
        sorted_by_distance(&mut ids, &mb);
        let mut v = view();
        for n in 0..7 {
            v.insert(record(n, NOW), NOW, true);
        }
        // The two closest are avoided: skipped while five others exist.
        v.avoid(&ids[0], NOW + DAY, NOW);
        v.avoid(&ids[1], NOW + DAY, NOW);
        assert_eq!(v.responsibles(&mb, NOW), ids[2..7].to_vec());
        // With only four others, the closest avoided one completes.
        v.avoid(&ids[6], NOW + DAY, NOW);
        let mut expected = ids[2..6].to_vec();
        expected.push(ids[0]);
        assert_eq!(v.responsibles(&mb, NOW), expected);
        // Once the avoidance is over they count normally again.
        assert_eq!(v.responsibles(&mb, NOW + DAY), ids[..5].to_vec());
    }

    #[test]
    fn needs_fallback_below_twenty() {
        let mut v = view();
        for i in 0..SMALL_VIEW as u8 - 1 {
            v.add_manual(NodeId([i; 32]), addr(1, 1, i).into(), NOW);
        }
        assert!(v.needs_fallback());
        v.add_manual(NodeId([200; 32]), addr(1, 1, 200).into(), NOW);
        assert_eq!(v.len(), SMALL_VIEW);
        assert!(!v.needs_fallback());
    }

    #[test]
    fn clock_jump_does_not_wipe_view_or_ban_forever() {
        let mut v = view();
        for n in 0..10 {
            v.insert(record(n, NOW), NOW, false);
        }
        // +30 days: everything is stale, but at most half goes per call.
        let later = NOW + 30 * DAY;
        assert_eq!(v.expire(later), 5);
        assert_eq!(v.len(), 5);
        assert_eq!(v.expire(later), 2);
        assert_eq!(v.expire(later), 1);

        // -30 days: entries seen "in the future" are clamped to now.
        let mut v = view();
        for n in 0..4 {
            v.insert(record(n, NOW), NOW, true);
        }
        v.avoid(&id_of(0), NOW + 365 * DAY, NOW);
        let back = NOW - 30 * DAY;
        assert_eq!(v.expire(back), 0);
        assert_eq!(v.expire(back + VIEW_TTL_SECS), 0);
        assert!(v.get(&id_of(1)).unwrap().last_seen <= back);
        // The avoidance is bounded to now + 7 days.
        assert!(v.get(&id_of(0)).unwrap().avoided_until.unwrap() <= NOW + 7 * DAY);
        let mb = mailbox(1);
        let got = v.responsibles(&mb, NOW + 8 * DAY);
        assert!(got.contains(&id_of(0)));
    }

    #[test]
    fn view_roundtrip_postcard() {
        let mut v = view();
        v.insert(record(0, NOW), NOW, true);
        v.insert(record(1, NOW), NOW, false);
        v.add_manual(id_of(2), addr(9, 9, 9).into(), NOW);
        v.avoid(&id_of(0), NOW + DAY, NOW);
        let bytes = postcard::to_allocvec(&v).unwrap();
        let back: View = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back.get(&id_of(0)), v.get(&id_of(0)));
        assert_eq!(back.get(&id_of(2)), v.get(&id_of(2)));
        // Junk never panics.
        assert!(postcard::from_bytes::<View>(&bytes[..bytes.len() / 2]).is_err());
    }

    #[test]
    fn bootstrap_candidates_prefer_confirmed_and_manual_addr() {
        let mut v = view();
        v.insert(record(0, NOW), NOW, false);
        v.insert(record(1, NOW), NOW, true);
        v.add_manual(id_of(2), addr(9, 9, 9).into(), NOW);
        let c = v.reachable_candidates_for_bootstrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].0, id_of(1));
        assert!(
            c.iter()
                .any(|(id, a)| *id == id_of(2) && a == &[SocketAddr::from(addr(9, 9, 9))])
        );
    }
}
