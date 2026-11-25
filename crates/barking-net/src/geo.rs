//! Offline IP to (ASN, country) base, and the verdict comparing what a node
//! says about its own origin with what the base says about its address.
//!
//! The phone never queries an online service: the table is built at
//! development time by `scripts/build-ipdb.sh` (DB-IP Lite, CC BY 4.0) and
//! shipped in the app.
//!
//! # File format (version 1, all integers big-endian)
//!
//! ```text
//! header (40 bytes)
//!   0  magic       8   b"BARKIPDB"
//!   8  version     4   u32 = 1
//!  12  source     16   ASCII source month ("2026-11"), NUL padded
//!  28  v4_count    4   u32
//!  32  v6_count    4   u32
//!  36  value_count 4   u32
//! values (6 bytes each, distinct): asn u32, country [u8; 2]
//! v4 entries (7 bytes each): start u32, value index u24
//! v6 entries (11 bytes each): start u64, value index u24
//! ```
//!
//! The value table keeps the file small (many ranges share an origin). An
//! entry covers its start up to the next entry's start (implicit end).
//! Starts are strictly increasing. Gaps are entries with asn 0 and country
//! "ZZ", and so is the terminating entry after the last range (unless the
//! last range reaches the end of the address space). `lookup` returns `None`
//! for those. A range known in only one of the two DB-IP sets keeps asn 0 or
//! country "ZZ" for the missing half. IPv6 is stored at /64 granularity: the
//! start is the high 64 bits of the address. IPv4-mapped IPv6 addresses are
//! looked up as IPv4.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use barking_proto::{NodeOrigin, NodeRecord};

const MAGIC: &[u8; 8] = b"BARKIPDB";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 40;
const VALUE_LEN: usize = 6;
const V4_ENTRY: usize = 7;
const V6_ENTRY: usize = 11;
/// Most distinct values a base can hold (u24 index).
const MAX_VALUES: usize = 1 << 24;
const SOURCE_LEN: usize = 16;
/// Country code of a range whose country is unknown.
pub const UNKNOWN_COUNTRY: [u8; 2] = *b"ZZ";

/// Why a base file could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    #[error("cannot read the IP base: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an IP base file")]
    BadMagic,
    #[error("unsupported IP base version {0}")]
    UnsupportedVersion(u32),
    #[error("IP base file truncated or with trailing bytes")]
    BadLength,
    #[error("IP base ranges are not sorted")]
    Unsorted,
    #[error("IP base entry points outside the value table")]
    BadValue,
}

/// An explicit range with its data, used to build a base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: u128,
    /// Inclusive.
    pub end: u128,
    pub asn: u32,
    pub country: [u8; 2],
}

/// The loaded base (the whole file, read once).
#[derive(Debug)]
pub struct IpDb {
    data: Vec<u8>,
    nv: usize,
    n4: usize,
    n6: usize,
}

fn be24(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

impl IpDb {
    /// Reads and validates the file.
    pub fn open(path: &Path) -> Result<IpDb, GeoError> {
        IpDb::from_bytes(std::fs::read(path)?)
    }

    /// Validates `data` (magic, version, length, sorted starts).
    pub fn from_bytes(data: Vec<u8>) -> Result<IpDb, GeoError> {
        if data.len() < HEADER_LEN || &data[..8] != MAGIC {
            return Err(GeoError::BadMagic);
        }
        let version = be32(&data[8..12]);
        if version != VERSION {
            return Err(GeoError::UnsupportedVersion(version));
        }
        let n4 = be32(&data[28..32]) as usize;
        let n6 = be32(&data[32..36]) as usize;
        let nv = be32(&data[36..40]) as usize;
        let expected = n4
            .checked_mul(V4_ENTRY)
            .and_then(|a| n6.checked_mul(V6_ENTRY).and_then(|b| a.checked_add(b)))
            .and_then(|a| nv.checked_mul(VALUE_LEN).and_then(|b| a.checked_add(b)))
            .and_then(|s| s.checked_add(HEADER_LEN));
        if expected != Some(data.len()) {
            return Err(GeoError::BadLength);
        }
        let db = IpDb { data, nv, n4, n6 };
        let mut prev = None;
        for i in 0..n4 {
            let s = u64::from(db.v4_start(i));
            if prev.is_some_and(|p| s <= p) {
                return Err(GeoError::Unsorted);
            }
            prev = Some(s);
            if db.v4_index(i) >= nv {
                return Err(GeoError::BadValue);
            }
        }
        let mut prev = None;
        for i in 0..n6 {
            let s = db.v6_start(i);
            if prev.is_some_and(|p| s <= p) {
                return Err(GeoError::Unsorted);
            }
            prev = Some(s);
            if db.v6_index(i) >= nv {
                return Err(GeoError::BadValue);
            }
        }
        Ok(db)
    }

    /// Source month recorded in the header ("2026-11").
    pub fn source(&self) -> String {
        let raw = &self.data[12..12 + SOURCE_LEN];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(SOURCE_LEN);
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    /// Number of (v4, v6) entries.
    pub fn counts(&self) -> (usize, usize) {
        (self.n4, self.n6)
    }

    fn v4_off(&self, i: usize) -> usize {
        HEADER_LEN + self.nv * VALUE_LEN + i * V4_ENTRY
    }

    fn v6_off(&self, i: usize) -> usize {
        HEADER_LEN + self.nv * VALUE_LEN + self.n4 * V4_ENTRY + i * V6_ENTRY
    }

    fn v4_start(&self, i: usize) -> u32 {
        be32(&self.data[self.v4_off(i)..])
    }

    fn v6_start(&self, i: usize) -> u64 {
        be64(&self.data[self.v6_off(i)..])
    }

    fn v4_index(&self, i: usize) -> usize {
        be24(&self.data[self.v4_off(i) + 4..])
    }

    fn v6_index(&self, i: usize) -> usize {
        be24(&self.data[self.v6_off(i) + 8..])
    }

    /// Value `i`; the caller checked `i < nv` (at open).
    fn value(&self, i: usize) -> (u32, [u8; 2]) {
        let o = HEADER_LEN + i * VALUE_LEN;
        (be32(&self.data[o..]), [self.data[o + 4], self.data[o + 5]])
    }

    /// The (ASN, country) of `ip`, or `None` if the base does not know it.
    pub fn lookup(&self, ip: IpAddr) -> Option<(u32, [u8; 2])> {
        let found = match ip {
            IpAddr::V4(a) => self.lookup_v4(a),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => self.lookup_v4(v4),
                None => self.lookup_v6(a),
            },
        }?;
        (found != (0, UNKNOWN_COUNTRY)).then_some(found)
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<(u32, [u8; 2])> {
        let key = u32::from(ip);
        let (mut lo, mut hi) = (0, self.n4);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.v4_start(mid) <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo > 0).then(|| self.value(self.v4_index(lo - 1)))
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<(u32, [u8; 2])> {
        let key = (u128::from(ip) >> 64) as u64;
        let (mut lo, mut hi) = (0, self.n6);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.v6_start(mid) <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo > 0).then(|| self.value(self.v6_index(lo - 1)))
    }
}

/// Sorts `ranges` and drops what overlaps an earlier range (the earlier one
/// wins).
fn normalize(ranges: &[(u128, u128, u32)]) -> Vec<(u128, u128, u32)> {
    let mut v: Vec<_> = ranges.iter().copied().filter(|r| r.0 <= r.1).collect();
    v.sort_by_key(|r| (r.0, r.1));
    let mut out: Vec<(u128, u128, u32)> = Vec::with_capacity(v.len());
    for (s, e, x) in v {
        match out.last() {
            Some(&(_, pe, _)) if s <= pe => {
                if e > pe {
                    out.push((pe + 1, e, x));
                }
            }
            _ => out.push((s, e, x)),
        }
    }
    out
}

/// Merges the ASN ranges and the country ranges of one address family into
/// ranges of (ASN, country), splitting at every boundary of either set. A
/// span known in one set only gets asn 0 or `UNKNOWN_COUNTRY`; a span in
/// neither is left out. Adjacent ranges with identical data are coalesced.
pub fn merge_ranges(asn: &[(u128, u128, u32)], country: &[(u128, u128, [u8; 2])]) -> Vec<Range> {
    let asn = normalize(asn);
    let cc_codes: Vec<[u8; 2]> = country.iter().map(|c| c.2).collect();
    let cc_idx: Vec<(u128, u128, u32)> = country
        .iter()
        .enumerate()
        .map(|(i, c)| (c.0, c.1, i as u32))
        .collect();
    // Normalizing the indices keeps them valid: only the surviving parts
    // carry their original index.
    let cc = normalize(&cc_idx);

    let mut bounds: Vec<u128> = Vec::with_capacity((asn.len() + cc.len()) * 2);
    for r in asn.iter().chain(cc.iter()) {
        bounds.push(r.0);
        if let Some(n) = r.1.checked_add(1) {
            bounds.push(n);
        }
    }
    bounds.sort_unstable();
    bounds.dedup();

    let (mut ia, mut ic) = (0, 0);
    let mut out: Vec<Range> = Vec::new();
    for (k, &b) in bounds.iter().enumerate() {
        let seg_end = bounds.get(k + 1).map_or(u128::MAX, |n| n - 1);
        while ia < asn.len() && asn[ia].1 < b {
            ia += 1;
        }
        while ic < cc.len() && cc[ic].1 < b {
            ic += 1;
        }
        let a = (ia < asn.len() && asn[ia].0 <= b).then(|| asn[ia].2);
        let c = (ic < cc.len() && cc[ic].0 <= b).then(|| cc_codes[cc[ic].2 as usize]);
        if a.is_none() && c.is_none() {
            continue;
        }
        let (a, c) = (a.unwrap_or(0), c.unwrap_or(UNKNOWN_COUNTRY));
        match out.last_mut() {
            Some(last)
                if last.end.checked_add(1) == Some(b) && last.asn == a && last.country == c =>
            {
                last.end = seg_end;
            }
            _ => out.push(Range {
                start: b,
                end: seg_end,
                asn: a,
                country: c,
            }),
        }
    }
    out
}

/// Entries (start, asn, country) with gaps filled by `(0, ZZ)` entries and
/// equal neighbours coalesced. `ranges` must be sorted and non-overlapping
/// in units of `max`'s space; `unit_start` / `unit_end` map a range to units.
fn entries(
    ranges: &[Range],
    max: u64,
    unit_start: impl Fn(u128) -> u64,
    unit_end: impl Fn(u128) -> u64,
) -> Vec<(u64, u32, [u8; 2])> {
    let mut out: Vec<(u64, u32, [u8; 2])> = Vec::new();
    let mut cursor: u128 = 0;
    let push = |out: &mut Vec<(u64, u32, [u8; 2])>, s: u64, a: u32, c: [u8; 2]| {
        if out.last().is_some_and(|l| l.1 == a && l.2 == c) {
            return;
        }
        out.push((s, a, c));
    };
    for r in ranges {
        let mut s = u128::from(unit_start(r.start));
        let e = u128::from(unit_end(r.end));
        if e < cursor {
            continue; // lies entirely inside units already covered
        }
        if s < cursor {
            // Starts in a unit the previous range ended in: the unit stays
            // with the earlier range, this one continues at the next unit.
            s = cursor;
        }
        if s > cursor {
            push(&mut out, cursor as u64, 0, UNKNOWN_COUNTRY);
        }
        push(&mut out, s as u64, r.asn, r.country);
        cursor = e + 1;
    }
    if cursor <= u128::from(max) {
        push(&mut out, cursor as u64, 0, UNKNOWN_COUNTRY);
    }
    out
}

/// Encodes a base. `v4` and `v6` are merged ranges (see `merge_ranges`),
/// sorted and non-overlapping; v4 ranges hold u32 values, v6 ranges u128.
/// `source` is the source month ("2026-11"), at most 16 ASCII bytes.
pub fn encode(source: &str, v4: &[Range], v6: &[Range]) -> Vec<u8> {
    let e4 = entries(v4, u64::from(u32::MAX), |s| s as u64, |e| e as u64);
    let e6 = entries(v6, u64::MAX, |s| (s >> 64) as u64, |e| (e >> 64) as u64);
    let mut values: Vec<(u32, [u8; 2])> = Vec::new();
    let mut index: HashMap<(u32, [u8; 2]), usize> = HashMap::new();
    let mut idx = |a: u32, c: [u8; 2]| -> [u8; 3] {
        let n = values.len();
        let i = *index.entry((a, c)).or_insert_with(|| {
            values.push((a, c));
            n
        });
        assert!(i < MAX_VALUES, "too many distinct values");
        [(i >> 16) as u8, (i >> 8) as u8, i as u8]
    };
    let i4: Vec<[u8; 3]> = e4.iter().map(|e| idx(e.1, e.2)).collect();
    let i6: Vec<[u8; 3]> = e6.iter().map(|e| idx(e.1, e.2)).collect();
    let mut out = Vec::with_capacity(
        HEADER_LEN + values.len() * VALUE_LEN + e4.len() * V4_ENTRY + e6.len() * V6_ENTRY,
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    let mut src = [0u8; SOURCE_LEN];
    let n = source.len().min(SOURCE_LEN);
    src[..n].copy_from_slice(&source.as_bytes()[..n]);
    out.extend_from_slice(&src);
    out.extend_from_slice(&(e4.len() as u32).to_be_bytes());
    out.extend_from_slice(&(e6.len() as u32).to_be_bytes());
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for (a, c) in &values {
        out.extend_from_slice(&a.to_be_bytes());
        out.extend_from_slice(c);
    }
    for (e, i) in e4.iter().zip(&i4) {
        out.extend_from_slice(&(e.0 as u32).to_be_bytes());
        out.extend_from_slice(i);
    }
    for (e, i) in e6.iter().zip(&i6) {
        out.extend_from_slice(&e.0.to_be_bytes());
        out.extend_from_slice(i);
    }
    out
}

/// Why an origin could not be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnverifiableReason {
    /// The node reports no origin.
    NotReported,
    /// The base has no data for the node's address (or there is no base).
    NotInBase,
    /// No record for the node, or none for the address family reported.
    NoRecord,
}

/// What the base says about a node's declared origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginVerdict {
    Matches,
    Mismatch {
        declared_asn: u32,
        declared_country: [u8; 2],
        observed_asn: u32,
        observed_country: [u8; 2],
    },
    Unverifiable(UnverifiableReason),
}

/// Compares the origin a node reports with the base's answer for the
/// address of its record in the family the origin describes (`for_v6`).
/// There is no fallback to another address.
///
/// An observed ASN 0 or country "ZZ" means that half is unknown, and an
/// unknown half never produces a `Mismatch`: any known observed half that
/// differs from the declared one is a `Mismatch`; otherwise it `Matches` if
/// both halves are known, else it is `Unverifiable(NotInBase)`.
pub fn verdict(
    db: Option<&IpDb>,
    origin: Option<&NodeOrigin>,
    record: Option<&NodeRecord>,
) -> OriginVerdict {
    use OriginVerdict::Unverifiable;
    let Some(origin) = origin else {
        return Unverifiable(UnverifiableReason::NotReported);
    };
    let ip = record.and_then(|r| {
        if origin.for_v6 {
            r.v6.map(|a| IpAddr::V6(*a.ip()))
        } else {
            r.v4.map(|a| IpAddr::V4(*a.ip()))
        }
    });
    let Some(ip) = ip else {
        return Unverifiable(UnverifiableReason::NoRecord);
    };
    let Some((asn, country)) = db.and_then(|d| d.lookup(ip)) else {
        return Unverifiable(UnverifiableReason::NotInBase);
    };
    let asn_known = asn != 0;
    let country_known = country != UNKNOWN_COUNTRY;
    let differs = (asn_known && asn != origin.asn)
        || (country_known && !country.eq_ignore_ascii_case(&origin.country));
    if !differs {
        if asn_known && country_known {
            OriginVerdict::Matches
        } else {
            Unverifiable(UnverifiableReason::NotInBase)
        }
    } else {
        OriginVerdict::Mismatch {
            declared_asn: origin.asn,
            declared_country: origin.country,
            observed_asn: asn,
            observed_country: country,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    fn v4(a: [u8; 4]) -> u128 {
        u128::from(u32::from(Ipv4Addr::from(a)))
    }

    fn v6(s: &str) -> u128 {
        u128::from(s.parse::<Ipv6Addr>().unwrap())
    }

    fn rng(start: u128, end: u128, asn: u32, country: &[u8; 2]) -> Range {
        Range {
            start,
            end,
            asn,
            country: *country,
        }
    }

    fn table() -> IpDb {
        let r4 = [
            rng(v4([10, 0, 0, 0]), v4([10, 0, 0, 255]), 64500, b"FR"),
            rng(v4([10, 0, 1, 0]), v4([10, 0, 1, 255]), 64501, b"DE"),
            rng(v4([20, 0, 0, 0]), v4([20, 255, 255, 255]), 64502, b"US"),
        ];
        let r6 = [rng(
            v6("2001:db8::"),
            v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            64503,
            b"NL",
        )];
        IpDb::from_bytes(encode("2026-11", &r4, &r6)).unwrap()
    }

    fn origin(asn: u32, country: &[u8; 2], for_v6: bool) -> NodeOrigin {
        NodeOrigin {
            asn,
            as_name: "X".into(),
            country: *country,
            for_v6,
        }
    }

    fn record(v4: Option<&str>, v6: Option<&str>) -> NodeRecord {
        NodeRecord {
            public_key: [0; 32],
            v4: v4.map(|a| a.parse::<SocketAddrV4>().unwrap()),
            v6: v6.map(|a| a.parse::<SocketAddrV6>().unwrap()),
            issued_at: 0,
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        }
    }

    #[test]
    fn lookup_finds_range_bounds() {
        let db = table();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(db.source(), "2026-11");
        assert_eq!(db.lookup(ip("10.0.0.0")), Some((64500, *b"FR")));
        assert_eq!(db.lookup(ip("10.0.0.255")), Some((64500, *b"FR")));
        assert_eq!(db.lookup(ip("10.0.1.0")), Some((64501, *b"DE")));
        assert_eq!(db.lookup(ip("10.0.1.255")), Some((64501, *b"DE")));
        assert_eq!(db.lookup(ip("10.0.2.0")), None);
        assert_eq!(db.lookup(ip("9.255.255.255")), None);
        assert_eq!(db.lookup(ip("20.255.255.255")), Some((64502, *b"US")));
        assert_eq!(db.lookup(ip("21.0.0.0")), None);
        assert_eq!(db.lookup(ip("255.255.255.255")), None);
        assert_eq!(db.lookup(ip("2001:db8::")), Some((64503, *b"NL")));
        assert_eq!(
            db.lookup(ip("2001:db8:ffff:ffff::1")),
            Some((64503, *b"NL"))
        );
        assert_eq!(db.lookup(ip("2001:db9::")), None);
        assert_eq!(db.lookup(ip("2001:db7:ffff:ffff::")), None);
        assert_eq!(db.lookup(ip("::ffff:10.0.1.7")), Some((64501, *b"DE")));
    }

    #[test]
    fn verdict_matches() {
        let db = table();
        let rec = record(Some("10.0.0.7:4000"), None);
        assert_eq!(
            verdict(Some(&db), Some(&origin(64500, b"FR", false)), Some(&rec)),
            OriginVerdict::Matches
        );
        let rec6 = record(Some("10.0.0.7:4000"), Some("[2001:db8::1]:4000"));
        assert_eq!(
            verdict(Some(&db), Some(&origin(64503, b"NL", true)), Some(&rec6)),
            OriginVerdict::Matches
        );
    }

    #[test]
    fn verdict_mismatch_on_asn() {
        let db = table();
        let rec = record(Some("10.0.0.7:4000"), None);
        assert_eq!(
            verdict(Some(&db), Some(&origin(1, b"FR", false)), Some(&rec)),
            OriginVerdict::Mismatch {
                declared_asn: 1,
                declared_country: *b"FR",
                observed_asn: 64500,
                observed_country: *b"FR",
            }
        );
    }

    #[test]
    fn verdict_mismatch_on_country() {
        let db = table();
        let rec = record(Some("10.0.0.7:4000"), None);
        assert_eq!(
            verdict(Some(&db), Some(&origin(64500, b"DE", false)), Some(&rec)),
            OriginVerdict::Mismatch {
                declared_asn: 64500,
                declared_country: *b"DE",
                observed_asn: 64500,
                observed_country: *b"FR",
            }
        );
    }

    #[test]
    fn verdict_unverifiable_without_record() {
        let db = table();
        let o4 = origin(64500, b"FR", false);
        let o6 = origin(64503, b"NL", true);
        let only4 = record(Some("10.0.0.7:4000"), None);
        assert_eq!(
            verdict(Some(&db), Some(&o4), None),
            OriginVerdict::Unverifiable(UnverifiableReason::NoRecord)
        );
        // The family named by the origin is absent: no fallback.
        assert_eq!(
            verdict(Some(&db), Some(&o6), Some(&only4)),
            OriginVerdict::Unverifiable(UnverifiableReason::NoRecord)
        );
    }

    #[test]
    fn verdict_unverifiable_not_in_base() {
        let db = table();
        let rec = record(Some("99.0.0.1:4000"), None);
        let o = origin(64500, b"FR", false);
        let nib = OriginVerdict::Unverifiable(UnverifiableReason::NotInBase);
        assert_eq!(verdict(Some(&db), Some(&o), Some(&rec)), nib);
        assert_eq!(verdict(None, Some(&o), Some(&rec)), nib);
    }

    #[test]
    fn verdict_unverifiable_not_reported() {
        let db = table();
        let rec = record(Some("10.0.0.7:4000"), None);
        assert_eq!(
            verdict(Some(&db), None, Some(&rec)),
            OriginVerdict::Unverifiable(UnverifiableReason::NotReported)
        );
    }

    #[test]
    fn open_rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipdb.bin");
        let mut bytes = encode("2026-11", &[], &[]);
        bytes[0] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(IpDb::open(&path), Err(GeoError::BadMagic)));
        assert!(matches!(
            IpDb::open(&dir.path().join("missing")),
            Err(GeoError::Io(_))
        ));
    }

    #[test]
    fn open_rejects_corrupt_files() {
        let good = encode(
            "2026-11",
            &[
                rng(v4([10, 0, 0, 0]), v4([10, 0, 0, 255]), 1, b"FR"),
                rng(v4([11, 0, 0, 0]), v4([11, 0, 0, 255]), 2, b"DE"),
            ],
            &[],
        );
        let mut truncated = good.clone();
        truncated.pop();
        assert!(matches!(
            IpDb::from_bytes(truncated),
            Err(GeoError::BadLength)
        ));
        assert!(matches!(IpDb::from_bytes(vec![]), Err(GeoError::BadMagic)));
        let mut version = good.clone();
        version[11] = 9;
        assert!(matches!(
            IpDb::from_bytes(version),
            Err(GeoError::UnsupportedVersion(9))
        ));
        // Swap the first two entries' starts: unsorted.
        let mut unsorted = good.clone();
        let base = HEADER_LEN + VALUE_LEN * 3; // three distinct values
        let a = base + V4_ENTRY;
        let b = base + V4_ENTRY * 2;
        let (x, y) = (unsorted[a..a + 4].to_vec(), unsorted[b..b + 4].to_vec());
        unsorted[a..a + 4].copy_from_slice(&y);
        unsorted[b..b + 4].copy_from_slice(&x);
        assert!(matches!(
            IpDb::from_bytes(unsorted),
            Err(GeoError::Unsorted)
        ));
        // An entry pointing past the value table.
        let mut badval = good.clone();
        let e = HEADER_LEN + VALUE_LEN * 3 + 4;
        badval[e + 2] = 200;
        assert!(matches!(IpDb::from_bytes(badval), Err(GeoError::BadValue)));
        // A count that overflows the length.
        let mut huge = good;
        huge[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(IpDb::from_bytes(huge), Err(GeoError::BadLength)));
    }

    #[test]
    fn merge_splits_at_every_boundary_and_coalesces() {
        let asn = [(0, 99, 7u32), (100, 199, 7), (300, 399, 8)];
        let cc = [(50, 149, *b"FR"), (150, 349, *b"DE")];
        let m = merge_ranges(&asn, &cc);
        assert_eq!(
            m,
            vec![
                rng(0, 49, 7, b"ZZ"),
                rng(50, 149, 7, b"FR"),
                rng(150, 199, 7, b"DE"),
                rng(200, 299, 0, b"DE"),
                rng(300, 349, 8, b"DE"),
                rng(350, 399, 8, b"ZZ"),
            ]
        );
    }

    #[test]
    fn verdict_half_known_never_mismatches_on_the_unknown_half() {
        let db = IpDb::from_bytes(encode(
            "2026-11",
            &[
                rng(v4([10, 0, 0, 0]), v4([10, 0, 0, 255]), 0, b"FR"),
                rng(v4([10, 0, 1, 0]), v4([10, 0, 1, 255]), 64500, b"ZZ"),
            ],
            &[],
        ))
        .unwrap();
        let a = record(Some("10.0.0.7:4000"), None); // asn unknown, FR
        let b = record(Some("10.0.1.7:4000"), None); // AS64500, country unknown
        let nib = OriginVerdict::Unverifiable(UnverifiableReason::NotInBase);
        assert_eq!(
            verdict(Some(&db), Some(&origin(7, b"FR", false)), Some(&a)),
            nib
        );
        assert!(matches!(
            verdict(Some(&db), Some(&origin(7, b"DE", false)), Some(&a)),
            OriginVerdict::Mismatch {
                observed_asn: 0,
                ..
            }
        ));
        assert_eq!(
            verdict(Some(&db), Some(&origin(64500, b"DE", false)), Some(&b)),
            nib
        );
        assert!(matches!(
            verdict(Some(&db), Some(&origin(1, b"DE", false)), Some(&b)),
            OriginVerdict::Mismatch {
                observed_asn: 64500,
                ..
            }
        ));
    }

    #[test]
    fn v6_range_starting_mid_unit_keeps_its_later_units() {
        // A ends mid-/64 (unit u); B starts in the same unit and runs on.
        let a = rng(v6("2001:db8::"), v6("2001:db8:0:1:8000::"), 1, b"FR");
        let b = rng(
            v6("2001:db8:0:1:8000::1"),
            v6("2001:db8:0:5:ffff:ffff:ffff:ffff"),
            2,
            b"DE",
        );
        let db = IpDb::from_bytes(encode("2026-11", &[], &[a, b])).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(db.lookup(ip("2001:db8:0:1::")), Some((1, *b"FR")));
        // Later units of B are covered, not a gap.
        for u in ["2001:db8:0:2::", "2001:db8:0:3::1", "2001:db8:0:5:ffff::"] {
            assert_eq!(db.lookup(ip(u)), Some((2, *b"DE")), "{u}");
        }
        assert_eq!(db.lookup(ip("2001:db8:0:6::")), None);
        // /64 design: an address in a range's first /64 maps to that range
        // even before the exact start.
        let c = rng(
            v6("2001:db9:0:7:8000::"),
            v6("2001:db9:0:7:ffff::"),
            3,
            b"NL",
        );
        let db = IpDb::from_bytes(encode("2026-11", &[], &[c])).unwrap();
        assert_eq!(db.lookup(ip("2001:db9:0:7::1")), Some((3, *b"NL")));
    }

    #[test]
    fn both_unknown_range_is_not_found() {
        let db = IpDb::from_bytes(encode(
            "2026-11",
            &[rng(v4([10, 0, 0, 0]), v4([10, 0, 0, 255]), 0, b"ZZ")],
            &[],
        ))
        .unwrap();
        assert_eq!(db.lookup("10.0.0.1".parse().unwrap()), None);
    }
}
