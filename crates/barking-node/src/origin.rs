//! Automatic origin of the node (`NodeInfoReport::origin`): the autonomous
//! system and country of its own public address, looked up through the Team
//! Cymru IP-to-ASN mapping over DNS (TXT records, `*.asn.cymru.com`). Two
//! queries: `origin(6).asn.cymru.com` for the ASN and country, then
//! `AS<asn>.asn.cymru.com` for the name.
//!
//! The address queried is the node's own public address, taken from its own
//! record; a node without one, or whose address is not routable, queries
//! nothing. The query names embed that address, so the resolver (and Team
//! Cymru) see it: `[info] origin_lookup = false` turns the lookup off. The
//! address and the raw answers are never logged.
//!
//! Refresh: every `REFRESH_PERIOD` (24 h) after a success; after any failure
//! (either query), a retry every `RETRY_PERIOD` (1 h). A failure keeps the
//! last origin known, if any.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use barking_proto::{MAX_AS_NAME_LEN, NodeOrigin, routable};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::sync::watch;

use crate::info::InfoState;

/// Delay before the next lookup after a success.
pub const REFRESH_PERIOD: Duration = Duration::from_secs(24 * 3600);
/// Delay before the next lookup after a failure.
pub const RETRY_PERIOD: Duration = Duration::from_secs(3600);
/// Deadline of one pair of queries.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A DNS lookup failed (no answer, timeout, resolver error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("DNS lookup failed")]
pub struct LookupError;

/// TXT queries, behind a trait so tests never touch the network.
pub trait TxtLookup: Send + Sync + 'static {
    /// The TXT records of `name`, each with its character strings joined.
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, LookupError>> + Send;
}

/// System resolver (`/etc/resolv.conf`) through hickory.
pub struct HickoryLookup(TokioResolver);

impl HickoryLookup {
    /// Fails when the system configuration cannot be read.
    pub fn from_system() -> Result<HickoryLookup, LookupError> {
        let b = TokioResolver::builder_tokio().map_err(|_| LookupError)?;
        Ok(HickoryLookup(b.build().map_err(|_| LookupError)?))
    }
}

impl TxtLookup for HickoryLookup {
    async fn txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        let l = self
            .0
            .lookup(name, RecordType::TXT)
            .await
            .map_err(|_| LookupError)?;
        Ok(l.answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(t) => Some(
                    t.txt_data
                        .iter()
                        .map(|s| String::from_utf8_lossy(s))
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

/// Name to query for the ASN and country of `ip`.
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(32 * 2 + 24);
            for b in v6.octets().iter().rev() {
                s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
                s.push('.');
                s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
                s.push('.');
            }
            s.push_str("origin6.asn.cymru.com");
            s
        }
    }
}

/// `"16276 | 51.38.0.0/16 | FR | ripencc | 2014-04-03"`: ASN (the first one
/// when several are listed) and country (upper-cased).
pub fn parse_origin(txt: &str) -> Option<(u32, [u8; 2])> {
    let mut f = txt.split('|').map(str::trim);
    let asn = f.next()?.split_whitespace().next()?.parse::<u32>().ok()?;
    let _prefix = f.next()?;
    let cc = f.next()?.as_bytes();
    match cc {
        [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
            Some((asn, [a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
        }
        _ => None,
    }
}

/// `"16276 | FR | ripencc | 2004-02-18 | OVH, FR"`: the name (fifth field),
/// reduced to printable ASCII and at most `MAX_AS_NAME_LEN` bytes.
pub fn parse_as_name(txt: &str) -> Option<String> {
    let name = txt.splitn(5, '|').nth(4)?;
    let mut out: String = name
        .chars()
        .filter(|c| (' '..='~').contains(c))
        .collect::<String>()
        .trim()
        .to_string();
    out.truncate(MAX_AS_NAME_LEN);
    let out = out.trim_end().to_string();
    (!out.is_empty()).then_some(out)
}

/// Same routability rule as the records (`barking_proto::routable`).
fn is_public(ip: IpAddr) -> bool {
    routable(&SocketAddr::new(ip, 1))
}

async fn resolve(lookup: &impl TxtLookup, ip: IpAddr) -> Option<NodeOrigin> {
    let answers = lookup.txt(&cymru_origin_name(ip)).await.ok()?;
    let (asn, country) = answers.iter().find_map(|t| parse_origin(t))?;
    let answers = lookup.txt(&format!("AS{asn}.asn.cymru.com")).await.ok()?;
    let as_name = answers.iter().find_map(|t| parse_as_name(t))?;
    Some(NodeOrigin {
        asn,
        as_name,
        country,
        for_v6: ip.is_ipv6(),
    })
}

/// Looks up the origin of `addr` at startup, then every `REFRESH_PERIOD`
/// (every `RETRY_PERIOD` after a failure), until `stop`. Without an address,
/// with a non-routable one, or if `enabled` is false: no query, origin
/// `None`.
pub async fn origin_loop(
    lookup: impl TxtLookup,
    addr: Option<IpAddr>,
    enabled: bool,
    state: Arc<InfoState>,
    mut stop: watch::Receiver<bool>,
) {
    let Some(ip) = addr.filter(|ip| enabled && is_public(*ip)) else {
        state.set_origin(None);
        return;
    };
    loop {
        let found = tokio::time::timeout(LOOKUP_TIMEOUT, resolve(&lookup, ip))
            .await
            .ok()
            .flatten();
        let wait = if let Some(o) = found {
            state.set_origin(Some(o));
            REFRESH_PERIOD
        } else {
            tracing::warn!("origin: lookup failed, retrying later");
            RETRY_PERIOD
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stop.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::wake::WakeConfig;

    const ORIGIN: &str = "16276 | 51.38.0.0/16 | FR | ripencc | 2014-04-03";
    const NAME: &str = "16276 | FR | ripencc | 2004-02-18 | OVH, FR";

    #[test]
    fn cymru_names_v4_v6() {
        assert_eq!(
            cymru_origin_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.origin.asn.cymru.com"
        );
        let n = cymru_origin_name("2001:db8::1".parse().unwrap());
        let nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2";
        assert_eq!(n, format!("{nibbles}.origin6.asn.cymru.com"));
    }

    #[test]
    fn parse_valid_cymru_answers() {
        assert_eq!(parse_origin(ORIGIN), Some((16276, *b"FR")));
        assert_eq!(parse_origin("1 2 | x/8 | US | arin |"), Some((1, *b"US")));
        assert_eq!(parse_as_name(NAME).as_deref(), Some("OVH, FR"));
    }

    #[test]
    fn parse_rejects_malformed_cymru_answers() {
        for bad in [
            "",
            "abc | x",
            "16276 | 51.38.0.0/16 | FRA | ripencc | 2014",
            "99999999999 | 51.38.0.0/16 | FR | ripencc | 2014",
        ] {
            assert_eq!(parse_origin(bad), None, "{bad:?}");
        }
        assert_eq!(parse_origin("1 | x | fr | y"), Some((1, *b"FR")));
        assert_eq!(parse_as_name(""), None);
        assert_eq!(parse_as_name("1 | FR | x | y"), None);
        let long = format!("1 | FR | x | y | {}", "A".repeat(500));
        assert_eq!(parse_as_name(&long).unwrap().len(), MAX_AS_NAME_LEN);
        assert_eq!(
            parse_as_name("1 | FR | x | y | OV\u{7}H").as_deref(),
            Some("OVH")
        );
    }

    #[derive(Default)]
    struct Fake {
        calls: AtomicUsize,
        answers: Mutex<HashMap<String, Vec<String>>>,
        fail: Mutex<bool>,
    }

    impl TxtLookup for Arc<Fake> {
        async fn txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if *self.fail.lock().unwrap() {
                return Err(LookupError);
            }
            self.answers
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .ok_or(LookupError)
        }
    }

    fn fake_ok(ip: &str) -> Arc<Fake> {
        let f = Arc::new(Fake::default());
        let mut a = f.answers.lock().unwrap();
        a.insert(
            cymru_origin_name(ip.parse().unwrap()),
            vec![ORIGIN.to_string()],
        );
        a.insert("AS16276.asn.cymru.com".into(), vec![NAME.to_string()]);
        drop(a);
        f
    }

    fn state() -> Arc<InfoState> {
        Arc::new(InfoState::new(1000, &WakeConfig::default(), 5, None))
    }

    #[tokio::test]
    async fn private_address_not_looked_up() {
        let f = fake_ok("10.0.0.1");
        for addr in ["10.0.0.1", "127.0.0.1", "fd00::1"] {
            let (_tx, rx) = watch::channel(false);
            let s = state();
            origin_loop(f.clone(), Some(addr.parse().unwrap()), true, s.clone(), rx).await;
            assert_eq!(s.snapshot(None).origin, None);
        }
        // Absent address, lookup disabled.
        let (_tx, rx) = watch::channel(false);
        origin_loop(f.clone(), None, true, state(), rx.clone()).await;
        origin_loop(
            f.clone(),
            Some("1.2.3.4".parse().unwrap()),
            false,
            state(),
            rx,
        )
        .await;
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_sets_origin_then_retries_after_failure() {
        let f = fake_ok("1.2.3.4");
        *f.fail.lock().unwrap() = true;
        let s = state();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(origin_loop(
            f.clone(),
            Some("1.2.3.4".parse().unwrap()),
            true,
            s.clone(),
            rx,
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(s.snapshot(None).origin, None);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        // Back up: the retry comes after one hour, not 24.
        *f.fail.lock().unwrap() = false;
        tokio::time::sleep(RETRY_PERIOD).await;
        assert_eq!(
            s.snapshot(None).origin,
            Some(NodeOrigin {
                asn: 16276,
                as_name: "OVH, FR".into(),
                country: *b"FR",
                for_v6: false,
            })
        );
        // Success: next lookup 24 h later; a failure then keeps the origin.
        *f.fail.lock().unwrap() = true;
        let before = f.calls.load(Ordering::SeqCst);
        tokio::time::sleep(RETRY_PERIOD * 2).await;
        assert_eq!(f.calls.load(Ordering::SeqCst), before);
        tokio::time::sleep(REFRESH_PERIOD).await;
        assert!(f.calls.load(Ordering::SeqCst) > before);
        assert!(s.snapshot(None).origin.is_some());
        tx.send(true).unwrap();
        task.await.unwrap();
    }
}
