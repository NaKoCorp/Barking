//! `barking census`: walks the network from the seeds of `BARKING_SEEDS`
//! (`<identifier>@<ip:port>`, separated by spaces, commas or newlines) and
//! writes the public list of the nodes that answered, as JSON.
//!
//! Needs no identity. The output never holds an address, not even in an
//! error: it feeds a public page, and the seeds stay private. A node is
//! placed in the country it declares (its own lookup of its address), and
//! with the IP base (`--ipdb`) from the address it answered on only when it
//! declares none; the verdict compares the two, and `ip_country` keeps what
//! the base says.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use barking_net::QuicDialer;
use barking_net::census::{CensusNode, CensusOptions, census};
use barking_net::geo::{IpDb, OriginVerdict, UNKNOWN_COUNTRY, verdict};
use barking_proto::FillTier;
use serde::Serialize;

use super::{CliError, CliResult, fail, now};

/// Version of the JSON layout.
const SCHEMA: u32 = 1;
const SEEDS_VAR: &str = "BARKING_SEEDS";

#[derive(Serialize)]
struct Output {
    schema: u32,
    generated_at: u64,
    /// Month of the IP base, `None` without one.
    ipdb: Option<String>,
    truncated: bool,
    /// Nodes found but not answering: counted, not listed.
    unreachable: usize,
    nodes: Vec<NodeOut>,
}

#[derive(Serialize)]
struct NodeOut {
    /// First 8 characters of the identifier, as the app shows it.
    id: String,
    in_table: bool,
    /// Country the node declares, else the one of the address it answered
    /// on (IP base).
    country: Option<String>,
    /// Country of the address it answered on, from the IP base.
    ip_country: Option<String>,
    asn: Option<u32>,
    as_name: Option<String>,
    /// "matches", "mismatch" or "unverifiable".
    origin: &'static str,
    software: Option<String>,
    protocol: Option<u16>,
    uptime_secs: Option<u64>,
    storage: Option<&'static str>,
    wake: Option<&'static str>,
}

fn tier(t: FillTier) -> &'static str {
    match t {
        FillTier::Low => "low",
        FillTier::Medium => "medium",
        FillTier::High => "high",
        FillTier::Full => "full",
    }
}

fn country(code: [u8; 2]) -> Option<String> {
    (code != UNKNOWN_COUNTRY && code.iter().all(u8::is_ascii_alphabetic))
        .then(|| String::from_utf8_lossy(&code).to_ascii_uppercase())
}

fn node_out(node: &CensusNode, db: Option<&IpDb>) -> Option<NodeOut> {
    let probe = node.probe.as_ref()?;
    let report = probe.report.as_ref();
    let declared = report.and_then(|r| r.origin.as_ref());
    let observed = node.observed_ip();
    let seen = observed.and_then(|ip| db.and_then(|d| d.lookup(ip)));
    let seen_asn = seen.map(|(asn, _)| asn).filter(|&a| a != 0);
    let seen_country = seen.and_then(|(_, c)| country(c));

    let asn = seen_asn.or(declared.map(|o| o.asn));
    let as_name = declared
        .filter(|o| Some(o.asn) == asn)
        .map(|o| o.as_name.clone())
        .filter(|n| !n.is_empty());
    let origin = match verdict(db, declared, observed) {
        OriginVerdict::Matches => "matches",
        OriginVerdict::Mismatch { .. } => "mismatch",
        OriginVerdict::Unverifiable(_) => "unverifiable",
    };
    Some(NodeOut {
        id: barking_net::sync::short_id(&node.id),
        in_table: node.in_table,
        country: declared
            .and_then(|o| country(o.country))
            .or_else(|| seen_country.clone()),
        ip_country: seen_country,
        asn,
        as_name,
        origin,
        software: report.map(|r| r.software.clone()),
        protocol: report.map(|r| r.protocol),
        uptime_secs: report.map(|r| r.uptime_secs),
        storage: report.map(|r| tier(r.storage)),
        wake: report.and_then(|r| r.wake).map(tier),
    })
}

/// Seeds of `BARKING_SEEDS`; an entry that does not parse is an error that
/// names its position, never its content.
fn seeds() -> CliResult<Vec<barking_dht::BootstrapEntry>> {
    let raw = std::env::var(SEEDS_VAR).unwrap_or_default();
    let mut out = Vec::new();
    for (i, entry) in raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        match barking_dht::parse_bootstrap(entry) {
            Ok(e) => out.push(e),
            Err(_) => {
                return fail(format!(
                    "{SEEDS_VAR}: entry {} is not <id>@<ip:port>",
                    i + 1
                ));
            }
        }
    }
    if out.is_empty() {
        return fail(format!(
            "{SEEDS_VAR} is empty: give at least one <id>@<ip:port>"
        ));
    }
    Ok(out)
}

pub fn run(ipdb: Option<&Path>, out: Option<&Path>, deadline_secs: u64) -> CliResult<()> {
    let seeds = seeds()?;
    let db = match ipdb {
        Some(path) => {
            Some(IpDb::open(path).map_err(|e| CliError(format!("Unreadable IP base: {e}")))?)
        }
        None => None,
    };
    let opts = CensusOptions {
        deadline: Duration::from_secs(deadline_secs),
        allow_private: super::nodes::allow_private(),
        ..CensusOptions::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError(format!("I/O error: {e}")))?;
    let mut rng = rand::rng();
    let result = rt.block_on(census(&QuicDialer, &seeds, opts, &mut rng, now()));
    rt.shutdown_timeout(Duration::from_secs(1));

    let nodes: Vec<NodeOut> = result
        .nodes
        .iter()
        .filter_map(|n| node_out(n, db.as_ref()))
        .collect();
    let output = Output {
        schema: SCHEMA,
        generated_at: now(),
        ipdb: db.as_ref().map(IpDb::source),
        truncated: result.truncated,
        unreachable: result.nodes.len() - nodes.len(),
        nodes,
    };
    let json =
        serde_json::to_string_pretty(&output).map_err(|e| CliError(format!("JSON error: {e}")))?;
    match out {
        Some(path) => fs::write(path, json + "\n")?,
        None => writeln!(std::io::stdout(), "{json}")?,
    }
    eprintln!(
        "Census: {} nodes answered, {} did not{}",
        output.nodes.len(),
        output.unreachable,
        if output.truncated {
            " (stopped early)"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes_are_two_letters_and_never_unknown() {
        assert_eq!(country(*b"fr").as_deref(), Some("FR"));
        assert_eq!(country(UNKNOWN_COUNTRY), None);
        assert_eq!(country(*b"1!"), None);
    }
}
