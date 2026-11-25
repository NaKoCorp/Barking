//! Converts the DB-IP Lite CSVs into the app's IP base (see `geo.rs`).
//! Driven by `scripts/build-ipdb.sh`:
//!
//!   build_ipdb <country.csv> <asn.csv> <YYYY-MM> <out.bin>
//!
//! country rows: `start,end,cc`; asn rows: `start,end,asn,"org"` (the
//! organisation may be quoted and contain commas; it is ignored).

use std::net::IpAddr;
use std::process::ExitCode;

use barking_net::geo::{Range, encode, merge_ranges};

type Rows<T> = (Vec<(u128, u128, T)>, Vec<(u128, u128, T)>);

fn parse<T>(path: &str, third: impl Fn(&str) -> Option<T>) -> Result<Rows<T>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    let mut skipped = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut f = line.splitn(4, ',').map(|s| s.trim().trim_matches('"'));
        let row = (|| {
            let s: IpAddr = f.next()?.parse().ok()?;
            let e: IpAddr = f.next()?.parse().ok()?;
            Some((s, e, third(f.next()?)?))
        })();
        match row {
            Some((IpAddr::V4(s), IpAddr::V4(e), x)) => {
                v4.push((u128::from(u32::from(s)), u128::from(u32::from(e)), x))
            }
            Some((IpAddr::V6(s), IpAddr::V6(e), x)) => v6.push((u128::from(s), u128::from(e), x)),
            _ => skipped += 1,
        }
    }
    if v4.is_empty() || v6.is_empty() || skipped * 100 > v4.len() + v6.len() {
        return Err(format!(
            "{path}: unusable ({} v4, {} v6, {skipped} skipped rows)",
            v4.len(),
            v6.len()
        ));
    }
    eprintln!(
        "{path}: {} v4, {} v6, {skipped} skipped",
        v4.len(),
        v6.len()
    );
    Ok((v4, v6))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [country, asn, source, out] = args.as_slice() else {
        return Err("usage: build_ipdb <country.csv> <asn.csv> <YYYY-MM> <out.bin>".into());
    };
    let (c4, c6) = parse(country, |s| {
        let b = s.as_bytes();
        (b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic))
            .then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
    })?;
    let (a4, a6) = parse(asn, |s| s.parse::<u32>().ok())?;
    let r4: Vec<Range> = merge_ranges(&a4, &c4);
    let r6: Vec<Range> = merge_ranges(&a6, &c6);
    let bytes = encode(source, &r4, &r6);
    std::fs::write(out, &bytes).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "{out}: {} bytes ({} merged v4 ranges, {} merged v6 ranges)",
        bytes.len(),
        r4.len(),
        r6.len()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("build_ipdb: {e}");
            ExitCode::FAILURE
        }
    }
}
