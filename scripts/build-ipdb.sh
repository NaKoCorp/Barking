#!/usr/bin/env bash
# Usage: scripts/build-ipdb.sh [YYYY-MM]
#
# Builds the offline IP base the app uses to check what a node says about its
# own origin (ASN, country): apple/Barking/Resources/ipdb.bin and its license
# text ipdb.LICENSE.txt.
#
# Source: DB-IP Lite (country + ASN), CC BY 4.0, no account or token. The
# month is the argument; by default the current month, falling back to the
# previous one if it is not published yet.
#
# The generated files ARE COMMITTED: the app build must not need the network.
# Run this script (about once a month at most) to refresh them, then commit.
# Downloads go to a temporary directory, never to the repository.
set -euo pipefail
cd "$(dirname "$0")/.."

out_dir=apple/Barking/Resources
base=https://download.db-ip.com/free

month_ago() { # YYYY-MM of the previous month (BSD and GNU date)
  date -v-1m +%Y-%m 2>/dev/null || date -d "$(date +%Y-%m-01) -1 month" +%Y-%m
}

fetch() { # fetch <kind> <month> <dest>: 0 if downloaded, a valid non-empty gzip
  curl -fsSL --retry 2 -o "$3.gz" "$base/dbip-$1-lite-$2.csv.gz" || return 1
  gzip -t "$3.gz" || return 1
  gunzip -c "$3.gz" >"$3"
  [ -s "$3" ] || return 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$#" -gt 1 ]; then
  echo "usage: scripts/build-ipdb.sh [YYYY-MM]" >&2
  exit 2
elif [ "$#" -eq 1 ]; then
  month=$1
  fetch country "$month" "$tmp/country.csv" && fetch asn "$month" "$tmp/asn.csv" || {
    echo "error: DB-IP Lite $month not downloadable" >&2
    exit 1
  }
else
  month=$(date +%Y-%m)
  if ! { fetch country "$month" "$tmp/country.csv" && fetch asn "$month" "$tmp/asn.csv"; }; then
    month=$(month_ago)
    echo "current month not published, using $month" >&2
    fetch country "$month" "$tmp/country.csv" && fetch asn "$month" "$tmp/asn.csv" || {
      echo "error: DB-IP Lite $month not downloadable" >&2
      exit 1
    }
  fi
fi
[[ "$month" =~ ^[0-9]{4}-[0-9]{2}$ ]] || {
  echo "error: month must be YYYY-MM" >&2
  exit 2
}

mkdir -p "$out_dir"
cargo run --release --locked -q -p barking-net --example build_ipdb -- \
  "$tmp/country.csv" "$tmp/asn.csv" "$month" "$out_dir/ipdb.bin"

cat >"$out_dir/ipdb.LICENSE.txt" <<LIC
ipdb.bin is built from the DB-IP Lite country and ASN databases
(source month: $month).

IP Geolocation by DB-IP (https://db-ip.com)

The DB-IP Lite databases are licensed under the Creative Commons Attribution
4.0 International License (CC BY 4.0):
https://creativecommons.org/licenses/by/4.0/

The data was converted to a compact binary format (see
crates/barking-net/src/geo.rs); IPv6 ranges are stored at /64 granularity.
Regenerate with scripts/build-ipdb.sh.
LIC
ls -l "$out_dir/ipdb.bin"
