#!/usr/bin/env bash
# Compares the two independent builds (copies a and b) of every published target byte by byte,
# then assembles the release files: the binaries (mode 755) and a merged, sorted SHA256SUMS.
#
# Usage: compare-copies.sh --copies <dir> --out <dir>
#   <dir>/build-<target>-a and <dir>/build-<target>-b exist for each target of CIBLES_PUBLIEES,
#   each holding one barking-cli-*, one barking-node-* and one barking-push-* binary plus SHA256SUMS.
#   <out> is created; it must be absent or empty.
# Exits with 1 and a message at the first anomaly. Compatible with bash 3.2 (macOS).
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() { echo "usage: $0 --copies <dir> --out <dir>" >&2; exit 2; }

copies=""; sortie=""
while [ $# -gt 0 ]; do
  case "$1" in
    --copies) [ $# -ge 2 ] || usage; copies="$2"; shift 2 ;;
    --out)    [ $# -ge 2 ] || usage; sortie="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$copies" ] && [ -n "$sortie" ] || usage

# Checks the files listed in <dir>/SHA256SUMS ($1) against their actual checksums.
verifier_sommes() {
  local dir="$1" ligne somme nom reel
  local motif='^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$'
  [ -s "$dir/SHA256SUMS" ] || erreur "SHA256SUMS missing or empty in $dir"
  while IFS= read -r ligne || [ -n "$ligne" ]; do
    [[ $ligne =~ $motif ]] || erreur "unreadable line in $dir/SHA256SUMS: $ligne"
    somme="${BASH_REMATCH[1]}"; nom="${BASH_REMATCH[2]}"
    [ -f "$dir/$nom" ] || erreur "$nom is listed in $dir/SHA256SUMS but missing"
    reel="$(sha256_de "$dir/$nom")" || reel=""
    [ "$reel" = "$somme" ] || erreur "incorrect checksum for $nom in $dir (SHA256SUMS: $somme, file: ${reel:-unreadable})"
  done < "$dir/SHA256SUMS"
}

# The output directory must be absent or empty.
if [ -e "$sortie" ]; then
  [ -d "$sortie" ] || erreur "$sortie exists and is not a directory"
  [ -z "$(ls -A "$sortie")" ] || erreur "output directory $sortie is not empty"
fi
mkdir -p "$sortie"

for t in $CIBLES_PUBLIEES; do
  a="$copies/build-$t-a"; b="$copies/build-$t-b"
  { [ -d "$a" ] && [ -d "$b" ]; } || erreur "missing copies for $t"
  for prog in barking-cli barking-node barking-push; do
    bins_a="$(cd "$a" && ls "$prog"-* 2>/dev/null || true)"
    bins_b="$(cd "$b" && ls "$prog"-* 2>/dev/null || true)"
    if [ -z "$bins_a" ] || [ "$(printf '%s\n' "$bins_a" | wc -l | tr -d ' ')" -ne 1 ]; then
      erreur "there must be exactly one $prog binary for $t (copy a): $bins_a"
    fi
    [ "$bins_a" = "$bins_b" ] || erreur "binary names differ for $t: $bins_a / $bins_b"
    case "$bins_a" in *"-$t") ;; *) erreur "unexpected name for $t: $bins_a" ;; esac
    cmp -s "$a/$bins_a" "$b/$bins_a" || erreur "the two copies of $t differ ($prog): non-reproducible build"
    cp "$a/$bins_a" "$sortie/"
  done
  cmp -s "$a/SHA256SUMS" "$b/SHA256SUMS" || erreur "the SHA256SUMS of the copies of $t differ"
  verifier_sommes "$a"
done

for prog in barking-cli barking-node barking-push; do
  n="$(find "$sortie" -maxdepth 1 -type f -name "$prog-*" | wc -l | tr -d ' ')"
  [ "$n" -eq 3 ] || erreur "3 $prog binaries expected, found $n"
done
chmod 755 "$sortie"/barking-cli-* "$sortie"/barking-node-* "$sortie"/barking-push-*

# Merged SHA256SUMS, sorted by file name, then checked again.
for f in "$sortie"/barking-cli-* "$sortie"/barking-node-* "$sortie"/barking-push-*; do
  printf '%s  %s\n' "$(sha256_de "$f")" "$(basename "$f")"
done | LC_ALL=C sort -k2 > "$sortie/SHA256SUMS"
verifier_sommes "$sortie"
cat "$sortie/SHA256SUMS"
