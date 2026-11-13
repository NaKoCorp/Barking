#!/usr/bin/env bash
# Test: two builds from two clones at different paths give the same checksums.
# REPRO_TARGET=<triple> builds another target than the host's; REPRO_KEEP=<dir>
# copies the release directory of the first build there once the test passed.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-repro-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echec() { echo "FAILURE: $*" >&2; exit 1; }

a="$tmp/a"
b="$tmp/much/longer/path"
mkdir -p "$(dirname "$b")"
git clone -q --no-hardlinks "$racine" "$a"
git clone -q --no-hardlinks "$racine" "$b"
# Same commit in both clones (the current repository's HEAD).
commit="$(git -C "$racine" rev-parse HEAD)"
git -C "$a" checkout -q "$commit"
git -C "$b" checkout -q "$commit"

cible_args=()
[ -n "${REPRO_TARGET:-}" ] && cible_args=(--target "$REPRO_TARGET")

"$a/scripts/repro-build.sh" ${cible_args[@]+"${cible_args[@]}"} --ref "$commit" --out "$tmp/out-a" \
  || echec "first build (non-zero exit code)"
"$b/scripts/repro-build.sh" ${cible_args[@]+"${cible_args[@]}"} --ref "$commit" --out "$tmp/out-b" \
  || echec "second build (non-zero exit code)"

diff "$tmp/out-a/SHA256SUMS" "$tmp/out-b/SHA256SUMS" \
  || echec "the SHA256SUMS differ between the two builds"

# Both binaries are produced and listed in SHA256SUMS (sorted).
for b in barking-cli barking-node barking-push; do
  [ "$(grep -c "  $b-" "$tmp/out-a/SHA256SUMS")" -eq 1 ] || echec "SHA256SUMS must list exactly one $b"
  [ "$(find "$tmp/out-a" -type f -name "$b-*" | wc -l | tr -d ' ')" -eq 1 ] || echec "there must be exactly one $b binary"
  cmp "$(find "$tmp/out-a" -type f -name "$b-*")" "$(find "$tmp/out-b" -type f -name "$b-*")" \
    || echec "the two builds of $b differ"
done
[ "$(wc -l < "$tmp/out-a/SHA256SUMS" | tr -d ' ')" -eq 3 ] || echec "SHA256SUMS must contain exactly three lines"
LC_ALL=C sort -c -k2 "$tmp/out-a/SHA256SUMS" || echec "SHA256SUMS is not sorted"

# The produced binaries run (in a container if they are Linux binaries).
for b in barking-cli barking-node barking-push; do
  bin="$(find "$tmp/out-a" -type f -name "$b-*" | head -n1)"
  [ -n "$bin" ] || echec "no $b artifact produced"
  case "$bin" in
    *-linux-musl)
      arch="amd64"; case "$bin" in *aarch64*) arch="arm64" ;; esac
      docker run --rm --platform "linux/$arch" -v "$bin:/$b:ro" \
        alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a "/$b" --help >/dev/null \
        || echec "$b --help failed" ;;
    *) "$bin" --help >/dev/null || echec "$b --help failed" ;;
  esac
done

# Every comparison passed: keep the first build for the caller if asked to.
if [ -n "${REPRO_KEEP:-}" ]; then
  mkdir -p "$REPRO_KEEP"
  cp -R "$tmp/out-a/." "$REPRO_KEEP/"
fi

echo "OK: identical builds ($(cat "$tmp/out-a/SHA256SUMS"))"
