#!/usr/bin/env bash
# Host tests of the CI and release scripts (bash and git only, no Docker).
# One cas_* function per case; each runs in its own subshell with a fresh temporary directory.
# Compatible with bash 3.2 (macOS).
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

cas_workspace_version_read() {
  local d out
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  cat > "$d/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/*"]

[workspace.dependencies]
foo = { version = "9.9.9" }

[workspace.package]
version = "1.2.3"
license = "AGPL-3.0-only"
TOML
  out="$(version_du_workspace "$d")"
  rm -rf "$d"
  [ "$out" = "1.2.3" ] || { echo "expected 1.2.3, got: $out" >&2; return 1; }
}

cas_workspace_version_missing() {
  local d out rc=0
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  cat > "$d/Cargo.toml" <<'TOML'
[workspace.dependencies]
foo = { version = "9.9.9" }

[workspace.package]
license = "AGPL-3.0-only"

[package]
version = "4.5.6"
TOML
  out="$( (version_du_workspace "$d") 2>&1)" || rc=$?
  rm -rf "$d"
  [ "$rc" -ne 0 ] || { echo "expected a non-zero exit code" >&2; return 1; }
  case "$out" in *"version not found"*) ;; *) echo "unexpected message: $out" >&2; return 1 ;; esac
}

# --- compare-copies.sh ---
# The cases below keep their temporary directory in the global d: the EXIT trap runs after the
# function has returned, when its locals are gone.
# Fake copies: <dir>/build-<target>-{a,b} with three tiny binaries and a SHA256SUMS each.
faire_copies() { # $1 = directory
  local t c p f
  for t in $CIBLES_PUBLIEES; do
    for c in a b; do
      mkdir -p "$1/build-$t-$c"
      for p in barking-cli barking-node barking-push; do
        printf '%s %s\n' "$p" "$t" > "$1/build-$t-$c/$p-1.0.0-$t"
      done
      for f in "$1/build-$t-$c"/barking-*; do
        printf '%s  %s\n' "$(sha256_de "$f")" "$(basename "$f")"
      done > "$1/build-$t-$c/SHA256SUMS"
    done
  done
}

# Runs compare-copies.sh on <d>/copies into <d>/out; sets SORTIE (output) and RC (exit code).
lancer_compare() { # $1 = working directory
  RC=0
  SORTIE="$("$racine/scripts/compare-copies.sh" --copies "$1/copies" --out "$1/out" 2>&1)" || RC=$?
}

# Expects a failure whose message contains $2.
attendre_echec() { # $1 = case name, $2 = expected fragment
  [ "$RC" -ne 0 ] || { echo "$1: expected a non-zero exit code" >&2; return 1; }
  case "$SORTIE" in *"$2"*) ;; *) echo "$1: unexpected message: $SORTIE" >&2; return 1 ;; esac
}

cas_compare_identical() {
  local n f
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  lancer_compare "$d"
  [ "$RC" -eq 0 ] || { echo "expected success, got $RC: $SORTIE" >&2; return 1; }
  n="$(find "$d/out" -maxdepth 1 -type f -name 'barking-*' | wc -l | tr -d ' ')"
  [ "$n" -eq 9 ] || { echo "expected 9 binaries, got $n" >&2; return 1; }
  [ "$(wc -l < "$d/out/SHA256SUMS" | tr -d ' ')" -eq 9 ] || { echo "expected 9 lines in SHA256SUMS" >&2; return 1; }
  LC_ALL=C sort -k2 -c "$d/out/SHA256SUMS" || { echo "SHA256SUMS is not sorted" >&2; return 1; }
  [ ! -x "$d/out/SHA256SUMS" ] || { echo "SHA256SUMS must not be executable" >&2; return 1; }
  for f in "$d"/out/barking-*; do
    [ -x "$f" ] || { echo "not executable: $f" >&2; return 1; }
    [ "$(sha256_de "$f")" = "$(grep "  $(basename "$f")\$" "$d/out/SHA256SUMS" | cut -d' ' -f1)" ] \
      || { echo "wrong checksum for $f" >&2; return 1; }
  done
}

cas_compare_binary_differs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo tampered >> "$d/copies/build-aarch64-apple-darwin-b/barking-node-1.0.0-aarch64-apple-darwin"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "differ" || return 1
  attendre_echec "${FUNCNAME[0]}" "non-reproducible" || return 1
}

cas_compare_missing_copy() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  rm -rf "$d/copies/build-aarch64-unknown-linux-musl-b"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "missing copies for aarch64-unknown-linux-musl" || return 1
}

cas_compare_two_binaries_for_one_program() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo extra > "$d/copies/build-x86_64-unknown-linux-musl-a/barking-cli-1.0.1-x86_64-unknown-linux-musl"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "exactly one" || return 1
}

cas_compare_wrong_target_suffix() {
  local t c
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  t=x86_64-unknown-linux-musl
  for c in a b; do
    mv "$d/copies/build-$t-$c/barking-push-1.0.0-$t" "$d/copies/build-$t-$c/barking-push-1.0.0-other"
  done
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "unexpected name" || return 1
}

cas_compare_sums_differ() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo "# extra" >> "$d/copies/build-x86_64-unknown-linux-musl-b/SHA256SUMS"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "SHA256SUMS of the copies of x86_64-unknown-linux-musl differ" || return 1
}

cas_compare_out_not_empty() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  mkdir "$d/out"; echo x > "$d/out/leftover"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "not empty" || return 1
  [ ! -e "$d/out/SHA256SUMS" ] || { echo "nothing must be written to a non-empty output" >&2; return 1; }
}

# --- runner ---
echec=""
for cas in $(declare -F | awk '{print $3}' | grep '^cas_'); do
  if ( set -e; "$cas" ); then echo "ok   $cas"; else echo "FAIL $cas"; echec="$echec $cas"; fi
done
if [ -n "$echec" ]; then echo "failed:$echec" >&2; exit 1; fi
echo "OK: all cases pass"
