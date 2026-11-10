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

# --- runner ---
echec=""
for cas in $(declare -F | awk '{print $3}' | grep '^cas_'); do
  if ( set -e; "$cas" ); then echo "ok   $cas"; else echo "FAIL $cas"; echec="$echec $cas"; fi
done
if [ -n "$echec" ]; then echo "failed:$echec" >&2; exit 1; fi
echo "OK: all cases pass"
