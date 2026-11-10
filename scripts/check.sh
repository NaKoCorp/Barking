#!/usr/bin/env bash
# Usage: scripts/check.sh [--full]
#   (no option)  fmt, clippy, fast nextest profile (default), doc tests.
#   --full       the same with the slow nextest profile (every binary,
#                including the network tests); run before pushing and in CI.
set -euo pipefail
cd "$(dirname "$0")/.."
profile=default
case "${1-}" in
  "") ;;
  --full) profile=slow ;;
  *)
    echo "usage: scripts/check.sh [--full]" >&2
    exit 2
    ;;
esac
[ "$#" -le 1 ] || {
  echo "usage: scripts/check.sh [--full]" >&2
  exit 2
}
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
# cargo-nextest runs the test binaries in parallel (cargo test runs them one
# after the other); without it, fall back to the complete cargo test.
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run --workspace --locked --profile "$profile"
  cargo test --workspace --locked --doc
else
  cargo test --workspace --locked
fi
# Deployment files: deploy/compose.yaml resolves for both profiles (needs
# docker compose, no daemon).
if docker compose version >/dev/null 2>&1; then
  scripts/tests/compose-config.sh
fi
