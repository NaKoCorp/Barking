#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
# cargo-nextest runs the test binaries in parallel (cargo test runs them one
# after the other); without it, fall back to cargo test.
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run --workspace --locked
  cargo test --workspace --locked --doc
else
  cargo test --workspace --locked
fi
