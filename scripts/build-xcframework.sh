#!/usr/bin/env bash
# BarkingFFI.xcframework and its Swift bindings (spec iOS foundations §3.4, §7).
# Usage: scripts/build-xcframework.sh [--release] [--sim-only]
#   --release   profile release-apple (panics unwind), otherwise dev
#   --sim-only  aarch64-apple-ios-sim only (CI)
# Output (not versioned): target/apple/BarkingFFI.xcframework, target/apple/swift/barking_ffi.swift
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "error: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "macOS only"

profile="dev"
targets=(aarch64-apple-ios aarch64-apple-ios-sim)
while [ $# -gt 0 ]; do
  case "$1" in
    --release) profile="release-apple"; shift ;;
    --sim-only) targets=(aarch64-apple-ios-sim); shift ;;
    -h|--help) sed -n 2,6p "$0"; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
# Cargo puts the dev profile in target/<triple>/debug.
outdir="$profile"; [ "$profile" = "dev" ] && outdir="debug"

# Same floor as apple/project.yml, for rustc and for the C code (SQLCipher,
# OpenSSL) built by the cc crate: otherwise the SDK default applies.
export IPHONEOS_DEPLOYMENT_TARGET=26.0

cd "$root"
out="$root/target/apple"
rustup target add "${targets[@]}" >/dev/null

libs=()
for t in "${targets[@]}"; do
  cargo build --locked -p barking-ffi --lib --target "$t" --profile "$profile"
  libs+=("$root/target/$t/$outdir/libbarking_ffi.a")
done

# Bindings from the library's metadata (same for every slice).
rm -rf "$out/swift"
cargo run --locked -q -p barking-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --library "${libs[0]}" --language swift --out-dir "$out/swift"

# One headers directory per slice: the C header and a module map named
# module.modulemap, as Xcode expects inside an XCFramework.
args=()
for i in "${!libs[@]}"; do
  headers="$out/headers/${targets[$i]}"
  rm -rf "$headers" && mkdir -p "$headers"
  cp "$out/swift/barking_ffiFFI.h" "$headers/"
  cp "$out/swift/barking_ffiFFI.modulemap" "$headers/module.modulemap"
  args+=(-library "${libs[$i]}" -headers "$headers")
done

rm -rf "$out/BarkingFFI.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/BarkingFFI.xcframework" >/dev/null
# Read by the Bench and Release builds, which refuse a dev library (spec §6:
# measurements on optimized Rust only).
echo "$profile" > "$out/PROFILE"
echo "$out/BarkingFFI.xcframework"
