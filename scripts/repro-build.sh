#!/usr/bin/env bash
# Reproducible build of barking-cli, barking-node and barking-push (spec §15).
# Usage: scripts/repro-build.sh [--target <triple>] [--ref <git-ref>] [--out <dir>] [--git-dir <repo>]
#
# The build environment (this script, docker/repro.Dockerfile, .xcode-version) is always the one from the
# directory containing this script. --git-dir designates the git repository from which to extract --ref: by default that same
# directory; release-lib.sh uses it to run the environment extracted from a tag on the real repository.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() { echo "Usage: $0 [--target <triple>] [--ref <git-ref>] [--out <dir>] [--git-dir <repo>]"; }

cible=""
ref="HEAD"
sortie="$racine/dist"
depot="$racine"

while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || erreur "--target expects a value"; cible="$2"; shift 2 ;;
    --ref)    [ $# -ge 2 ] || erreur "--ref expects a value";       ref="$2";   shift 2 ;;
    --out)    [ $# -ge 2 ] || erreur "--out expects a value";       sortie="$2"; shift 2 ;;
    --git-dir) [ $# -ge 2 ] || erreur "--git-dir expects a value"; depot="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) erreur "unknown option: $1" ;;
  esac
done

if [ -z "$cible" ]; then
  case "$(uname -m)" in
    x86_64|amd64)  cible="x86_64-unknown-linux-musl" ;;
    arm64|aarch64) cible="aarch64-unknown-linux-musl" ;;
    *) erreur "unsupported host architecture: $(uname -m)" ;;
  esac
fi

case "$cible" in
  x86_64-unknown-linux-musl)  plateforme="linux/amd64" ;;
  aarch64-unknown-linux-musl) plateforme="linux/arm64" ;;
  aarch64-apple-darwin)       plateforme="" ;;
  *) erreur "unsupported target: $cible" ;;
esac

git -C "$depot" rev-parse --verify --quiet "$ref^{commit}" >/dev/null \
  || erreur "git reference not found: $ref"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-repro.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Clean extraction of the reference: the working tree (possibly dirty) is never built.
src="$tmp/src"
mkdir -p "$src"
git -C "$depot" archive --format=tar "$ref" | tar -x -C "$src"

version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$src/crates/barking-cli/Cargo.toml" | head -n1)"
[ -n "$version" ] || erreur "version not found in crates/barking-cli/Cargo.toml"
version_node="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$src/crates/barking-node/Cargo.toml" | head -n1)"
[ -n "$version_node" ] || erreur "version not found in crates/barking-node/Cargo.toml"
version_push="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$src/crates/barking-push/Cargo.toml" | head -n1)"
[ -n "$version_push" ] || erreur "version not found in crates/barking-push/Cargo.toml"
[ "$version" = "$version_node" ] && [ "$version" = "$version_push" ] \
  || erreur "barking-cli ($version), barking-node ($version_node) and barking-push ($version_push) must have the same version: a published release carries all three binaries"
SOURCE_DATE_EPOCH="$(git -C "$depot" log -1 --format=%ct "$ref")"
export SOURCE_DATE_EPOCH

nom="barking-cli-${version}-${cible}"
nom_node="barking-node-${version}-${cible}"
nom_push="barking-push-${version}-${cible}"
# The node is built on its own (cargo build -p barking-node, a separate invocation from barking-cli's):
# libsqlite3-sys features are unified within a single build, and those of barking-cli (SQLCipher,
# OpenSSL) must not enter the node. This check fails if a SQLCipher or OpenSSL feature
# appears in the node's dependency tree.
# shellcheck disable=SC2016  # the script is interpreted by the bash of the container or the host, not here
controle_node='
  arbre="$(cargo tree --locked -p barking-node -e normal,features --target "$TARGET")" || exit 1
  if printf "%s\n" "$arbre" | grep -qiE "openssl|sqlcipher"; then
    echo "error: barking-node depends on OpenSSL or SQLCipher:" >&2
    printf "%s\n" "$arbre" | grep -iE "openssl|sqlcipher" >&2
    exit 1
  fi'
# barking-push is likewise built on its own (cargo build -p barking-push) and must stay OpenSSL-free: it
# talks to APNs with rustls only. openssl-probe (pulled by rustls-native-certs) only locates the system
# certificate directories and links no OpenSSL code, so it is excluded from the match.
# shellcheck disable=SC2016  # the script is interpreted by the bash of the container or the host, not here
controle_push='
  arbre="$(cargo tree --locked -p barking-push -e normal,features --target "$TARGET")" || exit 1
  arbre="$(printf "%s\n" "$arbre" | grep -v "openssl-probe" || true)"
  if printf "%s\n" "$arbre" | grep -qiE "openssl|sqlcipher"; then
    echo "error: barking-push depends on OpenSSL or SQLCipher:" >&2
    printf "%s\n" "$arbre" | grep -iE "openssl|sqlcipher" >&2
    exit 1
  fi'
mkdir -p "$sortie"
sortie="$(cd "$sortie" && pwd)"

if [ "$cible" = "aarch64-apple-darwin" ]; then
  # Native build (macOS runner), without notarization.
  [ "$(uname -s)" = "Darwin" ] || erreur "target $cible is built on macOS"
  # The official pinned toolchain (rust-toolchain.toml, via rustup): Homebrew's rustc, even of the
  # same version, is not built the same way and does not reproduce the CI binary.
  command -v rustup >/dev/null 2>&1 \
    || erreur "rustup is required for target $cible: Homebrew's rustc is not the official toolchain and does not reproduce the CI binary. Install rustup (https://rustup.rs); rust-toolchain.toml pins the version."
  command -v cargo >/dev/null 2>&1 || erreur "cargo is required for target $cible"
  # Same Xcode and same SDK as the CI (.xcode-version), otherwise the binary differs.
  environnement_darwin_conforme "$racine/.xcode-version" \
    || erreur "$RAISON_DARWIN: the binary would not be identical to the CI's. Install Xcode $XCODE_ATTENDU and select it (sudo xcode-select -s /Applications/Xcode_$XCODE_ATTENDU.app)."
  {
    echo "Xcode: $(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
    echo "macOS SDK: $(xcrun --show-sdk-version) ($(xcrun --show-sdk-path))"
    echo "clang: $(xcrun clang --version | head -n1)"
  } >&2
  # FIXED paths: OpenSSL (vendored C code) records __FILE__, the output directory and the
  # CFLAGS verbatim in the binary. No random or machine-specific path must therefore appear.
  # The directory is created atomically (lock); if it already exists, another build is running (or crashed).
  fixe="/private/tmp/barking-repro-darwin"
  mkdir "$fixe" 2>/dev/null \
    || erreur "$fixe already exists: another macOS build is running, or a previous one was interrupted (delete this directory)"
  trap 'rm -rf "$tmp" "$fixe"' EXIT
  mv "$src" "$fixe/src"
  src="$fixe/src"
  export CARGO_HOME="$fixe/cargo"
  export RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$CARGO_HOME=/cargo"
  export CFLAGS="-ffile-prefix-map=$src=/build -ffile-prefix-map=$CARGO_HOME=/cargo"
  export CARGO_TARGET_DIR="$fixe/target"
  # No link timestamp in the executable.
  export ZERO_AR_DATE=1
  # Fixed deployment target: otherwise cc/rustc take the version of the machine's macOS or SDK.
  export MACOSX_DEPLOYMENT_TARGET="11.0"
  # rust-toolchain.toml (in the extracted sources) is authoritative for rustup.
  (
    cd "$src"
    echo "rustc: $(rustc --version)" >&2
    cargo build --release --locked -p barking-cli --target "$cible" || exit 1
    TARGET="$cible" bash -ec "$controle_node" || exit 1
    cargo build --release --locked -p barking-node --target "$cible" || exit 1
    TARGET="$cible" bash -ec "$controle_push" || exit 1
    cargo build --release --locked -p barking-push --target "$cible" || exit 1
  ) || erreur "build failed"
  cp "$CARGO_TARGET_DIR/$cible/release/barking" "$sortie/$nom"
  cp "$CARGO_TARGET_DIR/$cible/release/barking-node" "$sortie/$nom_node"
  cp "$CARGO_TARGET_DIR/$cible/release/barking-push" "$sortie/$nom_push"
else
  command -v docker >/dev/null 2>&1 || erreur "docker is required for target $cible"
  empreinte_df="$(sha256_de "$racine/docker/repro.Dockerfile")"
  image="barking-repro:${empreinte_df:0:16}-${plateforme#linux/}"
  docker build --platform "$plateforme" -q -f "$racine/docker/repro.Dockerfile" \
    -t "$image" "$racine/docker" >/dev/null || erreur "building the build image failed"
  # The cargo registry cache is just an accelerator: the binary does not depend on it
  # (--locked and Cargo.lock checksums).
  volume="barking-repro-cargo-${plateforme#linux/}-$(id -u)"
  # Only initialize ownership of this user's cache; no source or socket is mounted.
  docker run --rm --platform "$plateforme" --network=none --read-only \
    --cap-drop=ALL --cap-add=CHOWN --security-opt=no-new-privileges \
    -v "$volume:/cargo" "$image" chown "$(id -u):$(id -g)" /cargo \
    || erreur "initializing the Cargo cache failed"
  mkdir -p "$tmp/out"
  docker run --rm --platform "$plateforme" --read-only \
    --cap-drop=ALL --security-opt=no-new-privileges --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,exec \
    -v "$src:/build:ro" -v "$volume:/cargo" -v "$tmp/out:/out" \
    -e SOURCE_DATE_EPOCH -e "TARGET=$cible" -e "NOM=$nom" -e "NOM_NODE=$nom_node" -e "NOM_PUSH=$nom_push" \
    -e "CONTROLE_NODE=$controle_node" -e "CONTROLE_PUSH=$controle_push" \
    -e CARGO_HOME=/cargo -e HOME=/tmp \
    -w /build "$image" bash -ec '
      export RUSTFLAGS="--remap-path-prefix=/build=/build --remap-path-prefix=$CARGO_HOME=/cargo -C target-feature=+crt-static"
      export CFLAGS="-ffile-prefix-map=/build=/build -ffile-prefix-map=$CARGO_HOME=/cargo"
      export CARGO_TARGET_DIR=/tmp/target
      cargo build --release --locked -p barking-cli --target "$TARGET"
      bash -ec "$CONTROLE_NODE"
      cargo build --release --locked -p barking-node --target "$TARGET"
      bash -ec "$CONTROLE_PUSH"
      cargo build --release --locked -p barking-push --target "$TARGET"
      for bin in barking barking-node barking-push; do
        file="/tmp/target/$TARGET/release/$bin"
        if readelf -l "$file" | grep -q INTERP || readelf -d "$file" | grep -q NEEDED; then
          echo "error: $bin is not a static executable" >&2
          exit 1
        fi
      done
      cp "/tmp/target/$TARGET/release/barking" "/out/$NOM"
      cp "/tmp/target/$TARGET/release/barking-node" "/out/$NOM_NODE"
      cp "/tmp/target/$TARGET/release/barking-push" "/out/$NOM_PUSH"
    ' || erreur "build failed in the container"
  cp "$tmp/out/$nom" "$sortie/$nom"
  cp "$tmp/out/$nom_node" "$sortie/$nom_node"
  cp "$tmp/out/$nom_push" "$sortie/$nom_push"
fi

chmod 755 "$sortie/$nom" "$sortie/$nom_node" "$sortie/$nom_push"
somme="$(sha256_de "$sortie/$nom")"
somme_node="$(sha256_de "$sortie/$nom_node")"
somme_push="$(sha256_de "$sortie/$nom_push")"

# SHA256SUMS: one line per file, sha256sum format, sorted by name; the lines of these files are replaced.
sums="$sortie/SHA256SUMS"
{
  if [ -f "$sums" ]; then grep -v -F -e "  $nom" -e "  $nom_node" -e "  $nom_push" "$sums" || true; fi
  printf '%s  %s\n' "$somme" "$nom"
  printf '%s  %s\n' "$somme_node" "$nom_node"
  printf '%s  %s\n' "$somme_push" "$nom_push"
} | LC_ALL=C sort -k2 > "$tmp/SHA256SUMS"
cp "$tmp/SHA256SUMS" "$sums"

echo "$somme  $nom"
echo "$somme_node  $nom_node"
echo "$somme_push  $nom_push"
