#!/usr/bin/env bash
# Signing a release (maintainer): rebuilds, compares, then signs SHA256SUMS with minisign.
# The signed comment is « barking v<version> commit <commit of the local tag> ».
# Usage: scripts/sign-release.sh <version> --seckey <file> [--from-dir <dir>] [--rebuilt-dir <dir>]
#           [--pubkey <file>] [--repo <owner/repo>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() { echo "Usage: $0 <version> --seckey <file> [--from-dir <dir>] [--rebuilt-dir <dir>] [--pubkey <file>] [--repo <owner/repo>]"; }

version=""; from_dir=""; seckey=""; rebuilt_dir=""; pubkey="$racine/keys/maintainer.pub"; repo_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir expects a value";       from_dir="$2";    shift 2 ;;
    --seckey)      [ $# -ge 2 ] || erreur "--seckey expects a value";         seckey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir expects a value";    rebuilt_dir="$2"; shift 2 ;;
    --pubkey)      [ $# -ge 2 ] || erreur "--pubkey expects a value";         pubkey="$2";      shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo expects a value";           repo_arg="$2";    shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) erreur "unknown option: $1" ;;
    *) [ -z "$version" ] || erreur "version already given: $version"; version="$1"; shift ;;
  esac
done
[ -n "$version" ] || { usage >&2; exit 1; }
valider_version "$version"
[ -n "$seckey" ] || erreur "--seckey is required (maintainer's minisign secret key)"
[ -f "$seckey" ] || erreur "secret key not found: $seckey"
command -v minisign >/dev/null 2>&1 || erreur "minisign is required"
# The produced signature is checked before any upload: the public key must therefore be valid.
exiger_cle_publique "$pubkey"

# The local tag's commit is bound to the signature (signed comment): it must be known here.
commit="$(git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" 2>/dev/null || true)"
[[ $commit =~ ^[0-9a-f]{40}$ ]] \
  || erreur "tag v$version not found in this clone: fetch it (git fetch --tags) before signing"
echo "commit of tag v$version: $commit" >&2

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-sign.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fichier_xcode_du_tag "$racine" "$version" "$tmp"
# Everything is checked, then signed, on this single copy.
dir="$tmp/assets"; mkdir -p "$dir"

if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "directory not found: $from_dir"
  [ -f "$from_dir/SHA256SUMS" ] || erreur "SHA256SUMS missing from $from_dir"
  cp "$from_dir/SHA256SUMS" "$dir/"
  for f in "$from_dir"/barking-cli-* "$from_dir"/barking-node-*; do
    [ -e "$f" ] || continue
    cp "$f" "$dir/"
  done
else
  command -v gh >/dev/null 2>&1 || erreur "gh is required to fetch the draft's assets"
  resoudre_repo "$repo_arg" "$racine"; exiger_repo
  gh release download "v$version" -R "$REPO" --dir "$dir" --pattern 'SHA256SUMS' --pattern 'barking-cli-*' --pattern 'barking-node-*' \
    || erreur "downloading the assets of v$version failed"
fi

# 1. Draft consistency: listed files present, none extra, exact checksums.
controler_somme_dir "$dir" "$version"

# 2. Local rebuild and comparison.
if [ -n "$rebuilt_dir" ]; then
  [ -d "$rebuilt_dir" ] || erreur "directory not found: $rebuilt_dir"
  rebuilt="$(cd "$rebuilt_dir" && pwd)"
else
  rebuilt="$tmp/rebuilt"
  recompiler_localement "$racine" "$version" "$rebuilt" "$tmp"
fi
comparer_reconstruction "$dir" "$rebuilt" "$version"

# 3. Signature (minisign's output stays visible: password prompt of a real key),
#    checked with the public key before any move or upload.
sig="$tmp/SHA256SUMS.minisig"
minisign -S -m "$dir/SHA256SUMS" -s "$seckey" -t "barking v$version commit $commit" -x "$sig" >&2 \
  || erreur "signing failed"
[ -s "$sig" ] || erreur "empty signature"
minisign -V -m "$dir/SHA256SUMS" -x "$sig" -p "$pubkey" >/dev/null 2>&1 \
  || erreur "the produced signature does not match the public key $pubkey (wrong secret key?): nothing is published"

if [ -n "$from_dir" ]; then
  cp "$sig" "$from_dir/SHA256SUMS.minisig.tmp"
  mv "$from_dir/SHA256SUMS.minisig.tmp" "$from_dir/SHA256SUMS.minisig"
  echo "Version $version signed: $from_dir/SHA256SUMS.minisig"
else
  gh release upload "v$version" "$sig" -R "$REPO" --clobber \
    || erreur "uploading SHA256SUMS.minisig failed"
  gh release edit "v$version" -R "$REPO" --draft=false \
    || erreur "publishing the draft failed (SHA256SUMS.minisig was uploaded)"
  echo "Version $version signed and published."
fi
