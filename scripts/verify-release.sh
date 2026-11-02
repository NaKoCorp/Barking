#!/usr/bin/env bash
# Verifying a release: signature, checksums, attestations, and optional rebuild.
# Usage: scripts/verify-release.sh <version> [--from-dir <dir>] [--pubkey <file>] [--rebuild]
#           [--rebuilt-dir <dir>] [--skip-attestation] [--repo <owner/repo>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() {
  echo "Usage: $0 <version> [--from-dir <dir>] [--pubkey <file>] [--rebuild] [--rebuilt-dir <dir>] [--skip-attestation] [--repo <owner/repo>]"
}

version=""; from_dir=""; pubkey="$racine/keys/maintainer.pub"; rebuild=0; rebuilt_dir=""
skip_att=0; repo_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir expects a value";       from_dir="$2";    shift 2 ;;
    --pubkey)      [ $# -ge 2 ] || erreur "--pubkey expects a value";         pubkey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir expects a value";    rebuilt_dir="$2"; rebuild=1; shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo expects a value";           repo_arg="$2";    shift 2 ;;
    --rebuild) rebuild=1; shift ;;
    --skip-attestation) skip_att=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) erreur "unknown option: $1" ;;
    *) [ -z "$version" ] || erreur "version already given: $version"; version="$1"; shift ;;
  esac
done
[ -n "$version" ] || { usage >&2; exit 1; }

# Every error is reported with the current step and exits with code 1.
ETAPE="preparation"
erreur() { echo "FAILURE at step « $ETAPE »: $*" >&2; exit 1; }
etape() { ETAPE="$2"; echo "$1" >&2; }

command -v minisign >/dev/null 2>&1 || erreur "minisign is required"

valider_version "$version"

# Public key: never empty nor without a key line (the maintainer may not have published it yet).
exiger_cle_publique "$pubkey"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fichier_xcode_du_tag "$racine" "$version" "$tmp"
# All steps work on this single copy (the original directory is not re-read).
dir="$tmp/assets"; mkdir -p "$dir"

resoudre_repo "$repo_arg" "$racine"
if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "directory not found: $from_dir"
  for f in "$from_dir"/SHA256SUMS "$from_dir"/SHA256SUMS.minisig "$from_dir"/barking-cli-* "$from_dir"/barking-node-* "$from_dir"/barking-push-*; do
    [ -e "$f" ] || continue
    cp "$f" "$dir/"
  done
else
  command -v gh >/dev/null 2>&1 || erreur "gh is required to download release v$version"
  exiger_repo
  gh release download "v$version" -R "$REPO" --dir "$dir" \
    --pattern 'SHA256SUMS' --pattern 'SHA256SUMS.minisig' --pattern 'barking-cli-*' --pattern 'barking-node-*' --pattern 'barking-push-*' \
    || erreur "downloading the assets of v$version failed"
fi

# Step 1: minisign signature of SHA256SUMS.
etape "1/4 signature of SHA256SUMS…" "signature"
[ -f "$dir/SHA256SUMS" ] || erreur "SHA256SUMS missing from $dir"
[ -f "$dir/SHA256SUMS.minisig" ] || erreur "SHA256SUMS.minisig missing from $dir"
sortie_min="$(minisign -V -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" -p "$pubkey" 2>&1)" \
  || erreur "invalid signature or key different from $pubkey: $sortie_min"
# Expected signed comment: « barking v<version> commit <40 hex> » (version compared literally).
commentaire="$(printf '%s\n' "$sortie_min" | sed -n 's/^Trusted comment: //p' | head -n1)"
prefixe="barking v$version commit "
commit_signe=""
case "$commentaire" in "$prefixe"*) commit_signe="${commentaire#"$prefixe"}" ;; esac
[[ $commit_signe =~ ^[0-9a-f]{40}$ ]] \
  || erreur "the signed comment « $commentaire » is not « barking v$version commit <commit> » (signature of another version?)"
echo "commit signed by the maintainer: $commit_signe" >&2
commit_local="$(git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" 2>/dev/null || true)"
if [ -n "$commit_local" ]; then
  [ "$commit_local" = "$commit_signe" ] \
    || erreur "tag v$version in this clone points to commit $commit_local, but the maintainer signed commit $commit_signe (tag moved?)"
  echo "commit of tag v$version in this clone: identical" >&2
else
  echo "notice: tag v$version is absent from this clone; the signed commit could not be compared locally (git fetch --tags)" >&2
fi

# Step 2: binary checksums, with no missing or extra file.
etape "2/4 binary checksums…" "checksums"
controler_somme_dir "$dir" "$version"

# Step 3: GitHub provenance attestations.
if [ "$skip_att" -eq 1 ]; then
  etape "3/4 attestations: skipped (--skip-attestation)" "attestations"
else
  etape "3/4 provenance attestations…" "attestations"
  exiger_repo
  command -v gh >/dev/null 2>&1 || erreur "gh is required to verify attestations (or --skip-attestation)"
  for nom in $NOMS_LISTES; do
    gh attestation verify "$dir/$nom" -R "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release.yml" \
      --source-ref "refs/tags/v$version" --deny-self-hosted-runners >/dev/null 2>"$tmp/err" \
      || erreur "attestation rejected for $nom: $(cat "$tmp/err")"
  done
fi

# Step 4: local rebuild (optional).
if [ "$rebuild" -eq 1 ]; then
  etape "4/4 local rebuild…" "rebuild"
  if [ -n "$rebuilt_dir" ]; then
    [ -d "$rebuilt_dir" ] || erreur "directory not found: $rebuilt_dir"
    rebuilt="$(cd "$rebuilt_dir" && pwd)"
  else
    rebuilt="$tmp/rebuilt"
    recompiler_localement "$racine" "$version" "$rebuilt" "$tmp"
  fi
  comparer_reconstruction "$dir" "$rebuilt" "$version"
else
  etape "4/4 rebuild: not requested (--rebuild)" "rebuild"
fi

echo "Version $version verified ✓"
