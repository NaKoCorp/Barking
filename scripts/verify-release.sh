#!/usr/bin/env bash
# Verifying a release: checksums, provenance attestations, and optional local rebuild.
# Usage: scripts/verify-release.sh <version> [--from-dir <dir>] [--rebuild]
#           [--rebuilt-dir <dir>] [--repo <owner/repo>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() {
  echo "Usage: $0 <version> [--from-dir <dir>] [--rebuild] [--rebuilt-dir <dir>] [--repo <owner/repo>]"
}

version=""; from_dir=""; rebuild=0; rebuilt_dir=""; repo_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir expects a value";       from_dir="$2";    shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir expects a value";    rebuilt_dir="$2"; rebuild=1; shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo expects a value";           repo_arg="$2";    shift 2 ;;
    --rebuild) rebuild=1; shift ;;
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

valider_version "$version"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fichier_xcode_du_tag "$racine" "$version" "$tmp"
# All steps work on this single copy (the original directory is not re-read).
dir="$tmp/assets"; mkdir -p "$dir"

resoudre_repo "$repo_arg" "$racine"
if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "directory not found: $from_dir"
  for f in "$from_dir"/SHA256SUMS "$from_dir"/barking-cli-* "$from_dir"/barking-node-* "$from_dir"/barking-push-*; do
    [ -e "$f" ] || continue
    cp "$f" "$dir/"
  done
else
  command -v gh >/dev/null 2>&1 || erreur "gh is required to download release v$version"
  exiger_repo
  gh release download "v$version" -R "$REPO" --dir "$dir" \
    --pattern 'SHA256SUMS' --pattern 'barking-cli-*' --pattern 'barking-node-*' --pattern 'barking-push-*' \
    || erreur "downloading the assets of v$version failed"
fi

# Step 1: binary checksums, with no missing or extra file.
etape "1/3 binary checksums…" "checksums"
controler_somme_dir "$dir" "$version"

# Step 2: GitHub provenance attestations, bound to the release workflow, the tag and, when the
# tag exists in this clone, the commit it points to.
etape "2/3 provenance attestations…" "attestations"
exiger_repo
command -v gh >/dev/null 2>&1 || erreur "gh is required to verify attestations"
commit_local="$(git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" 2>/dev/null || true)"
digest_opt=""
if [ -n "$commit_local" ]; then
  digest_opt="--source-digest"
else
  echo "notice: tag v$version is absent from this clone; the attested commit could not be compared locally (git fetch --tags)" >&2
fi
for nom in $NOMS_LISTES; do
  # shellcheck disable=SC2086  # digest_opt is empty or a single flag
  gh attestation verify "$dir/$nom" -R "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-ref "refs/tags/v$version" ${digest_opt:+$digest_opt "$commit_local"} \
    --deny-self-hosted-runners >/dev/null 2>"$tmp/err" \
    || erreur "attestation rejected for $nom: $(cat "$tmp/err")"
done

# Step 3: local rebuild (optional).
if [ "$rebuild" -eq 1 ]; then
  etape "3/3 local rebuild…" "rebuild"
  if [ -n "$rebuilt_dir" ]; then
    [ -d "$rebuilt_dir" ] || erreur "directory not found: $rebuilt_dir"
    rebuilt="$(cd "$rebuilt_dir" && pwd)"
  else
    rebuilt="$tmp/rebuilt"
    recompiler_localement "$racine" "$version" "$rebuilt" "$tmp"
  fi
  comparer_reconstruction "$dir" "$rebuilt" "$version"
else
  etape "3/3 rebuild: not requested (--rebuild)" "rebuild"
fi

echo "Version $version verified ✓"
