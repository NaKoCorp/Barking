#!/usr/bin/env bash
# Security checks of a public repository: the same ones in the git hooks
# (.githooks/) and in the CI job `security`.
# Usage: scripts/security-check.sh --staged          (pre-commit: what is about to be committed)
#        scripts/security-check.sh --range <a>..<b>  (pre-push, pull request: these commits)
#        scripts/security-check.sh --all             (whole history and tree)
#
# Checks:
#   files      no credential file (APNs key, certificates, provisioning, .env…)
#   gitleaks   no secret in the commits (or the staged diff)
#   scripts    shell scripts pass shellcheck
#   (not with --staged)
#   trivy      vulnerable dependencies, secrets, misconfigurations: HIGH and CRITICAL fail (trivy.yaml)
#   cargo-deny RustSec advisories, AGPL-compatible licenses, crates.io only (deny.toml)
#   zizmor, actionlint  GitHub Actions workflows
# A missing tool fails the check, with how to install it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage() { sed -n 4,6p "$0" | sed 's/^# //'; }
fail() { echo "error: $*" >&2; exit 1; }

mode=""
range=""
case "${1:-}" in
  --staged) mode=staged ;;
  --range) [ $# -ge 2 ] || { usage; exit 2; }; mode=range; range="$2" ;;
  --all) mode=all ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is missing (macOS: brew install $2)"
}

status=0
step() { echo "── $*"; }
bad() { echo "✗ $*" >&2; status=1; }

# Files that hold credentials: never committed, whatever their content.
forbidden='\.(p8|p12|pfx|mobileprovision|keystore|jks|key|pem)$|(^|/)\.env($|\.)|(^|/)id_(rsa|ed25519|ecdsa)($|\.)|(^|/)\.netrc$|^apple/Local\.xcconfig$'

case "$mode" in
  staged) files="$(git diff --cached --name-only --diff-filter=ACMR)" ;;
  range) files="$(git diff --name-only --diff-filter=ACMR "$range")" ;;
  all) files="$(git ls-files)" ;;
esac

step "files: no credential file"
if found="$(printf '%s\n' "$files" | grep -E "$forbidden")"; then
  bad "credential files: $(echo "$found" | tr '\n' ' ')(move them out of the repository)"
fi

step "gitleaks: no secret"
need gitleaks gitleaks
case "$mode" in
  staged) gitleaks git --pre-commit --staged --redact --no-banner --log-level warn . || bad "gitleaks found a secret in the staged changes" ;;
  range) gitleaks git --log-opts="$range" --redact --no-banner --log-level warn . || bad "gitleaks found a secret in $range" ;;
  all) gitleaks git --redact --no-banner --log-level warn . || bad "gitleaks found a secret in the history" ;;
esac

step "shellcheck: shell scripts"
need shellcheck shellcheck
scripts="$(printf '%s\n' "$files" | grep -E '(\.sh$|^\.githooks/)' || true)"
if [ -n "$scripts" ]; then
  # shellcheck disable=SC2086 # one path per word, none with spaces
  shellcheck --severity=warning $scripts || bad "shellcheck"
fi

if [ "$mode" != staged ]; then
  step "trivy: HIGH and CRITICAL findings"
  need trivy trivy
  trivy fs --config trivy.yaml --quiet . >/dev/null || {
    trivy fs --config trivy.yaml --quiet --format table . >&2 || true
    bad "trivy"
  }

  step "cargo-deny: advisories, licenses, bans, sources"
  need cargo-deny cargo-deny
  if ! report="$(cargo deny --locked check --hide-inclusion-graph 2>&1)"; then
    echo "$report" >&2
    bad "cargo-deny"
  fi

  step "zizmor, actionlint: workflows"
  need zizmor zizmor
  need actionlint actionlint
  zizmor --quiet --format plain .github/workflows/ || bad "zizmor"
  # The runner labels of this repository are newer than actionlint's list.
  # actionlint does not know the self-repository syntax ($/path, supported by GitHub); remove the
  # second -ignore once it does.
  actionlint -ignore 'label ".*" is unknown' \
    -ignore '"\$/[^"]*" (at "uses" is not following the format|in invalid format because ref is missing)' \
    || bad "actionlint"
fi

if [ "$status" -ne 0 ]; then
  echo "security checks failed" >&2
  exit 1
fi
echo "security checks passed"
