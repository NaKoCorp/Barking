#!/usr/bin/env bash
# Links the versioned hooks of .githooks/ into .git/hooks (pre-commit,
# pre-push). Other hooks there (graphify's post-* hooks) are left alone, which
# is why core.hooksPath is not used. Tools: brew install gitleaks trivy
# cargo-deny zizmor actionlint shellcheck
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hooks="$(git -C "$root" rev-parse --git-path hooks)"
case "$hooks" in /*) ;; *) hooks="$root/$hooks" ;; esac
mkdir -p "$hooks"
for h in pre-commit pre-push; do
  target="$hooks/$h"
  if [ -e "$target" ] && [ ! -L "$target" ]; then
    echo "error: $target exists and is not ours: move it, then run again" >&2
    exit 1
  fi
  ln -sf "$root/.githooks/$h" "$target"
  echo "installed $h"
done
