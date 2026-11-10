#!/usr/bin/env bash
# Decides whether a push to main must run the full CI.
# The main ruleset requires up-to-date branches and squash merges, so a merged tree is exactly the
# tree its pull request tested. The CI is skipped (run=false) only when that is proven:
#   - the event is a push;
#   - the GitHub API lists exactly one merged pull request for the commit;
#   - the commit tree equals the tree of that pull request's head;
#   - the last pull_request run of the ci workflow on that head concluded with success.
# Any other situation, and any failing command, means run=true.
# Input: EVENT, SHA, GITHUB_REPOSITORY, GH_TOKEN (environment); run from a full clone.
# Output: one line on stdout, run=true or run=false; the reason on stderr. Always exits 0: a job
# that needs the gate would be skipped if the gate failed.
set -euo pipefail

# Returns 0 only when the skip is proven; otherwise says why on stderr and returns 1.
# errexit is off inside a function called from a condition: every command is checked explicitly.
preuve() {
  local numeros nombre pr tete arbre_pr arbre_sha conclusion

  [ "${EVENT-}" = "push" ] || { echo "event is '${EVENT-}', not a push" >&2; return 1; }
  [ -n "${SHA-}" ] && [ -n "${GITHUB_REPOSITORY-}" ] \
    || { echo "SHA or GITHUB_REPOSITORY is not set" >&2; return 1; }

  numeros="$(gh api "repos/$GITHUB_REPOSITORY/commits/$SHA/pulls" \
    --jq ".[] | select(.merged_at != null and .merge_commit_sha == \"$SHA\") | .number")" \
    || { echo "could not list the pull requests of $SHA" >&2; return 1; }
  nombre="$(printf '%s' "$numeros" | grep -c . || true)"
  [ "$nombre" = "1" ] || { echo "$nombre merged pull requests for $SHA, expected exactly 1" >&2; return 1; }
  pr="$(printf '%s' "$numeros" | grep .)"
  case "$pr" in *[!0-9]*) echo "unexpected pull request number: $pr" >&2; return 1 ;; esac

  git fetch --quiet --no-tags origin "refs/pull/$pr/head" >/dev/null 2>&1 \
    || { echo "could not fetch refs/pull/$pr/head" >&2; return 1; }
  tete="$(git rev-parse --verify "FETCH_HEAD^{commit}" 2>/dev/null)" \
    || { echo "could not resolve the head of pull request $pr" >&2; return 1; }
  arbre_pr="$(git rev-parse --verify "$tete^{tree}" 2>/dev/null)" \
    || { echo "could not read the tree of $tete" >&2; return 1; }
  arbre_sha="$(git rev-parse --verify "$SHA^{tree}" 2>/dev/null)" \
    || { echo "could not read the tree of $SHA" >&2; return 1; }
  [ "$arbre_pr" = "$arbre_sha" ] \
    || { echo "tree of $SHA differs from the tree of pull request $pr ($tete)" >&2; return 1; }

  conclusion="$(gh run list --repo "$GITHUB_REPOSITORY" --workflow ci.yml --commit "$tete" \
    --event pull_request --limit 1 --json conclusion --jq '.[0].conclusion // ""')" \
    || { echo "could not list the ci runs of $tete" >&2; return 1; }
  [ "$conclusion" = "success" ] \
    || { echo "last ci run of $tete: '${conclusion:-none}', not success" >&2; return 1; }

  echo "tree of $SHA already validated by pull request $pr ($tete): CI skipped" >&2
}

if preuve; then
  echo "run=false"
else
  echo "run=true"
fi
