#!/usr/bin/env bash
# Checks that a pull request title follows Conventional Commits.
# Pull requests are squash-merged: the title becomes the commit message that release-please reads
# to compute the next version and the changelog. A malformed title would drop a change from it.
# Input: PR_TITLE (environment). Exit 0 if valid; otherwise exit 1 with the reason on stderr.
set -euo pipefail

types="feat fix perf refactor docs test ci build chore revert"
format='<type>(<scope>)!: <description>   (scope and "!" are optional)'
regex='^(feat|fix|perf|refactor|docs|test|ci|build|chore|revert)(\([a-z0-9][a-z0-9._/-]*\))?!?: [^ ].*$'

fail() {
  {
    echo "Invalid pull request title: $1"
    echo "Received: ${PR_TITLE-}"
    echo "Expected: $format"
    echo "Types: $types"
    echo "Scope: lowercase letters, digits, '.', '_', '/', '-'. One line, no trailing space."
  } >&2
  exit 1
}

if [ -z "${PR_TITLE+set}" ]; then
  echo "PR_TITLE is not set" >&2
  exit 1
fi

case "$PR_TITLE" in
  *$'\n'* | *$'\r'*) fail "the title must be a single line" ;;
  *[[:space:]]) fail "the title must not end with whitespace" ;;
esac

[[ $PR_TITLE =~ $regex ]] || fail "the title does not match the expected format"
