#!/usr/bin/env bash
# Contributor License Agreement check for one pull request (CLA.md).
# Every run does the same three things, so a run that is cancelled or fails loses nothing:
#   1. records, in signatures/cla.json on the cla-signatures branch, the authors of a signing
#      comment on this pull request who are not recorded yet;
#   2. reports the commit status "cla-signed" on the head of the pull request: success when every
#      commit author and the pull request author have signed, failure otherwise;
#   3. keeps one comment on the pull request that says who still has to sign.
# People are matched by GitHub account id, which survives a rename. Bots and the accounts listed
# in CLA_EXEMPT sign nothing. A commit whose author email is not linked to a GitHub account
# fails the check: its author cannot be identified.
# Everything read from the pull request (comments, logins) is data: it only goes through jq
# arguments, never through the shell.
# Input: GH_REPO (owner/name), PR (number), GH_TOKEN (environment).
#   CLA_EXEMPT  comma-separated logins that need no signature (default: HoaMi)
#   DRY_RUN=1   read only: prints what would be written instead of writing it
# Exits 0 when the status was reported, whatever it says; non-zero on an operational failure.
set -euo pipefail

: "${GH_REPO:?GH_REPO is not set}" "${PR:?PR is not set}"
case "$PR" in '' | *[!0-9]*) echo "unexpected pull request number: $PR" >&2; exit 2 ;; esac

PHRASE='I have read the CLA Document and I hereby sign the CLA'
CLA_VERSION='1.0'
CLA_URL="https://github.com/$GH_REPO/blob/main/CLA.md"
BRANCH='cla-signatures'
FILE='signatures/cla.json'
CONTEXT='cla-signed'
MARKER='<!-- cla-check -->'
BOT='github-actions[bot]'
exempt="${CLA_EXEMPT-HoaMi}"
dry="${DRY_RUN-}"

# gh api, with the HTTP error on stderr and a non-zero exit on failure.
api() { gh api "$@"; }

# Writes its JSON stdin to the API, or prints the call in a dry run.
send() {
  local method="$1" path="$2"
  if [ -n "$dry" ]; then
    echo "dry run: $method $path" >&2
    cat >/dev/null
  else
    api --method "$method" "$path" --input - >/dev/null
  fi
}

# Sets signatures (the JSON document) and file_sha (empty when the file does not exist yet).
# A missing file or branch is an empty list; any other failure stops the script, so that a
# network error is never read as "nobody has signed".
load_signatures() {
  local reply
  if reply="$(api "repos/$GH_REPO/contents/$FILE?ref=$BRANCH" 2>&1)"; then
    file_sha="$(jq -r '.sha' <<<"$reply")"
    signatures="$(jq -r '.content' <<<"$reply" | base64 --decode)"
    jq -e '.signatures | type == "array"' <<<"$signatures" >/dev/null \
      || { echo "$FILE on $BRANCH is not a signature list" >&2; exit 1; }
  elif grep -q 'HTTP 404' <<<"$reply"; then
    file_sha=''
    signatures='{"signatures":[]}'
  else
    echo "could not read $FILE on $BRANCH: $reply" >&2
    exit 1
  fi
}

# Commits the signature document given as $1, with the commit message $2. Creates the branch,
# without history, when it does not exist yet.
write_signatures() {
  local document="$1" message="$2" tree commit
  if api "repos/$GH_REPO/git/ref/heads/$BRANCH" >/dev/null 2>&1; then
    jq -n --arg m "$message" --arg b "$BRANCH" --arg s "$file_sha" \
      --arg c "$(printf '%s\n' "$document" | base64 | tr -d '\n')" \
      '{message: $m, branch: $b, content: $c} + (if $s == "" then {} else {sha: $s} end)' \
      | send PUT "repos/$GH_REPO/contents/$FILE"
  elif [ -n "$dry" ]; then
    echo "dry run: create the $BRANCH branch with $FILE" >&2
  else
    tree="$(jq -n --arg p "$FILE" --arg c "$(printf '%s\n' "$document")" \
      '{tree: [{path: $p, mode: "100644", type: "blob", content: $c}]}' \
      | api --method POST "repos/$GH_REPO/git/trees" --input - --jq '.sha')"
    commit="$(jq -n --arg m "$message" --arg t "$tree" '{message: $m, tree: $t, parents: []}' \
      | api --method POST "repos/$GH_REPO/git/commits" --input - --jq '.sha')"
    jq -n --arg r "refs/heads/$BRANCH" --arg s "$commit" '{ref: $r, sha: $s}' \
      | send POST "repos/$GH_REPO/git/refs"
  fi
}

pull="$(api "repos/$GH_REPO/pulls/$PR")"
head_sha="$(jq -r '.head.sha' <<<"$pull")"

comments="$(api --paginate "repos/$GH_REPO/issues/$PR/comments" \
  --jq '.[] | {id, body, created_at, html_url, login: .user.login, uid: .user.id}' | jq -s '.')"

# 1. Record the new signatures. Another run may write the file at the same time: the write then
# fails on a stale sha, and the whole step is redone from a fresh read.
attempt=0
while :; do
  load_signatures
  new="$(jq -n --argjson comments "$comments" --argjson known "$signatures" \
    --arg phrase "$PHRASE" --arg version "$CLA_VERSION" --argjson pr "$PR" '
      ($known.signatures | map(.id)) as $have
      | [ $comments[]
          | select((.body // "" | gsub("^\\s+|\\s+$"; "")) == $phrase)
          | select(.uid as $u | $have | index($u) | not)
          | {login, id: .uid, pull_request: $pr, comment_id: .id, comment_url: .html_url,
             signed_at: .created_at, cla_version: $version} ]
      | unique_by(.id)')"
  [ "$(jq 'length' <<<"$new")" -gt 0 ] || break
  signatures="$(jq --argjson new "$new" '.signatures += $new' <<<"$signatures")"
  message="chore(cla): record the signature of $(jq -r 'map(.login) | join(", ")' <<<"$new")"
  if write_signatures "$signatures" "$message"; then
    echo "recorded: $(jq -r 'map(.login) | join(", ")' <<<"$new")" >&2
    break
  fi
  attempt=$((attempt + 1))
  [ "$attempt" -lt 3 ] || { echo "could not write $FILE on $BRANCH" >&2; exit 1; }
  sleep 2
done

# 2. Who has to sign: the author of every commit and the author of the pull request.
commits="$(api --paginate "repos/$GH_REPO/pulls/$PR/commits" \
  --jq '.[] | {sha, login: .author.login, id: .author.id, type: .author.type}' | jq -s '.')"
verdict="$(jq -n --argjson commits "$commits" --argjson pull "$pull" \
  --argjson known "$signatures" --arg exempt "$exempt" '
    ($exempt | split(",") | map(gsub("^\\s+|\\s+$"; "") | ascii_downcase)) as $free
    | ($known.signatures | map(.id)) as $have
    | { unlinked: [ $commits[] | select(.id == null) | .sha[0:7] ],
        missing: [ ($commits[] | select(.id != null)),
                   ($pull.user | {login, id, type}) ]
                 | unique_by(.id)
                 | map(select(.type != "Bot"))
                 | map(select(.login | ascii_downcase | IN($free[]) | not))
                 | map(select(.id as $i | $have | index($i) | not))
                 | map(.login) }')"
missing="$(jq -r '.missing | map("@" + .) | join(", ")' <<<"$verdict")"
unlinked="$(jq -r '.unlinked | map("`" + . + "`") | join(", ")' <<<"$verdict")"

if [ -z "$missing" ] && [ -z "$unlinked" ]; then
  state='success'
  description='Every author has signed the CLA'
  body="$MARKER
Every author of this pull request has signed the [Contributor License Agreement]($CLA_URL). Thank you."
else
  state='failure'
  description='The CLA is not signed by every author'
  body="$MARKER
Thank you for your contribution. Before it can be merged, each of its authors signs the [Contributor License Agreement]($CLA_URL), once for all their contributions.

To sign, post a comment on this pull request with exactly this text:

> $PHRASE"
  [ -z "$missing" ] || body="$body

Still to sign: $missing"
  [ -z "$unlinked" ] || body="$body

The author of these commits cannot be identified, because their email address is not linked to a GitHub account: $unlinked. Add the address to your GitHub account, or rewrite the commits with an address that is linked."
fi
echo "$CONTEXT: $state (missing: ${missing:-none}; unlinked commits: ${unlinked:-none})" >&2

jq -n --arg s "$state" --arg c "$CONTEXT" --arg d "$description" --arg u "$CLA_URL" \
  '{state: $s, context: $c, description: $d, target_url: $u}' \
  | send POST "repos/$GH_REPO/statuses/$head_sha"

# 3. One comment, written by this workflow and recognised by its marker and its author. A pull
# request where nobody ever had to sign gets no comment at all.
previous="$(jq -r --arg marker "$MARKER" --arg bot "$BOT" \
  '[ .[] | select(.login == $bot and (.body // "" | startswith($marker))) ] | last // empty | .id' \
  <<<"$comments")"
previous_body="$(jq -r --argjson id "${previous:-0}" '.[] | select(.id == $id) | .body' <<<"$comments")"
if [ -n "$previous" ]; then
  [ "$previous_body" = "$body" ] \
    || jq -n --arg b "$body" '{body: $b}' | send PATCH "repos/$GH_REPO/issues/comments/$previous"
elif [ "$state" = failure ]; then
  jq -n --arg b "$body" '{body: $b}' | send POST "repos/$GH_REPO/issues/$PR/comments"
fi
[ -z "$dry" ] || printf '%s\n' "--- comment ---" "$body" >&2
