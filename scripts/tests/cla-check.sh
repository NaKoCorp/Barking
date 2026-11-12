#!/usr/bin/env bash
# Host tests of scripts/cla-check.sh (bash and jq only, no network).
# gh is replaced by a fake that serves JSON fixtures for reads and logs every write.
# One case_* function per case; each runs in its own subshell with a fresh temporary directory.
# Compatible with bash 3.2 (macOS).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PHRASE='I have read the CLA Document and I hereby sign the CLA'
SIGNATURES='repos/o/r/contents/signatures/cla.json?ref=cla-signatures'
BRANCH_REF='repos/o/r/git/ref/heads/cla-signatures'

# Fixture file name of an API path.
key() { printf '%s' "$1" | tr '/?=' '___'; }

# fixture <api path> <json>: what a read of that path returns. A path without fixture is a 404.
fixture() { printf '%s' "$2" > "$d/fix/$(key "$1")"; }

# The signature file as the contents API returns it, holding the signatures given as a JSON list.
signature_file() {
  jq -n --arg c "$(jq -n --argjson s "$1" '{signatures: $s}' | base64 | tr -d '\n')" \
    '{sha: "f1", content: $c}'
}

user() { jq -n --arg l "$1" --argjson i "$2" --arg t "${3:-User}" '{login: $l, id: $i, type: $t}'; }
comment() {
  jq -n --argjson id "$1" --argjson u "$2" --arg b "$3" \
    '{id: $id, body: $b, created_at: "2026-01-02T03:04:05Z", html_url: "https://example.test/c", user: $u}'
}

# Creates the temporary directory, the fake gh, and a pull request 7 opened by alice (id 10)
# with one commit of hers, an existing signature branch and nobody signed.
setup() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/cla-check.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  mkdir "$d/bin" "$d/fix"
  cat > "$d/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = api ] || exit 64
shift
method=GET path='' filter=''
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --method) method="$2"; shift ;;
    --input) shift ;;
    --jq) filter="$2"; shift ;;
    *) path="$1" ;;
  esac
  shift
done
name="$(printf '%s' "$path" | tr '/?=' '___')"
if [ "$method" = GET ]; then
  if [ -f "$FIX/ERR_$name" ]; then echo "gh: Server Error (HTTP 500)" >&2; exit 1; fi
  if [ ! -f "$FIX/$name" ]; then
    echo '{"message":"Not Found"}'
    echo "gh: Not Found (HTTP 404)" >&2
    exit 1
  fi
  out="$(cat "$FIX/$name")"
else
  body="$(cat)"
  if [ -f "$FIX/FAIL_$method" ]; then
    rm "$FIX/FAIL_$method"
    echo "gh: Conflict (HTTP 409)" >&2
    exit 1
  fi
  printf '%s %s %s\n' "$method" "$path" "$(jq -c . <<<"$body")" >> "$FIX/calls"
  out='{"sha":"new"}'
fi
if [ -n "$filter" ]; then jq -r "$filter" <<<"$out"; else printf '%s\n' "$out"; fi
GH
  chmod +x "$d/bin/gh"
  alice="$(user alice 10)"
  fixture repos/o/r/pulls/7 "$(jq -n --argjson u "$alice" '{head: {sha: "abc1234def"}, user: $u}')"
  fixture repos/o/r/pulls/7/commits "$(jq -n --argjson u "$alice" '[{sha: "abc1234def", author: $u}]')"
  fixture repos/o/r/issues/7/comments '[]'
  fixture "$SIGNATURES" "$(signature_file '[]')"
  fixture "$BRANCH_REF" '{}'
}

# Runs the check; its exit code is the function's. stderr goes to $d/err.
run() {
  PATH="$d/bin:$PATH" FIX="$d/fix" GH_REPO=o/r PR=7 CLA_EXEMPT=HoaMi DRY_RUN='' \
    "$root/scripts/cla-check.sh" 2> "$d/err"
}

calls() { cat "$d/fix/calls" 2>/dev/null || true; }
# wrote <pattern>: a write matching the extended regular expression was made.
wrote() { calls | grep -Eq -- "$1" || { echo "no write matches: $1" >&2; calls >&2; return 1; }; }
wrote_no() { ! calls | grep -Eq -- "$1" || { echo "unexpected write matches: $1" >&2; calls >&2; return 1; }; }
# The signature list of the last commit to the signature file.
recorded() {
  calls | grep '^PUT repos/o/r/contents/signatures/cla.json ' | tail -1 \
    | sed 's/^PUT [^ ]* //' | jq -r '.content' | base64 --decode | jq -c '.signatures'
}

case_unsigned_author_is_asked() {
  setup
  run
  wrote '^POST repos/o/r/statuses/abc1234def .*"state":"failure".*"context":"cla-signed"' || return 1
  wrote '^POST repos/o/r/issues/7/comments .*Still to sign: @alice' || return 1
  wrote_no '^PUT '
}

case_signing_comment_is_recorded() {
  setup
  fixture repos/o/r/issues/7/comments "$(jq -n --argjson c "$(comment 1 "$alice" "  $PHRASE
")" '[$c]')"
  run
  [ "$(recorded | jq -c '.[0] | [.login, .id, .pull_request, .comment_id, .cla_version]')" \
    = '["alice",10,7,1,"1.0"]' ] || { echo "recorded: $(recorded)" >&2; return 1; }
  wrote '^POST repos/o/r/statuses/abc1234def .*"state":"success"' || return 1
  wrote_no '^POST repos/o/r/issues/7/comments'
}

case_recorded_signature_covers_later_pull_requests() {
  setup
  fixture "$SIGNATURES" "$(signature_file '[{"login": "alice-old-name", "id": 10}]')"
  run
  wrote '"state":"success"' || return 1
  wrote_no '^PUT ' || return 1
  wrote_no 'issues/7/comments'
}

case_signature_of_someone_else_does_not_cover_the_author() {
  setup
  fixture repos/o/r/issues/7/comments "$(jq -n --argjson c "$(comment 1 "$(user bob 11)" "$PHRASE")" '[$c]')"
  run
  [ "$(recorded | jq -c 'map(.login)')" = '["bob"]' ] || return 1
  wrote '"state":"failure"' || return 1
  wrote 'Still to sign: @alice'
}

case_altered_phrase_is_not_a_signature() {
  setup
  fixture repos/o/r/issues/7/comments \
    "$(jq -n --argjson c "$(comment 1 "$alice" "$PHRASE, under protest")" '[$c]')"
  run
  wrote_no '^PUT ' || return 1
  wrote '"state":"failure"'
}

case_bots_and_exempt_accounts_sign_nothing() {
  setup
  fixture repos/o/r/pulls/7 "$(jq -n --argjson u "$(user 'renovate[bot]' 20 Bot)" '{head: {sha: "abc1234def"}, user: $u}')"
  fixture repos/o/r/pulls/7/commits "$(jq -n --argjson b "$(user 'renovate[bot]' 20 Bot)" \
    --argjson m "$(user hoami 30)" '[{sha: "a", author: $b}, {sha: "b", author: $m}]')"
  run
  wrote '"state":"success"' || return 1
  wrote_no 'issues/7/comments'
}

case_commit_without_github_account_fails() {
  setup
  fixture "$SIGNATURES" "$(signature_file '[{"login": "alice", "id": 10}]')"
  fixture repos/o/r/pulls/7/commits "$(jq -n --argjson u "$alice" \
    '[{sha: "abc1234def", author: $u}, {sha: "9999999aaaa", author: null}]')"
  run
  wrote '"state":"failure"' || return 1
  wrote 'issues/7/comments .*not linked to a GitHub account: `9999999`' || return 1
  wrote_no 'Still to sign'
}

case_missing_branch_is_created() {
  setup
  rm "$d/fix/$(key "$SIGNATURES")" "$d/fix/$(key "$BRANCH_REF")"
  fixture repos/o/r/issues/7/comments "$(jq -n --argjson c "$(comment 1 "$alice" "$PHRASE")" '[$c]')"
  run
  wrote '^POST repos/o/r/git/trees .*"path":"signatures/cla.json".*alice' || return 1
  wrote '^POST repos/o/r/git/commits .*"parents":\[\]' || return 1
  wrote '^POST repos/o/r/git/refs .*"ref":"refs/heads/cla-signatures","sha":"new"' || return 1
  wrote '"state":"success"'
}

case_unreadable_signatures_stop_the_check() {
  setup
  : > "$d/fix/ERR_$(key "$SIGNATURES")"
  if run; then echo "expected a failure" >&2; return 1; fi
  [ -z "$(calls)" ] || { echo "nothing should be written" >&2; calls >&2; return 1; }
}

case_write_conflict_is_retried() {
  setup
  fixture repos/o/r/issues/7/comments "$(jq -n --argjson c "$(comment 1 "$alice" "$PHRASE")" '[$c]')"
  : > "$d/fix/FAIL_PUT"
  run
  [ "$(recorded | jq -c 'map(.login)')" = '["alice"]' ] || return 1
  wrote '"state":"success"'
}

case_own_comment_is_updated_once_signed() {
  setup
  fixture "$SIGNATURES" "$(signature_file '[{"login": "alice", "id": 10}]')"
  fixture repos/o/r/issues/7/comments "$(jq -n \
    --argjson c "$(comment 5 "$(user 'github-actions[bot]' 40 Bot)" '<!-- cla-check -->
Still to sign: @alice')" '[$c]')"
  run
  wrote '^PATCH repos/o/r/issues/comments/5 .*has signed' || return 1
  wrote_no '^POST repos/o/r/issues/7/comments'
}

case_marker_from_another_account_is_ignored() {
  setup
  fixture repos/o/r/issues/7/comments "$(jq -n \
    --argjson c "$(comment 5 "$(user mallory 50)" '<!-- cla-check -->
Every author has signed.')" '[$c]')"
  run
  wrote_no '^PATCH ' || return 1
  wrote '^POST repos/o/r/issues/7/comments .*Still to sign: @alice'
}

# --- runner ---
failed=""
for name in $(declare -F | awk '{print $3}' | grep '^case_'); do
  if ( set -e; "$name" ); then echo "ok   $name"; else echo "FAIL $name"; failed="$failed $name"; fi
done
if [ -n "$failed" ]; then echo "failed:$failed" >&2; exit 1; fi
echo "OK: all cases pass"
