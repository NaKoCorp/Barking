#!/usr/bin/env bash
# Host tests of the CI and release scripts (bash and git only, no Docker).
# One cas_* function per case; each runs in its own subshell with a fresh temporary directory.
# Compatible with bash 3.2 (macOS).
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

cas_workspace_version_read() {
  local d out
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  cat > "$d/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/*"]

[workspace.dependencies]
foo = { version = "9.9.9" }

[workspace.package]
version = "1.2.3"
license = "AGPL-3.0-only"
TOML
  out="$(version_du_workspace "$d")"
  rm -rf "$d"
  [ "$out" = "1.2.3" ] || { echo "expected 1.2.3, got: $out" >&2; return 1; }
}

cas_workspace_version_missing() {
  local d out rc=0
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  cat > "$d/Cargo.toml" <<'TOML'
[workspace.dependencies]
foo = { version = "9.9.9" }

[workspace.package]
license = "AGPL-3.0-only"

[package]
version = "4.5.6"
TOML
  out="$( (version_du_workspace "$d") 2>&1)" || rc=$?
  rm -rf "$d"
  [ "$rc" -ne 0 ] || { echo "expected a non-zero exit code" >&2; return 1; }
  case "$out" in *"version not found"*) ;; *) echo "unexpected message: $out" >&2; return 1 ;; esac
}

# --- compare-copies.sh ---
# The cases below keep their temporary directory in the global d: the EXIT trap runs after the
# function has returned, when its locals are gone.
# Fake copies: <dir>/build-<target>-{a,b} with three tiny binaries and a SHA256SUMS each.
faire_copies() { # $1 = directory
  local t c p f
  for t in $CIBLES_PUBLIEES; do
    for c in a b; do
      mkdir -p "$1/build-$t-$c"
      for p in barking-cli barking-node barking-push; do
        printf '%s %s\n' "$p" "$t" > "$1/build-$t-$c/$p-1.0.0-$t"
      done
      for f in "$1/build-$t-$c"/barking-*; do
        printf '%s  %s\n' "$(sha256_de "$f")" "$(basename "$f")"
      done > "$1/build-$t-$c/SHA256SUMS"
    done
  done
}

# Runs compare-copies.sh on <d>/copies into <d>/out; sets SORTIE (output) and RC (exit code).
lancer_compare() { # $1 = working directory
  RC=0
  SORTIE="$("$racine/scripts/compare-copies.sh" --copies "$1/copies" --out "$1/out" 2>&1)" || RC=$?
}

# Expects a failure whose message contains $2.
attendre_echec() { # $1 = case name, $2 = expected fragment
  [ "$RC" -ne 0 ] || { echo "$1: expected a non-zero exit code" >&2; return 1; }
  case "$SORTIE" in *"$2"*) ;; *) echo "$1: unexpected message: $SORTIE" >&2; return 1 ;; esac
}

cas_compare_identical() {
  local n f
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  lancer_compare "$d"
  [ "$RC" -eq 0 ] || { echo "expected success, got $RC: $SORTIE" >&2; return 1; }
  n="$(find "$d/out" -maxdepth 1 -type f -name 'barking-*' | wc -l | tr -d ' ')"
  [ "$n" -eq 9 ] || { echo "expected 9 binaries, got $n" >&2; return 1; }
  [ "$(wc -l < "$d/out/SHA256SUMS" | tr -d ' ')" -eq 9 ] || { echo "expected 9 lines in SHA256SUMS" >&2; return 1; }
  LC_ALL=C sort -k2 -c "$d/out/SHA256SUMS" || { echo "SHA256SUMS is not sorted" >&2; return 1; }
  [ ! -x "$d/out/SHA256SUMS" ] || { echo "SHA256SUMS must not be executable" >&2; return 1; }
  for f in "$d"/out/barking-*; do
    [ -x "$f" ] || { echo "not executable: $f" >&2; return 1; }
    [ "$(sha256_de "$f")" = "$(grep "  $(basename "$f")\$" "$d/out/SHA256SUMS" | cut -d' ' -f1)" ] \
      || { echo "wrong checksum for $f" >&2; return 1; }
  done
}

cas_compare_binary_differs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo tampered >> "$d/copies/build-aarch64-apple-darwin-b/barking-node-1.0.0-aarch64-apple-darwin"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "differ" || return 1
  attendre_echec "${FUNCNAME[0]}" "non-reproducible" || return 1
}

cas_compare_missing_copy() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  rm -rf "$d/copies/build-aarch64-unknown-linux-musl-b"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "missing copies for aarch64-unknown-linux-musl" || return 1
}

cas_compare_two_binaries_for_one_program() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo extra > "$d/copies/build-x86_64-unknown-linux-musl-a/barking-cli-1.0.1-x86_64-unknown-linux-musl"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "exactly one" || return 1
}

cas_compare_wrong_target_suffix() {
  local t c
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  t=x86_64-unknown-linux-musl
  for c in a b; do
    mv "$d/copies/build-$t-$c/barking-push-1.0.0-$t" "$d/copies/build-$t-$c/barking-push-1.0.0-other"
  done
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "unexpected name" || return 1
}

cas_compare_sums_differ() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  echo "# extra" >> "$d/copies/build-x86_64-unknown-linux-musl-b/SHA256SUMS"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "SHA256SUMS of the copies of x86_64-unknown-linux-musl differ" || return 1
}

cas_compare_out_not_empty() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_copies "$d/copies"
  mkdir "$d/out"; echo x > "$d/out/leftover"
  lancer_compare "$d"
  attendre_echec "${FUNCNAME[0]}" "not empty" || return 1
  [ ! -e "$d/out/SHA256SUMS" ] || { echo "nothing must be written to a non-empty output" >&2; return 1; }
}

# --- check-pr-title.sh ---
# Runs the script with PR_TITLE=$1; sets SORTIE and RC.
lancer_titre() { # $1 = title
  RC=0
  SORTIE="$(PR_TITLE="$1" "$racine/scripts/check-pr-title.sh" 2>&1)" || RC=$?
}

cas_pr_title_accepted() {
  local t
  for t in 'feat: add relay stats' 'fix(ios): read every QR segment' 'feat(node)!: protocol v3' \
    'chore(deps): update rust crate tokio to v1.55' 'chore(main): release 0.2.0' 'revert: "feat: x"'; do
    lancer_titre "$t"
    [ "$RC" -eq 0 ] || { echo "rejected a valid title: $t: $SORTIE" >&2; return 1; }
  done
}

cas_pr_title_rejected() {
  local t
  for t in 'iOS app, block 2: messaging' 'Feat: x' 'feat:x' 'feat : x' 'feat(): x' 'feat(iOS): x' \
    'feature: x' 'feat: ' 'feat: x ' '' $'feat: x\ny' $'feat: x\r'; do
    lancer_titre "$t"
    [ "$RC" -eq 1 ] || { echo "accepted or crashed on an invalid title: '$t' (rc=$RC): $SORTIE" >&2; return 1; }
    case "$SORTIE" in *"Expected:"*"Types:"*) ;; *) echo "no format hint for '$t': $SORTIE" >&2; return 1 ;; esac
  done
}

cas_pr_title_unset() {
  RC=0
  SORTIE="$(env -u PR_TITLE "$racine/scripts/check-pr-title.sh" 2>&1)" || RC=$?
  [ "$RC" -eq 1 ] || { echo "expected exit 1, got $RC" >&2; return 1; }
  case "$SORTIE" in *"PR_TITLE is not set"*) ;; *) echo "unexpected message: $SORTIE" >&2; return 1 ;; esac
}

# --- ci-gate.sh ---
# A throwaway origin exposes a "pull request head" under refs/pull/7/head; the work clone holds the
# merge commit. The stub gh in <d>/bin prints GH_API_OUT / GH_RUN_OUT and exits GH_API_RC / GH_RUN_RC,
# and logs each call to GH_LOG. The tree of the merge commit is the PR tree (SHA) or another one (SHA_AUTRE).
git_test() { git -c user.name=test -c user.email=test@example.com -c commit.gpgsign=false "$@"; }

faire_depot_gate() { # $1 = directory
  local base tete
  mkdir -p "$1/bin" "$1/origin"
  git_test init -q "$1/origin"
  echo base > "$1/origin/f"
  git_test -C "$1/origin" add f
  git_test -C "$1/origin" commit -q -m base
  base="$(git -C "$1/origin" rev-parse HEAD)"
  echo change > "$1/origin/f"
  git_test -C "$1/origin" commit -q -am "pr head"
  tete="$(git -C "$1/origin" rev-parse HEAD)"
  git -C "$1/origin" update-ref refs/pull/7/head "$tete"
  git -C "$1/origin" reset -q --hard "$base"
  git_test clone -q "$1/origin" "$1/work"
  git -C "$1/work" fetch -q origin "refs/pull/7/head"
  # Squash-merge commit: the PR tree on top of the base, as a fresh commit.
  SHA="$(git_test -C "$1/work" commit-tree "$tete^{tree}" -p "$base" -m squash)"
  SHA_AUTRE="$(git_test -C "$1/work" commit-tree "$base^{tree}" -p "$base" -m other)"
  # Forget the PR head locally: the script must fetch it itself.
  git -C "$1/work" update-ref -d FETCH_HEAD 2>/dev/null || true
  cat > "$1/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1" in
  api) [ -z "$GH_API_OUT" ] || printf '%s\n' "$GH_API_OUT"; exit "${GH_API_RC:-0}" ;;
  run) [ -z "$GH_RUN_OUT" ] || printf '%s\n' "$GH_RUN_OUT"; exit "${GH_RUN_RC:-0}" ;;
esac
exit 99
STUB
  chmod +x "$1/bin/gh"
  : > "$1/gh.log"
}

# Runs ci-gate.sh in <d>/work; sets SORTIE (stdout), ERREUR (stderr) and RC. Event: $EVENEMENT (default push).
lancer_gate() { # $1 = working directory, $2 = SHA
  RC=0
  SORTIE="$(cd "$1/work" && PATH="$1/bin:$PATH" GH_LOG="$1/gh.log" EVENT="${EVENEMENT:-push}" SHA="$2" \
    GITHUB_REPOSITORY=acme/barking GH_TOKEN=unused \
    GH_API_OUT="${GH_API_OUT-7}" GH_API_RC="${GH_API_RC-0}" \
    GH_RUN_OUT="${GH_RUN_OUT-success}" GH_RUN_RC="${GH_RUN_RC-0}" \
    "$racine/scripts/ci-gate.sh" 2>"$1/stderr")" || RC=$?
  ERREUR="$(cat "$1/stderr")"
}

# Expects exit 0 and exactly one line on stdout, equal to $2.
attendre_gate() { # $1 = case name, $2 = expected line
  [ "$RC" -eq 0 ] || { echo "$1: expected exit 0, got $RC: $ERREUR" >&2; return 1; }
  [ "$SORTIE" = "$2" ] || { echo "$1: expected '$2', got '$SORTIE' ($ERREUR)" >&2; return 1; }
  [ -n "$ERREUR" ] || { echo "$1: the reason is missing on stderr" >&2; return 1; }
}

cas_gate_pull_request_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  EVENEMENT=pull_request lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
  [ ! -s "$d/gh.log" ] || { echo "gh must not be called: $(cat "$d/gh.log")" >&2; return 1; }
}

cas_gate_dispatch_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  EVENEMENT=workflow_dispatch lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
  [ ! -s "$d/gh.log" ] || { echo "gh must not be called: $(cat "$d/gh.log")" >&2; return 1; }
}

cas_gate_same_tree_green_skips() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=false" || return 1
  grep -q -- '--workflow ci.yml' "$d/gh.log" || { echo "the ci workflow was not queried" >&2; return 1; }
  grep -q -- '--event pull_request' "$d/gh.log" || { echo "pull_request runs were not queried" >&2; return 1; }
  grep -q -- "--commit $(git -C "$d/work" rev-parse FETCH_HEAD)" "$d/gh.log" \
    || { echo "runs were not queried for the PR head" >&2; return 1; }
}

cas_gate_different_tree_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  lancer_gate "$d" "$SHA_AUTRE"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

cas_gate_ci_not_green_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  GH_RUN_OUT=failure lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
  GH_RUN_OUT='' lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

cas_gate_no_pull_request_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  GH_API_OUT='' lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

cas_gate_two_pull_requests_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  GH_API_OUT=$'7\n8' lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

cas_gate_api_error_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  GH_API_RC=1 lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
  GH_RUN_RC=1 lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

cas_gate_fetch_error_runs() {
  d="$(mktemp -d "${TMPDIR:-/tmp}/ci-scripts.XXXXXX")"
  trap 'rm -rf "$d"' EXIT
  faire_depot_gate "$d"
  GH_API_OUT=8 lancer_gate "$d" "$SHA"
  attendre_gate "${FUNCNAME[0]}" "run=true" || return 1
}

# --- runner ---
echec=""
for cas in $(declare -F | awk '{print $3}' | grep '^cas_'); do
  if ( set -e; "$cas" ); then echo "ok   $cas"; else echo "FAIL $cas"; echec="$echec $cas"; fi
done
if [ -n "$echec" ]; then echo "failed:$echec" >&2; exit 1; fi
echo "OK: all cases pass"
