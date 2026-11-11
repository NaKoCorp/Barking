#!/usr/bin/env bash
# Test: verification of releases (verify-release.sh).
# Launched from the host, it relaunches itself in a container (git, no network, no gh).
# The tested scripts run from a throwaway git repository (tag v0.0.1), never from the real repository:
# no case depends on the repository's tags. gh is replaced by a stub created below.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -z "${BARKING_TEST_DANS_CONTENEUR:-}" ]; then
  command -v docker >/dev/null 2>&1 || { echo "error: docker is required for this test" >&2; exit 1; }
  df="$racine/docker/release-test.Dockerfile"
  if command -v sha256sum >/dev/null 2>&1; then empreinte="$(sha256sum "$df" | cut -d' ' -f1)"
  else empreinte="$(shasum -a 256 "$df" | cut -d' ' -f1)"; fi
  image="barking-release-test:${empreinte:0:16}"
  docker build -q -f "$df" -t "$image" "$racine/docker" >/dev/null \
    || { echo "error: building the test image failed" >&2; exit 1; }
  exec docker run --rm --read-only --network=none --cap-drop=ALL \
    --security-opt=no-new-privileges --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,nosuid,nodev,exec -e HOME=/tmp \
    -v "$racine:/repo:ro" -e BARKING_TEST_DANS_CONTENEUR=1 \
    -w /repo "$image" bash /repo/scripts/tests/release-scripts.sh
fi

version="0.0.1"
t_x86="x86_64-unknown-linux-musl"
t_arm="aarch64-unknown-linux-musl"
t_mac="aarch64-apple-darwin"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Throwaway repository: copy of the scripts, one commit, the tag v$version.
git_test() { git -c user.name=test -c user.email=test@example.invalid -c init.defaultBranch=main "$@"; }
copier_scripts() { # $1 = destination directory
  mkdir -p "$1"
  cp -R "$racine/scripts" "$1/"
  cp "$racine/.xcode-version" "$racine/rust-toolchain.toml" "$1/"
}
depot="$tmp/depot"
copier_scripts "$depot"
git_test -C "$depot" init -q
git_test -C "$depot" add -A
git_test -C "$depot" commit -q -m "test version"
git_test -C "$depot" tag "v$version"
commit_tag="$(git -C "$depot" rev-parse "v$version^{commit}")"
verify="$depot/scripts/verify-release.sh"

# gh stand-in, first in PATH: logs its arguments in $tmp/gh.log; « attestation verify » succeeds
# only when GH_STUB_ATTEST=ok.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "$tmp/gh.log"
if [ "\${1:-}" = "attestation" ] && [ "\${2:-}" = "verify" ]; then
  [ "\${GH_STUB_ATTEST:-}" = "ok" ] && exit 0
  echo "stub: attestation rejected" >&2
  exit 1
fi
exit 0
STUB
chmod 755 "$tmp/bin/gh"

compteur=0
# Creates a dummy release directory: $1 = directory. The « binaries » are small files.
faire_dist() {
  mkdir -p "$1"
  for t in "$t_x86" "$t_arm" "$t_mac"; do
    for b in barking-cli barking-node barking-push; do
      printf 'dummy binary %s %s\n%s\n' "$b" "$t" "$$-$compteur" > "$1/$b-$version-$t"
      chmod 755 "$1/$b-$version-$t"
    done
  done
  regenerer_sommes "$1"
}
regenerer_sommes() {
  (cd "$1" && for f in barking-cli-* barking-node-* barking-push-*; do [ -e "$f" ] || continue; printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done \
    | LC_ALL=C sort -k2 > SHA256SUMS)
}
# New workspace: $D (release to publish), $R (identical rebuild output).
nouveau() {
  compteur=$((compteur + 1))
  D="$tmp/c$compteur/dist"; R="$tmp/c$compteur/rebuilt"
  faire_dist "$D"
  cp -R "$D" "$R"
  : > "$tmp/gh.log"
}
verifier() { # extra options; the gh stub accepts attestations unless GH_STUB_ATTEST is overridden
  lancer env PATH="$tmp/bin:$PATH" BARKING_REPO=owner/repo GH_STUB_ATTEST="${GH_STUB_ATTEST:-ok}" "$verify" "$version" --from-dir "$D" "$@"
}
lancer() {
  CODE=0
  SORTIE="$("$@" 2>&1)" || CODE=$?
}
montrer_sortie() { printf '%s\n' "$SORTIE" | while IFS= read -r l; do echo "    | $l" >&2; done; }
attendre_code() { # $1 = expected code
  [ "$CODE" -eq "$1" ] || { echo "    code $CODE instead of $1; output:" >&2; montrer_sortie; return 1; }
}
attendre_texte() { # $1 = pattern
  printf '%s' "$SORTIE" | grep -q -- "$1" || { echo "    pattern missing: $1; output:" >&2; montrer_sortie; return 1; }
}
attendre_log() { # $1 = pattern expected in gh.log
  grep -qF -- "$1" "$tmp/gh.log" || { echo "    gh.log lacks: $1; content:" >&2; sed 's/^/    | /' "$tmp/gh.log" >&2; return 1; }
}

cas_verify_ok() {
  nouveau
  verifier; attendre_code 0 && attendre_texte "verified ✓" && attendre_texte "3/3 rebuild: not requested"
}
cas_verify_rebuild_ok() {
  nouveau
  verifier --rebuilt-dir "$R"; attendre_code 0 && attendre_texte "verified ✓"
}
cas_attestation_rejected() {
  nouveau
  GH_STUB_ATTEST=no verifier; attendre_code 1 && attendre_texte "FAILURE at step « attestations »" && attendre_texte "stub: attestation rejected"
}
cas_gh_missing() {
  nouveau
  # PATH without the stub: the container has no gh.
  lancer env BARKING_REPO=owner/repo "$verify" "$version" --from-dir "$D"
  attendre_code 1 && attendre_texte "gh is required"
}
cas_attestation_binds_tag_commit() {
  nouveau
  verifier; attendre_code 0 || return 1
  attendre_log "--source-ref refs/tags/v$version" && attendre_log "--source-digest $commit_tag" \
    && attendre_log "--deny-self-hosted-runners" \
    && attendre_log "--signer-workflow owner/repo/.github/workflows/release.yml" \
    && attendre_log "-R owner/repo" || return 1
  # Every published binary is verified, not just one of them.
  [ "$(grep -c "attestation verify" "$tmp/gh.log")" -eq 9 ] || { echo "expected 9 attestation checks"; return 1; }
}
cas_attestation_without_local_tag() {
  nouveau
  local clone="$tmp/clone-sans-tag"
  rm -rf "$clone"
  git clone -q "$depot" "$clone"
  git -C "$clone" tag -d "v$version" >/dev/null
  lancer env PATH="$tmp/bin:$PATH" BARKING_REPO=owner/repo GH_STUB_ATTEST=ok "$clone/scripts/verify-release.sh" "$version" --from-dir "$D"
  attendre_code 0 && attendre_texte "notice: tag v$version is absent" || return 1
  attendre_log "--source-ref refs/tags/v$version" || return 1
  ! grep -qF -- "--source-digest" "$tmp/gh.log" || { echo "    --source-digest passed without a local tag" >&2; return 1; }
}
cas_removed_options_refused() {
  nouveau
  verifier --skip-attestation; attendre_code 1 && attendre_texte "unknown option" || return 1
  verifier --pubkey x; attendre_code 1 && attendre_texte "unknown option"
}
cas_unsigned_leftover_ignored() {
  nouveau
  # A detached signature left over from the former procedure (name built in two parts so that no
  # reference to the removed tool remains in the tree).
  printf 'untrusted comment: leftover\nRWQ\n' > "$D/SHA256SUMS.mini""sig"
  verifier; attendre_code 0 && attendre_texte "verified ✓"
}
cas_tampered_binary_rejected() {
  nouveau
  printf 'X' >> "$D/barking-cli-$version-$t_x86"
  verifier; attendre_code 1 && attendre_texte "incorrect checksum"
}
cas_tampered_sums_rejected() {
  nouveau
  c="$(head -c1 "$D/SHA256SUMS")"; n=0; [ "$c" = "0" ] && n=1
  sed "1s/^./$n/" "$D/SHA256SUMS" > "$D/SHA256SUMS.n"
  cmp -s "$D/SHA256SUMS" "$D/SHA256SUMS.n" && { echo "    tampering had no effect" >&2; return 1; }
  mv "$D/SHA256SUMS.n" "$D/SHA256SUMS"
  verifier; attendre_code 1 && attendre_texte "incorrect checksum"
}
cas_extra_or_missing_binary_rejected() {
  nouveau
  cp "$D/barking-cli-$version-$t_x86" "$D/barking-cli-$version-extra"
  verifier; attendre_code 1 && attendre_texte "extra file" || return 1
  rm "$D/barking-cli-$version-extra" "$D/barking-cli-$version-$t_arm"
  verifier; attendre_code 1 && attendre_texte "missing file"
}
cas_node_binary_checked_like_cli() {
  nouveau
  verifier --rebuilt-dir "$R"; attendre_code 0 || return 1
  # The node binary is checked like the CLI's: checksum, rebuild, extra file.
  printf 'X' >> "$D/barking-node-$version-$t_x86"
  verifier; attendre_code 1 && attendre_texte "incorrect checksum for barking-node-" || return 1
  nouveau
  printf 'other\n' > "$R/barking-node-$version-$t_x86"
  verifier --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs from the published binary for barking-node-" || return 1
  nouveau
  cp "$D/barking-node-$version-$t_x86" "$D/barking-node-$version-extra"
  verifier; attendre_code 1 && attendre_texte "extra file" || return 1
  rm "$D/barking-node-$version-extra" "$D/barking-node-$version-$t_arm"
  verifier; attendre_code 1 && attendre_texte "missing file"
}
cas_push_binary_checked_like_cli() {
  # Complete set accepted: barking-cli, barking-node and barking-push for each published target.
  nouveau
  verifier --rebuilt-dir "$R"; attendre_code 0 || return 1
  # A set without barking-push (file and line removed) is refused.
  nouveau
  rm "$D/barking-push-$version-$t_x86" "$D/barking-push-$version-$t_arm" "$D/barking-push-$version-$t_mac"
  regenerer_sommes "$D"
  verifier; attendre_code 1 && attendre_texte "incomplete set: barking-push-" || return 1
  # A barking-push binary of another version is refused even with consistent checksums.
  nouveau
  printf 'intruder\n' > "$D/barking-push-9.9.9-$t_x86"
  regenerer_sommes "$D"
  verifier; attendre_code 1 && attendre_texte "unexpected entry" || return 1
  # Checked like the others: checksum, rebuild, extra file.
  nouveau
  printf 'X' >> "$D/barking-push-$version-$t_x86"
  verifier; attendre_code 1 && attendre_texte "incorrect checksum for barking-push-" || return 1
  nouveau
  printf 'other\n' > "$R/barking-push-$version-$t_x86"
  verifier --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs from the published binary for barking-push-" || return 1
  nouveau
  cp "$D/barking-push-$version-$t_x86" "$D/barking-push-$version-extra"
  verifier; attendre_code 1 && attendre_texte "extra file"
}
cas_mixed_version_or_unknown_name_refused() {
  # A binary of another version, or an unknown name, listed in SHA256SUMS: refused even if the
  # checksums and the file are consistent.
  local autre
  for autre in "barking-node-9.9.9-$t_x86" "barking-cli-9.9.9-$t_x86" "barking-push-9.9.9-$t_x86" "barking-relay-$version-$t_x86" "barking-node-$version-" "barking-push-$version-"; do
    nouveau
    printf 'intruder\n' > "$D/$autre"
    regenerer_sommes "$D"
    # Listed by hand: regenerer_sommes only knows valid binary names.
    grep -qF "  $autre" "$D/SHA256SUMS" \
      || { printf '%s  %s\n' "$(sha256sum "$D/$autre" | cut -d' ' -f1)" "$autre" >> "$D/SHA256SUMS"; }
    verifier; attendre_code 1 && attendre_texte "unexpected entry" || { echo "    case: $autre" >&2; return 1; }
  done
}
cas_incomplete_or_unknown_target_set_refused() {
  # Complete set required: a removed node binary (file and line) is refused.
  nouveau
  rm "$D/barking-node-$version-$t_arm"
  regenerer_sommes "$D"
  verifier; attendre_code 1 && attendre_texte "incomplete set" || return 1
  # Unknown target (including the false split of a pre-release name): refused.
  nouveau
  printf 'x\n' > "$D/barking-node-$version-riscv64-unknown-linux-musl"
  regenerer_sommes "$D"
  verifier; attendre_code 1 && attendre_texte "unexpected entry" || return 1
  nouveau
  printf 'x\n' > "$D/barking-cli-$version-rc.1-$t_x86"
  regenerer_sommes "$D"
  verifier; attendre_code 1 && attendre_texte "unexpected entry"
}
cas_verify_rebuilt_mismatch_rejected() {
  nouveau
  printf 'other\n' > "$R/barking-cli-$version-$t_x86"
  verifier --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs"
}
cas_rebuild_refuses_tag_without_build_env() {
  nouveau
  # The throwaway repository's tag does not record docker/repro.Dockerfile: the rebuild must refuse
  # rather than use the working tree's environment.
  verifier --rebuild
  attendre_code 1 && attendre_texte "does not contain docker/repro.Dockerfile"
}

echecs=0
for cas in verify_ok verify_rebuild_ok attestation_rejected gh_missing attestation_binds_tag_commit \
           attestation_without_local_tag removed_options_refused unsigned_leftover_ignored \
           tampered_binary_rejected tampered_sums_rejected extra_or_missing_binary_rejected \
           node_binary_checked_like_cli push_binary_checked_like_cli mixed_version_or_unknown_name_refused \
           incomplete_or_unknown_target_set_refused verify_rebuilt_mismatch_rejected \
           rebuild_refuses_tag_without_build_env; do
  if "cas_$cas"; then echo "PASS $cas"; else echo "FAIL $cas"; echecs=$((echecs + 1)); fi
done
[ "$echecs" -eq 0 ] || { echo "$echecs cases failed" >&2; exit 1; }
echo "OK: all cases pass"
