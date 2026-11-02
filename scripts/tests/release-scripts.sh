#!/usr/bin/env bash
# Test: signing and verification of releases (sign-release.sh, verify-release.sh).
# Launched from the host, it relaunches itself in a container (minisign, git, no network required).
# The tested scripts run from a throwaway git repository (tag v0.0.1), never from the real repository:
# no case depends on keys/maintainer.pub or on the repository's tags.
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
  mkdir -p "$1/keys"
  cp -R "$racine/scripts" "$1/"
  cp "$racine/.xcode-version" "$racine/rust-toolchain.toml" "$1/"
  : > "$1/keys/maintainer.pub"
}
depot="$tmp/depot"
copier_scripts "$depot"
git_test -C "$depot" init -q
git_test -C "$depot" add -A
git_test -C "$depot" commit -q -m "test version"
git_test -C "$depot" tag "v$version"
commit_tag="$(git -C "$depot" rev-parse "v$version^{commit}")"
sign="$depot/scripts/sign-release.sh"
verify="$depot/scripts/verify-release.sh"

# Throwaway keys, created here and nowhere else.
mkdir -p "$tmp/cles"
minisign -G -W -p "$tmp/cles/bonne.pub" -s "$tmp/cles/bonne.key" >/dev/null
minisign -G -W -p "$tmp/cles/intruse.pub" -s "$tmp/cles/intruse.key" >/dev/null

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
}
signer() { # $1 = secret key, $2 = verification public key (default: the good one)
  lancer "$sign" "$version" --from-dir "$D" --rebuilt-dir "$R" --seckey "$1" --pubkey "${2:-$tmp/cles/bonne.pub}"
}
verifier() { # $1 = public key, extra options
  local pub="$1"; shift
  lancer "$verify" "$version" --from-dir "$D" --pubkey "$pub" --skip-attestation "$@"
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
sans_minisig() { [ ! -e "$D/SHA256SUMS.minisig" ] || { echo "    SHA256SUMS.minisig should not exist" >&2; return 1; }; }
signer_ok() { signer "$tmp/cles/bonne.key"; attendre_code 0; }

# Replaces one character of the signature body (line 2 of the .minisig).
falsifier_minisig() {
  local f="$1" ligne c n
  ligne="$(sed -n 2p "$f")"; c="${ligne:20:1}"; n="A"; [ "$c" = "A" ] && n="B"
  { sed -n 1p "$f"; printf '%s\n' "${ligne:0:20}$n${ligne:21}"; sed -n '3,$p' "$f"; } > "$f.tmp"
  mv "$f.tmp" "$f"
}

cas_sign_then_verify_ok() {
  nouveau; signer_ok || return 1
  attendre_texte "commit of tag v$version: $commit_tag" || return 1
  minisign -V -m "$D/SHA256SUMS" -x "$D/SHA256SUMS.minisig" -p "$tmp/cles/bonne.pub" 2>&1 \
    | grep -qxF "Trusted comment: barking v$version commit $commit_tag" \
    || { echo "    unexpected signed comment" >&2; return 1; }
  verifier "$tmp/cles/bonne.pub"; attendre_code 0 && attendre_texte "verified" && attendre_texte "identical"
}
cas_sign_then_verify_rebuild_ok() {
  nouveau; signer_ok || return 1
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 0 && attendre_texte "verified"
}
cas_forged_signature_rejected() {
  nouveau; signer_ok || return 1
  falsifier_minisig "$D/SHA256SUMS.minisig"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "invalid signature"
}
cas_other_key_rejected() {
  nouveau; signer "$tmp/cles/intruse.key" "$tmp/cles/intruse.pub"; attendre_code 0 || return 1
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "invalid signature"
}
cas_tampered_binary_rejected() {
  nouveau; signer_ok || return 1
  printf 'X' >> "$D/barking-cli-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "checksum"
}
cas_tampered_sums_rejected() {
  nouveau; signer_ok || return 1
  c="$(head -c1 "$D/SHA256SUMS")"; n=0; [ "$c" = "0" ] && n=1
  sed "1s/^./$n/" "$D/SHA256SUMS" > "$D/SHA256SUMS.n"
  cmp -s "$D/SHA256SUMS" "$D/SHA256SUMS.n" && { echo "    tampering had no effect" >&2; return 1; }
  mv "$D/SHA256SUMS.n" "$D/SHA256SUMS"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "invalid signature"
}
cas_extra_or_missing_binary_rejected() {
  nouveau; signer_ok || return 1
  cp "$D/barking-cli-$version-$t_x86" "$D/barking-cli-$version-extra"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "extra file" || return 1
  rm "$D/barking-cli-$version-extra" "$D/barking-cli-$version-$t_arm"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "missing file"
}
cas_node_binary_checked_like_cli() {
  nouveau; signer_ok || return 1
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 0 || return 1
  # The node binary is checked like the CLI's: checksum, rebuild, extra file.
  printf 'X' >> "$D/barking-node-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "incorrect checksum for barking-node-" || return 1
  nouveau; signer_ok || return 1
  printf 'other\n' > "$R/barking-node-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs from the published binary for barking-node-" || return 1
  nouveau; signer_ok || return 1
  cp "$D/barking-node-$version-$t_x86" "$D/barking-node-$version-extra"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "extra file" || return 1
  rm "$D/barking-node-$version-extra" "$D/barking-node-$version-$t_arm"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "missing file"
}
cas_push_binary_checked_like_cli() {
  # Complete set accepted: barking-cli, barking-node and barking-push for each published target.
  nouveau; signer_ok || return 1
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 0 || return 1
  # A set without barking-push for one target (file and line removed) is refused, at signing and at verification.
  nouveau
  rm "$D/barking-push-$version-$t_mac"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "incomplete set" && sans_minisig || return 1
  nouveau
  rm "$D/barking-push-$version-$t_x86" "$D/barking-push-$version-$t_arm" "$D/barking-push-$version-$t_mac"
  regenerer_sommes "$D"
  signer_avec_commentaire "barking v$version commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "incomplete set: barking-push-" || return 1
  # A barking-push binary of another version is refused even with consistent checksums and a valid signature.
  nouveau
  printf 'intruder\n' > "$D/barking-push-9.9.9-$t_x86"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "unexpected entry" && sans_minisig || return 1
  nouveau
  printf 'intruder\n' > "$D/barking-push-9.9.9-$t_x86"
  regenerer_sommes "$D"
  signer_avec_commentaire "barking v$version commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "unexpected entry" || return 1
  # Checked like the others: checksum, rebuild, extra file.
  nouveau; signer_ok || return 1
  printf 'X' >> "$D/barking-push-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "incorrect checksum for barking-push-" || return 1
  nouveau; signer_ok || return 1
  printf 'other\n' > "$R/barking-push-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs from the published binary for barking-push-" || return 1
  nouveau; signer_ok || return 1
  cp "$D/barking-push-$version-$t_x86" "$D/barking-push-$version-extra"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "extra file" || return 1
  # Signing refuses a rebuild directory lacking barking-push for the host target.
  nouveau
  case "$(uname -m)" in x86_64|amd64) hote="$t_x86" ;; *) hote="$t_arm" ;; esac
  rm "$R/barking-push-$version-$hote"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "without a corresponding rebuild" && sans_minisig
}
cas_mixed_version_or_unknown_name_refused() {
  # A node binary of another version, or an unknown name, listed in SHA256SUMS: refused at
  # signing as at verification, even if the checksums and the file are consistent.
  local autre
  for autre in "barking-node-9.9.9-$t_x86" "barking-cli-9.9.9-$t_x86" "barking-push-9.9.9-$t_x86" "barking-relay-$version-$t_x86" "barking-node-$version-" "barking-push-$version-"; do
    nouveau
    printf 'intruder\n' > "$D/$autre"
    regenerer_sommes "$D"
    # Listed by hand: regenerer_sommes only knows valid binary names.
    grep -qF "  $autre" "$D/SHA256SUMS" \
      || { printf '%s  %s\n' "$(sha256sum "$D/$autre" | cut -d' ' -f1)" "$autre" >> "$D/SHA256SUMS"; }
    signer "$tmp/cles/bonne.key"
    attendre_code 1 && attendre_texte "unexpected entry" && sans_minisig || { echo "    case: $autre" >&2; return 1; }
  done
  # Verification: sums modified then re-signed, so the signature is valid and the refusal comes from the content.
  nouveau
  printf 'intruder\n' > "$D/barking-node-9.9.9-$t_x86"
  regenerer_sommes "$D"
  signer_avec_commentaire "barking v$version commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "unexpected entry"
}
cas_incomplete_or_unknown_target_set_refused() {
  # Complete set required: a removed node binary (file and line) is refused, valid signature or not.
  nouveau
  rm "$D/barking-node-$version-$t_mac"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "incomplete set" && sans_minisig || return 1
  nouveau
  rm "$D/barking-node-$version-$t_arm"
  regenerer_sommes "$D"
  signer_avec_commentaire "barking v$version commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "incomplete set" || return 1
  # Unknown target (including the false split of a pre-release name): refused.
  nouveau
  printf 'x\n' > "$D/barking-node-$version-riscv64-unknown-linux-musl"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "unexpected entry" && sans_minisig || return 1
  nouveau
  printf 'x\n' > "$D/barking-cli-$version-rc.1-$t_x86"
  regenerer_sommes "$D"
  signer_avec_commentaire "barking v$version commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "unexpected entry"
}
cas_sign_refuses_on_mismatch() {
  nouveau
  # Binary replaced in --from-dir; SHA256SUMS regenerated (consistent), the rebuild differs.
  printf 'backdoor\n' > "$D/barking-cli-$version-$t_x86"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "diff" && sans_minisig || return 1
  # Without regenerating SHA256SUMS: refused as soon as the directory's checksums are checked.
  nouveau
  printf 'backdoor\n' > "$D/barking-cli-$version-$t_arm"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "incorrect checksum" && sans_minisig
}
cas_sign_refuses_missing_or_unlisted() {
  nouveau; rm "$D/barking-cli-$version-$t_mac"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "missing file" && sans_minisig || return 1
  nouveau; cp "$D/barking-cli-$version-$t_x86" "$D/barking-cli-$version-extra"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "extra file" && sans_minisig
}
cas_sign_refuses_without_rebuilt_counterpart() {
  nouveau
  # The target buildable on this machine must have a rebuilt counterpart.
  case "$(uname -m)" in x86_64|amd64) hote="$t_x86" ;; *) hote="$t_arm" ;; esac
  rm "$R/barking-cli-$version-$hote"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "without a corresponding rebuild" && sans_minisig || return 1
  nouveau
  rm "$R/barking-node-$version-$hote"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "without a corresponding rebuild" && sans_minisig
}
cas_verify_rebuilt_mismatch_rejected() {
  nouveau; signer_ok || return 1
  printf 'other\n' > "$R/barking-cli-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "differs"
}
signer_avec_commentaire() { # $1 = signed comment
  minisign -S -m "$D/SHA256SUMS" -s "$tmp/cles/bonne.key" -t "$1" -x "$D/SHA256SUMS.minisig" >/dev/null
}
cas_trusted_comment_other_version_rejected() {
  nouveau; signer_avec_commentaire "barking v9.9.9 commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signed comment"
}
cas_trusted_comment_without_commit_rejected() {
  nouveau; signer_avec_commentaire "barking v$version"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signed comment" || return 1
  nouveau; signer_avec_commentaire "barking v$version commit ${commit_tag:0:39}"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signed comment" || return 1
  # The version is compared literally (the dot is not a wildcard).
  nouveau; signer_avec_commentaire "barking v0x0x1 commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signed comment"
}
cas_signed_commit_differs_from_local_tag_rejected() {
  nouveau; signer_ok || return 1
  # Another clone where tag v$version points to another commit.
  local autre="$tmp/autre-clone"
  rm -rf "$autre"
  git clone -q "$depot" "$autre"
  git_test -C "$autre" commit -q --allow-empty -m "other commit"
  git_test -C "$autre" tag -f "v$version" >/dev/null
  lancer "$autre/scripts/verify-release.sh" "$version" --from-dir "$D" --pubkey "$tmp/cles/bonne.pub" --skip-attestation
  attendre_code 1 && attendre_texte "tag moved" && attendre_texte "$commit_tag"
}
cas_signed_commit_unchecked_without_local_tag() {
  nouveau; signer_ok || return 1
  # Scripts outside any git repository: the commit cannot be compared, this is announced.
  local sans_git="$tmp/sans-git"
  [ -d "$sans_git" ] || copier_scripts "$sans_git"
  lancer "$sans_git/scripts/verify-release.sh" "$version" --from-dir "$D" --pubkey "$tmp/cles/bonne.pub" --skip-attestation
  attendre_code 0 && attendre_texte "could not be compared" && attendre_texte "commit signed by the maintainer: $commit_tag"
}
cas_sign_refuses_without_local_tag() {
  nouveau
  local sans_git="$tmp/sans-git"
  [ -d "$sans_git" ] || copier_scripts "$sans_git"
  lancer "$sans_git/scripts/sign-release.sh" "$version" --from-dir "$D" --rebuilt-dir "$R" \
    --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 1 && attendre_texte "tag v$version not found" && sans_minisig
}
cas_sign_refuses_tag_differing_from_origin() {
  # Clone whose origin is the throwaway repository: same tag, signing is allowed.
  local clone="$tmp/clone-origine"
  rm -rf "$clone"
  git clone -q "$depot" "$clone"
  nouveau
  lancer "$clone/scripts/sign-release.sh" "$version" --from-dir "$D" --rebuilt-dir "$R" \
    --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 0 || return 1
  # Tag moved in this clone only: refused, nothing is signed.
  git_test -C "$clone" commit -q --allow-empty -m "other commit"
  git_test -C "$clone" tag -f "v$version" >/dev/null
  nouveau
  lancer "$clone/scripts/sign-release.sh" "$version" --from-dir "$D" --rebuilt-dir "$R" \
    --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 1 && attendre_texte "differs between this clone" && sans_minisig
}
cas_sign_origin_unreachable_needs_from_dir() {
  local clone="$tmp/clone-injoignable"
  rm -rf "$clone"
  git clone -q "$depot" "$clone"
  git -C "$clone" remote set-url origin "$tmp/absent.git"
  # Without --from-dir (assets fetched from the draft): refused before any download.
  lancer "$clone/scripts/sign-release.sh" "$version" --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 1 && attendre_texte "origin unreachable" || return 1
  # With --from-dir: allowed, with a warning.
  nouveau
  lancer "$clone/scripts/sign-release.sh" "$version" --from-dir "$D" --rebuilt-dir "$R" \
    --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 0 && attendre_texte "warning: origin unreachable"
}
cas_sign_without_origin_needs_from_dir() {
  # The throwaway repository has no remote: refused without --from-dir, before any download.
  lancer "$sign" "$version" --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 1 && attendre_texte "no remote 'origin' configured" || return 1
  # With --from-dir: allowed, with a warning.
  nouveau; signer_ok || return 1
  attendre_texte "warning: no remote 'origin' configured"
}
cas_comment_only_pubkey_rejected() {
  nouveau; signer_ok || return 1
  printf 'untrusted comment: minisign public key AAAA\n' > "$tmp/commentaire.pub"
  verifier "$tmp/commentaire.pub"; attendre_code 1 && attendre_texte "keys/README.md" || return 1
  signer "$tmp/cles/bonne.key" "$tmp/commentaire.pub"; attendre_code 1 && attendre_texte "keys/README.md"
}
cas_sign_wrong_seckey_refused() {
  nouveau
  signer "$tmp/cles/intruse.key"; attendre_code 1 && attendre_texte "does not match" && sans_minisig
}
cas_rebuild_refuses_tag_without_build_env() {
  nouveau; signer_ok || return 1
  # The throwaway repository's tag does not record docker/repro.Dockerfile: the rebuild must refuse
  # rather than use the working tree's environment.
  verifier "$tmp/cles/bonne.pub" --rebuild
  attendre_code 1 && attendre_texte "does not contain docker/repro.Dockerfile"
}
cas_empty_pubkey_rejected() {
  nouveau; signer_ok || return 1
  : > "$tmp/vide.pub"
  verifier "$tmp/vide.pub"; attendre_code 1 && attendre_texte "keys/README.md" || return 1
  signer "$tmp/cles/bonne.key" "$tmp/vide.pub"; attendre_code 1 && attendre_texte "keys/README.md"
}

echecs=0
for cas in sign_then_verify_ok sign_then_verify_rebuild_ok forged_signature_rejected other_key_rejected \
           tampered_binary_rejected tampered_sums_rejected extra_or_missing_binary_rejected \
           node_binary_checked_like_cli push_binary_checked_like_cli mixed_version_or_unknown_name_refused incomplete_or_unknown_target_set_refused \
           sign_refuses_on_mismatch sign_refuses_missing_or_unlisted sign_refuses_without_rebuilt_counterpart \
           verify_rebuilt_mismatch_rejected trusted_comment_other_version_rejected \
           trusted_comment_without_commit_rejected signed_commit_differs_from_local_tag_rejected \
           signed_commit_unchecked_without_local_tag sign_refuses_without_local_tag \
           rebuild_refuses_tag_without_build_env sign_refuses_tag_differing_from_origin \
           sign_origin_unreachable_needs_from_dir sign_without_origin_needs_from_dir \
           comment_only_pubkey_rejected sign_wrong_seckey_refused empty_pubkey_rejected; do
  if "cas_$cas"; then echo "PASS $cas"; else echo "FAIL $cas"; echecs=$((echecs + 1)); fi
done
[ "$echecs" -eq 0 ] || { echo "$echecs cases failed" >&2; exit 1; }
echo "OK: all cases pass"
