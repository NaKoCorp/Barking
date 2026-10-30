#!/usr/bin/env bash
# Test : signature et vérification des versions (sign-release.sh, verify-release.sh).
# Lancé depuis l'hôte, il se relance lui-même dans un conteneur (minisign, git, aucun réseau requis).
# Les scripts testés tournent depuis un dépôt git jetable (tag v0.0.1), jamais depuis le dépôt réel :
# aucun cas ne dépend de keys/maintainer.pub ni des tags du dépôt.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -z "${BARKING_TEST_DANS_CONTENEUR:-}" ]; then
  command -v docker >/dev/null 2>&1 || { echo "erreur : docker est requis pour ce test" >&2; exit 1; }
  df="$racine/docker/release-test.Dockerfile"
  if command -v sha256sum >/dev/null 2>&1; then empreinte="$(sha256sum "$df" | cut -d' ' -f1)"
  else empreinte="$(shasum -a 256 "$df" | cut -d' ' -f1)"; fi
  image="barking-release-test:${empreinte:0:16}"
  docker build -q -f "$df" -t "$image" "$racine/docker" >/dev/null \
    || { echo "erreur : construction de l'image de test échouée" >&2; exit 1; }
  exec docker run --rm -v "$racine:/repo:ro" -e BARKING_TEST_DANS_CONTENEUR=1 \
    -w /repo "$image" bash /repo/scripts/tests/release-scripts.sh
fi

version="0.0.1"
t_x86="x86_64-unknown-linux-musl"
t_arm="aarch64-unknown-linux-musl"
t_mac="aarch64-apple-darwin"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Dépôt jetable : copie des scripts, un commit, le tag v$version.
git_test() { git -c user.name=test -c user.email=test@example.invalid -c init.defaultBranch=main "$@"; }
copier_scripts() { # $1 = répertoire de destination
  mkdir -p "$1/keys"
  cp -R "$racine/scripts" "$1/"
  cp "$racine/.xcode-version" "$racine/rust-toolchain.toml" "$1/"
  : > "$1/keys/maintainer.pub"
}
depot="$tmp/depot"
copier_scripts "$depot"
git_test -C "$depot" init -q
git_test -C "$depot" add -A
git_test -C "$depot" commit -q -m "version de test"
git_test -C "$depot" tag "v$version"
commit_tag="$(git -C "$depot" rev-parse "v$version^{commit}")"
sign="$depot/scripts/sign-release.sh"
verify="$depot/scripts/verify-release.sh"

# Clés jetables, créées ici et nulle part ailleurs.
mkdir -p "$tmp/cles"
minisign -G -W -p "$tmp/cles/bonne.pub" -s "$tmp/cles/bonne.key" >/dev/null
minisign -G -W -p "$tmp/cles/intruse.pub" -s "$tmp/cles/intruse.key" >/dev/null

compteur=0
# Crée un répertoire de version factice : $1 = répertoire. Les « binaires » sont de petits fichiers.
faire_dist() {
  mkdir -p "$1"
  for t in "$t_x86" "$t_arm" "$t_mac"; do
    for b in barking-cli barking-node; do
      printf 'binaire factice %s %s\n%s\n' "$b" "$t" "$$-$compteur" > "$1/$b-$version-$t"
      chmod 755 "$1/$b-$version-$t"
    done
  done
  regenerer_sommes "$1"
}
regenerer_sommes() {
  (cd "$1" && for f in barking-cli-* barking-node-*; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done \
    | LC_ALL=C sort -k2 > SHA256SUMS)
}
# Nouvel espace de travail : $D (version à publier), $R (sortie de reconstruction identique).
nouveau() {
  compteur=$((compteur + 1))
  D="$tmp/c$compteur/dist"; R="$tmp/c$compteur/rebuilt"
  faire_dist "$D"
  cp -R "$D" "$R"
}
signer() { # $1 = clé secrète, $2 = clé publique de contrôle (défaut : la bonne)
  lancer "$sign" "$version" --from-dir "$D" --rebuilt-dir "$R" --seckey "$1" --pubkey "${2:-$tmp/cles/bonne.pub}"
}
verifier() { # $1 = clé publique, options en plus
  local pub="$1"; shift
  lancer "$verify" "$version" --from-dir "$D" --pubkey "$pub" --skip-attestation "$@"
}
lancer() {
  CODE=0
  SORTIE="$("$@" 2>&1)" || CODE=$?
}
montrer_sortie() { printf '%s\n' "$SORTIE" | while IFS= read -r l; do echo "    | $l" >&2; done; }
attendre_code() { # $1 = code attendu
  [ "$CODE" -eq "$1" ] || { echo "    code $CODE au lieu de $1 ; sortie :" >&2; montrer_sortie; return 1; }
}
attendre_texte() { # $1 = motif
  printf '%s' "$SORTIE" | grep -q -- "$1" || { echo "    motif absent : $1 ; sortie :" >&2; montrer_sortie; return 1; }
}
sans_minisig() { [ ! -e "$D/SHA256SUMS.minisig" ] || { echo "    SHA256SUMS.minisig ne devait pas exister" >&2; return 1; }; }
signer_ok() { signer "$tmp/cles/bonne.key"; attendre_code 0; }

# Remplace un caractère du corps de la signature (ligne 2 du .minisig).
falsifier_minisig() {
  local f="$1" ligne c n
  ligne="$(sed -n 2p "$f")"; c="${ligne:20:1}"; n="A"; [ "$c" = "A" ] && n="B"
  { sed -n 1p "$f"; printf '%s\n' "${ligne:0:20}$n${ligne:21}"; sed -n '3,$p' "$f"; } > "$f.tmp"
  mv "$f.tmp" "$f"
}

cas_sign_then_verify_ok() {
  nouveau; signer_ok || return 1
  attendre_texte "commit du tag v$version : $commit_tag" || return 1
  minisign -V -m "$D/SHA256SUMS" -x "$D/SHA256SUMS.minisig" -p "$tmp/cles/bonne.pub" 2>&1 \
    | grep -qxF "Trusted comment: barking v$version commit $commit_tag" \
    || { echo "    commentaire signé inattendu" >&2; return 1; }
  verifier "$tmp/cles/bonne.pub"; attendre_code 0 && attendre_texte "vérifiée" && attendre_texte "identique"
}
cas_sign_then_verify_rebuild_ok() {
  nouveau; signer_ok || return 1
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 0 && attendre_texte "vérifiée"
}
cas_forged_signature_rejected() {
  nouveau; signer_ok || return 1
  falsifier_minisig "$D/SHA256SUMS.minisig"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signature invalide"
}
cas_other_key_rejected() {
  nouveau; signer "$tmp/cles/intruse.key" "$tmp/cles/intruse.pub"; attendre_code 0 || return 1
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signature invalide"
}
cas_tampered_binary_rejected() {
  nouveau; signer_ok || return 1
  printf 'X' >> "$D/barking-cli-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "empreinte"
}
cas_tampered_sums_rejected() {
  nouveau; signer_ok || return 1
  c="$(head -c1 "$D/SHA256SUMS")"; n=0; [ "$c" = "0" ] && n=1
  sed "1s/^./$n/" "$D/SHA256SUMS" > "$D/SHA256SUMS.n"
  cmp -s "$D/SHA256SUMS" "$D/SHA256SUMS.n" && { echo "    falsification sans effet" >&2; return 1; }
  mv "$D/SHA256SUMS.n" "$D/SHA256SUMS"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signature invalide"
}
cas_extra_or_missing_binary_rejected() {
  nouveau; signer_ok || return 1
  cp "$D/barking-cli-$version-$t_x86" "$D/barking-cli-$version-extra"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "en trop" || return 1
  rm "$D/barking-cli-$version-extra" "$D/barking-cli-$version-$t_arm"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "manquant"
}
cas_node_binary_checked_like_cli() {
  nouveau; signer_ok || return 1
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 0 || return 1
  # Le binaire du nœud est contrôlé comme celui de la CLI : empreinte, reconstruction, fichier en trop.
  printf 'X' >> "$D/barking-node-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "empreinte incorrecte pour barking-node-" || return 1
  nouveau; signer_ok || return 1
  printf 'autre\n' > "$R/barking-node-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "diffère du binaire publié pour barking-node-" || return 1
  nouveau; signer_ok || return 1
  cp "$D/barking-node-$version-$t_x86" "$D/barking-node-$version-extra"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "en trop" || return 1
  rm "$D/barking-node-$version-extra" "$D/barking-node-$version-$t_arm"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "manquant"
}
cas_mixed_version_or_unknown_name_refused() {
  # Un binaire du nœud d'une autre version, ou un nom inconnu, listé dans SHA256SUMS : refusé à la
  # signature comme à la vérification, même si les empreintes et le fichier sont cohérents.
  local autre
  for autre in "barking-node-9.9.9-$t_x86" "barking-cli-9.9.9-$t_x86" "barking-relay-$version-$t_x86" "barking-node-$version-"; do
    nouveau
    printf 'intrus\n' > "$D/$autre"
    regenerer_sommes "$D"
    # Listé à la main : regenerer_sommes ne connaît que les noms de binaires valides.
    grep -qF "  $autre" "$D/SHA256SUMS" \
      || { printf '%s  %s\n' "$(sha256sum "$D/$autre" | cut -d' ' -f1)" "$autre" >> "$D/SHA256SUMS"; }
    signer "$tmp/cles/bonne.key"
    attendre_code 1 && attendre_texte "entrée inattendue" && sans_minisig || { echo "    cas : $autre" >&2; return 1; }
  done
  nouveau; signer_ok || return 1
  printf 'intrus\n' > "$D/barking-node-9.9.9-$t_x86"
  regenerer_sommes "$D"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 || return 1
}
cas_sign_refuses_on_mismatch() {
  nouveau
  # Binaire remplacé dans --from-dir ; SHA256SUMS régénéré (cohérent), la reconstruction diffère.
  printf 'porte derobee\n' > "$D/barking-cli-$version-$t_x86"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "diff" && sans_minisig || return 1
  # Sans régénérer SHA256SUMS : refusé dès le contrôle des empreintes du répertoire.
  nouveau
  printf 'porte derobee\n' > "$D/barking-cli-$version-$t_arm"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "empreinte incorrecte" && sans_minisig
}
cas_sign_refuses_missing_or_unlisted() {
  nouveau; rm "$D/barking-cli-$version-$t_mac"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "manquant" && sans_minisig || return 1
  nouveau; cp "$D/barking-cli-$version-$t_x86" "$D/barking-cli-$version-extra"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "en trop" && sans_minisig
}
cas_sign_refuses_without_rebuilt_counterpart() {
  nouveau
  # La cible compilable sur cette machine doit avoir une contrepartie reconstruite.
  case "$(uname -m)" in x86_64|amd64) hote="$t_x86" ;; *) hote="$t_arm" ;; esac
  rm "$R/barking-cli-$version-$hote"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "sans recompilation" && sans_minisig || return 1
  nouveau
  rm "$R/barking-node-$version-$hote"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "sans recompilation" && sans_minisig
}
cas_verify_rebuilt_mismatch_rejected() {
  nouveau; signer_ok || return 1
  printf 'autre\n' > "$R/barking-cli-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub" --rebuilt-dir "$R"; attendre_code 1 && attendre_texte "diffère"
}
signer_avec_commentaire() { # $1 = commentaire signé
  minisign -S -m "$D/SHA256SUMS" -s "$tmp/cles/bonne.key" -t "$1" -x "$D/SHA256SUMS.minisig" >/dev/null
}
cas_trusted_comment_other_version_rejected() {
  nouveau; signer_avec_commentaire "barking v9.9.9 commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "commentaire signé"
}
cas_trusted_comment_without_commit_rejected() {
  nouveau; signer_avec_commentaire "barking v$version"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "commentaire signé" || return 1
  nouveau; signer_avec_commentaire "barking v$version commit ${commit_tag:0:39}"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "commentaire signé" || return 1
  # La version est comparée littéralement (le point n'est pas un joker).
  nouveau; signer_avec_commentaire "barking v0x0x1 commit $commit_tag"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "commentaire signé"
}
cas_signed_commit_differs_from_local_tag_rejected() {
  nouveau; signer_ok || return 1
  # Autre clone où le tag v$version désigne un autre commit.
  local autre="$tmp/autre-clone"
  rm -rf "$autre"
  git clone -q "$depot" "$autre"
  git_test -C "$autre" commit -q --allow-empty -m "autre commit"
  git_test -C "$autre" tag -f "v$version" >/dev/null
  lancer "$autre/scripts/verify-release.sh" "$version" --from-dir "$D" --pubkey "$tmp/cles/bonne.pub" --skip-attestation
  attendre_code 1 && attendre_texte "tag déplacé" && attendre_texte "$commit_tag"
}
cas_signed_commit_unchecked_without_local_tag() {
  nouveau; signer_ok || return 1
  # Scripts hors de tout dépôt git : le commit ne peut pas être comparé, c'est annoncé.
  local sans_git="$tmp/sans-git"
  [ -d "$sans_git" ] || copier_scripts "$sans_git"
  lancer "$sans_git/scripts/verify-release.sh" "$version" --from-dir "$D" --pubkey "$tmp/cles/bonne.pub" --skip-attestation
  attendre_code 0 && attendre_texte "n'a pas pu être comparé" && attendre_texte "commit signé par le mainteneur : $commit_tag"
}
cas_sign_refuses_without_local_tag() {
  nouveau
  local sans_git="$tmp/sans-git"
  [ -d "$sans_git" ] || copier_scripts "$sans_git"
  lancer "$sans_git/scripts/sign-release.sh" "$version" --from-dir "$D" --rebuilt-dir "$R" \
    --seckey "$tmp/cles/bonne.key" --pubkey "$tmp/cles/bonne.pub"
  attendre_code 1 && attendre_texte "tag v$version est introuvable" && sans_minisig
}
cas_comment_only_pubkey_rejected() {
  nouveau; signer_ok || return 1
  printf 'untrusted comment: minisign public key AAAA\n' > "$tmp/commentaire.pub"
  verifier "$tmp/commentaire.pub"; attendre_code 1 && attendre_texte "keys/README.md" || return 1
  signer "$tmp/cles/bonne.key" "$tmp/commentaire.pub"; attendre_code 1 && attendre_texte "keys/README.md"
}
cas_sign_wrong_seckey_refused() {
  nouveau
  signer "$tmp/cles/intruse.key"; attendre_code 1 && attendre_texte "ne correspond pas" && sans_minisig
}
cas_rebuild_refuses_tag_without_build_env() {
  nouveau; signer_ok || return 1
  # Le tag du dépôt jetable n'enregistre pas docker/repro.Dockerfile : la recompilation doit refuser
  # plutôt que d'utiliser l'environnement de l'arbre de travail.
  verifier "$tmp/cles/bonne.pub" --rebuild
  attendre_code 1 && attendre_texte "ne contient pas docker/repro.Dockerfile"
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
           node_binary_checked_like_cli mixed_version_or_unknown_name_refused \
           sign_refuses_on_mismatch sign_refuses_missing_or_unlisted sign_refuses_without_rebuilt_counterpart \
           verify_rebuilt_mismatch_rejected trusted_comment_other_version_rejected \
           trusted_comment_without_commit_rejected signed_commit_differs_from_local_tag_rejected \
           signed_commit_unchecked_without_local_tag sign_refuses_without_local_tag \
           rebuild_refuses_tag_without_build_env \
           comment_only_pubkey_rejected sign_wrong_seckey_refused empty_pubkey_rejected; do
  if "cas_$cas"; then echo "PASS $cas"; else echo "FAIL $cas"; echecs=$((echecs + 1)); fi
done
[ "$echecs" -eq 0 ] || { echo "$echecs cas en échec" >&2; exit 1; }
echo "OK : tous les cas passent"
