#!/usr/bin/env bash
# Test : signature et vérification des versions (sign-release.sh, verify-release.sh).
# Lancé depuis l'hôte, il se relance lui-même dans un conteneur (minisign, aucun réseau requis).
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

sign="$racine/scripts/sign-release.sh"
verify="$racine/scripts/verify-release.sh"
version="0.0.1"
t_x86="x86_64-unknown-linux-musl"
t_arm="aarch64-unknown-linux-musl"
t_mac="aarch64-apple-darwin"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Clés jetables, créées ici et nulle part ailleurs.
mkdir -p "$tmp/cles"
minisign -G -W -p "$tmp/cles/bonne.pub" -s "$tmp/cles/bonne.key" >/dev/null
minisign -G -W -p "$tmp/cles/intruse.pub" -s "$tmp/cles/intruse.key" >/dev/null

compteur=0
# Crée un répertoire de version factice : $1 = répertoire. Les « binaires » sont de petits fichiers.
faire_dist() {
  mkdir -p "$1"
  for t in "$t_x86" "$t_arm" "$t_mac"; do
    printf 'binaire factice %s\n%s\n' "$t" "$$-$compteur" > "$1/barking-cli-$version-$t"
    chmod 755 "$1/barking-cli-$version-$t"
  done
  regenerer_sommes "$1"
}
regenerer_sommes() {
  (cd "$1" && for f in barking-cli-*; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done \
    | LC_ALL=C sort -k2 > SHA256SUMS)
}
# Nouvel espace de travail : $D (version à publier), $R (sortie de reconstruction identique).
nouveau() {
  compteur=$((compteur + 1))
  D="$tmp/c$compteur/dist"; R="$tmp/c$compteur/rebuilt"
  faire_dist "$D"
  cp -R "$D" "$R"
}
signer() { # $1 = clé secrète
  lancer "$sign" "$version" --from-dir "$D" --rebuilt-dir "$R" --seckey "$1"
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
  verifier "$tmp/cles/bonne.pub"; attendre_code 0 && attendre_texte "vérifiée"
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
  nouveau; signer "$tmp/cles/intruse.key"; attendre_code 0 || return 1
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "signature invalide"
}
cas_tampered_binary_rejected() {
  nouveau; signer_ok || return 1
  printf 'X' >> "$D/barking-cli-$version-$t_x86"
  verifier "$tmp/cles/bonne.pub"; attendre_code 1 && attendre_texte "empreinte"
}
cas_tampered_sums_rejected() {
  nouveau; signer_ok || return 1
  sed '1s/^./0/;1s/^0/1/' "$D/SHA256SUMS" > "$D/SHA256SUMS.n"
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
cas_sign_refuses_on_mismatch() {
  nouveau
  # Binaire remplacé dans --from-dir ; SHA256SUMS régénéré (cohérent), la reconstruction diffère.
  printf 'porte derobee\n' > "$D/barking-cli-$version-$t_x86"
  regenerer_sommes "$D"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && attendre_texte "diff" && sans_minisig || return 1
  # Même chose sans régénérer SHA256SUMS : refusé aussi.
  nouveau
  printf 'porte derobee\n' > "$D/barking-cli-$version-$t_arm"
  signer "$tmp/cles/bonne.key"; attendre_code 1 && sans_minisig
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
  signer "$tmp/cles/bonne.key"; attendre_code 1 && sans_minisig
}
cas_empty_pubkey_rejected() {
  nouveau; signer_ok || return 1
  [ ! -s "$racine/keys/maintainer.pub" ] || { echo "    keys/maintainer.pub devrait être vide" >&2; return 1; }
  lancer "$verify" "$version" --from-dir "$D" --skip-attestation
  attendre_code 1 && attendre_texte "keys/README.md"
}

echecs=0
for cas in sign_then_verify_ok sign_then_verify_rebuild_ok forged_signature_rejected other_key_rejected \
           tampered_binary_rejected tampered_sums_rejected extra_or_missing_binary_rejected \
           sign_refuses_on_mismatch sign_refuses_missing_or_unlisted sign_refuses_without_rebuilt_counterpart \
           empty_pubkey_rejected; do
  if "cas_$cas"; then echo "PASS $cas"; else echo "FAIL $cas"; echecs=$((echecs + 1)); fi
done
[ "$echecs" -eq 0 ] || { echo "$echecs cas en échec" >&2; exit 1; }
echo "OK : tous les cas passent"
