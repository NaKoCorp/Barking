#!/usr/bin/env bash
# Vérification d'une version : signature, empreintes, attestations, et recompilation optionnelle.
# Usage : scripts/verify-release.sh <version> [--from-dir <dir>] [--pubkey <fichier>] [--rebuild]
#           [--rebuilt-dir <dir>] [--skip-attestation] [--repo <owner/repo>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() {
  echo "Usage : $0 <version> [--from-dir <dir>] [--pubkey <fichier>] [--rebuild] [--rebuilt-dir <dir>] [--skip-attestation] [--repo <owner/repo>]"
}

version=""; from_dir=""; pubkey="$racine/keys/maintainer.pub"; rebuild=0; rebuilt_dir=""
skip_att=0; repo_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir attend une valeur";    from_dir="$2";    shift 2 ;;
    --pubkey)      [ $# -ge 2 ] || erreur "--pubkey attend une valeur";      pubkey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir attend une valeur"; rebuilt_dir="$2"; rebuild=1; shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo attend une valeur";        repo_arg="$2";    shift 2 ;;
    --rebuild) rebuild=1; shift ;;
    --skip-attestation) skip_att=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) erreur "option inconnue : $1" ;;
    *) [ -z "$version" ] || erreur "version déjà donnée : $version"; version="$1"; shift ;;
  esac
done
[ -n "$version" ] || { usage >&2; exit 1; }

# Toute erreur est annoncée avec l'étape en cours et fait sortir avec le code 1.
ETAPE="préparation"
erreur() { echo "ÉCHEC à l'étape « $ETAPE » : $*" >&2; exit 1; }
etape() { ETAPE="$2"; echo "$1" >&2; }

command -v minisign >/dev/null 2>&1 || erreur "minisign est requis"

valider_version "$version"

# Clé publique : jamais vide ni sans ligne de clé (le mainteneur ne l'a peut-être pas encore publiée).
exiger_cle_publique "$pubkey"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fichier_xcode_du_tag "$racine" "$version" "$tmp"
# Toutes les étapes travaillent sur cette copie unique (pas de relecture du répertoire d'origine).
dir="$tmp/assets"; mkdir -p "$dir"

resoudre_repo "$repo_arg" "$racine"
if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "répertoire introuvable : $from_dir"
  for f in "$from_dir"/SHA256SUMS "$from_dir"/SHA256SUMS.minisig "$from_dir"/barking-cli-* "$from_dir"/barking-node-*; do
    [ -e "$f" ] || continue
    cp "$f" "$dir/"
  done
else
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour télécharger la version v$version"
  exiger_repo
  gh release download "v$version" -R "$REPO" --dir "$dir" \
    --pattern 'SHA256SUMS' --pattern 'SHA256SUMS.minisig' --pattern 'barking-cli-*' --pattern 'barking-node-*' \
    || erreur "téléchargement des assets de v$version échoué"
fi

# Étape 1 : signature minisign de SHA256SUMS.
etape "1/4 signature de SHA256SUMS…" "signature"
[ -f "$dir/SHA256SUMS" ] || erreur "SHA256SUMS absent de $dir"
[ -f "$dir/SHA256SUMS.minisig" ] || erreur "SHA256SUMS.minisig absent de $dir"
sortie_min="$(minisign -V -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" -p "$pubkey" 2>&1)" \
  || erreur "signature invalide ou clé différente de $pubkey : $sortie_min"
# Commentaire signé attendu : « barking v<version> commit <40 hexa> » (version comparée littéralement).
commentaire="$(printf '%s\n' "$sortie_min" | sed -n 's/^Trusted comment: //p' | head -n1)"
prefixe="barking v$version commit "
commit_signe=""
case "$commentaire" in "$prefixe"*) commit_signe="${commentaire#"$prefixe"}" ;; esac
[[ $commit_signe =~ ^[0-9a-f]{40}$ ]] \
  || erreur "le commentaire signé « $commentaire » n'est pas « barking v$version commit <commit> » (signature d'une autre version ?)"
echo "commit signé par le mainteneur : $commit_signe" >&2
commit_local="$(git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" 2>/dev/null || true)"
if [ -n "$commit_local" ]; then
  [ "$commit_local" = "$commit_signe" ] \
    || erreur "le tag v$version de ce clone désigne le commit $commit_local, mais le mainteneur a signé le commit $commit_signe (tag déplacé ?)"
  echo "commit du tag v$version dans ce clone : identique" >&2
else
  echo "avis : le tag v$version est absent de ce clone ; le commit signé n'a pas pu être comparé localement (git fetch --tags)" >&2
fi

# Étape 2 : empreintes des binaires, sans fichier manquant ni en trop.
etape "2/4 empreintes des binaires…" "empreintes"
controler_somme_dir "$dir" "$version"

# Étape 3 : attestations de provenance GitHub.
if [ "$skip_att" -eq 1 ]; then
  etape "3/4 attestations : ignorées (--skip-attestation)" "attestations"
else
  etape "3/4 attestations de provenance…" "attestations"
  exiger_repo
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour vérifier les attestations (ou --skip-attestation)"
  for nom in $NOMS_LISTES; do
    gh attestation verify "$dir/$nom" -R "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release.yml" \
      --source-ref "refs/tags/v$version" --deny-self-hosted-runners >/dev/null 2>"$tmp/err" \
      || erreur "attestation refusée pour $nom : $(cat "$tmp/err")"
  done
fi

# Étape 4 : recompilation locale (option).
if [ "$rebuild" -eq 1 ]; then
  etape "4/4 recompilation locale…" "recompilation"
  if [ -n "$rebuilt_dir" ]; then
    [ -d "$rebuilt_dir" ] || erreur "répertoire introuvable : $rebuilt_dir"
    rebuilt="$(cd "$rebuilt_dir" && pwd)"
  else
    rebuilt="$tmp/rebuilt"
    recompiler_localement "$racine" "$version" "$rebuilt" "$tmp"
  fi
  comparer_reconstruction "$dir" "$rebuilt" "$version"
else
  etape "4/4 recompilation : non demandée (--rebuild)" "recompilation"
fi

echo "Version $version vérifiée ✓"
