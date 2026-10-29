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
skip_att=0; repo="${BARKING_REPO:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir attend une valeur";    from_dir="$2";    shift 2 ;;
    --pubkey)      [ $# -ge 2 ] || erreur "--pubkey attend une valeur";      pubkey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir attend une valeur"; rebuilt_dir="$2"; rebuild=1; shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo attend une valeur";        repo="$2";        shift 2 ;;
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

# Clé publique : jamais vide (le mainteneur ne l'a peut-être pas encore publiée).
[ -f "$pubkey" ] || erreur "clé publique introuvable : $pubkey"
if ! grep -q '[^[:space:]]' "$pubkey"; then
  erreur "la clé publique $pubkey est vide : le mainteneur doit d'abord y publier sa clé minisign (voir keys/README.md). Ou passez une clé avec --pubkey <fichier>."
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "répertoire introuvable : $from_dir"
  dir="$(cd "$from_dir" && pwd)"
else
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour télécharger la version v$version"
  dir="$tmp/assets"; mkdir -p "$dir"
  gh release download "v$version" --dir "$dir" \
    --pattern 'SHA256SUMS' --pattern 'SHA256SUMS.minisig' --pattern 'barking-cli-*' \
    || erreur "téléchargement des assets de v$version échoué"
fi

# Étape 1 : signature minisign de SHA256SUMS.
etape "1/4 signature de SHA256SUMS…" "signature"
[ -f "$dir/SHA256SUMS" ] || erreur "SHA256SUMS absent de $dir"
[ -f "$dir/SHA256SUMS.minisig" ] || erreur "SHA256SUMS.minisig absent de $dir"
sortie_min="$(minisign -V -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig" -p "$pubkey" 2>&1)" \
  || erreur "signature invalide ou clé différente de $pubkey : $sortie_min"
printf '%s\n' "$sortie_min" | grep -q -x "Trusted comment: barking v$version" \
  || erreur "le commentaire signé n'est pas « barking v$version » (signature d'une autre version ?)"

# Étape 2 : empreintes des binaires, sans fichier manquant ni en trop.
etape "2/4 empreintes des binaires…" "empreintes"
controler_somme_dir "$dir" "$version"

# Étape 3 : attestations de provenance GitHub.
if [ "$skip_att" -eq 1 ]; then
  etape "3/4 attestations : ignorées (--skip-attestation)" "attestations"
else
  etape "3/4 attestations de provenance…" "attestations"
  if [ -z "$repo" ]; then
    url="$(git -C "$racine" remote get-url origin 2>/dev/null || true)"
    case "$url" in
      https://github.com/*) repo="${url#https://github.com/}" ;;
      git@github.com:*)     repo="${url#git@github.com:}" ;;
      ssh://git@github.com/*) repo="${url#ssh://git@github.com/}" ;;
    esac
    repo="${repo%.git}"
  fi
  [ -n "$repo" ] || erreur "dépôt GitHub inconnu pour la vérification des attestations : passez --repo <owner/repo> ou définissez BARKING_REPO (ou --skip-attestation)"
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour vérifier les attestations (ou --skip-attestation)"
  for nom in $NOMS_LISTES; do
    gh attestation verify "$dir/$nom" --repo "$repo" >/dev/null 2>"$tmp/err" \
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
    recompiler_localement "$racine" "$version" "$rebuilt"
  fi
  comparer_reconstruction "$dir" "$rebuilt" "$version"
else
  etape "4/4 recompilation : non demandée (--rebuild)" "recompilation"
fi

echo "Version $version vérifiée ✓"
