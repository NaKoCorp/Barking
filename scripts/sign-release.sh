#!/usr/bin/env bash
# Signature d'une version (mainteneur) : recompile, compare, puis signe SHA256SUMS avec minisign.
# Usage : scripts/sign-release.sh <version> --seckey <fichier> [--from-dir <dir>] [--rebuilt-dir <dir>]
#           [--pubkey <fichier>] [--repo <owner/repo>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() { echo "Usage : $0 <version> --seckey <fichier> [--from-dir <dir>] [--rebuilt-dir <dir>] [--pubkey <fichier>] [--repo <owner/repo>]"; }

version=""; from_dir=""; seckey=""; rebuilt_dir=""; pubkey="$racine/keys/maintainer.pub"; repo_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir attend une valeur";    from_dir="$2";    shift 2 ;;
    --seckey)      [ $# -ge 2 ] || erreur "--seckey attend une valeur";      seckey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir attend une valeur"; rebuilt_dir="$2"; shift 2 ;;
    --pubkey)      [ $# -ge 2 ] || erreur "--pubkey attend une valeur";      pubkey="$2";      shift 2 ;;
    --repo)        [ $# -ge 2 ] || erreur "--repo attend une valeur";        repo_arg="$2";    shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) erreur "option inconnue : $1" ;;
    *) [ -z "$version" ] || erreur "version déjà donnée : $version"; version="$1"; shift ;;
  esac
done
[ -n "$version" ] || { usage >&2; exit 1; }
valider_version "$version"
[ -n "$seckey" ] || erreur "--seckey est requis (clé secrète minisign du mainteneur)"
[ -f "$seckey" ] || erreur "clé secrète introuvable : $seckey"
command -v minisign >/dev/null 2>&1 || erreur "minisign est requis"
# La signature produite est contrôlée avant tout dépôt : la clé publique doit donc être valable.
exiger_cle_publique "$pubkey"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-sign.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
# Tout est contrôlé, puis signé, sur cette copie unique.
dir="$tmp/assets"; mkdir -p "$dir"

if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "répertoire introuvable : $from_dir"
  [ -f "$from_dir/SHA256SUMS" ] || erreur "SHA256SUMS absent de $from_dir"
  cp "$from_dir/SHA256SUMS" "$dir/"
  for f in "$from_dir"/barking-cli-*; do
    [ -e "$f" ] || continue
    cp "$f" "$dir/"
  done
else
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour récupérer les assets du brouillon"
  resoudre_repo "$repo_arg" "$racine"; exiger_repo
  gh release download "v$version" -R "$REPO" --dir "$dir" --pattern 'SHA256SUMS' --pattern 'barking-cli-*' \
    || erreur "téléchargement des assets de v$version échoué"
fi

# 1. Cohérence du brouillon : fichiers listés présents, aucun en trop, empreintes exactes.
controler_somme_dir "$dir" "$version"

# 2. Recompilation locale et comparaison.
if [ -n "$rebuilt_dir" ]; then
  [ -d "$rebuilt_dir" ] || erreur "répertoire introuvable : $rebuilt_dir"
  rebuilt="$(cd "$rebuilt_dir" && pwd)"
else
  rebuilt="$tmp/rebuilt"
  recompiler_localement "$racine" "$version" "$rebuilt"
fi
comparer_reconstruction "$dir" "$rebuilt" "$version"

# 3. Signature (la sortie de minisign reste visible : invite de mot de passe d'une vraie clé),
#    contrôlée avec la clé publique avant tout déplacement ou dépôt.
sig="$tmp/SHA256SUMS.minisig"
minisign -S -m "$dir/SHA256SUMS" -s "$seckey" -t "barking v$version" -x "$sig" >&2 \
  || erreur "la signature a échoué"
[ -s "$sig" ] || erreur "signature vide"
minisign -V -m "$dir/SHA256SUMS" -x "$sig" -p "$pubkey" >/dev/null 2>&1 \
  || erreur "la signature produite ne correspond pas à la clé publique $pubkey (mauvaise clé secrète ?) : rien n'est publié"

if [ -n "$from_dir" ]; then
  cp "$sig" "$from_dir/SHA256SUMS.minisig.tmp"
  mv "$from_dir/SHA256SUMS.minisig.tmp" "$from_dir/SHA256SUMS.minisig"
  echo "Version $version signée : $from_dir/SHA256SUMS.minisig"
else
  gh release upload "v$version" "$sig" -R "$REPO" --clobber \
    || erreur "dépôt de SHA256SUMS.minisig échoué"
  gh release edit "v$version" -R "$REPO" --draft=false \
    || erreur "publication du brouillon échouée (SHA256SUMS.minisig a été déposé)"
  echo "Version $version signée et publiée."
fi
