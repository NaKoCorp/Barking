#!/usr/bin/env bash
# Signature d'une version (mainteneur) : recompile, compare, puis signe SHA256SUMS avec minisign.
# Usage : scripts/sign-release.sh <version> --seckey <fichier> [--from-dir <dir>] [--rebuilt-dir <dir>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-lib.sh
. "$racine/scripts/release-lib.sh"

usage() { echo "Usage : $0 <version> --seckey <fichier> [--from-dir <dir>] [--rebuilt-dir <dir>]"; }

version=""; from_dir=""; seckey=""; rebuilt_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from-dir)    [ $# -ge 2 ] || erreur "--from-dir attend une valeur";    from_dir="$2";    shift 2 ;;
    --seckey)      [ $# -ge 2 ] || erreur "--seckey attend une valeur";      seckey="$2";      shift 2 ;;
    --rebuilt-dir) [ $# -ge 2 ] || erreur "--rebuilt-dir attend une valeur"; rebuilt_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) erreur "option inconnue : $1" ;;
    *) [ -z "$version" ] || erreur "version déjà donnée : $version"; version="$1"; shift ;;
  esac
done
[ -n "$version" ] || { usage >&2; exit 1; }
[ -n "$seckey" ] || erreur "--seckey est requis (clé secrète minisign du mainteneur)"
[ -f "$seckey" ] || erreur "clé secrète introuvable : $seckey"
command -v minisign >/dev/null 2>&1 || erreur "minisign est requis"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-sign.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

if [ -n "$from_dir" ]; then
  [ -d "$from_dir" ] || erreur "répertoire introuvable : $from_dir"
  dir="$(cd "$from_dir" && pwd)"
else
  command -v gh >/dev/null 2>&1 || erreur "gh est requis pour récupérer les assets du brouillon"
  dir="$tmp/assets"; mkdir -p "$dir"
  gh release download "v$version" --dir "$dir" --pattern 'SHA256SUMS' --pattern 'barking-cli-*' \
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

# 3. Signature, écrite dans un fichier temporaire puis déplacée seulement après succès.
minisign -S -m "$dir/SHA256SUMS" -s "$seckey" -t "barking v$version" -x "$tmp/SHA256SUMS.minisig" >/dev/null \
  || erreur "la signature a échoué"
[ -s "$tmp/SHA256SUMS.minisig" ] || erreur "signature vide"

if [ -n "$from_dir" ]; then
  mv "$tmp/SHA256SUMS.minisig" "$dir/SHA256SUMS.minisig"
  echo "Version $version signée : $dir/SHA256SUMS.minisig"
else
  gh release upload "v$version" "$tmp/SHA256SUMS.minisig" --clobber \
    || erreur "dépôt de SHA256SUMS.minisig échoué"
  gh release edit "v$version" --draft=false \
    || erreur "publication du brouillon échouée (SHA256SUMS.minisig a été déposé)"
  echo "Version $version signée et publiée."
fi
