#!/usr/bin/env bash
# Test : deux builds depuis deux clones à des chemins différents donnent les mêmes empreintes.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-repro-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echec() { echo "ÉCHEC : $*" >&2; exit 1; }

a="$tmp/a"
b="$tmp/un/chemin/bien/plus/long"
mkdir -p "$(dirname "$b")"
git clone -q --no-hardlinks "$racine" "$a"
git clone -q --no-hardlinks "$racine" "$b"
# Même commit dans les deux clones (celui de HEAD du dépôt courant).
commit="$(git -C "$racine" rev-parse HEAD)"
git -C "$a" checkout -q "$commit"
git -C "$b" checkout -q "$commit"

cible_args=()
[ -n "${REPRO_TARGET:-}" ] && cible_args=(--target "$REPRO_TARGET")

"$a/scripts/repro-build.sh" ${cible_args[@]+"${cible_args[@]}"} --ref "$commit" --out "$tmp/out-a" \
  || echec "premier build (code de sortie non nul)"
"$b/scripts/repro-build.sh" ${cible_args[@]+"${cible_args[@]}"} --ref "$commit" --out "$tmp/out-b" \
  || echec "second build (code de sortie non nul)"

diff "$tmp/out-a/SHA256SUMS" "$tmp/out-b/SHA256SUMS" \
  || echec "les SHA256SUMS diffèrent entre les deux builds"

# Les deux binaires sont produits et listés dans SHA256SUMS (triés).
for b in barking-cli barking-node; do
  [ "$(grep -c "  $b-" "$tmp/out-a/SHA256SUMS")" -eq 1 ] || echec "SHA256SUMS doit lister exactement un $b"
  [ "$(find "$tmp/out-a" -type f -name "$b-*" | wc -l | tr -d ' ')" -eq 1 ] || echec "il faut exactement un binaire $b"
  cmp "$(find "$tmp/out-a" -type f -name "$b-*")" "$(find "$tmp/out-b" -type f -name "$b-*")" \
    || echec "les deux builds de $b diffèrent"
done
[ "$(wc -l < "$tmp/out-a/SHA256SUMS" | tr -d ' ')" -eq 2 ] || echec "SHA256SUMS doit contenir exactement deux lignes"
LC_ALL=C sort -c -k2 "$tmp/out-a/SHA256SUMS" || echec "SHA256SUMS n'est pas trié"

# Les binaires produits s'exécutent (dans un conteneur si ce sont des binaires Linux).
for b in barking-cli barking-node; do
  bin="$(find "$tmp/out-a" -type f -name "$b-*" | head -n1)"
  [ -n "$bin" ] || echec "aucun artefact $b produit"
  case "$bin" in
    *-linux-musl)
      arch="amd64"; case "$bin" in *aarch64*) arch="arm64" ;; esac
      docker run --rm --platform "linux/$arch" -v "$bin:/$b:ro" \
        debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 "/$b" --help >/dev/null \
        || echec "$b --help a échoué" ;;
    *) "$bin" --help >/dev/null || echec "$b --help a échoué" ;;
  esac
done

echo "OK : builds identiques ($(cat "$tmp/out-a/SHA256SUMS"))"
