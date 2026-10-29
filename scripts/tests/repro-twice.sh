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

# Le binaire produit s'exécute (dans un conteneur si c'est un binaire Linux).
bin="$(find "$tmp/out-a" -type f -name 'barking-cli-*' | head -n1)"
[ -n "$bin" ] || echec "aucun artefact produit"
case "$bin" in
  *-linux-musl)
    arch="amd64"; case "$bin" in *aarch64*) arch="arm64" ;; esac
    docker run --rm --platform "linux/$arch" -v "$bin:/barking-cli:ro" \
      debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 /barking-cli --help >/dev/null \
      || echec "barking-cli --help a échoué" ;;
  *) "$bin" --help >/dev/null || echec "barking-cli --help a échoué" ;;
esac

echo "OK : builds identiques ($(cat "$tmp/out-a/SHA256SUMS"))"
