#!/usr/bin/env bash
# Test: the runtime images of barking-node and barking-push build from a
# release directory (binaries and SHA256SUMS, see scripts/repro-build.sh) for
# the architecture of the host, start, report the expected version and run as
# the unprivileged user.
# Usage: scripts/tests/images.sh <release-dir> <version>
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echec() { echo "FAILURE: $*" >&2; exit 1; }

[ $# -eq 2 ] || { echo "Usage: $0 <release-dir> <version>" >&2; exit 2; }
[ -d "$1" ] || echec "release directory not found: $1"
[ -n "$2" ] || echec "the version is empty"
command -v docker >/dev/null 2>&1 || echec "docker is required for this test"
sortie="$(cd "$1" && pwd)"
version="$2"

trap 'docker image rm -f barking-node:test barking-push:test >/dev/null 2>&1 || true' EXIT

# $1 = binary name; the remaining arguments are added to the build.
controler_image() {
  local nom="$1" image="$1:test" affiche utilisateur
  shift
  docker build -q -f "$racine/docker/${nom#barking-}.Dockerfile" "$@" \
    --build-arg "VERSION=$version" -t "$image" "$sortie" >/dev/null \
    || echec "building $image failed"
  affiche="$(docker run --rm "$image" --version)" || echec "$image --version failed"
  echo "$image --version: $affiche"
  [ "$affiche" = "$nom $version" ] \
    || echec "$image --version printed « $affiche », expected « $nom $version »"
  utilisateur="$(docker image inspect --format '{{.Config.User}}' "$image")" \
    || echec "inspecting $image failed"
  [ "$utilisateur" = "65532:65532" ] \
    || echec "$image runs as « $utilisateur », expected 65532:65532"
}

controler_image barking-node
controler_image barking-push --build-context "apk=$racine/docker/apk"

echo "OK: barking-node and barking-push images build, start and run as 65532:65532"
