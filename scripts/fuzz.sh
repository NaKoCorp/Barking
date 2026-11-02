#!/usr/bin/env bash
# Fuzzing of barking-core and of barking-proto frames, entirely in Docker (nothing is installed on the host).
# Usage: scripts/fuzz.sh [target|all] [seconds]      (default: all 300)
# Targets: packet_decode, reassemble, receive, receive_frame, proto_frame (node protocol frames),
# dht_response (filtering of `Nodes` responses of the hash table), link_files (offer, request,
# bundle and history archive files), card_text (contact cards, text form and stored bytes).
# The versioned corpus (crates/barking-core/fuzz/corpus/<target>/) only contains seeds; discovered
# inputs live in a Docker volume, without dirtying the repository. A crash leaves its
# artifact in crates/barking-core/fuzz/artifacts/<target>/ and makes the script exit with an error.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cibles_connues=(packet_decode reassemble receive receive_frame proto_frame dht_response link_files card_text)

erreur() { echo "error: $*" >&2; exit 1; }
usage() { echo "Usage: $0 [target|all] [seconds]   (targets: ${cibles_connues[*]})"; }

case "${1:-}" in -h|--help) usage; exit 0 ;; esac
choix="${1:-all}"
duree="${2:-300}"
[ $# -le 2 ] || { usage >&2; exit 2; }
case "$duree" in ''|*[!0-9]*) erreur "invalid duration: $duree (seconds expected)" ;; esac
[ "$duree" -ge 1 ] || erreur "invalid duration: $duree"

if [ "$choix" = "all" ]; then
  cibles=("${cibles_connues[@]}")
else
  trouve=0
  for c in "${cibles_connues[@]}"; do [ "$c" = "$choix" ] && trouve=1; done
  [ "$trouve" = 1 ] || erreur "unknown target: $choix (targets: ${cibles_connues[*]})"
  cibles=("$choix")
fi

command -v docker >/dev/null 2>&1 || erreur "docker is required"
docker info >/dev/null 2>&1 || erreur "the docker daemon is not responding"

dockerfile="$racine/docker/fuzz.Dockerfile"
if command -v sha256sum >/dev/null 2>&1; then
  empreinte="$(sha256sum "$dockerfile" | cut -c1-16)"
else
  empreinte="$(shasum -a 256 "$dockerfile" | cut -c1-16)"
fi
image="barking-fuzz:$empreinte"
echo "Building image $image..." >&2
docker build -f "$dockerfile" -t "$image" "$racine/docker" >&2 \
  || erreur "building the fuzzing image failed (log above)"

# Caches: simple accelerators (cargo registry, build, discovered inputs).
volume_cargo="barking-fuzz-cargo"
volume_cible="barking-fuzz-target"
volume_travail="barking-fuzz-work"
fuzz_dir="/work/crates/barking-core/fuzz"

# The container runs as root (cache volumes, HOME); on exit, the files written to the repository
# (corpus, artifacts) are handed back to the host user, otherwise they would stay owned by root on Linux.
lancer() {
  # shellcheck disable=SC2016  # the script is interpreted by the container's bash
  docker run --rm \
    -v "$racine:/work" -v "$volume_cargo:/cargo" -v "$volume_cible:/target" \
    -v "$volume_travail:/fuzzwork" \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
    -e "HOTE_UID=$(id -u)" -e "HOTE_GID=$(id -g)" \
    -w "$fuzz_dir" "$image" bash -c '
      trap "chown -R \"$HOTE_UID:$HOTE_GID\" /work/crates/barking-core/fuzz" EXIT
      "$@"
    ' _ "$@"
}

# Initial corpus: produced by the `seed` binary for targets whose corpus is empty.
corpus_vide() { [ -z "$(ls -A "$racine/crates/barking-core/fuzz/corpus/$1" 2>/dev/null)" ]; }
for c in packet_decode receive receive_frame; do
  if corpus_vide "$c"; then
    echo "Corpus of $c is empty: generating seeds..." >&2
    lancer cargo run --release --locked --bin seed -- "$fuzz_dir/corpus" "$c" \
      || erreur "corpus generation failed"
  fi
done

# cargo-fuzz does not accept --locked: we check that Cargo.lock is up to date before running.
lancer cargo metadata --locked --format-version 1 >/dev/null \
  || erreur "the fuzzing crate's Cargo.lock is not up to date"

echec=()
for cible in "${cibles[@]}"; do
  echo "=== $cible: ${duree} s ===" >&2
  mkdir -p "$racine/crates/barking-core/fuzz/corpus/$cible"
  # shellcheck disable=SC2016  # $1 and $2 are those of the container's bash
  if ! lancer bash -c '
      mkdir -p "/fuzzwork/$1" && cargo fuzz run "$1" "/fuzzwork/$1" "corpus/$1" -- "-max_total_time=$2" -timeout=10 -rss_limit_mb=2048
    ' _ "$cible" "$duree"; then
    echec+=("$cible")
    artefact="$(find "$racine/crates/barking-core/fuzz/artifacts/$cible" -type f -print 2>/dev/null | head -n1 || true)"
    echo "CRASH of target $cible. Artifact: ${artefact:-not found (see crates/barking-core/fuzz/artifacts/$cible/)}" >&2
  fi
done

if [ "${#echec[@]}" -gt 0 ]; then
  echo "Failed targets: ${echec[*]}" >&2
  exit 1
fi
echo "No target crashes (${duree} s each)." >&2
