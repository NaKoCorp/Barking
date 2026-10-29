#!/usr/bin/env bash
# Fuzzing de barking-core, entièrement dans Docker (rien n'est installé sur l'hôte).
# Usage : scripts/fuzz.sh [cible|all] [secondes]      (défaut : all 300)
# Cibles : packet_decode, reassemble, receive, receive_frame.
# Le corpus versionné (crates/barking-core/fuzz/corpus/<cible>/) ne contient que les graines ; les
# entrées découvertes vivent dans un volume Docker, sans salir le dépôt. Un plantage laisse son
# artefact dans crates/barking-core/fuzz/artifacts/<cible>/ et fait sortir le script en erreur.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cibles_connues=(packet_decode reassemble receive receive_frame)

erreur() { echo "erreur : $*" >&2; exit 1; }
usage() { echo "Usage : $0 [cible|all] [secondes]   (cibles : ${cibles_connues[*]})"; }

case "${1:-}" in -h|--help) usage; exit 0 ;; esac
choix="${1:-all}"
duree="${2:-300}"
[ $# -le 2 ] || { usage >&2; exit 2; }
case "$duree" in ''|*[!0-9]*) erreur "durée invalide : $duree (secondes attendues)" ;; esac
[ "$duree" -ge 1 ] || erreur "durée invalide : $duree"

if [ "$choix" = "all" ]; then
  cibles=("${cibles_connues[@]}")
else
  trouve=0
  for c in "${cibles_connues[@]}"; do [ "$c" = "$choix" ] && trouve=1; done
  [ "$trouve" = 1 ] || erreur "cible inconnue : $choix (cibles : ${cibles_connues[*]})"
  cibles=("$choix")
fi

command -v docker >/dev/null 2>&1 || erreur "docker est requis"
docker info >/dev/null 2>&1 || erreur "le démon docker ne répond pas"

dockerfile="$racine/docker/fuzz.Dockerfile"
empreinte="$(shasum -a 256 "$dockerfile" | cut -c1-16)"
image="barking-fuzz:$empreinte"
echo "Construction de l'image $image..." >&2
docker build -q -f "$dockerfile" -t "$image" "$racine/docker" >/dev/null \
  || erreur "construction de l'image de fuzzing échouée"

# Caches : simples accélérateurs (registre cargo, compilation, entrées découvertes).
volume_cargo="barking-fuzz-cargo"
volume_cible="barking-fuzz-target"
volume_travail="barking-fuzz-work"
fuzz_dir="/work/crates/barking-core/fuzz"

lancer() {
  docker run --rm \
    -v "$racine:/work" -v "$volume_cargo:/cargo" -v "$volume_cible:/target" \
    -v "$volume_travail:/fuzzwork" \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
    -w "$fuzz_dir" "$image" "$@"
}

# Corpus initial : produit par le binaire `seed` s'il manque.
if [ -z "$(ls -A "$racine/crates/barking-core/fuzz/corpus/receive" 2>/dev/null)" ] \
  || [ -z "$(ls -A "$racine/crates/barking-core/fuzz/corpus/receive_frame" 2>/dev/null)" ]; then
  echo "Corpus vide : génération des graines..." >&2
  lancer cargo run --release --locked --bin seed -- "$fuzz_dir/corpus" \
    || erreur "génération du corpus échouée"
fi

# cargo-fuzz n'accepte pas --locked : on vérifie que Cargo.lock est à jour avant de lancer.
lancer cargo metadata --locked --format-version 1 >/dev/null \
  || erreur "Cargo.lock du crate de fuzzing n'est pas à jour"

echec=0
for cible in "${cibles[@]}"; do
  echo "=== $cible : ${duree} s ===" >&2
  mkdir -p "$racine/crates/barking-core/fuzz/corpus/$cible"
  # shellcheck disable=SC2016  # les $1 et $2 sont ceux du bash du conteneur
  if ! lancer bash -c '
      mkdir -p "/fuzzwork/$1" && exec cargo fuzz run "$1" "/fuzzwork/$1" "corpus/$1" -- "-max_total_time=$2"
    ' _ "$cible" "$duree"; then
    echec=1
    artefact="$(find "$racine/crates/barking-core/fuzz/artifacts/$cible" -type f -print 2>/dev/null | head -n1 || true)"
    echo "PLANTAGE de la cible $cible. Artefact : ${artefact:-introuvable (voir crates/barking-core/fuzz/artifacts/$cible/)}" >&2
    break
  fi
done

[ "$echec" = 0 ] || exit 1
echo "Aucune cible ne plante (${duree} s chacune)." >&2
