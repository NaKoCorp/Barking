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
if command -v sha256sum >/dev/null 2>&1; then
  empreinte="$(sha256sum "$dockerfile" | cut -c1-16)"
else
  empreinte="$(shasum -a 256 "$dockerfile" | cut -c1-16)"
fi
image="barking-fuzz:$empreinte"
echo "Construction de l'image $image..." >&2
docker build -f "$dockerfile" -t "$image" "$racine/docker" >&2 \
  || erreur "construction de l'image de fuzzing échouée (journal ci-dessus)"

# Caches : simples accélérateurs (registre cargo, compilation, entrées découvertes).
volume_cargo="barking-fuzz-cargo"
volume_cible="barking-fuzz-target"
volume_travail="barking-fuzz-work"
fuzz_dir="/work/crates/barking-core/fuzz"

# Le conteneur tourne en root (volumes de cache, HOME) ; à la sortie, les fichiers écrits dans le dépôt
# (corpus, artefacts) sont rendus à l'utilisateur de l'hôte, sinon ils resteraient à root sous Linux.
lancer() {
  # shellcheck disable=SC2016  # le script est interprété par le bash du conteneur
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

# Corpus initial : produit par le binaire `seed` pour les cibles dont le corpus est vide.
corpus_vide() { [ -z "$(ls -A "$racine/crates/barking-core/fuzz/corpus/$1" 2>/dev/null)" ]; }
for c in packet_decode receive receive_frame; do
  if corpus_vide "$c"; then
    echo "Corpus de $c vide : génération des graines..." >&2
    lancer cargo run --release --locked --bin seed -- "$fuzz_dir/corpus" "$c" \
      || erreur "génération du corpus échouée"
  fi
done

# cargo-fuzz n'accepte pas --locked : on vérifie que Cargo.lock est à jour avant de lancer.
lancer cargo metadata --locked --format-version 1 >/dev/null \
  || erreur "Cargo.lock du crate de fuzzing n'est pas à jour"

echec=()
for cible in "${cibles[@]}"; do
  echo "=== $cible : ${duree} s ===" >&2
  mkdir -p "$racine/crates/barking-core/fuzz/corpus/$cible"
  # shellcheck disable=SC2016  # les $1 et $2 sont ceux du bash du conteneur
  if ! lancer bash -c '
      mkdir -p "/fuzzwork/$1" && cargo fuzz run "$1" "/fuzzwork/$1" "corpus/$1" -- "-max_total_time=$2" -timeout=10 -rss_limit_mb=2048
    ' _ "$cible" "$duree"; then
    echec+=("$cible")
    artefact="$(find "$racine/crates/barking-core/fuzz/artifacts/$cible" -type f -print 2>/dev/null | head -n1 || true)"
    echo "PLANTAGE de la cible $cible. Artefact : ${artefact:-introuvable (voir crates/barking-core/fuzz/artifacts/$cible/)}" >&2
  fi
done

if [ "${#echec[@]}" -gt 0 ]; then
  echo "Cibles en échec : ${echec[*]}" >&2
  exit 1
fi
echo "Aucune cible ne plante (${duree} s chacune)." >&2
