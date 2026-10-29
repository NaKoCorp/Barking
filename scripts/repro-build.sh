#!/usr/bin/env bash
# Build reproductible de barking-cli (spec §15).
# Usage : scripts/repro-build.sh [--target <triple>] [--ref <git-ref>] [--out <dir>]
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

erreur() { echo "erreur : $*" >&2; exit 1; }

sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

cible=""
ref="HEAD"
sortie="$racine/dist"

while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || erreur "--target attend une valeur"; cible="$2"; shift 2 ;;
    --ref)    [ $# -ge 2 ] || erreur "--ref attend une valeur";    ref="$2";   shift 2 ;;
    --out)    [ $# -ge 2 ] || erreur "--out attend une valeur";    sortie="$2"; shift 2 ;;
    -h|--help)
      echo "Usage : $0 [--target <triple>] [--ref <git-ref>] [--out <dir>]"; exit 0 ;;
    *) erreur "option inconnue : $1" ;;
  esac
done

if [ -z "$cible" ]; then
  case "$(uname -m)" in
    x86_64|amd64)  cible="x86_64-unknown-linux-musl" ;;
    arm64|aarch64) cible="aarch64-unknown-linux-musl" ;;
    *) erreur "architecture hôte non prise en charge : $(uname -m)" ;;
  esac
fi

case "$cible" in
  x86_64-unknown-linux-musl)  plateforme="linux/amd64" ;;
  aarch64-unknown-linux-musl) plateforme="linux/arm64" ;;
  aarch64-apple-darwin)       plateforme="" ;;
  *) erreur "cible non prise en charge : $cible" ;;
esac

git -C "$racine" rev-parse --verify --quiet "$ref^{commit}" >/dev/null \
  || erreur "référence git introuvable : $ref"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-repro.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Extraction propre de la référence : l'arbre de travail (éventuellement sale) n'est jamais compilé.
src="$tmp/src"
mkdir -p "$src"
git -C "$racine" archive --format=tar "$ref" | tar -x -C "$src"

version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$src/crates/barking-cli/Cargo.toml" | head -n1)"
[ -n "$version" ] || erreur "version introuvable dans crates/barking-cli/Cargo.toml"
SOURCE_DATE_EPOCH="$(git -C "$racine" log -1 --format=%ct "$ref")"
export SOURCE_DATE_EPOCH

nom="barking-cli-${version}-${cible}"
mkdir -p "$sortie"
sortie="$(cd "$sortie" && pwd)"

if [ "$cible" = "aarch64-apple-darwin" ]; then
  # Build natif (runner macOS), sans notarisation.
  command -v cargo >/dev/null 2>&1 || erreur "cargo est requis pour la cible $cible"
  [ "$(uname -s)" = "Darwin" ] || erreur "la cible $cible se compile sur macOS"
  # Chemins FIXES : OpenSSL (code C vendorisé) enregistre dans le binaire __FILE__, le répertoire de
  # sortie et les CFLAGS verbatim. Aucun chemin aléatoire ni propre à la machine ne doit donc apparaître.
  # Le répertoire est créé atomiquement (verrou) ; s'il existe déjà, un autre build est en cours (ou a planté).
  fixe="/private/tmp/barking-repro-darwin"
  mkdir "$fixe" 2>/dev/null \
    || erreur "$fixe existe déjà : un autre build macOS est en cours, ou un précédent a été interrompu (supprimez ce répertoire)"
  trap 'rm -rf "$tmp" "$fixe"' EXIT
  mv "$src" "$fixe/src"
  src="$fixe/src"
  export CARGO_HOME="$fixe/cargo"
  export RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$CARGO_HOME=/cargo"
  export CFLAGS="-ffile-prefix-map=$src=/build -ffile-prefix-map=$CARGO_HOME=/cargo"
  export CARGO_TARGET_DIR="$fixe/target"
  # Pas d'horodatage de liaison dans l'exécutable.
  export ZERO_AR_DATE=1
  # Cible de déploiement fixe : sinon cc/rustc prennent la version du macOS ou du SDK de la machine.
  export MACOSX_DEPLOYMENT_TARGET="11.0"
  # Avec rustup, rust-toolchain.toml fait foi ; sans rustup, le compilateur du PATH doit avoir la même version.
  if ! command -v rustup >/dev/null 2>&1; then
    canal="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$src/rust-toolchain.toml")"
    [ "$(rustc --version | cut -d' ' -f2)" = "$canal" ] \
      || erreur "rustc $(rustc --version | cut -d' ' -f2) ne correspond pas à la chaîne épinglée $canal (installez rustup)"
  fi
  (cd "$src" && cargo build --release --locked -p barking-cli --target "$cible")
  cp "$CARGO_TARGET_DIR/$cible/release/barking" "$sortie/$nom"
else
  command -v docker >/dev/null 2>&1 || erreur "docker est requis pour la cible $cible"
  empreinte_df="$(sha256_de "$racine/docker/repro.Dockerfile")"
  image="barking-repro:${empreinte_df:0:16}-${plateforme#linux/}"
  docker build --platform "$plateforme" -q -f "$racine/docker/repro.Dockerfile" \
    -t "$image" "$racine/docker" >/dev/null || erreur "construction de l'image de build échouée"
  # Le cache du registre cargo est un simple accélérateur : le binaire n'en dépend pas
  # (--locked et sommes de contrôle de Cargo.lock).
  volume="barking-repro-cargo-${plateforme#linux/}"
  mkdir -p "$tmp/out"
  docker run --rm --platform "$plateforme" \
    -v "$src:/build" -v "$volume:/cargo" -v "$tmp/out:/out" \
    -e SOURCE_DATE_EPOCH -e "TARGET=$cible" -e "NOM=$nom" \
    -e CARGO_HOME=/cargo \
    -w /build "$image" bash -ec '
      export RUSTFLAGS="--remap-path-prefix=/build=/build --remap-path-prefix=$CARGO_HOME=/cargo"
      export CFLAGS="-ffile-prefix-map=/build=/build -ffile-prefix-map=$CARGO_HOME=/cargo"
      export CARGO_TARGET_DIR=/tmp/target
      cargo build --release --locked -p barking-cli --target "$TARGET"
      cp "/tmp/target/$TARGET/release/barking" "/out/$NOM"
    ' || erreur "compilation échouée dans le conteneur"
  cp "$tmp/out/$nom" "$sortie/$nom"
fi

chmod 755 "$sortie/$nom"
somme="$(sha256_de "$sortie/$nom")"

# SHA256SUMS : une ligne par fichier, format sha256sum, trié par nom ; la ligne de ce fichier est remplacée.
sums="$sortie/SHA256SUMS"
{
  if [ -f "$sums" ]; then grep -v -F "  $nom" "$sums" || true; fi
  printf '%s  %s\n' "$somme" "$nom"
} | LC_ALL=C sort -k2 > "$tmp/SHA256SUMS"
cp "$tmp/SHA256SUMS" "$sums"

echo "$somme  $nom"
