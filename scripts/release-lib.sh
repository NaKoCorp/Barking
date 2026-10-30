#!/usr/bin/env bash
# Fonctions communes à sign-release.sh et verify-release.sh (à sourcer, pas à exécuter).
# Compatible bash 3.2 (macOS) : ni tableau associatif, ni mapfile.

erreur() { echo "erreur : $*" >&2; exit 1; }

# sha256sum n'existe pas partout (macOS) : repli sur shasum.
sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Format de version accepté (sert à construire des noms de fichiers et des tags).
valider_version() {
  [[ $1 =~ ^[0-9A-Za-z.+-]+$ ]] || erreur "version invalide : « $1 » (caractères autorisés : lettres, chiffres, . + -)"
}

# Dépôt GitHub pour gh : $1 (--repo), sinon $BARKING_REPO, sinon l'URL de origin (github https ou ssh).
# Positionne REPO (vide si inconnu). $2 = racine du dépôt git.
resoudre_repo() {
  local url
  REPO="${1:-${BARKING_REPO:-}}"
  if [ -z "$REPO" ]; then
    url="$(git -C "$2" remote get-url origin 2>/dev/null || true)"
    case "$url" in
      https://github.com/*)   REPO="${url#https://github.com/}" ;;
      git@github.com:*)       REPO="${url#git@github.com:}" ;;
      ssh://git@github.com/*) REPO="${url#ssh://git@github.com/}" ;;
    esac
    REPO="${REPO%.git}"
  fi
  return 0
}
exiger_repo() {
  [ -n "$REPO" ] || erreur "dépôt GitHub inconnu : passez --repo <owner/repo> ou définissez BARKING_REPO"
}

# Une clé publique minisign contient une ligne « RW… » (56 caractères base64), pas seulement des commentaires.
exiger_cle_publique() { # $1 = fichier
  [ -f "$1" ] || erreur "clé publique introuvable : $1"
  grep -qE '^RW[A-Za-z0-9+/]{54}$' "$1" \
    || erreur "la clé publique $1 est vide ou invalide : le mainteneur doit d'abord y publier sa clé minisign (voir keys/README.md). Ou passez une clé avec --pubkey <fichier>."
}

# Environnement macOS de la CI, lu dans un fichier .xcode-version (lignes « clé=valeur »).
# Positionne XCODE_ATTENDU et SDK_ATTENDU ; code 1 si le fichier est absent ou incomplet.
lire_xcode_version() { # $1 = fichier
  XCODE_ATTENDU=""; SDK_ATTENDU=""
  [ -f "$1" ] || return 1
  XCODE_ATTENDU="$(sed -n 's/^xcode=//p' "$1" | head -n1)"
  SDK_ATTENDU="$(sed -n 's/^sdk=//p' "$1" | head -n1)"
  [ -n "$XCODE_ATTENDU" ] && [ -n "$SDK_ATTENDU" ]
}

# Cette machine peut-elle reproduire le binaire macOS de la CI ? Il faut rustup (la chaîne officielle
# épinglée par rust-toolchain.toml, pas le rustc de Homebrew) et exactement l'Xcode et le SDK de la CI.
# Code 0 si oui ; sinon 1, avec la raison dans RAISON_DARWIN.
environnement_darwin_conforme() { # $1 = fichier .xcode-version
  local xcode sdk
  RAISON_DARWIN=""
  if ! command -v rustup >/dev/null 2>&1; then
    RAISON_DARWIN="rustup absent (le rustc de Homebrew n'est pas la chaîne officielle épinglée)"
    return 1
  fi
  if ! lire_xcode_version "$1"; then
    RAISON_DARWIN="fichier $1 absent ou incomplet (Xcode de la CI inconnu)"
    return 1
  fi
  xcode="$(xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' | head -n1 || true)"
  sdk="$(xcrun --show-sdk-version 2>/dev/null || true)"
  if [ "$xcode" != "$XCODE_ATTENDU" ] || [ "$sdk" != "$SDK_ATTENDU" ]; then
    RAISON_DARWIN="SDK/Xcode différent de celui de la CI (ici : Xcode ${xcode:-inconnu}, SDK ${sdk:-inconnu} ; CI : Xcode $XCODE_ATTENDU, SDK $SDK_ATTENDU, voir .xcode-version)"
    return 1
  fi
  return 0
}

# Fichier .xcode-version qui décrit l'environnement macOS attendu : celui du tag de la version
# (voir fichier_xcode_du_tag et recompiler_localement), sinon celui de l'arbre de travail.
XCODE_VERSION_FICHIER=""
AVIS_DARWIN_DONNE=0

# Prend le .xcode-version enregistré dans le tag v<version>, s'il existe.
fichier_xcode_du_tag() { # $1 = racine du dépôt, $2 = version, $3 = répertoire de travail
  if git -C "$1" show "v$2:.xcode-version" > "$3/xcode-version-du-tag" 2>/dev/null; then
    XCODE_VERSION_FICHIER="$3/xcode-version-du-tag"
  else
    XCODE_VERSION_FICHIER="$1/.xcode-version"
  fi
}

# Cibles compilables sur cette machine : cibles Linux musl de l'architecture de l'hôte
# (via Docker) ; aarch64-apple-darwin seulement sur macOS arm64, avec rustup et l'Xcode/SDK de la CI.
cible_compilable_ici() {
  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  case "$1" in
    x86_64-unknown-linux-musl)  case "$arch" in x86_64|amd64) return 0 ;; esac ;;
    aarch64-unknown-linux-musl) case "$arch" in arm64|aarch64) return 0 ;; esac ;;
    aarch64-apple-darwin)
      [ "$os" = "Darwin" ] || return 1
      case "$arch" in arm64|aarch64) ;; *) return 1 ;; esac
      environnement_darwin_conforme "$XCODE_VERSION_FICHIER" && return 0
      if [ "$AVIS_DARWIN_DONNE" -eq 0 ]; then
        AVIS_DARWIN_DONNE=1
        echo "avis : aarch64-apple-darwin n'est pas recompilé sur cette machine : $RAISON_DARWIN." >&2
        echo "avis : pour cette cible, la confiance repose sur le double build de la CI, l'attestation de provenance et les reconstructions indépendantes (barking-rebuilds). Seules les cibles Linux de cette machine sont recompilées et comparées." >&2
      fi
      ;;
  esac
  return 1
}

# Cible d'un binaire de la version $2 : « barking-cli-<version>-<cible> » ou « barking-node-<version>-<cible> ».
# Affiche la cible ; code 1 pour tout autre nom (autre binaire, autre version).
# Les cibles publiées sont exactement CIBLES_PUBLIEES : toute autre cible est refusée.
CIBLES_PUBLIEES="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin"
cible_du_nom() { # $1 = nom, $2 = version
  local c
  case "$1" in
    "barking-cli-$2-"?*)  c="${1#"barking-cli-$2-"}" ;;
    "barking-node-$2-"?*) c="${1#"barking-node-$2-"}" ;;
    *) return 1 ;;
  esac
  case " $CIBLES_PUBLIEES " in *" $c "*) printf '%s\n' "$c" ;; *) return 1 ;; esac
}

# Contrôle SHA256SUMS et les binaires barking-cli-<version>-* et barking-node-<version>-* d'un répertoire.
# Calcule et compare soi-même les empreintes. Sort en erreur (exit 1) au premier problème.
# Positionne NOMS_LISTES (noms séparés par des espaces).
controler_somme_dir() { # $1 = répertoire, $2 = version
  local dir="$1" version="$2" sums ligne somme nom reel f n c p
  local motif='^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$'
  local vus="|"
  NOMS_LISTES=""
  sums="$dir/SHA256SUMS"
  [ -s "$sums" ] || erreur "SHA256SUMS absent ou vide dans $dir"
  while IFS= read -r ligne || [ -n "$ligne" ]; do
    [[ $ligne =~ $motif ]] || erreur "ligne illisible dans SHA256SUMS : $ligne"
    somme="${BASH_REMATCH[1]}"; nom="${BASH_REMATCH[2]}"
    cible_du_nom "$nom" "$version" >/dev/null || erreur "entrée inattendue dans SHA256SUMS (pas un binaire barking-cli ou barking-node de la version $version pour une cible publiée : $CIBLES_PUBLIEES) : $nom"
    case "$vus" in *"|$nom|"*) erreur "entrée en double dans SHA256SUMS : $nom" ;; esac
    vus="$vus$nom|"
    [ -f "$dir/$nom" ] || erreur "fichier manquant : $nom est listé dans SHA256SUMS mais absent de $dir"
    reel="$(sha256_de "$dir/$nom")" || reel=""
    [ -n "$reel" ] || erreur "calcul de l'empreinte impossible pour $nom"
    [ "$reel" = "$somme" ] || erreur "empreinte incorrecte pour $nom (SHA256SUMS : $somme, fichier : $reel)"
    NOMS_LISTES="$NOMS_LISTES $nom"
  done < "$sums"
  for f in "$dir"/barking-cli-* "$dir"/barking-node-*; do
    [ -e "$f" ] || continue
    n="$(basename "$f")"
    case "$vus" in *"|$n|"*) ;; *) erreur "fichier en trop : $n est présent dans $dir mais absent de SHA256SUMS" ;; esac
  done
  # Jeu complet exigé : barking-cli et barking-node pour chacune des cibles publiées, ni plus ni moins.
  for c in $CIBLES_PUBLIEES; do
    for p in barking-cli barking-node; do
      case "$vus" in *"|$p-$version-$c|"*) ;; *) erreur "jeu incomplet : $p-$version-$c est absent de SHA256SUMS (barking-cli et barking-node sont exigés pour chaque cible publiée)" ;; esac
    done
  done
  NOMS_LISTES="${NOMS_LISTES# }"
}

# Compare les binaires de $1 (liste NOMS_LISTES) à ceux d'un répertoire produit par repro-build.sh.
comparer_reconstruction() { # $1 = répertoire de la version, $2 = répertoire reconstruit, $3 = version
  local dir="$1" rebuilt="$2" version="$3" nom cible compares=0 h_rec h_pub
  for nom in $NOMS_LISTES; do
    cible="$(cible_du_nom "$nom" "$version")" || erreur "nom de binaire inattendu : $nom"
    if [ -f "$rebuilt/$nom" ]; then
      h_rec="$(sha256_de "$rebuilt/$nom")" || h_rec=""
      h_pub="$(sha256_de "$dir/$nom")" || h_pub=""
      if [ -z "$h_rec" ] || [ -z "$h_pub" ]; then erreur "calcul de l'empreinte impossible pour $nom"; fi
      [ "$h_rec" = "$h_pub" ] \
        || erreur "la recompilation locale diffère du binaire publié pour $nom (build non reproductible ou binaire altéré)"
      compares=$((compares + 1))
    elif cible_compilable_ici "$cible"; then
      erreur "cible compilable sur cette machine sans recompilation correspondante : $nom"
    fi
  done
  [ "$compares" -gt 0 ] || erreur "aucune cible n'a pu être recompilée et comparée sur cette machine"
}

# Recompile avec repro-build.sh chaque cible listée compilable ici, dans $3.
# L'environnement de build (scripts/, docker/, .xcode-version, rust-toolchain.toml) est celui enregistré
# dans le tag v<version>, extrait dans $4 : jamais celui de l'arbre de travail.
recompiler_localement() { # $1 = racine du dépôt, $2 = version, $3 = répertoire de sortie, $4 = répertoire de travail
  local racine="$1" version="$2" out="$3" env="$4/env-du-tag" nom cible chemin faites=" "
  git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" >/dev/null \
    || erreur "le tag v$version est introuvable dans ce clone (git fetch --tags)"
  for chemin in scripts/repro-build.sh scripts/release-lib.sh docker/repro.Dockerfile .xcode-version rust-toolchain.toml; do
    git -C "$racine" cat-file -e "v$version:$chemin" 2>/dev/null \
      || erreur "le tag v$version ne contient pas $chemin : son environnement de build n'est pas enregistré (version antérieure à cette procédure). Recompilez à la main depuis le tag (voir docs/VERIFYING.md)."
  done
  mkdir -p "$env" "$out"
  git -C "$racine" archive --format=tar "v$version" scripts docker .xcode-version rust-toolchain.toml \
    | tar -x -C "$env" || erreur "extraction de l'environnement de build du tag v$version échouée"
  XCODE_VERSION_FICHIER="$env/.xcode-version"
  for nom in $NOMS_LISTES; do
    cible="$(cible_du_nom "$nom" "$version")" || erreur "nom de binaire inattendu : $nom"
    # Une seule reconstruction par cible : repro-build.sh produit déjà les deux binaires.
    case "$faites" in *" $cible "*) continue ;; esac
    cible_compilable_ici "$cible" || continue
    faites="$faites$cible "
    echo "recompilation de $cible (environnement de build du tag v$version)…" >&2
    "$env/scripts/repro-build.sh" --git-dir "$racine" --target "$cible" --ref "v$version" --out "$out" >/dev/null \
      || erreur "la recompilation de $cible a échoué"
  done
}
