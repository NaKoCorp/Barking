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

# Cibles compilables sur cette machine : cibles Linux musl de l'architecture de l'hôte
# (via Docker) ; aarch64-apple-darwin seulement sur macOS arm64.
cible_compilable_ici() {
  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  case "$1" in
    x86_64-unknown-linux-musl)  case "$arch" in x86_64|amd64) return 0 ;; esac ;;
    aarch64-unknown-linux-musl) case "$arch" in arm64|aarch64) return 0 ;; esac ;;
    aarch64-apple-darwin)       [ "$os" = "Darwin" ] && case "$arch" in arm64|aarch64) return 0 ;; esac ;;
  esac
  return 1
}

# Contrôle SHA256SUMS et les binaires barking-cli-<version>-* d'un répertoire.
# Calcule et compare soi-même les empreintes. Sort en erreur (exit 1) au premier problème.
# Positionne NOMS_LISTES (noms séparés par des espaces).
controler_somme_dir() { # $1 = répertoire, $2 = version
  local dir="$1" version="$2" sums ligne somme nom reel f n
  local motif='^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$'
  local vus="|"
  NOMS_LISTES=""
  sums="$dir/SHA256SUMS"
  [ -s "$sums" ] || erreur "SHA256SUMS absent ou vide dans $dir"
  while IFS= read -r ligne || [ -n "$ligne" ]; do
    [[ $ligne =~ $motif ]] || erreur "ligne illisible dans SHA256SUMS : $ligne"
    somme="${BASH_REMATCH[1]}"; nom="${BASH_REMATCH[2]}"
    case "$nom" in "barking-cli-${version}-"?*) ;; *) erreur "entrée inattendue dans SHA256SUMS (pas un binaire de la version $version) : $nom" ;; esac
    case "$vus" in *"|$nom|"*) erreur "entrée en double dans SHA256SUMS : $nom" ;; esac
    vus="$vus$nom|"
    [ -f "$dir/$nom" ] || erreur "fichier manquant : $nom est listé dans SHA256SUMS mais absent de $dir"
    reel="$(sha256_de "$dir/$nom")" || reel=""
    [ -n "$reel" ] || erreur "calcul de l'empreinte impossible pour $nom"
    [ "$reel" = "$somme" ] || erreur "empreinte incorrecte pour $nom (SHA256SUMS : $somme, fichier : $reel)"
    NOMS_LISTES="$NOMS_LISTES $nom"
  done < "$sums"
  for f in "$dir"/barking-cli-*; do
    [ -e "$f" ] || continue
    n="$(basename "$f")"
    case "$vus" in *"|$n|"*) ;; *) erreur "fichier en trop : $n est présent dans $dir mais absent de SHA256SUMS" ;; esac
  done
  NOMS_LISTES="${NOMS_LISTES# }"
}

# Compare les binaires de $1 (liste NOMS_LISTES) à ceux d'un répertoire produit par repro-build.sh.
comparer_reconstruction() { # $1 = répertoire de la version, $2 = répertoire reconstruit, $3 = version
  local dir="$1" rebuilt="$2" version="$3" nom cible compares=0 h_rec h_pub
  for nom in $NOMS_LISTES; do
    cible="${nom#"barking-cli-${version}-"}"
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
recompiler_localement() { # $1 = racine du dépôt, $2 = version, $3 = répertoire de sortie
  local racine="$1" version="$2" out="$3" nom cible
  mkdir -p "$out"
  for nom in $NOMS_LISTES; do
    cible="${nom#"barking-cli-${version}-"}"
    cible_compilable_ici "$cible" || continue
    echo "recompilation de $cible…" >&2
    "$racine/scripts/repro-build.sh" --target "$cible" --ref "v$version" --out "$out" >/dev/null \
      || erreur "la recompilation de $cible a échoué"
  done
}
