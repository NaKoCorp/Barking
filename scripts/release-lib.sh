#!/usr/bin/env bash
# Functions shared by sign-release.sh and verify-release.sh (to be sourced, not executed).
# Compatible with bash 3.2 (macOS): no associative arrays, no mapfile.

erreur() { echo "error: $*" >&2; exit 1; }

# Version of the workspace: the `version` key of the [workspace.package] section of <dir>/Cargo.toml
# (the single source of truth; every crate inherits it). Reads the file only, no cargo needed.
version_du_workspace() { # $1 = directory containing the workspace Cargo.toml
  local v
  [ -f "$1/Cargo.toml" ] || erreur "Cargo.toml not found in $1"
  v="$(awk '
    /^[[:space:]]*\[/ { en_section = ($0 ~ /^[[:space:]]*\[workspace\.package\][[:space:]]*(#.*)?$/); next }
    en_section && /^[[:space:]]*version[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*"/, ""); sub(/".*$/, ""); print; exit
    }' "$1/Cargo.toml")"
  [ -n "$v" ] || erreur "version not found in [workspace.package] of $1/Cargo.toml"
  printf '%s\n' "$v"
}

# sha256sum is not available everywhere (macOS): fall back to shasum.
sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Accepted version format (used to build file names and tags).
valider_version() {
  [[ $1 =~ ^[0-9A-Za-z.+-]+$ ]] || erreur "invalid version: « $1 » (allowed characters: letters, digits, . + -)"
}

# GitHub repository for gh: $1 (--repo), otherwise $BARKING_REPO, otherwise the origin URL (github https or ssh).
# Sets REPO (empty if unknown). $2 = root of the git repository.
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
  [ -n "$REPO" ] || erreur "unknown GitHub repository: pass --repo <owner/repo> or set BARKING_REPO"
}

# A minisign public key contains an « RW… » line (56 base64 characters), not just comments.
exiger_cle_publique() { # $1 = fichier
  [ -f "$1" ] || erreur "public key not found: $1"
  grep -qE '^RW[A-Za-z0-9+/]{54}$' "$1" \
    || erreur "the public key $1 is empty or invalid: the maintainer must first publish their minisign key there (see keys/README.md). Or pass a key with --pubkey <file>."
}

# CI macOS environment, read from an .xcode-version file (« key=value » lines).
# Sets XCODE_ATTENDU and SDK_ATTENDU; returns 1 if the file is missing or incomplete.
lire_xcode_version() { # $1 = fichier
  XCODE_ATTENDU=""; SDK_ATTENDU=""
  [ -f "$1" ] || return 1
  XCODE_ATTENDU="$(sed -n 's/^xcode=//p' "$1" | head -n1)"
  SDK_ATTENDU="$(sed -n 's/^sdk=//p' "$1" | head -n1)"
  [ -n "$XCODE_ATTENDU" ] && [ -n "$SDK_ATTENDU" ]
}

# Can this machine reproduce the CI's macOS binary? It needs rustup (the official toolchain
# pinned by rust-toolchain.toml, not Homebrew's rustc) and exactly the CI's Xcode and SDK.
# Returns 0 if so; otherwise 1, with the reason in RAISON_DARWIN.
environnement_darwin_conforme() { # $1 = fichier .xcode-version
  local xcode sdk
  RAISON_DARWIN=""
  if ! command -v rustup >/dev/null 2>&1; then
    RAISON_DARWIN="rustup missing (Homebrew's rustc is not the official pinned toolchain)"
    return 1
  fi
  if ! lire_xcode_version "$1"; then
    RAISON_DARWIN="file $1 missing or incomplete (CI Xcode unknown)"
    return 1
  fi
  xcode="$(xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' | head -n1 || true)"
  sdk="$(xcrun --show-sdk-version 2>/dev/null || true)"
  if [ "$xcode" != "$XCODE_ATTENDU" ] || [ "$sdk" != "$SDK_ATTENDU" ]; then
    RAISON_DARWIN="Xcode/SDK differs from the CI's (here: Xcode ${xcode:-unknown}, SDK ${sdk:-unknown}; CI: Xcode $XCODE_ATTENDU, SDK $SDK_ATTENDU, see .xcode-version)"
    return 1
  fi
  return 0
}

# .xcode-version file describing the expected macOS environment: the one from the release tag
# (see fichier_xcode_du_tag and recompiler_localement), otherwise the working tree's.
XCODE_VERSION_FICHIER=""
AVIS_DARWIN_DONNE=0

# Takes the .xcode-version recorded in tag v<version>, if it exists.
fichier_xcode_du_tag() { # $1 = repository root, $2 = version, $3 = working directory
  if git -C "$1" show "v$2:.xcode-version" > "$3/xcode-version-du-tag" 2>/dev/null; then
    XCODE_VERSION_FICHIER="$3/xcode-version-du-tag"
  else
    XCODE_VERSION_FICHIER="$1/.xcode-version"
  fi
}

# Targets buildable on this machine: Linux musl targets of the host architecture
# (via Docker); aarch64-apple-darwin only on macOS arm64, with rustup and the CI's Xcode/SDK.
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
        echo "notice: aarch64-apple-darwin is not rebuilt on this machine: $RAISON_DARWIN." >&2
        echo "notice: for this target, trust rests on the CI double build, the provenance attestation and the independent rebuilds (barking-rebuilds). Only this machine's Linux targets are rebuilt and compared." >&2
      fi
      ;;
  esac
  return 1
}

# Target of a binary of version $2: « barking-cli-<version>-<target> », « barking-node-<version>-<target> » or
# « barking-push-<version>-<target> ».
# Prints the target; returns 1 for any other name (other binary, other version).
# The published targets are exactly CIBLES_PUBLIEES: any other target is refused.
CIBLES_PUBLIEES="x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin"
cible_du_nom() { # $1 = nom, $2 = version
  local c
  case "$1" in
    "barking-cli-$2-"?*)  c="${1#"barking-cli-$2-"}" ;;
    "barking-node-$2-"?*) c="${1#"barking-node-$2-"}" ;;
    "barking-push-$2-"?*) c="${1#"barking-push-$2-"}" ;;
    *) return 1 ;;
  esac
  case " $CIBLES_PUBLIEES " in *" $c "*) printf '%s\n' "$c" ;; *) return 1 ;; esac
}

# Checks SHA256SUMS and the barking-cli-<version>-*, barking-node-<version>-* and barking-push-<version>-* binaries of a directory.
# Computes and compares the checksums itself. Exits with an error (exit 1) at the first problem.
# Sets NOMS_LISTES (names separated by spaces).
controler_somme_dir() { # $1 = directory, $2 = version
  local dir="$1" version="$2" sums ligne somme nom reel f n c p
  local motif='^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$'
  local vus="|"
  NOMS_LISTES=""
  sums="$dir/SHA256SUMS"
  [ -s "$sums" ] || erreur "SHA256SUMS missing or empty in $dir"
  while IFS= read -r ligne || [ -n "$ligne" ]; do
    [[ $ligne =~ $motif ]] || erreur "unreadable line in SHA256SUMS: $ligne"
    somme="${BASH_REMATCH[1]}"; nom="${BASH_REMATCH[2]}"
    cible_du_nom "$nom" "$version" >/dev/null || erreur "unexpected entry in SHA256SUMS (not a barking-cli, barking-node or barking-push binary of version $version for a published target: $CIBLES_PUBLIEES): $nom"
    case "$vus" in *"|$nom|"*) erreur "duplicate entry in SHA256SUMS: $nom" ;; esac
    vus="$vus$nom|"
    [ -f "$dir/$nom" ] || erreur "missing file: $nom is listed in SHA256SUMS but absent from $dir"
    reel="$(sha256_de "$dir/$nom")" || reel=""
    [ -n "$reel" ] || erreur "cannot compute the checksum for $nom"
    [ "$reel" = "$somme" ] || erreur "incorrect checksum for $nom (SHA256SUMS: $somme, file: $reel)"
    NOMS_LISTES="$NOMS_LISTES $nom"
  done < "$sums"
  for f in "$dir"/barking-cli-* "$dir"/barking-node-* "$dir"/barking-push-*; do
    [ -e "$f" ] || continue
    n="$(basename "$f")"
    case "$vus" in *"|$n|"*) ;; *) erreur "extra file: $n is present in $dir but absent from SHA256SUMS" ;; esac
  done
  # Complete set required: barking-cli, barking-node and barking-push for each published target, no more, no less.
  for c in $CIBLES_PUBLIEES; do
    for p in barking-cli barking-node barking-push; do
      case "$vus" in *"|$p-$version-$c|"*) ;; *) erreur "incomplete set: $p-$version-$c is absent from SHA256SUMS (barking-cli, barking-node and barking-push are required for each published target)" ;; esac
    done
  done
  NOMS_LISTES="${NOMS_LISTES# }"
}

# Compares the binaries of $1 (list NOMS_LISTES) with those of a directory produced by repro-build.sh.
comparer_reconstruction() { # $1 = release directory, $2 = rebuilt directory, $3 = version
  local dir="$1" rebuilt="$2" version="$3" nom cible compares=0 h_rec h_pub
  for nom in $NOMS_LISTES; do
    cible="$(cible_du_nom "$nom" "$version")" || erreur "unexpected binary name: $nom"
    if [ -f "$rebuilt/$nom" ]; then
      h_rec="$(sha256_de "$rebuilt/$nom")" || h_rec=""
      h_pub="$(sha256_de "$dir/$nom")" || h_pub=""
      if [ -z "$h_rec" ] || [ -z "$h_pub" ]; then erreur "cannot compute the checksum for $nom"; fi
      [ "$h_rec" = "$h_pub" ] \
        || erreur "the local rebuild differs from the published binary for $nom (non-reproducible build or tampered binary)"
      compares=$((compares + 1))
    elif cible_compilable_ici "$cible"; then
      erreur "target buildable on this machine without a corresponding rebuild: $nom"
    fi
  done
  [ "$compares" -gt 0 ] || erreur "no target could be rebuilt and compared on this machine"
}

# Rebuilds with repro-build.sh each listed target buildable here, into $3.
# The build environment (scripts/, docker/, .xcode-version, rust-toolchain.toml) is the one recorded
# in tag v<version>, extracted into $4: never the working tree's.
recompiler_localement() { # $1 = repository root, $2 = version, $3 = output directory, $4 = working directory
  local racine="$1" version="$2" out="$3" env="$4/env-du-tag" nom cible chemin faites=" "
  git -C "$racine" rev-parse --verify --quiet "v$version^{commit}" >/dev/null \
    || erreur "tag v$version not found in this clone (git fetch --tags)"
  for chemin in scripts/repro-build.sh scripts/release-lib.sh docker/repro.Dockerfile .xcode-version rust-toolchain.toml; do
    git -C "$racine" cat-file -e "v$version:$chemin" 2>/dev/null \
      || erreur "tag v$version does not contain $chemin: its build environment is not recorded (version predating this procedure). Rebuild by hand from the tag (see docs/VERIFYING.md)."
  done
  mkdir -p "$env" "$out"
  git -C "$racine" archive --format=tar "v$version" scripts docker .xcode-version rust-toolchain.toml \
    | tar -x -C "$env" || erreur "extracting the build environment of tag v$version failed"
  XCODE_VERSION_FICHIER="$env/.xcode-version"
  for nom in $NOMS_LISTES; do
    cible="$(cible_du_nom "$nom" "$version")" || erreur "unexpected binary name: $nom"
    # Only one rebuild per target: repro-build.sh already produces both binaries.
    case "$faites" in *" $cible "*) continue ;; esac
    cible_compilable_ici "$cible" || continue
    faites="$faites$cible "
    echo "rebuilding $cible (build environment of tag v$version)…" >&2
    "$env/scripts/repro-build.sh" --git-dir "$racine" --target "$cible" --ref "v$version" --out "$out" >/dev/null \
      || erreur "rebuilding $cible failed"
  done
}
