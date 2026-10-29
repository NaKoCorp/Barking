# Vérifier une version de Barking

Cette page explique comment vérifier qu'un binaire `barking-cli` publié correspond exactement au code source public, et qu'il a été approuvé par le mainteneur. Elle décrit aussi comment devenir reconstructeur indépendant. Le cadre complet est dans la spec, §15.

## Ce qui est vérifié

Chaque version `vX.Y.Z` publiée sur GitHub contient, par cible, un binaire `barking-cli-<version>-<cible>`, plus `SHA256SUMS` et `SHA256SUMS.minisig`. Les cibles sont `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` et `aarch64-apple-darwin` (macOS, sans notarisation).

Trois contrôles se complètent :

1. **Signature du mainteneur** : `SHA256SUMS.minisig` est une signature minisign de `SHA256SUMS`, vérifiée avec `keys/maintainer.pub`. Le commentaire signé doit être `barking v<version>`.
2. **Empreintes** : chaque binaire a l'empreinte SHA-256 listée dans `SHA256SUMS`, et aucun fichier n'est en trop ni manquant.
3. **Attestations de provenance** : GitHub certifie que chaque binaire a été produit par le workflow `.github/workflows/release.yml`, depuis le tag `refs/tags/v<version>` du dépôt.

Pour publier une fausse version, il faudrait donc compromettre à la fois la CI et la clé hors ligne du mainteneur.

## Prérequis

- `git`, `minisign` et `gh` (GitHub CLI, connecté avec `gh auth login`) ;
- pour la vérification complète : Docker pour les cibles Linux, ou un Mac Apple Silicon pour `aarch64-apple-darwin`.

Clonez le dépôt et placez-vous à la racine :

    git clone https://github.com/<owner>/barking.git
    cd barking

La clé publique du mainteneur est `keys/maintainer.pub`. Contrôlez son empreinte (l'identifiant de la deuxième ligne du fichier) auprès d'un canal indépendant du dépôt, comme le site du projet ou l'annonce de version. Tant que le fichier est vide, la vérification s'arrête avec un message explicite : le mainteneur n'a pas encore publié sa clé.

## Vérification rapide

    scripts/verify-release.sh <version> --repo <owner>/barking

Par exemple `scripts/verify-release.sh 0.1.0 --repo <owner>/barking`. Sans `--repo`, le script utilise la variable `BARKING_REPO`, puis l'URL du remote `origin` du dépôt. Il télécharge les fichiers de la version `v<version>` avec `gh`, puis exécute les étapes dans l'ordre :

1. signature de `SHA256SUMS` ;
2. empreintes des binaires ;
3. attestations (`gh attestation verify` pour chaque binaire, liées au workflow `release.yml` et au tag `v<version>`) ;
4. recompilation : non demandée.

Il se termine par `Version <version> vérifiée ✓` et un code de sortie 0. En cas de problème, il affiche « ÉCHEC à l'étape … » et sort avec le code 1 : n'utilisez alors pas le binaire.

Options utiles :

- `--from-dir <dir>` : vérifie des fichiers déjà téléchargés (`SHA256SUMS`, `SHA256SUMS.minisig` et les binaires) au lieu de passer par `gh release download` ;
- `--pubkey <fichier>` : utilise une autre clé publique que `keys/maintainer.pub` ;
- `--skip-attestation` : saute l'étape 3 (par exemple hors ligne, avec `--from-dir`). Ce contrôle est alors perdu : n'en tirez pas la même confiance.

## Vérification complète : recompiler

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

En plus des trois contrôles, le script recompile depuis le tag `v<version>` avec `scripts/repro-build.sh`, puis compare les binaires obtenus à ceux de la version. Il recompile chaque cible qu'il sait compiler sur votre machine :

- Linux x86_64 : la cible `x86_64-unknown-linux-musl`, via Docker ;
- Linux arm64 : la cible `aarch64-unknown-linux-musl`, via Docker ;
- macOS arm64 : la cible `aarch64-apple-darwin`, en natif, **et** la cible `aarch64-unknown-linux-musl` si Docker est disponible.

Chaque cible Linux est compilée nativement sur son architecture, jamais en émulation. Les autres cibles ne sont pas comparées. Si aucune cible n'est compilable sur votre machine, le script échoue : il n'y a rien eu de recompilé.

Le tag `v<version>` doit exister dans votre clone (`git fetch --tags`).

Pour comparer avec une compilation que vous avez déjà faite, utilisez `--rebuilt-dir <dir>`, qui désigne un répertoire produit par `repro-build.sh` (il implique `--rebuild`) :

    scripts/repro-build.sh --target <cible> --ref v<version> --out <dir>
    scripts/verify-release.sh <version> --rebuilt-dir <dir> --repo <owner>/barking

`repro-build.sh` écrit le binaire `barking-cli-<version>-<cible>` et `SHA256SUMS` dans `<dir>` (par défaut `dist/`) et affiche l'empreinte.

### Compiler avec la bonne référence

Le binaire contient la date du commit (`SOURCE_DATE_EPOCH` est l'horodatage du commit construit). Il faut donc compiler **exactement le commit du tag**. Un commit recréé ou amendé, même avec un contenu identique, a un autre horodatage ou un autre identifiant, et donne un binaire différent. Si vos empreintes diffèrent, vérifiez d'abord que `git rev-parse v<version>^{commit}` est bien le commit attendu.

### Limites

- **Linux** : le build tourne dans une image Docker épinglée par son empreinte, avec un compilateur Rust 1.94.1 et des paquets pris dans un snapshot Debian daté. Docker est requis.
- **macOS** : le build est natif, dans le répertoire fixe `/private/tmp/barking-repro-darwin`. Si ce répertoire existe déjà, le script refuse de démarrer : supprimez-le après un build interrompu. La cible de déploiement est fixée à macOS 11.0. **La reproductibilité n'est garantie qu'avec la même version de Xcode et du SDK macOS** que celle de la CI (runner `macos-14`) : avec un autre SDK, une différence ne prouve pas une altération. Sans `rustup`, le `rustc` du `PATH` doit être exactement la version épinglée dans `rust-toolchain.toml` (1.94.1).

## Devenir reconstructeur indépendant

Plusieurs reconstructions identiques, faites par des personnes différentes, prouvent publiquement que le binaire correspond au code (spec §15.5). Pour y participer :

1. Recompilez une cible depuis le tag, comme ci-dessus, sur une machine que vous maîtrisez.
2. Comparez l'empreinte obtenue à celle de `SHA256SUMS` (le code de sortie de `verify-release.sh --rebuilt-dir` le fait pour vous).
3. Publiez votre résultat dans le dépôt `barking-rebuilds`, sous la forme d'une entrée signée avec **votre propre clé minisign** :

        version: <version>
        cible: <cible>
        sha256: <empreinte du binaire que vous avez compilé>
        identique: oui|non
        date: <date de la reconstruction, AAAA-MM-JJ>

   Signez ce fichier avec `minisign -S -m <entrée> -s <votre clé>` et déposez l'entrée avec son `.minisig`. Ajoutez votre clé publique au dépôt, ou publiez-la ailleurs, pour qu'on puisse la contrôler.

Publiez aussi vos résultats `identique: non` : c'est précisément ce qui alerte. Le dépôt `barking-rebuilds` est à créer ; ce format est celui fixé par le projet.

## Règle des mises à jour

Quand les mises à jour automatiques existeront (le code vient plus tard, le format est fixé maintenant, spec §15.6), un nœud ou une app n'installera une mise à jour que si :

- la signature du mainteneur (ou le seuil k sur n, quand l'équipe grandira) est valide ;
- la version est **strictement plus récente** que celle installée, ce qui empêche de forcer un retour à une version vulnérable.

## Android et iOS

- **Android** : l'APK sera reproductible à l'étape 3 du plan. On comparera son contenu hors bloc de signature, comme le fait F-Droid.
- **iOS** : une app installée depuis l'App Store **n'est pas vérifiable**. Apple chiffre chaque binaire puis le re-signe avec ses propres clés, donc l'empreinte de ce que vous installez ne peut pas être comparée à celle du code source. Ce que le projet publie à la place : cette limite, expliquée ici, et un **build vérifiable pour les auditeurs**, reproductible et signé comme les autres, qui permet de contrôler que le code livré à Apple est bien le code public.

Ces deux applications ne sont pas encore livrées. Aujourd'hui, seul `barking-cli` est publié ; `barking-node` suivra.
