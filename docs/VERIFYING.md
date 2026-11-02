# Vérifier une version de Barking

Cette page explique comment vérifier qu'un binaire `barking-cli`, `barking-node` ou `barking-push` (relais de notifications iOS) publié correspond exactement au code source public, et qu'il a été approuvé par le mainteneur. Elle décrit aussi comment devenir reconstructeur indépendant. Le cadre complet est dans la spec, §15.

## Ce qui est vérifié

Chaque version `vX.Y.Z` publiée sur GitHub contient, par cible, trois binaires, `barking-cli-<version>-<cible>`, `barking-node-<version>-<cible>` et `barking-push-<version>-<cible>` (même version pour les trois), plus `SHA256SUMS` et `SHA256SUMS.minisig`. Les cibles sont `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` et `aarch64-apple-darwin` (macOS, sans notarisation).

Trois contrôles se complètent :

1. **Signature du mainteneur** : `SHA256SUMS.minisig` est une signature minisign de `SHA256SUMS`, vérifiée avec `keys/maintainer.pub`. Le commentaire signé doit être exactement `barking v<version> commit <commit>`, où `<commit>` est l'identifiant complet (40 caractères hexadécimaux) du commit du tag `v<version>` chez le mainteneur au moment de signer. Le script affiche ce commit ; si le tag `v<version>` existe dans votre clone, il exige qu'il désigne le même commit, et refuse la version sinon (tag déplacé). Si le tag est absent de votre clone, il le signale seulement : le commit n'a pas pu être contrôlé localement.
2. **Empreintes** : chaque binaire a l'empreinte SHA-256 listée dans `SHA256SUMS`, et aucun fichier n'est en trop ni manquant.
3. **Attestations de provenance** : GitHub certifie que chaque binaire a été produit par le workflow `.github/workflows/release.yml`, depuis le tag `refs/tags/v<version>` du dépôt. L'attestation est liée au workflow et au nom du tag, pas à l'empreinte d'un commit : un tag déplacé serait accepté par cette étape seule, d'où l'importance du ruleset de tags décrit dans `docs/RELEASING.md` et du commit lié par la signature (contrôle 1). Les attestations produites sur un runner auto-hébergé sont refusées (`--deny-self-hosted-runners`).

**Ce que la signature atteste vraiment.** Le mainteneur ne signe qu'après avoir recompilé lui-même, sur sa machine, les cibles que celle-ci sait compiler : une machine Linux x86_64 recompile `x86_64-unknown-linux-musl` ; un Mac arm64 recompile `aarch64-unknown-linux-musl` (Docker est alors requis), et `aarch64-apple-darwin` seulement s'il a `rustup` et exactement l'Xcode et le SDK de la CI (fichier `.xcode-version`) : sinon cette cible est sautée, avec un avis explicite. Pour ces cibles, publier un faux binaire exige de compromettre à la fois la CI et la clé hors ligne. Pour les autres cibles, la signature couvre quand même tout `SHA256SUMS`, mais elle repose sur le double build de la CI, l'attestation et l'approbation du mainteneur : une CI compromise suffirait à faire signer un binaire, sauf si quelqu'un recompile cette cible. Les reconstructions indépendantes (voir plus bas) comblent cet écart.

## Prérequis

- `git`, `minisign` et `gh` (GitHub CLI, connecté avec `gh auth login`), en version 2.68.0 ou plus récente : c'est la première qui accepte `gh attestation verify --source-ref` (`--signer-workflow` et `--deny-self-hosted-runners` sont plus anciens) ;
- pour la vérification complète : Docker pour les cibles Linux, et Docker aussi sur un Mac Apple Silicon. Pour `aarch64-apple-darwin`, il faut en plus `rustup` et l'Xcode indiqué dans `.xcode-version` (voir « Limites »).

Clonez le dépôt et placez-vous à la racine :

    git clone https://github.com/<owner>/barking.git
    cd barking

La clé publique du mainteneur est `keys/maintainer.pub`. Contrôlez la ligne de clé complète (la deuxième ligne du fichier, qui commence par `RW`) auprès d'un canal indépendant du dépôt, comme le site du projet ou l'annonce de version. Tant que le fichier est vide, la vérification s'arrête avec un message explicite : le mainteneur n'a pas encore publié sa clé.

## Vérification rapide

    scripts/verify-release.sh <version> --repo <owner>/barking

`<version>` s'écrit sans le préfixe `v`, par exemple `scripts/verify-release.sh 0.1.0 --repo <owner>/barking`. Sans `--repo`, le script utilise la variable `BARKING_REPO`, puis l'URL du remote `origin` du dépôt. Il télécharge les fichiers de la version `v<version>` avec `gh`, puis exécute les étapes dans l'ordre :

1. signature de `SHA256SUMS` ;
2. empreintes des binaires ;
3. attestations (`gh attestation verify` pour chaque binaire, liées au workflow `release.yml` et au tag `v<version>`) ;
4. recompilation : non demandée.

Il se termine par `Version <version> vérifiée ✓` et un code de sortie 0. En cas de problème, il affiche « ÉCHEC à l'étape … » et sort avec le code 1 : n'utilisez alors pas le binaire.

Options utiles :

- `--from-dir <dir>` : vérifie des fichiers déjà téléchargés au lieu de passer par `gh release download`. Le répertoire doit contenir `SHA256SUMS`, `SHA256SUMS.minisig` et **tous** les binaires de la version : un binaire listé dans `SHA256SUMS` mais absent fait échouer la vérification ;
- `--pubkey <fichier>` : utilise une autre clé publique que `keys/maintainer.pub` ;
- `--skip-attestation` : saute l'étape 3 (par exemple hors ligne, avec `--from-dir`). Ce contrôle est alors perdu : n'en tirez pas la même confiance.

## Vérification complète : recompiler

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

En plus des trois contrôles, le script recompile depuis le tag `v<version>`, puis compare les binaires obtenus à ceux de la version. La recompilation utilise **l'environnement de build enregistré dans le tag** (`scripts/repro-build.sh`, `docker/repro.Dockerfile`, `.xcode-version`, `rust-toolchain.toml`, extraits du tag avec `git archive`), jamais celui de votre arbre de travail. Si le tag ne contient pas ces fichiers (version antérieure à cette procédure), le script s'arrête et le dit : recompilez alors à la main. Il recompile chaque cible qu'il sait compiler sur votre machine :

- Linux x86_64 : la cible `x86_64-unknown-linux-musl`, via Docker ;
- Linux arm64 : la cible `aarch64-unknown-linux-musl`, via Docker ;
- macOS arm64 : la cible `aarch64-unknown-linux-musl`, qui exige Docker (sans Docker, le script échoue sur un Mac arm64) ; et la cible `aarch64-apple-darwin`, en natif, seulement avec `rustup` et l'Xcode/SDK de `.xcode-version`. Sinon, le script annonce que cette cible n'est pas recompilée ici : pour elle, la confiance repose sur le double build de la CI, l'attestation et les reconstructions indépendantes.

Chaque cible Linux est compilée nativement sur son architecture, jamais en émulation. Les autres cibles ne sont pas comparées. Si aucune cible n'est compilable sur votre machine, le script échoue : il n'y a rien eu de recompilé.

Le tag `v<version>` doit exister dans votre clone (`git fetch --tags`).

Pour comparer avec des compilations déjà faites, utilisez `--rebuilt-dir <dir>` (il implique `--rebuild`). Le répertoire doit contenir **toutes** les cibles que votre machine sait compiler, produites par `repro-build.sh` (même `--out`) : une cible compilable ici mais absente du répertoire fait échouer le script.

    scripts/repro-build.sh --target <cible> --ref v<version> --out <dir>
    scripts/verify-release.sh <version> --rebuilt-dir <dir> --repo <owner>/barking

`repro-build.sh` écrit les binaires `barking-cli-<version>-<cible>`, `barking-node-<version>-<cible>` et `barking-push-<version>-<cible>` et `SHA256SUMS` dans `<dir>` (par défaut `dist/`) et affiche l'empreinte.

Si vous ne compilez qu'une seule cible, comparez à la main : compilez avec `scripts/repro-build.sh --target <cible> --ref v<version> --out <dir>`, puis comparez les empreintes affichées (une par binaire, ou celles de `<dir>/SHA256SUMS`) aux lignes correspondantes du `SHA256SUMS` de la version.

### Compiler avec la bonne référence

Le binaire contient la date du commit (`SOURCE_DATE_EPOCH` est l'horodatage du commit construit : seul cet horodatage change le binaire, pas l'identifiant du commit). Il faut donc compiler **exactement le commit du tag**. Un commit recréé ou amendé, même avec un contenu identique, a un autre horodatage, et donne un binaire différent. Si vos empreintes diffèrent, vérifiez d'abord que `git rev-parse v<version>^{commit}` est bien le commit attendu.

### Limites

- **Linux** : le build tourne dans une image Docker épinglée par son empreinte, avec Rust 1.99.1 sur Alpine et un ensemble complet de versions APK épinglées dans `docker/apk/build.txt`. Les anciens paquets Alpine peuvent disparaître des dépôts publics : il faut en conserver une archive immuable ou l’image de build pour les reconstructions à long terme (voir [RELEASING.md](RELEASING.md)). Docker est requis.
- **macOS** : le build est natif, dans le répertoire fixe `/private/tmp/barking-repro-darwin`. Si ce répertoire existe déjà, le script refuse de démarrer : supprimez-le après un build interrompu. La cible de déploiement est fixée à macOS 11.0. **La reproductibilité n'est garantie qu'avec la même version de Xcode et du SDK macOS que la CI.** Ils sont épinglés dans `.xcode-version` (runner GitHub, version de Xcode, version du SDK) ; les workflows sélectionnent cet Xcode et vérifient le SDK. `repro-build.sh` refuse de compiler cette cible si `xcodebuild -version` ou `xcrun --show-sdk-version` diffèrent (« SDK/Xcode différent de celui de la CI ») : installez cet Xcode et sélectionnez-le avec `sudo xcode-select -s /Applications/Xcode_<version>.app`. `rustup` est aussi requis : le `rustc` de Homebrew, même en 1.94.1, n'est pas la chaîne officielle et ne reproduit pas le binaire. Le script affiche les versions de Xcode, du SDK, de clang et de rustc utilisées.

## Devenir reconstructeur indépendant

Plusieurs reconstructions identiques, faites par des personnes différentes, attestent publiquement que le binaire correspond au code (spec §15.5). Elles sont aussi ce qui comble l'écart décrit plus haut : pour les cibles que le mainteneur ne recompile pas lui-même, seules des reconstructions indépendantes les couvrent. Pour y participer :

1. Recompilez une cible depuis le tag, comme ci-dessus, sur une machine que vous maîtrisez.
2. Comparez l'empreinte obtenue à celle de `SHA256SUMS`, à la main ou avec `verify-release.sh --rebuilt-dir` si votre répertoire contient toutes les cibles compilables chez vous.
3. Publiez votre résultat dans le dépôt `barking-rebuilds`, sous la forme d'une entrée signée avec **votre propre clé minisign** :

        version: <version>
        cible: <cible>
        sha256: <empreinte du binaire que vous avez compilé>
        identique: oui|non
        date: <date de la reconstruction, AAAA-MM-JJ>

   Le format ci-dessus est fixé ; la façon de signer est une suggestion : `minisign -S -m <entrée> -s <votre clé>`. Déposez l'entrée avec son `.minisig`. Ajoutez votre clé publique au dépôt, ou publiez-la ailleurs, pour qu'on puisse la contrôler.

Publiez aussi vos résultats `identique: non` : c'est précisément ce qui alerte. Le dépôt `barking-rebuilds` est à créer ; ce format est celui fixé par le projet.

## Règle des mises à jour

Quand les mises à jour automatiques existeront (le code vient plus tard, le format est fixé maintenant, spec §15.6), un nœud ou une app n'installera une mise à jour que si :

- la signature du mainteneur (ou le seuil k sur n, quand l'équipe grandira) est valide ;
- la version est **strictement plus récente** que celle installée, ce qui empêche de forcer un retour à une version vulnérable.

## Android et iOS

- **Android** : l'APK sera reproductible à l'étape 3 de la feuille de route (spec). On comparera son contenu hors bloc de signature, comme le fait F-Droid.
- **iOS** : une app installée depuis l'App Store **n'est pas vérifiable**. Apple chiffre chaque binaire puis le re-signe avec ses propres clés, donc l'empreinte de ce que vous installez ne peut pas être comparée à celle du code source. Ce que le projet fait à la place : documenter cette limite ici, et publier, pour les auditeurs, un build iOS construit depuis le code public. Il permettra d'auditer ce code, mais pas de prouver que la version de l'App Store en est issue.

Ces deux applications ne sont pas encore livrées. Aujourd'hui, les versions contiennent `barking-cli`, `barking-node` et `barking-push`.
