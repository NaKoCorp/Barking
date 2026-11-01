# Publier une version

Procédure du mainteneur. La conception est dans la spec, §15. Le modèle : la CI construit deux fois et atteste, puis le mainteneur recompile chez lui et signe hors ligne.

## Prérequis

- Docker (cibles Linux) ; pour recompiler aussi la cible macOS, un Mac Apple Silicon avec `rustup` et exactement l'Xcode et le SDK de la CI, indiqués dans `.xcode-version` (sinon cette cible est sautée, voir l'étape 4) ;
- `minisign` et `gh` 2.68.0 ou plus récent (connecté avec un compte qui peut modifier les versions du dépôt) ;
- la **clé secrète minisign du mainteneur**, hors ligne : voir `keys/README.md` pour la génération, le rangement et la rotation. Cette clé ne va jamais dans le dépôt, dans la CI ni dans un outil automatique ;
- `keys/maintainer.pub` renseigné avec la clé publique. Tant qu'il est vide, `sign-release.sh` refuse de signer, sauf si vous passez `--pubkey <fichier>`.

## Réglages GitHub à faire une fois

Pousser un tag `v*` est la seule porte vers le workflow de publication. Il faut donc la verrouiller :

- **Ruleset de tags** : restreindre qui peut créer, modifier ou supprimer les tags `v*` (par exemple le seul mainteneur), et interdire de les déplacer ;
- **Protection de la branche `main`** : pas de push forcé, relecture obligatoire, vérifications `repro-check` exigées ;
- garder les actions des workflows épinglées par SHA de commit, comme aujourd'hui.

## Avant la première version

Dans cet ordre, une seule fois :

1. Rendre le dépôt GitHub public (les attestations et les reconstructions indépendantes en dépendent).
2. Créer le ruleset de tags `v*` et la protection de `main` décrits ci-dessus, avec les vérifications de `repro-check` exigées (contrôle Rust, scripts de signature, double build).
3. Dans les réglages Actions du dépôt, autoriser les workflows à créer des versions (`GITHUB_TOKEN` en écriture pour `release.yml`, qui ne demande `contents: write` que dans son dernier job).
4. Pousser `main`, puis ouvrir une première pull request et attendre que `repro-check` soit vert : contrôle Rust, scripts de signature, et double build `x86_64-unknown-linux-musl`, qui n'a jamais été compilé sur la machine de développement (Mac arm64). `repro-check` ne se lance pas sur un simple push.
5. Lancer `repro-check` à la main (`workflow_dispatch`) pour obtenir le double build complet des trois cibles, et vérifier que les copies sont identiques, macOS compris (Xcode de `.xcode-version`).
6. Générer la clé hors ligne (`keys/README.md`), committer `keys/maintainer.pub` avec relecture par une seconde personne, et publier la ligne `RW…` par un canal indépendant du dépôt.
7. Faire une répétition complète sur un tag de pré-version, par exemple `0.1.0-rc.1` (version de `crates/barking-cli/Cargo.toml` et de `crates/barking-node/Cargo.toml` mise à jour en conséquence) : tag, CI, `sign-release.sh`, puis `verify-release.sh --rebuild`.
8. Créer le dépôt `barking-rebuilds` (format des entrées dans `docs/VERIFYING.md`).
9. Tagger `v0.1.0`, en suivant les étapes ci-dessous.

## Conserver l’environnement Alpine

Les builds Linux utilisent l’image Rust/Alpine épinglée et les versions APK de `docker/apk/build.txt`. Avant une publication, conserver les APK signés et les index correspondants dans un miroir immuable, ou conserver l’image de build par son empreinte : les dépôts publics Alpine peuvent retirer les anciennes révisions. Pour changer l’image (digest) ou un paquet, régénérer la liste complète (lignes `paquet=version` triées, le format que compare `docker/apk/install.sh`) et vérifier qu’elle est la même sur x86-64 et ARM64, puis refaire passer `repro-check` : `docker/apk/install.sh` refuse toute différence. `docker/apk/release.txt` joue le même rôle pour l’image de test des scripts de signature. Le fuzzing garde son image Debian (glibc) : AddressSanitizer ne prend pas en charge les cibles musl.

## Changer l'Xcode de la CI

`.xcode-version` fixe le runner macOS (`runner=`), la version de Xcode (`xcode=`) et celle du SDK (`sdk=`). Les workflows sélectionnent cet Xcode et échouent si le SDK diffère. Quand GitHub retire cet Xcode ou ce runner de ses images, choisissez une version listée dans le README de l'image (dépôt `actions/runner-images`, `images/macos/macos-<n>-arm64-Readme.md`, sections « Xcode » et « Installed SDKs »), mettez à jour `.xcode-version` et le `runner` des matrices dans les deux workflows, et faites passer `repro-check`. Chaque tag enregistre son `.xcode-version` : une ancienne version se recompile avec l'Xcode de son tag.

## Étapes

### 1. Préparer

1. Mettre à jour `version` dans `crates/barking-cli/Cargo.toml` **et** dans `crates/barking-node/Cargo.toml` (les deux doivent être identiques), ainsi que `Cargo.lock`, committer, fusionner dans `main`, et attendre que `repro-check` soit vert.
2. Se placer sur le commit à publier, avec un arbre de travail propre.

### 2. Tagger

    git tag v<version>
    git push origin v<version>

Le tag doit être `v` suivi de la version de `crates/barking-cli/Cargo.toml`, qui doit être celle de `crates/barking-node/Cargo.toml` : sinon le premier job du workflow `release.yml` échoue.

Ne recréez jamais un tag sur un commit réécrit ou amendé : le binaire contient la date du commit, donc un autre commit donne d'autres empreintes (voir `docs/VERIFYING.md`).

### 3. Laisser la CI travailler

Le workflow `release.yml` :

1. vérifie que le commit du tag est un ancêtre de `main` et que le tag correspond à la version ;
2. compile chaque cible deux fois (`barking-cli` puis `barking-node`, en deux invocations `cargo build -p` distinctes : `repro-build.sh` refuse le build si l'arbre de dépendances du nœud contient OpenSSL ou SQLCipher), en deux exécutions indépendantes (deux runners neufs) ;
3. compare les copies octet par octet (`cmp`) : une différence bloque tout ;
4. produit les attestations de provenance ;
5. crée la version GitHub **en brouillon**, avec les binaires `barking-cli` et `barking-node` de chaque cible et `SHA256SUMS`.

À ce stade, aucune version n'est publiée (le tag et les attestations, eux, sont déjà publics). Si une version `v<version>` existe déjà (brouillon d'un run précédent), la dernière étape échoue et le dit : supprimez-la (`gh release delete v<version> -R <owner>/barking`), puis relancez le workflow.

### 4. Signer

Sur la machine de signature, depuis un clone à jour qui contient le tag. `<version>` s'écrit sans le préfixe `v` (par exemple `0.1.0`) :

    git fetch --tags
    scripts/sign-release.sh <version> --seckey <chemin/maintainer.key> --repo <owner>/barking

Le script :

1. affiche le commit du tag local `v<version>` (il refuse de signer si ce tag n'existe pas dans le clone) : vérifiez que c'est le commit attendu ;
2. télécharge les fichiers du brouillon et contrôle `SHA256SUMS` et les empreintes ;
3. **recompile localement** chaque cible possible sur cette machine et compare. La recompilation utilise l'environnement de build enregistré dans le tag (`scripts/`, `docker/`, `.xcode-version`, `rust-toolchain.toml`, extraits avec `git archive`), pas celui de l'arbre de travail ;
4. ne signe **que si tout est identique** et qu'aucun fichier listé ne manque ;
5. signe `SHA256SUMS` avec le commentaire signé `barking v<version> commit <commit du tag>`, et contrôle la signature produite avec la clé publique ;
6. dépose `SHA256SUMS.minisig` et **publie** le brouillon.

Options : `--pubkey <fichier>` pour une autre clé publique (obligatoire tant que `keys/maintainer.pub` est vide), `--from-dir <dir>` pour travailler sur des fichiers locaux au lieu du brouillon (la signature est alors écrite dans ce répertoire, rien n'est publié), `--rebuilt-dir <dir>` pour comparer avec une recompilation déjà faite par `repro-build.sh`.

Une seule machine ne compile pas toutes les cibles : une machine Linux x86_64 recompile `x86_64-unknown-linux-musl` ; un Mac arm64 recompile `aarch64-unknown-linux-musl`, et **Docker y est requis** (sans lui, le script échoue). Il ne recompile `aarch64-apple-darwin` que s'il a `rustup` et l'Xcode/SDK de `.xcode-version` : sinon le script le dit (avis « aarch64-apple-darwin n'est pas recompilé sur cette machine ») et signe avec la seule cible Linux recompilée. Les cibles qui ne sont pas recompilées ici sont signées sur la foi du double build de la CI et des attestations : la signature ne les couvre pas autrement (voir `docs/VERIFYING.md`).

Pour tout recompiler, compilez les autres cibles sur d'autres machines, puis rassemblez toutes les sorties de `repro-build.sh` dans **un seul répertoire** et passez-le avec `--rebuilt-dir`. Ce répertoire doit contenir toutes les cibles compilables sur la machine de signature. Le script ne contrôle pas comment ce répertoire a été produit : en l'utilisant, vous faites confiance à ces machines et à ce que vous y avez copié.

### 5. Contrôle final

Comme n'importe quel utilisateur (c'est la même commande que celle de `docs/VERIFYING.md`) :

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

Il doit finir par `Version <version> vérifiée ✓`.

## Si la CI ou la recompilation diffère

**Ne signez pas.** Une différence veut dire un build non reproductible, une source de non-déterminisme nouvelle, ou une compromission.

- Si la CI échoue à la comparaison (`compare`) : rien n'est publié. Ouvrez un ticket avec le journal du workflow.
- Si `sign-release.sh` annonce que la recompilation locale diffère : il s'arrête sans rien signer ni publier. Pour obtenir les deux empreintes à comparer :

        gh release download v<version> -R <owner>/barking --dir <d1>
        scripts/repro-build.sh --target <cible> --ref v<version> --out <d2>
        cmp <d1>/barking-<cli|node>-<version>-<cible> <d2>/barking-<cli|node>-<version>-<cible>

  (ou comparez les lignes de `<d1>/SHA256SUMS` et `<d2>/SHA256SUMS`). Ouvrez un ticket avec ces deux empreintes, le commit du tag, la machine et la version de Docker, ou de Xcode pour macOS.
- Cherchez d'abord les causes bénignes : mauvais commit (`git rev-parse v<version>^{commit}`), SDK macOS différent de celui de la CI (normalement refusé par `repro-build.sh`, qui compare à `.xcode-version`), image du runner macOS mise à jour par GitHub avec un autre clang pour le même Xcode.
- Dépannage : si un build macOS échoue sans compiler, c'est que `/private/tmp/barking-repro-darwin` existe, laissé par un build interrompu. Supprimez-le et relancez ; cela n'a aucun effet sur les empreintes.
- Ne publiez la version qu'une fois la cause comprise et corrigée, avec un nouveau tag et une nouvelle version : ne déplacez pas un tag déjà poussé.
- Si la version est déjà publiée et qu'un binaire est contesté, retirez-la (`gh release edit v<version> --draft=true -R <owner>/barking`) et annoncez-le.

## Rotation de la clé

Voir `keys/README.md` : l'ancienne clé signe la nouvelle (`keys/rotation-<date>.minisig`), puis `keys/maintainer.pub` est remplacé dans le même commit, relu par une seconde personne. Publiez la nouvelle empreinte par un canal indépendant du dépôt. Signez ensuite les versions suivantes avec la nouvelle clé.

## Tests des scripts

    scripts/tests/repro-twice.sh        # deux builds depuis deux chemins, mêmes empreintes (Docker)
    scripts/tests/release-scripts.sh    # signature et falsifications détectées (Docker, clés jetables)

Dans `repro-check.yml`, `release-scripts.sh` et `scripts/check.sh` (format, clippy, tests Rust, avec la chaîne épinglée) tournent sur chaque pull request et chaque semaine. `repro-twice.sh` ne tourne que sur les pull requests ; le run hebdomadaire fait à la place le double build complet sur toutes les cibles, avec comparaison des copies.
