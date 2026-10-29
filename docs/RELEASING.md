# Publier une version

Procédure du mainteneur. La conception est dans la spec, §15. Le modèle : la CI construit deux fois et atteste, puis le mainteneur recompile chez lui et signe hors ligne.

## Prérequis

- Docker (cibles Linux) ; pour la cible macOS, un Mac Apple Silicon avec `rustup` ;
- `minisign` et `gh` (connecté avec un compte qui peut modifier les versions du dépôt) ;
- la **clé secrète minisign du mainteneur**, hors ligne : voir `keys/README.md` pour la génération, le rangement et la rotation. Cette clé ne va jamais dans le dépôt, dans la CI ni dans un outil automatique ;
- `keys/maintainer.pub` renseigné avec la clé publique. Tant qu'il est vide, `sign-release.sh` refuse de signer, sauf si vous passez `--pubkey <fichier>`.

## Réglages GitHub à faire une fois

Pousser un tag `v*` est la seule porte vers le workflow de publication. Il faut donc la verrouiller :

- **Ruleset de tags** : restreindre qui peut créer, modifier ou supprimer les tags `v*` (par exemple le seul mainteneur), et interdire de les déplacer ;
- **Protection de la branche `main`** : pas de push forcé, relecture obligatoire, vérifications `repro-check` exigées ;
- garder les actions des workflows épinglées par SHA de commit, comme aujourd'hui.

## Étapes

### 1. Préparer

1. Mettre à jour `version` dans `crates/barking-cli/Cargo.toml` et `Cargo.lock`, committer, fusionner dans `main`, et attendre que `repro-check` soit vert.
2. Se placer sur le commit à publier, avec un arbre de travail propre.

### 2. Tagger

    git tag v<version>
    git push origin v<version>

Le tag doit être `v` suivi de la version de `crates/barking-cli/Cargo.toml` : sinon le premier job du workflow `release.yml` échoue.

Ne recréez jamais un tag sur un commit réécrit ou amendé : le binaire contient la date du commit, donc un autre commit donne d'autres empreintes (voir `docs/VERIFYING.md`).

### 3. Laisser la CI travailler

Le workflow `release.yml` :

1. vérifie que le tag correspond à la version ;
2. compile chaque cible sur deux machines différentes ;
3. compare les copies octet par octet (`cmp`) : une différence bloque tout ;
4. produit les attestations de provenance ;
5. crée la version GitHub **en brouillon**, avec les binaires et `SHA256SUMS`.

Rien n'est public à ce stade. Si une version `v<version>` existe déjà (brouillon d'un run précédent), la dernière étape échoue et le dit : supprimez-la (`gh release delete v<version> -R <owner>/barking`), puis relancez le workflow.

### 4. Signer

Sur la machine de signature, depuis un clone à jour qui contient le tag :

    git fetch --tags
    scripts/sign-release.sh <version> --seckey <chemin/maintainer.key> --repo <owner>/barking

Le script :

1. télécharge les fichiers du brouillon et contrôle `SHA256SUMS` et les empreintes ;
2. **recompile localement** chaque cible possible sur cette machine avec `repro-build.sh` et compare ;
3. ne signe **que si tout est identique** et qu'aucun fichier listé ne manque ;
4. signe `SHA256SUMS` avec le commentaire signé `barking v<version>`, et contrôle la signature produite avec la clé publique ;
5. dépose `SHA256SUMS.minisig` et **publie** le brouillon.

Options : `--pubkey <fichier>` pour une autre clé publique (obligatoire tant que `keys/maintainer.pub` est vide), `--from-dir <dir>` pour travailler sur des fichiers locaux au lieu du brouillon (la signature est alors écrite dans ce répertoire, rien n'est publié), `--rebuilt-dir <dir>` pour comparer avec une recompilation déjà faite par `repro-build.sh`.

Une seule machine ne compile pas toutes les cibles : une machine Linux x86_64 recompile `x86_64-unknown-linux-musl`, un Mac arm64 recompile `aarch64-apple-darwin` et `aarch64-unknown-linux-musl`. Les cibles qui ne sont pas recompilées ici sont signées sur la foi des attestations. Pour tout recompiler, utilisez une autre machine puis `--rebuilt-dir`, ou une seconde passe de vérification.

### 5. Contrôle final

Comme n'importe quel utilisateur (c'est la même commande que celle de `docs/VERIFYING.md`) :

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

Il doit finir par `Version <version> vérifiée ✓`.

## Si la CI ou la recompilation diffère

**Ne signez pas.** Une différence veut dire un build non reproductible, une source de non-déterminisme nouvelle, ou une compromission.

- Si la CI échoue à la comparaison (`compare`) : rien n'est publié. Ouvrez un ticket avec le journal du workflow.
- Si `sign-release.sh` annonce que la recompilation locale diffère : il s'arrête sans rien signer ni publier. Ouvrez un ticket avec les deux empreintes (`sha256sum` du binaire du brouillon et de `dist/`), le commit du tag, la machine et la version de Docker, ou de Xcode pour macOS.
- Cherchez d'abord les causes bénignes : mauvais commit (`git rev-parse v<version>^{commit}`), SDK macOS différent de celui de la CI (la reproductibilité macOS n'est garantie qu'avec le même), `/private/tmp/barking-repro-darwin` laissé par un build interrompu.
- Ne publiez la version qu'une fois la cause comprise et corrigée, avec un nouveau tag et une nouvelle version : ne déplacez pas un tag déjà poussé.
- Si la version est déjà publiée et qu'un binaire est contesté, retirez-la (`gh release edit v<version> --draft=true -R <owner>/barking`) et annoncez-le.

## Rotation de la clé

Voir `keys/README.md` : l'ancienne clé signe la nouvelle (`keys/rotation-<date>.minisig`), puis `keys/maintainer.pub` est remplacé dans le même commit, relu par une seconde personne. Publiez la nouvelle empreinte par un canal indépendant du dépôt. Signez ensuite les versions suivantes avec la nouvelle clé.

## Tests des scripts

    scripts/tests/repro-twice.sh        # deux builds depuis deux chemins, mêmes empreintes (Docker)
    scripts/tests/release-scripts.sh    # signature et falsifications détectées (Docker, clés jetables)

Ils tournent aussi dans `repro-check.yml` : sur chaque pull request, et chaque semaine pour la vérification complète sur toutes les cibles.
