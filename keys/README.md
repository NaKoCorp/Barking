# Clé de signature du mainteneur

`keys/maintainer.pub` contient la clé publique minisign avec laquelle `scripts/verify-release.sh`
vérifie `SHA256SUMS.minisig`. Elle est **vide** tant que le mainteneur n'a pas publié sa clé :
la vérification échoue alors avec un message explicite.

Personne d'autre que le mainteneur ne génère ni ne manipule la clé secrète.

## Génération (hors ligne)

Sur une machine déconnectée, avec un mot de passe fort :

    minisign -G -p maintainer.pub -s maintainer.key

## Rangement de la clé secrète

- `maintainer.key` ne quitte jamais la machine de signature ; elle n'est ni dans le dépôt ni dans la CI.
- Faire une sauvegarde chiffrée (par exemple `age -p maintainer.key > maintainer.key.age`)
  sur un support hors ligne, rangé à un autre endroit que la clé elle-même.

## Publication de la clé publique

Copier `maintainer.pub` dans `keys/maintainer.pub`, puis faire valider le commit par une seconde
personne. Publier aussi l'empreinte de la clé (l'identifiant de la deuxième ligne du fichier) par
un canal indépendant du dépôt (site, annonce de version).

## Rotation

1. Générer la nouvelle paire comme ci-dessus.
2. L'ancienne clé signe la nouvelle clé publique :

       minisign -S -m new-maintainer.pub -s old-maintainer.key -x keys/rotation-<date>.minisig

3. Remplacer `keys/maintainer.pub` par la nouvelle clé et ajouter `keys/rotation-<date>.minisig`
   dans le même commit. Les vérificateurs qui ont l'ancienne clé contrôlent la chaîne avec
   `minisign -V -m keys/maintainer.pub -p old-maintainer.pub -x keys/rotation-<date>.minisig`.

## Seuil k sur n (à venir)

À terme, une version devra porter les signatures de k mainteneurs parmi n
(`SHA256SUMS.<id>.minisig`), la vérification exigeant k signatures valides de clés distinctes.
Ce n'est pas encore en place : une seule clé signe aujourd'hui.
