# Maintainer signing key

`keys/maintainer.pub` contains the minisign public key with which `scripts/verify-release.sh`
verifies `SHA256SUMS.minisig`. It is **empty** until the maintainer has published their key:
verification then fails with an explicit message.

Nobody other than the maintainer generates or handles the secret key.

## Generation (offline)

On a disconnected machine, with a strong password:

    minisign -G -p maintainer.pub -s maintainer.key

## Storing the secret key

- `maintainer.key` never leaves the signing machine; it is neither in the repository nor in the CI.
- Make an encrypted backup (for example `age -p maintainer.key > maintainer.key.age`)
  on offline media, stored in a different place from the key itself.

## Publishing the public key

Copy `maintainer.pub` to `keys/maintainer.pub`, then have the commit validated by a second
person. Also publish the full key line (the second line of the file, which starts with `RW`) through
a channel independent of the repository (website, release announcement).

## Rotation

1. Generate the new pair as above.
2. The old key signs the new public key:

       minisign -S -m new-maintainer.pub -s old-maintainer.key -x keys/rotation-<date>.minisig

3. Replace `keys/maintainer.pub` with the new key and add `keys/rotation-<date>.minisig`
   in the same commit. Verifiers who have the old key check the chain with
   `minisign -V -m keys/maintainer.pub -p old-maintainer.pub -x keys/rotation-<date>.minisig`.

## k-of-n threshold (upcoming)

Eventually, a release will have to carry the signatures of k maintainers out of n
(`SHA256SUMS.<id>.minisig`), with verification requiring k valid signatures from distinct keys.
This is not in place yet: a single key signs today.
