# Publishing a release

Maintainer procedure. The design is in the spec, §15. The model: CI builds twice and attests, then the maintainer rebuilds at home and signs offline.

## Prerequisites

- Docker (Linux targets); to also rebuild the macOS target, an Apple Silicon Mac with `rustup` and exactly the Xcode and SDK used by CI, given in `.xcode-version` (otherwise that target is skipped, see step 4);
- `minisign` and `gh` 2.68.0 or newer (logged in with an account that can edit the repository's releases);
- the **maintainer's minisign secret key**, offline: see `keys/README.md` for generation, storage and rotation. This key never goes into the repository, into CI or into an automated tool;
- `keys/maintainer.pub` filled in with the public key. While it is empty, `sign-release.sh` refuses to sign, unless you pass `--pubkey <file>`.

## GitHub settings to configure once

Pushing a `v*` tag is the only gate into the release workflow. It must therefore be locked down:

- **Tag ruleset**: restrict who can create, modify or delete `v*` tags (for example the maintainer alone), and forbid moving them;
- **Protection of the `main` branch**: no force pushes, required review, required `ci` checks (Rust check, signing scripts, double build);
- keep the workflow actions pinned by commit SHA, as they are today.

## Before the first release

In this order, once:

1. Make the GitHub repository public (attestations and independent rebuilds depend on it).
2. Create the `v*` tag ruleset and the `main` protection described above, with the required `ci` checks (Rust check, signing scripts, double build).
3. In the repository's Actions settings, allow workflows to create releases (`GITHUB_TOKEN` with write access for `release.yml`, which requests `contents: write` only in its last job).
4. Push `main`, then open a first pull request and wait for `ci` to be green: Rust check, signing scripts, and the `x86_64-unknown-linux-musl` double build when the pull request changes the build environment.
5. Run `ci` by hand (`workflow_dispatch`: `gh workflow run ci.yml --ref main`) to get the full double build of all three targets, and check that the copies are identical, macOS included (Xcode from `.xcode-version`).
6. Generate the offline key (`keys/README.md`), commit `keys/maintainer.pub` with review by a second person, and publish the `RW…` line through a channel independent of the repository.
7. Do a full rehearsal on a pre-release tag, for example `0.1.0-rc.1` (with the version in `crates/barking-cli/Cargo.toml`, `crates/barking-node/Cargo.toml` and `crates/barking-push/Cargo.toml` updated accordingly): tag, CI, `sign-release.sh`, then `verify-release.sh --rebuild`.
8. Create the `barking-rebuilds` repository (entry format in `docs/VERIFYING.md`).
9. Tag `v0.1.0`, following the steps below.

## Preserving the Alpine environment

Linux builds use the pinned Rust/Alpine image and the APK versions in `docker/apk/build.txt`. Before a release, keep the signed APKs and the matching indexes in an immutable mirror, or keep the build image by its digest: the public Alpine repositories may remove old revisions. To change the image (digest) or a package, regenerate the full list (sorted `package=version` lines, the format that `docker/apk/install.sh` compares) and check that it is the same on x86-64 and ARM64, then get `ci` to pass (the pull request runs the double build): `docker/apk/install.sh` rejects any difference. `docker/apk/release.txt` plays the same role for the test image of the signing scripts. Fuzzing keeps its Debian (glibc) image: AddressSanitizer does not support musl targets.

## Changing the CI's Xcode

`.xcode-version` fixes the macOS runner (`runner=`), the Xcode version (`xcode=`) and the SDK version (`sdk=`). The workflows select that Xcode and fail if the SDK differs. When GitHub removes that Xcode or runner from its images, choose a version listed in the image's README (`actions/runner-images` repository, `images/macos/macos-<n>-arm64-Readme.md`, sections "Xcode" and "Installed SDKs"), update `.xcode-version` and the `runner` of the matrices in `ci.yml` and `release.yml`, then run `ci` by hand (`workflow_dispatch`). Each tag records its `.xcode-version`: an old version is rebuilt with the Xcode of its tag.

## Steps

### 1. Prepare

1. Update `version` in `crates/barking-cli/Cargo.toml`, `crates/barking-node/Cargo.toml` **and** `crates/barking-push/Cargo.toml` (all three must be identical), as well as `Cargo.lock`, commit, merge into `main`, and wait for `ci` to be green.
2. Run `ci` by hand on `main` (`gh workflow run ci.yml --ref main`) and wait for the full double build of all three targets: pull requests only check it when the build environment changes, and a pushed tag does not move (a failure at the release stage costs a new version).
3. Check out the commit to release, with a clean working tree.

### 2. Tag

    git tag v<version>
    git push origin v<version>

The tag must be `v` followed by the version in `crates/barking-cli/Cargo.toml`, which must match that of `crates/barking-node/Cargo.toml` and of `crates/barking-push/Cargo.toml`: otherwise the first job of the `release.yml` workflow fails.

Never recreate a tag on a rewritten or amended commit: the binary contains the commit date, so a different commit gives different hashes (see `docs/VERIFYING.md`).

### 3. Let CI work

The `release.yml` workflow:

1. checks that the tag's commit is an ancestor of `main` and that the tag matches the version;
2. builds each target twice (`barking-cli`, `barking-node` then `barking-push`, in three separate `cargo build -p` invocations: `repro-build.sh` refuses the build if the dependency tree of the node or of the notification relay contains OpenSSL or SQLCipher), in two independent runs (two fresh runners);
3. compares the copies byte by byte (`cmp`): any difference blocks everything;
4. produces the provenance attestations;
5. creates the GitHub release **as a draft**, with the three binaries `barking-cli`, `barking-node` and `barking-push` for each target and `SHA256SUMS`.

At this point, no release is published (the tag and the attestations, however, are already public). If a release `v<version>` already exists (a draft from a previous run), the last step fails and says so: delete it (`gh release delete v<version> -R <owner>/barking`), then rerun the workflow.

### 4. Sign

On the signing machine, from an up-to-date clone that contains the tag. `<version>` is written without the `v` prefix (for example `0.1.0`):

    git fetch --tags
    scripts/sign-release.sh <version> --seckey <path/maintainer.key> --repo <owner>/barking

The script:

1. prints the commit of the local tag `v<version>` (it refuses to sign if that tag does not exist in the clone): check that it is the expected commit. It compares it with the tag on `origin` (`git ls-remote`) and refuses if the tag is missing there or points to another commit; if `origin` is not configured or is unreachable, it also refuses, except with `--from-dir` (a simple warning);
2. downloads the draft's files and checks `SHA256SUMS` and the hashes;
3. **rebuilds locally** every target possible on this machine and compares. The rebuild uses the build environment recorded in the tag (`scripts/`, `docker/`, `.xcode-version`, `rust-toolchain.toml`, extracted with `git archive`), not that of the working tree;
4. signs **only if everything is identical** and no listed file is missing;
5. signs `SHA256SUMS` with the signed comment `barking v<version> commit <tag commit>`, and checks the resulting signature with the public key;
6. uploads `SHA256SUMS.minisig` and **publishes** the draft.

Options: `--pubkey <file>` for another public key (required while `keys/maintainer.pub` is empty), `--from-dir <dir>` to work on local files instead of the draft (the signature is then written to that directory, nothing is published), `--rebuilt-dir <dir>` to compare with a rebuild already done by `repro-build.sh`.

A single machine does not build every target: a Linux x86_64 machine rebuilds `x86_64-unknown-linux-musl`; an arm64 Mac rebuilds `aarch64-unknown-linux-musl`, and **Docker is required there** (without it, the script fails). It rebuilds `aarch64-apple-darwin` only if it has `rustup` and the Xcode/SDK of `.xcode-version`: otherwise the script says so (notice "aarch64-apple-darwin is not rebuilt on this machine") and signs with only the rebuilt Linux target. Targets that are not rebuilt here are signed on the strength of the CI's double build and the attestations: the signature does not otherwise cover them (see `docs/VERIFYING.md`).

To rebuild everything, build the other targets on other machines, then gather all the outputs of `repro-build.sh` into **a single directory** and pass it with `--rebuilt-dir`. This directory must contain all the targets that can be built on the signing machine. The script does not check how this directory was produced: by using it, you trust those machines and whatever you copied there.

### 5. Final check

As any user would (it is the same command as in `docs/VERIFYING.md`):

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

It must end with `Version <version> verified ✓`.

## If CI or the rebuild differs

**Do not sign.** A difference means a non-reproducible build, a new source of non-determinism, or a compromise.

- If CI fails at the comparison (`compare`): nothing is published. Open an issue with the workflow log.
- If `sign-release.sh` reports that the local rebuild differs: it stops without signing or publishing anything. To get the two hashes to compare:

        gh release download v<version> -R <owner>/barking --dir <d1>
        scripts/repro-build.sh --target <target> --ref v<version> --out <d2>
        cmp <d1>/barking-<cli|node>-<version>-<target> <d2>/barking-<cli|node>-<version>-<target>

  (or compare the lines of `<d1>/SHA256SUMS` and `<d2>/SHA256SUMS`). Open an issue with these two hashes, the tag's commit, the machine and the Docker version, or the Xcode version for macOS.
- Look first for benign causes: wrong commit (`git rev-parse v<version>^{commit}`), a macOS SDK different from the CI's (normally rejected by `repro-build.sh`, which compares against `.xcode-version`), a macOS runner image updated by GitHub with a different clang for the same Xcode.
- Troubleshooting: if a macOS build fails without compiling, `/private/tmp/barking-repro-darwin` exists, left by an interrupted build. Delete it and rerun; this has no effect on the hashes.
- Only publish the release once the cause is understood and fixed, with a new tag and a new version: do not move a tag that has already been pushed.
- If the release is already published and a binary is disputed, withdraw it (`gh release edit v<version> --draft=true -R <owner>/barking`) and announce it.

## Key rotation

See `keys/README.md`: the old key signs the new one (`keys/rotation-<date>.minisig`), then `keys/maintainer.pub` is replaced in the same commit, reviewed by a second person. Publish the new fingerprint through a channel independent of the repository. Then sign subsequent releases with the new key.

## Script tests

    scripts/tests/repro-twice.sh        # two builds from two paths, same hashes (Docker)
    scripts/tests/release-scripts.sh    # signing and detected tampering (Docker, throwaway keys)

In `ci.yml`, `release-scripts.sh` and `scripts/check.sh` (format, clippy, Rust tests in parallel with `cargo-nextest`, with the pinned toolchain) run on every pull request and on `main`. `repro-twice.sh` runs on pull requests that change the build environment (lockfile, manifests, `build.rs`, toolchain, `docker/`, `.xcode-version`, build scripts, workflows); the job still reports, with its build skipped, on the others. Run by hand (`workflow_dispatch`), `ci` does the full double build of all targets with comparison of the copies, as `release.yml` does on every tag.
