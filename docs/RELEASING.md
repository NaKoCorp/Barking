# Publishing a release

Maintainer procedure. Releases are automatic: merging pull requests keeps a release pull request up to date, and merging that one publishes the binaries and the container images. Nothing is built or signed on the maintainer's machine.

```
pull request (Conventional Commits title) ──squash──▶ main
                                                       │  release-please.yml
                                                       ▼
                               release pull request (version, Cargo.lock, CHANGELOG.md)
                                                       │  merged by the maintainer
                                                       ▼
                                  tag vX.Y.Z and draft release (release notes)
                                                       │  release.yml
                                                       ▼
        tag check ─▶ double build ─▶ comparison ─▶ attestations, files attached, release published
                                                       │
                                                       ▼
                                  images pushed to ghcr.io and attested
```

## Prerequisites

- The right to merge into `main`.
- `gh` 2.68.0 or newer, logged in (`gh auth login`), to follow the workflows and to run the final check.
- For the final check with a rebuild: Docker, and for the macOS target an Apple Silicon Mac with `rustup` and exactly the Xcode and SDK given in `.xcode-version` (otherwise that target is skipped, see [VERIFYING.md](VERIFYING.md)).

There is no signing key and no secret to keep on a maintainer machine.

## GitHub settings to configure once

The workflows rely on these settings. The first six must be in place before the first release; the last two come after it.

1. **Allowed actions.** In the repository's Actions settings, allow these third-party actions next to the GitHub-owned ones: `googleapis/release-please-action@*`, `docker/login-action@*`, `docker/setup-buildx-action@*`, `docker/metadata-action@*`, `docker/build-push-action@*`. Without them, the workflows fail to load. Every action stays pinned by commit SHA in the workflow files.
2. **Release GitHub App.** Create a GitHub App with the repository permissions Contents and Pull requests in read and write, and install it on `NaKoCorp/Barking` only. Create the `release-please` environment, restricted to the `main` branch, with the variable `RELEASE_APP_CLIENT_ID` and the secret `RELEASE_APP_PRIVATE_KEY`. `release-please.yml` uses the App's token instead of `GITHUB_TOKEN`: a pull request or a tag created with `GITHUB_TOKEN` starts no workflow, so the release pull request would get no checks and the tag would not start `release.yml`.
3. **`release tags` ruleset.** It restricts who can create `v*` tags and forbids moving or deleting them. Add the App to its bypass list, so that release-please can create the tag.
4. **`release` environment.** Only `v*` tags may deploy to it. The job of `release.yml` that attests and publishes runs in this environment.
5. **Squash commits.** The squash commit must take the pull request's title and description:

        gh api -X PATCH repos/NaKoCorp/Barking -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY

6. **`main` ruleset.** Squash merges only, up-to-date branches, and these required checks: `Rust checks (fmt, clippy, tests)`, `double build (PR)`, `release scripts` and `PR title`.
7. **Container packages.** After the first release, make the two packages `barking-node` and `barking-push` public on ghcr.io.
8. **Immutable releases** (recommended). Nothing is added to a release after its publication:

        gh api -X PUT repos/NaKoCorp/Barking/immutable-releases

The independent rebuilds are collected in the `barking-rebuilds` repository (entry format in [VERIFYING.md](VERIFYING.md)), which is yet to be created.

## How a release happens

### 1. Pull requests carry a Conventional Commits title

Pull requests are squash-merged: the title becomes the commit message, the only thing release-please reads. The `PR title` check (`pr-title.yml`, `scripts/check-pr-title.sh`) refuses any other format:

    <type>(<scope>)!: <description>

- The scope and the `!` are optional. The scope is made of lowercase letters, digits, `.`, `_`, `/` and `-`.
- Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `ci`, `build`, `chore`, `revert`.
- `fix` and `perf` raise the patch version, `feat` raises the minor version. A breaking change (`!` after the type, or a `BREAKING CHANGE:` footer) raises the minor version while the version is 0.x.
- The changelog lists `feat` (Features), `fix` (Bug Fixes), `perf` (Performance) and `revert` (Reverts). The `refactor`, `docs`, `test`, `ci`, `build` and `chore` types are hidden from it and do not cause a release on their own.

### 2. The release pull request follows `main`

On every push to `main`, `release-please.yml` opens or updates a pull request titled `chore(main): release X.Y.Z`. It contains:

- the version in `Cargo.toml` (`[workspace.package]`, the single source that every crate inherits);
- the version of each workspace crate in `Cargo.lock`;
- the new section of `CHANGELOG.md`.

Each merge into `main` makes this pull request out of date. Release-please regenerates it on that same push, and its checks run again.

Read the changelog before merging; you can edit `CHANGELOG.md` on the release branch. Do it last: a later merge into `main` regenerates the pull request. The notes of the GitHub release may come from the pull request description rather than from `CHANGELOG.md`: check them on the published release, and edit them there if needed (`gh release edit <tag> --notes-file`). For the first release in particular, the commits that predate this procedure have no Conventional Commits title and are missing from the changelog: complete the section by hand.

### 3. Merge the release pull request

Merge it when you want to release. Release-please then creates the tag `vX.Y.Z` and a **draft** release that holds the release notes. The tag starts `release.yml`.

Before merging, you can run `ci` by hand on `main` to get the full double build of the three targets (`gh workflow run ci.yml --ref main`). Pull requests only run the `x86_64-unknown-linux-musl` double build, and only when they change the build environment. A tag does not move: a build that fails at release time costs a new version.

### 4. `release.yml` builds and publishes

1. **`tag and version`**: the tag's commit is an ancestor of `main`, and the tag is `v` followed by the workspace version.
2. **`double build`** (`repro-build.yml`): each target is built twice, on two fresh runners. `scripts/repro-build.sh` builds `barking-cli`, `barking-node` and `barking-push` separately, and refuses the build if the dependency tree of the node or of the push relay contains OpenSSL or SQLCipher. `scripts/compare-copies.sh` then compares the two copies byte by byte and merges `SHA256SUMS`. Any difference stops the release.
3. **`attestation and publication`**: checks the file names and the checksums, produces the provenance attestation of each binary, attaches the nine binaries and `SHA256SUMS` to the draft, then publishes it. A release is therefore never visible without its files.
4. **`image node`** and **`image push`**: once the release is published, builds the images from those same files for `linux/amd64` and `linux/arm64`, pushes them to `ghcr.io/nakocorp/barking-node` and `ghcr.io/nakocorp/barking-push`, and attests each image digest. The attestation is stored in the registry next to the image.

Image tags: `X.Y.Z`, `X.Y` and `latest`. A pre-release (`X.Y.Z-rc.N`) only gets its exact tag and moves neither `X.Y` nor `latest`.

### 5. Final check

As any user would (it is the same command as in [VERIFYING.md](VERIFYING.md)), from an up-to-date clone that contains the tag:

    git fetch --tags
    scripts/verify-release.sh <version> --rebuild

`<version>` is written without the `v` prefix, for example `0.2.0`. It must end with `Version <version> verified ✓`. This local rebuild is the only check made outside GitHub: do it for every release.

## Choosing the version

Release-please computes the next version from the titles merged since the last release. To force another one, such as `1.0.0` or a pre-release, end the description of a pull request with a `Release-As:` footer:

    Release-As: 1.0.0

The description becomes the body of the squash commit (setting 5 above), where release-please reads the footer. The release pull request then proposes that version.

## Rehearsing with a pre-release

Before the first release, and after any change to the release workflows, rehearse on a pre-release:

1. Open a pull request with an empty commit, titled `chore: release rehearsal`, whose description ends with `Release-As: 0.2.0-rc.1`. Merge it.
2. Merge the release pull request that follows.
3. Check the result:
   - the tag `v0.2.0-rc.1` exists, and the release is published with nine binaries and `SHA256SUMS`;
   - (the packages are private until you make them public, setting above: run `docker login ghcr.io` first)
   - `docker buildx imagetools inspect ghcr.io/nakocorp/barking-node:0.2.0-rc.1` lists `linux/amd64` and `linux/arm64`;
   - the image tags `latest` and `0.2` do **not** exist;
   - `docker run --rm ghcr.io/nakocorp/barking-push:0.2.0-rc.1 --version` prints the version;
   - `scripts/verify-release.sh 0.2.0-rc.1 --rebuild` ends with `verified ✓`;
   - rerunning `release.yml` (`gh run rerun <run-id>`) succeeds.

Check the version that the next release pull request proposes, and set it with `Release-As:` if it is not the one you want.

## Preserving the Alpine environment

Linux builds use the pinned Rust/Alpine image and the APK versions in `docker/apk/build.txt`. Before a release, keep the signed APKs and the matching indexes in an immutable mirror, or keep the build image by its digest: the public Alpine repositories may remove old revisions. To change the image (digest) or a package, regenerate the full list (sorted `package=version` lines, the format that `docker/apk/install.sh` compares) and check that it is the same on x86-64 and ARM64, then get `ci` to pass (the pull request runs the double build): `docker/apk/install.sh` rejects any difference. `docker/apk/release.txt` plays the same role for the test image of the release scripts, and `docker/apk/push.txt` for the CA bundle of the `barking-push` image. Fuzzing keeps its Debian (glibc) image: AddressSanitizer does not support musl targets.

## Changing the CI's Xcode

`.xcode-version` fixes the macOS runner (`runner=`), the Xcode version (`xcode=`) and the SDK version (`sdk=`). The workflows select that Xcode, and the double build fails if the runner or the SDK differs. When GitHub removes that Xcode or runner from its images, choose a version listed in the image's README (`actions/runner-images` repository, `images/macos/macos-<n>-arm64-Readme.md`, sections "Xcode" and "Installed SDKs"). Update `.xcode-version`, the `runner` of the macOS rows of the matrix in `repro-build.yml` and the `runs-on` of the macOS jobs in `ci.yml`, then run `ci` by hand (`workflow_dispatch`). Each tag records its `.xcode-version`: an old version is rebuilt with the Xcode of its tag.

## When something fails

A difference between two builds means a non-reproducible build, a new source of non-determinism, or a compromise. Do not work around it.

- **`tag and version` fails.** The tag is not on `main`, or it does not match the workspace version. Nothing is built.
- **The comparison of the copies differs.** Nothing is attested or published; the tag and the draft stay. Open an issue with the workflow log. Look first for benign causes: a macOS runner image updated by GitHub with a different clang for the same Xcode, or an interrupted macOS build that left `/private/tmp/barking-repro-darwin` behind (delete it and rerun; this has no effect on the checksums).
- **A later job fails** (network, registry, GitHub API). Rerun the workflow: `gh run rerun <run-id>`. The publication job replaces the files of a draft and leaves an already published release untouched; the image jobs then run again. The build artifacts are kept for 7 days: after that, rerun all the jobs, not only the failed ones.
- **`no draft release for vX.Y.Z`.** The tag was pushed by hand. Releases are cut by merging the release pull request, never by pushing a tag.
- **Several releases exist for the tag.** Keep the one created by release-please, delete the others, then rerun the workflow.
- **The final check reports that the local rebuild differs.** To get the two checksums to compare:

        gh release download v<version> -R NaKoCorp/Barking --dir <d1>
        scripts/repro-build.sh --target <target> --ref v<version> --out <d2>

  then compare the lines of `<d1>/SHA256SUMS` and `<d2>/SHA256SUMS`. Check first that you built the right commit (`git rev-parse v<version>^{commit}`) and, for macOS, with the SDK of `.xcode-version` (`repro-build.sh` normally refuses another one). Open an issue with the two checksums, the tag's commit, the machine and the Docker version, or the Xcode version for macOS.

**Never move a tag.** The binary contains the commit date, so a recreated or amended commit gives different checksums. Fix the cause on `main` and release a new version. The draft of the failed version can be deleted (`gh release delete v<version> -R NaKoCorp/Barking`); its tag stays.

**Withdrawing a published release.** If a binary is disputed, delete the release (`gh release delete v<version> -R NaKoCorp/Barking`), delete the matching image versions on the two package pages of ghcr.io, and announce it. The image tags `X.Y` and `latest` that pointed to those versions go with them. Then publish a fixed version.

## Script tests

    scripts/tests/repro-twice.sh        # two builds from two paths, same checksums (Docker)
    scripts/tests/release-scripts.sh    # verify-release.sh against valid and tampered releases (Docker, offline)
    bash scripts/tests/ci-scripts.sh    # pull request titles, CI gate, comparison of the copies (no Docker)
    scripts/tests/images.sh <dir> <version>   # the two images build and start from a release directory

In `ci.yml`, the `release scripts` job runs `release-scripts.sh`, `ci-scripts.sh`, `stack-init.sh` and `compose-config.sh`, and `scripts/check.sh` runs the format, clippy and Rust tests, on every pull request. `repro-twice.sh` and `images.sh` run on pull requests that change the build environment (lockfile, manifests, `build.rs`, toolchain, `docker/`, `.xcode-version`, build scripts, workflows); the `double build (PR)` job still reports, with its build skipped, on the others. Run by hand (`workflow_dispatch`), `ci` does the full double build of all targets with comparison of the copies, as `release.yml` does on every tag.

A push to `main` does not repeat what its pull request validated. The `gate` job (`scripts/ci-gate.sh`) skips the checks when the merged tree is exactly the tree the pull request tested and that run was green. In any other case, and in any doubt, the full CI runs.
