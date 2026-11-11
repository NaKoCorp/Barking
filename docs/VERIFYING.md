# Verifying a Barking release

This page explains how to check that a published `barking-cli`, `barking-node` or `barking-push` (iOS notification relay) binary, or a published container image, was built by the project's release workflow from the public source code, and how to rebuild it yourself. It also describes how to become an independent rebuilder.

## What is verified

Each `vX.Y.Z` release published on GitHub contains, for each target, three binaries, `barking-cli-<version>-<target>`, `barking-node-<version>-<target>` and `barking-push-<version>-<target>` (same version for all three), plus `SHA256SUMS`. The targets are `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `aarch64-apple-darwin` (macOS, not notarized).

Verification has three steps:

1. **Checksums**: each binary has the SHA-256 checksum listed in `SHA256SUMS`, and no file is extra or missing.
2. **Provenance attestations**: GitHub certifies that each binary was produced by the `.github/workflows/release.yml` workflow of the repository, from the `refs/tags/v<version>` tag, on a GitHub-hosted runner (`--deny-self-hosted-runners`). If the tag exists in your clone, the attestation must also name the commit that your tag points to: a moved tag is rejected. If the tag is absent from your clone, the script says so and the commit is not compared.
3. **Rebuild** (optional, with `--rebuild`): the script rebuilds the binaries from the tag on your machine and compares them with the published ones.

## Trust model

There is no maintainer signature: no key held offline signs a release. A release is built, attested and published by the release workflow alone, as soon as two independent builds of each target are identical.

**GitHub is therefore the only root of trust of steps 1 and 2.** The attestations are Sigstore signatures issued to the workflow run. They prove where a binary was built: this repository, the release workflow, this tag and this commit. They do not protect against a compromise of GitHub, of its runners or of the release workflow, and whoever takes over a maintainer account can publish a release that passes both steps.

**The independent rebuild is the counter-check.** The builds are reproducible: anyone can rebuild a release from its tag and must get the same bytes. A binary that does not come from the tagged source cannot pass step 3, whatever the attestation says. This is the only check that does not rest on GitHub's build and signing infrastructure. It shows that the binary matches the source; it says nothing about the source itself, which is public and reviewable.

In practice:

- run `scripts/verify-release.sh <version> --rebuild` when you can;
- otherwise, look in the `barking-rebuilds` repository for rebuilds published by people you trust (see [Becoming an independent rebuilder](#becoming-an-independent-rebuilder)).

## Prerequisites

- `git` and `gh` (GitHub CLI, logged in with `gh auth login`), version 2.68.0 or newer: it is the first version that accepts `gh attestation verify --source-ref` (`--signer-workflow` and `--deny-self-hosted-runners` are older);
- for the rebuild: Docker for the Linux targets, and Docker as well on an Apple Silicon Mac. For `aarch64-apple-darwin`, you also need `rustup` and the Xcode given in `.xcode-version` (see "Limits").

Clone the repository and go to its root:

    git clone https://github.com/NaKoCorp/Barking.git
    cd Barking

## Quick verification

    scripts/verify-release.sh <version>

`<version>` is written without the `v` prefix, for example `scripts/verify-release.sh 0.2.0`. The script takes the GitHub repository from `--repo <owner/repo>`, otherwise from the `BARKING_REPO` variable, otherwise from the URL of the clone's `origin` remote. It downloads the files of release `v<version>` with `gh`, then runs the steps in order:

1. binary checksums;
2. attestations (`gh attestation verify` for each binary, bound to the `release.yml` workflow, the `v<version>` tag and its commit);
3. rebuild: not requested.

It ends with `Version <version> verified ✓` and exit code 0. If anything goes wrong, it prints "FAILURE at step …" and exits with code 1: do not use the binary in that case.

Fetch the tags first (`git fetch --tags`), so that step 2 can compare the attested commit with your tag.

To verify files that you already downloaded, pass `--from-dir <dir>` instead of letting the script call `gh release download`. The directory must contain `SHA256SUMS` and **all** the binaries of the release: a binary listed in `SHA256SUMS` but missing makes verification fail. The attestations are still requested from GitHub: step 2 is never skipped, and it needs `gh` and a network connection.

## Full verification: rebuilding

    scripts/verify-release.sh <version> --rebuild

In addition to the first two steps, the script rebuilds from tag `v<version>`, then compares the resulting binaries with those of the release. The rebuild uses **the build environment recorded in the tag** (`scripts/repro-build.sh`, `docker/repro.Dockerfile`, `.xcode-version`, `rust-toolchain.toml`, extracted from the tag with `git archive`), never the one in your working tree. If the tag does not contain these files, the script stops and says so: rebuild by hand in that case. It rebuilds every target it can build on your machine:

- Linux x86_64: the `x86_64-unknown-linux-musl` target, via Docker;
- Linux arm64: the `aarch64-unknown-linux-musl` target, via Docker;
- macOS arm64: the `aarch64-unknown-linux-musl` target, which requires Docker (without Docker, the script fails on an arm64 Mac); and the `aarch64-apple-darwin` target, natively, only with `rustup` and the Xcode/SDK from `.xcode-version`. Otherwise, the script announces that this target is not rebuilt here: for it, trust relies on the CI's double build, the attestation and independent rebuilds.

Each Linux target is built natively on its own architecture, never under emulation. The other targets are not compared. If no target can be built on your machine, the script fails: nothing was rebuilt.

Tag `v<version>` must exist in your clone (`git fetch --tags`).

To compare against builds you have already made, use `--rebuilt-dir <dir>` (it implies `--rebuild`). The directory must contain **all** the targets your machine can build, produced by `repro-build.sh` (same `--out`): a target that can be built here but is missing from the directory makes the script fail.

    scripts/repro-build.sh --target <target> --ref v<version> --out <dir>
    scripts/verify-release.sh <version> --rebuilt-dir <dir>

`repro-build.sh` writes the binaries `barking-cli-<version>-<target>`, `barking-node-<version>-<target>` and `barking-push-<version>-<target>` and `SHA256SUMS` to `<dir>` (`dist/` by default) and prints the checksum.

If you only build a single target, compare by hand: build with `scripts/repro-build.sh --target <target> --ref v<version> --out <dir>`, then compare the printed checksums (one per binary, or those in `<dir>/SHA256SUMS`) with the matching lines of the release's `SHA256SUMS`.

### Building with the right reference

The binary embeds the commit date (`SOURCE_DATE_EPOCH` is the timestamp of the commit being built: only this timestamp changes the binary, not the commit identifier). You must therefore build **exactly the tag's commit**. A recreated or amended commit, even with identical content, has a different timestamp and produces a different binary. If your checksums differ, first check that `git rev-parse v<version>^{commit}` is the expected commit.

### Limits

- **Linux**: the build runs in a Docker image pinned by its digest, with Rust 1.99.1 on Alpine and a full set of pinned APK versions in `docker/apk/build.txt`. Old Alpine packages can disappear from public repositories: keep an immutable archive of them, or the build image, for long-term rebuilds (see [RELEASING.md](RELEASING.md)). Docker is required.
- **macOS**: the build is native, in the fixed directory `/private/tmp/barking-repro-darwin`. If this directory already exists, the script refuses to start: delete it after an interrupted build. The deployment target is fixed at macOS 11.0. **Reproducibility is only guaranteed with the same Xcode and macOS SDK versions as the CI.** They are pinned in `.xcode-version` (GitHub runner, Xcode version, SDK version); the workflows select that Xcode and check the SDK. `repro-build.sh` refuses to build this target if `xcodebuild -version` or `xcrun --show-sdk-version` differ ("Xcode/SDK differs from the CI's"): install that Xcode and select it with `sudo xcode-select -s /Applications/Xcode_<version>.app`. `rustup` is also required: Homebrew's `rustc`, even at the same version, is not the official toolchain and does not reproduce the binary. The script prints the Xcode, SDK, clang and rustc versions used.

## Container images

Each release also publishes two images, for `linux/amd64` and `linux/arm64`:

- `ghcr.io/nakocorp/barking-node`
- `ghcr.io/nakocorp/barking-push`

They carry the tags `X.Y.Z`, `X.Y` and `latest`; a pre-release (`X.Y.Z-rc.N`) only has its exact tag. An image contains the static Linux binary of the release and nothing else (`barking-push` also has a CA bundle), on an empty base, and runs as the unprivileged user `65532`. The release workflow builds the images from the very files it attaches to the release, and the build checks each binary against `SHA256SUMS`.

The release workflow attests each image, as it does each binary. To verify an image:

    gh attestation verify oci://ghcr.io/nakocorp/barking-node:<version> -R NaKoCorp/Barking

To also require the release workflow, the tag and a GitHub-hosted runner, as `verify-release.sh` does for the binaries:

    gh attestation verify oci://ghcr.io/nakocorp/barking-node:<version> -R NaKoCorp/Barking \
      --signer-workflow NaKoCorp/Barking/.github/workflows/release.yml \
      --source-ref refs/tags/v<version> --deny-self-hosted-runners

A tag can be moved to another image later; a digest cannot. Read the digest of the image you verified, verify it and run it by digest:

    docker buildx imagetools inspect ghcr.io/nakocorp/barking-node:<version>
    gh attestation verify oci://ghcr.io/nakocorp/barking-node@sha256:<digest> -R NaKoCorp/Barking
    docker pull ghcr.io/nakocorp/barking-node@sha256:<digest>

Use the digest of the image index, printed on the `Digest:` line: it covers both architectures.

The trust model is the same as for the binaries: the attestation rests on GitHub alone. For a check that does not, verify the release with `scripts/verify-release.sh <version> --rebuild`, then build the image yourself from the verified files (`docker/node.Dockerfile`, `docker/push.Dockerfile`; see [`deploy/README.md`](../deploy/README.md)).

## Becoming an independent rebuilder

Several identical rebuilds, made by different people, publicly attest that the binary matches the code. They are what makes the trust model hold for people who cannot rebuild themselves, and for the targets a given machine cannot build. To take part:

1. Rebuild a target from the tag, as above, on a machine you control.
2. Compare the resulting checksum with the one in `SHA256SUMS`, by hand or with `verify-release.sh --rebuilt-dir` if your directory contains all the targets that can be built on your machine.
3. Publish your result in the `barking-rebuilds` repository, as an entry in this format:

        version: <version>
        target: <target>
        sha256: <checksum of the binary you built>
        identical: yes|no
        date: <date of the rebuild, YYYY-MM-DD>

   The format above is fixed. Sign the entry with a key of your own (a signed commit is enough), and make your public key known so that the entry can be checked.

Also publish your `identical: no` results: that is precisely what raises the alarm. The `barking-rebuilds` repository is yet to be created; this format is the one fixed by the project.

## Update rule

Automatic updates do not exist yet. When they do, a node or an app will only install an update if:

- the release is authentic. How an updater establishes this without a maintainer signature will be decided with that code;
- the version is **strictly newer** than the installed one, which prevents forcing a rollback to a vulnerable version.

## Android and iOS

- **Android**: the APK will be reproducible when the Android app ships. Its contents will be compared excluding the signing block, as F-Droid does.
- **iOS**: an app installed from the App Store **cannot be verified**. Apple encrypts each binary and then re-signs it with its own keys, so the checksum of what you install cannot be compared with that of the source code. What the project does instead: document this limit here, and publish, for auditors, an iOS build built from the public code. It will make it possible to audit that code, but not to prove that the App Store version comes from it.

Neither of these apps has shipped yet. Today, releases contain `barking-cli`, `barking-node` and `barking-push`.
