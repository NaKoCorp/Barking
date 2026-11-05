# Verifying a Barking release

This page explains how to check that a published `barking-cli`, `barking-node` or `barking-push` (iOS notification relay) binary matches the public source code exactly, and that the maintainer approved it. It also describes how to become an independent rebuilder. The full framework is in the spec, §15.

## What is verified

Each `vX.Y.Z` release published on GitHub contains, for each target, three binaries, `barking-cli-<version>-<target>`, `barking-node-<version>-<target>` and `barking-push-<version>-<target>` (same version for all three), plus `SHA256SUMS` and `SHA256SUMS.minisig`. The targets are `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `aarch64-apple-darwin` (macOS, not notarized).

Three checks complement each other:

1. **Maintainer signature**: `SHA256SUMS.minisig` is a minisign signature of `SHA256SUMS`, verified with `keys/maintainer.pub`. The signed comment must be exactly `barking v<version> commit <commit>`, where `<commit>` is the full identifier (40 hexadecimal characters) of the commit of tag `v<version>` in the maintainer's repository at signing time. The script prints this commit; if tag `v<version>` exists in your clone, it requires the tag to point to the same commit, and otherwise rejects the release (moved tag). If the tag is absent from your clone, it only reports it: the commit could not be checked locally.
2. **Checksums**: each binary has the SHA-256 checksum listed in `SHA256SUMS`, and no file is extra or missing.
3. **Provenance attestations**: GitHub certifies that each binary was produced by the `.github/workflows/release.yml` workflow, from the repository's `refs/tags/v<version>` tag. The attestation is bound to the workflow and the tag name, not to a commit hash: a moved tag would be accepted by this step alone, which is why the tag ruleset described in `docs/RELEASING.md` and the commit bound by the signature (check 1) matter. Attestations produced on a self-hosted runner are rejected (`--deny-self-hosted-runners`).

**What the signature really attests.** The maintainer signs only after rebuilding, on their own machine, the targets that machine can build: a Linux x86_64 machine rebuilds `x86_64-unknown-linux-musl`; an arm64 Mac rebuilds `aarch64-unknown-linux-musl` (Docker is then required), and `aarch64-apple-darwin` only if it has `rustup` and exactly the CI's Xcode and SDK (`.xcode-version` file): otherwise that target is skipped, with an explicit notice. For these targets, publishing a fake binary requires compromising both the CI and the offline key. For the other targets, the signature still covers all of `SHA256SUMS`, but it relies on the CI's double build, the attestation and the maintainer's approval: a compromised CI would be enough to get a binary signed, unless someone rebuilds that target. Independent rebuilds (see below) close this gap.

## Prerequisites

- `git`, `minisign` and `gh` (GitHub CLI, logged in with `gh auth login`), version 2.68.0 or newer: it is the first version that accepts `gh attestation verify --source-ref` (`--signer-workflow` and `--deny-self-hosted-runners` are older);
- for full verification: Docker for the Linux targets, and Docker as well on an Apple Silicon Mac. For `aarch64-apple-darwin`, you also need `rustup` and the Xcode given in `.xcode-version` (see "Limits").

Clone the repository and go to its root:

    git clone https://github.com/<owner>/barking.git
    cd barking

The maintainer's public key is `keys/maintainer.pub`. Check the full key line (the second line of the file, which starts with `RW`) against a channel independent of the repository, such as the project website or the release announcement. While the file is empty, verification stops with an explicit message: the maintainer has not published their key yet.

## Quick verification

    scripts/verify-release.sh <version> --repo <owner>/barking

`<version>` is written without the `v` prefix, for example `scripts/verify-release.sh 0.1.0 --repo <owner>/barking`. Without `--repo`, the script uses the `BARKING_REPO` variable, then the URL of the repository's `origin` remote. It downloads the files of release `v<version>` with `gh`, then runs the steps in order:

1. signature of `SHA256SUMS`;
2. binary checksums;
3. attestations (`gh attestation verify` for each binary, bound to the `release.yml` workflow and the `v<version>` tag);
4. rebuild: not requested.

It ends with `Version <version> verified ✓` and exit code 0. If anything goes wrong, it prints "FAILURE at step …" and exits with code 1: do not use the binary in that case.

Useful options:

- `--from-dir <dir>`: verifies files that were already downloaded instead of going through `gh release download`. The directory must contain `SHA256SUMS`, `SHA256SUMS.minisig` and **all** the binaries of the release: a binary listed in `SHA256SUMS` but missing makes verification fail;
- `--pubkey <file>`: uses a public key other than `keys/maintainer.pub`;
- `--skip-attestation`: skips step 3 (for example offline, with `--from-dir`). This check is then lost: do not place the same trust in the result.

## Full verification: rebuilding

    scripts/verify-release.sh <version> --rebuild --repo <owner>/barking

In addition to the three checks, the script rebuilds from tag `v<version>`, then compares the resulting binaries with those of the release. The rebuild uses **the build environment recorded in the tag** (`scripts/repro-build.sh`, `docker/repro.Dockerfile`, `.xcode-version`, `rust-toolchain.toml`, extracted from the tag with `git archive`), never the one in your working tree. If the tag does not contain these files (a release that predates this procedure), the script stops and says so: rebuild by hand in that case. It rebuilds every target it can build on your machine:

- Linux x86_64: the `x86_64-unknown-linux-musl` target, via Docker;
- Linux arm64: the `aarch64-unknown-linux-musl` target, via Docker;
- macOS arm64: the `aarch64-unknown-linux-musl` target, which requires Docker (without Docker, the script fails on an arm64 Mac); and the `aarch64-apple-darwin` target, natively, only with `rustup` and the Xcode/SDK from `.xcode-version`. Otherwise, the script announces that this target is not rebuilt here: for it, trust relies on the CI's double build, the attestation and independent rebuilds.

Each Linux target is built natively on its own architecture, never under emulation. The other targets are not compared. If no target can be built on your machine, the script fails: nothing was rebuilt.

Tag `v<version>` must exist in your clone (`git fetch --tags`).

To compare against builds you have already made, use `--rebuilt-dir <dir>` (it implies `--rebuild`). The directory must contain **all** the targets your machine can build, produced by `repro-build.sh` (same `--out`): a target that can be built here but is missing from the directory makes the script fail.

    scripts/repro-build.sh --target <target> --ref v<version> --out <dir>
    scripts/verify-release.sh <version> --rebuilt-dir <dir> --repo <owner>/barking

`repro-build.sh` writes the binaries `barking-cli-<version>-<target>`, `barking-node-<version>-<target>` and `barking-push-<version>-<target>` and `SHA256SUMS` to `<dir>` (`dist/` by default) and prints the checksum.

If you only build a single target, compare by hand: build with `scripts/repro-build.sh --target <target> --ref v<version> --out <dir>`, then compare the printed checksums (one per binary, or those in `<dir>/SHA256SUMS`) with the matching lines of the release's `SHA256SUMS`.

### Building with the right reference

The binary embeds the commit date (`SOURCE_DATE_EPOCH` is the timestamp of the commit being built: only this timestamp changes the binary, not the commit identifier). You must therefore build **exactly the tag's commit**. A recreated or amended commit, even with identical content, has a different timestamp and produces a different binary. If your checksums differ, first check that `git rev-parse v<version>^{commit}` is the expected commit.

### Limits

- **Linux**: the build runs in a Docker image pinned by its digest, with Rust 1.99.1 on Alpine and a full set of pinned APK versions in `docker/apk/build.txt`. Old Alpine packages can disappear from public repositories: keep an immutable archive of them, or the build image, for long-term rebuilds (see [RELEASING.md](RELEASING.md)). Docker is required.
- **macOS**: the build is native, in the fixed directory `/private/tmp/barking-repro-darwin`. If this directory already exists, the script refuses to start: delete it after an interrupted build. The deployment target is fixed at macOS 11.0. **Reproducibility is only guaranteed with the same Xcode and macOS SDK versions as the CI.** They are pinned in `.xcode-version` (GitHub runner, Xcode version, SDK version); the workflows select that Xcode and check the SDK. `repro-build.sh` refuses to build this target if `xcodebuild -version` or `xcrun --show-sdk-version` differ ("Xcode/SDK differs from the CI's"): install that Xcode and select it with `sudo xcode-select -s /Applications/Xcode_<version>.app`. `rustup` is also required: Homebrew's `rustc`, even at 1.94.1, is not the official toolchain and does not reproduce the binary. The script prints the Xcode, SDK, clang and rustc versions used.

## Becoming an independent rebuilder

Several identical rebuilds, made by different people, publicly attest that the binary matches the code (spec §15.5). They are also what closes the gap described above: for the targets the maintainer does not rebuild themselves, only independent rebuilds cover them. To take part:

1. Rebuild a target from the tag, as above, on a machine you control.
2. Compare the resulting checksum with the one in `SHA256SUMS`, by hand or with `verify-release.sh --rebuilt-dir` if your directory contains all the targets that can be built on your machine.
3. Publish your result in the `barking-rebuilds` repository, as an entry signed with **your own minisign key**:

        version: <version>
        target: <target>
        sha256: <checksum of the binary you built>
        identical: yes|no
        date: <date of the rebuild, YYYY-MM-DD>

   The format above is fixed; how to sign is a suggestion: `minisign -S -m <entry> -s <your key>`. Submit the entry with its `.minisig`. Add your public key to the repository, or publish it elsewhere, so that it can be checked.

Also publish your `identical: no` results: that is precisely what raises the alarm. The `barking-rebuilds` repository is yet to be created; this format is the one fixed by the project.

## Update rule

When automatic updates exist (the code comes later, the format is fixed now, spec §15.6), a node or an app will only install an update if:

- the maintainer's signature (or the k-of-n threshold, once the team grows) is valid;
- the version is **strictly newer** than the installed one, which prevents forcing a rollback to a vulnerable version.

## Android and iOS

- **Android**: the APK will be reproducible at step 3 of the roadmap (spec). Its contents will be compared excluding the signing block, as F-Droid does.
- **iOS**: an app installed from the App Store **cannot be verified**. Apple encrypts each binary and then re-signs it with its own keys, so the checksum of what you install cannot be compared with that of the source code. What the project does instead: document this limit here, and publish, for auditors, an iOS build built from the public code. It will make it possible to audit that code, but not to prove that the App Store version comes from it.

Neither of these apps has shipped yet. Today, releases contain `barking-cli`, `barking-node` and `barking-push`.
