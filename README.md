<div align="center">

# 🐕 Barking

**Open-source, end-to-end encrypted messaging that does not depend on a central server.**

Post-quantum key agreement · Double Ratchet · self-hosted relays · built for unreliable networks

[![CI](https://github.com/NaKoCorp/Barking/actions/workflows/ci.yml/badge.svg)](https://github.com/NaKoCorp/Barking/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-pinned%20toolchain-orange?logo=rust)
![Status](https://img.shields.io/badge/status-prototype-yellow)

[Quick start](#-quick-start) ·
[Features](#-features) ·
[Run a relay](#-run-a-relay) ·
[Verify a binary](#-verify-a-binary) ·
[Roadmap](#-roadmap)

</div>

---

> [!WARNING]
> Barking is a **prototype**. It has not been externally audited, relays can observe client IP addresses, and there is no public relay network yet. Do not rely on it for sensitive communications.

## ✨ Features

The current prototype ships a command-line client and decentralized internet relay nodes.

| | |
|---|---|
| 🔐 **Encrypted 1:1 messaging** | Identities with 24-word recovery phrases, contact cards, safety codes, delivery receipts, message history and persistent outgoing queues. Messages up to 4,000 UTF-8 bytes. |
| 🛡️ **Post-quantum session setup** | PQXDH (X25519 + ML-KEM) followed by a Double Ratchet. |
| 💾 **Encrypted local storage** | SQLCipher database, keyed from a passphrase in the CLI. |
| 📱 **Multiple devices** | Link up to eight devices to one identity through a file exchange, optionally transfer encrypted history, and synchronize contacts and messages. |
| 📦 **Two transports** | Move `.pkt` files by hand (USB key, email, anything), or run `barking sync` to send and receive through internet relays. |
| 🖧 **Self-hosted relays** | `barking-node` stores encrypted packets over QUIC until recipients fetch them. Config examples and systemd units in [`docs/deploy`](docs/deploy). |
| 🕸️ **Distributed routing** | S/Kademlia node discovery, replication between responsible nodes, client-side reliability scores and retries. |
| 📶 **Built for bad connections** | Resumable fetches, adaptive page sizes and saved synchronization progress. |
| 🔔 **iOS wake-ups (server side)** | Nodes accept wake subscriptions and notify `barking-push`, a stateless relay that forwards sealed tokens to APNs. |

## 🚀 Quick start

Install Rust with [rustup](https://rustup.rs); the toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

```sh
cargo build --release -p barking-cli -p barking-node -p barking-push
```

**1. Create an identity and export your contact card**

```sh
./target/release/barking init --name laptop
./target/release/barking card --display-name Alice
```

The CLI asks for a passphrase and stores its data in `~/.barking` (use `--home <dir>` for separate identities).

> [!IMPORTANT]
> Keep the recovery phrase offline. Recovering an identity does **not** restore its contacts or message history.

**2. Add a contact and a relay, then talk**

```sh
./target/release/barking add '<contact-card>' --alias bob
./target/release/barking node add <IP:port> <node-id>
./target/release/barking send bob 'Hello!' --out ./packets
./target/release/barking sync
./target/release/barking messages bob
```

`send` writes packet files **and** queues the message for network delivery. Each participant runs `sync` to push pending packets, receive messages and exchange delivery receipts. Synchronization is manual for now.

> [!NOTE]
> The built-in [bootstrap list](crates/barking-dht/bootstrap.toml) is empty. Add a reachable relay with `barking node add`, or get one from a contact card that carries valid node records.

## 🖧 Run a relay

<details open>
<summary><b>With Docker</b> (~5 MB image)</summary>

Each release publishes the image `ghcr.io/nakocorp/barking-node` for `linux/amd64` and `linux/arm64`, with the tags `X.Y.Z`, `X.Y` and `latest` (and `ghcr.io/nakocorp/barking-push` for the push relay). It holds the static `barking-node` binary of the release alone on an empty base. No release has been published yet: until the first one, build the image yourself as shown below. To check where an image comes from, see [docs/VERIFYING.md](docs/VERIFYING.md#container-images).

```sh
docker run --rm -v barking-node:/var/lib/barking-node ghcr.io/nakocorp/barking-node:<version> init
docker run -d --name barking-node -v barking-node:/var/lib/barking-node -p 4433:4433/udp ghcr.io/nakocorp/barking-node:<version>
```

To build the same image yourself, [`docker/node.Dockerfile`](docker/node.Dockerfile) takes a release directory as its build context and checks the binary against its `SHA256SUMS`:

```sh
docker build -f docker/node.Dockerfile --build-arg VERSION=<version> -t barking-node dist
```

To use a configuration file, mount it read-only and pass it to `run`:

```sh
-v ./barking-node.toml:/etc/barking-node.toml:ro <image> run --config /etc/barking-node.toml
```

`docker exec barking-node /barking-node status` shows what the node holds.

To run a node, or a node and the push relay, with Docker Compose on a Mac: see [`deploy/README.md`](deploy/README.md).

</details>

<details>
<summary><b>With systemd</b></summary>

See [`docs/deploy`](docs/deploy) for `barking-node.toml`, `barking-push.toml.example` and their systemd units.

</details>

## 🧱 Repository layout

| Crate | Role |
|---|---|
| [`barking-cli`](crates/barking-cli) | `barking` command-line client |
| [`barking-core`](crates/barking-core) | Messenger core: identities, PQXDH, Double Ratchet, storage (no network) |
| [`barking-packet`](crates/barking-packet) | Universal packet format |
| [`barking-proto`](crates/barking-proto) | Client-to-node protocol and QUIC client |
| [`barking-net`](crates/barking-net) | Client-side network view: node selection, reliability scores, sync state |
| [`barking-dht`](crates/barking-dht) | S/Kademlia discovery and replication |
| [`barking-node`](crates/barking-node) | Relay node |
| [`barking-push`](crates/barking-push) | Stateless APNs wake-up relay |
| [`barking-ffi`](crates/barking-ffi) | UniFFI bindings of the core for the mobile apps |
| [`apple/`](apple) | iOS app and its notification extension (XcodeGen project) |

## 🛠️ Development

```sh
scripts/check.sh
```

Runs formatting checks, Clippy and the workspace tests. Network integration tests open local UDP sockets.

```sh
scripts/install-hooks.sh
```

Installs the git hooks: before a commit, no credential file and no secret (gitleaks); before a push, also trivy (no HIGH or CRITICAL finding), cargo-deny (advisories, AGPL-compatible licenses) and the workflow linters. The CI runs the same `scripts/security-check.sh`. Tools: `brew install gitleaks trivy cargo-deny zizmor actionlint shellcheck`. Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

Linux release builds run in a pinned Rust/Alpine Docker image and produce static musl binaries; Apple binaries are built natively on macOS.

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (`feat: …`, `fix(node): …`): pull requests are squash-merged, and the title decides the next version and the changelog entry. The `PR title` check enforces the format (`scripts/check-pr-title.sh`).

## ✅ Verify a binary

Releases are automatic. Merging the release pull request makes the CI build `barking-cli`, `barking-node` and `barking-push` twice for each target, compare the two builds byte by byte, attest the binaries and publish them with their `SHA256SUMS`. The same workflow then pushes the container images `ghcr.io/nakocorp/barking-node` and `ghcr.io/nakocorp/barking-push` (`linux/amd64` and `linux/arm64`; tags `X.Y.Z`, `X.Y` and `latest`).

```sh
scripts/verify-release.sh <version>             # checksums and GitHub provenance attestations
scripts/verify-release.sh <version> --rebuild   # and rebuild the binaries locally, then compare
```

No maintainer key signs a release: GitHub's attestations are the only root of trust, and the reproducible build is the counter-check. Rebuild when you can.

- 📖 [docs/VERIFYING.md](docs/VERIFYING.md): how to verify a release or an image, the trust model and its limits
- 🏷️ [docs/RELEASING.md](docs/RELEASING.md): the maintainer's release procedure

> [!NOTE]
> No release has been published yet: the automated process still needs its end-to-end rehearsal.

## 🗺️ Roadmap

- [x] Encrypted one-to-one messaging (CLI)
- [x] Multi-device identities
- [x] Self-hosted QUIC relays with DHT routing and replication
- [x] Server side of iOS background wake-ups
- [ ] Android and iOS apps
- [ ] Mesh transports: Bluetooth LE, Wi-Fi, LoRa
- [ ] Groups and media attachments
- [ ] Tor / mixnet integration to hide client IPs from relays
- [ ] External security audit

## 📄 License

[AGPL-3.0-only](LICENSE)
