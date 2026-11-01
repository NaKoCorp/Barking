# Barking

Barking is an open-source, end-to-end encrypted messaging project. The current prototype provides a command-line client and decentralized internet relay nodes. Mobile apps and mesh transports (Bluetooth LE, Wi-Fi and LoRa) are planned.

## Current status

The implementation includes:

- **Encrypted one-to-one text messaging:** identities with 24-word recovery phrases, contact cards, safety codes, delivery receipts, message history and persistent outgoing queues. Text messages can contain up to 4,000 UTF-8 bytes.
- **Encrypted local storage:** SQLCipher, with a passphrase-derived key in the CLI.
- **Multiple devices:** link up to eight devices to an identity through a file exchange, optionally transfer encrypted history, and synchronize contacts and messages.
- **Two ways to exchange packets:** manually transfer `.pkt` files, or run `barking sync` to send and receive through internet relays. Network synchronization is invoked manually.
- **Self-hosted relays:** `barking-node` stores encrypted packets for later retrieval over QUIC. Configuration examples and a systemd unit are available in [docs/deploy](docs/deploy).
- **Distributed routing and replication:** S/Kademlia node discovery and replication between responsible nodes, with client-side reliability scores and retries.
- **Support for unreliable connections:** resumable fetches, adaptive page sizes and saved synchronization progress.

The built-in [bootstrap list](crates/barking-dht/bootstrap.toml) is currently empty. To use the network, you need a reachable relay, supplied manually with `barking node add <IP:port> <node-id>` or discovered through a contact card containing valid node records.

Android and iOS apps, Bluetooth/Wi-Fi/LoRa mesh transports, groups and media attachments are not implemented yet. Relays can observe client IP addresses; Tor and mixnet integration are not implemented. An external security audit remains planned.

## Build and run

Install Rust through rustup; the repository pins its toolchain in [rust-toolchain.toml](rust-toolchain.toml).

```sh
cargo build --release -p barking-cli -p barking-node
./target/release/barking --help
./target/release/barking-node --help
```

Create an identity and export a contact card:

```sh
./target/release/barking init --name laptop
./target/release/barking card --display-name Alice
```

The CLI prompts for a passphrase and stores its data in `~/.barking` by default. Use `--home <directory>` to keep separate identities. Keep the recovery phrase offline; recovering an identity does not restore its contacts or message history.

After exchanging contact cards and adding a reachable relay:

```sh
./target/release/barking add '<contact-card>' --alias bob
./target/release/barking node add <IP:port> <node-id>
./target/release/barking send bob 'Hello!' --out ./packets
./target/release/barking sync
./target/release/barking messages bob
```

`send` writes packet files and queues the message for network delivery. Each participant runs `sync` to send pending packets, receive messages and exchange delivery receipts.

## Development checks

```sh
scripts/check.sh
```

This runs formatting checks, Clippy and the workspace tests. Network integration tests open local UDP sockets.

Linux release builds run in a pinned Rust/Alpine Docker image and produce static musl binaries; Apple binaries are built natively on macOS.

## Verify a binary

The release tooling covers `barking-cli` and `barking-node`: reproducible builds, GitHub CI attestations, an offline maintainer signature, and verification and rebuild scripts. The complete publication process still needs an end-to-end release rehearsal; the maintainer public key has not yet been published in the repository.

See [docs/VERIFYING.md](docs/VERIFYING.md) for verification instructions and limitations, and [docs/RELEASING.md](docs/RELEASING.md) for the maintainer's release procedure.
