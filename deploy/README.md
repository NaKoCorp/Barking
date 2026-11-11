# Run Barking with Docker Compose

[`compose.yaml`](compose.yaml) runs a `barking-node` and, behind the `relay` profile, the `barking-push` relay that wakes iOS devices through APNs.

- **Anyone** can run a node. Wake-ups need no setting: the iOS app tells each node which relay to call.
- **NaKoCorp** runs the node **and** the relay, whose identity and seal key are built into the iOS app.

Both must be reachable from the internet: TestFlight and App Store builds refuse private addresses.

These steps work on a Mac with Docker Desktop (IPv4) and on a Linux server with Docker Engine (IPv4, IPv6 or both, see [IPv6 server](#ipv6-server)). For a systemd host without Docker, see [`docs/deploy`](../docs/deploy).

## 1. Get a verified release

The images are built from the static binaries of a release. Each binary is checked against `SHA256SUMS`.

1. Download the release files (`barking-node-…`, `barking-push-…` for NaKoCorp, `SHA256SUMS`, `SHA256SUMS.minisig`) into `dist/`.
2. Verify them as described in [Verify a binary](../README.md#-verify-a-binary) (`scripts/verify-release.sh`).

Use the `aarch64` binaries on Apple silicon and the `x86_64` ones on Intel. Alternatively, build them yourself with `scripts/repro-build.sh --target aarch64-unknown-linux-musl`.

## 2. Run a node

```sh
scripts/stack-init.sh --version 0.1.0 --public-addr <public-ipv4>:4433
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml exec node /barking-node status
```

`stack-init.sh` performs these steps:

1. writes `deploy/.env` and `deploy/config/barking-node.toml`;
2. builds the image;
3. creates the node key in the `barking_node-data` volume;
4. prints the identifier and the address to publish.

`--public-addr` is the public address of the server: `IPV4:PORT`, `[IPV6]:PORT`, or one of each (pass the option twice). The node publishes it in its signed record, so it cannot be a DNS name. The script refuses a private, local or reserved address, as the node does.

It also refuses to run twice. Without `--relay`, `--force` stops the node and deletes its volume, and with it the node's key and stored packets. A running relay is left alone.

If a run fails, the script removes the configuration and the volumes it created, so you can run it again without `--force`.

## 3. NaKoCorp: node and push relay

You need the APNs authentication key (`.p8`) of the app, with its key id and the Apple team id. Keep it outside the repository, for example in `~/.apple/`.

```sh
scripts/stack-init.sh --version 0.1.0 --public-addr <public-ipv4>:4433 \
  --relay --relay-host relay.example.org \
  --apns-key ~/.apple/AuthKey_FGHIJ67890.p8 --team-id ABCDE12345 --key-id FGHIJ67890
docker compose -f deploy/compose.yaml --profile relay up -d
```

The relay's key, seal key and a copy of the `.p8` live in the `barking_relay-secrets` volume. They are owned by the container user with mode `0600`.

The script ends with five lines to put in `apple/Local.xcconfig`:

```
BARKING_RELAY_HOST = relay.example.org
BARKING_RELAY_PORT = 4434
BARKING_RELAY_ID = …
BARKING_RELAY_SEAL_ID = 1
BARKING_RELAY_SEAL_PUBLIC = …
```

These values are **built into the app**: changing the host, the relay key or the seal key requires a new TestFlight build. Prefer a stable DNS name (dynamic DNS for a home connection) to an IP address.

A node that is already running keeps its key when you add `--relay` later.

> **Warning:** `--relay --force` stops the whole stack and deletes **both** volumes. The relay then gets a new identity and a new seal key. Every installed build stops receiving wake-ups until a new TestFlight build carries the new `Local.xcconfig` values. Only use it to start over.

## 4. Hosting on a Mac

- **Router.** Forward UDP 4433 (node) and, for the relay, UDP 4434 to the Mac. Give the Mac a fixed address on the local network (DHCP reservation).
- **Public address.** A fixed IP is best. With a dynamic one, give the relay a dynamic DNS name (`--relay-host`): nodes resolve it at each wake-up. The node's own `public_addr` is an IP: when it changes, edit it in `deploy/config/barking-node.toml` and run `docker compose -f deploy/compose.yaml up -d --force-recreate node`. A plain `restart` can keep the old file, since editors often replace it. Do not use `--force`, which deletes the keys.
- **Always on.** Prevent sleep (System Settings › Energy, or `sudo pmset -a sleep 0`), start Docker Desktop at login, and keep the services' `restart: unless-stopped`.
- **Docker Desktop hides client addresses.** On a Mac, published ports go through Docker Desktop's proxy, so the containers likely see every peer coming from the same internal address. The node's per-address limits (`max_connections_per_ip`, 8 by default) then apply to all peers together, and it does not learn peers that connect to it. The relay's per-address limits behave the same way. This is fine for a TestFlight test with a few devices. A node meant to serve the public network belongs on Linux with Docker Engine, where peer addresses are preserved. To check on your Mac: `docker run --rm -p 5000:5000/udp alpine nc -ulv -p 5000`, send a datagram from an outside host, and look at the source address it prints.
- **Logs and state.** `docker compose -f deploy/compose.yaml logs -f relay`, `… exec node /barking-node status`.

## IPv6 server

On a Linux server with a public IPv6, the node and the relay can be reached over IPv6, alone or next to IPv4:

```sh
scripts/stack-init.sh --version 0.1.0 --public-addr 203.0.113.7:4433 --public-addr '[2001:db8:1::7]:4433'
```

(Replace the example addresses with yours: the script refuses documentation ranges.)

Given an IPv6 address, the script:

- sets `BARKING_IPV6=true` in `deploy/.env`, so the compose network gets IPv6;
- makes both services listen on `[::]`, which also accepts IPv4.

Docker Engine then publishes the ports on the host's IPv6 and keeps the peers' source addresses.

- **Docker Engine 27 or later.** It gives IPv6 networks an address range by itself and filters them with ip6tables. With an older engine, enable `"ipv6": true` and `"ip6tables": true` in `/etc/docker/daemon.json`, then restart Docker.
- **Firewall.** IPv6 has no port forwarding, but the provider's or the host's firewall usually blocks inbound traffic. Open UDP 4433 (node) and 4434 (relay) for IPv6, for example `ufw allow 4433/udp` and `ufw allow 4434/udp`, and in the provider's panel.
- **Stable address.** Publish the server's fixed address, not a temporary (privacy) one. If the provider changes the prefix, update `public_addr` (see Hosting on a Mac, "Public address"; the steps are the same).
- **Relay host.** `--relay-host` accepts a DNS name, an IPv4 or an `[IPv6]` in brackets. A DNS name with A and AAAA records is best: nodes on either family can reach the relay, and the address can change without a new app build.
- **On a Mac,** Docker Desktop's IPv6 publishing is not guaranteed. Prefer IPv4 there.

## 5. Check that the node reaches its relay (hairpin NAT)

The node only dials public relay addresses. On the Mac that hosts both, it reaches its own relay through the router's public address. This only works if the router supports *hairpin NAT* (also called NAT loopback).

1. Start the stack with the relay profile.
2. On an iPhone running a build with the `Local.xcconfig` values, open the app once so that it subscribes.
3. From a network **outside** your home (a phone hotspot), send a message to that account with the `barking` CLI.
4. Watch `docker compose -f deploy/compose.yaml logs -f relay`. The relay's periodic report must count the wake-up, and the iPhone must show a notification with the app closed.

If the node logs connection failures to the relay while the relay is reachable from outside, the router does not loop back. Enable NAT loopback in its settings, if it has the option. No workaround is provided here.

## Update

1. Verify the new release and put it in `dist/`.
2. Set `BARKING_VERSION` in `deploy/.env`.
3. Run `docker compose -f deploy/compose.yaml [--profile relay] up -d --build`.

The volumes, and therefore the keys, are kept.

## Seal key rotation

Not automated. Follow the two-key procedure of [`barking-push.toml.example`](../docs/deploy/barking-push.toml.example):

1. Create the new key with `docker compose -f deploy/compose.yaml --profile relay run --rm --entrypoint /barking-push relay keygen-seal --out /var/lib/barking-push/seal2.key --id 2`.
2. List both keys in `deploy/config/barking-push.toml`.
3. Ship an app build with the new key.
4. Remove the old key once the old builds have expired.
