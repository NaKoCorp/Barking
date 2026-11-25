# Run Barking with Docker Compose

[`compose.yaml`](compose.yaml) runs a `barking-node` and, behind the `relay` profile, the `barking-push` relay that wakes iOS devices through APNs.

- **Anyone** can run a node. Wake-ups need no setting: the iOS app tells each node which relay to call.
- **NaKoCorp** runs the node **and** the relay, whose identity and seal key are built into the iOS app.

Both must be reachable from the internet: TestFlight and App Store builds refuse private addresses.

These steps work on a Mac with Docker Desktop (IPv4) and on a Linux server with Docker Engine (IPv4, IPv6 or both, see [IPv6 server](#ipv6-server)). For a systemd host without Docker, see [`docs/deploy`](../docs/deploy).

## 1. Get a verified release

The images are built from the static binaries of a release. Each binary is checked against `SHA256SUMS`.

1. Download the release files (`barking-node-…`, `barking-push-…` for NaKoCorp and `SHA256SUMS`) into `dist/`.
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

## Node 0.5: Info and origin lookup

Node 0.5.0 speaks protocol 5 and answers a new `Info` request. The app uses it to show each node's state in its node list. A report holds:

- the software version, the protocol and the uptime;
- how full the node is, in coarse tiers (low, medium, high, full) for storage and for wake subscriptions, never exact counts;
- the state of the push link to the relay the app asked about (see below);
- the origin of the node (autonomous system and country), when known.

**Push link.** The node checks the push relays itself. Every 5 minutes it connects to each relay that its live subscriptions name, checks the relay's identity (`Hello`) and closes the connection; it sends no wake-up. A push relay refuses new connections while its own sends to Apple fail, so `Ok` means "the relay answers and its link to APNs works". The state never comes from the wake-ups the node sends, so it does not tell when users receive messages, and there is no subscription threshold: a relay used by a single person is reported like any other. What stays visible: the change from `Unknown` to a state shows, within 5 minutes, that a first subscription to that relay appeared on this node.

The host of a relay comes from whoever posted the subscription. Only a host that has already answered with the relay's identity (a proven host) can make the relay read `Failing`; a forged subscription with a dead host leaves at worst a relay never reached since the start `Unknown`. A relay that is down from the node's start therefore reads `Unknown`, not `Failing`, until it answers once. Bounds per 5-minute round: at most 32 relays (those with a proven host first), 6 hosts each, 8 at once, routable addresses only; nothing is logged. A node with `[wake] enabled = false` makes no probes. Expect outgoing QUIC connections to the push relays (UDP to their port) every 5 minutes.

The report is precomputed: answering it reads no database, and the node logs nothing about the client that asked, neither its IP address nor the relay it named. A 0.4 node does not understand `Info`: the app does not send it and shows no report for that node.

The origin comes from a lookup that the node makes itself, at startup, then 24 h after a success, or 1 h after a failure. It needs a public address in `[dht]`. The query name contains the node's own IP address, so the **system resolver and Team Cymru see it**: `origin.asn.cymru.com` for IPv4, `origin6.asn.cymru.com` for IPv6, then a second query, `AS<n>.asn.cymru.com`, for the name of the autonomous system. This is the address the node already publishes in its signed record.

Team Cymru answers are plain DNS, not authenticated. A resolver on the path can forge the origin; the app then shows it as a mismatch with its own IP base. To turn the lookup off, add this to `deploy/config/barking-node.toml`:

```toml
[info]
origin_lookup = false
```

The default is `true`. The report then carries no origin.

**Upgrade.** Update the 6 deployed nodes to 0.5.0 as described in [Update](#update). No configuration change is needed: `[info]` is optional and the other keys are unchanged. The nodes can be upgraded one at a time, and 0.4 and 0.5 nodes work together.

**IP base in the app.** The app checks the origin a node states against an embedded base, `apple/Barking/Resources/ipdb.bin` (DB-IP Lite, CC BY 4.0). Regenerate it for each app release (spec §6.3), with the source month as argument, and commit the result:

```sh
scripts/build-ipdb.sh 2026-12
```

The script downloads the country and ASN files into a temporary directory and rewrites `ipdb.bin` and `ipdb.LICENSE.txt`, which records the source month and the SHA-256 of `ipdb.bin`. It fails if the base exceeds 10 MB (10 485 760 bytes), the cap for the app bundle. Each regeneration adds a new binary of nearly 10 MB to the repository history, which is why it follows releases, not the calendar.

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

## Relay replicas

The relay can run on several servers behind one DNS name, `push.barking.nakocorp.com`. Every replica has the **same** relay identity and seal keys, so the app needs no change. Each replica has its **own** node and its own APNs key. Nodes fail over from one address of the name to the next. A replica whose APNs calls fail refuses connections, so nodes try the next one. A stopping replica refuses new connections and finishes its pushes in flight (10 s at most).

### Add a replica

The new server needs Docker Engine, a user in the `docker` group that you reach with `ssh` without a password prompt, and neither a relay nor a node yet. Create a new APNs key for it in the Apple developer account. From your clone, with the verified release in `dist/`:

```sh
scripts/relay-replica.sh --from relay1 --to relay2 \
  --public-addr <public-ipv4>:4433 --public-addr '[<public-ipv6>]:4433' \
  --apns-key ~/.apple/AuthKey_KLMNO12345.p8 --team-id ABCDE12345 --key-id KLMNO12345 \
  --version 0.1.0
```

`--from` and `--to` are ssh destinations (`user@host` or a `~/.ssh/config` alias). Both servers hold the deployment in `~/barking`. `--key-id` is the id of **this replica's** APNs key. The script:

1. checks the release for the target's architecture, the source's relay keys (it hashes them), and that the target has neither `barking_relay-secrets` nor `barking_node-data`; it changes nothing if a check fails;
2. copies `deploy/compose.yaml`, `docker/` and the release to `~/barking` on the target, and writes `deploy/.env` and both configuration files there;
3. builds the images and creates a new node identity;
4. streams `node.key` and the `seal*.key` files from the source's volume to the target's. They never touch your machine's disk. It then checks that the copied keys have the same SHA-256 on both servers (the sums are computed in a container on each server: only the sums travel);
5. installs the APNs key, starts the node and the relay, and waits for the target relay to log its identity, which it prints.

The source is only read: its relay keeps running and is never restarted.

If a step fails after the checks, the script removes the target's containers and volumes, so you can run it again. If that clean-up fails too, it prints a warning with the commands to run on the target by hand. It ends with the records to add:

```
relay id : …
A push.barking.nakocorp.com <public-ipv4>
AAAA push.barking.nakocorp.com <public-ipv6>
```

Add them only once the relay runs. Keep the records **DNS only** (not proxied) with a TTL of 60 s, so that a replica leaves the name within a minute.

Open UDP 4434 inbound on **every** replica (and UDP 4433 for its node), in the host's firewall and the provider's panel.

### Update without downtime

On the server, the deployment lives in `~/barking`: put the verified release in `~/barking/dist` and set `BARKING_VERSION` in `~/barking/deploy/.env`. Then, one replica at a time:

1. Remove its A and AAAA records.
2. Wait for the TTL (60 s).
3. Run `docker compose -f ~/barking/deploy/compose.yaml --profile relay up -d --build`. The relay finishes its pushes in flight before it stops.
4. Check the log: `docker compose -f ~/barking/deploy/compose.yaml --profile relay logs relay` must show `relay … started` with the same id, then `relay stats` lines with `available=true`.
5. Put the records back.

Deploy in this order: the NaKoCorp nodes first, then the relays, then the second replica.

### Remove a replica

1. Remove its A and AAAA records and wait for the TTL (60 s).
2. Stop and remove the relay container only (the server's node keeps running):

   ```sh
   docker compose -f ~/barking/deploy/compose.yaml --profile relay stop relay
   docker compose -f ~/barking/deploy/compose.yaml --profile relay rm -f relay
   ```

3. Delete its relay keys: `docker volume rm barking_relay-secrets`.
4. Revoke its APNs key in the Apple developer account.

### Seal key rotation on replicas

Apply the [two-key procedure](#seal-key-rotation) on **every** replica, with the same new key, before you ship the app build that carries it. Create the key on one replica (`relay1` below), then stream it to each other one (`relay2`), from container to container through ssh: it never touches your disk. Set `k` to the new key's file name:

```sh
k=seal2.key
ssh relay1 docker run --rm --network none -v barking_relay-secrets:/v:ro alpine tar -C /v -cf - "$k" \
  | ssh relay2 docker run --rm -i --network none -v barking_relay-secrets:/v alpine \
      sh -c "'tar -C /v --numeric-owner -xpf - && chown 65532:65532 /v/$k && chmod 600 /v/$k'"
```

Then check that every replica holds the same keys. The sums are computed on each server; the lines must be identical everywhere:

```sh
for h in relay1 relay2; do
  echo "== $h"
  ssh "$h" docker run --rm --network none -v barking_relay-secrets:/v:ro alpine sh -c "'cd /v && sha256sum node.key seal*.key'"
done
```

Only then list the new key in `deploy/config/barking-push.toml` and restart the relay, one replica at a time.

### A compromised replica

All replicas share one identity: if one server is compromised, the identity is compromised everywhere.

1. Revoke that replica's APNs key at once.
2. Create a new relay identity and seal key, and put them on every replica.
3. Ship a new app build with the new values.

### Limits per replica

The per-device quota and the per-node budget live in each replica's memory. With N replicas, a device or a node can get up to N times the limit in total. This is accepted: the limits protect each server, and N stays small (2 to 4).
