#!/usr/bin/env bash
# One-time set-up of the Docker Compose deployment (deploy/compose.yaml): a
# barking-node, and with --relay the barking-push relay too (NaKoCorp).
#
# Usage:
#   scripts/stack-init.sh --version V --public-addr IP:PORT [--force]
#       [--relay --relay-host NAME --apns-key PATH --team-id ID --key-id ID [--topic T]]
#
# Writes deploy/.env and deploy/config/*.toml, builds the images from the
# verified release in dist/, creates the keys inside the named volumes (as the
# container user), copies the APNs key there, and prints the values the iOS
# app needs (apple/Local.xcconfig). Keys are never overwritten without --force.
# Exit codes: 0 success, 2 invalid usage, 1 any other error.
# Runs on the macOS bash (3.2).
set -euo pipefail

root="${BARKING_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
compose_file="$root/deploy/compose.yaml"
config_dir="$root/deploy/config"
node_toml="$config_dir/barking-node.toml"
push_toml="$config_dir/barking-push.toml"
# Same pinned base as docker/node.Dockerfile; only used to install the APNs key.
alpine="alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
# Named volumes of deploy/compose.yaml (project name `barking`).
node_volume="barking_node-data"
relay_volume="barking_relay-secrets"
node_port=4433
relay_port=4434
seal_id=1

usage() {
  sed -n '5,7p' "$0" | sed 's/^# \{0,1\}//' >&2
}
usage_error() { echo "error: $*" >&2; usage; exit 2; }
fail() { echo "error: $*" >&2; exit 1; }

# Address checks (ip_is_public, host_is_public, addr_family) and apple_id.
# shellcheck source=scripts/deploy-lib.sh
. "$(dirname "$0")/deploy-lib.sh"

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) echo aarch64 ;;
    x86_64 | amd64) echo x86_64 ;;
    *) fail "unsupported host architecture $(uname -m)" ;;
  esac
}

# --- arguments ------------------------------------------------------------

version="" public_v4="" public_v6="" force=0 relay=0
relay_host="" apns_key="" team_id="" key_id="" topic="com.nakocorp.barking"
need_value() { [ "$2" -ge 2 ] || usage_error "$1 expects a value"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) need_value "$1" "$#"; version="$2"; shift 2 ;;
    --public-addr)
      need_value "$1" "$#"
      family="$(addr_family "$2")" || usage_error \
        "--public-addr must be a public IPV4:PORT or [IPV6]:PORT of this server, reachable from the internet (got $2)"
      if [ "$family" = 4 ]; then
        [ -z "$public_v4" ] || usage_error "--public-addr: at most one IPv4 address"
        public_v4="$2"
      else
        [ -z "$public_v6" ] || usage_error "--public-addr: at most one IPv6 address"
        public_v6="$(lower "$2")"
      fi
      shift 2
      ;;
    --force) force=1; shift ;;
    --relay) relay=1; shift ;;
    --relay-host) need_value "$1" "$#"; relay_host="$2"; shift 2 ;;
    --apns-key) need_value "$1" "$#"; apns_key="$2"; shift 2 ;;
    --team-id) need_value "$1" "$#"; team_id="$2"; shift 2 ;;
    --key-id) need_value "$1" "$#"; key_id="$2"; shift 2 ;;
    --topic) need_value "$1" "$#"; topic="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown option $1" ;;
  esac
done

[ -n "$version" ] || usage_error "--version is required"
case "$version" in *[!0-9A-Za-z.-]*) usage_error "--version: invalid version $version" ;; esac
[ -n "$public_v4$public_v6" ] || usage_error "--public-addr is required"

if [ "$relay" -eq 1 ]; then
  [ -n "$relay_host" ] || usage_error "--relay needs --relay-host"
  host_is_public "$relay_host" \
    || usage_error "--relay-host must be a public DNS name, IPv4 or [IPv6] address, without a port (got $relay_host)"
  case "$relay_host" in \[*) relay_host="$(lower "$relay_host")" ;; esac
  [ -n "$apns_key" ] || usage_error "--relay needs --apns-key"
  [ -f "$apns_key" ] || usage_error "--apns-key: no such file: $apns_key"
  # Mounted with --mount, whose value is comma-separated.
  case "$apns_key" in *,*) usage_error "--apns-key: the path must not contain a comma" ;; esac
  apns_key="$(cd "$(dirname "$apns_key")" && pwd)/$(basename "$apns_key")"
  [ -n "$team_id" ] || usage_error "--relay needs --team-id"
  [ -n "$key_id" ] || usage_error "--relay needs --key-id"
  # `case`, not grep: grep accepts a value if any one of its lines matches, and
  # these values are written into the TOML as they are.
  apple_id "$team_id" || usage_error "--team-id must be the 10-character Apple team identifier"
  apple_id "$key_id" || usage_error "--key-id must be the 10-character APNs key identifier"
  case "$topic" in
    '' | *[!A-Za-z0-9.-]*) usage_error "--topic: invalid bundle identifier" ;;
  esac
elif [ -n "$relay_host$apns_key$team_id$key_id" ]; then
  usage_error "--relay-host, --apns-key, --team-id and --key-id go with --relay"
fi

# --- preconditions ----------------------------------------------------------

arch="$(host_arch)"
sums="$root/dist/SHA256SUMS"
[ -f "$sums" ] || fail "no release in $root/dist (SHA256SUMS missing); see deploy/README.md"
bins="node"
[ "$relay" -eq 0 ] || bins="node push"
for b in $bins; do
  name="barking-$b-$version-$arch-unknown-linux-musl"
  grep -q "  $name\$" "$sums" && [ -f "$root/dist/$name" ] \
    || fail "$name is missing from $root/dist (or from its SHA256SUMS)"
done

do_node=1 do_relay="$relay"
if [ -e "$node_toml" ] && [ "$force" -eq 0 ]; then do_node=0; fi
if [ "$relay" -eq 1 ] && [ -e "$push_toml" ] && [ "$force" -eq 0 ]; then do_relay=0; fi
if [ "$do_node" -eq 0 ] && [ "$do_relay" -eq 0 ]; then
  existing="$node_toml"
  [ "$relay" -eq 0 ] || existing="$existing, $push_toml"
  fail "already initialized ($existing); pass --force to regenerate keys"
fi

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker info >/dev/null 2>&1 || fail "the Docker daemon does not answer (is Docker Desktop running?)"

# BARKING_VERSION in the environment: compose interpolates the whole file, and
# deploy/.env may not exist yet (first run with --force).
dc() { BARKING_VERSION="$version" docker compose -f "$compose_file" "$@"; }

if [ "$force" -eq 1 ]; then
  if [ "$do_relay" -eq 1 ]; then
    echo "--force: stopping the node and the relay, deleting their volumes to regenerate"
    dc --profile relay down
  else
    # Only the node: a running relay keeps its keys and keeps running.
    echo "--force: stopping the node and deleting its volume to regenerate"
    dc rm --stop --force node
  fi
  [ "$do_node" -eq 0 ] || docker volume rm -f "$node_volume"
  [ "$do_relay" -eq 0 ] || docker volume rm -f "$relay_volume"
fi

# A failed run must not leave a configuration behind (it marks the component
# as initialized) nor a half-filled volume (keygen refuses existing keys).
# Only what this run created is removed: never a volume that held keys before.
new_node_volume=0 new_relay_volume=0
if [ "$do_node" -eq 1 ] && ! docker volume inspect "$node_volume" >/dev/null 2>&1; then new_node_volume=1; fi
if [ "$do_relay" -eq 1 ] && ! docker volume inspect "$relay_volume" >/dev/null 2>&1; then new_relay_volume=1; fi
on_exit() {
  local status=$?
  [ "$status" -ne 0 ] || return 0
  echo "error: set-up failed; removing what this run created so that it can be run again" >&2
  [ "$do_node" -eq 0 ] || rm -f "$node_toml"
  [ "$do_relay" -eq 0 ] || rm -f "$push_toml"
  [ "$new_node_volume" -eq 0 ] || docker volume rm -f "$node_volume" >/dev/null 2>&1 || true
  [ "$new_relay_volume" -eq 0 ] || docker volume rm -f "$relay_volume" >/dev/null 2>&1 || true
  return "$status"
}
trap on_exit EXIT

mkdir -p "$config_dir"
# IPv6: the compose network gets IPv6 (BARKING_IPV6) and the services listen on
# [::], which also accepts IPv4 on Linux. Without it, Docker disables IPv6 in
# the containers and [::] cannot be bound: listen on 0.0.0.0.
ipv6=false listen_host="0.0.0.0"
case "$public_v6$relay_host" in *\[*) ipv6=true listen_host="[::]" ;; esac
public_list=""
for a in "$public_v4" "$public_v6"; do
  [ -z "$a" ] || public_list="$public_list${public_list:+, }\"$a\""
done
printf 'BARKING_VERSION=%s\nBARKING_IPV6=%s\n' "$version" "$ipv6" > "$root/deploy/.env"

# --- node -----------------------------------------------------------------

if [ "$do_node" -eq 1 ]; then
  cat > "$node_toml" <<EOF
# Generated by scripts/stack-init.sh; see docs/deploy/barking-node.toml for every key.
listen = ["$listen_host:$node_port"]
data_dir = "/var/lib/barking-node"

[dht]
# Addresses published in the node's signed record (at most one per family):
# reachable from the internet on UDP $node_port.
public_addr = [$public_list]
EOF
  dc build node
  init_out="$(dc run --rm node init --config /etc/barking-node.toml)"
  node_id="$(printf '%s\n' "$init_out" | sed -n 's/^identifier *: //p')"
  [ -n "$node_id" ] || fail "barking-node init printed no identifier"
  echo
  echo "Node initialized."
  echo "  identifier : $node_id"
  echo "  addresses  : $public_v4${public_v4:+ }$public_v6"
else
  echo "Node already initialized ($node_toml), kept."
fi

# --- relay ----------------------------------------------------------------

if [ "$do_relay" -eq 1 ]; then
  cat > "$push_toml" <<EOF
# Generated by scripts/stack-init.sh; see docs/deploy/barking-push.toml.example
# for every key.
listen = ["$listen_host:$relay_port"]
node_key_file = "/var/lib/barking-push/node.key"
seal_keys = [
  { id = $seal_id, file = "/var/lib/barking-push/seal$seal_id.key" },
]

[apns]
team_id = "$team_id"
key_id = "$key_id"
topic = "$topic"
key_file = "/var/lib/barking-push/apns.p8"
EOF
  dc --profile relay build relay
  relay_id="$(dc --profile relay run --rm --entrypoint /barking-push relay \
    keygen-node --out /var/lib/barking-push/node.key | sed -n 's/^node id *: //p')"
  [ -n "$relay_id" ] || fail "barking-push keygen-node printed no node id"
  seal_public="$(dc --profile relay run --rm --entrypoint /barking-push relay \
    keygen-seal --out "/var/lib/barking-push/seal$seal_id.key" --id "$seal_id" \
    | sed -n 's/^public key *: //p')"
  [ -n "$seal_public" ] || fail "barking-push keygen-seal printed no public key"
  # The relay refuses a key readable by others: install it owned by the
  # container user, mode 0600, from a throwaway container.
  docker run --rm --network none --user 0:0 \
    -v "$relay_volume:/s" --mount "type=bind,src=$apns_key,dst=/in/apns.p8,readonly" "$alpine" \
    install -m 0600 -o 65532 -g 65532 /in/apns.p8 /s/apns.p8
  echo
  echo "Relay initialized. Put these lines in apple/Local.xcconfig, then build the app:"
  echo
  echo "BARKING_RELAY_HOST = $relay_host"
  echo "BARKING_RELAY_PORT = $relay_port"
  echo "BARKING_RELAY_ID = $relay_id"
  echo "BARKING_RELAY_SEAL_ID = $seal_id"
  echo "BARKING_RELAY_SEAL_PUBLIC = $seal_public"
elif [ "$relay" -eq 1 ]; then
  echo "Relay already initialized ($push_toml), kept."
fi

# --- next steps -----------------------------------------------------------

echo
echo "Next:"
if [ "$relay" -eq 1 ] || [ -e "$push_toml" ]; then
  echo "  docker compose -f deploy/compose.yaml --profile relay up -d"
  echo "  Forward UDP $node_port (node) and UDP $relay_port (relay) from your router to this machine."
else
  echo "  docker compose -f deploy/compose.yaml up -d"
  echo "  Forward UDP $node_port from your router to this machine."
fi
echo "  If your public IP changes, edit public_addr in deploy/config/barking-node.toml and run"
echo "  docker compose -f deploy/compose.yaml up -d --force-recreate node (keys are kept)."
