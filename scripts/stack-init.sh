#!/usr/bin/env bash
# One-time set-up of the Docker Compose deployment (deploy/compose.yaml): a
# barking-node, and with --relay the barking-push relay too (NaKoCorp).
#
# Usage:
#   scripts/stack-init.sh --version V --public-addr HOST:PORT [--force]
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

# --- address checks -------------------------------------------------------

# True if the dotted IPv4 $1 is public (not private, loopback, link-local,
# shared, "this network", multicast or reserved).
ipv4_is_public() {
  local IFS=. a b c d
  # shellcheck disable=SC2086 # split on dots, on purpose
  set -- $1
  [ "$#" -eq 4 ] || return 1
  for x in "$@"; do
    case "$x" in '' | *[!0-9]*) return 1 ;; esac
    [ "$x" -le 255 ] || return 1
  done
  a=$1 b=$2 c=$3 d=$4
  : "$c" "$d"
  [ "$a" -eq 0 ] && return 1
  [ "$a" -eq 10 ] && return 1
  [ "$a" -eq 127 ] && return 1
  [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1
  [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 1
  [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
  [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 1
  [ "$a" -ge 224 ] && return 1
  return 0
}

# True if the IPv6 literal $1 (without brackets) is public: not unspecified,
# loopback, unique local (fc00::/7), link-local (fe80::/10) or multicast.
ipv6_is_public() {
  local h
  h="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$h" in *[!0-9a-f:.]* | '' | *:*:*:*:*:*:*:*:*:*) return 1 ;; esac
  case "$h" in *:*) ;; *) return 1 ;; esac
  case "$h" in
    :: | ::1 | ::ffff:*) return 1 ;;
    fc* | fd* | fe8* | fe9* | fea* | feb* | ff*) return 1 ;;
  esac
  return 0
}

# True if $1 is a public IP literal (IPv6 in brackets) or a DNS name that is
# not obviously local.
host_is_public() {
  local h="$1"
  case "$h" in
    \[*\]) ipv6_is_public "${h#[}" && return 0 || return 1 ;;
  esac
  h="${h%]}"
  case "$h" in
    *[!0-9.]*) ;;
    *) ipv4_is_public "$h"; return ;;
  esac
  case "$h" in
    '' | *[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
  esac
  h="$(printf '%s' "$h" | tr '[:upper:]' '[:lower:]')"
  case "$h" in
    localhost | *.localhost | *.local | *.internal | *.lan | *.home.arpa) return 1 ;;
  esac
  return 0
}

# True if $1 is HOST:PORT with a public host and a port from 1 to 65535.
addr_is_public() {
  local host port
  case "$1" in
    \[*\]:*) host="${1%:*}"; port="${1##*:}" ;;
    *:*:*) return 1 ;;
    *:*) host="${1%:*}"; port="${1##*:}" ;;
    *) return 1 ;;
  esac
  case "$port" in '' | *[!0-9]*) return 1 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
  host_is_public "$host"
}

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) echo aarch64 ;;
    x86_64 | amd64) echo x86_64 ;;
    *) fail "unsupported host architecture $(uname -m)" ;;
  esac
}

# --- arguments ------------------------------------------------------------

version="" public_addr="" force=0 relay=0
relay_host="" apns_key="" team_id="" key_id="" topic="com.nakocorp.barking"
need_value() { [ "$2" -ge 2 ] || usage_error "$1 expects a value"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) need_value "$1" "$#"; version="$2"; shift 2 ;;
    --public-addr) need_value "$1" "$#"; public_addr="$2"; shift 2 ;;
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
[ -n "$public_addr" ] || usage_error "--public-addr is required"
addr_is_public "$public_addr" \
  || usage_error "--public-addr must be a public HOST:PORT reachable from the internet (got $public_addr)"

if [ "$relay" -eq 1 ]; then
  [ -n "$relay_host" ] || usage_error "--relay needs --relay-host"
  host_is_public "$relay_host" \
    || usage_error "--relay-host must be a public name or address, without a port (got $relay_host)"
  [ -n "$apns_key" ] || usage_error "--relay needs --apns-key"
  [ -f "$apns_key" ] || usage_error "--apns-key: no such file: $apns_key"
  apns_key="$(cd "$(dirname "$apns_key")" && pwd)/$(basename "$apns_key")"
  [ -n "$team_id" ] || usage_error "--relay needs --team-id"
  [ -n "$key_id" ] || usage_error "--relay needs --key-id"
  printf '%s' "$team_id" | grep -Eq '^[A-Z0-9]{10}$' \
    || usage_error "--team-id must be the 10-character Apple team identifier (got $team_id)"
  printf '%s' "$key_id" | grep -Eq '^[A-Z0-9]{10}$' \
    || usage_error "--key-id must be the 10-character APNs key identifier (got $key_id)"
  printf '%s' "$topic" | grep -Eq '^[A-Za-z0-9.-]+$' || usage_error "--topic: invalid bundle identifier $topic"
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

dc() { docker compose -f "$compose_file" "$@"; }

if [ "$force" -eq 1 ]; then
  echo "--force: stopping the stack and deleting the volumes to regenerate"
  dc --profile relay down
  [ "$do_node" -eq 0 ] || docker volume rm -f "$node_volume"
  [ "$do_relay" -eq 0 ] || docker volume rm -f "$relay_volume"
fi

mkdir -p "$config_dir"
printf 'BARKING_VERSION=%s\n' "$version" > "$root/deploy/.env"

# --- node -----------------------------------------------------------------

if [ "$do_node" -eq 1 ]; then
  cat > "$node_toml" <<EOF
# Generated by scripts/stack-init.sh; see docs/deploy/barking-node.toml for every key.
listen = ["0.0.0.0:$node_port"]
data_dir = "/var/lib/barking-node"

[dht]
# Address published in the node's signed record: reachable from the internet
# (UDP $node_port forwarded to this machine).
public_addr = ["$public_addr"]
EOF
  dc build node
  init_out="$(dc run --rm node init --config /etc/barking-node.toml)"
  node_id="$(printf '%s\n' "$init_out" | sed -n 's/^identifier *: //p')"
  [ -n "$node_id" ] || fail "barking-node init printed no identifier"
  echo
  echo "Node initialized."
  echo "  identifier : $node_id"
  echo "  address    : $public_addr"
else
  echo "Node already initialized ($node_toml), kept."
fi

# --- relay ----------------------------------------------------------------

if [ "$do_relay" -eq 1 ]; then
  cat > "$push_toml" <<EOF
# Generated by scripts/stack-init.sh; see docs/deploy/barking-push.toml.example
# for every key.
listen = ["0.0.0.0:$relay_port"]
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
    -v "$relay_volume:/s" -v "$apns_key:/in/apns.p8:ro" "$alpine" \
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
if [ "$relay" -eq 1 ]; then
  echo "  docker compose -f deploy/compose.yaml --profile relay up -d"
  echo "  Forward UDP $node_port (node) and UDP $relay_port (relay) from your router to this machine."
else
  echo "  docker compose -f deploy/compose.yaml up -d"
  echo "  Forward UDP $node_port from your router to this machine."
fi
