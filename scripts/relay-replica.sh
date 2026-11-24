#!/usr/bin/env bash
# Creates a replica of the push relay on a new server: same relay identity and
# seal keys as an existing one, its own node and its own APNs key (NaKoCorp).
#
# Usage:
#   scripts/relay-replica.sh --from SSH_SOURCE --to SSH_TARGET --public-addr IP:PORT
#       [--public-addr [IPV6]:PORT] --apns-key PATH --team-id ID --key-id ID --version V [--topic T]
#
# Runs on the operator's machine, from a repository clone with the verified
# release in dist/. Both servers hold the deployment in ~/barking and are
# reached with `ssh` (batch mode: keys or an agent, no password prompt) as a
# user of the `docker` group. The target must have neither relay nor node
# volume. The script copies the deployment there, writes its configuration
# (this replica's APNs key id), builds the images, creates a new node identity,
# streams the relay keys (node.key, seal*.key) from the source's volume to the
# target's (they never touch this machine's disk), checks that the copied
# keys hash the same on both servers (only SHA-256 sums cross the wire),
# installs the APNs key, starts the node and the relay, waits for the target
# relay to log its identity, and prints it with the DNS records to add. The
# source is only read (its key volume); nothing on it is restarted.
# If a step fails after the checks, the target's containers and volumes are
# removed so that the script can be run again; if that clean-up fails, the
# commands to run by hand are printed. RELAY_REPLICA_WAIT (default 30) is the
# number of 2-second tries waiting for the target relay to start.
# Exit codes: 0 success, 2 invalid usage, 1 any other error.
# Runs on the macOS bash (3.2).
set -euo pipefail

root="${BARKING_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
# Same pinned base as docker/node.Dockerfile and scripts/stack-init.sh.
alpine="alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
# Named volumes of deploy/compose.yaml (project name `barking`).
node_volume="barking_node-data"
relay_volume="barking_relay-secrets"
# Container of the relay service (project `barking`, see deploy/compose.yaml).
relay_container="barking-relay-1"
node_port=4433
relay_port=4434
dns_name="push.barking.nakocorp.com"

usage() {
  sed -n '5,7p' "$0" | sed 's/^# \{0,1\}//' >&2
}
usage_error() { echo "error: $*" >&2; usage; exit 2; }
fail() { echo "error: $*" >&2; exit 1; }
step() { echo "==> $*" >&2; }

# Address checks (ip_is_public, addr_family, lower) and apple_id.
# shellcheck source=scripts/deploy-lib.sh
. "$(dirname "$0")/deploy-lib.sh"

# An ssh destination as given to ssh (user@host or a ~/.ssh/config alias):
# no option, no space, nothing a shell would interpret.
ssh_dest() {
  case "$1" in
    '' | -* | *[!A-Za-z0-9._@:-]*) return 1 ;;
    *) return 0 ;;
  esac
}

# Run a command on the source or the target. Batch mode: fail instead of
# prompting for a password. Calls that do not stream redirect stdin.
on_src() { ssh -o BatchMode=yes -- "$from" "$@"; }
on_dst() { ssh -o BatchMode=yes -- "$to" "$@"; }

# The relay's log (it logs to stderr), read from its container: the name is
# fixed by `name: barking` in deploy/compose.yaml, whatever the path of the
# deployment. Fails if the container cannot be read.
relay_log() { # host-function
  "$1" "docker logs $relay_container 2>&1" </dev/null
}

# Prints the last relay identity announced in the relay log read on stdin
# (`relay <id> started`, the id in base32). Only displayed: the identity is
# checked on the key hashes, the log may have rotated.
last_relay_id() {
  sed -n 's/.*relay \([A-Z2-7][A-Z2-7]*\) started.*/\1/p' | tail -n 1
}

# --- arguments ------------------------------------------------------------

from="" to="" version="" public_v4="" public_v6="" apns_key="" team_id="" key_id=""
topic="com.nakocorp.barking"
need_value() { [ "$2" -ge 2 ] || usage_error "$1 expects a value"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --from) need_value "$1" "$#"; from="$2"; shift 2 ;;
    --to) need_value "$1" "$#"; to="$2"; shift 2 ;;
    --version) need_value "$1" "$#"; version="$2"; shift 2 ;;
    --public-addr)
      need_value "$1" "$#"
      family="$(addr_family "$2")" || usage_error \
        "--public-addr must be a public IPV4:PORT or [IPV6]:PORT of the new server, reachable from the internet (got $2)"
      if [ "$family" = 4 ]; then
        [ -z "$public_v4" ] || usage_error "--public-addr: at most one IPv4 address"
        public_v4="$2"
      else
        [ -z "$public_v6" ] || usage_error "--public-addr: at most one IPv6 address"
        public_v6="$(lower "$2")"
      fi
      shift 2
      ;;
    --apns-key) need_value "$1" "$#"; apns_key="$2"; shift 2 ;;
    --team-id) need_value "$1" "$#"; team_id="$2"; shift 2 ;;
    --key-id) need_value "$1" "$#"; key_id="$2"; shift 2 ;;
    --topic) need_value "$1" "$#"; topic="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown option $1" ;;
  esac
done

[ -n "$from" ] || usage_error "--from is required"
[ -n "$to" ] || usage_error "--to is required"
ssh_dest "$from" || usage_error "--from: invalid ssh destination $from"
ssh_dest "$to" || usage_error "--to: invalid ssh destination $to"
[ "$from" != "$to" ] || usage_error "--from and --to must be different servers"
[ -n "$public_v4$public_v6" ] || usage_error "--public-addr is required"
[ -n "$apns_key" ] || usage_error "--apns-key is required"
[ -f "$apns_key" ] && [ -r "$apns_key" ] || usage_error "--apns-key: no such readable file: $apns_key"
[ -n "$team_id" ] || usage_error "--team-id is required"
[ -n "$key_id" ] || usage_error "--key-id is required"
# `case`, not grep: these values are written into the TOML as they are.
apple_id "$team_id" || usage_error "--team-id must be the 10-character Apple team identifier"
apple_id "$key_id" || usage_error "--key-id must be the 10-character APNs key identifier of this replica"
case "$topic" in
  '' | *[!A-Za-z0-9.-]*) usage_error "--topic: invalid bundle identifier" ;;
esac
[ -n "$version" ] || usage_error "--version is required"
case "$version" in *[!0-9A-Za-z.-]*) usage_error "--version: invalid version $version" ;; esac

# --- checks (read only: nothing is changed on either server) --------------

sums="$root/dist/SHA256SUMS"
[ -f "$sums" ] || fail "no release in $root/dist (SHA256SUMS missing); see deploy/README.md"

step "checking the target ($to)"
target_arch="$(on_dst 'uname -m' </dev/null)" || fail "cannot run commands on $to over ssh"
case "$target_arch" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) fail "$to: unsupported architecture $target_arch" ;;
esac
bins=""
for b in node push; do
  name="barking-$b-$version-$arch-unknown-linux-musl"
  grep -q "  $name\$" "$sums" && [ -f "$root/dist/$name" ] \
    || fail "$name is missing from $root/dist (or from its SHA256SUMS)"
  bins="$bins dist/$name"
done

# Prints yes or no; anything else (ssh or docker down) is an error.
has_volume() { # host-function volume
  local answer
  answer="$("$1" "docker volume inspect $2 >/dev/null 2>&1 && echo yes || echo no" </dev/null)" || answer=""
  case "$answer" in
    yes) return 0 ;;
    no) return 1 ;;
    *) fail "cannot query Docker over ssh ($1)" ;;
  esac
}

on_dst 'docker info >/dev/null 2>&1' </dev/null \
  || fail "$to: Docker does not answer (installed, running, user in the docker group?)"
for v in "$relay_volume" "$node_volume"; do
  ! has_volume on_dst "$v" \
    || fail "$to already has the volume $v: a replica goes on a server without relay nor node"
done

step "checking the source ($from)"
on_src 'docker info >/dev/null 2>&1' </dev/null \
  || fail "$from: Docker does not answer (installed, running, user in the docker group?)"
# Inspect first: `docker run -v` would create a missing volume.
has_volume on_src "$relay_volume" || fail "$from has no relay (no volume $relay_volume)"
listing="$(on_src "docker run --rm --network none -v $relay_volume:/v:ro $alpine ls /v" </dev/null)" \
  || fail "$from: cannot list the volume $relay_volume"
# Only names matching node.key and seal<1-255>.key are kept: they go into the
# TOML and into remote commands. One name per line, read (never globbed).
has_node_key=0 seal_ids=""
while IFS= read -r f; do
  case "$f" in
    node.key) has_node_key=1 ;;
    seal[1-9]*.key)
      id="${f#seal}"
      id="${id%.key}"
      case "$id" in *[!0123456789]*) continue ;; esac
      [ "${#id}" -le 3 ] && [ "$id" -le 255 ] || continue
      seal_ids="$seal_ids$id
"
      ;;
  esac
done <<EOF
$listing
EOF
[ "$has_node_key" -eq 1 ] || fail "$from: no node.key in the volume $relay_volume"
[ -n "$seal_ids" ] || fail "$from: no seal*.key in the volume $relay_volume"
seal_ids="$(printf '%s' "$seal_ids" | sort -n | tr '\n' ' ')"
key_files="node.key" key_paths="/v/node.key" seal_lines="" key_count=1
for id in $seal_ids; do
  key_count=$((key_count + 1))
  key_files="$key_files seal$id.key"
  key_paths="$key_paths /v/seal$id.key"
  seal_lines="$seal_lines  { id = $id, file = \"/var/lib/barking-push/seal$id.key\" },
"
done

# SHA-256 of the relay keys in a host's volume, one `<sum>  <file>` line per
# key in the order of key_files, computed in a container on that host: the
# keys never leave it. Fails unless every key was hashed.
key_hashes() { # host-function
  local out
  out="$("$1" "docker run --rm --network none -v $relay_volume:/v:ro $alpine sh -c 'cd /v && sha256sum $key_files'" </dev/null)" \
    || return 1
  [ "$(printf '%s\n' "$out" | grep -cE '^[0-9a-f]{64}  ')" -eq "$key_count" ] || return 1
  printf '%s\n' "$out"
}
source_hashes="$(key_hashes on_src)" || fail "$from: cannot hash the relay keys in the volume $relay_volume"
step "source seal keys:$seal_ids"

# --- from here on the target changes; a failure undoes it ------------------

on_exit() {
  local status=$? cleaned=1
  [ "$status" -ne 0 ] || return 0
  echo "error: replica set-up failed; removing the target's containers and volumes so that it can be run again" >&2
  # No deployment copied yet: no container either.
  on_dst '[ ! -d ~/barking/deploy ] || { cd ~/barking/deploy && docker compose --profile relay down; }' \
    </dev/null >/dev/null 2>&1 || cleaned=0
  on_dst "docker volume rm -f $relay_volume" </dev/null >/dev/null 2>&1 || cleaned=0
  on_dst "docker volume rm -f $node_volume" </dev/null >/dev/null 2>&1 || cleaned=0
  if [ "$cleaned" -eq 0 ]; then
    cat >&2 <<WARN

!!! WARNING: the clean-up of $to FAILED. It may still run this replica's
!!! containers or hold its volumes (a copy of the relay keys), and a new run
!!! will refuse it. Run these commands on $to by hand:
!!!
!!!   cd ~/barking/deploy && docker compose --profile relay down
!!!   docker volume rm $relay_volume $node_volume

WARN
  fi
  return "$status"
}
trap on_exit EXIT

step "copying the deployment and the release to $to:~/barking"
# shellcheck disable=SC2086 # bins: one word per file
COPYFILE_DISABLE=1 tar -C "$root" -cf - deploy/compose.yaml docker dist/SHA256SUMS $bins \
  | on_dst 'mkdir -p ~/barking && tar -C ~/barking -xf -'

# Through ssh stdin, from printf (a bash 3.2 here-document is a temp file):
# nothing is written on this machine.
put() { on_dst "mkdir -p ~/barking/deploy/config && cat > ~/barking/$1"; }

# IPv6: as scripts/stack-init.sh, the compose network gets IPv6 and the
# services listen on [::] (IPv4 too); without it, on 0.0.0.0.
ipv6=false listen_host="0.0.0.0"
[ -z "$public_v6" ] || { ipv6=true; listen_host="[::]"; }
public_list=""
for a in "$public_v4" "$public_v6"; do
  [ -z "$a" ] || public_list="$public_list${public_list:+, }\"$a\""
done
printf 'BARKING_VERSION=%s\nBARKING_IPV6=%s\n' "$version" "$ipv6" | put deploy/.env
printf '%s\n' "\
# Generated by scripts/relay-replica.sh; see docs/deploy/barking-node.toml for every key.
listen = [\"$listen_host:$node_port\"]
data_dir = \"/var/lib/barking-node\"

[dht]
# Addresses published in the node's signed record (at most one per family):
# reachable from the internet on UDP $node_port.
public_addr = [$public_list]" | put deploy/config/barking-node.toml
printf '%s\n' "\
# Generated by scripts/relay-replica.sh (replica of $from); see
# docs/deploy/barking-push.toml.example for every key.
listen = [\"$listen_host:$relay_port\"]
node_key_file = \"/var/lib/barking-push/node.key\"
seal_keys = [
$seal_lines]

[apns]
team_id = \"$team_id\"
# This replica's own APNs key.
key_id = \"$key_id\"
topic = \"$topic\"
key_file = \"/var/lib/barking-push/apns.p8\"" | put deploy/config/barking-push.toml

step "building the images on $to"
on_dst 'cd ~/barking/deploy && docker compose --profile relay build node relay' </dev/null >&2

step "creating the node identity on $to"
init_out="$(on_dst 'cd ~/barking/deploy && docker compose run --rm node init --config /etc/barking-node.toml' </dev/null)"
node_id="$(printf '%s\n' "$init_out" | sed -n 's/^identifier *: //p')"
[ -n "$node_id" ] || fail "barking-node init printed no identifier"

step "streaming the relay keys ($key_files) from $from to $to"
# Source container -> ssh -> this machine's memory -> ssh -> target container.
on_src "docker run --rm --network none -v $relay_volume:/v:ro $alpine tar -C /v -cf - $key_files" </dev/null \
  | on_dst "docker run --rm -i --network none --user 0:0 -v $relay_volume:/v $alpine sh -c 'tar -C /v --numeric-owner -xpf - && chown 65532:65532 /v $key_paths && chmod 700 /v && chmod 600 $key_paths'"

step "checking that the keys on $to are the source's (SHA-256)"
target_hashes="$(key_hashes on_dst)" || fail "$to: cannot hash the relay keys in the volume $relay_volume"
[ "$target_hashes" = "$source_hashes" ] \
  || fail "identity mismatch: the relay keys on $to do not hash like the source's"

step "installing this replica's APNs key on $to"
# Through a tmpfs: the key only lands in the volume, owned by the container user.
on_dst "docker run --rm -i --network none --user 0:0 --tmpfs /tmp -v $relay_volume:/s $alpine sh -c 'cat > /tmp/apns.p8 && install -m 0600 -o 65532 -g 65532 /tmp/apns.p8 /s/apns.p8'" \
  < "$apns_key"

step "starting the node and the relay on $to"
on_dst 'cd ~/barking/deploy && docker compose --profile relay up -d' </dev/null >&2

step "waiting for the relay to log its identity"
tries="${RELAY_REPLICA_WAIT:-30}"
case "$tries" in '' | *[!0-9]*) tries=30 ;; esac
target_id=""
i=0
while :; do
  target_id="$(relay_log on_dst | last_relay_id)" \
    || fail "$to: cannot read the log of the relay container $relay_container (not found, or Docker error)"
  [ -z "$target_id" ] || break
  i=$((i + 1))
  [ "$i" -lt "$tries" ] || fail "the relay on $to did not log 'relay <id> started'; see: docker logs $relay_container"
  sleep 2
done

trap - EXIT
step "replica ready (node $node_id). Add these DNS records (DNS only, TTL 60 s):"
echo "relay id : $target_id"
[ -z "$public_v4" ] || echo "A $dns_name ${public_v4%:*}"
if [ -n "$public_v6" ]; then
  h="${public_v6%:*}"
  h="${h#[}"
  echo "AAAA $dns_name ${h%]}"
fi
