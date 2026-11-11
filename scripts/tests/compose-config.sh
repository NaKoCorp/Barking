#!/usr/bin/env bash
# Test: deploy/compose.yaml resolves for both profiles (node alone; node and
# push relay), with the expected ports and hardening. Needs only
# `docker compose` (no daemon, no image).
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="$racine/deploy/compose.yaml"
command -v docker >/dev/null 2>&1 || { echo "error: docker is required for this test" >&2; exit 1; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-compose-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
printf 'BARKING_VERSION=0.0.1\n' > "$tmp/test.env"
: > "$tmp/empty.env"

echecs=0
ok() { echo "ok   $1"; }
ko() { echo "FAIL $1" >&2; echecs=$((echecs + 1)); }
expect() { # $1 = name, $2 = got, $3 = expected
  if [ "$2" = "$3" ]; then ok "$1"; else ko "$1 (got $2, expected $3)"; fi
}

dc() { docker compose --env-file "$tmp/test.env" -f "$compose_file" "$@"; }

# Reads a field of the JSON on stdin by a dotted path (list indexes as numbers)
# and prints it as compact JSON.
field() {
  python3 -c '
import json, sys
v = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else v[k]
print(json.dumps(v, separators=(",", ":")))' "$1"
}

expect "default profile: node only" "$(dc config --services)" "node"
expect "relay profile: node and relay" "$(dc --profile relay config --services | sort | tr '\n' ' ')" "node relay "

dc --profile relay config --format json > "$tmp/config.json"
check() { # $1 = dotted path, $2 = expected compact JSON
  expect "$1" "$(field "$1" < "$tmp/config.json")" "$2"
}
for s in node relay; do
  check "services.$s.read_only" "true"
  check "services.$s.cap_drop" '["ALL"]'
  check "services.$s.restart" '"unless-stopped"'
  check "services.$s.tmpfs" '["/tmp"]'
  check "services.$s.logging.options.max-size" '"10m"'
  check "services.$s.logging.options.max-file" '"3"'
done
check services.node.ports.0.target 4433
check services.node.ports.0.protocol '"udp"'
check services.relay.ports.0.target 4434
check services.relay.ports.0.protocol '"udp"'
check networks.default.enable_ipv6 false
printf 'BARKING_VERSION=0.0.1\nBARKING_IPV6=true\n' > "$tmp/v6.env"
expect "networks.default.enable_ipv6 with BARKING_IPV6=true" \
  "$(docker compose --env-file "$tmp/v6.env" -f "$compose_file" config --format json | field networks.default.enable_ipv6)" true
expect "volumes" "$(dc --profile relay config --volumes | sort | tr '\n' ' ')" "node-data relay-secrets "

if (unset BARKING_VERSION; docker compose --env-file "$tmp/empty.env" -f "$compose_file" config >/dev/null 2>&1); then
  ko "missing BARKING_VERSION is refused"
else
  ok "missing BARKING_VERSION is refused"
fi

[ "$echecs" -eq 0 ] || { echo "$echecs failure(s)" >&2; exit 1; }
echo "all compose checks passed"
