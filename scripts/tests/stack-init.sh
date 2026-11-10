#!/usr/bin/env bash
# Test: scripts/stack-init.sh (deployment set-up of a node and the push relay).
# Runs on a throwaway copy of the repository, with a fake `docker` first in
# PATH that logs each call and prints what the real binaries print. No daemon
# and no network needed.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-stack-init-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
tmp="$(cd "$tmp" && pwd)"

node_id="0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
relay_id="aa00bb11cc22dd33ee44ff5566778899aa00bb11cc22dd33ee44ff5566778899"
seal_pub="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Fake docker: one line per call in $FAKE_DOCKER_LOG (arguments separated by
# a tab, so a path with spaces stays one field).
mkdir -p "$tmp/bin"
# Knobs: FAKE_FAIL=<word> fails any call that has this word; FAKE_VOLUMES lists
# volumes that already exist; FAKE_STRICT_ENV=1 fails compose calls made
# without BARKING_VERSION in the environment (compose would refuse to
# interpolate the file when deploy/.env is missing).
cat > "$tmp/bin/docker" <<EOF
#!/usr/bin/env bash
( IFS=\$'\t'; printf '%s\n' "\$*" ) >> "\$FAKE_DOCKER_LOG"
if [ -n "\${FAKE_FAIL:-}" ]; then
  case " \$* " in *" \$FAKE_FAIL "*) echo "fake docker: failing \$FAKE_FAIL" >&2; exit 1 ;; esac
fi
if [ "\${FAKE_STRICT_ENV:-}" = 1 ] && [ "\$1" = compose ] && [ -z "\${BARKING_VERSION:-}" ]; then
  echo "required variable BARKING_VERSION is missing a value" >&2; exit 1
fi
case " \$* " in
  " volume inspect "*) case " \${FAKE_VOLUMES:-} " in *" \$3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  *" init "*) printf 'identifier  : $node_id\naddress     : 0.0.0.0:4433\n' ;;
  *" keygen-node "*) printf 'node id : $relay_id\n' ;;
  *" keygen-seal "*) printf 'id         : 1\npublic key : $seal_pub\n' ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/docker"

case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) echo "error: unsupported host architecture" >&2; exit 1 ;;
esac

n=0
fresh() { # new repository copy in $repo, empty docker log
  n=$((n + 1))
  repo="$tmp/repo$n"
  mkdir -p "$repo/dist" "$repo/docs"
  cp -R "$racine/scripts" "$racine/deploy" "$repo/"
  cp -R "$racine/docs/deploy" "$repo/docs/"
  rm -rf "$repo/deploy/config" "$repo/deploy/.env"
  local ar bin f
  for ar in aarch64 x86_64; do
    for bin in node push; do : > "$repo/dist/barking-$bin-0.1.0-$ar-unknown-linux-musl"; done
  done
  (cd "$repo/dist" && for f in barking-*; do
     printf '%s  %s\n' "$(cksum < "$f" | cut -d' ' -f1)" "$f"; done) > "$repo/dist/SHA256SUMS"
  export FAKE_DOCKER_LOG="$repo/docker.log"
  : > "$FAKE_DOCKER_LOG"
  mkdir -p "$repo/Key Dir"
  printf -- '-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n' > "$repo/Key Dir/AuthKey.p8"
}
run() { # runs stack-init in $repo; sets $code and $out
  set +e
  out="$(PATH="$tmp/bin:$PATH" bash "$repo/scripts/stack-init.sh" "$@" 2>&1)"
  code=$?
  set -e
}
relay_args() { # sets the array ra (bash 3.2 has no mapfile)
  ra=(--relay --relay-host relay.example.org --apns-key "$repo/Key Dir/AuthKey.p8"
    --team-id ABCDE12345 --key-id FGHIJ67890)
}

echecs=0
ok() { echo "ok   $1"; }
ko() { echo "FAIL $1" >&2; [ -z "${out:-}" ] || printf '%s\n' "$out" | sed 's/^/     | /' >&2; echecs=$((echecs + 1)); }
has() { grep -qF -- "$2" "$1"; }

# --- node_only_writes_env_and_toml
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433
t=node_only_writes_env_and_toml
cfg="$repo/deploy/config/barking-node.toml"
if [ "$code" -eq 0 ] && [ "$(cat "$repo/deploy/.env")" = "BARKING_VERSION=0.1.0" ] \
  && has "$cfg" 'listen = ["0.0.0.0:4433"]' && has "$cfg" 'data_dir = "/var/lib/barking-node"' \
  && has "$cfg" '[dht]' && has "$cfg" 'public_addr = ["80.67.169.12:4433"]' \
  && grep -q $'build\tnode' "$FAKE_DOCKER_LOG" \
  && grep -q $'run\t--rm\tnode\tinit\t--config\t/etc/barking-node.toml' "$FAKE_DOCKER_LOG" \
  && ! grep -q relay "$FAKE_DOCKER_LOG" && [ ! -e "$repo/deploy/config/barking-push.toml" ] \
  && printf '%s' "$out" | grep -qF "$node_id"; then ok "$t"; else ko "$t"; fi

# --- relay_prints_xcconfig_block
fresh
relay_args
run --version 0.1.0 --public-addr 80.67.169.12:4433 "${ra[@]}"
t=relay_prints_xcconfig_block
pcfg="$repo/deploy/config/barking-push.toml"
block="BARKING_RELAY_HOST = relay.example.org
BARKING_RELAY_PORT = 4434
BARKING_RELAY_ID = $relay_id
BARKING_RELAY_SEAL_ID = 1
BARKING_RELAY_SEAL_PUBLIC = $seal_pub"
if [ "$code" -eq 0 ] && printf '%s' "$out" | grep -qF "$block" \
  && has "$pcfg" 'listen = ["0.0.0.0:4434"]' \
  && has "$pcfg" 'node_key_file = "/var/lib/barking-push/node.key"' \
  && has "$pcfg" '{ id = 1, file = "/var/lib/barking-push/seal1.key" }' \
  && has "$pcfg" 'team_id = "ABCDE12345"' && has "$pcfg" 'key_id = "FGHIJ67890"' \
  && has "$pcfg" 'topic = "com.nakocorp.barking"' \
  && has "$pcfg" 'key_file = "/var/lib/barking-push/apns.p8"' \
  && grep -q $'keygen-node\t--out\t/var/lib/barking-push/node.key' "$FAKE_DOCKER_LOG" \
  && grep -q $'keygen-seal\t--out\t/var/lib/barking-push/seal1.key\t--id\t1' "$FAKE_DOCKER_LOG" \
  && grep -qF "$repo/Key Dir/AuthKey.p8:/in/apns.p8:ro" "$FAKE_DOCKER_LOG" \
  && grep -q 'barking_relay-secrets:/s' "$FAKE_DOCKER_LOG"; then ok "$t"; else ko "$t"; fi

# --- rejects_private_public_addr
t=rejects_private_public_addr
for a in 192.168.1.10:4433 10.0.0.1:4433 172.16.0.1:4433 127.0.0.1:4433 '[::1]:4433' \
  100.64.0.1:4433 169.254.1.1:4433 '[fd00::1]:4433' '[fe80::1]:4433' 80.67.169.12 localhost:4433 \
  203.0.113.7:4433 198.51.100.9:4433 192.0.2.1:4433 '[2001:db8::1]:4433' '[fec0::1]:4433' \
  240.0.0.1:4433 80.67.169.12:0 relay.example.org:4433; do
  fresh
  run --version 0.1.0 --public-addr "$a"
  if [ "$code" -eq 2 ] && [ ! -s "$FAKE_DOCKER_LOG" ]; then ok "$t $a"; else ko "$t $a (code $code)"; fi
done

# --- second_run_without_force_keeps_keys
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433
cp "$repo/deploy/config/barking-node.toml" "$tmp/before.toml" 2>/dev/null || : > "$tmp/before.toml"
: > "$FAKE_DOCKER_LOG"
run --version 0.1.0 --public-addr 80.67.169.40:4433
t=second_run_without_force_keeps_keys
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -q "already initialized" \
  && ! grep -qE $'\tinit\t|keygen' "$FAKE_DOCKER_LOG" \
  && cmp -s "$tmp/before.toml" "$repo/deploy/config/barking-node.toml"; then ok "$t"; else ko "$t"; fi
run --version 0.1.0 --public-addr 80.67.169.40:4433 --force
t=second_run_with_force_regenerates
if [ "$code" -eq 0 ] && grep -q $'volume\trm' "$FAKE_DOCKER_LOG" \
  && has "$repo/deploy/config/barking-node.toml" 'public_addr = ["80.67.169.40:4433"]'; then ok "$t"; else ko "$t"; fi

# --- missing_binary_for_arch
fresh
grep -v "barking-node-0.1.0-$arch-" "$repo/dist/SHA256SUMS" > "$tmp/sums" && cp "$tmp/sums" "$repo/dist/SHA256SUMS"
run --version 0.1.0 --public-addr 80.67.169.12:4433
t=missing_binary_for_arch
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF "barking-node-0.1.0-$arch-unknown-linux-musl" \
  && ! grep -q build "$FAKE_DOCKER_LOG"; then ok "$t"; else ko "$t"; fi
fresh
run --version 9.9.9 --public-addr 80.67.169.12:4433
t=missing_version
if [ "$code" -eq 1 ] && [ ! -s "$FAKE_DOCKER_LOG" ]; then ok "$t"; else ko "$t"; fi

# --- apns_key_missing_or_spaced
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433 --relay --relay-host relay.example.org \
  --apns-key "$repo/nope.p8" --team-id ABCDE12345 --key-id FGHIJ67890
t=apns_key_missing
if [ "$code" -eq 2 ] && [ ! -s "$FAKE_DOCKER_LOG" ]; then ok "$t"; else ko "$t"; fi
# The spaced path is exercised by relay_prints_xcconfig_block ("Key Dir").

# --- relay_requires_apns_options
t=relay_requires_apns_options
for missing in --relay-host --apns-key --team-id --key-id; do
  fresh
  relay_args
  args=()
  i=0
  while [ "$i" -lt "${#ra[@]}" ]; do
    if [ "${ra[$i]}" = "$missing" ]; then i=$((i + 2)); continue; fi
    args+=("${ra[$i]}"); i=$((i + 1))
  done
  run --version 0.1.0 --public-addr 80.67.169.12:4433 "${args[@]}"
  if [ "$code" -eq 2 ] && printf '%s' "$out" | grep -qF -- "$missing" && [ ! -s "$FAKE_DOCKER_LOG" ]
  then ok "$t $missing"; else ko "$t $missing (code $code)"; fi
done
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433 --relay --relay-host relay.example.org \
  --apns-key "$repo/Key Dir/AuthKey.p8" --team-id ABC --key-id FGHIJ67890
if [ "$code" -eq 2 ] && printf '%s' "$out" | grep -qF -- --team-id; then ok "$t short team id"; else ko "$t short team id"; fi

# --- relay_added_later_keeps_node
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433
cp "$repo/deploy/config/barking-node.toml" "$tmp/before.toml"
: > "$FAKE_DOCKER_LOG"
relay_args
run --version 0.1.0 --public-addr 80.67.169.12:4433 "${ra[@]}"
t=relay_added_later_keeps_node
if [ "$code" -eq 0 ] && ! grep -q $'\tinit\t' "$FAKE_DOCKER_LOG" && grep -q keygen-node "$FAKE_DOCKER_LOG" \
  && cmp -s "$tmp/before.toml" "$repo/deploy/config/barking-node.toml" \
  && [ -e "$repo/deploy/config/barking-push.toml" ]; then ok "$t"; else ko "$t"; fi

# --- force_first_run_without_env
fresh
FAKE_STRICT_ENV=1 run --version 0.1.0 --public-addr 80.67.169.12:4433 --force
t=force_first_run_without_env
if [ "$code" -eq 0 ]; then ok "$t"; else ko "$t (code $code)"; fi

# --- force_sequence: down, then only the node volume (no --relay)
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433
: > "$FAKE_DOCKER_LOG"
run --version 0.1.0 --public-addr 80.67.169.12:4433 --force
t=force_sequence
down_line="$(grep -n $'\tdown' "$FAKE_DOCKER_LOG" | head -n1 | cut -d: -f1)"
rm_line="$(grep -n $'volume\trm\t-f\tbarking_node-data' "$FAKE_DOCKER_LOG" | head -n1 | cut -d: -f1)"
if [ "$code" -eq 0 ] && [ -n "$down_line" ] && [ -n "$rm_line" ] && [ "$down_line" -lt "$rm_line" ] \
  && ! grep -q 'barking_relay-secrets' "$FAKE_DOCKER_LOG"; then ok "$t"; else ko "$t"; fi

# --- failed_relay_init_is_cleaned: a failed run leaves nothing that blocks a retry
fresh
run --version 0.1.0 --public-addr 80.67.169.12:4433
cp "$repo/deploy/config/barking-node.toml" "$tmp/before.toml"
: > "$FAKE_DOCKER_LOG"
relay_args
FAKE_FAIL=keygen-seal run --version 0.1.0 --public-addr 80.67.169.12:4433 "${ra[@]}"
t=failed_relay_init_is_cleaned
if [ "$code" -eq 1 ] && [ ! -e "$repo/deploy/config/barking-push.toml" ] \
  && grep -q $'volume\trm\t-f\tbarking_relay-secrets' "$FAKE_DOCKER_LOG" \
  && ! grep -q 'barking_node-data' "$FAKE_DOCKER_LOG" \
  && cmp -s "$tmp/before.toml" "$repo/deploy/config/barking-node.toml"; then ok "$t"; else ko "$t (code $code)"; fi
: > "$FAKE_DOCKER_LOG"
run --version 0.1.0 --public-addr 80.67.169.12:4433 "${ra[@]}"
t=retry_after_failed_relay_init
if [ "$code" -eq 0 ] && ! grep -q $'\tinit\t' "$FAKE_DOCKER_LOG" && grep -q keygen-seal "$FAKE_DOCKER_LOG"
then ok "$t"; else ko "$t (code $code)"; fi

# --- a failed run deletes only a volume it created
fresh
FAKE_VOLUMES=barking_node-data FAKE_FAIL=init run --version 0.1.0 --public-addr 80.67.169.12:4433
t=failed_init_keeps_preexisting_volume
if [ "$code" -eq 1 ] && [ ! -e "$repo/deploy/config/barking-node.toml" ] \
  && ! grep -q $'volume\trm' "$FAKE_DOCKER_LOG"; then ok "$t"; else ko "$t (code $code)"; fi
fresh
FAKE_FAIL=init run --version 0.1.0 --public-addr 80.67.169.12:4433
t=failed_init_removes_new_volume
if [ "$code" -eq 1 ] && [ ! -e "$repo/deploy/config/barking-node.toml" ] \
  && grep -q $'volume\trm\t-f\tbarking_node-data' "$FAKE_DOCKER_LOG"; then ok "$t"; else ko "$t (code $code)"; fi

# --- apns_values_are_strict (no newline or quote may reach the TOML)
t=apns_values_are_strict
nl=$'\n'
for bad in "--team-id|abcde12345" "--team-id|ABCDE12345${nl}key_file = \"x" "--key-id|FGHIJ6789!" \
  "--topic|com.x\"y" "--topic|com.x${nl}evil"; do
  fresh
  relay_args
  opt="${bad%%|*}"
  val="${bad#*|}"
  run --version 0.1.0 --public-addr 80.67.169.12:4433 "${ra[@]}" "$opt" "$val"
  if [ "$code" -eq 2 ] && [ ! -s "$FAKE_DOCKER_LOG" ]; then ok "$t $opt"; else ko "$t $opt (code $code)"; fi
done

# --- accepts_public_ipv6
t=accepts_public_ipv6
for a in '[2a01:e0a::1]:4433' '[2A01:E0A::1]:4433'; do
  fresh
  run --version 0.1.0 --public-addr "$a"
  if [ "$code" -eq 0 ]; then ok "$t $a"; else ko "$t $a (code $code)"; fi
done

# --- usage
fresh
run --public-addr 80.67.169.12:4433
if [ "$code" -eq 2 ]; then ok "missing --version"; else ko "missing --version"; fi
run --version 0.1.0 --public-addr 80.67.169.12:4433 --bogus
if [ "$code" -eq 2 ]; then ok "unknown option"; else ko "unknown option"; fi

[ "$echecs" -eq 0 ] || { echo "$echecs failure(s)" >&2; exit 1; }
echo "all stack-init checks passed"
