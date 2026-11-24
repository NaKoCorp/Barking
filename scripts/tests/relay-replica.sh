#!/usr/bin/env bash
# Test: scripts/relay-replica.sh (a push relay replica cloned from another).
# Runs on a throwaway copy of the repository, with a fake `ssh`, `docker` and
# `uname` first in PATH. The fake ssh runs the remote command locally with a
# per-host HOME (hosts/<name>/home) and logs; the fake docker logs each call
# in its host's docker.log and acts on that host's state. No daemon, no
# network needed.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/barking-relay-replica-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
tmp="$(cd "$tmp" && pwd)"

relay_id="QPZ7XNCJ2LHFKUTWMRAV5YBE6GDO3SI4QPZ7XNCJ2LHFKUTWMRAV"
other_id="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"
node_id="ZZZZ2222YYYY3333XXXX4444WWWW5555VVVV6666UUUU7777TTTT"
# Stands for the relay keys in the source's tar stream.
secret="FAKE-RELAY-SECRET-7c1d9e"

mkdir -p "$tmp/bin"

# Fake ssh: `ssh [-o OPT]... [--] HOST COMMAND...`. Like the real one, joins
# the command words with spaces and gives them to a shell on the host.
cat > "$tmp/bin/ssh" <<'EOF'
#!/usr/bin/env bash
opts=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) opts="$opts $2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "fake ssh: unexpected option $1" >&2; exit 255 ;;
    *) break ;;
  esac
done
case "$opts" in *BatchMode=yes*) ;; *) echo "fake ssh: BatchMode=yes missing" >&2; exit 255 ;; esac
host="$1"; shift
dir="$FAKE_HOSTS/$host"
[ -d "$dir" ] || { echo "ssh: Could not resolve hostname $host" >&2; exit 255; }
printf '%s\n' "$*" >> "$dir/ssh.log"
cd "$dir/home"
HOME="$dir/home" FAKE_HOST_DIR="$dir" exec sh -c "$*"
EOF

# Fake uname: the host's architecture on a fake host.
cat > "$tmp/bin/uname" <<'EOF'
#!/usr/bin/env bash
if [ -n "${FAKE_HOST_DIR:-}" ]; then cat "$FAKE_HOST_DIR/arch"; else exec /usr/bin/uname "$@"; fi
EOF

# Fake docker, per host (FAKE_HOST_DIR): volumes lists the existing volumes,
# relay-files the files of barking_relay-secrets, relay.log the relay's log
# (no file: no relay container; written at `up` from relay-log-on-up, unless
# no-container exists), fail a word that fails any call that
# has it. Arguments are logged separated by a tab.
cat > "$tmp/bin/docker" <<EOF
#!/usr/bin/env bash
d="\${FAKE_HOST_DIR:?fake docker: not on a fake host}"
( IFS=\$'\t'; printf '%s\n' "\$*" ) >> "\$d/docker.log"
if [ -s "\$d/fail" ]; then
  case " \$* " in *" \$(cat "\$d/fail") "*) echo "fake docker: failing" >&2; exit 1 ;; esac
fi
case " \$* " in
  " info "*) exit 0 ;;
  " volume inspect "*) grep -qxF "\$3" "\$d/volumes"; exit ;;
  " volume rm "*) for v in "\$@"; do grep -vxF "\$v" "\$d/volumes" > "\$d/v.tmp" || true; mv "\$d/v.tmp" "\$d/volumes"; done ;;
  *" ls /v "*) cat "\$d/relay-files" ;;
  *" -cf - "*) printf '$secret %s\n' "\$*" ;;
  *" -xpf - "*) cat > "\$d/received-keys"; echo barking_relay-secrets >> "\$d/volumes" ;;
  *" /tmp/apns.p8 "*) cat > "\$d/received-apns" ;;
  # The relay container exists once relay.log does (at \`up\` on the target).
  " logs barking-relay-1 "*)
    [ -e "\$d/relay.log" ] || { echo "Error response from daemon: No such container: barking-relay-1" >&2; exit 1; }
    cat "\$d/relay.log" ;;
  *" logs "*) echo "fake docker: unexpected logs call" >&2; exit 1 ;;
  *" init "*) echo barking_node-data >> "\$d/volumes"; printf 'identifier  : $node_id\naddress     : 0.0.0.0:4433\n' ;;
  *" up "*)
    [ ! -e "\$d/no-container" ] || exit 0
    : >> "\$d/relay.log"
    [ ! -e "\$d/relay-log-on-up" ] || cp "\$d/relay-log-on-up" "\$d/relay.log" ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/ssh" "$tmp/bin/uname" "$tmp/bin/docker"

n=0
fresh() { # new repository copy in $repo, a source host `src` and a new host `dst`
  n=$((n + 1))
  repo="$tmp/repo$n"
  mkdir -p "$repo/dist"
  cp -R "$racine/scripts" "$racine/deploy" "$racine/docker" "$repo/"
  # Without the tests: this file holds the fake secret.
  rm -rf "$repo/deploy/config" "$repo/deploy/.env" "$repo/scripts/tests"
  local ar bin f
  for ar in aarch64 x86_64; do
    for bin in node push; do : > "$repo/dist/barking-$bin-0.1.0-$ar-unknown-linux-musl"; done
  done
  (cd "$repo/dist" && for f in barking-*; do
     printf '%s  %s\n' "$(cksum < "$f" | cut -d' ' -f1)" "$f"; done) > "$repo/dist/SHA256SUMS"
  export FAKE_HOSTS="$tmp/hosts$n"
  src="$FAKE_HOSTS/src" dst="$FAKE_HOSTS/dst"
  mkdir -p "$src/home/barking/deploy" "$dst/home"
  echo x86_64 > "$src/arch"
  echo aarch64 > "$dst/arch"
  printf '%s\n' barking_node-data barking_relay-secrets > "$src/volumes"
  : > "$dst/volumes"
  printf '%s\n' apns.p8 node.key seal1.key seal2.key > "$src/relay-files"
  printf 'INFO barking_push: relay %s started\nINFO barking_push: relay stats available=true\n' \
    "$relay_id" > "$src/relay.log"
  printf 'INFO barking_push: relay %s started\n' "$relay_id" > "$dst/relay-log-on-up"
  mkdir -p "$repo/Key Dir"
  printf -- '-----BEGIN PRIVATE KEY-----\nREPLICA-APNS\n-----END PRIVATE KEY-----\n' > "$repo/Key Dir/AuthKey.p8"
  mkdir -p "$tmp/tmpdir$n"
}
run() { # runs relay-replica in $repo with a private TMPDIR; sets $code and $out
  set +e
  out="$(cd "$repo" && PATH="$tmp/bin:$PATH" TMPDIR="$tmp/tmpdir$n" \
    RELAY_REPLICA_WAIT=1 bash "$repo/scripts/relay-replica.sh" "$@" 2>&1)"
  code=$?
  set -e
}
std_args() { # sets the array ra (bash 3.2 has no mapfile)
  ra=(--from src --to dst --public-addr 80.67.169.12:4433
    --apns-key "$repo/Key Dir/AuthKey.p8" --team-id ABCDE12345 --key-id KLMNO12345 --version 0.1.0)
}
# Fails if the target or the source logged a call that changes something.
nothing_changed() {
  ! grep -qE $'(^|\t)(build|up|down|init|-xpf|rm)(\t|$)' "$src/docker.log" "$dst/docker.log" 2>/dev/null \
    && ! grep -qE 'cat >|tar -C [^ ]* -xf|-xpf' "$dst/ssh.log" 2>/dev/null \
    && [ ! -e "$dst/home/barking" ]
}

echecs=0
ok() { echo "ok   $1"; }
ko() { echo "FAIL $1" >&2; [ -z "${out:-}" ] || printf '%s\n' "$out" | sed 's/^/     | /' >&2; echecs=$((echecs + 1)); }
has() { grep -qF -- "$2" "$1"; }

# --- refuses_when_target_has_secrets
for v in barking_relay-secrets barking_node-data; do
  fresh
  echo "$v" > "$dst/volumes"
  std_args
  run "${ra[@]}"
  t="refuses_when_target_has_secrets $v"
  if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF "$v" && nothing_changed
  then ok "$t"; else ko "$t (code $code)"; fi
done

# --- refuses_when_source_has_no_relay
fresh
: > "$src/volumes"
std_args
run "${ra[@]}"
t=refuses_when_source_has_no_relay
if [ "$code" -eq 1 ] && nothing_changed && ! grep -q $'\trun\t' "$src/docker.log"
then ok "$t"; else ko "$t (code $code)"; fi
for files in "apns.p8 seal1.key" "apns.p8 node.key"; do
  fresh
  # shellcheck disable=SC2086 # one name per word, on purpose
  printf '%s\n' $files > "$src/relay-files"
  std_args
  run "${ra[@]}"
  t="refuses_when_source_has_no_relay ($files)"
  if [ "$code" -eq 1 ] && nothing_changed; then ok "$t"; else ko "$t (code $code)"; fi
done
fresh
: > "$src/relay.log"
std_args
run "${ra[@]}"
t="refuses_when_source_logs_no_relay_id"
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -q 'logs rotated' && nothing_changed
then ok "$t"; else ko "$t (code $code)"; fi
fresh
rm "$src/relay.log"
std_args
run "${ra[@]}"
t="refuses_when_source_relay_log_unreadable"
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF 'src: cannot read the log of the relay container barking-relay-1' \
  && ! printf '%s' "$out" | grep -qi 'restart' && nothing_changed
then ok "$t"; else ko "$t (code $code)"; fi

# --- streams_relay_keys_without_local_copy
fresh
std_args
run "${ra[@]}"
t=streams_relay_keys_without_local_copy
leaks="$(grep -rlF "$secret" "$repo" "$tmp/tmpdir$n" 2>/dev/null || true)"
named="$(find "$repo" "$tmp/tmpdir$n" \( -name '*node.key*' -o -name '*seal*' \) 2>/dev/null || true)"
if [ "$code" -eq 0 ] && [ -z "$leaks" ] && [ -z "$named" ] \
  && ! printf '%s' "$out" | grep -qF "$secret" \
  && grep -qF -- "-cf - node.key seal1.key seal2.key" "$src/ssh.log" \
  && ! grep -q 'apns.p8' "$src/ssh.log" \
  && grep -qF -- "-xpf -" "$dst/ssh.log" \
  && has "$dst/received-keys" "$secret" \
  && grep -q $'\trun\t--rm\t.*node\tinit\t--config\t/etc/barking-node.toml' "$dst/docker.log" \
  && cmp -s "$repo/Key Dir/AuthKey.p8" "$dst/received-apns" \
  && ! printf '%s' "$out" | grep -qF "REPLICA-APNS" \
  && grep -qF "install -m 0600 -o 65532 -g 65532 /tmp/apns.p8 /s/apns.p8" "$dst/ssh.log" \
  && [ -f "$dst/home/barking/deploy/compose.yaml" ] && [ -f "$dst/home/barking/docker/push.Dockerfile" ] \
  && [ -f "$dst/home/barking/dist/barking-push-0.1.0-aarch64-unknown-linux-musl" ] \
  && [ -f "$dst/home/barking/dist/SHA256SUMS" ] \
  && [ ! -e "$dst/home/barking/deploy/config/._barking-push.toml" ] \
  && grep -q $'\tup\t-d' "$dst/docker.log" \
  && ! grep -qE $'(^|\t)(build|up|down|-xpf|rm)(\t|$)' "$src/docker.log"
then ok "$t"; else ko "$t (code $code)"; fi
# Every ssh call runs in batch mode (the fake refuses others), the APNs key
# goes after the relay keys, and the relay starts after both.
xl="$(grep -n -- '-xpf -' "$dst/ssh.log" | head -n1 | cut -d: -f1 || true)"
al="$(grep -n 'apns.p8' "$dst/ssh.log" | head -n1 | cut -d: -f1 || true)"
ul="$(grep -n ' up -d' "$dst/ssh.log" | head -n1 | cut -d: -f1 || true)"
t=order_keys_then_up
if [ -n "$xl" ] && [ -n "$al" ] && [ -n "$ul" ] && [ "$xl" -lt "$al" ] && [ "$al" -lt "$ul" ]
then ok "$t"; else ko "$t"; fi

# --- writes_replica_key_id (and the rest of the configuration)
t=writes_replica_key_id
pcfg="$dst/home/barking/deploy/config/barking-push.toml"
ncfg="$dst/home/barking/deploy/config/barking-node.toml"
if [ "$code" -eq 0 ] && has "$pcfg" 'key_id = "KLMNO12345"' && has "$pcfg" 'team_id = "ABCDE12345"' \
  && has "$pcfg" 'topic = "com.nakocorp.barking"' && has "$pcfg" 'listen = ["0.0.0.0:4434"]' \
  && has "$pcfg" 'node_key_file = "/var/lib/barking-push/node.key"' \
  && has "$pcfg" '{ id = 1, file = "/var/lib/barking-push/seal1.key" }' \
  && has "$pcfg" '{ id = 2, file = "/var/lib/barking-push/seal2.key" }' \
  && has "$pcfg" 'key_file = "/var/lib/barking-push/apns.p8"' \
  && has "$ncfg" 'listen = ["0.0.0.0:4433"]' && has "$ncfg" 'data_dir = "/var/lib/barking-node"' \
  && has "$ncfg" 'public_addr = ["80.67.169.12:4433"]' \
  && [ "$(cat "$dst/home/barking/deploy/.env")" = "BARKING_VERSION=0.1.0
BARKING_IPV6=false" ] && [ ! -e "$repo/deploy/.env" ] && [ ! -e "$repo/deploy/config" ]
then ok "$t"; else ko "$t (code $code)"; fi
fresh
std_args
run "${ra[@]}" --topic com.example.app
if [ "$code" -eq 0 ] && has "$dst/home/barking/deploy/config/barking-push.toml" 'topic = "com.example.app"'
then ok "$t --topic"; else ko "$t --topic (code $code)"; fi

# --- fails_on_identity_mismatch
fresh
printf 'INFO barking_push: relay %s started\n' "$other_id" > "$dst/relay-log-on-up"
std_args
run "${ra[@]}"
t=fails_on_identity_mismatch
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF "$other_id" \
  && ! printf '%s' "$out" | grep -q 'push.barking.nakocorp.com' \
  && grep -qE $'\tdown(\t|$)' "$dst/docker.log" \
  && grep -q $'volume\trm\t-f\tbarking_relay-secrets' "$dst/docker.log" \
  && grep -q $'volume\trm\t-f\tbarking_node-data' "$dst/docker.log" \
  && ! grep -qE $'(^|\t)(down|rm)(\t|$)' "$src/docker.log"
then ok "$t"; else ko "$t (code $code)"; fi
fresh
rm "$dst/relay-log-on-up"
std_args
run "${ra[@]}"
t=fails_when_target_never_starts
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF "did not log 'relay <id> started'" \
  && grep -q $'volume\trm\t-f\tbarking_relay-secrets' "$dst/docker.log"
then ok "$t"; else ko "$t (code $code)"; fi
fresh
touch "$dst/no-container"
std_args
run "${ra[@]}"
t=fails_when_target_relay_log_unreadable
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF 'dst: cannot read the log of the relay container barking-relay-1' \
  && grep -q $'volume\trm\t-f\tbarking_relay-secrets' "$dst/docker.log"
then ok "$t"; else ko "$t (code $code)"; fi

# --- prints_dns_records
fresh
std_args
run "${ra[@]}" --public-addr '[2A01:E0A::1]:4433'
t=prints_dns_records
ncfg="$dst/home/barking/deploy/config/barking-node.toml"
pcfg="$dst/home/barking/deploy/config/barking-push.toml"
if [ "$code" -eq 0 ] && printf '%s\n' "$out" | grep -qxF "relay id : $relay_id" \
  && printf '%s\n' "$out" | grep -qxF 'A push.barking.nakocorp.com 80.67.169.12' \
  && printf '%s\n' "$out" | grep -qxF 'AAAA push.barking.nakocorp.com 2a01:e0a::1' \
  && grep -qx 'BARKING_IPV6=true' "$dst/home/barking/deploy/.env" \
  && has "$ncfg" 'public_addr = ["80.67.169.12:4433", "[2a01:e0a::1]:4433"]' \
  && has "$ncfg" 'listen = ["[::]:4433"]' && has "$pcfg" 'listen = ["[::]:4434"]'
then ok "$t"; else ko "$t (code $code)"; fi
fresh
std_args
run --from src --to dst --public-addr '[2a01:e0a::1]:4433' --apns-key "$repo/Key Dir/AuthKey.p8" \
  --team-id ABCDE12345 --key-id KLMNO12345 --version 0.1.0
if [ "$code" -eq 0 ] && ! printf '%s\n' "$out" | grep -q '^A push' \
  && printf '%s\n' "$out" | grep -qxF 'AAAA push.barking.nakocorp.com 2a01:e0a::1'
then ok "$t ipv6 only"; else ko "$t ipv6 only (code $code)"; fi

# --- usage errors: exit 2, no ssh at all
t=usage_errors
for bad in "--public-addr|203.0.113.7:4433" "--public-addr|192.168.1.10:4433" "--public-addr|80.67.169.12" \
  "--key-id|klmno12345" "--team-id|ABC" "--topic|com.x\"y" "--version|0.1.0;x" "--to|src" "--to|-oProxyCommand=x" \
  "--apns-key|/nonexistent/AuthKey.p8" "--bogus|x"; do
  fresh
  std_args
  opt="${bad%%|*}"
  val="${bad#*|}"
  if [ "$opt" = --public-addr ]; then
    run --from src --to dst --public-addr "$val" --apns-key "$repo/Key Dir/AuthKey.p8" \
      --team-id ABCDE12345 --key-id KLMNO12345 --version 0.1.0
  else
    run "${ra[@]}" "$opt" "$val"
  fi
  if [ "$code" -eq 2 ] && [ ! -e "$src/ssh.log" ] && [ ! -e "$dst/ssh.log" ]
  then ok "$t $opt $val"; else ko "$t $opt $val (code $code)"; fi
done
for missing in --from --to --public-addr --apns-key --team-id --key-id --version; do
  fresh
  std_args
  args=()
  i=0
  while [ "$i" -lt "${#ra[@]}" ]; do
    if [ "${ra[$i]}" = "$missing" ]; then i=$((i + 2)); continue; fi
    args+=("${ra[$i]}"); i=$((i + 1))
  done
  run "${args[@]}"
  if [ "$code" -eq 2 ] && printf '%s' "$out" | grep -qF -- "$missing" && [ ! -e "$dst/ssh.log" ]
  then ok "$t missing $missing"; else ko "$t missing $missing (code $code)"; fi
done

# --- missing_binary_for_target_arch (aarch64 on dst): refused before any change
fresh
grep -v "barking-push-0.1.0-aarch64-" "$repo/dist/SHA256SUMS" > "$tmp/sums" && cp "$tmp/sums" "$repo/dist/SHA256SUMS"
std_args
run "${ra[@]}"
t=missing_binary_for_target_arch
if [ "$code" -eq 1 ] && printf '%s' "$out" | grep -qF "barking-push-0.1.0-aarch64-unknown-linux-musl" \
  && nothing_changed; then ok "$t"; else ko "$t (code $code)"; fi

# --- failed_build_is_cleaned: nothing left that blocks a retry, source untouched
fresh
echo build > "$dst/fail"
std_args
run "${ra[@]}"
t=failed_build_is_cleaned
if [ "$code" -eq 1 ] && ! grep -qE $'(^|\t)(build|up|down|rm|-cf)(\t|$)' "$src/docker.log" \
  && [ ! -s "$dst/volumes" ]; then ok "$t"; else ko "$t (code $code)"; fi

[ "$echecs" -eq 0 ] || { echo "$echecs failure(s)" >&2; exit 1; }
echo "all relay-replica checks passed"
