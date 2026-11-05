#!/usr/bin/env bash
# Test push to the APNs sandbox (spec iOS foundations §6.3): the exact push the
# barking-push relay sends (spec iOS push §4), straight to Apple, with no node
# and no relay. Development only.
# Usage: APNS_KEY_FILE=<key.p8> APNS_KEY_ID=<id> APNS_TEAM_ID=<id> scripts/apns-send.sh [--dry-run] <device-token>
#
# The .p8 key and the team identifier never go in the repository.
set -euo pipefail

TOPIC="com.nakocorp.barking"
HOST="api.sandbox.push.apple.com"
PAYLOAD='{"aps":{"alert":{"loc-key":"NEW_MESSAGE"},"mutable-content":1,"sound":"default"}}'

usage() { echo "Usage: APNS_KEY_FILE=… APNS_KEY_ID=… APNS_TEAM_ID=… $0 [--dry-run] <device-token>" >&2; }
fail() { echo "error: $*" >&2; exit 2; }

dry_run=false
if [ "${1:-}" = "--dry-run" ]; then dry_run=true; shift; fi
[ $# -eq 1 ] || { usage; exit 2; }
token="$1"
[[ "$token" =~ ^[0-9a-f]{64,200}$ ]] || fail "device token: 64 to 200 lowercase hexadecimal characters expected"
for v in APNS_KEY_FILE APNS_KEY_ID APNS_TEAM_ID; do
  [ -n "${!v:-}" ] || fail "$v is not set"
done

headers=(
  -H "apns-push-type: alert"
  -H "apns-priority: 10"
  -H "apns-topic: $TOPIC"
  -H "apns-expiration: $(( $(date +%s) + 3600 ))"
)

if $dry_run; then
  echo "POST https://$HOST/3/device/$token"
  printf '%s\n' "${headers[@]}" | grep -v '^-H$'
  echo "$PAYLOAD"
  exit 0
fi

[ -r "$APNS_KEY_FILE" ] || fail "APNS_KEY_FILE is not readable"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# ES256 JWT. openssl signs in DER (SEQUENCE of two INTEGERs); JWS wants r||s,
# 32 bytes each, left-padded.
header="$(printf '{"alg":"ES256","kid":"%s"}' "$APNS_KEY_ID" | b64url)"
claims="$(printf '{"iss":"%s","iat":%d}' "$APNS_TEAM_ID" "$(date +%s)" | b64url)"
der="$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$APNS_KEY_FILE" | openssl asn1parse -inform DER)"
raw=""
while read -r int; do
  int="${int#*:}"
  while [ ${#int} -lt 64 ]; do int="0$int"; done
  raw="$raw${int: -64}"
done < <(printf '%s\n' "$der" | sed -n 's/.*INTEGER *:\([0-9A-F]*\)$/x:\1/p')
[ ${#raw} -eq 128 ] || fail "unexpected signature format"
signature="$(printf '%s' "$raw" | xxd -r -p | b64url)"

curl --silent --show-error --http2 --fail-with-body \
  "${headers[@]}" \
  -H "authorization: bearer $header.$claims.$signature" \
  --data "$PAYLOAD" \
  "https://$HOST/3/device/$token"
echo "sent"
