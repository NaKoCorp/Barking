# shellcheck shell=bash
# Checks shared by the deployment scripts (scripts/stack-init.sh,
# scripts/relay-replica.sh). Sourced, never run. Bash 3.2 (macOS).

# --- address checks -------------------------------------------------------

# Address checks mirror barking_proto::record::routable: the node refuses to
# start with a non-routable public_addr, and to dial a non-routable relay.

# True if the dotted IPv4 $1 is routable (not private, loopback, link-local,
# shared, documentation, "this network", multicast, broadcast or reserved).
ipv4_is_public() {
  local IFS=. a b c d x
  # shellcheck disable=SC2086 # split on dots, on purpose
  set -- $1
  [ "$#" -eq 4 ] || return 1
  for x in "$@"; do
    # Rust's Ipv4Addr parser refuses leading zeros (octal ambiguity).
    case "$x" in '' | *[!0-9]* | 0[0-9]*) return 1 ;; esac
    [ "$x" -le 255 ] || return 1
  done
  a=$1 b=$2 c=$3 d=$4
  : "$d"
  [ "$a" -eq 0 ] && return 1
  [ "$a" -eq 10 ] && return 1
  [ "$a" -eq 127 ] && return 1
  [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1
  [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 1
  [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
  [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 1
  # Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
  [ "$a" -eq 192 ] && [ "$b" -eq 0 ] && [ "$c" -eq 2 ] && return 1
  [ "$a" -eq 198 ] && [ "$b" -eq 51 ] && [ "$c" -eq 100 ] && return 1
  [ "$a" -eq 203 ] && [ "$b" -eq 0 ] && [ "$c" -eq 113 ] && return 1
  [ "$a" -ge 224 ] && return 1
  return 0
}

# Checks the colon-separated hex groups of $1 (no "::" inside): each 1 to 4
# hex digits. Appends them, as numbers, to the global `groups`.
ipv6_part() {
  local IFS=: g
  [ -n "$1" ] || return 0
  case "$1" in :* | *:) return 1 ;; esac
  # shellcheck disable=SC2086 # split on colons, on purpose
  set -- $1
  for g in "$@"; do
    case "$g" in '' | *[!0-9a-f]* | ?????*) return 1 ;; esac
    groups="$groups $((16#$g))"
  done
}

# True if the IPv6 literal $1 (no brackets, lower case) is well formed and
# routable, as barking_proto::record::{routable_v6, embeds_ipv4} decide: not
# unspecified, loopback or IPv4 embedded (first five groups zero),
# link-local (fe80::/10), site-local (fec0::/10), unique local (fc00::/7),
# multicast (ff00::/8) or documentation (2001:db8::/32).
ipv6_is_public() {
  local h="$1" n zeros
  groups=""
  case "$h" in '' | *[!0-9a-f:]* | *:::*) return 1 ;; esac
  case "$h" in *::*::*) return 1 ;; esac
  case "$h" in
    *::*)
      ipv6_part "${h%%::*}" || return 1
      ipv6_part "${h#*::}" || return 1
      # shellcheck disable=SC2086 # count words
      set -- $groups
      n=$#
      [ "$n" -le 7 ] || return 1
      zeros=""
      while [ "$n" -lt 8 ]; do zeros="$zeros 0"; n=$((n + 1)); done
      groups=""
      ipv6_part "${h%%::*}"
      groups="$groups$zeros"
      ipv6_part "${h#*::}"
      ;;
    *) ipv6_part "$h" || return 1 ;;
  esac
  # shellcheck disable=SC2086 # eight words
  set -- $groups
  [ "$#" -eq 8 ] || return 1
  [ "$1" -eq 0 ] && [ "$2" -eq 0 ] && [ "$3" -eq 0 ] && [ "$4" -eq 0 ] && [ "$5" -eq 0 ] && return 1
  [ $(($1 & 0xffc0)) -eq $((0xfe80)) ] && return 1
  [ $(($1 & 0xffc0)) -eq $((0xfec0)) ] && return 1
  [ $(($1 & 0xfe00)) -eq $((0xfc00)) ] && return 1
  [ $(($1 & 0xff00)) -eq $((0xff00)) ] && return 1
  [ "$1" -eq $((0x2001)) ] && [ "$2" -eq $((0xdb8)) ] && return 1
  return 0
}

# Lower case of $1.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# True if $1 is a routable IP literal: dotted IPv4, or IPv6 in brackets.
ip_is_public() {
  case "$1" in
    \[*\]) local h="${1#[}"; ipv6_is_public "$(lower "${h%]}")" ;;
    *[!0-9.]* | '') return 1 ;;
    *) ipv4_is_public "$1" ;;
  esac
}

# True if $1 is a routable IP literal (IPv6 in brackets) or a DNS name that is
# not obviously local (what a relay host may be).
host_is_public() {
  local h="$1"
  case "$h" in
    \[*\]) ip_is_public "$h"; return ;;
    *[!0-9.]*) ;;
    *) ipv4_is_public "$h"; return ;;
  esac
  case "$h" in
    '' | *[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
  esac
  h="$(lower "$h")"
  case "$h" in
    localhost | *.localhost | *.local | *.internal | *.lan | *.home.arpa) return 1 ;;
  esac
  return 0
}

# Prints the family (4 or 6) of $1 if it is IPV4:PORT or [IPV6]:PORT with a
# routable address and a port from 1 to 65535; fails otherwise. The node
# publishes it in its signed record: no DNS name.
addr_family() {
  local host port
  case "$1" in
    \[*\]:*) host="${1%:*}"; port="${1##*:}" ;;
    *:*:*) return 1 ;;
    *:*) host="${1%:*}"; port="${1##*:}" ;;
    *) return 1 ;;
  esac
  case "$port" in '' | *[!0-9]* | 0*) return 1 ;; esac
  [ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
  ip_is_public "$host" || return 1
  case "$host" in \[*) echo 6 ;; *) echo 4 ;; esac
}

# True if $1 is exactly 10 characters among A-Z and 0-9 (Apple team and key ids).
apple_id() {
  case "$1" in
    # Spelled out: a range such as A-Z can match lower case letters in some locales.
    *[!ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*) return 1 ;;
    ??????????) return 0 ;;
    *) return 1 ;;
  esac
}
