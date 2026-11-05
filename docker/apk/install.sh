#!/bin/sh
# Install the APK closure listed in $1, then fail unless exactly that closure is installed.
set -eu
# shellcheck disable=SC2046 # one package per word, on purpose
apk add --no-cache $(cat "$1")
awk '/^P:/{p=substr($0,3)} /^V:/{print p "=" substr($0,3)}' /lib/apk/db/installed \
  | sort | cmp - "$1"
