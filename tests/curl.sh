#!/usr/bin/env bash

: "${_URL:=$1}"
: "${_PROXY:=https://127.0.0.1:4430}"
: "${_SLEEP:=10}"

set -o errexit -o nounset

[[ -n "$_URL" ]]

_TMPDIR="$(mktemp -d /tmp/dduct-curl-XXXX)" && install -d "$_TMPDIR/" && echo "$_TMPDIR/"

xargs --no-run-if-empty -i{} -n1 -P4 sh -c '{}' <<EOF
sleep       0; curl -s --proxy-insecure --proxy $_PROXY --insecure $_URL --output $_TMPDIR/A && echo A;
sleep $_SLEEP; curl -s --proxy-insecure --proxy $_PROXY --insecure $_URL --output $_TMPDIR/B && echo B;
sleep $_SLEEP; curl -s --proxy-insecure --proxy $_PROXY --insecure $_URL --output $_TMPDIR/C && echo C;
sleep $_SLEEP; curl -v --proxy-insecure --proxy $_PROXY --insecure $_URL --output $_TMPDIR/D && echo D;
EOF

(cd "$_TMPDIR/" && ls -lha && md5sum *)
