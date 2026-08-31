#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/pg_config" >&2
  exit 2
fi

pg_config="$1"
pg_bindir="$("$pg_config" --bindir)"
pg_major="$("$pg_config" --version | sed -n 's/.* \([0-9][0-9]*\).*/\1/p')"
test_port="$((55000 + pg_major))"
test_root="$(mktemp -d "/tmp/pg-crypto-pg${pg_major}.XXXXXX")"

cleanup() {
  "$pg_bindir/pg_ctl" -D "$test_root/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$test_root"
}
trap cleanup EXIT

cargo pgrx install --pg-config "$pg_config"
"$pg_bindir/initdb" -D "$test_root/data" --no-locale --encoding=UTF8 >/dev/null
"$pg_bindir/pg_ctl"   -D "$test_root/data"   -o "-F -p $test_port -k $test_root"   -w start >/dev/null
"$pg_bindir/createdb" -h "$test_root" -p "$test_port" pg_crypto_test
"$pg_bindir/psql"   -X -v ON_ERROR_STOP=1   -h "$test_root" -p "$test_port" -d pg_crypto_test   -f "$(dirname "$0")/crypto-smoke.sql"
