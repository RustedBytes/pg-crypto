#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_version="$(
  sed -n '/^\[package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p'     "$repo_root/Cargo.toml"
)"
control_version="$(
  sed -n "s/^default_version = '\([^']*\)'/\1/p"     "$repo_root/pg_crypto.control"
)"

if [[ -z "$cargo_version" || "$cargo_version" != "$control_version" ]]; then
  echo "Cargo.toml and pg_crypto.control versions differ" >&2
  exit 1
fi

if [[ "$cargo_version" == "0.1.0" ]]; then
  echo "pg_crypto 0.1.0 is the initial release; version metadata is synchronized"
  exit 0
fi

upgrade_script="$repo_root/sql/pg_crypto--0.1.0--$cargo_version.sql"
if [[ ! -f "$upgrade_script" ]]; then
  echo "missing upgrade script: $upgrade_script" >&2
  exit 1
fi

if ! rg -q "ALTER EXTENSION|ALTER TABLE|CREATE OR REPLACE FUNCTION" "$upgrade_script"; then
  echo "upgrade script contains no recognized migration statement" >&2
  exit 1
fi

echo "validated upgrade metadata and $upgrade_script"
