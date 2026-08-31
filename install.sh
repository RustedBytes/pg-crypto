#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if ! command -v cargo-pgrx >/dev/null 2>&1; then
    echo "cargo-pgrx is required; install it with: cargo install --locked cargo-pgrx" >&2
    exit 1
fi

if [[ ! -f "${PGRX_HOME:-$HOME/.pgrx}/config.toml" ]]; then
    cargo pgrx init
fi

cargo pgrx package "$@"
