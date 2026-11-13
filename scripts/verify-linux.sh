#!/bin/sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
    echo "Run this verification on Linux." >&2
    exit 1
fi

BWRAP=${BWRAP:-bwrap}
export BWRAP
"$BWRAP" --version
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
