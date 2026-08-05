#!/bin/sh
set -eu

cd "$(dirname "$0")"
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --locked -- -D warnings
