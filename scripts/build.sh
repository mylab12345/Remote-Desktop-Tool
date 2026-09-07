#!/usr/bin/env bash
# Format, lint, test and build the workspace.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> rustfmt"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> tests"
cargo test --workspace

echo "==> release build"
cargo build --workspace --release

echo "==> done; binaries in target/release"
