#!/usr/bin/env bash
#
# update.sh — rebuild the gotool binary from the latest Go sources.
#
# Run it manually after making code changes:
#     ./update.sh
#
# It is also wired into the repository as a git post-commit hook, so every
# time you commit new code changes, the tool is rebuilt automatically and
# embedded build metadata (version / commit / date) is refreshed.
#
set -euo pipefail

# --- Locate paths ------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
TOOL_SRC="$REPO_ROOT/gotool"
BIN_DIR="$REPO_ROOT/bin"
BIN_PATH="$BIN_DIR/gotool"

# --- Preconditions -----------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    echo "error: 'go' not found in PATH. Install Go >= 1.19 first." >&2
    exit 1
fi

if [ ! -d "$TOOL_SRC" ]; then
    echo "error: tool sources not found at $TOOL_SRC" >&2
    exit 1
fi

mkdir -p "$BIN_DIR"

# --- Build metadata ----------------------------------------------------------
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
VERSION="${GOTOOL_VERSION:-0.1.0-$COMMIT}"

LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${DATE}"

# --- Rebuild -----------------------------------------------------------------
echo ">> Building gotool (commit ${COMMIT}, built ${DATE}) ..."
(
    cd "$TOOL_SRC"
    CGO_ENABLED=0 GOFLAGS=-mod=mod go build -trimpath -ldflags "$LDFLAGS" -o "$BIN_PATH" .
)

echo ">> Updated: $BIN_PATH"
"$BIN_PATH" version
