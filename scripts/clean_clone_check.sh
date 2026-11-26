#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$TMP"
cd "$TMP"
moon check --deny-warn
moon test -j 1
moon build --target native cmd/main
moon build --target wasm --release src/web
bash web/build.sh
node test/web_node_check.mjs
echo "CLEAN CLONE PASS"
