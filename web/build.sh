#!/usr/bin/env bash
# Build the moonforge wasm workbench and stage it next to web/index.html.
#
# The MoonBit wasm backend emits only the module; the host glue lives in
# web/runtime.mjs and is shared with the node acceptance test, so the page and
# CI exercise the same code path.
#
# Usage:  bash web/build.sh
# Serve:  cd web && python -m http.server 8080   ->  http://localhost:8080/
# Test:   node test/web_node_check.mjs
set -euo pipefail
cd "$(dirname "$0")/.."

moon build --target wasm --release src/web

wasm=_build/wasm/release/build/src/web/web.wasm
cp "$wasm" web/main.wasm
echo "staged web/main.wasm ($(wc -c < web/main.wasm) bytes)"