#!/usr/bin/env bash
# Rebuild the WASM bundle into web/pkg/.
# Run from anywhere; resolves repo root via this script's own path.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.."
wasm-pack build --target web --out-dir web/pkg --release crates/wasm
