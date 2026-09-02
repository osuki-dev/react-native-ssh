#!/usr/bin/env bash
# Regenerates cpp/rnssh.h from rust/rnssh-ffi via cbindgen.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/rust"
cbindgen --config cbindgen.toml --crate rnssh-ffi --output "$ROOT/cpp/rnssh.h"
echo "wrote cpp/rnssh.h"
