#!/usr/bin/env bash
# Run Facebook Infer across the C++ port.
# Requires `infer` on PATH (`brew install infer` on macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build-infer"
if [[ ! -d "$BUILD" ]]; then
    cmake -S "$ROOT" -B "$BUILD" \
        -DSECRET_SHARING_BUILD_TESTS=OFF \
        -DSECRET_SHARING_BUILD_FUZZ=OFF \
        -DSECRET_SHARING_BUILD_BENCH=OFF
fi
cd "$BUILD"
exec infer run --compilation-database compile_commands.json
