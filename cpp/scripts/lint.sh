#!/usr/bin/env bash
# Run clang-tidy across the C++ port. Requires `cmake -B build`
# beforehand so `compile_commands.json` exists.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
if [[ ! -f "$BUILD/compile_commands.json" ]]; then
    echo "error: $BUILD/compile_commands.json missing — run cmake first" >&2
    exit 1
fi
SOURCES=$(find "$ROOT/src" "$ROOT/include" -name '*.cpp' -o -name '*.hpp' | sort)
exec clang-tidy -p "$BUILD" --warnings-as-errors='*' $SOURCES
