#!/usr/bin/env bash
# Build and run a libFuzzer harness for a fixed wallclock budget.
# Usage: fuzz.sh <fuzz_target> [seconds]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-fuzz_field}"
SECS="${2:-30}"

BUILD="$ROOT/build-fuzz"
if [[ ! -d "$BUILD" ]]; then
    cmake -S "$ROOT" -B "$BUILD" \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DSECRET_SHARING_BUILD_FUZZ=ON \
        -DSECRET_SHARING_BUILD_TESTS=OFF \
        -DSECRET_SHARING_BUILD_BENCH=OFF
fi
cmake --build "$BUILD" --target "$TARGET" -j 4

# Per-target corpus directory.
CORPUS="$ROOT/build-fuzz/corpus_$TARGET"
mkdir -p "$CORPUS"

exec "$BUILD/fuzz/$TARGET" "$CORPUS" -max_total_time="$SECS" -print_final_stats=1
