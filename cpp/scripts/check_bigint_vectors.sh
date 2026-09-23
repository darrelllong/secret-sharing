#!/usr/bin/env bash
# Verify that the committed C++ differential vectors exactly match a fresh
# pinned-rump regeneration.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CURRENT="$ROOT/cpp/test/bigint_differential_vectors.inc"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cargo run --manifest-path "$ROOT/Cargo.toml" --release --example dump_bigint_vectors > "$TMP"
diff -u "$CURRENT" "$TMP"
