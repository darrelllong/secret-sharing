#!/usr/bin/env bash
# Regenerate the pinned-rump BigInt differential vectors used by the C++
# BigInt tests. The reference values come from the repository's Rust
# BigInt/number-theory layer, which is pinned to the contest rump crate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/cpp/test/bigint_differential_vectors.inc"

cargo run --manifest-path "$ROOT/Cargo.toml" --release --example dump_bigint_vectors > "$OUT"
