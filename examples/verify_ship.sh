#!/usr/bin/env bash
# verify_ship.sh — round-trip the bundled ship-of-fools image through
# the visual-cryptography example and confirm the recovered PBM is
# byte-identical to the secret. Leaves the per-share PBMs in
# `examples/ship_output/` for inspection.
#
# Usage:
#   bash examples/verify_ship.sh           # default 3-of-3 split
#   bash examples/verify_ship.sh 2         # 2-of-2 split
#   N=5 bash examples/verify_ship.sh       # 5-of-5 split via env

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

input="assets/ship_of_fools.pbm"
out_dir="examples/ship_output"
prefix="$out_dir/ship"
n="${1:-${N:-3}}"

if [ ! -f "$input" ]; then
    echo "missing $input — bundled secret image is required" >&2
    exit 1
fi

mkdir -p "$out_dir"
rm -f "$prefix".*.pbm "$prefix".pbm

echo "==> building example (release)"
cargo build --release --example visual_ship >/dev/null

echo "==> running visual_ship with n=$n"
./target/release/examples/visual_ship "$input" "$prefix" "$n"

recovered="$prefix.recovered.pbm"
if [ ! -f "$recovered" ]; then
    echo "FAIL: $recovered was not produced" >&2
    exit 1
fi

echo "==> diffing recovered against secret"
if diff -q "$input" "$recovered" >/dev/null; then
    echo "PASS: $recovered is byte-identical to $input"
else
    echo "FAIL: $recovered differs from $input" >&2
    diff "$input" "$recovered" | head -5 >&2 || true
    exit 1
fi

echo
echo "Artefacts left in $out_dir/ for inspection:"
ls -la "$out_dir"
