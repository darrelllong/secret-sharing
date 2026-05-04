#!/usr/bin/env bash
# verify_ship_color.sh — round-trip the bundled colour ship-of-fools
# image through the colour visual-cryptography example and confirm
# the recovered PPM is byte-identical to the halftoned reference (the
# lossless artefact after Floyd-Steinberg dithering — NOT the raw
# RGB source, which is irrecoverably 8-bit-per-channel). Leaves the
# per-share PPMs in `examples/ship_output/` for inspection.
#
# Usage:
#   bash examples/verify_ship_color.sh         # default 3-of-3 split
#   bash examples/verify_ship_color.sh 2       # 2-of-2 split
#   N=4 bash examples/verify_ship_color.sh     # 4-of-4 split via env

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

input="assets/ship_of_fools.ppm"
out_dir="examples/ship_output"
prefix="$out_dir/ship_color"
n="${1:-${N:-3}}"

if [ ! -f "$input" ]; then
    echo "missing $input — bundled colour secret image is required" >&2
    exit 1
fi

mkdir -p "$out_dir"
rm -f "$prefix".*.ppm

echo "==> building example (release)"
cargo build --release --example visual_ship_color >/dev/null

echo "==> running visual_ship_color with n=$n"
./target/release/examples/visual_ship_color "$input" "$prefix" "$n"

reference="$prefix.halftoned.ppm"
recovered="$prefix.recovered.ppm"
for f in "$reference" "$recovered"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: $f was not produced" >&2
        exit 1
    fi
done

echo "==> diffing recovered against halftoned reference"
if diff -q "$reference" "$recovered" >/dev/null; then
    echo "PASS: $recovered is byte-identical to $reference"
else
    echo "FAIL: $recovered differs from $reference" >&2
    exit 1
fi

echo
echo "Artefacts left in $out_dir/ for inspection:"
ls -la "$out_dir" | grep ship_color
