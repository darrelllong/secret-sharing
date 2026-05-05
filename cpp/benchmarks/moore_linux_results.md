# Linux x86 results — moore.soe.ucsc.edu

Host: AMD EPYC 7452 32-Core (128 logical cores), Ubuntu 20.04, clang
10.0.0, CMake 3.16.3, pilot-bench (`quick` preset),
PILOT_SS_ITERS_PERCENT=100.

## Rust vs C++ — Shamir threshold ops

| Operation                | impl | ms/op    | ±CI (95%)  | Runs | C++ speedup |
|--------------------------|------|---------:|-----------:|-----:|------------:|
| shamir_split             | rust | 0.01026  | ±0.001164  |  30  |             |
| shamir_split             | cpp  | 0.007798 | ±0.001289  |  35  | 1.32×       |
| shamir_reconstruct       | rust | 0.01187  | ±0.000275  |  30  |             |
| shamir_reconstruct       | cpp  | 0.01092  | ±0.000378  |  61  | 1.09×       |
| shamir_split_4kb         | rust | 2.019    | ±0.01017   |  49  |             |
| shamir_split_4kb         | cpp  | 1.411    | ±0.01064   |  36  | 1.43×       |
| shamir_reconstruct_4kb   | rust | 3.517    | ±0.01770   |  30  |             |
| shamir_reconstruct_4kb   | cpp  | 3.298    | ±0.05684   |  30  | 1.07×       |

The C++ port wins on every operation, but the gap is narrower on
reconstruct than on split — Lagrange interpolation at x = 0 calls
mod_inverse once, which dominates the per-call cost and is identical
in both languages. Split dominates on schoolbook field multiplications
where the bounds-check overhead in the Rust impl matters most.

Compared to the macOS results in rust_vs_cpp.md (1.25×–1.52×), the
Linux gap is similar in shape but slightly smaller (1.07×–1.43×).
Both numbers are toolchain-level, not algorithmic.

## C++ per-prime mul-mod throughput

Speedup is the parametric reducer (or `mersenne127` u128 path) vs the
generic Montgomery path under `big_uint::mod_mul`. Median of 50
warmup + 200 measured calls.

| Prime       | bits | fast path | generic   | speedup  |
|-------------|-----:|----------:|----------:|---------:|
| mersenne127 |  127 |     50 ns |  2.465 µs |  49.30×  |
| mersenne521 |  521 |    291 ns |  11.66 µs |  40.08×  |
| curve448    |  448 |    601 ns |  9.778 µs |  16.27×  |
| curve25519  |  255 |    461 ns |  5.059 µs |  10.97×  |
| nist_p224   |  224 |    601 ns |  5.901 µs |   9.82×  |
| secp256k1   |  256 |    541 ns |  5.029 µs |   9.30×  |
| nist_p384   |  384 |    992 ns |  8.726 µs |   8.80×  |
| nist_p192   |  192 |    481 ns |  3.798 µs |   7.90×  |
| poly1305    |  130 |    451 ns |  3.486 µs |   7.73×  |
| nist_p256   |  256 |  6.832 µs |  6.492 µs |   0.95×  |

`nist_p256` is recognised in the catalogue but routed through
Montgomery (the `prefer_fast: false` flag); the row above is
Montgomery-vs-Montgomery so the ratio drifts in noise. Every other
prime gets a real speedup from the parametric reducer or the u128
fast path, with the largest wins on the cleanest polynomials
(mersenne127, mersenne521).

The shape of these speedups roughly tracks what the Rust crate sees
on the same hardware: the cleaner the polynomial structure (single
term, small coefficient), the larger the win over Montgomery.

## Full Rust pilot table (Linux x86 baseline)

The Linux numbers run roughly 2× the macOS numbers in PERFORMANCE.md
end-to-end, consistent with the EPYC 7452 / DDR4 memory-system being
slower per single-thread than Apple silicon's M-series. Selected
rows:

Threshold (k=3, n=5, GF over 2^127 − 1):
- shamir_split:                0.01017 ms/op
- shamir_reconstruct:          0.01184 ms/op
- blakley_split:               0.3294  ms/op
- kothari_split:               0.01015 ms/op
- karchmer_wigderson_split:    0.01042 ms/op
- brickell_split:              0.01041 ms/op
- massey_split:                0.00686 ms/op

4 KiB block end-to-end (split + reconstruct, ms / 4 KiB):
- massey:             3.95   (≈1.01 MiB/s)
- shamir:             5.53
- kothari:            5.21
- karchmer–wigderson: 7.51
- brickell:           7.59
- blakley:           137.4

VSS:
- vss_split:          0.0625 ms/op   (Rabin–Ben-Or)
- cgma_vss_split:     2.425  ms/op   (RFC 5114 §2.3 group)
- cgma_vss_reconstruct: 23.20 ms/op  (15 × 2048-bit modexp)

The full table is in /soe/darrell/work/secret-sharing/benchmarks/pilot_ss_latest.md
on moore after a `cargo build --release --bin pilot_ss` and
`scripts/bench_pilot.sh`.

## libFuzzer results — 30 seconds each

Sanitizers: AddressSanitizer + UBSan + libFuzzer. Built under clang
10.0.0 on Linux x86. Total executions: ~3.4 million. **No crashes,
no sanitizer hits, no contract violations.**

| Harness     | Executions | exec/s | New corpus units | Notes |
|-------------|-----------:|-------:|-----------------:|-------|
| fuzz_bigint |  1,014,618 | 32,729 |  5 |
| fuzz_field  |  2,310,185 | 74,522 |  2 |
| fuzz_shamir |     46,578 |  1,502 | 15 | per-iter does full split + reconstruct + tampering checks |

The bigint harness checks `(a + b) − b == a`, commutativity of
multiplication, `a · 0 == 0`, `a · 1 == a`, the bit-split round-trip
`high · 2^k + low = a`, and `mod_mul` agreement with `(a · b) % m`.
The field harness checks the Mersenne-127 fast path against
generic Montgomery on every random operand pair. The Shamir harness
exercises the round-trip plus the tampered-extra rejection contract
across (k, n) drawn from the input.

The Shamir harness is allocation-heavy (multiple BigUint per share
× n shares × per-iteration tampered duplicate); the lower exec/s
reflects that, not a fuzzer issue. Coverage at 528 features — the
plateau means the fuzzer found every reachable path early and
spent the remainder confirming no crash exists in those paths.
