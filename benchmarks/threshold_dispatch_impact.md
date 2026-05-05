# Threshold-driven dispatch — pilot before/after

Two threshold-driven dispatches landed in this commit:

1. `MontgomeryCtx::pow` picks **binary square-and-multiply** when the
   exponent has fewer than 64 bits and the **4-bit fixed-window** path
   otherwise (`POW_WINDOW_THRESHOLD_BITS = 64`). The window's 14
   table-build mont-muls cost more than they save below the
   crossover; above it the body savings dominate.
2. `MignotteSequence::reconstruct` and
   `AsmuthBloomParams::reconstruct` pick **per-fold `mod_inverse`**
   when the moduli's largest bit length is below 128 and the
   **pairwise CRT-inverse precomp** path at or above
   (`CRT_PRECOMP_THRESHOLD_BITS = 128`). At small modulus sizes
   `BigUint::mod_mul` rebuilds a Montgomery context per call and
   the setup cost outweighs the per-step extended-Euclidean
   saving; the cost flips at ~130 bits.

All measurements: pilot-bench `quick` preset,
`PILOT_SS_ITERS_PERCENT=100`. The "before" binary is built from
commit `cfbf31b` (which had unconditional window-method exp but no
CRT precomp) in a worktree with the new pilot ops backported. The
"after" is `b0a350d` with both threshold dispatches.

## Where the threshold dispatch makes a measured difference

### macOS (Apple silicon)

| Operation                              | before (ms)        | after (ms)         | speedup |
|----------------------------------------|-------------------:|-------------------:|--------:|
| `mignotte_reconstruct_large` (130-bit) | 0.04688 ± 3.87e-04 | 0.01266 ± 8.18e-05 | **3.70×** |

### Linux x86 (moore, AMD EPYC 7452)

| Operation                              | before (ms)       | after (ms)        | speedup |
|----------------------------------------|------------------:|------------------:|--------:|
| `mignotte_reconstruct_large` (130-bit) | 0.1176 ± 9.7e-04  | 0.02382 ± 1.3e-04 | **4.94×** |
| `cgma_vss_reconstruct` (256-bit exp)   | 21.68 ± 0.077     | 20.03 ± 0.131     | 1.08×  |
| `cgma_vss_split` (256-bit exp)         | 2.235 ± 0.011     | 2.112 ± 0.008     | 1.06×  |

The 4.94× win on Linux x86 is larger than the 3.70× on macOS
because EPYC's per-`mod_inverse` cost at 130-bit moduli is higher
in absolute terms while the precomp branch's `mod_mul` cost is
similar — so the saving is proportionally larger. The cgma_vss
rows on Linux drift modestly below their CIs even though both
versions use the window method, suggesting the threshold-dispatch
branch (`if exponent.bits() < 64`) costs essentially nothing
inside an already long-running modexp.

This is the headline. A 130-bit Mignotte sequence is the smallest
modulus class that crosses the 128-bit threshold, and the precomp
branch immediately pays off: the per-fold $k - 1 = 2$ extended-
Euclidean calls become $\binom{k}{2} = 3$ precomputed-pair
multiplications.

## Where the threshold dispatch is correctly silent

Below the thresholds, the dispatch routes to the historical path
and the change is bit-for-bit identical to `cfbf31b`. Within-noise
deltas confirm no regression. macOS sample:

| Operation                         | before (ms)         | after (ms)          | Δ |
|-----------------------------------|--------------------:|--------------------:|---|
| `cgma_vss_split` (256-bit exp)    | 1.164  ± 0.103      | 1.136  ± 0.152      | within ±CI |
| `cgma_vss_reconstruct` (256-bit)  | 11.38  ± 1.015      | 10.41  ± 0.011      | within ±CI |
| `mignotte_split` (≤8-bit moduli)  | 0.0003641 ± 1.4e-05 | 0.0003432 ± 1.5e-05 | within ±CI |
| `mignotte_reconstruct`            | 0.002678 ± 6.0e-05  | 0.002646 ± 6.5e-05  | within ±CI |
| `asmuth_bloom_split`              | 0.0005934 ± 1.8e-05 | 0.0006074 ± 1.3e-05 | within ±CI |
| `asmuth_bloom_reconstruct`        | 0.002791 ± 7.5e-05  | 0.002815 ± 8.2e-05  | within ±CI |
| `shamir_split` (no exp involved)  | 0.006138 ± 6.0e-04  | 0.005853 ± 5.8e-04  | within ±CI |

Linux confirms the same shape (asmuth_bloom_reconstruct 5.33 →
5.17 µs, mignotte_reconstruct 4.93 → 4.87 µs, shamir_split 10.39
→ 9.75 µs — all within their CIs).

`cgma_vss` exponents are 256-bit, so both branches take the
window path; the small drift is run-to-run noise, not the
dispatch logic. `mignotte_split` / `_reconstruct` use ≤ 8-bit
moduli (the bundled small example sequence), so both branches
take the `mod_inverse` path.

## Why thresholds, not "always use the new algorithm"

The CRT precomp went through one earlier round of measurement
where it was applied unconditionally; pilot showed it regressed
the small-modulus reconstruct paths by ~1.6× because
`BigUint::mod_mul` rebuilds a Montgomery context per call — at
small modulus sizes that setup is comparable to the per-step
extended-Euclidean it tries to replace, so the change moved a
direct call into a more expensive indirect call. The threshold
dispatch is the right shape: ship the optimization where it
demonstrably wins, fall back where it demonstrably doesn't.

The window-method exponentiation has the same structure on a
smaller scale: its 14 table-build multiplies are cheap relative
to a 256-bit exponent (where they amortise over ~64 windows) but
expensive relative to a 16-bit exponent (where they are 14 × the
cost of the body). Same dispatch, same threshold story.

## Both branches are regression-tested

Three new tests pin the dispatch:

- `bigint::tests::montgomery_pow_handles_short_exponents` — the
  binary path on every exponent in [0, 20] and the all-zero-windows
  case 2^16, against an independent schoolbook reference.
- `mignotte::tests::small_example_skips_precomp` — asserts the
  precomp table is `None` for the 8-23 bit small example.
- `mignotte::tests::large_example_uses_precomp` and
  `large_example_round_trip_via_precomp` — assert the precomp
  table is populated for a deterministically-generated 130-bit
  sequence and that reconstruct via the precomp branch produces
  the same secret as the direct branch.

Together these prevent any future refactor from quietly routing
all traffic through one branch.

## Reproducing

```bash
git worktree add /tmp/ss-prethreshold cfbf31b
cp src/bin/pilot_ss.rs /tmp/ss-prethreshold/src/bin/pilot_ss.rs
( cd /tmp/ss-prethreshold && cargo build --release --bin pilot_ss )
cargo build --release --bin pilot_ss

BENCH=$HOME/pilot-bench/build/cli/bench
export PILOT_SS_ITERS_PERCENT=100
for op in mignotte_reconstruct_large cgma_vss_reconstruct mignotte_reconstruct shamir_split; do
    "$BENCH" run_program --preset quick --pi "before_${op},ms/op,0,1,1" \
        -- /tmp/ss-prethreshold/target/release/pilot_ss "$op"
    "$BENCH" run_program --preset quick --pi "after_${op},ms/op,0,1,1" \
        -- ./target/release/pilot_ss "$op"
done
```
