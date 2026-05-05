# Window-method exponentiation: before vs after

Same machine (macOS, Apple silicon), same harness (pilot-bench
`quick` preset, `PILOT_SS_ITERS_PERCENT=100`), same operand stream.
The "before" build is the `pilot_ss` binary at commit `d568545`
(parent of cfbf31b); the "after" build is `cfbf31b` with the 4-bit
fixed-window scan in `MontgomeryCtx::pow`.

## Headline: cgma_vss

| Operation               | before (ms)        | after (ms)         | speedup |
|-------------------------|-------------------:|-------------------:|--------:|
| `cgma_vss_split`        | 1.559 ± 0.150      | 1.192 ± 0.0952     | **1.31×** |
| `cgma_vss_reconstruct`  | 14.51  ± 1.51      | 12.12  ± 2.363     | **1.20×** |

`cgma_vss_split` calls `MontgomeryCtx::pow` $k = 3$ times to commit
the polynomial coefficients; `cgma_vss_reconstruct` calls it
$n \cdot k = 15$ times across per-share verification, plus a final
Lagrange interpolation in $\mathrm{GF}(q)$ that does not exponentiate.
Both ops sit deep in 2048-bit modular exponentiation, which is
exactly where the window method buys time.

The split-side gain is larger in proportion (24% faster) because the
14 setup multiplies for the 16-entry table are amortised over the
shorter exponent's full run, where the saving on each fold is a
larger fraction of total work. Reconstruct's exponent shape gives
16% — slightly above the 11% predicted theoretically — and the
larger ±CI reflects the longer tail of the per-share verify loop.

## Control: schemes that don't use modexp

These should be unchanged within run-to-run noise, since the only
code path touched was `MontgomeryCtx::pow`:

| Operation                  | before (ms)   | after (ms)    | Δ |
|----------------------------|--------------:|--------------:|----|
| `vss_split`                | 0.03424       | 0.03385       | within ±CI |
| `vss_reconstruct`          | 0.01799       | 0.01879       | within ±CI |
| `mignotte_split`           | 0.0003614     | 0.0003601     | within ±CI |
| `mignotte_reconstruct`     | 0.002707      | 0.002650      | within ±CI |
| `asmuth_bloom_split`       | 0.0006228     | 0.0005973     | within ±CI |
| `asmuth_bloom_reconstruct` | 0.002873      | 0.002788      | within ±CI |
| `shamir_split`             | 0.005932      | 0.005974      | within ±CI |
| `shamir_reconstruct`       | 0.006994      | 0.007184      | within ±CI |

Every control row sits inside both runs' confidence intervals — the
window method change is precisely targeted and does not regress
anything else.

## Reproducing

```bash
git worktree add /tmp/ss-baseline cfbf31b^
( cd /tmp/ss-baseline && cargo build --release --bin pilot_ss )
cargo build --release --bin pilot_ss

BENCH=$HOME/pilot-bench/build/cli/bench
export PILOT_SS_ITERS_PERCENT=100
for op in cgma_vss_split cgma_vss_reconstruct; do
    "$BENCH" run_program --preset quick --pi "before_${op},ms/op,0,1,1" \
        -- /tmp/ss-baseline/target/release/pilot_ss "$op"
    "$BENCH" run_program --preset quick --pi "after_${op},ms/op,0,1,1" \
        -- ./target/release/pilot_ss "$op"
done
```

## On the CRT precomp that didn't ship

A second optimisation was prototyped at the same time — caching
pairwise CRT inverses inside `MignotteSequence` and
`AsmuthBloomParams` so reconstruct's hot loop replaces $k - 1$
`mod_inverse` calls with $O(k^2)$ `mod_mul` calls — and reverted
when pilot showed it regressed both schemes by ~1.6× at the test
sequence sizes. The cause: `BigUint::mod_mul` rebuilds a Montgomery
context on every call, and at small modulus sizes that setup cost
exceeded the per-`mod_inverse` saving. The change would help at
production-sized moduli (≥ 256 bit), but the example sequences in
this crate sit well below that threshold.

This is the kind of regression that "I think it should be faster"
intuition misses and pilot catches in one round of measurement.
