# perf-fork — performance pass (no external deps)

Branch: `perf-fork`. All changes preserve the "paper-faithful +
zero-dep + strong secret hygiene" character of the crate and are
mirrored on the C++ side, which keeps bit-for-bit compatibility (the
`compat.*` vector tests pin this).

## What changed

1. **Short division for one-limb divisors** (`src/bigint.rs`,
   `cpp/src/bigint.cpp`). `div_rem` now handles a single-limb divisor
   with grade-school short division — a $O(\text{limbs})$ scan with a
   `u128` carry — instead of the $O(\text{bits})$ bit-by-bit loop. The
   extended-gcd tail in `mod_inverse` and the CRT schemes (mignotte,
   asmuth_bloom) spend most of their divisions there once the working
   values shrink, so this is the change that moves the CRT family most.
   Multi-limb divisors keep the bit-by-bit loop.

2. **Field add/reduce fast paths** (`src/field.rs`,
   `cpp/src/field.cpp`, `cpp/include/secret_sharing/field.hpp`).
   `add` does one conditional subtract when the sum is below $2p$
   (always true for reduced inputs) instead of a division-based
   `modulo`; `reduce` returns a clone when the value is already
   $< p$. Every Horner step and Lagrange accumulation hits both.

3. **Batch inversion in Lagrange evaluation** (`src/poly.rs`,
   `cpp/src/poly.cpp`). The $k$ denominator inverses now come from
   Montgomery's batch trick: one extended-gcd inversion of the full
   denominator product, then two multiplies per point to peel off the
   individual inverses. Inversion dominates reconstruction cost, so
   this replaces the $k$ most expensive operations in the evaluator
   with one.

4. **Karatsuba threshold corrected 32 → 128 limbs** (both sides).
   Measured on the benchmark hardware (median over 300 multiplies per
   size), this implementation's Karatsuba — with its `Vec` temporaries
   and recursive splits — loses to schoolbook at every size up to
   ~96 limbs and only pulls ahead from 128 limbs (~25% faster at 256).
   The old threshold of 32 was a ~2× pessimization for 32–64-limb
   products; nothing in the crate's own workloads is large enough to
   reach the new threshold except CRT modulus products and external
   callers.

## Claims from the first iteration of this fork that did not survive

- *"Lower the Karatsuba threshold to 8 so mersenne521 uses Karatsuba."*
  Measured: threshold 8 made an 8-limb multiply ~10× slower (459 ns vs
  42 ns schoolbook) and a 32-limb multiply ~11× slower. The apparent
  bench wins in that iteration came entirely from the div/add changes
  it was bundled with. The threshold went the other way; see item 4.
- *"Precompute the Lagrange denominator inverses once so repeated
  evaluations on the same point set skip the `inv` work."* The
  precomputation was per-call — nothing was cached across calls, and
  callers (`shamir::reconstruct` etc.) call `lagrange_eval` fresh for
  each extra share — so the restructure was a perf no-op. Batch
  inversion (item 3) delivers a real per-call reduction instead.

## Measurements

Controlled before/after, **same host, same session, back to back**:
build `pilot_ss` on pristine `main` (`git stash`), measure; restore the
branch, rebuild, measure. Host: Apple M4 Pro (arm64). pilot-bench
`normal` preset (95% CI ≤ 10% of mean, ≥ 50 samples),
`PILOT_SS_ITERS_PERCENT=25`. ms/op, lower is better.

| op                          | main    | branch  | Δ        |
|-----------------------------|---------|---------|----------|
| shamir_split                | 0.00645 | 0.00312 | −52 %    |
| shamir_reconstruct          | 0.00776 | 0.00646 | −17 %    |
| mignotte_reconstruct        | 0.00285 | 0.00183 | −36 %    |
| asmuth_bloom_reconstruct    | 0.00300 | 0.00183 | −39 %    |
| vss_reconstruct             | 0.02020 | 0.01393 | −31 %    |
| ramp_reconstruct            | 0.02371 | 0.02031 | −14 %    |
| decode_reconstruct_t1       | 0.07551 | 0.06367 | −16 %    |
| mignotte_reconstruct_large  | 0.01379 | 0.01321 | −4 %     |

`mignotte_reconstruct_large` moves least: its three ~131-bit moduli
make the CRT product ~7 limbs, so the single-limb div fast path rarely
fires and the win comes only from the cheaper add. cgma_vss stays flat
(~10.4 ms): its cost is 2048-bit modexp in the verify step, which runs
the Montgomery workspace path and never touches the changed code.

Full per-host sweeps (all ~80 ops, `quick` preset) are committed
alongside this document:

- `benchmarks/pilot_ss_latest.md` — Apple M4 Pro (local)
- `benchmarks/pilot_ss_dyson.md` — Apple M-series (dyson)
- `benchmarks/pilot_ss_twilight.md` — AMD EPYC 7452, x86_64
  (twilight.soe.ucsc.edu)

The kiviat radars and scaling charts in `assets/` were regenerated on
the branch (`cargo run --release --example bench`).

All 265 Rust lib tests + 7 integration tests + 3 doc-tests and all 48
C++ tests (including the Rust-compat byte-stream vectors) pass.

## Deliberately left out

- Knuth multi-limb division for the `div_rem` fallback. The
  single-limb path plus fast Euclid shrinkage captures most of the
  practical win.
- Workspace pooling through `MontgomeryCtx::mul`/`pow` (each public
  call still allocates and re-encodes); would be the next step for the
  modexp-bound cgma case.
- Solinas-specialised add/sub for the registered primes; the
  conditional-subtract `add` already covers the dominant path.
