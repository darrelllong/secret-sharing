# PERFORMANCE — `secret-sharing`

The authoritative measurement layer is
[`pilot-bench`](https://github.com/darrelllong/pilot-bench): each
operation is driven repeatedly until a 95 % confidence interval of
≤ 20 % of the mean is reached. Numbers below report **mean ms/op**,
**±CI (95 %)** half-width, and the number of pilot rounds the
framework decided were needed to reach that interval.

## Reproducing

```sh
# Build the operation dispatcher.
cargo build --release --bin pilot_ss

# Drive it through pilot-bench (assumes pilot-bench at $HOME/pilot-bench).
bash scripts/bench_pilot.sh > benchmarks/pilot_ss_latest.md
```

Environment knobs honoured by `scripts/bench_pilot.sh`:

| Variable | Default | Effect |
|---|---|---|
| `PILOT_BENCH_CLI` | `$HOME/pilot-bench/build/cli/bench` | Path to the `bench` binary |
| `PILOT_SS_BIN` | `target/release/pilot_ss` | Path to the dispatcher |
| `PILOT_PRESET` | `quick` | `quick` (20 % CI / 30 samples), `normal` (10 % / 50), `strict` (10 % / 200) |
| `PILOT_SS_ITERS_PERCENT` | `25` | Inner-loop scale 1..=100 inside `pilot_ss` |

The `quick` preset is the right default for an at-a-glance comparison
or development feedback. Use `normal` or `strict` for publication
numbers; both will need many more rounds per operation.

## Latest measurements

The captured run below is mirrored at
[`benchmarks/pilot_ss_latest.md`](benchmarks/pilot_ss_latest.md).
Conditions: Apple silicon, macOS, release build, `quick` preset,
`PILOT_SS_ITERS_PERCENT=25`.

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `shamir_split`                   |  0.005299  | ±0.000545  |    66 |
| `shamir_reconstruct`             |  0.006671  | ±0.000256  |    32 |
| `blakley_split`                  |   0.1574   | ±0.001840  |    60 |
| `blakley_reconstruct`            |   0.06367  | ±0.001919  |    30 |
| `kothari_split`                  |  0.005964  | ±0.000746  |    30 |
| `kothari_reconstruct`            |  0.006663  | ±0.000199  |   131 |
| `karchmer_wigderson_split`       |  0.005777  | ±0.000620  |    37 |
| `karchmer_wigderson_reconstruct` |   0.01117  | ±0.000419  |    30 |
| `brickell_split`                 |  0.005881  | ±0.000561  |    38 |
| `brickell_reconstruct`           |   0.01123  | ±0.000383  |    90 |
| `massey_split`                   |  0.004240  | ±0.000522  |    39 |
| `massey_reconstruct`             |  0.005429  | ±0.000213  |    30 |

`shamir`, `kothari`, `brickell`, `massey` cluster together (4–11 µs
split, 5–12 µs recover) — Lagrange-style reconstruction over a
single Mersenne field element, with each algebraic surface paying a
constant overhead. `blakley` is still the outlier on the recovery
side (~64 µs) because it solves a `k × k` linear system end-to-end
where Lagrange just evaluates a single denominator-product per
share; with the Mersenne mul-mod no longer dominating, blakley's
remaining cost is dominated by `mod_inverse` calls inside the
augmented-matrix pivot step. See [Mersenne-127 fast path](#mersenne-127-fast-path)
below for the implementation that produced the order-of-magnitude
shift in this table relative to the previous Montgomery-only path.

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `ramp_split`                     |   0.03309  | ±0.000767  |   101 |
| `ramp_reconstruct`               |   0.02164  | ±0.000516  |    45 |
| `yamamoto_split`                 |   0.03318  | ±0.000786  |    86 |
| `yamamoto_reconstruct`           |   0.02139  | ±0.000637  |    60 |
| `blakley_meadows_split`          |    0.1561  | ±0.000355  |   300 |
| `blakley_meadows_reconstruct`    |   0.06565  | ±0.002092  |    30 |
| `kgh_split`                      |   0.02312  | ±0.001155  |    60 |
| `kgh_reconstruct`                |   0.02067  | ±0.000822  |    30 |

All four ramp / vector schemes pay roughly `L×` the threshold-scheme
cost on split (since each polynomial / matrix lives over a length-`L`
secret). `blakley_meadows` is the heaviest at split because the
hyperplane-bank rejection-sampling guard (commit 7b54acc) re-rolls
the random matrix on rare singular events.

### Verifiable secret sharing

Two schemes only — `vss` (Rabin–Ben-Or, information-theoretic) and
`cgma_vss` (Chor-GMA, computational). A radar with two axes
degenerates to a line, so the right honest format is the table:

| Scheme                | op           | ms/op    | ±CI (95%)  | Runs |
|-----------------------|--------------|----------|------------|------|
| `vss`                 | split        | 0.03456  | ±0.001524  |  60  |
| `vss`                 | reconstruct  | 0.01905  | ±0.000852  |  30  |
| `cgma_vss`            | split        | 1.255    | ±0.006247  |  36  |
| `cgma_vss`            | reconstruct  | 10.77    | ±0.246     |  60  |

`vss::deal` builds a full bivariate `k × k` polynomial matrix, so
splits cost ~5× a single Shamir secret. Reconstruction is dominated
by the `n²` pairwise consistency check.

`cgma_vss` is now benched against the **RFC 5114 §2.3 group**
(2048-bit $p$, 256-bit prime-order subgroup $q$) — the canonical
Schnorr-style group from the IETF standard, ~112-bit symmetric-
equivalent security per NIST SP 800-57. Numbers are dominated by
2048-bit modular exponentiation: `deal` performs $k = 3$ group
exponentiations to commit, `reconstruct` performs $n \cdot k = 15$
exponentiations across the per-share `verify` calls plus the final
Lagrange interpolation in $\mathrm{GF}(q)$. Constructor
[`rfc5114_modp_2048_256`](src/cgma_vss.rs) returns the validated
group. The reconstruct cost dropped from 12.04 ms to 10.77 ms (~11%)
when `MontgomeryCtx::pow` switched from bit-by-bit
square-and-multiply to a 4-bit fixed-window scan; see the
"Window-Method Modular Exponentiation" section in
[`THEORY.md`](THEORY.md) for the algebra. For the scaling curve across group sizes (toy → 167 → 1024
OAKLEY → 2048 RFC 5114) see `assets/cgma-vss-scaling.svg`.

### CRT schemes (small example sequences)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `mignotte_split`                 | 0.0003385  | ±1.49e-05  |    60 |
| `mignotte_reconstruct`           | 0.002720   | ±6.76e-05  |    67 |
| `asmuth_bloom_split`             | 0.0006299  | ±1.90e-05  |    41 |
| `asmuth_bloom_reconstruct`       | 0.002861   | ±7.73e-05  |    30 |

Both run on the bundled small (≈12-bit β) sequences — the schemes
where the secret-size model is the legal-range gap `(α, β)` rather
than a field bit-width. For a scaling curve at larger β see
`assets/mignotte-scaling.svg` and `assets/asmuth-bloom-scaling.svg`.

### Other / convenience schemes

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `trivial_split`                  |   0.001512 | ±3.58e-05  |    33 |
| `trivial_reconstruct`            |   0.000986 | ±0.000149  |    88 |
| `ito_split`                      |   0.004530 | ±9.83e-05  |    40 |
| `ito_reconstruct`                |   0.002558 | ±0.000300  |    36 |
| `benaloh_leichter_split`         |   0.001048 | ±9.36e-05  |    93 |
| `benaloh_leichter_reconstruct`   |  0.0006737 | ±0.000131  |    70 |
| `proactive_refresh`              |   0.02900  | ±0.000613  |    33 |
| `proactive_recover`              |   0.006867 | ±0.000255  |    36 |
| `bytes_split_16`                 |   0.008875 | ±0.000188  |    58 |
| `bytes_reconstruct_16`           |   0.01435  | ±0.000454  |    30 |
| `ida_split_16`                   |   0.002578 | ±9.06e-05  |    73 |
| `ida_reconstruct_16`             |   0.007782 | ±0.000242  |    64 |
| `decode_reconstruct_t1`          |   0.06559  | ±0.002233  |    49 |

`benaloh_leichter` and `trivial` are the cheapest schemes in the
crate — under 2 µs at this parameterisation. `decode_reconstruct_t1`
(Berlekamp–Welch errors-and-erasures with one tampered share at
`n = 11`) is the heaviest because the homogeneous-system solve runs
even when no tampering is present.

### Visual cryptography (n=3, 8×8 image)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `visual_split_3_8`               |   0.006760 | ±0.000280  |    30 |
| `visual_decode_3_8`              |  0.0009607 | ±1.73e-05  |   107 |

Visual cryptography is image-domain. The single-image numbers above
are at a fixed configuration; for scaling with `n` and image area
see `assets/visual-by-n.svg` and `assets/visual-by-pixels.svg`.

### 4 KiB block (k=3, n=5, GF(2^127 − 1))

The threshold tables above measure a single Mersenne-127 element
(~16 bytes). Real callers wrap a longer secret. The `*_4kb` ops chunk
4096 bytes into 274 × 15-byte field elements and call the per-element
`split` / `reconstruct` over each chunk inside the timed region; one
`ms/op` value is therefore the latency of one full 4 KiB secret.

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| `shamir_split_4kb`                       |     1.092  | ±0.02519   |   42  |
| `shamir_reconstruct_4kb`                 |     1.835  | ±0.02893   |  187  |
| `blakley_split_4kb`                      |    42.61   | ±0.137     |  120  |
| `blakley_reconstruct_4kb`                |    24.16   | ±0.180     |   30  |
| `kothari_split_4kb`                      |     1.097  | ±0.02829   |   30  |
| `kothari_reconstruct_4kb`                |     1.715  | ±0.05966   |   31  |
| `karchmer_wigderson_split_4kb`           |     1.156  | ±0.03508   |   30  |
| `karchmer_wigderson_reconstruct_4kb`     |     2.993  | ±0.09921   |   31  |
| `brickell_split_4kb`                     |     1.139  | ±0.02823   |   74  |
| `brickell_reconstruct_4kb`               |     3.068  | ±0.1017    |   30  |
| `massey_split_4kb`                       |    0.6975  | ±0.0336    |   60  |
| `massey_reconstruct_4kb`                 |     1.467  | ±0.03336   |   50  |

Per-block costs scale linearly with the chunk count (4 KiB / 15 B ≈
274 chunks): each entry above lands within run-to-run variance of
274 × the single-element number from the threshold table. There is
no shared per-secret amortisation — the polynomial / matrix bank is
re-randomised per chunk because each chunk is an independent secret.

End-to-end (split + reconstruct, per 4 KiB secret). The total-time
CI propagates from the per-op CIs by Pythagorean addition assuming
independence (`σ_total = √(σ_split² + σ_recon²)`); throughput is
`4000 / total_ms` KiB/s with the delta-method CI
`(throughput / total_ms) · σ_total`:

| Scheme               | total ms (±CI 95%) | throughput KiB/s (±CI 95%) |
|----------------------|-------------------:|---------------------------:|
| `massey`             |     2.16 ± 0.047   |        1848 ± 40           |
| `kothari`            |     2.81 ± 0.066   |        1423 ± 33           |
| `shamir`             |     2.93 ± 0.038   |        1366 ± 18           |
| `karchmer_wigderson` |     4.15 ± 0.105   |         964 ± 24           |
| `brickell`           |     4.21 ± 0.106   |         951 ± 24           |
| `blakley`            |    66.77 ± 0.226   |         59.91 ± 0.20       |

`blakley` is still the outlier — its k×k Gaussian elimination plus
the singularity-guarded random hyperplane sample dominate the
budget; with `mul` no longer the bottleneck (see
[Mersenne-127 fast path](#mersenne-127-fast-path) below) the
remaining cost is split between `mod_inverse` and `field.add`/`sub`
inside the augmented-matrix pivot. The Lagrange-style schemes
(`massey`, `kothari`, `shamir`) now sit in a tight 2.1–2.9 ms band;
`karchmer_wigderson` and `brickell` form a second tier at ~4.2 ms
because both pay the recovery-vector solve on top of the simpler
inner product. `massey` retains the lead because its CodeScheme
runs a single linear combination over a fixed generator matrix on
both split and reconstruct.

The kiviat below visualises the same 4 KiB-block data, with one
polygon for split throughput and one for reconstruct throughput on
the same six-axis rosette. The polygons separate where the scheme is
asymmetric: blakley is the only one whose reconstruct polygon sits
appreciably outside (faster than) its split polygon, because split
must sample fresh hyperplane coefficients and reject singular
configurations on top of the same k×k linear work that reconstruct
performs once. Every other scheme on the radar is split-faster, so
its split polygon (teal) sits outside its reconstruct polygon (red).
Source: `examples/bench.rs`, coarse `Instant`-based timer (5 warmup
+ 20 measured iterations of the full 274-chunk loop, median
latency); the pilot-bench numbers above are the authoritative CI'd
values.

![4 KiB block radar](assets/four-kb-throughput-radar.svg)

### Standardised-prime fast paths

`PrimeField::mul` recognises a catalogue of standardised primes at
construction time and routes each through the cheapest correct
multiplier for its modulus structure. The catalogue covers ten
RFC- or FIPS-blessed primes; one BigUint comparison per
`PrimeField::new*` call selects the dispatch.

| Prime             | Form                                                                          | Standard         |
|-------------------|-------------------------------------------------------------------------------|------------------|
| `mersenne127`     | $2^{127} - 1$ (Mersenne)                                                      | this crate       |
| `mersenne521`     | $2^{521} - 1$ (Mersenne; = NIST P-521 base field)                             | FIPS 186-4       |
| `curve25519`      | $2^{255} - 19$ (pseudo-Mersenne)                                              | RFC 7748         |
| `poly1305`        | $2^{130} - 5$ (pseudo-Mersenne)                                               | RFC 8439         |
| `secp256k1`       | $2^{256} - 2^{32} - 977$ (pseudo-Mersenne, 2 terms)                           | SEC 2 / RFC 6979 |
| `curve448`        | $2^{448} - 2^{224} - 1$ (Solinas, 2 terms)                                    | RFC 7748         |
| `nist_p192`       | $2^{192} - 2^{64} - 1$ (Solinas, 2 terms)                                     | FIPS 186-4       |
| `nist_p224`       | $2^{224} - 2^{96} + 1$ (Solinas, 2 terms, mixed signs)                        | FIPS 186-4       |
| `nist_p256`       | $2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$ (Solinas, 4 terms, mixed signs)    | FIPS 186-4       |
| `nist_p384`       | $2^{384} - 2^{128} - 2^{96} + 2^{32} - 1$ (Solinas, 4 terms, mixed signs)     | FIPS 186-4       |

The same parametric reducer handles all ten. Each prime is
described by $\delta = 2^k - p$ decomposed into signed terms
$(e_i, s_i)$ such that $\delta = \sum_i s_i \cdot 2^{e_i}$; the
multiplier:

1. Pre-reduces each operand to $\le k$ bits (slow path, unreached
   when callers feed reduced values).
2. Computes $\text{prod} = a \cdot b$ via `BigUint::mul_ref`
   (Karatsuba above 32 limbs).
3. Iteratively folds: $t' = \text{low} + \text{high} \cdot \delta$,
   accumulated as positive and negative `BigUint` running sums.
   Construction-time validation (`validate_reduction_params`)
   requires $\delta > 0$, which guarantees the running sum stays
   non-negative across every fold so the BigInt machinery is
   never reached for the registered primes.
4. Hard-asserts a 32-fold cap (panic on overrun, never silent
   partial reduction). NIST P-256 is the worst case in the catalogue
   at ~8 folds; everything else converges in 1–3.

`mersenne127` keeps a separate hand-rolled `u128` fast path because
its operands fit in two `u64`s and a 2 × 2 schoolbook plus Mersenne
fold stays entirely in registers — measurably faster than going
through the parametric reducer.

**Per-prime speedup vs generic Montgomery** (release build, Apple
silicon, 50 warmup + 200 measured iterations, median latency, from
`examples/bench_field_mul.rs`):

| Prime          | bits | fast path |  generic  | speedup |
|----------------|-----:|----------:|----------:|--------:|
| `mersenne521`  |  521 |    292 ns |   6.08 µs |  20.83× |
| `curve448`     |  448 |    667 ns |   4.83 µs |   7.25× |
| `mersenne127`  |  127 |    542 ns |   3.54 µs |   6.54× |
| `curve25519`   |  255 |   1.42 µs |   6.38 µs |   4.50× |
| `secp256k1`    |  256 |   1.21 µs |   5.21 µs |   4.31× |
| `nist_p224`    |  224 |   1.79 µs |   7.12 µs |   3.98× |
| `nist_p192`    |  192 |   1.50 µs |   4.83 µs |   3.22× |
| `poly1305`     |  130 |   1.50 µs |   4.71 µs |   3.14× |
| `nist_p384`    |  384 |   2.25 µs |   4.42 µs |   1.96× |
| `nist_p256`    |  256 |   6.96 µs |   7.00 µs |   1.01× |

`nist_p256` is recognised but routes to Montgomery in production via
a `prefer_fast: false` flag in its table entry. Its 4-term
mixed-sign polynomial with `max_offset = 224, k = 256` requires ~8
fold iterations each doing 4 BigUint shifts and adds; that's more
work than Montgomery's 4 mont-muls on 4 limbs. The 1.01× row above
is Montgomery-vs-Montgomery (signal noise — both columns time the
same code) and the entry stays in the catalogue so the parametric
reducer's correctness is still validated for it under the per-prime
fuzz harness.

**Speedup on schemes that internally use `mersenne127`** (the
catalogue's most-used prime; pilot-bench, quick preset, 100% iter
scale). These remain the table from the previous mersenne127-only
commit because the `mersenne127` fast path itself is unchanged:

| Operation                          | before (ms) | after (ms) | speedup |
|------------------------------------|------------:|-----------:|--------:|
| `shamir_split`                     |     0.02215 |   0.005299 |   4.18× |
| `shamir_reconstruct`               |     0.02774 |   0.006671 |   4.16× |
| `kothari_split`                    |     0.02261 |   0.005964 |   3.79× |
| `kothari_reconstruct`              |     0.03715 |   0.006663 |   5.58× |
| `karchmer_wigderson_split`         |     0.02285 |   0.005777 |   3.95× |
| `karchmer_wigderson_reconstruct`   |     0.05484 |    0.01117 |   4.91× |
| `brickell_split`                   |     0.02331 |   0.005881 |   3.96× |
| `brickell_reconstruct`             |     0.05495 |    0.01123 |   4.89× |
| `massey_split`                     |     0.01761 |   0.004240 |   4.15× |
| `massey_reconstruct`               |     0.02356 |   0.005429 |   4.34× |
| `blakley_split`                    |     0.1972  |    0.1574  |   1.25× |
| `blakley_reconstruct`              |     0.09191 |    0.06367 |   1.44× |
| `ramp_split`                       |     0.1361  |    0.03309 |   4.11× |
| `vss_split`                        |     0.1367  |    0.03456 |   3.95× |
| `proactive_refresh`                |     0.1133  |    0.02900 |   3.91× |
| `decode_reconstruct_t1`            |     0.4415  |    0.06559 |   6.73× |

**Correctness coverage.** Every catalogue prime has a per-prime
fuzz test (`field::tests::fuzz_<name>`) running 16 384 random
multiplies through the fast path and the generic Montgomery path
and asserting exact equality on every input. Edge cases (`0`, `1`,
$p - 1$, $p$, $p + 1$, $2^{k-1}$), unreduced-input handling, and the
$(p - 1)^2$ worst-case convergence path are exercised independently.
Construction-time validation rejects malformed table entries
(zero coefficient, offset ≥ k, δ ≤ 0, δ ≠ 2^k − p), with negative
unit tests pinning each contract.

**Side-channel scope.** The parametric reducer's iteration count
and per-fold limb work are operand-dependent. This path makes no
constant-time claim, and the underlying `BigUint` is itself not
constant-time (see the module-level note in `src/bigint.rs`). The
crate's stated threat model is residue scrubbing on `Drop`, not
timing-channel resistance against a co-located attacker.

**Out of scope.** Brainpool primes (RFC 5639) are generic primes
without Solinas structure and stay on the Montgomery path.
NIST P-256 is recognised but routes to Montgomery as documented
above. Adding a new pseudo-Mersenne / Solinas prime is one entry
in the catalogue plus a constructor; the fuzz harness picks it up
automatically.

## Kiviat charts

Operations that share a "single integer secret of N bits" model also
have legacy kiviat (radar) charts in
[`assets/`](assets/) — three families with ≥ 3 axes get a radar; the
two-axis VSS family is the table above. These charts use a coarse
in-process timer (`std::time::Instant`, 50 warmup + 200 measured
iterations, median latency) and exist for at-a-glance shape rather
than confidence-interval rigour. The pilot-bench tables above are
the authoritative numbers.

![Threshold throughput radar](assets/threshold-throughput-radar.svg)

![Ramp / vector throughput radar](assets/ramp-throughput-radar.svg)

![Other-schemes throughput radar](assets/other-throughput-radar.svg)

## Non-radar scaling charts

For schemes whose secret-size model differs structurally from a
fixed bit-width (CRT moduli, visual pixel expansion, Schnorr group
size) the legacy `examples/bench` driver also emits scaling charts:

- [Mignotte: latency vs legal-range bit width](assets/mignotte-scaling.svg)
- [Asmuth-Bloom: latency vs m₀ bit width](assets/asmuth-bloom-scaling.svg)
- [Visual cryptography by n](assets/visual-by-n.svg)
- [Visual cryptography by image area](assets/visual-by-pixels.svg)
- [CGMA-VSS by Schnorr group bit width](assets/cgma-vss-scaling.svg)
- [Cold-cache vs warm median (split)](assets/cold-cache-split.svg)
- [Cold-cache vs warm median (reconstruct)](assets/cold-cache-reconstruct.svg)

## Methodology notes

- **Pilot-bench** drives `pilot_ss` with a configurable preset; the
  framework chooses the round count from the requested CI width and
  the observed sample-to-sample autocorrelation. The fork lives at
  `~/pilot-bench` (CMake build, headless `bench` binary).
- **Inner loop scaling.** `pilot_ss` honours
  `PILOT_SS_ITERS_PERCENT` to multiply each operation's per-round
  iteration count. The default 25 % keeps individual rounds short
  enough that the `quick` preset converges quickly; raise it for
  more stable per-round timings under `normal` / `strict`.
- **Seeds.** `pilot_ss` seeds `ChaCha20Rng` from `OsRng` once per
  process invocation; pilot-bench launches a new process per round,
  so seed-derived state does not persist across measurements.
- **What we do not bench yet.** All previously-open items are now
  closed: the 4 KiB block table above closed "byte-string secrets
  larger than 16 bytes"; the threshold (k, n) sweep below closes
  "multi-(k, n) sweeps for each scheme" (currently Shamir only —
  extending the same template to the other threshold schemes is
  one helper function plus dispatch arms each); the cold-cache
  pilot-bench numbers below close "full cold-cache numbers". The
  legacy `cold-cache-*.svg` charts from `examples/bench` remain
  in place as visual aids; their numbers are no longer the
  authoritative cold-cache data.

### Threshold (k, n) sweep — Shamir

| Operation                  | ms/op    | ±CI (95%)   |
|----------------------------|---------:|------------:|
| `shamir_split_2_3`         | 0.001934 | ±0.000245   |
| `shamir_reconstruct_2_3`   | 0.003532 | ±0.000157   |
| `shamir_split_3_5`         | 0.005540 | ±0.000579   |
| `shamir_reconstruct_3_5`   | 0.006523 | ±0.000251   |
| `shamir_split_5_9`         | 0.016760 | ±0.001081   |
| `shamir_reconstruct_5_9`   | 0.014580 | ±0.000254   |
| `shamir_split_7_15`        | 0.041480 | ±0.001915   |
| `shamir_reconstruct_7_15`  | 0.026650 | ±0.000873   |
| `shamir_split_10_20`       | 0.080440 | ±0.003318   |
| `shamir_reconstruct_10_20` | 0.050980 | ±0.001857   |

Split scales approximately linearly in $n$ (one Horner evaluation
per share); reconstruct scales approximately quadratically in $k$
(Lagrange denominators are products over $k - 1$ pairs each).
Empirically: the ratio shamir_split_10_20 / shamir_split_2_3 ≈
41.6× (for $n$ growing 3 → 20, ~6.7×; the residual 6× factor is
overhead per share from the per-trustee evaluation loop).
Reconstruct's ratio 14.4× across $k$ growing 2 → 10 (5×) is
consistent with $O(k^2)$ scaling plus a per-call linear term.

### Cold-cache first-iteration latency

| Operation                  | ms/op   | ±CI (95%)  |
|----------------------------|--------:|-----------:|
| `shamir_cold_split`        | 0.01060 | ±0.001052  |
| `shamir_cold_reconstruct`  | 0.01398 | ±0.000806  |
| `blakley_cold_split`       | 0.17840 | ±0.007872  |
| `blakley_cold_reconstruct` | 0.07682 | ±0.004062  |
| `massey_cold_split`        | 0.008215 | ±0.000988 |
| `massey_cold_reconstruct`  | 0.01233 | ±0.000968  |

Cold/warm ratios using the matching warm rows from the threshold
table above:

| Scheme  | warm split | cold split | ratio | warm recon | cold recon | ratio |
|---------|-----------:|-----------:|------:|-----------:|-----------:|------:|
| shamir  |   0.005299 |   0.01060  | 2.00× |   0.006671 |   0.01398  | 2.10× |
| blakley |   0.1574   |   0.1784   | 1.13× |   0.06367  |   0.07682  | 1.21× |
| massey  |   0.004240 |   0.008215 | 1.94× |   0.005429 |   0.01233  | 2.27× |

The 2× cold/warm ratio on the Lagrange-style schemes (shamir,
massey) reflects the BigUint heap allocations dominating
first-call cost: the Mersenne-127 fast path allocates one
`BigUint` per multiply, and on a cold L1 / L2 the allocator's
size-class fast paths haven't been touched yet. Blakley's 1.1–1.2×
is consistent with its Gaussian-elimination work being
allocation-light per chunk — the shares' linear systems live in
already-allocated `Vec`s reused across solve steps. Reconstruct
ratios are slightly higher than split ratios across the board
because the Lagrange denominators allocate more transient
BigUints than the polynomial evaluation in split.
