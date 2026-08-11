# PERFORMANCE — `secret-sharing`

The authoritative measurement layer is
[`pilot-bench`](https://github.com/darrelllong/pilot-bench): each
operation is driven repeatedly until a 95 % confidence interval of
≤ 20 % of the mean is reached. Numbers below report **mean ms/op**,
**±CI (95 %)** half-width, and the number of pilot rounds the
framework decided were needed to reach that interval. Lower is
better throughout.

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

The tables below mirror
[`benchmarks/pilot_ss_latest.md`](benchmarks/pilot_ss_latest.md).
Conditions: Apple M4 (arm64, host Hardy), macOS, release build,
`normal` preset (95 % CI ≤ 10 % of the mean),
`PILOT_SS_ITERS_PERCENT=25`. The same sweep on three
other hosts is summarised under [Cross-processor](#cross-processor)
below.

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `shamir_split` | 0.0029110 | ±0.0000369 | 80 |
| `shamir_reconstruct` | 0.0056850 | ±0.0000488 | 59 |
| `blakley_split` | 0.0448100 | ±0.0005800 | 50 |
| `blakley_reconstruct` | 0.0243100 | ±0.0003657 | 50 |
| `kothari_split` | 0.0028870 | ±0.0000422 | 80 |
| `kothari_reconstruct` | 0.0059680 | ±0.0000644 | 84 |
| `karchmer_wigderson_split` | 0.0031030 | ±0.0000286 | 50 |
| `karchmer_wigderson_reconstruct` | 0.0080680 | ±0.0000716 | 50 |
| `brickell_split` | 0.0030950 | ±0.0000408 | 50 |
| `brickell_reconstruct` | 0.0081480 | ±0.0000603 | 80 |
| `massey_split` | 0.0024140 | ±0.0000216 | 170 |
| `massey_reconstruct` | 0.0039580 | ±0.0000531 | 50 |

`shamir`, `kothari`, `brickell`, `massey` cluster together (2.4–3.1 µs
split, 4–8 µs recover): Lagrange-style reconstruction over a single
Mersenne-127 field element, each algebraic surface paying a constant
overhead on top. `blakley` is the outlier on recovery (~24 µs) because
it solves a $k \times k$ linear system end-to-end where Lagrange just
evaluates one denominator-product per share; with the Mersenne
multiply no longer dominating, blakley's remaining cost is the
`mod_inverse` calls inside the augmented-matrix pivot. The
[standardised-prime fast paths](#standardised-prime-fast-paths) and
the [arithmetic pass](#arithmetic-pass-division--add--lagrange--karatsuba)
below are what produced these numbers relative to the original
Montgomery-only path.

![Threshold throughput radar](assets/threshold-throughput-radar.svg)

*Throughput rosette: split (teal) vs reconstruct (red) ops/s across the
threshold family.*

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `ramp_split` | 0.0264200 | ±0.0002044 | 118 |
| `ramp_reconstruct` | 0.0182900 | ±0.0001985 | 50 |
| `yamamoto_split` | 0.0265600 | ±0.0002471 | 53 |
| `yamamoto_reconstruct` | 0.0179800 | ±0.0001459 | 50 |
| `blakley_meadows_split` | 0.0447100 | ±0.0002875 | 50 |
| `blakley_meadows_reconstruct` | 0.0287500 | ±0.0005305 | 52 |
| `kgh_split` | 0.0149400 | ±0.0001310 | 50 |
| `kgh_reconstruct` | 0.0174900 | ±0.0001764 | 50 |

The ramp / vector schemes pay roughly $L\times$ the threshold-scheme
cost on split, since each polynomial / matrix lives over a length-$L$
secret. `blakley_meadows` is heaviest at split because the
hyperplane-bank rejection-sampling guard re-rolls the random matrix
on rare singular events.

![Ramp / vector throughput radar](assets/ramp-throughput-radar.svg)

*Throughput rosette: split (teal) vs reconstruct (red) ops/s across the
ramp / vector family.*

### Verifiable secret sharing

Two schemes only — `vss` (Rabin–Ben-Or, information-theoretic) and
`cgma_vss` (Chor-GMA, computational). A radar with two axes
degenerates to a line, so the table is the honest format:

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `vss_split` | 0.0173300 | ±0.0001374 | 50 |
| `vss_reconstruct` | 0.0128200 | ±0.0000839 | 80 |
| `cgma_vss_split` | 0.8339000 | ±0.0029180 | 50 |
| `cgma_vss_reconstruct` | 7.1950000 | ±0.0269300 | 110 |

`vss::deal` builds a full bivariate $k \times k$ polynomial matrix, so
splits cost ~6× a single Shamir secret; reconstruction is dominated
by the $n^2$ pairwise consistency check.

`cgma_vss` runs against the **RFC 5114 §2.3 group** (2048-bit $p$,
256-bit prime-order subgroup $q$) — the canonical Schnorr-style group
from the IETF standard, ~112-bit symmetric-equivalent security per
NIST SP 800-57. Its cost is 2048-bit modular exponentiation: `deal`
performs $k = 3$ group exponentiations to commit, `reconstruct`
performs $n \cdot k = 15$ across the per-share `verify` calls plus the
final Lagrange interpolation in $\mathrm{GF}(q)$. The exponentiator is
a 4-bit fixed-window scan (`MontgomeryCtx::pow`; see the
"Window-Method Modular Exponentiation" section of
[`THEORY.md`](THEORY.md) for the algebra), which replaced bit-by-bit
square-and-multiply. This is the noisiest row in the suite — the wide
±CI reflects run-to-run modexp variance, not measurement error.
Constructor [`rfc5114_modp_2048_256`](src/cgma_vss.rs) returns the
validated group; for the scaling curve across group sizes (toy → 167
→ 1024 OAKLEY → 2048 RFC 5114) see `assets/cgma-vss-scaling.svg`.

### CRT schemes (small example sequences)

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `mignotte_split` | 0.0002456 | ±0.0000043 | 57 |
| `mignotte_reconstruct` | 0.0010240 | ±0.0000110 | 54 |
| `mignotte_reconstruct_large` | 0.0012910 | ±0.0000193 | 50 |
| `asmuth_bloom_split` | 0.0003328 | ±0.0000056 | 52 |
| `asmuth_bloom_reconstruct` | 0.0011130 | ±0.0000180 | 80 |

These run on the bundled small (≈12-bit $\beta$) sequences — the
schemes where the secret-size model is the legal-range gap
$(\alpha, \beta)$ rather than a field bit-width.
`mignotte_reconstruct_large` uses three ~131-bit moduli. For a
scaling curve at larger $\beta$ see `assets/mignotte-scaling.svg` and
`assets/asmuth-bloom-scaling.svg`.

### Other / convenience schemes

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `trivial_split` | 0.0005176 | ±0.0000054 | 56 |
| `trivial_reconstruct` | 0.0001362 | ±0.0000020 | 80 |
| `ito_split` | 0.0019120 | ±0.0000140 | 140 |
| `ito_reconstruct` | 0.0006803 | ±0.0000068 | 50 |
| `benaloh_leichter_split` | 0.0010800 | ±0.0000073 | 82 |
| `benaloh_leichter_reconstruct` | 0.0004443 | ±0.0000059 | 50 |
| `proactive_refresh` | 0.0150500 | ±0.0001228 | 80 |
| `proactive_recover` | 0.0059380 | ±0.0000386 | 85 |
| `bytes_split_16` | 0.0062400 | ±0.0000878 | 110 |
| `bytes_reconstruct_16` | 0.0116100 | ±0.0000758 | 110 |
| `ida_split_16` | 0.0029130 | ±0.0000228 | 80 |
| `ida_reconstruct_16` | 0.0070770 | ±0.0000413 | 50 |
| `decode_reconstruct_t1` | 0.0646200 | ±0.0007770 | 170 |

`trivial` and `benaloh_leichter` are the cheapest schemes in the crate
— well under 2 µs at this parameterisation. `decode_reconstruct_t1`
(Berlekamp–Welch errors-and-erasures with one tampered share at
$n = 11$) is the heaviest because the homogeneous-system solve runs
even when no tampering is present.

![Other-schemes throughput radar](assets/other-throughput-radar.svg)

*Throughput rosette: split (teal) vs reconstruct (red) ops/s across the
other / convenience family.*

### Visual cryptography (n=3, 8×8 image)

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `visual_split_3_8` | 0.0074110 | ±0.0001136 | 50 |
| `visual_decode_3_8` | 0.0009763 | ±0.0000101 | 140 |

Visual cryptography is image-domain. The single-image numbers above
are at a fixed configuration; for scaling with `n` and image area see
`assets/visual-by-n.svg` and `assets/visual-by-pixels.svg`.

### 4 KiB block (k=3, n=5, GF(2^127 − 1))

The threshold tables above measure a single Mersenne-127 element
(~16 bytes). Real callers wrap a longer secret. The `*_4kb` ops chunk
4096 bytes into 274 × 15-byte field elements and call the per-element
`split` / `reconstruct` over each chunk inside the timed region; one
`ms/op` value is therefore the latency of one full 4 KiB secret.

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `shamir_split_4kb` | 0.7136000 | ±0.0044740 | 117 |
| `shamir_reconstruct_4kb` | 1.3500000 | ±0.0110600 | 50 |
| `blakley_split_4kb` | 12.0000000 | ±0.1344000 | 50 |
| `blakley_reconstruct_4kb` | 6.3060000 | ±0.0835500 | 80 |
| `kothari_split_4kb` | 0.7033000 | ±0.0082550 | 140 |
| `kothari_reconstruct_4kb` | 1.3980000 | ±0.0115700 | 110 |
| `karchmer_wigderson_split_4kb` | 0.7608000 | ±0.0061900 | 80 |
| `karchmer_wigderson_reconstruct_4kb` | 2.0160000 | ±0.0212950 | 200 |
| `brickell_split_4kb` | 0.7997000 | ±0.0178950 | 110 |
| `brickell_reconstruct_4kb` | 2.0950000 | ±0.0225900 | 50 |
| `massey_split_4kb` | 0.6466000 | ±0.0122000 | 50 |
| `massey_reconstruct_4kb` | 0.9114000 | ±0.0100800 | 50 |

Per-block costs scale linearly with the chunk count (4 KiB / 15 B ≈
274 chunks): each entry lands within run-to-run variance of 274 × the
single-element number from the threshold table. There is no shared
per-secret amortisation — the polynomial / matrix bank is
re-randomised per chunk because each chunk is an independent secret.

End-to-end (split + reconstruct, per 4 KiB secret). Writing $t$ for the
total time in ms, its CI propagates from the per-op CIs by Pythagorean
addition assuming independence,
$\sigma_t = \sqrt{\sigma_\text{split}^2 + \sigma_\text{recon}^2}$, and
throughput is $4000 / t$ KiB/s with delta-method CI
$(\text{throughput} / t) \cdot \sigma_t$:

| Scheme | total ms (±CI 95%) | throughput KiB/s (±CI 95%) |
|--------|-------------------:|---------------------------:|
| `massey` | 1.56 ± 0.016 | 2567 ± 26 |
| `shamir` | 2.06 ± 0.012 | 1938 ± 11 |
| `kothari` | 2.10 ± 0.014 | 1904 ± 13 |
| `karchmer_wigderson` | 2.78 ± 0.022 | 1441 ± 12 |
| `brickell` | 2.89 ± 0.029 | 1382 ± 14 |
| `blakley` | 18.31 ± 0.158 | 219 ± 2 |

The Lagrange-style schemes (`massey`, `kothari`, `shamir`) sit in a
tight 1.6–2.1 ms band; `brickell` and `karchmer_wigderson` form a
second tier at ~2.8–2.9 ms because both pay a recovery-vector solve on
top of the simpler inner product. `massey` keeps the lead — its
`CodeScheme` runs a single linear combination over a fixed generator
matrix on both split and reconstruct. `blakley` remains the outlier
for the reason given in the threshold section (its $k \times k$
Gaussian elimination plus the singularity-guarded random hyperplane
sample). It is also the only scheme whose reconstruct is faster than
its split — split must sample fresh hyperplane coefficients and reject
singular configurations on top of the same linear work reconstruct
does once. Every other scheme is split-faster.

The rosette below visualises this same 4 KiB-block data on a six-axis
rosette (split teal, reconstruct red); `blakley` is the one scheme
whose reconstruct polygon sits outside its split.

![4 KiB block radar](assets/four-kb-throughput-radar.svg)

### Threshold (k, n) sweep — Shamir

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `shamir_split_2_3` | 0.0012700 | ±0.0000115 | 80 |
| `shamir_reconstruct_2_3` | 0.0032070 | ±0.0000335 | 80 |
| `shamir_split_3_5` | 0.0030510 | ±0.0000657 | 50 |
| `shamir_reconstruct_3_5` | 0.0059850 | ±0.0001081 | 54 |
| `shamir_split_5_9` | 0.0076400 | ±0.0001253 | 57 |
| `shamir_reconstruct_5_9` | 0.0128200 | ±0.0002163 | 80 |
| `shamir_split_7_15` | 0.0153900 | ±0.0001737 | 111 |
| `shamir_reconstruct_7_15` | 0.0244400 | ±0.0004892 | 170 |
| `shamir_split_10_20` | 0.0403500 | ±0.0006800 | 292 |
| `shamir_reconstruct_10_20` | 0.0445500 | ±0.0003237 | 145 |

Split scales approximately linearly in $n$ (one Horner evaluation per
share); reconstruct scales approximately quadratically in $k$
(Lagrange denominators are products over $k - 1$ pairs each).
Empirically split_10_20 / split_2_3 ≈ 31.8×, which sits right on the
$O(n \cdot k)$ work model — $(20 \cdot 10)/(3 \cdot 2) = 33×$ — now
that the arithmetic layer no longer buries the tiny configuration
under per-call overhead. Reconstruct's 13.9× across $k$ growing 2 → 10
(5×) is consistent with $O(k^2)$ scaling plus a per-call linear term.

### Cold-cache first-iteration latency

One operation per fresh process — the first call before caches and
allocator fast-paths are warm.

| Operation | ms/op | ±CI (95%) | Runs |
|---|---:|---:|---:|
| `shamir_cold_split` | 0.0060090 | ±0.0000766 | 80 |
| `shamir_cold_reconstruct` | 0.0135400 | ±0.0002193 | 50 |
| `blakley_cold_split` | 0.0834700 | ±0.0013215 | 113 |
| `blakley_cold_reconstruct` | 0.0325900 | ±0.0005085 | 50 |
| `massey_cold_split` | 0.0056260 | ±0.0000860 | 88 |
| `massey_cold_reconstruct` | 0.0093010 | ±0.0001036 | 112 |

Cold/warm ratios against the matching warm rows from the threshold
table:

| Scheme | warm split | cold split | ratio | warm recon | cold recon | ratio |
|---------|-----------:|-----------:|------:|-----------:|-----------:|------:|
| shamir  |   0.002911 |   0.006009 | 2.06× |  0.005685 |  0.013540 | 2.38× |
| blakley |   0.044810 |   0.083470 | 1.86× |  0.024310 |  0.032590 | 1.34× |
| massey  |   0.002414 |   0.005626 | 2.33× |  0.003958 |  0.009301 | 2.35× |

The 2.1–2.4× cold/warm ratio on the Lagrange-style schemes (shamir,
massey) reflects BigUint heap allocation dominating first-call cost:
the Mersenne-127 fast path allocates one `BigUint` per multiply, and
on a cold L1/L2 the allocator's size-class fast paths haven't been
touched. Blakley's 1.3–1.9× is consistent with its
Gaussian-elimination work being allocation-light per chunk — the
linear systems live in `Vec`s reused across solve steps. Reconstruct
ratios run higher than split because the Lagrange denominators
allocate more transient BigUints than split's polynomial evaluation.

## Cross-processor

The same `quick`-preset sweep on four machines spanning three
architectures — Apple M1, Apple M4, and x86_64. (The canonical tables
above use the tighter `normal` preset; this comparison keeps all four
hosts on `quick` so the columns are like for like.) Per-host captures:
[`pilot_ss_hardy_quick.md`](benchmarks/pilot_ss_hardy_quick.md)
(Apple M4, Hardy),
[`pilot_ss_wigner.md`](benchmarks/pilot_ss_wigner.md) (Apple M1 Max,
wigner), [`pilot_ss_dyson.md`](benchmarks/pilot_ss_dyson.md) (Apple
M4 Pro, dyson), and
[`pilot_ss_twilight.md`](benchmarks/pilot_ss_twilight.md) (AMD
EPYC 7452, x86_64, twilight.soe.ucsc.edu). A representative slice
(ms/op):

| Operation | M1 Max (wigner) | M4 (Hardy) | M4 Pro (dyson) | EPYC x86 (twilight) |
|---|---:|---:|---:|---:|
| `shamir_split` | 0.003919 | 0.002952 | 0.003364 | 0.00459 |
| `shamir_reconstruct` | 0.007982 | 0.005876 | 0.006172 | 0.009721 |
| `mignotte_reconstruct` | 0.001346 | 0.001155 | 0.001125 | 0.001935 |
| `vss_reconstruct` | 0.01721 | 0.01422 | 0.01434 | 0.02041 |
| `cgma_vss_reconstruct` | 10.79 | 8.292 | 8.048 | 14.68 |
| `decode_reconstruct_t1` | 0.08609 | 0.07265 | 0.06966 | 0.1087 |

The Apple parts order by generation: the M4 (Hardy) and M4 Pro
(dyson) track within run-to-run noise of each other (0.96–1.14×
across the slice — single-thread work, where the Pro's extra cores
buy nothing), and the M1 Max is ~1.2–1.4× behind the M4 across the
field-arithmetic schemes (1.30× on the 2048-bit `cgma_vss` modexp).
The EPYC is ~1.4–1.7× behind on field arithmetic and 1.8× on
`cgma_vss`, consistent with its lower single-thread clock. Relative
scheme ordering is identical across all four.

## Optimization history

### The rust-mp migration (2026-08-11)

The in-tree bigint/primes fork was replaced by the
[rump](https://github.com/darrelllong/rump) crate (crates.io
`rust-mp` 0.1.1), which carries Knuth Algorithm D division,
word-level Montgomery multiplication, and CRT/number-theory routines
this fork predated. Measured on the canonical host against the last
in-tree sweep: `mignotte_reconstruct_large` (three ~131-bit CRT
moduli, division-bound) **11.5×**; the `blakley` family (Gaussian
elimination over generic field elements) **2.3–2.9×**; `cgma_vss`
(2048-bit modexp) **1.8×**; median across all 72 operations 1.1×,
the Mersenne-127 fast paths being deliberately untouched. One
regression was caught and fixed during the sweep itself: routing
`mod_inverse` through the general Bézout routine doubled its signed
bookkeeping and cost cold Lagrange reconstruction up to 1.6× —
rust-mp 0.1.1 restores the lean single-coefficient loop.

### Standardised-prime fast paths

`PrimeField::mul` recognises a catalogue of standardised primes at
construction time and routes each through the cheapest correct
multiplier for its modulus structure. The catalogue covers ten
RFC- or FIPS-blessed primes; one BigUint comparison per
`PrimeField::new*` call selects the dispatch.

| Prime | Form | Standard |
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

A single parametric reducer handles all ten. Each prime is described
by $\delta = 2^k - p$ decomposed into signed terms $(e_i, s_i)$ such
that $\delta = \sum_i s_i \cdot 2^{e_i}$; the multiplier:

1. Pre-reduces each operand to $\le k$ bits (slow path, unreached when
   callers feed reduced values).
2. Computes $\text{prod} = a \cdot b$ via `BigUint::mul_ref`
   (schoolbook; Karatsuba only above 128 limbs, far larger than any
   catalogue prime — see the [arithmetic
   pass](#arithmetic-pass-division--add--lagrange--karatsuba)).
3. Iteratively folds $t' = \text{low} + \text{high} \cdot \delta$,
   accumulated as positive and negative `BigUint` running sums.
   Construction-time validation requires $\delta > 0$, which keeps the
   running sum non-negative across every fold so the signed BigInt
   path is never reached for the registered primes.
4. Hard-asserts a 32-fold cap (panic on overrun, never silent partial
   reduction). NIST P-256 is the worst case at ~8 folds; everything
   else converges in 1–3.

`mersenne127` keeps a separate hand-rolled `u128` fast path: its
operands fit in two `u64`s, so a 2 × 2 schoolbook plus a Mersenne fold
stays entirely in registers — measurably faster than the parametric
reducer.

**Per-prime speedup vs generic Montgomery** (release build, Apple
silicon, 50 warmup + 200 measured iterations, median latency, from
`examples/bench_field_mul.rs`):

| Prime | bits | fast path | generic | speedup |
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

Routing the Lagrange-family schemes onto the `mersenne127` fast path
(its 6.5× over Montgomery above) is what lifted `shamir`, `kothari`,
`brickell`, and `massey` ~4–6× over the original Montgomery-only path.

`nist_p256` is recognised but routes to Montgomery in production via a
`prefer_fast: false` flag. Its 4-term mixed-sign polynomial (largest
term offset 224, $k = 256$) needs ~8 fold iterations, each doing 4
BigUint shifts and adds — more work than Montgomery's 4
mont-muls on 4 limbs. The 1.01× row is Montgomery-vs-Montgomery
(noise — both columns time the same code); the entry stays in the
catalogue so the parametric reducer's correctness is still validated
for it under the per-prime fuzz harness.

**Correctness coverage.** Every catalogue prime has a per-prime fuzz
test (`field::tests::fuzz_<name>`) running 16 384 random multiplies
through the fast path and the generic Montgomery path and asserting
exact equality. Edge cases ($0$, $1$, $p - 1$, $p$, $p + 1$,
$2^{k-1}$), unreduced inputs, and the $(p - 1)^2$ worst-case
convergence path are exercised independently. Construction-time
validation rejects malformed table entries (zero coefficient,
offset ≥ k, δ ≤ 0, δ ≠ 2^k − p), with negative unit tests pinning each
contract.

**Side-channel scope.** The parametric reducer's iteration count and
per-fold limb work are operand-dependent. This path makes no
constant-time claim, and the underlying `BigUint` is itself not
constant-time (see the module note in `src/bigint.rs`). The crate's
stated threat model is residue scrubbing on `Drop`, not
timing-channel resistance against a co-located attacker.

**Out of scope.** Brainpool primes (RFC 5639) lack Solinas structure
and stay on the Montgomery path. Adding a new pseudo-Mersenne / Solinas
prime is one catalogue entry plus a constructor; the fuzz harness
picks it up automatically.

### Arithmetic pass: division / add / Lagrange / Karatsuba

A localised, zero-dependency pass over the bignum core, mirrored on
the C++ side (the `compat.*` vector tests pin byte-for-byte Rust↔C++
agreement):

1. **Short division for one-limb divisors** (`src/bigint.rs`,
   `cpp/src/bigint.cpp`). `div_rem` handles a single-limb divisor with
   grade-school short division — an $O(\text{limbs})$ scan with a
   `u128` carry — instead of the $O(\text{bits})$ bit-by-bit loop.
   The extended-gcd tail in `mod_inverse` and the CRT schemes
   (`mignotte`, `asmuth_bloom`) spend most of their divisions there.
   Multi-limb divisors keep the bit-by-bit loop.
2. **Field add / reduce fast paths** (`src/field.rs`, C++ mirror).
   `add` does one conditional subtract when the sum is below $2p$
   (always true for reduced inputs) instead of a division-based
   `modulo`; `reduce` clones when the value is already $< p$. Every
   Horner step and Lagrange accumulation hits both.
3. **Batch inversion in Lagrange** (`src/poly.rs`, C++ mirror). The
   $k$ denominator inverses come from Montgomery's batch trick: one
   extended-gcd inversion of the full denominator product, then two
   multiplies per point to peel off the individual inverses. Inversion
   dominates reconstruction cost, so this replaces the $k$ most
   expensive operations in the evaluator with one.
4. **Karatsuba threshold 32 → 128 limbs.** Re-measured on Apple M4
   and AMD EPYC 7452 (median over 300 multiplies per size): this
   implementation's Karatsuba — `Vec` temporaries plus recursive
   splits — ties or loses to schoolbook through ~96 limbs and only
   pulls ahead from 128 (~16–31% at 256). The old 32 was a
   pessimisation. Nothing in the crate's own workloads exceeds 17
   limbs, so only CRT-style products of many moduli and external
   callers reach the new threshold.

**Controlled before/after** — same host, same session, back to back:
build `pilot_ss` on pristine `main`, measure; apply the pass, rebuild,
measure. Apple M4 (Hardy), pilot-bench `normal` preset (95% CI ≤ 10%
of mean, ≥ 50 samples), `PILOT_SS_ITERS_PERCENT=25`. ms/op:

| Operation | before | after | Δ |
|---|---:|---:|---:|
| `shamir_split` | 0.0029110 | ±0.0000369 | 80 |
| `asmuth_bloom_reconstruct` | 0.0011130 | ±0.0000180 | 80 |
| `mignotte_reconstruct` | 0.0010240 | ±0.0000110 | 54 |
| `vss_reconstruct` | 0.0128200 | ±0.0000839 | 80 |
| `shamir_reconstruct` | 0.0056850 | ±0.0000488 | 59 |
| `decode_reconstruct_t1` | 0.0646200 | ±0.0007770 | 170 |
| `ramp_reconstruct` | 0.0182900 | ±0.0001985 | 50 |
| `mignotte_reconstruct_large` | 0.0012910 | ±0.0000193 | 50 |

`mignotte_reconstruct_large` moves least: its three ~131-bit moduli
make the CRT product ~7 limbs, so the single-limb division fast path
rarely fires and the win is only the cheaper add. `cgma_vss` is flat —
its cost is 2048-bit modexp in the verify step, which runs the
Montgomery workspace path the pass never touches.

**Deliberately left out.** Knuth multi-limb division for the `div_rem`
fallback (the single-limb path plus fast Euclid shrinkage captures
most of the practical win); workspace pooling through
`MontgomeryCtx::mul`/`pow` (the next step for the modexp-bound
`cgma_vss`); Solinas-specialised add/sub (the conditional-subtract
`add` already covers the dominant path).

## Scaling charts

For schemes whose secret-size model differs structurally from a fixed
bit-width (CRT moduli, visual pixel expansion, Schnorr group size) the
`examples/bench` driver emits scaling charts:

- [Mignotte: latency vs legal-range bit width](assets/mignotte-scaling.svg)
- [Asmuth-Bloom: latency vs m₀ bit width](assets/asmuth-bloom-scaling.svg)
- [Visual cryptography by n](assets/visual-by-n.svg)
- [Visual cryptography by image area](assets/visual-by-pixels.svg)
- [CGMA-VSS by Schnorr group bit width](assets/cgma-vss-scaling.svg)
- [Cold-cache vs warm median (split)](assets/cold-cache-split.svg)
- [Cold-cache vs warm median (reconstruct)](assets/cold-cache-reconstruct.svg)

The `cold-cache-*.svg` charts are visual aids; the cold-cache table
above carries the authoritative pilot-bench numbers.

## Methodology notes

- **Pilot-bench** drives `pilot_ss` with a configurable preset; the
  framework chooses the round count from the requested CI width and
  the observed sample-to-sample autocorrelation. The fork lives at
  `~/pilot-bench` (CMake build, headless `bench` binary). Its
  "Reading CI" is the full two-sided interval width;
  `scripts/bench_pilot.sh` reports half of it as the ± column.
- **Radar & scaling charts.** The per-family throughput rosettes (shown
  inline above) and the scaling charts in `assets/` come from
  `examples/bench.rs`, a coarse in-process timer
  (`std::time::Instant`, median of measured iterations) — not
  pilot-bench. They were generated on Hardy (Apple M4), the same host
  as the canonical pilot-bench tables. Split throughput is the teal
  polygon, reconstruct the red. They convey at-a-glance shape; the
  pilot-bench tables are authoritative.
- **Controlled before/after.** Comparisons that claim a speedup from a
  specific change (e.g. the arithmetic pass above) are run on one host
  in one session — build baseline, measure; apply change, rebuild,
  measure — so machine load and thermal state are shared between the
  two columns.
- **Inner-loop scaling.** `pilot_ss` honours `PILOT_SS_ITERS_PERCENT`
  to multiply each operation's per-round iteration count. The default
  25 % keeps rounds short enough that `quick` converges quickly; raise
  it for more stable per-round timings under `normal` / `strict`.
- **Seeds.** `pilot_ss` seeds `ChaCha20Rng` from `OsRng` once per
  process; pilot-bench launches a new process per round, so
  seed-derived state does not persist across measurements.
