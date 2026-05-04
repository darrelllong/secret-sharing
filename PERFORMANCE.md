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
| `cgma_vss`            | reconstruct  | 12.04    | ±0.04553   |  48  |

`vss::deal` builds a full bivariate `k × k` polynomial matrix, so
splits cost ~5× a single Shamir secret. Reconstruction is dominated
by the `n²` pairwise consistency check.

`cgma_vss` is now benched against the **RFC 5114 §2.3 group**
(2048-bit `p`, 256-bit prime-order subgroup `q`) — the canonical
Schnorr-style group from the IETF standard, ~112-bit symmetric-
equivalent security per NIST SP 800-57. Numbers are dominated by
2048-bit modular exponentiation: `deal` performs `k = 3` group
exponentiations to commit, `reconstruct` performs `n × k = 15`
exponentiations across the per-share `verify` calls plus the
final Lagrange interpolation in `GF(q)`. Constructor
[`rfc5114_modp_2048_256`](src/cgma_vss.rs) returns the validated
group. For the scaling curve across group sizes (toy → 167 → 1024
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

### Mersenne-127 fast path

`PrimeField::mul` now branches on the modulus at construction. For
`p = 2^127 − 1` (the bundled `mersenne127()`) it dispatches to a
specialised `mersenne127_mul` that:

1. Reduces each operand to a `u128` (one `low_u128()` call; the
   slow modulo path is taken only on the rare unreduced input).
2. Forms a 254-bit product as a 2 × 2 schoolbook on `u128`
   partial multiplies — four 64×64→128 multiplies, summed with
   carry propagation into four `u64` limbs.
3. Reduces using `2^127 ≡ 1 (mod p)`: one fold of bits 127..253
   into bits 0..126, a second fold of bit 127 of the resulting
   128-bit sum, and one final conditional subtract.

No allocation, no Montgomery setup, no `BigUint::mod_mul` call.
Generic moduli still take the Montgomery path unchanged, and the
fast path is unit-tested against the generic path on edge cases
plus 256 random fuzz inputs (`field::tests::mersenne127_mul_matches_generic_on_random_fuzz`).

Speedups vs the previous Montgomery-only path (per-element ops,
`PILOT_SS_ITERS_PERCENT=100`, quick preset):

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

Lagrange-style threshold schemes hit a tight 4–5× band; the ramp,
yamamoto, kgh, vss, and proactive schemes inherit roughly the same
speedup because their internal loops resolve to the same
`PrimeField::mul`. `decode_reconstruct_t1` (Berlekamp–Welch) leads
at 6.7× because its homogeneous-system solve is mul-mod heavy
end-to-end. `blakley` is the visible exception at 1.25×–1.44×,
since with the multiplier dispatched cheaply the bottleneck shifts
to `mod_inverse` (extended Euclidean over `BigUint`) inside the
augmented-matrix pivot — the natural target for the next round of
optimisation if blakley specifically matters.

`cgma_vss` is unaffected: it uses 2048-bit modular exponentiation
in a different group, not `PrimeField::mul`. AVX-512 IFMA on x86 or
ARM SVE2 is the right next step for that scheme.

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
- **What we do not bench yet.** Multi-`(k, n)` sweeps for each
  scheme and the full cold-cache numbers (the current
  `cold-cache-*.svg` charts use the legacy `examples/bench`
  first-iteration sampler). Adding either is a matter of dispatching
  a new operation in `src/bin/pilot_ss.rs` and a new `measure …`
  line in `scripts/bench_pilot.sh`. The 4 KiB block table above
  closes a previously-open item ("byte-string secrets larger than
  16 bytes"); arbitrary secret sizes are now a one-line constant
  change in `pilot_ss::SECRET_BYTES`.
