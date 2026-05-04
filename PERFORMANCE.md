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
| `shamir_split`                   |    0.02704 | ±0.005247  |   277 |
| `shamir_reconstruct`             |    0.03144 | ±0.001019  |    30 |
| `blakley_split`                  |     0.2273 | ±0.008214  |    36 |
| `blakley_reconstruct`            |     0.1059 | ±0.003940  |   210 |
| `kothari_split`                  |    0.02642 | ±0.000991  |    30 |
| `kothari_reconstruct`            |    0.04325 | ±0.004995  |   188 |
| `karchmer_wigderson_split`       |    0.02533 | ±0.001056  |    30 |
| `karchmer_wigderson_reconstruct` |    0.06225 | ±0.005759  |   150 |
| `brickell_split`                 |    0.02565 | ±0.000859  |   125 |
| `brickell_reconstruct`           |    0.06169 | ±0.001462  |   243 |
| `massey_split`                   |    0.02051 | ±0.001134  |    31 |
| `massey_reconstruct`             |    0.02708 | ±0.000883  |    30 |

`shamir`, `kothari`, `brickell`, `massey` cluster together (~25 µs
split, 25–60 µs recover) — Lagrange-style reconstruction over a
single Mersenne field element, with each algebraic surface paying a
constant overhead. `blakley` is the outlier on the recovery side
(105 µs) because it solves a `k × k` linear system end-to-end where
Lagrange just evaluates a single denominator-product per share.

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `ramp_split`                     |     0.1532 | ±0.003517  |   240 |
| `ramp_reconstruct`               |     0.09695 | ±0.003572 |   210 |
| `yamamoto_split`                 |     0.1495 | ±0.006313  |   127 |
| `yamamoto_reconstruct`           |     0.0895 | ±0.001877  |    31 |
| `blakley_meadows_split`          |     0.2133 | ±0.005761  |   394 |
| `blakley_meadows_reconstruct`    |     0.1027 | ±0.002922  |   120 |
| `kgh_split`                      |     0.1372 | ±0.002903  |   210 |
| `kgh_reconstruct`                |     0.08747 | ±0.001073  |   151 |

All four ramp / vector schemes pay roughly `L×` the threshold-scheme
cost on split (since each polynomial / matrix lives over a length-`L`
secret). `blakley_meadows` is the heaviest at split because the
hyperplane-bank rejection-sampling guard (commit 7b54acc) re-rolls
the random matrix on rare singular events.

### Verifiable secret sharing

Two schemes only — `vss` (Rabin–Ben-Or, information-theoretic) and
`cgma_vss` (Chor-GMA, computational). A radar with two axes
degenerates to a line, so the right honest format is the table:

| Scheme                | op           | ms/op   | ±CI (95%)  | Runs |
|-----------------------|--------------|---------|------------|------|
| `vss`                 | split        | 0.1551  | ±0.01006   | 93   |
| `vss`                 | reconstruct  | 0.08332 | ±0.001296  | 150  |
| `cgma_vss`            | split        | 1.338   | ±0.08875   | 39   |
| `cgma_vss`            | reconstruct  | 13.14   | ±1.136     | 34   |

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
| `mignotte_split`                 | 0.0004321  | ±2.84e-05  |   120 |
| `mignotte_reconstruct`           | 0.002869   | ±5.75e-05  |   120 |
| `asmuth_bloom_split`             | 0.0007179  | ±4.56e-05  |    60 |
| `asmuth_bloom_reconstruct`       | 0.003038   | ±8.08e-05  |   120 |

Both run on the bundled small (≈12-bit β) sequences — the schemes
where the secret-size model is the legal-range gap `(α, β)` rather
than a field bit-width. For a scaling curve at larger β see
`assets/mignotte-scaling.svg` and `assets/asmuth-bloom-scaling.svg`.

### Other / convenience schemes

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `trivial_split`                  |   0.001542 | ±2.95e-05  |    35 |
| `trivial_reconstruct`            |   0.001080 | ±0.000198  |    77 |
| `ito_split`                      |   0.004689 | ±0.000131  |    30 |
| `ito_reconstruct`                |   0.002798 | ±0.000246  |    90 |
| `benaloh_leichter_split`         |   0.001176 | ±4.10e-05  |   180 |
| `benaloh_leichter_reconstruct`   |  0.0007085 | ±0.000142  |    43 |
| `proactive_refresh`              |   0.1210   | ±0.001434  |   120 |
| `proactive_recover`              |   0.02873  | ±0.000321  |   150 |
| `bytes_split_16`                 |   0.04760  | ±0.001136  |   210 |
| `bytes_reconstruct_16`           |   0.05854  | ±0.000777  |   120 |
| `ida_split_16`                   |   0.02043  | ±0.000290  |    30 |
| `ida_reconstruct_16`             |   0.05487  | ±0.003740  |   176 |
| `decode_reconstruct_t1`          |   0.4738   | ±0.01235   |   226 |

`benaloh_leichter` and `trivial` are the cheapest schemes in the
crate — under 2 µs at this parameterisation. `decode_reconstruct_t1`
(Berlekamp–Welch errors-and-erasures with one tampered share at
`n = 11`) is the heaviest because the homogeneous-system solve runs
even when no tampering is present.

### Visual cryptography (n=3, 8×8 image)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| `visual_split_3_8`               |   0.007723 | ±0.000429  |    30 |
| `visual_decode_3_8`              |   0.001016 | ±9.11e-05  |    34 |

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
| `shamir_split_4kb`                       |     5.762  | ±0.06048   |   45  |
| `shamir_reconstruct_4kb`                 |     7.481  | ±0.0865    |   30  |
| `blakley_split_4kb`                      |    53.85   | ±0.2891    |   72  |
| `blakley_reconstruct_4kb`                |    33.02   | ±0.3106    |   30  |
| `kothari_split_4kb`                      |     5.729  | ±0.07609   |   66  |
| `kothari_reconstruct_4kb`                |    10.18   | ±0.1114    |  105  |
| `karchmer_wigderson_split_4kb`           |     5.889  | ±0.1712    |   30  |
| `karchmer_wigderson_reconstruct_4kb`     |    15.10   | ±0.1287    |   45  |
| `brickell_split_4kb`                     |     5.832  | ±0.05842   |  103  |
| `brickell_reconstruct_4kb`               |    15.20   | ±0.1940    |   30  |
| `massey_split_4kb`                       |     4.394  | ±0.04171   |   73  |
| `massey_reconstruct_4kb`                 |     6.531  | ±0.1838    |   94  |

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
| `massey`             |    10.93 ± 0.189   |        366.2 ± 6.3         |
| `shamir`             |    13.24 ± 0.106   |        302.0 ± 2.4         |
| `kothari`            |    15.91 ± 0.135   |        251.4 ± 2.1         |
| `karchmer_wigderson` |    20.99 ± 0.214   |        190.6 ± 1.9         |
| `brickell`           |    21.03 ± 0.203   |        190.2 ± 1.8         |
| `blakley`            |    86.87 ± 0.424   |         46.05 ± 0.23       |

`blakley` is the obvious outlier: both split (random hyperplane
generation with a singularity guard) and reconstruct (k×k Gaussian
elimination) pay quadratic field-multiply work that dominates at
274 chunks. `kothari` / `karchmer_wigderson` / `brickell` cluster
together because all three are linear schemes with comparable
recovery-vector cost. `massey` wins overall because its CodeScheme
constructs a single linear combination over a fixed generator
matrix on both split and reconstruct.

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
