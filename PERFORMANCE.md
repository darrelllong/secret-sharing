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
| `cgma_vss`            | split        | 0.0149  | ±0.000374  | 63   |
| `cgma_vss`            | reconstruct  | 0.0520  | ±0.001457  | 88   |

`vss::deal` builds a full bivariate `k × k` polynomial matrix, so
splits cost ~5× a single Shamir secret. Reconstruction is dominated
by the `n²` pairwise consistency check.

`cgma_vss` numbers are over the toy `(p = 23, q = 11, g = 4)` group
— useful for checking the reconstruction wire path, **uninformative
for production**. Real DH-style group exponentiation costs orders of
magnitude more; see `assets/cgma-vss-scaling.svg` for the
group-size scaling curve.

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

## Kiviat charts

Operations that share a "single integer secret of N bits" model also
have legacy kiviat (radar) charts in
[`assets/`](assets/) — three families with ≥ 3 axes get a radar; the
two-axis VSS family is the table above. These charts use a coarse
in-process timer (`std::time::Instant`, 50 warmup + 200 measured
iterations, median latency) and exist for at-a-glance shape rather
than confidence-interval rigour. The pilot-bench tables above are
the authoritative numbers.

- [Threshold throughput radar](assets/threshold-throughput-radar.svg)
- [Ramp / vector throughput radar](assets/ramp-throughput-radar.svg)
- [Other-schemes throughput radar](assets/other-throughput-radar.svg)

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
  scheme, byte-string secrets larger than 16 bytes, and the full
  cold-cache numbers (the current `cold-cache-*.svg` charts use the
  legacy `examples/bench` first-iteration sampler). Adding any of
  these is a matter of dispatching a new operation in
  `src/bin/pilot_ss.rs` and a new `measure …` line in
  `scripts/bench_pilot.sh`.
