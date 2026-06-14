# pilot_ss sweep — AMD EPYC 7452 (x86_64, Ubuntu 22.04) — twilight.soe.ucsc.edu

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0043700 | ±0.0002004 |    30 |
| shamir_reconstruct                       |  0.0092040 | ±0.0000246 |    59 |
| blakley_split                            |  0.2363000 | ±0.0006715 |    30 |
| blakley_reconstruct                      |  0.1147000 | ±0.0029355 |    30 |
| kothari_split                            |  0.0039800 | ±0.0000244 |    60 |
| kothari_reconstruct                      |  0.0088600 | ±0.0000303 |    30 |
| karchmer_wigderson_split                 |  0.0045660 | ±0.0000235 |    30 |
| karchmer_wigderson_reconstruct           |  0.0128600 | ±0.0000491 |    33 |
| brickell_split                           |  0.0044660 | ±0.0000244 |    30 |
| brickell_reconstruct                     |  0.0131000 | ±0.0000487 |    39 |
| massey_split                             |  0.0036260 | ±0.0000220 |    63 |
| massey_reconstruct                       |  0.0056580 | ±0.0000273 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0445300 | ±0.0001348 |    30 |
| ramp_reconstruct                         |  0.0284600 | ±0.0001082 |    41 |
| yamamoto_split                           |  0.0445000 | ±0.0001089 |    52 |
| yamamoto_reconstruct                     |  0.0283300 | ±0.0001815 |    67 |
| blakley_meadows_split                    |  0.2373000 | ±0.0005070 |    49 |
| blakley_meadows_reconstruct              |  0.1150000 | ±0.0028785 |    30 |
| kgh_split                                |  0.0216300 | ±0.0001150 |    39 |
| kgh_reconstruct                          |  0.0275500 | ±0.0001099 |    43 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0258400 | ±0.0001499 |    30 |
| vss_reconstruct                          |  0.0191900 | ±0.0001053 |    30 |
| cgma_vss_split                           |  2.1470000 | ±0.0034595 |    45 |
| cgma_vss_reconstruct                     | 20.3900000 | ±0.0243700 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002906 | ±0.0000031 |    30 |
| mignotte_reconstruct                     |  0.0027410 | ±0.0000196 |    30 |
| mignotte_reconstruct_large               |  0.0223200 | ±0.0000880 |    74 |
| asmuth_bloom_split                       |  0.0004936 | ±0.0000067 |    30 |
| asmuth_bloom_reconstruct                 |  0.0028670 | ±0.0000258 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0008679 | ±0.0000061 |    30 |
| trivial_reconstruct                      |  0.0001964 | ±0.0000036 |    90 |
| ito_split                                |  0.0034780 | ±0.0001593 |    38 |
| ito_reconstruct                          |  0.0010310 | ±0.0000117 |    30 |
| benaloh_leichter_split                   |  0.0017520 | ±0.0000119 |    33 |
| benaloh_leichter_reconstruct             |  0.0008298 | ±0.0000022 |    49 |
| proactive_refresh                        |  0.0215600 | ±0.0001085 |   180 |
| proactive_recover                        |  0.0094100 | ±0.0000383 |    64 |
| bytes_split_16                           |  0.0091760 | ±0.0000832 |    35 |
| bytes_reconstruct_16                     |  0.0188200 | ±0.0000681 |    60 |
| ida_split_16                             |  0.0040270 | ±0.0000284 |    60 |
| ida_reconstruct_16                       |  0.0106500 | ±0.0000331 |    40 |
| decode_reconstruct_t1                    |  0.0960500 | ±0.0004437 |    30 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0141200 | ±0.0000782 |    49 |
| visual_decode_3_8                        |  0.0014130 | ±0.0000132 |    30 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  1.1430000 | ±0.0103300 |    30 |
| shamir_reconstruct_4kb                   |  2.5510000 | ±0.0043730 |    47 |
| blakley_split_4kb                        | 65.1300000 | ±0.1272000 |    30 |
| blakley_reconstruct_4kb                  | 35.1700000 | ±0.0574500 |   118 |
| kothari_split_4kb                        |  1.0630000 | ±0.0056700 |    30 |
| kothari_reconstruct_4kb                  |  2.4380000 | ±0.0051950 |    34 |
| karchmer_wigderson_split_4kb             |  1.1880000 | ±0.0044900 |    30 |
| karchmer_wigderson_reconstruct_4kb       |  3.5510000 | ±0.0069100 |    31 |
| brickell_split_4kb                       |  1.1970000 | ±0.0030535 |    42 |
| brickell_reconstruct_4kb                 |  3.6070000 | ±0.0073400 |    33 |
| massey_split_4kb                         |  0.9706000 | ±0.0036750 |    36 |
| massey_reconstruct_4kb                   |  1.5230000 | ±0.0039955 |    31 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0018750 | ±0.0000154 |    30 |
| shamir_reconstruct_2_3                   |  0.0050130 | ±0.0000265 |    30 |
| shamir_split_3_5                         |  0.0042860 | ±0.0000254 |    31 |
| shamir_reconstruct_3_5                   |  0.0092430 | ±0.0000317 |    30 |
| shamir_split_5_9                         |  0.0117900 | ±0.0000399 |    39 |
| shamir_reconstruct_5_9                   |  0.0202300 | ±0.0000604 |    30 |
| shamir_split_7_15                        |  0.0263500 | ±0.0000941 |    30 |
| shamir_reconstruct_7_15                  |  0.0396200 | ±0.0001071 |    30 |
| shamir_split_10_20                       |  0.0494600 | ±0.0000858 |    73 |
| shamir_reconstruct_10_20                 |  0.0965100 | ±0.0002006 |    30 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0165500 | ±0.0003641 |    45 |
| shamir_cold_reconstruct                  |  0.0185800 | ±0.0016025 |    30 |
| blakley_cold_split                       |  0.2550000 | ±0.0059500 |    46 |
| blakley_cold_reconstruct                 |  0.1209000 | ±0.0034905 |    60 |
| massey_cold_split                        |  0.0124500 | ±0.0012425 |    40 |
| massey_cold_reconstruct                  |  0.0125000 | ±0.0012380 |    72 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
