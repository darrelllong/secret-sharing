# pilot_ss sweep — Apple M-series (arm64, macOS) — dyson

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0030310 | ±0.0000467 |    32 |
| shamir_reconstruct                       |  0.0065370 | ±0.0001001 |    30 |
| blakley_split                            |  0.1279000 | ±0.0009165 |    90 |
| blakley_reconstruct                      |  0.0551600 | ±0.0011340 |    30 |
| kothari_split                            |  0.0027970 | ±0.0000391 |    90 |
| kothari_reconstruct                      |  0.0063030 | ±0.0000722 |    57 |
| karchmer_wigderson_split                 |  0.0032000 | ±0.0000468 |    60 |
| karchmer_wigderson_reconstruct           |  0.0085690 | ±0.0001748 |   120 |
| brickell_split                           |  0.0031970 | ±0.0000527 |   363 |
| brickell_reconstruct                     |  0.0083920 | ±0.0000981 |   211 |
| massey_split                             |  0.0024540 | ±0.0000358 |    37 |
| massey_reconstruct                       |  0.0041030 | ±0.0000568 |    33 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0289700 | ±0.0003465 |   180 |
| ramp_reconstruct                         |  0.0199800 | ±0.0003386 |    30 |
| yamamoto_split                           |  0.0291300 | ±0.0003791 |    90 |
| yamamoto_reconstruct                     |  0.0212600 | ±0.0002844 |    60 |
| blakley_meadows_split                    |  0.1288000 | ±0.0010800 |    30 |
| blakley_meadows_reconstruct              |  0.0587800 | ±0.0009990 |    30 |
| kgh_split                                |  0.0147500 | ±0.0001945 |    30 |
| kgh_reconstruct                          |  0.0188700 | ±0.0001935 |    90 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0171400 | ±0.0001917 |   120 |
| vss_reconstruct                          |  0.0144000 | ±0.0001953 |   421 |
| cgma_vss_split                           |  1.2140000 | ±0.0534000 |    60 |
| cgma_vss_reconstruct                     | 11.3300000 | ±0.4726000 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002618 | ±0.0000027 |    37 |
| mignotte_reconstruct                     |  0.0016630 | ±0.0000099 |    38 |
| mignotte_reconstruct_large               |  0.0130800 | ±0.0001621 |   149 |
| asmuth_bloom_split                       |  0.0003480 | ±0.0000074 |    60 |
| asmuth_bloom_reconstruct                 |  0.0018050 | ±0.0000317 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005272 | ±0.0000051 |    66 |
| trivial_reconstruct                      |  0.0001373 | ±0.0000017 |    81 |
| ito_split                                |  0.0020960 | ±0.0000274 |    30 |
| ito_reconstruct                          |  0.0006772 | ±0.0000056 |   330 |
| benaloh_leichter_split                   |  0.0011320 | ±0.0000139 |    33 |
| benaloh_leichter_reconstruct             |  0.0004502 | ±0.0000063 |   180 |
| proactive_refresh                        |  0.0147800 | ±0.0001513 |    32 |
| proactive_recover                        |  0.0066030 | ±0.0000817 |   420 |
| bytes_split_16                           |  0.0059550 | ±0.0000555 |   100 |
| bytes_reconstruct_16                     |  0.0131000 | ±0.0001781 |   120 |
| ida_split_16                             |  0.0029130 | ±0.0000353 |    30 |
| ida_reconstruct_16                       |  0.0071690 | ±0.0000986 |   124 |
| decode_reconstruct_t1                    |  0.0647900 | ±0.0008310 |   372 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0077100 | ±0.0001442 |    90 |
| visual_decode_3_8                        |  0.0010090 | ±0.0000071 |    47 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7148000 | ±0.0147400 |    30 |
| shamir_reconstruct_4kb                   |  1.5450000 | ±0.0221100 |   120 |
| blakley_split_4kb                        | 34.2400000 | ±0.1911000 |    30 |
| blakley_reconstruct_4kb                  | 19.1600000 | ±0.1002000 |    90 |
| kothari_split_4kb                        |  0.6897000 | ±0.0071050 |    60 |
| kothari_reconstruct_4kb                  |  1.4620000 | ±0.0281400 |    30 |
| karchmer_wigderson_split_4kb             |  0.7471000 | ±0.0122200 |    60 |
| karchmer_wigderson_reconstruct_4kb       |  2.0200000 | ±0.0210200 |   500 |
| brickell_split_4kb                       |  0.7397000 | ±0.0103950 |    30 |
| brickell_reconstruct_4kb                 |  2.0430000 | ±0.0249850 |   210 |
| massey_split_4kb                         |  0.6193000 | ±0.0078050 |    63 |
| massey_reconstruct_4kb                   |  0.9388000 | ±0.0123750 |    34 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0013420 | ±0.0000170 |    40 |
| shamir_reconstruct_2_3                   |  0.0038720 | ±0.0000313 |    60 |
| shamir_split_3_5                         |  0.0029650 | ±0.0000433 |    38 |
| shamir_reconstruct_3_5                   |  0.0062410 | ±0.0000711 |   182 |
| shamir_split_5_9                         |  0.0072740 | ±0.0001254 |   161 |
| shamir_reconstruct_5_9                   |  0.0122900 | ±0.0001144 |   120 |
| shamir_split_7_15                        |  0.0146200 | ±0.0001205 |    30 |
| shamir_reconstruct_7_15                  |  0.0235900 | ±0.0004059 |    32 |
| shamir_split_10_20                       |  0.0261300 | ±0.0003990 |   690 |
| shamir_reconstruct_10_20                 |  0.0542700 | ±0.0005790 |    31 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0065500 | ±0.0001544 |    30 |
| shamir_cold_reconstruct                  |  0.0140200 | ±0.0004671 |    30 |
| blakley_cold_split                       |  0.1653000 | ±0.0029430 |    35 |
| blakley_cold_reconstruct                 |  0.0664300 | ±0.0016980 |    30 |
| massey_cold_split                        |  0.0055320 | ±0.0000972 |    45 |
| massey_cold_reconstruct                  |  0.0088030 | ±0.0001382 |   120 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
