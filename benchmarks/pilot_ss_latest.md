# pilot_ss sweep — Apple M4 Pro (arm64, macOS) — Hardy (local)

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0029340 | ±0.0000224 |    90 |
| shamir_reconstruct                       |  0.0062900 | ±0.0001024 |    30 |
| blakley_split                            |  0.1292000 | ±0.0012540 |    30 |
| blakley_reconstruct                      |  0.0572300 | ±0.0016695 |    54 |
| kothari_split                            |  0.0032450 | ±0.0000789 |    60 |
| kothari_reconstruct                      |  0.0061130 | ±0.0001325 |    90 |
| karchmer_wigderson_split                 |  0.0032120 | ±0.0000692 |    30 |
| karchmer_wigderson_reconstruct           |  0.0084940 | ±0.0002062 |    60 |
| brickell_split                           |  0.0033580 | ±0.0000799 |    30 |
| brickell_reconstruct                     |  0.0087980 | ±0.0001722 |    36 |
| massey_split                             |  0.0025580 | ±0.0000498 |    30 |
| massey_reconstruct                       |  0.0039600 | ±0.0000824 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0320200 | ±0.0006250 |    96 |
| ramp_reconstruct                         |  0.0210500 | ±0.0004810 |    41 |
| yamamoto_split                           |  0.0305100 | ±0.0005255 |    45 |
| yamamoto_reconstruct                     |  0.0213100 | ±0.0005105 |    35 |
| blakley_meadows_split                    |  0.1309000 | ±0.0014900 |    40 |
| blakley_meadows_reconstruct              |  0.0614100 | ±0.0016415 |    30 |
| kgh_split                                |  0.0155100 | ±0.0003940 |    30 |
| kgh_reconstruct                          |  0.0196800 | ±0.0003900 |    34 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0181000 | ±0.0003934 |    63 |
| vss_reconstruct                          |  0.0142000 | ±0.0004218 |   120 |
| cgma_vss_split                           |  1.3370000 | ±0.0637000 |    60 |
| cgma_vss_reconstruct                     | 12.6500000 | ±0.4883000 |    60 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002645 | ±0.0000071 |   121 |
| mignotte_reconstruct                     |  0.0017570 | ±0.0000409 |   110 |
| mignotte_reconstruct_large               |  0.0146800 | ±0.0002198 |    30 |
| asmuth_bloom_split                       |  0.0003539 | ±0.0000051 |    30 |
| asmuth_bloom_reconstruct                 |  0.0019600 | ±0.0000479 |    53 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005721 | ±0.0000093 |    55 |
| trivial_reconstruct                      |  0.0001439 | ±0.0000030 |    35 |
| ito_split                                |  0.0022500 | ±0.0000506 |    40 |
| ito_reconstruct                          |  0.0007439 | ±0.0000133 |    66 |
| benaloh_leichter_split                   |  0.0012360 | ±0.0000324 |    65 |
| benaloh_leichter_reconstruct             |  0.0005208 | ±0.0000145 |    37 |
| proactive_refresh                        |  0.0168900 | ±0.0003725 |    47 |
| proactive_recover                        |  0.0070580 | ±0.0001836 |    90 |
| bytes_split_16                           |  0.0068470 | ±0.0001661 |   180 |
| bytes_reconstruct_16                     |  0.0141800 | ±0.0002401 |    85 |
| ida_split_16                             |  0.0031550 | ±0.0000846 |   150 |
| ida_reconstruct_16                       |  0.0082150 | ±0.0002083 |    60 |
| decode_reconstruct_t1                    |  0.0709500 | ±0.0009760 |   128 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0085380 | ±0.0002885 |    30 |
| visual_decode_3_8                        |  0.0011040 | ±0.0000235 |   390 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7939000 | ±0.0163600 |    52 |
| shamir_reconstruct_4kb                   |  1.7200000 | ±0.0334500 |    60 |
| blakley_split_4kb                        | 37.0600000 | ±0.4065500 |    60 |
| blakley_reconstruct_4kb                  | 20.9100000 | ±0.2267000 |    30 |
| kothari_split_4kb                        |  0.7440000 | ±0.0129300 |    30 |
| kothari_reconstruct_4kb                  |  1.5470000 | ±0.0377650 |    32 |
| karchmer_wigderson_split_4kb             |  0.9075000 | ±0.0256700 |    90 |
| karchmer_wigderson_reconstruct_4kb       |  2.2620000 | ±0.0527500 |    34 |
| brickell_split_4kb                       |  0.8755000 | ±0.0284150 |    30 |
| brickell_reconstruct_4kb                 |  2.2560000 | ±0.0376600 |    95 |
| massey_split_4kb                         |  0.6696000 | ±0.0161550 |    42 |
| massey_reconstruct_4kb                   |  1.0200000 | ±0.0257650 |    31 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0015640 | ±0.0000167 |   330 |
| shamir_reconstruct_2_3                   |  0.0043610 | ±0.0000755 |   106 |
| shamir_split_3_5                         |  0.0033530 | ±0.0001172 |    62 |
| shamir_reconstruct_3_5                   |  0.0070960 | ±0.0001428 |    50 |
| shamir_split_5_9                         |  0.0083290 | ±0.0002027 |   120 |
| shamir_reconstruct_5_9                   |  0.0140800 | ±0.0004345 |   240 |
| shamir_split_7_15                        |  0.0162600 | ±0.0003017 |   120 |
| shamir_reconstruct_7_15                  |  0.0263000 | ±0.0005760 |    60 |
| shamir_split_10_20                       |  0.0292500 | ±0.0006415 |    90 |
| shamir_reconstruct_10_20                 |  0.0583300 | ±0.0009325 |    71 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0064540 | ±0.0001225 |    90 |
| shamir_cold_reconstruct                  |  0.0149200 | ±0.0004453 |    30 |
| blakley_cold_split                       |  0.1861000 | ±0.0031240 |    30 |
| blakley_cold_reconstruct                 |  0.0691900 | ±0.0020640 |    90 |
| massey_cold_split                        |  0.0068450 | ±0.0001157 |   721 |
| massey_cold_reconstruct                  |  0.0100700 | ±0.0003203 |   111 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
