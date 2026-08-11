
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0029110 | ±0.0000369 |    80 |
| shamir_reconstruct                       |  0.0056850 | ±0.0000488 |    59 |
| blakley_split                            |  0.0448100 | ±0.0005800 |    50 |
| blakley_reconstruct                      |  0.0243100 | ±0.0003657 |    50 |
| kothari_split                            |  0.0028870 | ±0.0000422 |    80 |
| kothari_reconstruct                      |  0.0059680 | ±0.0000644 |    84 |
| karchmer_wigderson_split                 |  0.0031030 | ±0.0000286 |    50 |
| karchmer_wigderson_reconstruct           |  0.0080680 | ±0.0000716 |    50 |
| brickell_split                           |  0.0030950 | ±0.0000408 |    50 |
| brickell_reconstruct                     |  0.0081480 | ±0.0000603 |    80 |
| massey_split                             |  0.0024140 | ±0.0000216 |   170 |
| massey_reconstruct                       |  0.0039580 | ±0.0000531 |    50 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0264200 | ±0.0002044 |   118 |
| ramp_reconstruct                         |  0.0182900 | ±0.0001985 |    50 |
| yamamoto_split                           |  0.0265600 | ±0.0002471 |    53 |
| yamamoto_reconstruct                     |  0.0179800 | ±0.0001459 |    50 |
| blakley_meadows_split                    |  0.0447100 | ±0.0002875 |    50 |
| blakley_meadows_reconstruct              |  0.0287500 | ±0.0005305 |    52 |
| kgh_split                                |  0.0149400 | ±0.0001310 |    50 |
| kgh_reconstruct                          |  0.0174900 | ±0.0001764 |    50 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0173300 | ±0.0001374 |    50 |
| vss_reconstruct                          |  0.0128200 | ±0.0000839 |    80 |
| cgma_vss_split                           |  0.8339000 | ±0.0029180 |    50 |
| cgma_vss_reconstruct                     |  7.1950000 | ±0.0269300 |   110 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002456 | ±0.0000043 |    57 |
| mignotte_reconstruct                     |  0.0010240 | ±0.0000110 |    54 |
| mignotte_reconstruct_large               |  0.0012910 | ±0.0000193 |    50 |
| asmuth_bloom_split                       |  0.0003328 | ±0.0000056 |    52 |
| asmuth_bloom_reconstruct                 |  0.0011130 | ±0.0000180 |    80 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005176 | ±0.0000054 |    56 |
| trivial_reconstruct                      |  0.0001362 | ±0.0000020 |    80 |
| ito_split                                |  0.0019120 | ±0.0000140 |   140 |
| ito_reconstruct                          |  0.0006803 | ±0.0000068 |    50 |
| benaloh_leichter_split                   |  0.0010800 | ±0.0000073 |    82 |
| benaloh_leichter_reconstruct             |  0.0004443 | ±0.0000059 |    50 |
| proactive_refresh                        |  0.0150500 | ±0.0001228 |    80 |
| proactive_recover                        |  0.0059380 | ±0.0000386 |    85 |
| bytes_split_16                           |  0.0062400 | ±0.0000878 |   110 |
| bytes_reconstruct_16                     |  0.0116100 | ±0.0000758 |   110 |
| ida_split_16                             |  0.0029130 | ±0.0000228 |    80 |
| ida_reconstruct_16                       |  0.0070770 | ±0.0000413 |    50 |
| decode_reconstruct_t1                    |  0.0646200 | ±0.0007770 |   170 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0074110 | ±0.0001136 |    50 |
| visual_decode_3_8                        |  0.0009763 | ±0.0000101 |   140 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7136000 | ±0.0044740 |   117 |
| shamir_reconstruct_4kb                   |  1.3500000 | ±0.0110600 |    50 |
| blakley_split_4kb                        | 12.0000000 | ±0.1344000 |    50 |
| blakley_reconstruct_4kb                  |  6.3060000 | ±0.0835500 |    80 |
| kothari_split_4kb                        |  0.7033000 | ±0.0082550 |   140 |
| kothari_reconstruct_4kb                  |  1.3980000 | ±0.0115700 |   110 |
| karchmer_wigderson_split_4kb             |  0.7608000 | ±0.0061900 |    80 |
| karchmer_wigderson_reconstruct_4kb       |  2.0160000 | ±0.0212950 |   200 |
| brickell_split_4kb                       |  0.7997000 | ±0.0178950 |   110 |
| brickell_reconstruct_4kb                 |  2.0950000 | ±0.0225900 |    50 |
| massey_split_4kb                         |  0.6466000 | ±0.0122000 |    50 |
| massey_reconstruct_4kb                   |  0.9114000 | ±0.0100800 |    50 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0012700 | ±0.0000115 |    80 |
| shamir_reconstruct_2_3                   |  0.0032070 | ±0.0000335 |    80 |
| shamir_split_3_5                         |  0.0030510 | ±0.0000657 |    50 |
| shamir_reconstruct_3_5                   |  0.0059850 | ±0.0001081 |    54 |
| shamir_split_5_9                         |  0.0076400 | ±0.0001253 |    57 |
| shamir_reconstruct_5_9                   |  0.0128200 | ±0.0002163 |    80 |
| shamir_split_7_15                        |  0.0153900 | ±0.0001737 |   111 |
| shamir_reconstruct_7_15                  |  0.0244400 | ±0.0004892 |   170 |
| shamir_split_10_20                       |  0.0403500 | ±0.0006800 |   292 |
| shamir_reconstruct_10_20                 |  0.0445500 | ±0.0003237 |   145 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0060090 | ±0.0000766 |    80 |
| shamir_cold_reconstruct                  |  0.0135400 | ±0.0002193 |    50 |
| blakley_cold_split                       |  0.0834700 | ±0.0013215 |   113 |
| blakley_cold_reconstruct                 |  0.0325900 | ±0.0005085 |    50 |
| massey_cold_split                        |  0.0056260 | ±0.0000860 |    88 |
| massey_cold_reconstruct                  |  0.0093010 | ±0.0001036 |   112 |

Generated by `scripts/bench_pilot.sh` (preset: normal).
