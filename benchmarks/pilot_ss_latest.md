
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |    0.02215 | ±0.0009007 |    30 |
| shamir_reconstruct                       |    0.02774 | ±0.0003942 |    30 |
| blakley_split                            |     0.1972 | ±0.002221 |    30 |
| blakley_reconstruct                      |    0.09191 | ±0.002517 |    30 |
| kothari_split                            |    0.02261 | ±0.0008464 |    60 |
| kothari_reconstruct                      |    0.03715 | ±0.0003547 |    46 |
| karchmer_wigderson_split                 |    0.02285 | ±0.0007502 |    30 |
| karchmer_wigderson_reconstruct           |    0.05484 | ±0.0006248 |    59 |
| brickell_split                           |    0.02331 | ±0.0005648 |    35 |
| brickell_reconstruct                     |    0.05495 | ±0.0005559 |    55 |
| massey_split                             |    0.01761 | ±0.0006226 |    30 |
| massey_reconstruct                       |    0.02356 | ±0.000385 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |     0.1361 | ±0.004191 |    30 |
| ramp_reconstruct                         |    0.08232 | ±0.0009252 |    60 |
| yamamoto_split                           |     0.1386 | ±0.002791 |    30 |
| yamamoto_reconstruct                     |    0.08442 | ±0.0009712 |    63 |
| blakley_meadows_split                    |     0.1971 |  ±0.00207 |    60 |
| blakley_meadows_reconstruct              |    0.09519 | ±0.002329 |    40 |
| kgh_split                                |     0.1245 | ±0.001634 |    33 |
| kgh_reconstruct                          |    0.08396 | ±0.001245 |    37 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |     0.1367 | ±0.003139 |    30 |
| vss_reconstruct                          |    0.07889 | ±0.001074 |    97 |
| cgma_vss_split                           |      1.344 |   ±0.1228 |    30 |
| cgma_vss_reconstruct                     |      12.36 |    ±0.729 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0003413 | ±1.49e-05 |   256 |
| mignotte_reconstruct                     |   0.002671 | ±6.177e-05 |    30 |
| asmuth_bloom_split                       |  0.0005981 | ±2.44e-05 |   120 |
| asmuth_bloom_reconstruct                 |   0.002823 | ±8.054e-05 |    60 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |   0.001457 | ±5.411e-05 |    35 |
| trivial_reconstruct                      |   0.000921 | ±0.0001816 |    62 |
| ito_split                                |   0.004514 | ±8.536e-05 |    35 |
| ito_reconstruct                          |   0.002585 | ±0.0003043 |    32 |
| benaloh_leichter_split                   |   0.001088 | ±2.572e-05 |    30 |
| benaloh_leichter_reconstruct             |  0.0006559 | ±0.0001311 |    35 |
| proactive_refresh                        |     0.1133 | ±0.001355 |    36 |
| proactive_recover                        |     0.0275 | ±0.0005001 |    30 |
| bytes_split_16                           |    0.04302 | ±0.0005363 |    31 |
| bytes_reconstruct_16                     |    0.05547 | ±0.0005686 |    49 |
| ida_split_16                             |    0.01948 | ±0.0002647 |    46 |
| ida_reconstruct_16                       |    0.04822 | ±0.0005091 |    39 |
| decode_reconstruct_t1                    |     0.4415 | ±0.006298 |    30 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |   0.007034 | ±0.0003714 |   243 |
| visual_decode_3_8                        |  0.0009639 | ±1.361e-05 |    30 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |      5.762 |  ±0.06048 |    45 |
| shamir_reconstruct_4kb                   |      7.481 |   ±0.0865 |    30 |
| blakley_split_4kb                        |      53.85 |   ±0.2891 |    72 |
| blakley_reconstruct_4kb                  |      33.02 |   ±0.3106 |    30 |
| kothari_split_4kb                        |      5.729 |  ±0.07609 |    66 |
| kothari_reconstruct_4kb                  |      10.18 |   ±0.1114 |   105 |
| karchmer_wigderson_split_4kb             |      5.889 |   ±0.1712 |    30 |
| karchmer_wigderson_reconstruct_4kb       |       15.1 |   ±0.1287 |    45 |
| brickell_split_4kb                       |      5.832 |  ±0.05842 |   103 |
| brickell_reconstruct_4kb                 |       15.2 |    ±0.194 |    30 |
| massey_split_4kb                         |      4.394 |  ±0.04171 |    73 |
| massey_reconstruct_4kb                   |      6.531 |   ±0.1838 |    94 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
