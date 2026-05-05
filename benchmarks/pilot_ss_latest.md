
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |   0.005299 | ±0.0005448 |    66 |
| shamir_reconstruct                       |   0.006671 | ±0.0002561 |    32 |
| blakley_split                            |     0.1574 |  ±0.00184 |    60 |
| blakley_reconstruct                      |    0.06367 | ±0.001919 |    30 |
| kothari_split                            |   0.005964 | ±0.0007457 |    30 |
| kothari_reconstruct                      |   0.006663 | ±0.0001991 |   131 |
| karchmer_wigderson_split                 |   0.005777 | ±0.0006196 |    37 |
| karchmer_wigderson_reconstruct           |    0.01117 | ±0.0004192 |    30 |
| brickell_split                           |   0.005881 | ±0.000561 |    38 |
| brickell_reconstruct                     |    0.01123 | ±0.0003832 |    90 |
| massey_split                             |    0.00424 | ±0.0005216 |    39 |
| massey_reconstruct                       |   0.005429 | ±0.0002128 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |    0.03309 | ±0.0007674 |   101 |
| ramp_reconstruct                         |    0.02164 | ±0.0005162 |    45 |
| yamamoto_split                           |    0.03318 | ±0.0007856 |    86 |
| yamamoto_reconstruct                     |    0.02139 | ±0.0006366 |    60 |
| blakley_meadows_split                    |     0.1561 | ±0.0003551 |   300 |
| blakley_meadows_reconstruct              |    0.06565 | ±0.002092 |    30 |
| kgh_split                                |    0.02312 | ±0.001155 |    60 |
| kgh_reconstruct                          |    0.02067 | ±0.000822 |    30 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |    0.03456 | ±0.001524 |    60 |
| vss_reconstruct                          |    0.01905 | ±0.000852 |    30 |
| cgma_vss_split                           |      1.255 | ±0.006247 |    36 |
| cgma_vss_reconstruct                     |      12.04 |  ±0.04553 |    48 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0003385 | ±1.494e-05 |    60 |
| mignotte_reconstruct                     |    0.00272 | ±6.755e-05 |    67 |
| asmuth_bloom_split                       |  0.0006299 | ±1.897e-05 |    41 |
| asmuth_bloom_reconstruct                 |   0.002861 | ±7.725e-05 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |   0.001512 | ±3.576e-05 |    33 |
| trivial_reconstruct                      |   0.000986 | ±0.0001489 |    88 |
| ito_split                                |    0.00453 | ±9.831e-05 |    40 |
| ito_reconstruct                          |   0.002558 | ±0.0003001 |    36 |
| benaloh_leichter_split                   |   0.001048 | ±9.357e-05 |    93 |
| benaloh_leichter_reconstruct             |  0.0006737 | ±0.0001307 |    70 |
| proactive_refresh                        |      0.029 | ±0.0006131 |    33 |
| proactive_recover                        |   0.006867 | ±0.0002554 |    36 |
| bytes_split_16                           |   0.008875 | ±0.0001882 |    58 |
| bytes_reconstruct_16                     |    0.01435 | ±0.0004538 |    30 |
| ida_split_16                             |   0.002578 | ±9.064e-05 |    73 |
| ida_reconstruct_16                       |   0.007782 | ±0.0002419 |    64 |
| decode_reconstruct_t1                    |    0.06559 | ±0.002233 |    49 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |    0.00676 | ±0.0002797 |    30 |
| visual_decode_3_8                        |  0.0009607 | ±1.725e-05 |   107 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |      1.092 |  ±0.02519 |    42 |
| shamir_reconstruct_4kb                   |      1.835 |  ±0.02893 |   187 |
| blakley_split_4kb                        |      42.61 |    ±0.137 |   120 |
| blakley_reconstruct_4kb                  |      24.16 |     ±0.18 |    30 |
| kothari_split_4kb                        |      1.097 |  ±0.02829 |    30 |
| kothari_reconstruct_4kb                  |      1.715 |  ±0.05966 |    31 |
| karchmer_wigderson_split_4kb             |      1.156 |  ±0.03508 |    30 |
| karchmer_wigderson_reconstruct_4kb       |      2.993 |  ±0.09921 |    31 |
| brickell_split_4kb                       |      1.139 |  ±0.02823 |    74 |
| brickell_reconstruct_4kb                 |      3.068 |   ±0.1017 |    30 |
| massey_split_4kb                         |     0.6975 |   ±0.0336 |    60 |
| massey_reconstruct_4kb                   |      1.467 |  ±0.03336 |    50 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
