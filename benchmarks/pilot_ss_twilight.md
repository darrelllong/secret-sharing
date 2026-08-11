
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0045900 | ±0.0000628 |    30 |
| shamir_reconstruct                       |  0.0097210 | ±0.0000295 |    30 |
| blakley_split                            |  0.0912600 | ±0.0002079 |    30 |
| blakley_reconstruct                      |  0.0474000 | ±0.0007950 |    31 |
| kothari_split                            |  0.0043660 | ±0.0000242 |    30 |
| kothari_reconstruct                      |  0.0099130 | ±0.0000400 |    30 |
| karchmer_wigderson_split                 |  0.0047550 | ±0.0000240 |    35 |
| karchmer_wigderson_reconstruct           |  0.0141700 | ±0.0000333 |    42 |
| brickell_split                           |  0.0046190 | ±0.0000298 |    60 |
| brickell_reconstruct                     |  0.0143500 | ±0.0000447 |    30 |
| massey_split                             |  0.0038500 | ±0.0000229 |    60 |
| massey_reconstruct                       |  0.0061950 | ±0.0000250 |    33 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0468700 | ±0.0001747 |    30 |
| ramp_reconstruct                         |  0.0297200 | ±0.0001611 |    30 |
| yamamoto_split                           |  0.0471200 | ±0.0001537 |    30 |
| yamamoto_reconstruct                     |  0.0296500 | ±0.0001564 |    30 |
| blakley_meadows_split                    |  0.0913000 | ±0.0001300 |    60 |
| blakley_meadows_reconstruct              |  0.0474200 | ±0.0005620 |    54 |
| kgh_split                                |  0.0239100 | ±0.0001006 |    97 |
| kgh_reconstruct                          |  0.0283600 | ±0.0001259 |    30 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0277900 | ±0.0001028 |   134 |
| vss_reconstruct                          |  0.0204100 | ±0.0000734 |    59 |
| cgma_vss_split                           |  1.6760000 | ±0.0047625 |    30 |
| cgma_vss_reconstruct                     | 14.6800000 | ±0.0135550 |    87 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0003093 | ±0.0000056 |    31 |
| mignotte_reconstruct                     |  0.0019350 | ±0.0000098 |    30 |
| mignotte_reconstruct_large               |  0.0022430 | ±0.0000183 |    30 |
| asmuth_bloom_split                       |  0.0004694 | ±0.0000040 |    30 |
| asmuth_bloom_reconstruct                 |  0.0020660 | ±0.0000338 |    90 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0008707 | ±0.0000052 |    30 |
| trivial_reconstruct                      |  0.0002395 | ±0.0000034 |    36 |
| ito_split                                |  0.0034260 | ±0.0001662 |    36 |
| ito_reconstruct                          |  0.0010510 | ±0.0000132 |    60 |
| benaloh_leichter_split                   |  0.0017740 | ±0.0000120 |    30 |
| benaloh_leichter_reconstruct             |  0.0008376 | ±0.0000044 |    30 |
| proactive_refresh                        |  0.0229300 | ±0.0001042 |    35 |
| proactive_recover                        |  0.0098800 | ±0.0000208 |    60 |
| bytes_split_16                           |  0.0097120 | ±0.0000915 |    30 |
| bytes_reconstruct_16                     |  0.0196200 | ±0.0000559 |    38 |
| ida_split_16                             |  0.0044790 | ±0.0000264 |    30 |
| ida_reconstruct_16                       |  0.0123900 | ±0.0000332 |    30 |
| decode_reconstruct_t1                    |  0.1087000 | ±0.0003788 |    30 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0126900 | ±0.0000871 |    51 |
| visual_decode_3_8                        |  0.0013140 | ±0.0000093 |    30 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  1.2110000 | ±0.0039450 |    30 |
| shamir_reconstruct_4kb                   |  2.6520000 | ±0.0072650 |    30 |
| blakley_split_4kb                        | 25.0900000 | ±0.0680500 |    32 |
| blakley_reconstruct_4kb                  | 13.2900000 | ±0.0374850 |    90 |
| kothari_split_4kb                        |  1.1710000 | ±0.0028215 |    58 |
| kothari_reconstruct_4kb                  |  2.7150000 | ±0.0065400 |    58 |
| karchmer_wigderson_split_4kb             |  1.2330000 | ±0.0043465 |    30 |
| karchmer_wigderson_reconstruct_4kb       |  3.8870000 | ±0.0059300 |    60 |
| brickell_split_4kb                       |  1.2410000 | ±0.0031060 |    47 |
| brickell_reconstruct_4kb                 |  3.9490000 | ±0.0075750 |    35 |
| massey_split_4kb                         |  1.0350000 | ±0.0040770 |    30 |
| massey_reconstruct_4kb                   |  1.6890000 | ±0.0042345 |   150 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0019380 | ±0.0000161 |    33 |
| shamir_reconstruct_2_3                   |  0.0050520 | ±0.0000239 |   120 |
| shamir_split_3_5                         |  0.0045180 | ±0.0000319 |    60 |
| shamir_reconstruct_3_5                   |  0.0097090 | ±0.0000350 |    60 |
| shamir_split_5_9                         |  0.0127300 | ±0.0000463 |    30 |
| shamir_reconstruct_5_9                   |  0.0227100 | ±0.0000433 |    80 |
| shamir_split_7_15                        |  0.0286400 | ±0.0000755 |    30 |
| shamir_reconstruct_7_15                  |  0.0443400 | ±0.0000899 |    30 |
| shamir_split_10_20                       |  0.0535200 | ±0.0001389 |    30 |
| shamir_reconstruct_10_20                 |  0.0892800 | ±0.0001982 |    30 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0080050 | ±0.0000477 |    52 |
| shamir_cold_reconstruct                  |  0.0205900 | ±0.0001563 |    31 |
| blakley_cold_split                       |  0.1035000 | ±0.0018105 |    30 |
| blakley_cold_reconstruct                 |  0.0487900 | ±0.0006785 |    55 |
| massey_cold_split                        |  0.0126400 | ±0.0005020 |    79 |
| massey_cold_reconstruct                  |  0.0103800 | ±0.0001496 |    60 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
