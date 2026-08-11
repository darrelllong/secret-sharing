
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0029520 | ±0.0000342 |    36 |
| shamir_reconstruct                       |  0.0058760 | ±0.0000735 |    40 |
| blakley_split                            |  0.0456100 | ±0.0008475 |    30 |
| blakley_reconstruct                      |  0.0325200 | ±0.0011685 |    60 |
| kothari_split                            |  0.0042280 | ±0.0001788 |    60 |
| kothari_reconstruct                      |  0.0096410 | ±0.0004703 |    30 |
| karchmer_wigderson_split                 |  0.0049390 | ±0.0002817 |   102 |
| karchmer_wigderson_reconstruct           |  0.0128400 | ±0.0004914 |    30 |
| brickell_split                           |  0.0048200 | ±0.0001722 |    78 |
| brickell_reconstruct                     |  0.0130400 | ±0.0004546 |    31 |
| massey_split                             |  0.0038270 | ±0.0001533 |    30 |
| massey_reconstruct                       |  0.0060420 | ±0.0003889 |    90 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0426500 | ±0.0014575 |    60 |
| ramp_reconstruct                         |  0.0285600 | ±0.0011760 |    39 |
| yamamoto_split                           |  0.0413200 | ±0.0015880 |    30 |
| yamamoto_reconstruct                     |  0.0296400 | ±0.0010725 |    45 |
| blakley_meadows_split                    |  0.0526100 | ±0.0008910 |    30 |
| blakley_meadows_reconstruct              |  0.0321300 | ±0.0008700 |   123 |
| kgh_split                                |  0.0168900 | ±0.0004746 |   181 |
| kgh_reconstruct                          |  0.0193200 | ±0.0005310 |   222 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0189100 | ±0.0008270 |    94 |
| vss_reconstruct                          |  0.0142200 | ±0.0005675 |    35 |
| cgma_vss_split                           |  0.9350000 | ±0.0224550 |    61 |
| cgma_vss_reconstruct                     |  8.2920000 | ±0.1147500 |    60 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002480 | ±0.0000067 |    66 |
| mignotte_reconstruct                     |  0.0011550 | ±0.0000478 |    40 |
| mignotte_reconstruct_large               |  0.0013590 | ±0.0000374 |    33 |
| asmuth_bloom_split                       |  0.0003693 | ±0.0000119 |    32 |
| asmuth_bloom_reconstruct                 |  0.0012710 | ±0.0000322 |    48 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005632 | ±0.0000167 |    30 |
| trivial_reconstruct                      |  0.0001452 | ±0.0000038 |    31 |
| ito_split                                |  0.0021620 | ±0.0000771 |    41 |
| ito_reconstruct                          |  0.0007226 | ±0.0000168 |    62 |
| benaloh_leichter_split                   |  0.0011720 | ±0.0000256 |    30 |
| benaloh_leichter_reconstruct             |  0.0005083 | ±0.0000218 |    32 |
| proactive_refresh                        |  0.0160000 | ±0.0004306 |    78 |
| proactive_recover                        |  0.0065810 | ±0.0001591 |    54 |
| bytes_split_16                           |  0.0065010 | ±0.0001500 |    68 |
| bytes_reconstruct_16                     |  0.0129400 | ±0.0004223 |    34 |
| ida_split_16                             |  0.0032280 | ±0.0000620 |    30 |
| ida_reconstruct_16                       |  0.0076810 | ±0.0002381 |   100 |
| decode_reconstruct_t1                    |  0.0726500 | ±0.0044685 |    33 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0080700 | ±0.0003682 |    60 |
| visual_decode_3_8                        |  0.0010770 | ±0.0000494 |    32 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7805000 | ±0.0230000 |    30 |
| shamir_reconstruct_4kb                   |  1.5940000 | ±0.0347300 |   121 |
| blakley_split_4kb                        | 11.7800000 | ±0.0937000 |   124 |
| blakley_reconstruct_4kb                  |  6.0740000 | ±0.0701000 |    30 |
| kothari_split_4kb                        |  0.6910000 | ±0.0046915 |    81 |
| kothari_reconstruct_4kb                  |  1.3690000 | ±0.0126800 |    30 |
| karchmer_wigderson_split_4kb             |  0.7619000 | ±0.0087850 |    31 |
| karchmer_wigderson_reconstruct_4kb       |  1.9490000 | ±0.0144400 |    47 |
| brickell_split_4kb                       |  0.7580000 | ±0.0100200 |    30 |
| brickell_reconstruct_4kb                 |  1.9820000 | ±0.0198100 |    30 |
| massey_split_4kb                         |  0.6045000 | ±0.0062300 |    62 |
| massey_reconstruct_4kb                   |  0.8982000 | ±0.0140200 |    35 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0013210 | ±0.0000376 |    32 |
| shamir_reconstruct_2_3                   |  0.0032750 | ±0.0000699 |    30 |
| shamir_split_3_5                         |  0.0029000 | ±0.0000276 |    49 |
| shamir_reconstruct_3_5                   |  0.0058120 | ±0.0000644 |    30 |
| shamir_split_5_9                         |  0.0072850 | ±0.0000644 |    46 |
| shamir_reconstruct_5_9                   |  0.0120500 | ±0.0001140 |    42 |
| shamir_split_7_15                        |  0.0147800 | ±0.0001246 |    60 |
| shamir_reconstruct_7_15                  |  0.0221500 | ±0.0001603 |    65 |
| shamir_split_10_20                       |  0.0264800 | ±0.0002341 |    30 |
| shamir_reconstruct_10_20                 |  0.0433000 | ±0.0003840 |    30 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0062990 | ±0.0001906 |    30 |
| shamir_cold_reconstruct                  |  0.0140900 | ±0.0003299 |    30 |
| blakley_cold_split                       |  0.0855200 | ±0.0012800 |    52 |
| blakley_cold_reconstruct                 |  0.0359900 | ±0.0021940 |    30 |
| massey_cold_split                        |  0.0056530 | ±0.0000616 |   119 |
| massey_cold_reconstruct                  |  0.0099150 | ±0.0002809 |    34 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
