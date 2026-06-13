# pilot_ss sweep — AMD EPYC 7452 (x86_64, Ubuntu 22.04) — twilight.soe.ucsc.edu

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0043470 | ±0.0002002 |    30 |
| shamir_reconstruct                       |  0.0092180 | ±0.0000222 |    46 |
| blakley_split                            |  0.2374000 | ±0.0006675 |    35 |
| blakley_reconstruct                      |  0.1151000 | ±0.0029360 |    33 |
| kothari_split                            |  0.0040060 | ±0.0000285 |    92 |
| kothari_reconstruct                      |  0.0089140 | ±0.0000301 |    49 |
| karchmer_wigderson_split                 |  0.0045980 | ±0.0000240 |    98 |
| karchmer_wigderson_reconstruct           |  0.0129400 | ±0.0000266 |    48 |
| brickell_split                           |  0.0044600 | ±0.0000226 |    33 |
| brickell_reconstruct                     |  0.0131300 | ±0.0000272 |   175 |
| massey_split                             |  0.0036060 | ±0.0000189 |    54 |
| massey_reconstruct                       |  0.0056600 | ±0.0000197 |    50 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0444700 | ±0.0001116 |    53 |
| ramp_reconstruct                         |  0.0284500 | ±0.0001041 |    30 |
| yamamoto_split                           |  0.0446800 | ±0.0001148 |    48 |
| yamamoto_reconstruct                     |  0.0284000 | ±0.0000841 |    30 |
| blakley_meadows_split                    |  0.2383000 | ±0.0009305 |    30 |
| blakley_meadows_reconstruct              |  0.1146000 | ±0.0036030 |    30 |
| kgh_split                                |  0.0216600 | ±0.0000982 |    44 |
| kgh_reconstruct                          |  0.0275300 | ±0.0000906 |    32 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0258800 | ±0.0000965 |    42 |
| vss_reconstruct                          |  0.0193900 | ±0.0000883 |    30 |
| cgma_vss_split                           |  2.1430000 | ±0.0048590 |    68 |
| cgma_vss_reconstruct                     | 20.3900000 | ±0.0250600 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002932 | ±0.0000043 |   120 |
| mignotte_reconstruct                     |  0.0027350 | ±0.0000109 |    65 |
| mignotte_reconstruct_large               |  0.0222200 | ±0.0000939 |    40 |
| asmuth_bloom_split                       |  0.0004895 | ±0.0000047 |    37 |
| asmuth_bloom_reconstruct                 |  0.0028960 | ±0.0000264 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0008704 | ±0.0000068 |    60 |
| trivial_reconstruct                      |  0.0001950 | ±0.0000035 |    30 |
| ito_split                                |  0.0034750 | ±0.0001274 |    58 |
| ito_reconstruct                          |  0.0010310 | ±0.0000086 |    60 |
| benaloh_leichter_split                   |  0.0017490 | ±0.0000115 |    60 |
| benaloh_leichter_reconstruct             |  0.0008535 | ±0.0000034 |    31 |
| proactive_refresh                        |  0.0214200 | ±0.0000907 |    70 |
| proactive_recover                        |  0.0093490 | ±0.0000307 |    33 |
| bytes_split_16                           |  0.0091680 | ±0.0000860 |    90 |
| bytes_reconstruct_16                     |  0.0186200 | ±0.0000554 |    30 |
| ida_split_16                             |  0.0040370 | ±0.0000254 |    40 |
| ida_reconstruct_16                       |  0.0106600 | ±0.0000396 |    60 |
| decode_reconstruct_t1                    |  0.0960100 | ±0.0003524 |    31 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0140400 | ±0.0000779 |    30 |
| visual_decode_3_8                        |  0.0014200 | ±0.0000116 |    82 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  1.1380000 | ±0.0023750 |    55 |
| shamir_reconstruct_4kb                   |  2.5510000 | ±0.0055400 |    30 |
| blakley_split_4kb                        | 65.0600000 | ±0.1682000 |    30 |
| blakley_reconstruct_4kb                  | 35.2000000 | ±0.0731500 |    33 |
| kothari_split_4kb                        |  1.0650000 | ±0.0040985 |    39 |
| kothari_reconstruct_4kb                  |  2.4370000 | ±0.0055500 |    30 |
| karchmer_wigderson_split_4kb             |  1.1930000 | ±0.0105600 |    30 |
| karchmer_wigderson_reconstruct_4kb       |  3.5470000 | ±0.0078600 |    30 |
| brickell_split_4kb                       |  1.1970000 | ±0.0029315 |    53 |
| brickell_reconstruct_4kb                 |  3.6050000 | ±0.0059650 |    90 |
| massey_split_4kb                         |  0.9693000 | ±0.0038955 |    30 |
| massey_reconstruct_4kb                   |  1.5250000 | ±0.0043755 |    60 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0018830 | ±0.0000142 |    35 |
| shamir_reconstruct_2_3                   |  0.0050300 | ±0.0000321 |    30 |
| shamir_split_3_5                         |  0.0042780 | ±0.0000202 |    57 |
| shamir_reconstruct_3_5                   |  0.0092500 | ±0.0000502 |    30 |
| shamir_split_5_9                         |  0.0118400 | ±0.0000363 |    56 |
| shamir_reconstruct_5_9                   |  0.0202600 | ±0.0000456 |    30 |
| shamir_split_7_15                        |  0.0263200 | ±0.0000972 |    30 |
| shamir_reconstruct_7_15                  |  0.0395600 | ±0.0001068 |    34 |
| shamir_split_10_20                       |  0.0493900 | ±0.0001226 |    30 |
| shamir_reconstruct_10_20                 |  0.0963000 | ±0.0001500 |    44 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0170400 | ±0.0005865 |    30 |
| shamir_cold_reconstruct                  |  0.0186400 | ±0.0018585 |    35 |
| blakley_cold_split                       |  0.2525000 | ±0.0073900 |    31 |
| blakley_cold_reconstruct                 |  0.1229000 | ±0.0033340 |    40 |
| massey_cold_split                        |  0.0133100 | ±0.0012880 |    30 |
| massey_cold_reconstruct                  |  0.0123000 | ±0.0012080 |    34 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
