# pilot_ss sweep — Apple M1 Max (arm64, macOS) — wigner

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0038180 | ±0.0000184 |    60 |
| shamir_reconstruct                       |  0.0077530 | ±0.0000345 |    37 |
| blakley_split                            |  0.1668000 | ±0.0004013 |   171 |
| blakley_reconstruct                      |  0.0775700 | ±0.0016735 |    60 |
| kothari_split                            |  0.0037230 | ±0.0000266 |    37 |
| kothari_reconstruct                      |  0.0073220 | ±0.0000678 |    30 |
| karchmer_wigderson_split                 |  0.0039460 | ±0.0000268 |    30 |
| karchmer_wigderson_reconstruct           |  0.0101700 | ±0.0000476 |   120 |
| brickell_split                           |  0.0039930 | ±0.0000387 |   120 |
| brickell_reconstruct                     |  0.0101500 | ±0.0000382 |    37 |
| massey_split                             |  0.0030700 | ±0.0000253 |    30 |
| massey_reconstruct                       |  0.0049750 | ±0.0000321 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0360300 | ±0.0001131 |    40 |
| ramp_reconstruct                         |  0.0252100 | ±0.0002239 |    30 |
| yamamoto_split                           |  0.0364100 | ±0.0001837 |    31 |
| yamamoto_reconstruct                     |  0.0256100 | ±0.0002533 |   240 |
| blakley_meadows_split                    |  0.1728000 | ±0.0017515 |    60 |
| blakley_meadows_reconstruct              |  0.0835300 | ±0.0021600 |    30 |
| kgh_split                                |  0.0215500 | ±0.0002566 |    64 |
| kgh_reconstruct                          |  0.0249000 | ±0.0001682 |    42 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0224300 | ±0.0001435 |    90 |
| vss_reconstruct                          |  0.0176600 | ±0.0002907 |    30 |
| cgma_vss_split                           |  1.5550000 | ±0.0135550 |    31 |
| cgma_vss_reconstruct                     | 14.8300000 | ±0.1846000 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0003044 | ±0.0000015 |    37 |
| mignotte_reconstruct                     |  0.0020660 | ±0.0000163 |    40 |
| mignotte_reconstruct_large               |  0.0192000 | ±0.0000323 |   100 |
| asmuth_bloom_split                       |  0.0004241 | ±0.0000047 |    37 |
| asmuth_bloom_reconstruct                 |  0.0021100 | ±0.0000199 |    90 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0006871 | ±0.0000060 |    30 |
| trivial_reconstruct                      |  0.0001680 | ±0.0000025 |    51 |
| ito_split                                |  0.0025520 | ±0.0000129 |    60 |
| ito_reconstruct                          |  0.0008343 | ±0.0000071 |   145 |
| benaloh_leichter_split                   |  0.0014930 | ±0.0000445 |    36 |
| benaloh_leichter_reconstruct             |  0.0006760 | ±0.0000079 |    30 |
| proactive_refresh                        |  0.0185700 | ±0.0000859 |    30 |
| proactive_recover                        |  0.0078550 | ±0.0000371 |   214 |
| bytes_split_16                           |  0.0078950 | ±0.0000420 |    60 |
| bytes_reconstruct_16                     |  0.0157200 | ±0.0000607 |    37 |
| ida_split_16                             |  0.0036330 | ±0.0000158 |    40 |
| ida_reconstruct_16                       |  0.0087410 | ±0.0000559 |    30 |
| decode_reconstruct_t1                    |  0.0801800 | ±0.0005960 |   126 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0107500 | ±0.0001203 |    30 |
| visual_decode_3_8                        |  0.0012720 | ±0.0000175 |    63 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.8968000 | ±0.0095400 |    60 |
| shamir_reconstruct_4kb                   |  1.8300000 | ±0.0028035 |    33 |
| blakley_split_4kb                        | 45.8200000 | ±0.2884500 |    30 |
| blakley_reconstruct_4kb                  | 24.2000000 | ±0.0743500 |    41 |
| kothari_split_4kb                        |  0.8787000 | ±0.0052050 |    33 |
| kothari_reconstruct_4kb                  |  1.7330000 | ±0.0039755 |   150 |
| karchmer_wigderson_split_4kb             |  0.9498000 | ±0.0062800 |    31 |
| karchmer_wigderson_reconstruct_4kb       |  2.4710000 | ±0.0216150 |   220 |
| brickell_split_4kb                       |  0.9576000 | ±0.0053650 |    30 |
| brickell_reconstruct_4kb                 |  2.4720000 | ±0.0049235 |    60 |
| massey_split_4kb                         |  0.7542000 | ±0.0068650 |    37 |
| massey_reconstruct_4kb                   |  1.1220000 | ±0.0168800 |    30 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0016510 | ±0.0000229 |   114 |
| shamir_reconstruct_2_3                   |  0.0045130 | ±0.0000274 |    97 |
| shamir_split_3_5                         |  0.0039840 | ±0.0000296 |    32 |
| shamir_reconstruct_3_5                   |  0.0078000 | ±0.0000290 |   300 |
| shamir_split_5_9                         |  0.0092420 | ±0.0000450 |    30 |
| shamir_reconstruct_5_9                   |  0.0151300 | ±0.0000764 |    44 |
| shamir_split_7_15                        |  0.0188400 | ±0.0000562 |    60 |
| shamir_reconstruct_7_15                  |  0.0285000 | ±0.0000501 |    62 |
| shamir_split_10_20                       |  0.0338600 | ±0.0001332 |    37 |
| shamir_reconstruct_10_20                 |  0.0682800 | ±0.0001130 |   174 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0080070 | ±0.0001278 |    60 |
| shamir_cold_reconstruct                  |  0.0184800 | ±0.0001111 |    60 |
| blakley_cold_split                       |  0.2181000 | ±0.0055500 |    30 |
| blakley_cold_reconstruct                 |  0.0943500 | ±0.0017645 |    30 |
| massey_cold_split                        |  0.0082930 | ±0.0001361 |    30 |
| massey_cold_reconstruct                  |  0.0119500 | ±0.0001582 |    30 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
