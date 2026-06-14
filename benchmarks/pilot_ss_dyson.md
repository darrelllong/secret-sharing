# pilot_ss sweep — Apple arm64 (macOS) — dyson

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0031700 | ±0.0003151 |    46 |
| shamir_reconstruct                       |  0.0063710 | ±0.0002542 |    30 |
| blakley_split                            |  0.1342000 | ±0.0084900 |    91 |
| blakley_reconstruct                      |  0.0567500 | ±0.0034990 |    50 |
| kothari_split                            |  0.0028800 | ±0.0000555 |    60 |
| kothari_reconstruct                      |  0.0064360 | ±0.0006420 |    52 |
| karchmer_wigderson_split                 |  0.0030670 | ±0.0000700 |    66 |
| karchmer_wigderson_reconstruct           |  0.0086670 | ±0.0008580 |   128 |
| brickell_split                           |  0.0032350 | ±0.0003186 |    73 |
| brickell_reconstruct                     |  0.0087460 | ±0.0003726 |    36 |
| massey_split                             |  0.0023960 | ±0.0000337 |    30 |
| massey_reconstruct                       |  0.0039290 | ±0.0000688 |    62 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0294500 | ±0.0004748 |    90 |
| ramp_reconstruct                         |  0.0190700 | ±0.0002322 |    90 |
| yamamoto_split                           |  0.0290000 | ±0.0004006 |   120 |
| yamamoto_reconstruct                     |  0.0200600 | ±0.0002721 |    30 |
| blakley_meadows_split                    |  0.1421000 | ±0.0141100 |    50 |
| blakley_meadows_reconstruct              |  0.0563600 | ±0.0012020 |    30 |
| kgh_split                                |  0.0149000 | ±0.0002879 |    30 |
| kgh_reconstruct                          |  0.0192900 | ±0.0004792 |   150 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0183600 | ±0.0012495 |    34 |
| vss_reconstruct                          |  0.0143400 | ±0.0013905 |    34 |
| cgma_vss_split                           |  1.3180000 | ±0.1317500 |    41 |
| cgma_vss_reconstruct                     | 11.5800000 | ±0.5330000 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002581 | ±0.0000043 |   270 |
| mignotte_reconstruct                     |  0.0016920 | ±0.0000193 |    60 |
| mignotte_reconstruct_large               |  0.0131300 | ±0.0000829 |    31 |
| asmuth_bloom_split                       |  0.0003600 | ±0.0000056 |    40 |
| asmuth_bloom_reconstruct                 |  0.0018480 | ±0.0000302 |   150 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005480 | ±0.0000102 |   120 |
| trivial_reconstruct                      |  0.0001445 | ±0.0000031 |    90 |
| ito_split                                |  0.0021000 | ±0.0000226 |   398 |
| ito_reconstruct                          |  0.0006777 | ±0.0000058 |   102 |
| benaloh_leichter_split                   |  0.0011010 | ±0.0000104 |    90 |
| benaloh_leichter_reconstruct             |  0.0004639 | ±0.0000099 |    30 |
| proactive_refresh                        |  0.0145500 | ±0.0001743 |    40 |
| proactive_recover                        |  0.0065080 | ±0.0000752 |    35 |
| bytes_split_16                           |  0.0065140 | ±0.0001076 |    60 |
| bytes_reconstruct_16                     |  0.0132800 | ±0.0001383 |   390 |
| ida_split_16                             |  0.0028500 | ±0.0000331 |   180 |
| ida_reconstruct_16                       |  0.0071520 | ±0.0001101 |    37 |
| decode_reconstruct_t1                    |  0.0687800 | ±0.0010855 |   151 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0077260 | ±0.0001667 |    60 |
| visual_decode_3_8                        |  0.0009928 | ±0.0000050 |   153 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7074000 | ±0.0072750 |    60 |
| shamir_reconstruct_4kb                   |  1.5950000 | ±0.0136850 |   347 |
| blakley_split_4kb                        | 34.3200000 | ±0.1922000 |    30 |
| blakley_reconstruct_4kb                  | 19.2500000 | ±0.1423500 |   211 |
| kothari_split_4kb                        |  0.7193000 | ±0.0144300 |    94 |
| kothari_reconstruct_4kb                  |  1.4050000 | ±0.0168350 |   184 |
| karchmer_wigderson_split_4kb             |  0.7730000 | ±0.0107300 |    31 |
| karchmer_wigderson_reconstruct_4kb       |  2.1010000 | ±0.1078000 |    74 |
| brickell_split_4kb                       |  0.7552000 | ±0.0104350 |    79 |
| brickell_reconstruct_4kb                 |  2.0320000 | ±0.0334300 |    30 |
| massey_split_4kb                         |  0.5928000 | ±0.0089050 |    90 |
| massey_reconstruct_4kb                   |  0.9642000 | ±0.0187100 |    60 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0013730 | ±0.0000229 |    30 |
| shamir_reconstruct_2_3                   |  0.0038460 | ±0.0000388 |    43 |
| shamir_split_3_5                         |  0.0029680 | ±0.0000366 |   210 |
| shamir_reconstruct_3_5                   |  0.0065250 | ±0.0000858 |   120 |
| shamir_split_5_9                         |  0.0073080 | ±0.0001169 |    60 |
| shamir_reconstruct_5_9                   |  0.0126800 | ±0.0001396 |   121 |
| shamir_split_7_15                        |  0.0153400 | ±0.0002403 |   127 |
| shamir_reconstruct_7_15                  |  0.0238600 | ±0.0014835 |    30 |
| shamir_split_10_20                       |  0.0262900 | ±0.0003529 |    30 |
| shamir_reconstruct_10_20                 |  0.0535000 | ±0.0004303 |    65 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0065960 | ±0.0000975 |   180 |
| shamir_cold_reconstruct                  |  0.0158500 | ±0.0007125 |    45 |
| blakley_cold_split                       |  0.1782000 | ±0.0028750 |    89 |
| blakley_cold_reconstruct                 |  0.0677500 | ±0.0013660 |    45 |
| massey_cold_split                        |  0.0054210 | ±0.0000644 |    90 |
| massey_cold_reconstruct                  |  0.0084640 | ±0.0001299 |    60 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
