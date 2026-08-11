
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0039190 | ±0.0000222 |    60 |
| shamir_reconstruct                       |  0.0079820 | ±0.0000454 |   120 |
| blakley_split                            |  0.0610200 | ±0.0004192 |    30 |
| blakley_reconstruct                      |  0.0334500 | ±0.0006050 |    30 |
| kothari_split                            |  0.0037520 | ±0.0000328 |    30 |
| kothari_reconstruct                      |  0.0079800 | ±0.0000379 |    90 |
| karchmer_wigderson_split                 |  0.0040850 | ±0.0000221 |    76 |
| karchmer_wigderson_reconstruct           |  0.0107300 | ±0.0000374 |    63 |
| brickell_split                           |  0.0041750 | ±0.0000492 |    30 |
| brickell_reconstruct                     |  0.0109000 | ±0.0000300 |    85 |
| massey_split                             |  0.0032590 | ±0.0000317 |    64 |
| massey_reconstruct                       |  0.0050590 | ±0.0000315 |    30 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0357800 | ±0.0001487 |    32 |
| ramp_reconstruct                         |  0.0245500 | ±0.0004738 |    60 |
| yamamoto_split                           |  0.0360600 | ±0.0001871 |    61 |
| yamamoto_reconstruct                     |  0.0238100 | ±0.0001002 |    52 |
| blakley_meadows_split                    |  0.0613700 | ±0.0002170 |   120 |
| blakley_meadows_reconstruct              |  0.0374100 | ±0.0003734 |    71 |
| kgh_split                                |  0.0208100 | ±0.0008600 |    97 |
| kgh_reconstruct                          |  0.0234900 | ±0.0003476 |    30 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0232400 | ±0.0000926 |    77 |
| vss_reconstruct                          |  0.0172100 | ±0.0000954 |   103 |
| cgma_vss_split                           |  1.1810000 | ±0.0106700 |    62 |
| cgma_vss_reconstruct                     | 10.7900000 | ±0.2901000 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0003350 | ±0.0000274 |    58 |
| mignotte_reconstruct                     |  0.0013460 | ±0.0000132 |   112 |
| mignotte_reconstruct_large               |  0.0029630 | ±0.0002067 |   167 |
| asmuth_bloom_split                       |  0.0007121 | ±0.0000590 |    35 |
| asmuth_bloom_reconstruct                 |  0.0015390 | ±0.0000687 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0007215 | ±0.0000055 |    30 |
| trivial_reconstruct                      |  0.0001765 | ±0.0000022 |    90 |
| ito_split                                |  0.0026030 | ±0.0000169 |    62 |
| ito_reconstruct                          |  0.0009054 | ±0.0000056 |    30 |
| benaloh_leichter_split                   |  0.0015210 | ±0.0000084 |    93 |
| benaloh_leichter_reconstruct             |  0.0007253 | ±0.0000106 |    90 |
| proactive_refresh                        |  0.0190400 | ±0.0001635 |    30 |
| proactive_recover                        |  0.0078370 | ±0.0000531 |    30 |
| bytes_split_16                           |  0.0081180 | ±0.0000394 |    30 |
| bytes_reconstruct_16                     |  0.0155400 | ±0.0000711 |    62 |
| ida_split_16                             |  0.0038330 | ±0.0000177 |    30 |
| ida_reconstruct_16                       |  0.0094010 | ±0.0000638 |    34 |
| decode_reconstruct_t1                    |  0.0860900 | ±0.0005715 |   101 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0103900 | ±0.0001081 |    34 |
| visual_decode_3_8                        |  0.0012770 | ±0.0000027 |    57 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.9491000 | ±0.0048560 |    38 |
| shamir_reconstruct_4kb                   |  1.8210000 | ±0.0028920 |   180 |
| blakley_split_4kb                        | 16.4700000 | ±0.0325700 |    66 |
| blakley_reconstruct_4kb                  |  8.5740000 | ±0.0359200 |    41 |
| kothari_split_4kb                        |  0.9271000 | ±0.0069650 |   127 |
| kothari_reconstruct_4kb                  |  1.8620000 | ±0.0118200 |    50 |
| karchmer_wigderson_split_4kb             |  0.9954000 | ±0.0086300 |    31 |
| karchmer_wigderson_reconstruct_4kb       |  2.6580000 | ±0.0280650 |    60 |
| brickell_split_4kb                       |  0.9971000 | ±0.0045170 |    60 |
| brickell_reconstruct_4kb                 |  2.6630000 | ±0.0073400 |   150 |
| massey_split_4kb                         |  0.7878000 | ±0.0061800 |    32 |
| massey_reconstruct_4kb                   |  1.1900000 | ±0.0071800 |    44 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0017400 | ±0.0000102 |    60 |
| shamir_reconstruct_2_3                   |  0.0041840 | ±0.0000380 |    32 |
| shamir_split_3_5                         |  0.0038880 | ±0.0000266 |    32 |
| shamir_reconstruct_3_5                   |  0.0076770 | ±0.0000438 |    30 |
| shamir_split_5_9                         |  0.0097530 | ±0.0000562 |    60 |
| shamir_reconstruct_5_9                   |  0.0165100 | ±0.0001690 |   210 |
| shamir_split_7_15                        |  0.0202200 | ±0.0001322 |    30 |
| shamir_reconstruct_7_15                  |  0.0304200 | ±0.0000949 |   150 |
| shamir_split_10_20                       |  0.0364400 | ±0.0002718 |    31 |
| shamir_reconstruct_10_20                 |  0.0589900 | ±0.0005165 |    69 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0088450 | ±0.0002170 |    61 |
| shamir_cold_reconstruct                  |  0.0205900 | ±0.0005515 |    30 |
| blakley_cold_split                       |  0.1114000 | ±0.0014470 |    36 |
| blakley_cold_reconstruct                 |  0.0450100 | ±0.0008685 |    30 |
| massey_cold_split                        |  0.0079430 | ±0.0001457 |    30 |
| massey_cold_reconstruct                  |  0.0134600 | ±0.0002334 |   125 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
