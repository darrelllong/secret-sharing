
### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0033640 | ±0.0000766 |    60 |
| shamir_reconstruct                       |  0.0061720 | ±0.0000358 |   158 |
| blakley_split                            |  0.0510300 | ±0.0008230 |   122 |
| blakley_reconstruct                      |  0.0274200 | ±0.0003353 |    30 |
| kothari_split                            |  0.0030960 | ±0.0000356 |    36 |
| kothari_reconstruct                      |  0.0065410 | ±0.0000752 |    30 |
| karchmer_wigderson_split                 |  0.0033670 | ±0.0000374 |    46 |
| karchmer_wigderson_reconstruct           |  0.0090120 | ±0.0000756 |    31 |
| brickell_split                           |  0.0034070 | ±0.0000475 |    39 |
| brickell_reconstruct                     |  0.0091170 | ±0.0000570 |    60 |
| massey_split                             |  0.0025640 | ±0.0000213 |    88 |
| massey_reconstruct                       |  0.0042710 | ±0.0000250 |   149 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0289700 | ±0.0002482 |    90 |
| ramp_reconstruct                         |  0.0199300 | ±0.0002346 |    30 |
| yamamoto_split                           |  0.0286400 | ±0.0003727 |    30 |
| yamamoto_reconstruct                     |  0.0198300 | ±0.0001453 |    90 |
| blakley_meadows_split                    |  0.0510100 | ±0.0005310 |    30 |
| blakley_meadows_reconstruct              |  0.0306200 | ±0.0004203 |    30 |
| kgh_split                                |  0.0169000 | ±0.0002634 |    51 |
| kgh_reconstruct                          |  0.0192900 | ±0.0001769 |    46 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0190300 | ±0.0002671 |    33 |
| vss_reconstruct                          |  0.0143400 | ±0.0001445 |    30 |
| cgma_vss_split                           |  0.9360000 | ±0.0034570 |    60 |
| cgma_vss_reconstruct                     |  8.0480000 | ±0.0288100 |    31 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002588 | ±0.0000027 |   120 |
| mignotte_reconstruct                     |  0.0011250 | ±0.0000108 |    30 |
| mignotte_reconstruct_large               |  0.0013680 | ±0.0000058 |    30 |
| asmuth_bloom_split                       |  0.0003658 | ±0.0000041 |    30 |
| asmuth_bloom_reconstruct                 |  0.0012480 | ±0.0000244 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0005808 | ±0.0000049 |   120 |
| trivial_reconstruct                      |  0.0001559 | ±0.0000035 |    60 |
| ito_split                                |  0.0022380 | ±0.0000245 |    30 |
| ito_reconstruct                          |  0.0007043 | ±0.0000122 |    30 |
| benaloh_leichter_split                   |  0.0011830 | ±0.0000096 |    68 |
| benaloh_leichter_reconstruct             |  0.0005094 | ±0.0000059 |    60 |
| proactive_refresh                        |  0.0156000 | ±0.0002232 |    42 |
| proactive_recover                        |  0.0063940 | ±0.0000364 |    60 |
| bytes_split_16                           |  0.0068120 | ±0.0000766 |    33 |
| bytes_reconstruct_16                     |  0.0127600 | ±0.0001392 |    60 |
| ida_split_16                             |  0.0031740 | ±0.0000452 |    60 |
| ida_reconstruct_16                       |  0.0081270 | ±0.0001181 |    30 |
| decode_reconstruct_t1                    |  0.0696600 | ±0.0003395 |    30 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0084050 | ±0.0001295 |    30 |
| visual_decode_3_8                        |  0.0010550 | ±0.0000044 |    90 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.7859000 | ±0.0089800 |    30 |
| shamir_reconstruct_4kb                   |  1.4800000 | ±0.0094550 |    60 |
| blakley_split_4kb                        | 13.6300000 | ±0.1930500 |   150 |
| blakley_reconstruct_4kb                  |  7.0690000 | ±0.6850000 |    30 |
| kothari_split_4kb                        |  0.7570000 | ±0.0102750 |    60 |
| kothari_reconstruct_4kb                  |  1.5680000 | ±0.0127550 |    56 |
| karchmer_wigderson_split_4kb             |  0.8206000 | ±0.0092800 |    60 |
| karchmer_wigderson_reconstruct_4kb       |  2.1700000 | ±0.0101450 |   150 |
| brickell_split_4kb                       |  0.8155000 | ±0.0067650 |    60 |
| brickell_reconstruct_4kb                 |  2.2230000 | ±0.0094200 |    60 |
| massey_split_4kb                         |  0.6059000 | ±0.0111800 |    60 |
| massey_reconstruct_4kb                   |  0.9196000 | ±0.0092300 |    30 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0013890 | ±0.0000239 |    51 |
| shamir_reconstruct_2_3                   |  0.0033110 | ±0.0000724 |    30 |
| shamir_split_3_5                         |  0.0031000 | ±0.0000670 |    35 |
| shamir_reconstruct_3_5                   |  0.0063280 | ±0.0000698 |    60 |
| shamir_split_5_9                         |  0.0081510 | ±0.0000974 |    30 |
| shamir_reconstruct_5_9                   |  0.0134300 | ±0.0000816 |    47 |
| shamir_split_7_15                        |  0.0163700 | ±0.0001142 |   120 |
| shamir_reconstruct_7_15                  |  0.0252200 | ±0.0002049 |    39 |
| shamir_split_10_20                       |  0.0298100 | ±0.0001637 |    93 |
| shamir_reconstruct_10_20                 |  0.0488400 | ±0.0005960 |    30 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0074630 | ±0.0001175 |    62 |
| shamir_cold_reconstruct                  |  0.0164400 | ±0.0003144 |    60 |
| blakley_cold_split                       |  0.0890500 | ±0.0015985 |    30 |
| blakley_cold_reconstruct                 |  0.0378100 | ±0.0007085 |    30 |
| massey_cold_split                        |  0.0058700 | ±0.0001495 |    36 |
| massey_cold_reconstruct                  |  0.0106000 | ±0.0002724 |    60 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
