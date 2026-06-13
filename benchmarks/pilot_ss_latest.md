# pilot_ss sweep — Apple M4 Pro (arm64, macOS) — local

_preset `quick` (95% CI ≤ 20% of mean, ≥30 samples); `PILOT_SS_ITERS_PERCENT=25`._

### Threshold (k=3, n=5, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split                             |  0.0029960 | ±0.0000517 |    60 |
| shamir_reconstruct                       |  0.0062530 | ±0.0000834 |    36 |
| blakley_split                            |  0.1295000 | ±0.0008800 |    86 |
| blakley_reconstruct                      |  0.0591000 | ±0.0014485 |    30 |
| kothari_split                            |  0.0031540 | ±0.0000876 |    30 |
| kothari_reconstruct                      |  0.0062840 | ±0.0001566 |    30 |
| karchmer_wigderson_split                 |  0.0035810 | ±0.0001213 |    32 |
| karchmer_wigderson_reconstruct           |  0.0090330 | ±0.0001816 |    30 |
| brickell_split                           |  0.0035530 | ±0.0000673 |    46 |
| brickell_reconstruct                     |  0.0115600 | ±0.0003062 |   242 |
| massey_split                             |  0.0035230 | ±0.0000464 |    41 |
| massey_reconstruct                       |  0.0053470 | ±0.0001290 |   240 |

### Ramp / vector (k=3, L=k or L=k−1, n=5)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| ramp_split                               |  0.0377700 | ±0.0007120 |    92 |
| ramp_reconstruct                         |  0.0256300 | ±0.0004151 |    37 |
| yamamoto_split                           |  0.0440000 | ±0.0006850 |   124 |
| yamamoto_reconstruct                     |  0.0272800 | ±0.0005685 |    60 |
| blakley_meadows_split                    |  0.1500000 | ±0.0004467 |   125 |
| blakley_meadows_reconstruct              |  0.0701700 | ±0.0011825 |    32 |
| kgh_split                                |  0.0188100 | ±0.0004132 |    30 |
| kgh_reconstruct                          |  0.0230400 | ±0.0002131 |    30 |

### Verifiable secret sharing

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| vss_split                                |  0.0220800 | ±0.0004466 |    90 |
| vss_reconstruct                          |  0.0186000 | ±0.0003678 |    51 |
| cgma_vss_split                           |  1.4370000 | ±0.0672500 |    40 |
| cgma_vss_reconstruct                     | 13.2100000 | ±0.5145000 |    30 |

### CRT (small example sequences)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| mignotte_split                           |  0.0002930 | ±0.0000056 |   115 |
| mignotte_reconstruct                     |  0.0019300 | ±0.0000520 |    30 |
| mignotte_reconstruct_large               |  0.0151700 | ±0.0001425 |    60 |
| asmuth_bloom_split                       |  0.0004245 | ±0.0000104 |    70 |
| asmuth_bloom_reconstruct                 |  0.0021290 | ±0.0000683 |    30 |

### Other / convenience schemes

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| trivial_split                            |  0.0006598 | ±0.0000110 |    62 |
| trivial_reconstruct                      |  0.0001783 | ±0.0000032 |    43 |
| ito_split                                |  0.0025330 | ±0.0000415 |    44 |
| ito_reconstruct                          |  0.0007885 | ±0.0000107 |   115 |
| benaloh_leichter_split                   |  0.0013020 | ±0.0000181 |    90 |
| benaloh_leichter_reconstruct             |  0.0005541 | ±0.0000114 |    30 |
| proactive_refresh                        |  0.0186400 | ±0.0003309 |    30 |
| proactive_recover                        |  0.0077290 | ±0.0001040 |    61 |
| bytes_split_16                           |  0.0082090 | ±0.0001759 |    77 |
| bytes_reconstruct_16                     |  0.0171200 | ±0.0004035 |    30 |
| ida_split_16                             |  0.0039130 | ±0.0000631 |    30 |
| ida_reconstruct_16                       |  0.0097810 | ±0.0001752 |    30 |
| decode_reconstruct_t1                    |  0.0873000 | ±0.0020565 |    60 |

### Visual cryptography (n=3, 8×8 image)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| visual_split_3_8                         |  0.0103600 | ±0.0002191 |    30 |
| visual_decode_3_8                        |  0.0013640 | ±0.0000102 |    86 |

### 4 KiB block (k=3, n=5, GF(2^127 − 1), 274 × 15-byte chunks)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_4kb                         |  0.9957000 | ±0.0227000 |    31 |
| shamir_reconstruct_4kb                   |  2.0040000 | ±0.0412500 |    60 |
| blakley_split_4kb                        | 40.5500000 | ±0.1222000 |   180 |
| blakley_reconstruct_4kb                  | 23.0400000 | ±0.1534500 |   243 |
| kothari_split_4kb                        |  0.8875000 | ±0.0183550 |    30 |
| kothari_reconstruct_4kb                  |  1.8770000 | ±0.0445850 |    46 |
| karchmer_wigderson_split_4kb             |  1.0270000 | ±0.0203650 |    30 |
| karchmer_wigderson_reconstruct_4kb       |  2.5950000 | ±0.0754500 |    30 |
| brickell_split_4kb                       |  0.9750000 | ±0.0193900 |    31 |
| brickell_reconstruct_4kb                 |  2.7330000 | ±0.0514000 |    30 |
| massey_split_4kb                         |  0.9241000 | ±0.0201600 |   103 |
| massey_reconstruct_4kb                   |  1.3090000 | ±0.0328700 |    74 |

### Threshold (k, n) sweep (Shamir, GF(2^127 − 1))

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_split_2_3                         |  0.0018450 | ±0.0000308 |   197 |
| shamir_reconstruct_2_3                   |  0.0053250 | ±0.0000956 |    35 |
| shamir_split_3_5                         |  0.0039600 | ±0.0000741 |    51 |
| shamir_reconstruct_3_5                   |  0.0090650 | ±0.0001354 |    41 |
| shamir_split_5_9                         |  0.0107800 | ±0.0002913 |    30 |
| shamir_reconstruct_5_9                   |  0.0170400 | ±0.0010180 |    34 |
| shamir_split_7_15                        |  0.0253200 | ±0.0006985 |    90 |
| shamir_reconstruct_7_15                  |  0.0345500 | ±0.0009525 |    91 |
| shamir_split_10_20                       |  0.0364700 | ±0.0008500 |   120 |
| shamir_reconstruct_10_20                 |  0.0674900 | ±0.0011585 |   364 |

### Cold-cache first-iteration latency (one op per fresh process)

| Operation                                |   ms/op    | ±CI (95%)  | Runs  |
|------------------------------------------|------------|------------|-------|
| shamir_cold_split                        |  0.0078590 | ±0.0001233 |    71 |
| shamir_cold_reconstruct                  |  0.0191000 | ±0.0006085 |    33 |
| blakley_cold_split                       |  0.2140000 | ±0.0056800 |    46 |
| blakley_cold_reconstruct                 |  0.0886000 | ±0.0022090 |    30 |
| massey_cold_split                        |  0.0082890 | ±0.0001090 |    53 |
| massey_cold_reconstruct                  |  0.0121800 | ±0.0002015 |    31 |

Generated by `scripts/bench_pilot.sh` (preset: quick).
