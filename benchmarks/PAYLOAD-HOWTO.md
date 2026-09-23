# Payload benchmarks with Pilot

Build `cargo build --release --bin pilot_payload` and a Release C++ tree with benchmarks enabled. Run `python3 scripts/bench_payload.py --output /absolute/results/path --cpu 4`. The default Pilot executable is `~/pilot-bench/build/cli/bench`; override with `--pilot`. Override `--cpp` when the C++ build directory is not `cpp/build`.

Each driver takes `METHOD split|reconstruct 64|1024`, checks a complete round trip, then prints milliseconds per payload. Each sample runs for at least 20 ms (or one complete operation if longer). Pilot's normal preset requests 50 subsession samples, a full 95% confidence-interval width within 10% of the mean, and autocorrelation within ±0.2. Latency uses Pilot's ordinary-value indicator, not its throughput-ratio indicator. The runner pins sequential measurements to one CPU and saves every command, raw Pilot export and session log. A timeout or nonconvergence is a failed measurement, never a zero latency.

C++ currently supplies only Shamir. The remaining C++ cells are `not_implemented`; charts must leave them missing. The existing `pilot_ss` interfaces remain available unchanged.

## Workloads

Both drivers use the same reproducible payload bytes `(73*i+41) mod 256` and ChaCha20 seed `[53;32]`. Field methods use GF(2^127−1), k=3 and n=5 unless listed below. The scalar payload is divided into 15-byte big-endian chunks: five chunks for 64 bytes and 69 for 1 KiB. One timed operation processes the entire payload. Input encoding, field/parameter construction, initial sharing for reconstruction, and validation are outside the timer; output allocation and destruction are included. These are arithmetic payload benchmarks, not network/wire-format throughput tests. Fixed benchmark randomness is never a production recommendation.

| Methods | Parameters / representation |
|---|---|
| Shamir, Blakley, Kothari, Karchmer–Wigderson, Brickell, Massey, Ito, Benaloh–Leichter | 3-of-5; Vandermonde threshold constructions where applicable; Benaloh–Leichter uses an OR of all ten 3-party AND clauses. |
| Ramp | Three field elements per vector, threshold 3; this deterministic dispersal construction does not hide all information below threshold. |
| Yamamoto, Blakley–Meadows | Two elements per vector, threshold 3. |
| KGH | Three elements per vector, threshold 3. |
| Vector methods | Last vector padded with zero elements; reported size remains the original payload length. |
| VSS | Bivariate dealing, k=3, n=5; reconstruction uses three shares. |
| CGMA VSS | RFC 5114 2048/256 group; 31-byte chunks; reconstruction includes verification of the three participating shares. |
| Mignotte | Five consecutive primes starting above 2^130, threshold 3; 15-byte chunks encoded as alpha+1+chunk. |
| Asmuth–Bloom | Same 131-bit CRT moduli, m0=2^127−1; 15-byte chunks. |
| Trivial / trivial XOR | 5-of-5 additive field sharing / native byte XOR sharing. |
| Bytes | Native framed Shamir byte API, 3-of-5. |
| IDA | Native byte dispersal API, 3-of-5; dispersal does not promise secrecy. |
| Visual | Every input byte becomes eight pixels; 3-of-3 visual sharing, including stack/decode for reconstruction. |

Different methods have different security guarantees and expansion. Their axis values describe these exact workloads, not interchangeable security services. Refresh, lost-share recovery and error correction are auxiliary protocols, not additional split/reconstruct methods in this payload sweep.

Render saved results with `python3 scripts/chart_payload.py /path/to/results /path/to/charts` (requires NumPy and Matplotlib). The charts use blue for Rust and orange for C++, and keep unsupported cells missing. See the [dennard results](dennard-20260923/README.md) for a complete run.
