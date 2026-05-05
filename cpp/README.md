# secret_sharing — C++ port

Bit-compatible C++23 port of the Rust `secret_sharing` crate at the
repository root. Same wire formats, same byte-stream outputs from
`ChaCha20Rng`, same Mersenne-127 fast path on `prime_field::mul`,
same Lagrange round-trip on Shamir shares. The cross-language
contract is exercised in `test/test_compat.cpp` against test
vectors emitted by `cargo run --release --example dump_compat_vectors`.

## Scope

Mirrors the foundations + the most-used scheme:

- `big_uint` — multiprecision integers, little-endian `u64` limb
  vector, schoolbook + Karatsuba multiply, `mod_mul` dispatched
  through `montgomery_ctx` for odd moduli, byte-encoded round-trip
  identical to Rust's `to_be_bytes` / `from_be_bytes`.
- `chacha20_rng` — RFC 7539 conformant CSPRNG, RFC test vectors
  pinned in `test/test_csprng.cpp`.
- `prime_field` — generic field with Mersenne-127 fast path
  (closed-form fold, no Montgomery setup) selected at construction.
- `poly` — Horner evaluation, Lagrange interpolation.
- `shamir::split` / `shamir::reconstruct` — same `(x, y)` share
  layout, same extras-validation contract as the Rust impl.

The remaining schemes (Blakley, Karchmer–Wigderson, Brickell, Massey,
ramp/Yamamoto, VSS, etc.) are not ported in this commit. Adding a
scheme is one source pair plus a fuzz target.

## Build / test

```bash
cmake -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Lint, fuzz, infer

```bash
# clang-tidy across all sources, treating warnings as errors.
./scripts/lint.sh

# libFuzzer for 30 seconds against fuzz_field. Other targets:
# fuzz_bigint, fuzz_shamir. Requires LLVM clang (libFuzzer runtime
# is not shipped with Apple clang); install with `brew install llvm`
# and prepend its bin/ to PATH before running.
./scripts/fuzz.sh fuzz_field 30

# Facebook Infer (requires `infer` on PATH).
./scripts/infer.sh
```

## Sanitizers

```bash
cmake -B build-asan -DSANITISE=address-undefined
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

The build flags `-DSANITISE=...` for `address`, `undefined`,
`address-undefined`, `thread`, or `memory`.

## Cross-language vector regeneration

The vectors in `test/test_compat.cpp` are produced by the Rust
example at the repo root. To regenerate after intentional Rust
changes:

```bash
# from the repo root:
cargo run --release --example dump_compat_vectors
```

Copy the output values into the constexpr arrays in
`test/test_compat.cpp`. Any divergence between Rust output and the
committed vectors causes `compat.*` tests to fail loudly.

## Performance

The bench target `pilot_ss_cpp` exposes the same operation interface
as the Rust `pilot_ss` binary so pilot-bench can drive both with a
single harness (see `cpp/scripts/bench_compare.sh`). Coverage today
is `shamir_split`, `shamir_reconstruct`, and the `*_4kb` variants.

## Licence

BSD 2-Clause. See [`../LICENSE`](../LICENSE).
