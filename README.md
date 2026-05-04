# secret-sharing

Threshold secret-sharing schemes implemented in pure, safe Rust directly
from their published specifications. The crate covers three papers in
`pubs/` and an additional eight schemes catalogued in
`bib/references.bib`:

| Paper | Year | What it gives us |
|-------|------|------------------|
| Shamir, *How to Share a Secret* | 1979 | The classical `(k, n)` polynomial threshold scheme |
| Karnin, Greene, Hellman, *On Secret Sharing Systems* | 1983 | Trivial `n`-of-`n` split, multi-secret extension, the matrix scheme `v_i = u·A_i` |
| McEliece, Sarwate, *On Sharing Secrets and Reed–Solomon Codes* | 1981 | Ramp (data-compressed) variant and errors-and-erasures recovery via Berlekamp–Welch |
| Blakley, *Safeguarding Cryptographic Keys* | 1979 | Geometric `(k, n)` threshold via random hyperplanes through a fixed point |
| Mignotte, *How to Share a Secret* | 1983 | CRT-based `(k, n)` (reconstruction-uniqueness, not perfectly secret) |
| Asmuth, Bloom, *A Modular Approach to Key Safeguarding* | 1983 | CRT-based `(k, n)` with information-theoretic secrecy |
| Rabin, *Efficient Dispersal of Information…* | 1989 | Reed–Solomon-style information dispersal (erasure coding, not secret sharing) |
| Yamamoto, *Secret Sharing System Using `(k, L, n)`* | 1986 | Generalised ramp scheme spanning Shamir (`L=1`) and McEliece–Sarwate (`L=k`) |
| Ito, Saito, Nishizeki, *Secret Sharing Scheme Realising General Access Structure* | 1989 | Cumulative-array realisation of any monotone access structure |
| Benaloh, Leichter, *Generalised Secret Sharing and Monotone Functions* | 1988 | Recursive distribution along a monotone Boolean formula |
| Rabin, Ben-Or, *Verifiable Secret Sharing and Multiparty Protocols* | 1989 | Information-theoretic VSS via bivariate polynomials with cross-checks |
| Kothari, *Generalized Linear Threshold Scheme* | 1984 | Linear `(k, n)` over any user-supplied k×n matrix with the spreading property |
| Brickell, *Some Ideal Secret Sharing Schemes* | 1989 | Ideal vector-space SSS — one field-element per player |
| Karchmer, Wigderson, *On Span Programs* | 1993 | Monotone span programs — captures every linear SSS |
| Massey, *Minimal Codewords and Secret Sharing* | 1993 | Linear-code SSS — secret = column 0 of a generator matrix |
| Naor, Shamir, *Visual Cryptography* | 1994 | `(n, n)` scheme on black/white images; reconstruction by stacking |
| Blakley, Meadows, *Security of Ramp Schemes* | 1984 | `(k, L, n)` ramp generalisation of Blakley's hyperplane scheme |
| Chor, Goldwasser, Micali, Awerbuch, *Verifiable Secret Sharing* | 1985 | Computational VSS via discrete-log (Feldman) commitments |
| Herzberg, Jarecki, Krawczyk, Yung, *Proactive Secret Sharing* | 1995 | Periodic refresh of Shamir shares + lost-share recovery |

All polynomial and big-integer arithmetic runs over the `BigUint` /
`Csprng` / `mod_inverse` / `random_below` primitives from the sibling
[`cryptography`](../cryptography) crate (`path = "../cryptography"`).

## Threshold model

A *(k, n) threshold scheme* splits a secret `s` into `n` *shares* such that

1. **Recoverability:** any `k` shares reconstruct `s`,
2. **Secrecy:** any `k − 1` shares reveal nothing — every candidate value of
   `s` remains equally likely (information-theoretic security).

`k = 1` is forbidden everywhere in this crate, since a degree-zero
polynomial would distribute the secret in plaintext.

## Modules

```
secret_sharing
├── field             PrimeField over BigUint; mersenne127 / mersenne521 helpers
├── poly              Horner evaluation, Lagrange interpolation
├── trivial           KGH §I additive (and XOR) n-of-n split
├── shamir            Shamir 1979 (k, n) + KGH §IV multi-secret extension
├── bytes             Chunked byte-string Shamir with a versioned wire format
├── kgh               KGH §II matrix scheme v_i = u·A_i for vector secrets
├── ramp              McEliece–Sarwate ramp / data-compressed Reed–Solomon
├── decode            McEliece–Sarwate errors-and-erasures via Berlekamp–Welch
├── blakley           Blakley 1979 hyperplane (k, n) threshold
├── mignotte          Mignotte 1983 CRT (k, n) — reconstruction-uniqueness
├── asmuth_bloom      Asmuth–Bloom 1983 modular CRT (k, n) — perfectly secret
├── ida               Rabin 1989 Information Dispersal (erasure coding, no secrecy)
├── yamamoto          Yamamoto 1986 (k, L, n) ramp — generalises Shamir & MS-ramp
├── ito               Ito–Saito–Nishizeki 1989 cumulative-array general access
├── benaloh_leichter  Benaloh–Leichter 1988 monotone-formula scheme
├── kothari           Kothari 1984 generalised linear (k, n)
├── karchmer_wigderson Karchmer–Wigderson 1993 monotone span programs
├── brickell          Brickell 1989 ideal vector-space SSS
├── massey            Massey 1993 linear-code SSS via minimal codewords
├── visual            Naor–Shamir 1994 visual cryptography (n, n)
├── blakley_meadows   Blakley–Meadows 1984 (k, L, n) hyperplane ramp
├── vss               Rabin–Ben-Or 1989 bivariate-polynomial VSS
├── cgma_vss          Chor–Goldwasser–Micali–Awerbuch 1985 Feldman-style VSS
├── proactive         Herzberg et al. 1995 share refresh + lost-share recovery
├── bigint            Self-contained big integer (BigUint) + Montgomery
├── csprng            Csprng trait + ChaCha20Rng (RFC 7539)
└── primes            gcd, mod_inverse, random_below
```

## How each scheme works

### `trivial` — n-of-n additive split (KGH §I)

Pick `v_1, …, v_{n-1}` uniformly at random in `[0, p)`, then set

```
v_n = s − (v_1 + v_2 + … + v_{n-1})  (mod p)
```

so that `Σ v_i = s (mod p)`. Reconstruction is the sum. The XOR variant
is the `q = 2` special case applied byte-wise. There is no `k < n`
threshold — every share is required.

### `shamir` — (k, n) polynomial threshold scheme (Shamir 1979)

Choose a random degree-`(k − 1)` polynomial

```
q(x) = a_0 + a_1·x + a_2·x^2 + … + a_{k-1}·x^{k-1},   a_0 = s
```

over `GF(p)`. Trustee `i ∈ {1, …, n}` is given `(i, q(i) mod p)`. Any
`k` shares interpolate `q(x)` (Lagrange), and `s = q(0)`. Knowledge of
`k − 1` or fewer shares leaves the secret uniformly distributed.

### `shamir::split_multi` — multi-secret extension (KGH §IV)

Pack `ℓ ≤ k` secrets into the lowest-order coefficients:

```
q(x) = s_0 + s_1·x + … + s_{ℓ-1}·x^{ℓ-1} + u_ℓ·x^ℓ + … + u_{k-1}·x^{k-1}
```

with `u_ℓ, …, u_{k-1}` uniform random padding. Any `k` trustees recover
all `ℓ` secrets simultaneously; any `k − 1` trustees learn nothing
about any single secret.

### `kgh` — matrix scheme `v_i = u·A_i` for vector secrets (KGH §II)

Generalize the secret to a length-`m` vector `s ∈ GF(p)^m`. Form the
internal vector `u = (s, u_1, …, u_{k-1})`, where each `u_j` is a
length-`m` block of independent uniform field elements. Trustee `i`
receives the vector share `v_i = u·A_i` where the `A_i` are public
`km × m` matrices, every `k`-subset of which has full rank. The crate
instantiates the public matrix bank with the Vandermonde construction
from KGH eq. (16): equivalently, each component runs an independent
Shamir polynomial in `α_i = i`.

### `bytes` — chunked byte-string Shamir

Real secrets are byte strings (AES keys, passphrases, files), not single
field elements. The `bytes` module chunks the secret into
`block_len = (p.bits() − 1) / 8` byte blocks, runs an independent Shamir
polynomial per block, and serializes each share with the wire format

```
version : u8         = 0x01
label   : u8         = trustee index 1..=255
length  : u32 (BE)   = byte-length of the original secret
blocks  : [u8; ...]  = concatenated big-endian field-element blocks
```

`share_elem_len = ⌈p.bits() / 8⌉` bytes are used to serialize each
field element so that no high byte is ever truncated (16 bytes for
`2^127 − 1`, even though plaintext blocks are 15 bytes).

### `ramp` — McEliece–Sarwate ramp scheme

The secret is now `k` field elements `(b_1, …, b_k)`. Find the unique
degree-`(k − 1)` polynomial `P(x)` with `P(j) = b_j` for `j = 1..k`,
and distribute `(k + i, P(k + i))` for `i = 1..n`. Any `k` shares
interpolate `P` and reconstruct every `b_j`. Per-trustee payload is
one field element regardless of secret length — `k×` smaller than the
secret. The trade-off is that an opponent with `k − 1` shares narrows
the secret to one of `p` candidates rather than `p^k`.

### `decode` — Berlekamp–Welch errors-and-erasures recovery

McEliece–Sarwate observed that Shamir's scheme is a Reed–Solomon code,
so the standard errors-and-erasures decoders apply. Given `m` shares,
of which up to `t` may have been tampered with, the secret can still be
recovered whenever

```
m − 2t ≥ k.
```

This crate implements **Berlekamp–Welch**: find polynomials `Q(x)` of
degree `< k + t` and `E(x)` of degree `≤ t`, with `E ≢ 0`, such that
`Q(x_i) = y_i · E(x_i)` for every share. Solve as a homogeneous linear
system over `GF(p)`, polynomial-divide `Q / E` to recover the original
message polynomial `M(x)`, and read `s = M(0)`. Erasures are handled by
simply not supplying the lost share — the agreement bound applies to
whatever shares remain.

### `blakley` — geometric `(k, n)` threshold (Blakley 1979)

Pick a random point `P = (s, r_1, …, r_{k−1}) ∈ GF(p)^k` whose first
coordinate is the secret. Each share is a random hyperplane through `P`:
`a_1 y_1 + … + a_{k−1} y_{k−1} + y_k = b` with `b` chosen so the
equation holds at `P`. Any `k` shares solve a linear system for `P` and
read off `s`; any `k − 1` shares cut a one-dimensional line of
candidates uniformly distributed over `GF(p)`.

### `mignotte` — CRT-based `(k, n)` (Mignotte 1983)

A *Mignotte sequence* is `m_1 < m_2 < … < m_n` pairwise coprime with
`α := ∏(k − 1 largest) < β := ∏(k smallest)`. The secret `S ∈ (α, β)`
is shared as `(m_i, S mod m_i)`. Any `k` residues CRT-determine `S`
uniquely in `[0, ∏ m_{i_j}) ⊇ [0, β) ∋ S`. Mignotte gives reconstruction
uniqueness, *not* perfect secrecy: `k − 1` residues narrow the
candidates to roughly `(β − α) / ∏(those k − 1 moduli)` values.

### `asmuth_bloom` — modular CRT `(k, n)` (Asmuth–Bloom 1983)

Strengthens Mignotte with a public secret-modulus `m_0` (coprime with
each `m_i`) and the inequality `m_0 · M_top < M_bot`. The secret
`S < m_0` is masked as `y = S + A · m_0` for uniform `A ∈ [0, ⌊M_bot /
m_0⌋)` and shared as `(m_i, y mod m_i)`. CRT-recover `y`, then return
`y mod m_0`. The mask makes secrecy *information-theoretic*:
`k − 1` shares leave `S` uniformly distributed over `[0, m_0)`.

### `ida` — Rabin Information Dispersal (Rabin 1989)

**Not** a secret-sharing scheme. Encode a file `F` as Reed–Solomon
codewords (each polynomial coefficient = `bl` bytes of `F`) and
distribute one evaluation per `(k − 1)`-degree polynomial per trustee.
Per-share storage is `|F|/k` bytes; any `k` shares reconstruct `F`;
fewer than `k` reveal nothing useful, but `k` *of any provenance* will
reconstruct, including a colluding majority that holds no secret. Use
when load-balancing or erasure tolerance is the goal and secrecy isn't.

### `yamamoto` — `(k, L, n)` ramp (Yamamoto 1986)

The secret is `(s_1, …, s_L) ∈ GF(p)^L` with `1 ≤ L ≤ k`. Pick the
unique degree-`(k − 1)` polynomial `P` such that `P(j) = s_j` for
`j = 1..L` and `P(j) = u_j` (uniform random) for `j = L+1..k`.
Distribute `P(k + 1), …, P(k + n)`. Any `k` shares interpolate `P`
and read every `s_j`; any `k − L` shares reveal nothing; intermediate
counts leak proportional information by Yamamoto's analysis. The
`L = 1` case is Shamir; `L = k` is McEliece–Sarwate ramp.

### `ito` — general access structure (Ito–Saito–Nishizeki 1989)

Realise *any* monotone access structure `A`. The user supplies the
maximal forbidden coalitions `F_1, …, F_t` (`Q ∈ A ⇔ ∀i, Q ⊄ F_i`).
Choose `r_1, …, r_{t−1}` uniform with `r_t = s − Σ r_i (mod p)`;
player `j` holds `{(i, r_i) : j ∉ F_i}`. A qualified coalition covers
every `i`, so summing the `r_i` recovers `s`. Per-player share size is
the number of `F_i` not containing `j` — exponential in the worst case
but appropriate for arbitrary monotone structures.

### `benaloh_leichter` — monotone-formula scheme (Benaloh–Leichter 1988)

Distribute the secret along a monotone Boolean formula tree:

- AND nodes additively split the value among children (random shares
  summing to the value).
- OR nodes hand each child the same value.
- Leaves go to the labelled party.

Reconstruction walks the formula bottom-up: AND requires every child to
recover (sum); OR succeeds as soon as any child recovers. Per-party
share size is the number of leaves labelled with that party — small
when the formula is succinct.

### `vss` — bivariate-polynomial VSS (Rabin–Ben-Or 1989)

Information-theoretic verifiable secret sharing. Sample a bivariate
polynomial `F(x, y)` of degree `≤ k − 1` in each variable with
`F(0, 0) = s`. Player `i` receives `g_i(y) = F(i, y)` and
`h_i(x) = F(x, i)`. Pairwise cross-checks
`g_i(j) ?= h_j(i)` (in both directions) catch any tampered slice with
probability 1. Reconstruction Lagrange-interpolates `Φ(x) = F(x, 0)`
from `g_i(0)` for `k` consistent players, then reads `s = Φ(0)`.

## Usage

### Add the dependency

```toml
[dependencies]
secret-sharing = { path = "path/to/secret-sharing" }
cryptography   = { path = "path/to/cryptography" }
```

### Shamir over `GF(2^127 − 1)`

```rust
use secret_sharing::field::{mersenne127, PrimeField};
use secret_sharing::{shamir, BigUint};
use cryptography::CtrDrbgAes256;

let field = PrimeField::new(mersenne127());
let mut rng = CtrDrbgAes256::new(&[0x42u8; 48]);
let secret = BigUint::from_u64(0xC0FFEE);

let shares = shamir::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/5);
let recovered = shamir::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

### Byte-string Shamir for an AES key

```rust
use secret_sharing::bytes;
use secret_sharing::field::{mersenne127, PrimeField};
use cryptography::CtrDrbgAes256;

let field = PrimeField::new(mersenne127());
let mut rng = CtrDrbgAes256::new(&[0xA5u8; 48]);
let aes_key = b"32-byte AES-256 key payload!!!!!";

let shares = bytes::split(&field, &mut rng, aes_key, /*k=*/3, /*n=*/5);
let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
let recovered = bytes::reconstruct(&field, &refs[..3], 3).unwrap();
assert_eq!(recovered, aes_key.to_vec());
```

### Robust reconstruction in the presence of tampering

```rust
use secret_sharing::decode::reconstruct_with_errors;
use secret_sharing::field::{mersenne127, PrimeField};
use secret_sharing::{shamir, BigUint};
use cryptography::CtrDrbgAes256;

let field = PrimeField::new(mersenne127());
let mut rng = CtrDrbgAes256::new(&[0x5Au8; 48]);
let secret = BigUint::from_u64(0xDECAF);

// k = 4, n = 11 — survives up to t = 3 tampered shares (m − 2t = 5 ≥ k).
let mut shares = shamir::split(&field, &mut rng, &secret, 4, 11);
shares[2].y = field.add(&shares[2].y, &BigUint::from_u64(1));
shares[5].y = BigUint::zero();
shares[9].y = field.add(&shares[9].y, &BigUint::from_u64(99));

let recovered = reconstruct_with_errors(&field, &shares, 4, 3).unwrap();
assert_eq!(recovered, secret);
```

### Multi-secret pack

```rust
use secret_sharing::field::{mersenne127, PrimeField};
use secret_sharing::{shamir, BigUint};
use cryptography::CtrDrbgAes256;

let field = PrimeField::new(mersenne127());
let mut rng = CtrDrbgAes256::new(&[0x77u8; 48]);
let secrets: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(900 + i)).collect();

let shares = shamir::split_multi(&field, &mut rng, &secrets, /*k=*/4, /*n=*/7);
let got = shamir::reconstruct_multi(&field, &shares[..4], 4, secrets.len()).unwrap();
assert_eq!(got, secrets);
```

### Ramp / data-compressed variant

```rust
use secret_sharing::field::{mersenne127, PrimeField};
use secret_sharing::{ramp, BigUint};

let field = PrimeField::new(mersenne127());
let secret: Vec<BigUint> = (0..5).map(|i| BigUint::from_u64(0x1000 + i)).collect();
let shares = ramp::split(&field, &secret, /*n=*/8);
let recovered = ramp::reconstruct(&field, &shares[..5], secret.len()).unwrap();
assert_eq!(recovered, secret);
```

### Vector secrets via the KGH matrix scheme

```rust
use secret_sharing::field::{mersenne127, PrimeField};
use secret_sharing::{kgh, BigUint};
use cryptography::CtrDrbgAes256;

let field = PrimeField::new(mersenne127());
let mut rng = CtrDrbgAes256::new(&[0x33u8; 48]);
let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(0x100 + i)).collect();

let shares = kgh::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/6);
let recovered = kgh::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

## Testing and lints

```sh
cargo test                                       # 136 tests
cargo clippy --all-targets -- -D warnings        # clean
```

## Choosing a field

The crate is generic over the prime modulus. Two convenience fields:

| Function | Modulus | Plaintext block | Share-element width |
|----------|---------|-----------------|---------------------|
| `field::mersenne127()` | `2^127 − 1` | 15 bytes | 16 bytes |
| `field::mersenne521()` | `2^521 − 1` | 65 bytes | 66 bytes |

Any user-supplied prime works as well — `PrimeField::new(p)` accepts an
arbitrary `BigUint`. The caller is responsible for choosing a value that
is genuinely prime and large enough to comfortably exceed `n`.

## Design notes

- **Variable-time arithmetic.** `BigUint` from the sibling `cryptography`
  crate is documented as variable-time. This crate inherits that
  property; do not use it in side-channel-exposed environments.
- **No allocation-free path.** Polynomials and matrices use plain
  `Vec<BigUint>`. Performance is dominated by big-integer modular
  multiplication, not by allocator overhead.
- **No serialization beyond `bytes`.** Other modules return native
  `BigUint` shares; serialize via `BigUint::to_be_bytes()` if needed.
- **No constant-time bounds checking.** Every entry point validates its
  inputs and returns `Option<...>` (or `None`) on contract violations
  by inputs that the caller may not have controlled (corrupt shares,
  malformed wire format, duplicate `x` coordinates). Static contract
  violations (e.g. `k < 2`) panic.
