# HOWTO — Using `secret-sharing`

Working, copy-pasteable examples for every scheme in the crate. Every
snippet compiles against `secret-sharing = { path = "..." }` with no
other dependencies.

For randomness the crate uses a ChaCha20 CSPRNG (RFC 7539), seeded
from operating-system entropy via [`OsRng`](src/csprng.rs):

```rust
use secret_sharing::{
    BigUint, ChaCha20Rng, PrimeField,
    csprng::OsRng,
    field::mersenne127,
};

fn fresh_rng() -> ChaCha20Rng {
    // Production: seed ChaCha20 from /dev/urandom via OsRng.
    let mut os = OsRng::new().expect("operating-system entropy unavailable");
    ChaCha20Rng::from_os_entropy(&mut os)
}

fn small_field() -> PrimeField {
    PrimeField::new(mersenne127())
}
```

**Tests and reproducible benches** may seed from a fixed byte array
via `ChaCha20Rng::from_seed(&[0x42u8; 32])` — the snippets below in
this document use the OS-entropy form to model real usage. If you only
have a hardware RNG or a non-`/dev/urandom` platform, implement the
[`Csprng`](src/csprng.rs) trait yourself; that trait is the boundary,
not the bundled `ChaCha20Rng`.

## Pick the right scheme

| You want | Use |
|----------|-----|
| Threshold `(k, n)` over field elements | `shamir` |
| Threshold `(k, n)` for byte strings | `bytes` |
| Geometric variant (hyperplanes) | `blakley` |
| `(k, n)` without polynomials, using CRT | `mignotte` (uniqueness) or `asmuth_bloom` (statistical secrecy) |
| Erasure coding of a file (no secrecy) | `ida` |
| Vector secret with data compression | `ramp`, `kgh`, `yamamoto`, `blakley_meadows` |
| Reed–Solomon-style robust recovery | `decode` (Berlekamp–Welch) |
| Arbitrary monotone access structure | `ito` (cumulative) or `benaloh_leichter` (formula tree) |
| Linear scheme over user-supplied matrix | `kothari`, `karchmer_wigderson`, `brickell`, `massey` |
| Verifiable shares (info-theoretic) | `vss` |
| Verifiable shares (computational, smaller) | `cgma_vss` |
| Long-lived secret refreshed periodically | `proactive` |
| Secret picture you can decode by stacking | `visual` |
| Trivial `n`-of-`n` for testing | `trivial` |

---

## `shamir` — Shamir 1979 `(k, n)` polynomial threshold

```rust
use secret_sharing::{csprng::OsRng, shamir, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let shares = shamir::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/5);
let recovered = shamir::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

Multi-secret pack (`ℓ ≤ k` secrets share the same polynomial; KGH §IV):

```rust
use secret_sharing::{csprng::OsRng, shamir, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secrets: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(900 + i)).collect();

let shares = shamir::split_multi(&field, &mut rng, &secrets, /*k=*/4, /*n=*/7);
let got = shamir::reconstruct_multi(&field, &shares[..4], 4, secrets.len()).unwrap();
assert_eq!(got, secrets);
```

## `bytes` — byte-string Shamir

Real secrets are byte arrays (AES keys, passphrases, files). The
`bytes` module chunks a secret into field-sized blocks, runs Shamir per
block, and serialises each share with a self-describing header.

```rust
use secret_sharing::{csprng::OsRng, bytes, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let aes_key = b"32-byte AES-256 key payload!!!!!";

let shares = bytes::split(&field, &mut rng, aes_key, /*k=*/3, /*n=*/5);
let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
let recovered = bytes::reconstruct(&field, &refs[..3], 3).unwrap();
assert_eq!(recovered, aes_key.to_vec());
```

## `blakley` — geometric `(k, n)`

```rust
use secret_sharing::{csprng::OsRng, blakley, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let shares = blakley::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/5);
let recovered = blakley::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

## `mignotte` — CRT `(k, n)` with uniqueness recovery

```rust
use secret_sharing::{mignotte, BigUint};

// Bundled (3, 5) sequence over small primes; see source for the full
// validation rules.
let seq = mignotte::small_example_3_of_5();
// Secret must lie strictly inside (alpha, beta) = (437, 2431).
let secret = BigUint::from_u64(1234);
let shares = mignotte::split(&seq, &secret);
let recovered = mignotte::reconstruct(&seq, &shares[..3]).unwrap();
assert_eq!(recovered, secret);
```

To build your own sequence, use `MignotteSequence::new(moduli, k)` with
pairwise-coprime, strictly-increasing `moduli` satisfying `α < β`.

## `asmuth_bloom` — modular CRT `(k, n)`

```rust
use secret_sharing::{csprng::OsRng, asmuth_bloom, BigUint, ChaCha20Rng};

let params = asmuth_bloom::small_example_3_of_5();
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(2); // < m_0 = 5

let shares = asmuth_bloom::split(&params, &mut rng, &secret);
let recovered = asmuth_bloom::reconstruct(&params, &shares[..3]).unwrap();
assert_eq!(recovered, secret);
```

## `ida` — Rabin Information Dispersal

Erasure coding, **not** secret sharing — per-share is `|F|/k` bytes,
any `k` shares reconstruct, but `k` of any provenance suffice.

```rust
use secret_sharing::{ida, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let data = b"the quick brown fox jumps over the lazy dog".to_vec();
let shares = ida::split(&field, &data, /*k=*/3, /*n=*/5);
let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
let recovered = ida::reconstruct(&field, &refs[..3], 3).unwrap();
assert_eq!(recovered, data);
```

## `ramp` — McEliece–Sarwate ramp

Vector secret of `k` field elements; per-share payload is one field
element regardless of secret length.

```rust
use secret_sharing::{ramp, BigUint, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let secret: Vec<BigUint> = (0..5).map(|i| BigUint::from_u64(0x1000 + i)).collect();

let shares = ramp::split(&field, &secret, /*n=*/8);
let recovered = ramp::reconstruct(&field, &shares[..5], secret.len()).unwrap();
assert_eq!(recovered, secret);
```

## `decode` — Berlekamp–Welch errors-and-erasures recovery

```rust
use secret_sharing::decode::reconstruct_with_errors;
use secret_sharing::{csprng::OsRng, shamir, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xDECAF);

// k = 4, n = 11 — survives up to t = 3 tampered shares (m − 2t = 5 ≥ k).
let mut shares = shamir::split(&field, &mut rng, &secret, 4, 11);
shares[2].y = field.add(&shares[2].y, &BigUint::from_u64(1));
shares[5].y = BigUint::zero();
shares[9].y = field.add(&shares[9].y, &BigUint::from_u64(99));

let recovered = reconstruct_with_errors(&field, &shares, 4, 3).unwrap();
assert_eq!(recovered, secret);
```

## `kgh` — KGH §II matrix scheme for vector secrets

```rust
use secret_sharing::{csprng::OsRng, kgh, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(0x100 + i)).collect();

let shares = kgh::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/6);
let recovered = kgh::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

## `yamamoto` — `(k, L, n)` ramp

```rust
use secret_sharing::{csprng::OsRng, yamamoto, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(0x500 + i)).collect();

// k=5, L=3, n=8: any 5 shares recover all 3 secrets; ≤ 2 reveal nothing.
let shares = yamamoto::split(&field, &mut rng, &secret, /*k=*/5, /*n=*/8);
let recovered = yamamoto::reconstruct(&field, &shares[..5], 5, secret.len()).unwrap();
assert_eq!(recovered, secret);
```

## `blakley_meadows` — `(k, L, n)` Blakley ramp

```rust
use secret_sharing::{csprng::OsRng, blakley_meadows, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(0x100 + i)).collect();

// k=5, L=3, n=8: same threshold structure as yamamoto, geometric form.
let shares = blakley_meadows::split(&field, &mut rng, &secret, /*k=*/5, /*n=*/8);
let recovered = blakley_meadows::reconstruct(&field, &shares[..5], 5, secret.len()).unwrap();
assert_eq!(recovered, secret);
```

## `ito` — Ito–Saito–Nishizeki cumulative array

Realises any monotone access structure described by its maximal
forbidden coalitions.

```rust
use secret_sharing::{csprng::OsRng, ito, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64(65_537));
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());

// Custom access structure: {1,2}, {3,4}, {1,3} qualify.
// Maximal forbidden coalitions: {1,4}, {2,3}, {2,4}.
let structure = ito::AccessStructure::new(
    /*n=*/4,
    vec![vec![1, 4], vec![2, 3], vec![2, 4]],
).unwrap();

let secret = BigUint::from_u64(0xC0DE);
let shares = ito::split(&field, &mut rng, &secret, &structure);

// {1, 2} qualifies and recovers.
let coalition: Vec<_> = shares.iter()
    .filter(|s| matches!(s.player, 1 | 2))
    .cloned()
    .collect();
let recovered = ito::reconstruct(&field, &structure, &coalition).unwrap();
assert_eq!(recovered, secret);
```

For an `(k, n)` threshold rendered as ISN, use the helper:

```rust
use secret_sharing::ito::threshold_access_structure;
let structure = threshold_access_structure(/*n=*/5, /*k=*/3);
```

## `benaloh_leichter` — monotone formula tree

```rust
use secret_sharing::{csprng::OsRng, benaloh_leichter as bl, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64(65_537));
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());

// T = (P1 AND P2) OR (P1 AND P3) OR (P2 AND P3) — a 2-of-3 threshold.
let formula = bl::Formula::or(vec![
    bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(2)]),
    bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(3)]),
    bl::Formula::and(vec![bl::Formula::party(2), bl::Formula::party(3)]),
]);

let secret = BigUint::from_u64(0xBEEF);
let shares = bl::split(&field, &mut rng, &secret, &formula);

let pair: Vec<_> = shares.iter()
    .filter(|s| matches!(s.player, 1 | 2))
    .cloned()
    .collect();
let recovered = bl::reconstruct(&field, &formula, &pair).unwrap();
assert_eq!(recovered, secret);
```

## `kothari` — generalised linear `(k, n)`

User-supplied public matrix. Vandermonde convenience matches Shamir.

```rust
use secret_sharing::{csprng::OsRng, kothari, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64((1u64 << 61) - 1));
let scheme = kothari::vandermonde(field, /*k=*/3, /*n=*/5);
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xCAFE);

let shares = kothari::split(&scheme, &mut rng, &secret);
let pairs: Vec<_> = (0..3).map(|c| (c, shares[c].clone())).collect();
let recovered = kothari::reconstruct(&scheme, &pairs).unwrap();
assert_eq!(recovered, secret);
```

## `karchmer_wigderson` — monotone span programs

The most general linear-SSS framework. Threshold convenience:

```rust
use secret_sharing::{csprng::OsRng, karchmer_wigderson as kw, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64((1u64 << 61) - 1));
let prog = kw::threshold_msp(field, /*k=*/3, /*n=*/5);
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let shares = kw::split(&prog, &mut rng, &secret);
let coalition: Vec<_> = shares.iter()
    .filter(|s| matches!(s.player, 1 | 2 | 3))
    .cloned()
    .collect();
let recovered = kw::reconstruct(&prog, &coalition).unwrap();
assert_eq!(recovered, secret);
```

For a custom MSP, hand-build the `(rows, labels)` so that the row-set
of every qualified coalition spans the canonical target `e_1`.

## `brickell` — ideal vector-space SSS

One vector per player; per-player share is a single field element.

```rust
use secret_sharing::{csprng::OsRng, brickell, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64((1u64 << 61) - 1));
// Brickell's flagship example: realises an access structure where
// {1} qualifies alone, {2,3} qualifies, but {2} and {3} do not.
let v = vec![
    vec![BigUint::one(),  BigUint::zero()],     // v_1 = (1, 0)
    vec![BigUint::one(),  BigUint::one()],      // v_2 = (1, 1)
    vec![BigUint::one(),  BigUint::from_u64(2)],// v_3 = (1, 2)
    vec![BigUint::zero(), BigUint::one()],      // v_4 = (0, 1)
];
let scheme = brickell::Scheme::new(field, v);
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(33);

let shares = brickell::split(&scheme, &mut rng, &secret);
let solo_p1: Vec<_> = shares.iter()
    .filter(|s| s.player == 1)
    .cloned()
    .collect();
let recovered = brickell::reconstruct(&scheme, &solo_p1).unwrap();
assert_eq!(recovered, secret);
```

## `massey` — linear-code SSS via minimal codewords

```rust
use secret_sharing::{csprng::OsRng, massey, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64((1u64 << 61) - 1));
// Reed–Solomon-style (2, 3) Shamir as a Massey code:
// G is 2 × 4, column 0 is the secret slot, columns 1..3 are players.
let g = vec![
    vec![BigUint::one(),  BigUint::one(),  BigUint::one(),  BigUint::one()],
    vec![BigUint::zero(), BigUint::one(),  BigUint::from_u64(2), BigUint::from_u64(3)],
];
let scheme = massey::CodeScheme::new(field, g);
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let shares = massey::split(&scheme, &mut rng, &secret);
let pair: Vec<_> = shares.iter()
    .filter(|s| matches!(s.player, 1 | 2))
    .cloned()
    .collect();
let recovered = massey::reconstruct(&scheme, &pair).unwrap();
assert_eq!(recovered, secret);
```

## `vss` — Rabin–Ben-Or bivariate VSS (information-theoretic)

```rust
use secret_sharing::{csprng::OsRng, vss, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64((1u64 << 61) - 1));
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

// Honest-majority: 2(k − 1) < n. Helper:
assert!(vss::is_honest_majority(/*k=*/3, /*n=*/5));

let shares = vss::deal(&field, &mut rng, &secret, 3, 5);

// Pairwise cross-checks must pass before any share is used.
assert!(vss::verify_consistent(&field, &shares));

let recovered = vss::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

## `cgma_vss` — Chor-GMA computational VSS (Feldman commitments)

```rust
use secret_sharing::{csprng::OsRng, cgma_vss, BigUint, ChaCha20Rng};

// Production: supply your own (p, q, g) — RFC 3526 group 14 or
// equivalent. Toy group below for illustration only.
let group = cgma_vss::small_test_group();
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(7); // < q

let (shares, commits) = cgma_vss::deal(&group, &mut rng, &secret, /*k=*/3, /*n=*/5);

// Each receiver must verify before using their share.
for s in &shares {
    assert!(cgma_vss::verify_share(&group, &commits, s), "share {} valid", s.player);
}

let recovered = cgma_vss::reconstruct(&group, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

## `proactive` — Herzberg et al. share refresh

Refresh a Shamir share set without changing the underlying secret.
Old shares are no longer compatible with new shares — discard them.

```rust
use secret_sharing::{csprng::OsRng, proactive, shamir, BigUint, ChaCha20Rng, PrimeField};
use secret_sharing::field::mersenne127;

let field = PrimeField::new(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let mut shares = shamir::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/5);

// Epoch boundary: refresh.
shares = proactive::refresh(&field, &mut rng, &shares, 3);

// Same secret, different polynomial.
let recovered = shamir::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);

// Lost-share recovery: simulate losing player 3's share.
let lost_x = shares[2].x.clone();
let live = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
let recovered_share = proactive::recover_share(&field, &live, 3, &lost_x).unwrap();
assert_eq!(recovered_share, shares[2]);
```

## `visual` — Naor–Shamir visual cryptography (n, n)

Black-and-white image as `Vec<Vec<bool>>`; reconstruction by stacking
(bitwise OR) all `n` shares. Per-pixel expansion is `2^(n-1)`.

```rust
use secret_sharing::{csprng::OsRng, visual, ChaCha20Rng};

let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());

// 4×4 checkerboard.
let secret: Vec<Vec<bool>> = (0..4)
    .map(|y| (0..4).map(|x| (x + y) % 2 == 0).collect())
    .collect();

let shares = visual::split_n_of_n(&mut rng, &secret, /*n=*/2);
// Stack — physically, lay the transparencies on top of each other.
let stacked = visual::stack(&shares).unwrap();
let decoded = visual::decode(&stacked, /*n=*/2).unwrap();
assert_eq!(decoded, secret);
```

`n` is not stored alongside the shares — caller must persist it.

## `trivial` — `n`-of-`n` additive split

```rust
use secret_sharing::{csprng::OsRng, trivial, BigUint, ChaCha20Rng, PrimeField};

let field = PrimeField::new(BigUint::from_u64(65_537));
let mut rng = ChaCha20Rng::from_seed(&[7u8; 32]);
let secret = BigUint::from_u64(12_345);

let shares = trivial::split(&field, &mut rng, &secret, /*n=*/3);
let recovered = trivial::reconstruct(&field, &shares);
assert_eq!(recovered, secret);

// Byte-XOR variant (q = 2 special case):
let xor_shares = trivial::split_xor(&mut rng, b"my super secret payload", 3);
let recovered = trivial::reconstruct_xor(&xor_shares);
assert_eq!(recovered, b"my super secret payload".to_vec());
```

---

## Failure modes that return `None`

Every reconstruction function in this crate uses `Option<...>` rather
than panicking on caller-supplied bad input. A `None` means **one of**:

- fewer than `k` shares,
- duplicate / out-of-range share index or player,
- malformed wire bytes (for `bytes` and `ida`),
- extra shares (beyond the first `k`) inconsistent with the
  polynomial or matrix fitted to the first `k`,
- (CRT schemes) recovered value outside the legal secret range,
- (`vss`) any pairwise cross-check fails,
- (`cgma_vss`) commitment fails the discrete-log verification or lies
  outside the order-`q` subgroup.

Static contract violations (e.g. `k < 2`, `n < k`, secret ≥ field
modulus) panic via `assert!` — those are programmer errors, not
runtime failures.

## Picking a field

| Helper | Modulus | Plaintext block | Share-element width |
|--------|---------|-----------------|---------------------|
| `field::mersenne127()` | `2^127 − 1` | 15 bytes | 16 bytes |
| `field::mersenne521()` | `2^521 − 1` | 65 bytes | 66 bytes |

Any user-supplied prime works — `PrimeField::new(p)` accepts an
arbitrary `BigUint`. The caller is responsible for choosing a value
that is genuinely prime and large enough to comfortably exceed `n`.

## Threat model recap

- **Variable-time arithmetic.** `BigUint` is documented as variable-
  time; do not deploy in side-channel-exposed environments.
- **Honest dealer.** Most schemes (everything except `vss` and
  `cgma_vss`) trust the dealer. Use a VSS module if dealer integrity
  is in scope.
- **Tampering.** Naive Lagrange / linear-system reconstruction returns
  a wrong-but-plausible secret if exactly `k` shares are supplied and
  one is corrupted. Provide extras (`shares.len() > k`) so the
  validator can cross-check, or use `decode` for Reed–Solomon error
  correction up to `(m − k) / 2` shares.
- **Zeroization.** `BigUint` zeroes its limb buffer on `Drop`. Other
  intermediate `Vec`s and byte buffers are not scrubbed beyond that.
