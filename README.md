# secret-sharing

Threshold secret-sharing schemes implemented in pure, safe Rust
directly from their published specifications. The crate is fully
**self-contained**: `Cargo.toml` declares no external dependencies, and
its `Cargo.lock` lists only this crate. Big-integer arithmetic, prime
helpers, the `Csprng` trait, the `ChaCha20Rng` CSPRNG, and the
`OsRng` entropy source are all in-tree.

## Catalogue

The crate covers three papers in `pubs/` and every constructive
scheme catalogued in [`bib/references.bib`](bib/references.bib):

| Paper | Year | What it gives us |
|-------|------|------------------|
| Shamir, *How to Share a Secret* | 1979 | Classical $(k, n)$ polynomial threshold scheme |
| Karnin, Greene, Hellman, *On Secret Sharing Systems* | 1983 | Trivial n-of-n split, multi-secret extension, the matrix scheme $v_i = u \cdot A_i$ |
| McEliece, Sarwate, *On Sharing Secrets and Reed–Solomon Codes* | 1981 | Ramp (data-compressed) variant and errors-and-erasures recovery via Berlekamp–Welch |
| Blakley, *Safeguarding Cryptographic Keys* | 1979 | Geometric $(k, n)$ threshold via random hyperplanes through a fixed point |
| Mignotte, *How to Share a Secret* | 1983 | CRT-based $(k, n)$ (reconstruction-uniqueness, not perfectly secret) |
| Asmuth, Bloom, *A Modular Approach to Key Safeguarding* | 1983 | CRT-based $(k, n)$ with statistical secrecy |
| Rabin, *Efficient Dispersal of Information…* | 1989 | Reed–Solomon-style information dispersal (erasure coding, not secret sharing) |
| Yamamoto, *Secret Sharing System Using $(k, L, n)$ | 1986 | Generalised ramp scheme spanning Shamir (when $L = 1$) and McEliece–Sarwate (when $L = k$) |
| Ito, Saito, Nishizeki, *Secret Sharing Scheme Realising General Access Structure* | 1989 | Cumulative-array realisation of any monotone access structure |
| Benaloh, Leichter, *Generalised Secret Sharing and Monotone Functions* | 1988 | Recursive distribution along a monotone Boolean formula |
| Rabin, Ben-Or, *Verifiable Secret Sharing and Multiparty Protocols* | 1989 | Information-theoretic VSS via bivariate polynomials with cross-checks |
| Kothari, *Generalized Linear Threshold Scheme* | 1984 | Linear $(k, n)$ over any user-supplied $k \times n$ matrix with the spreading property |
| Brickell, *Some Ideal Secret Sharing Schemes* | 1989 | Ideal vector-space SSS — one field-element per player |
| Karchmer, Wigderson, *On Span Programs* | 1993 | Monotone span programs — captures every linear SSS |
| Massey, *Minimal Codewords and Secret Sharing* | 1993 | Linear-code SSS — secret = column 0 of a generator matrix |
| Naor, Shamir, *Visual Cryptography* | 1994 | $(n, n)$ scheme on black/white images; reconstruction by stacking |
| Blakley, Meadows, *Security of Ramp Schemes* | 1984 | $(k, L, n)$ ramp generalisation of Blakley's hyperplane scheme |
| Chor, Goldwasser, Micali, Awerbuch, *Verifiable Secret Sharing* | 1985 | Computational VSS via discrete-log (Feldman) commitments |
| Herzberg, Jarecki, Krawczyk, Yung, *Proactive Secret Sharing* | 1995 | Periodic refresh of Shamir shares + lost-share recovery |

For the algebra behind every scheme, see [`THEORY.md`](THEORY.md).
For copy-pasteable usage examples, see [`HOWTO.md`](HOWTO.md). For
performance numbers and kiviat / line / bar charts, see
[`PERFORMANCE.md`](PERFORMANCE.md). For the current peer-review
status, see [`PEER-REVIEW.md`](PEER-REVIEW.md).

## Threshold model

A *(k, n) threshold scheme* splits a secret $s$ into $n$ *shares* such
that

1. **Recoverability:** any $k$ shares reconstruct $s$.
2. **Secrecy:** any $k - 1$ shares reveal nothing — every candidate
 value of $s$ remains equally likely (information-theoretic
 security).

$k = 1$ is forbidden everywhere in this crate, since a degree-zero
polynomial would distribute the secret in plaintext.

## Modules

```text
secret_sharing
├── field PrimeField over BigUint; mersenne127 / mersenne521 helpers
├── poly Horner evaluation, Lagrange interpolation
├── trivial KGH §I additive (and XOR) n-of-n split
├── shamir Shamir 1979 (k, n) + KGH §IV multi-secret extension
├── bytes Chunked byte-string Shamir with a versioned wire format
├── kgh KGH §II matrix scheme v_i = u·A_i for vector secrets
├── ramp McEliece–Sarwate ramp / data-compressed Reed–Solomon
├── decode McEliece–Sarwate errors-and-erasures via Berlekamp–Welch
├── blakley Blakley 1979 hyperplane (k, n) threshold
├── mignotte Mignotte 1983 CRT (k, n) — reconstruction-uniqueness
├── asmuth_bloom Asmuth–Bloom 1983 modular CRT (k, n) — statistical secrecy
├── ida Rabin 1989 Information Dispersal (erasure coding, no secrecy)
├── yamamoto Yamamoto 1986 (k, L, n) ramp — generalises Shamir & MS-ramp
├── ito Ito–Saito–Nishizeki 1989 cumulative-array general access
├── benaloh_leichter Benaloh–Leichter 1988 monotone-formula scheme
├── kothari Kothari 1984 generalised linear (k, n)
├── karchmer_wigderson Karchmer–Wigderson 1993 monotone span programs
├── brickell Brickell 1989 ideal vector-space SSS
├── massey Massey 1993 linear-code SSS via minimal codewords
├── visual Naor–Shamir 1994 visual cryptography (n, n)
├── blakley_meadows Blakley–Meadows 1984 (k, L, n) hyperplane ramp
├── vss Rabin–Ben-Or 1989 bivariate-polynomial VSS
├── cgma_vss Chor–Goldwasser–Micali–Awerbuch 1985 Feldman-style VSS
├── proactive Herzberg et al. 1995 share refresh + lost-share recovery
├── bigint Self-contained BigUint + BigInt + MontgomeryCtx
├── csprng Csprng trait + ChaCha20Rng (RFC 7539) + OsRng
├── primes gcd, mod_inverse, mod_pow, random_below, is_probable_prime{,_random}
├── secure Zeroize + Zeroizing<T> + ct_eq_biguint + ct_eq_biguint_padded
└── poly Horner + Lagrange (mod-p label discipline)
```

## How each scheme works

### `trivial` — n-of-n additive split (KGH §I)

Pick $v_1, \ldots, v_{n-1}$ uniformly at random in $[0, p)$, then set

$$ v_n = s - (v_1 + v_2 + \cdots + v_{n-1}) \pmod{p} $$

so that $\sum_i v_i \equiv s \pmod{p}$. Reconstruction is the sum.
The XOR variant is the $q = 2$ special case applied byte-wise. There
is no $k < n$ threshold — every share is required.

### `shamir` — (k, n) polynomial threshold scheme (Shamir 1979)

Choose a random degree $k - 1$ polynomial

$$ q(x) = a_0 + a_1 x + a_2 x^2 + \cdots + a_{k-1} x^{k-1}, \qquad a_0 = s $$

over $\mathrm{GF}(p)$. Trustee $i \in \{1, \ldots, n\}$ is given
$(i, q(i) \bmod p)$. Any $k$ shares interpolate $q(x)$ (Lagrange) and
yield $s = q(0)$. Knowledge of $k - 1$ or fewer shares leaves the
secret uniformly distributed.

### `shamir::split_multi` — multi-secret extension (KGH §IV)

Pack $\ell \le k$ secrets into the lowest-order coefficients:

$$ q(x) = s_0 + s_1 x + \cdots + s_{\ell-1} x^{\ell-1} + u_\ell x^\ell + \cdots + u_{k-1} x^{k-1} $$

with $u_\ell, \ldots, u_{k-1}$ uniform random padding. Any $k$
trustees recover all $\ell$ secrets simultaneously; any $k - 1$
trustees learn nothing about any single secret.

### `kgh` — matrix scheme $v_i = u \cdot A_i$ for vector secrets (KGH §II)

Generalise the secret to a length $m$ vector $s \in \mathrm{GF}(p)^m$.
Form the internal vector $u = (s, u_1, \ldots, u_{k-1})$, where each
$u_j$ is a length $m$ block of independent uniform field elements.
Trustee $i$ receives the vector share $v_i = u \cdot A_i$ where the
$A_i$ are public $km \times m$ matrices, every $k$-subset of which
has full rank. The crate instantiates the public matrix bank with the
Vandermonde construction from KGH eq. (16): equivalently, each
component runs an independent Shamir polynomial in $\alpha_i = i$.

### `bytes` — chunked byte-string Shamir

Real secrets are byte strings (AES keys, passphrases, files), not
single field elements. The `bytes` module chunks the secret into
`block_len` = $\lfloor (\mathrm{bits}(p) - 1) / 8 \rfloor$ byte
blocks, runs an independent Shamir polynomial per block, and
serialises each share with the wire format

```text
version : u8 = 0x01
label : u8 = trustee index 1..=255
length : u32 (BE) = byte-length of the original secret
blocks : [u8; ...] = concatenated big-endian field-element blocks
```

`share_elem_len` = $\lceil \mathrm{bits}(p) / 8 \rceil$ bytes are used
to serialise each field element so that no high byte is ever truncated
(16 bytes for $2^{127} - 1$, even though plaintext
blocks are 15 bytes).

### `ramp` — McEliece–Sarwate ramp scheme

The secret is now $k$ field elements $(b_1, \ldots, b_k)$. Find the
unique degree $k - 1$ polynomial $P(x)$ with $P(j) = b_j$ for $j = 1..k$, and distribute $(k + i, P(k + i))$ for $i = 1..n$. Any $k$
shares interpolate $P$ and reconstruct every $b_j$. Per-trustee
payload is one field element regardless of secret length — $k\times$
smaller than the secret. The trade-off is that an opponent with $k - 1$ shares narrows the secret to one of $p$ candidates rather than
$p^k$.

### `decode` — Berlekamp–Welch errors-and-erasures recovery

McEliece–Sarwate observed that Shamir's scheme is a Reed–Solomon
code, so the standard errors-and-erasures decoders apply. Given $m$
shares, of which up to $t$ may have been tampered with, the secret
can still be recovered whenever

$$ m - 2t \ge k. $$

This crate implements **Berlekamp–Welch**: find polynomials $Q(x)$ of
degree $< k + t$ and $E(x)$ of degree $\le t$, with $E \not\equiv 0$,
such that $Q(x_i) = y_i \cdot E(x_i)$ for every share. Solve as a
homogeneous linear system over $\mathrm{GF}(p)$, polynomial-divide $Q / E$ to recover the original message polynomial $M(x)$, and read $s = M(0)$. Erasures are handled by simply not supplying the lost share —
the agreement bound applies to whatever shares remain.

### `blakley` — geometric $(k, n)$ threshold (Blakley 1979)

Pick a random point $P = (s, r_1, \ldots, r_{k-1}) \in \mathrm{GF}(p)^k$ whose first coordinate is the secret. Each share is
a random hyperplane through $P$:

$$ a_1 y_1 + \cdots + a_{k-1} y_{k-1} + y_k = b $$

with $b$ chosen so the equation holds at $P$. Any $k$ shares solve a
linear system for $P$ and read off $s$; any $k - 1$ shares cut a
one-dimensional line of candidates uniformly distributed over
$\mathrm{GF}(p)$.

### `mignotte` — CRT-based $(k, n)$ (Mignotte 1983)

A *Mignotte sequence* is $m_1 < m_2 < \cdots < m_n$ pairwise coprime
with

$$ \alpha := \prod\nolimits_{(k - 1)\mathrm{largest}} m_i < \beta := \prod\nolimits_{k\mathrm{smallest}} m_i. $$

The secret $S \in (\alpha, \beta)$ is shared as $(m_i, S \bmod m_i)$.
Any $k$ residues CRT-determine $S$ uniquely in $[0, \prod m_{i_j}) \supseteq [0, \beta) \ni S$. Mignotte gives reconstruction
uniqueness, *not* perfect secrecy: $k - 1$ residues narrow the
candidates to roughly $(\beta - \alpha) / \prod (\text{those } k - 1 \text{ moduli})$
values.

### `asmuth_bloom` — modular CRT $(k, n)$ (Asmuth–Bloom 1983)

Strengthens Mignotte with a public secret-modulus $m_0$ (coprime with
each $m_i$) and the inequality $m_0 \cdot M_{\mathrm{top}} < M_{\mathrm{bot}}$. The secret $S < m_0$ is masked as $y = S + A \cdot m_0$ for uniform $A \in [0, \lfloor M_{\mathrm{bot}} / m_0 \rfloor)$
and shared as $(m_i, y \bmod m_i)$. CRT-recover $y$, then return $y \bmod m_0$. The mask makes secrecy *statistical* (near-perfect with
deviation $O(m_0 \cdot M_{\mathrm{top}} / M_{\mathrm{bot}})$): $k - 1$ shares leave $S$ very nearly uniform over $[0, m_0)$.

### `ida` — Rabin Information Dispersal (Rabin 1989)

**Not** a secret-sharing scheme. Encode a file $F$ as Reed–Solomon
codewords (each polynomial coefficient = $\mathrm{bl}$ bytes of $F$)
and distribute one evaluation per $(k - 1)$-degree polynomial per
trustee. Per-share storage is $|F|/k$ bytes; any $k$ shares
reconstruct $F$; fewer than $k$ reveal nothing useful, but $k$ *of
any provenance* will reconstruct, including a colluding majority that
holds no secret. Use when load-balancing or erasure tolerance is the
goal and secrecy isn't.

### `yamamoto` — $(k, L, n)$ ramp (Yamamoto 1986)

The secret is $(s_1, \ldots, s_L) \in \mathrm{GF}(p)^L$ with $1 \le L \le k$. Pick the unique degree $k - 1$ polynomial $P$ such that
$P(j) = s_j$ for $j = 1..L$ and $P(j) = u_j$ (uniform random) for $j = L+1..k$. Distribute $P(k + 1), \ldots, P(k + n)$. Any $k$ shares
interpolate $P$ and read every $s_j$; any $k - L$ shares reveal
nothing; intermediate counts leak proportional information by
Yamamoto's analysis. The $L = 1$ case is Shamir; $L = k$ is
McEliece–Sarwate ramp.

### `ito` — general access structure (Ito–Saito–Nishizeki 1989)

Realise *any* monotone access structure $\mathcal{A}$. The user
supplies the maximal forbidden coalitions $F_1, \ldots, F_t$ ($Q \in \mathcal{A} \iff \forall i, Q \not\subseteq F_i$). Choose $r_1, \ldots, r_{t-1}$ uniform with $r_t = s - \sum r_i \pmod{p}$; player
$j$ holds $\{(i, r_i) : j \notin F_i\}$. A qualified coalition covers
every $i$, so summing the $r_i$ recovers $s$. Per-player share size
is the number of $F_i$ not containing $j$ — exponential in the worst
case but appropriate for arbitrary monotone structures.

### `benaloh_leichter` — monotone-formula scheme (Benaloh–Leichter 1988)

Distribute the secret along a monotone Boolean formula tree:

- AND nodes additively split the value among children (random shares
 summing to the value).
- OR nodes hand each child the same value.
- Leaves go to the labelled party.

Reconstruction walks the formula bottom-up: AND requires every child
to recover (sum); OR succeeds as soon as any child recovers.
Per-party share size is the number of leaves labelled with that
party — small when the formula is succinct. Each fragment carries the
path to its source leaf, and `reconstruct` rejects fragments whose
path resolves to a leaf labelled with a different player.

### `kothari` — generalised linear $(k, n)$ (Kothari 1984)

Public $k \times n$ matrix $A$ over $\mathrm{GF}(p)$ whose every $k$
columns are linearly independent (the *spreading* condition). Pick
uniform $u = (s, r_2, \ldots, r_k)$; share $i$ is $v_i = u \cdot A_i$.
Recovery from any $k$ shares solves $u \cdot A_S = v_S$. Specialises
to Shamir (Vandermonde $A$), Blakley (random hyperplane $A$), and
KGH (block-diagonal $A$).

### `karchmer_wigderson` — monotone span programs (Karchmer–Wigderson 1993)

The most general linear SSS framework. A labelled matrix
$(M, \rho)$ over $\mathrm{GF}(p)$ together with target vector $e_1$.
A coalition is qualified iff $e_1$ lies in the row span of the
sub-matrix on its labelled rows. Realises every monotone access
structure; subsumes van Dijk's "linear construction."

### `brickell` — ideal vector-space SSS (Brickell 1989)

One vector $v_j \in \mathrm{GF}(p)^m$ per player. Sample uniform $u \in \mathrm{GF}(p)^m$ with $\langle u, e_1 \rangle = s$; player $j$
gets $\langle v_j, u \rangle$. Per-player share is one field element
regardless of $m$ (the *ideal* property). Internally a one-row-per-
player specialisation of MSP.

### `massey` — linear-code SSS via minimal codewords (Massey 1993)

A $k \times (n + 1)$ generator matrix $G$ over $\mathrm{GF}(p)$;
column 0 is the secret slot. Sample message $m$ with $m \cdot G[:,0] = s$; player $j$ receives $c_j = \langle m, G[:, j] \rangle$. A
coalition is qualified iff $G[:, 0]$ lies in the span of its columns;
the minimal qualified sets correspond to minimal codewords of the
dual code $C^\perp$ — Massey's theorem.

### `visual` — Naor–Shamir visual cryptography (Naor–Shamir 1994)

Black-and-white image as `Vec<Vec<bool>>`. Each pixel expands to $m = 2^{n-1}$ sub-pixels per share. Two basis matrices $C_0$ (white,
even-cardinality subsets) and $C_1$ (black, odd-cardinality subsets)
are column-permuted per pixel and rows distributed to the shares.
Reconstruction stacks (bitwise OR) all $n$ shares; the eye reads the
contrast between weight $m$ (black) and weight $m - 1$ (white) blocks.

### `blakley_meadows` — $(k, L, n)$ Blakley ramp (Blakley–Meadows 1984)

Place the length $L$ secret in the first $L$ coordinates of an
internal point $P \in \mathrm{GF}(p)^k$, fill the rest with uniform
padding, and emit $n$ random hyperplanes through $P$. Any $k$ shares
recover $P$ (and hence every $s_j$); any $k - L$ shares fix $P$ on
an $L$-dimensional affine subspace, leaving the secret coordinate
vector statistically uniform over $\mathrm{GF}(p)^L$.

### `vss` — bivariate-polynomial VSS (Rabin–Ben-Or 1989)

Information-theoretic verifiable secret sharing. Sample a bivariate
polynomial $F(x, y)$ of degree $\le k - 1$ in each variable with
$F(0, 0) = s$. Player $i$ receives $g_i(y) = F(i, y)$ and $h_i(x) = F(x, i)$. Pairwise cross-checks $g_i(j) \stackrel{?}{=} h_j(i)$ (in
both directions) catch any tampered slice with probability 1.
Reconstruction Lagrange-interpolates $\Phi(x) = F(x, 0)$ from
$g_i(0)$ for $k$ consistent players, then reads $s = \Phi(0)$. The
honest-majority bound $2(k - 1) < n$ is enforced by the
`deal_validated` constructor.

### `cgma_vss` — Chor–GMA computational VSS via Feldman commitments (1985)

Public Schnorr group $(p, q, g)$ with $q$ prime, $q \mid p - 1$, $g$
of order exactly $q$. Sample $f(x) = a_0 + a_1 x + \cdots + a_{k-1} x^{k-1}$ over $\mathrm{GF}(q)$ with $a_0 = s$. Broadcast commitments
$c_i = g^{a_i} \bmod p$. Each share $(j, f(j) \bmod q)$ is verified
by

$$ g^{f(j)} \stackrel{?}{=} \prod_{i=0}^{k-1} c_i^{j^i} \pmod{p}. $$

Group construction validates primality of $p$ and $q$ via Miller–
Rabin (deterministic for sizes $< 2^{81}$, random-witness via
`is_probable_prime_random` for larger), exact divisibility $q \mid (p - 1)$, and that $g$ reduced mod $p$ is neither 0 nor 1. Every
commitment is also subgroup-checked at `verify_share` time.

### `proactive` — Herzberg et al. share refresh (1995)

`refresh` produces a fresh share vector for the same secret by
having each player contribute a degree $k - 1$ polynomial $r_i(x)$
with $r_i(0) = 0$ and adding $\sum_i r_i(j)$ to player $j$'s share.
Old shares no longer combine with new shares. `recover_share`
reconstructs a missing share via Lagrange evaluation, with the same
extras-validation discipline as `shamir::reconstruct`.

## Defensive-security baseline

Beyond the per-scheme math, the crate enforces a uniform defensive-
security layer:

- **Volatile-zero on drop.** Every secret-bearing intermediate buffer
 (polynomial coefficient vectors, bivariate matrices, refresh
 contributions, rng buffers) is wrapped in `Zeroizing<T>` so its
 contents are volatile-zeroed on every exit path, including panic
 unwind. `BigUint::Drop` itself volatile-zeros the entire allocated
 capacity of its limb buffer (not just $[0..\mathrm{len})$).
- **Constant-time secret-derived equality.** `BigUint::eq` compares
 all limbs in an OR-fold without short-circuit. The
 `secure::ct_eq_biguint{,_padded}` helpers do the same at the byte
 level; every reconstruct / extras-validate site that compares
 secret-derived values uses one of them, never `==` directly.
- **Non-leaking Debug.** `BigUint`'s manual `Debug` prints
 `BigUint(<elided>)` so panic backtraces, `dbg!`, and `assert_eq!`
 failure messages cannot accidentally print a secret limb. Every
 share-bearing struct elides its inner value through the same
 pattern.
- **CSPRNG memory hygiene.** `ChaCha20Rng` has no `Clone`, scrubs its
 key / nonce / counter / keystream-buffer in `Drop`, scrubs the
 `state` and `init` stack arrays inside `refill` through their live
 mutable bindings, and treats $(\mathrm{counter},\mathrm{nonce})$
 as a single 128-bit block index so the period is $2^{128}$
 blocks.

What is **not** addressed:

- Variable-time arithmetic. `BigUint` `mul` / `add` / `sub` / `inv`
 are not constant-time. Co-located timing observers can recover
 bit-length information from secret arithmetic. Side-channel
 resistance is explicitly out of scope.
- `mlock` against swap. Platform-specific; do at the application
 layer if needed.

## Usage

### Add the dependency

```toml
[dependencies]
secret-sharing = { path = "path/to/secret-sharing" }
```

The crate has no other dependencies.

### Shamir over $\mathrm{GF}(2^{127} - 1)$

```rust
use secret_sharing::{
 csprng::OsRng,
 field::{mersenne127, PrimeField},
 shamir, BigUint, ChaCha20Rng,
};

let field = PrimeField::new_unchecked(mersenne127()); // bundled prime
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret = BigUint::from_u64(0xC0FFEE);

let shares = shamir::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/5);
let recovered = shamir::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

### Byte-string Shamir for an AES key

```rust
use secret_sharing::{
 csprng::OsRng, bytes,
 field::{mersenne127, PrimeField},
 ChaCha20Rng,
};

let field = PrimeField::new_unchecked(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let aes_key = b"32-byte AES-256 key payload!!!!!";

let shares = bytes::split(&field, &mut rng, aes_key, /*k=*/3, /*n=*/5);
let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
let recovered = bytes::reconstruct(&field, &refs[..3], 3).unwrap();
assert_eq!(recovered, aes_key.to_vec());
```

### Robust reconstruction in the presence of tampering

```rust
use secret_sharing::{
 csprng::OsRng,
 decode::reconstruct_with_errors,
 field::{mersenne127, PrimeField},
 shamir, BigUint, ChaCha20Rng,
};

let field = PrimeField::new_unchecked(mersenne127());
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

### Multi-secret pack

```rust
use secret_sharing::{
 csprng::OsRng,
 field::{mersenne127, PrimeField},
 shamir, BigUint, ChaCha20Rng,
};

let field = PrimeField::new_unchecked(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secrets: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(900 + i)).collect();

let shares = shamir::split_multi(&field, &mut rng, &secrets, /*k=*/4, /*n=*/7);
let got = shamir::reconstruct_multi(&field, &shares[..4], 4, secrets.len()).unwrap();
assert_eq!(got, secrets);
```

### Ramp / data-compressed variant

```rust
use secret_sharing::{
 field::{mersenne127, PrimeField},
 ramp, BigUint,
};

let field = PrimeField::new_unchecked(mersenne127());
let secret: Vec<BigUint> = (0..5).map(|i| BigUint::from_u64(0x1000 + i)).collect();
let shares = ramp::split(&field, &secret, /*n=*/8);
let recovered = ramp::reconstruct(&field, &shares[..5], secret.len()).unwrap();
assert_eq!(recovered, secret);
```

### Vector secrets via the KGH matrix scheme

```rust
use secret_sharing::{
 csprng::OsRng,
 field::{mersenne127, PrimeField},
 kgh, BigUint, ChaCha20Rng,
};

let field = PrimeField::new_unchecked(mersenne127());
let mut rng = ChaCha20Rng::from_os_entropy(&mut OsRng::new().unwrap());
let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(0x100 + i)).collect();

let shares = kgh::split(&field, &mut rng, &secret, /*k=*/3, /*n=*/6);
let recovered = kgh::reconstruct(&field, &shares[..3], 3).unwrap();
assert_eq!(recovered, secret);
```

For copy-pasteable examples covering every scheme, see
[`HOWTO.md`](HOWTO.md).

## Testing and lints

```sh
cargo test # 236 unit + 7 integration + 2 doc
cargo clippy --all-targets -- -D warnings # clean
```

## Choosing a field

The crate is generic over the prime modulus. Two convenience fields:

| Function | Modulus | Plaintext block | Share-element width |
|----------|---------|-----------------|---------------------|
| `field::mersenne127()` | $2^{127} - 1$ | 15 bytes | 16 bytes |
| `field::mersenne521()` | $2^{521} - 1$ | 65 bytes | 66 bytes |

Any user-supplied prime works as well — `PrimeField::new(p)` runs
Miller–Rabin (deterministic for $p < 2^{81}$) and panics on a
composite. For larger user-supplied primes, run
`primes::is_probable_prime_random` yourself first and then construct
via `PrimeField::new_unchecked` once you have witnesses.

## Design notes

- **No external dependencies.** `Cargo.toml`'s `[dependencies]` is
 empty. Big-integer code is in-tree (`src/bigint.rs`); the CSPRNG is
 ChaCha20 (`src/csprng.rs`); OS entropy is read directly from
 `/dev/urandom` (`src/csprng.rs::OsRng`).
- **Variable-time arithmetic.** `BigUint` is documented as
 variable-time; do not deploy in side-channel-exposed environments.
- **No allocation-free path.** Polynomials and matrices use plain
 `Vec<BigUint>`. Performance is dominated by big-integer modular
 multiplication, not by allocator overhead.
- **Wire format only in `bytes` and `ida`.** Other modules return
 native `BigUint` shares; serialise via `BigUint::to_be_bytes()` if
 needed.
- **`Option`-returning reconstructors.** Every `reconstruct` validates
 its inputs and returns `None` on contract violations the caller may
 not have controlled (corrupt shares, malformed wire format,
 duplicate / mod-p-aliased $x$ coordinates, non-canonical encoded
 field elements). Static contract violations (e.g. $k < 2$) panic.

<p align="center">
 <img src="assets/ship_of_fools.png" width="50%" alt="Ship of Fools">
</p>
