//! Secret-sharing primitives implemented from the papers in
//! `pubs/` and `bib/references.bib`.
//!
//! Schemes from `pubs/`:
//! - `trivial`: Karnin–Greene–Hellman §I trivial n-of-n additive split
//!   (`v_n = s − Σ v_i mod q`), plus a byte-XOR convenience for `q = 2`.
//! - `shamir`: Shamir 1979 (k, n) threshold scheme via polynomial
//!   interpolation over GF(p), and the Karnin–Greene–Hellman §IV
//!   multi-secret extension that places ℓ ≤ k secrets in the low-order
//!   coefficients of the same polynomial.
//! - `bytes`: byte-string Shamir — chunk an arbitrary-length secret
//!   into field-sized blocks and run Shamir per block, with a
//!   self-describing wire format for each share.
//! - `kgh`: the genuine Karnin–Greene–Hellman §II matrix scheme
//!   (`v_i = u·A_i`) for vector secrets `s ∈ GF(p)^m`, instantiated
//!   with the Vandermonde matrix bank from KGH eq. (16).
//! - `ramp`: McEliece–Sarwate 1981 ramp / data-compressed Reed–Solomon
//!   variant — the secret occupies k positions of a Reed–Solomon
//!   codeword and only the remaining positions are distributed.
//! - `decode`: McEliece–Sarwate 1981 errors-and-erasures recovery via
//!   the Berlekamp–Welch algorithm — reconstructs from m shares with
//!   up to t tampered shares whenever `m − 2t ≥ k` in polynomial time.
//!
//! Additional schemes from `bib/references.bib`:
//! - `blakley`: Blakley 1979 geometric (k, n) threshold via random
//!   hyperplanes through a fixed point in GF(p)^k.
//! - `blakley_meadows`: Blakley–Meadows 1984 (k, L, n) ramp version of
//!   Blakley's hyperplane scheme.
//! - `mignotte`: Mignotte 1983 CRT scheme — `(m_1, …, m_n)` pairwise
//!   coprime with the secret in the gap `(α, β)` between `k − 1`-largest
//!   and `k`-smallest products. Reconstruction-uniqueness rather than
//!   information-theoretic secrecy.
//! - `asmuth_bloom`: Asmuth–Bloom 1983 modular CRT scheme — like
//!   Mignotte but with an extra public modulus `m_0` and stricter
//!   parameters that recover information-theoretic secrecy below
//!   threshold.
//! - `ida`: Rabin 1989 Information Dispersal Algorithm — Reed–Solomon
//!   erasure coding for files; provides `|F|/k`-sized shares with `k`
//!   to reconstruct, but no secrecy.
//! - `yamamoto`: Yamamoto 1986 (k, L, n) ramp — secret of L elements,
//!   k shares for full recovery, k−L for nothing, intermediate counts
//!   leak proportionally. Generalises both Shamir (L=1) and the McEliece
//!   ramp (L=k).
//! - `ito`: Ito–Saito–Nishizeki 1989 cumulative-array scheme realising
//!   any monotone access structure described by its maximal forbidden
//!   coalitions.
//! - `benaloh_leichter`: Benaloh–Leichter 1988 monotone-formula scheme —
//!   recursive AND-additive, OR-replicating distribution along a
//!   formula tree.
//! - `kothari`: Kothari 1984 generalised linear `(k, n)` threshold over
//!   any user-supplied k×n matrix satisfying the spreading condition.
//! - `karchmer_wigderson`: Karchmer–Wigderson 1993 monotone span
//!   programs — captures every linear SSS in one matrix-and-labels
//!   form. Subsumes van Dijk 1994's "linear construction" by
//!   equivalent formulation.
//! - `brickell`: Brickell 1989 ideal vector-space SSS — one vector per
//!   player; specialisation of `karchmer_wigderson`.
//! - `massey`: Massey 1993 linear-code SSS via minimal codewords — the
//!   secret occupies column 0 of a generator matrix `G`, qualifying
//!   coalitions are those whose columns span column 0.
//! - `visual`: Naor–Shamir 1994 visual cryptography — `(n, n)` scheme
//!   over black-and-white images with bitwise-OR reconstruction.
//! - `vss`: Rabin–Ben-Or 1989 information-theoretic verifiable secret
//!   sharing via bivariate polynomials with pairwise cross-checks.
//! - `cgma_vss`: Chor–Goldwasser–Micali–Awerbuch 1985 computational
//!   VSS instantiated with discrete-log (Feldman) commitments.
//! - `proactive`: Herzberg, Jarecki, Krawczyk, Yung 1995 proactive
//!   refresh — re-shares an existing share set without changing the
//!   secret.
//!
//! All polynomial arithmetic runs over a user-supplied prime field
//! (`PrimeField`) backed by the local `BigUint` (`crate::bigint`) and
//! its `MontgomeryCtx` for fast modular exponentiation. Two convenience
//! moduli are provided: the Mersenne primes `mersenne127` (2^127 − 1)
//! and `mersenne521` (2^521 − 1).
//!
//! The crate is fully self-contained: `Cargo.toml` declares no
//! dependencies. Big-integer arithmetic, the `Csprng` trait, and a
//! ChaCha20-based generator (`csprng::ChaCha20Rng`) all live inside
//! this crate.
//!
//! Bibliography entries deliberately not implemented:
//! - Beimel 2011 *Secret-sharing schemes: A survey* — a survey, no
//!   single scheme to instantiate.
//! - Franklin–Yung 1992 *Communication complexity of secure
//!   computation* — communication-complexity bounds, not a constructive
//!   scheme.
//! - Watanabe–Shikata 2014 *Timed-release secret sharing* — requires an
//!   external time-release oracle that has no library-only realisation.
//! - Zou et al. 2014 *An information theoretic approach to secret
//!   sharing* — capacity-region analysis, not a constructive scheme.
//!
//! These have been removed from `bib/references.bib`.

pub mod asmuth_bloom;
pub mod benaloh_leichter;
pub mod bigint;
pub mod blakley;
pub mod blakley_meadows;
pub mod brickell;
pub mod bytes;
pub mod cgma_vss;
pub mod csprng;
pub mod decode;
pub mod field;
pub mod ida;
pub mod ito;
pub mod karchmer_wigderson;
pub mod kgh;
pub mod kothari;
pub mod massey;
pub mod mignotte;
pub mod poly;
pub mod primes;
pub mod proactive;
pub mod ramp;
pub mod shamir;
pub mod trivial;
pub mod visual;
pub mod vss;
pub mod yamamoto;

pub use bigint::{BigUint, MontgomeryCtx};
pub use csprng::{ChaCha20Rng, Csprng};

pub use field::{mersenne127, mersenne521, PrimeField};
pub use shamir::Share;
