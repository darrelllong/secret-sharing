//! Secret-sharing primitives implemented from the published papers in `pubs/`.
//!
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
//! All polynomial arithmetic runs over a user-supplied prime field
//! (`PrimeField`) backed by the variable-time `BigUint` from the
//! sibling `cryptography` crate. Two convenience moduli are provided:
//! the Mersenne primes `mersenne127` (2^127 − 1) and `mersenne521`
//! (2^521 − 1).

pub mod bytes;
pub mod decode;
pub mod field;
pub mod kgh;
pub mod poly;
pub mod ramp;
pub mod shamir;
pub mod trivial;

pub use cryptography::vt::BigUint;
pub use cryptography::Csprng;

pub use field::{mersenne127, mersenne521, PrimeField};
pub use shamir::Share;
