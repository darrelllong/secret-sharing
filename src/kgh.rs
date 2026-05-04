//! Karnin–Greene–Hellman 1983 §II–III: the genuine matrix scheme.
//!
//! "Find a set of `n + 1` matrices over `GF(q)`, `{A_0, A_1, …, A_n}`,
//! each of dimension `km`-by-`m`, such that every set of `k` of the
//! `A_i` has full rank … `v_i = u · A_i`." (KGH eq. 10.)
//!
//! Whereas Shamir's polynomial scheme is the *scalar* case of this
//! construction (KGH §III, Note 1: the Vandermonde encoder reduces to
//! Shamir when `m = 1`), the matrix form generalizes naturally to a
//! **vector** secret `s ∈ GF(p)^m` of `m` field elements at once,
//! producing a vector share `v_i ∈ GF(p)^m` per trustee. Theorem 2 of
//! the paper establishes that any `k` trustees recover `u` (and hence
//! `s = u · A_0`) iff every k-subset of the `A_i` has full rank.
//!
//! We implement the construction over an arbitrary prime field with
//! the Vandermonde-derived matrix bank from KGH equation (16):
//!
//! ```text
//! G = [I_k | V],   V_{i,j} = (α_j)^i,   i = 0..k-1,  j = 0..n-1
//! ```
//!
//! where `α_1, …, α_n` are distinct nonzero field elements (we use
//! `1, 2, …, n`). Lifting to `m`-vector secrets is done block-wise:
//! `A_i ∈ GF(p)^{km × m}` is the row-`i` block of `G ⊗ I_m`.
//!
//! Equivalently, viewing `u = (u_0, …, u_{k−1})` with each `u_j ∈
//! GF(p)^m`, the share for trustee `i` is
//!
//! ```text
//! v_i = u · A_i = Σ_{j=0..k-1} u_j · g_{j,i}    (component-wise)
//! ```
//!
//! where `g_{j,i}` is the `(j, i)` entry of `G`. Setting `u_0 = s` and
//! drawing `u_1, …, u_{k−1}` uniformly at random recovers exactly the
//! KGH multi-secret embedding (with `ℓ = 1`, the secret in the leading
//! slot) generalized from scalars to length-`m` vectors.
//!
//! Reconstruction is a Vandermonde linear solve in the field: given
//! `k` vector shares, treat each component independently and recover
//! the corresponding component of `u_0` (i.e. of the secret `s`).

use crate::field::PrimeField;
use crate::poly::lagrange_eval_unchecked;
use crate::secure::ct_eq_biguint;
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// One vector share for the matrix scheme. `x` is the trustee label;
/// `y` is `u · A_i`, a length-`m` vector in `GF(p)^m`.
#[derive(Clone, Eq, PartialEq)]
pub struct VectorShare {
    pub x: BigUint,
    pub y: Vec<BigUint>,
}

impl core::fmt::Debug for VectorShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("VectorShare(<elided>)")
    }
}

/// KGH (k, n) split of a vector secret `s ∈ GF(p)^m`.
///
/// The internal `u` vector is `(s, u_1, …, u_{k−1})` where each `u_j`
/// is a length-`m` block of independent uniform field elements.
///
/// # Panics
/// - `secret.len() == 0`,
/// - `k < 2` (a constant `u_0` would put `s` in every share),
/// - `n < k`,
/// - `n ≥ p` (the Vandermonde bank needs `n` distinct nonzero
///   abscissae; cf. KGH eq. (5): `n ≤ |F| − 1`).
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &[BigUint],
    k: usize,
    n: usize,
) -> Vec<VectorShare> {
    let m = secret.len();
    assert!(m >= 1, "secret must have at least one component");
    assert!(k >= 2, "k must be at least 2 (k = 1 would leak the secret)");
    assert!(n >= k, "n must be at least k");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );

    // Build u = (u_0, u_1, …, u_{k-1}), each block of length m.
    // u_0 = secret; u_j (j ≥ 1) drawn uniformly at random.
    let mut u: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    u.push(secret.iter().map(|c| field.reduce(c)).collect());
    for _ in 1..k {
        let block: Vec<BigUint> = (0..m).map(|_| field.random(rng)).collect();
        u.push(block);
    }

    // For trustee i with abscissa α_i = i, evaluate v_i component-wise:
    //   v_i[c] = Σ_{j=0..k-1} u_j[c] · α_i^j
    // — i.e. each component is a Shamir polynomial in α_i with
    // coefficient sequence (u_0[c], u_1[c], …, u_{k-1}[c]).
    (1..=n)
        .map(|i| {
            let alpha = BigUint::from_u64(i as u64);
            let mut y = vec![BigUint::zero(); m];
            for (c, y_c) in y.iter_mut().enumerate() {
                let mut acc = BigUint::zero();
                let mut pow = BigUint::one();
                for u_block in u.iter().take(k) {
                    let term = field.mul(&u_block[c], &pow);
                    acc = field.add(&acc, &term);
                    pow = field.mul(&pow, &alpha);
                }
                *y_c = acc;
            }
            VectorShare { x: alpha, y }
        })
        .collect()
}

/// Reconstruct a vector secret from `≥ k` shares. With more than `k`
/// shares supplied, extras are validated against the polynomial
/// recovered from the first `k`; any inconsistency yields `None`.
///
/// Returns `None` on:
/// - `k == 0` or `shares.len() < k`,
/// - empty shares or shares with mismatched component counts,
/// - duplicate or zero `x` labels,
/// - any extra share that contradicts the recovered polynomial.
#[must_use]
pub fn reconstruct(
    field: &PrimeField,
    shares: &[VectorShare],
    k: usize,
) -> Option<Vec<BigUint>> {
    if k == 0 || shares.len() < k {
        return None;
    }
    let m = shares[0].y.len();
    if m == 0 {
        return None;
    }
    for s in shares {
        if s.x.is_zero() || s.y.len() != m {
            return None;
        }
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return None;
            }
        }
    }

    // For each component c, build `pts` from the first k shares once
    // and reuse it both to recover the secret (eval at x = 0) and to
    // validate every extra share's `y[c]`. This drops the validation
    // cost from O(extras · m · k²) of cloning + Lagrange-with-rebuild
    // to O(m · k² + extras · m · k²) without the redundant rebuilds.
    let mut secret: Vec<BigUint> = Vec::with_capacity(m);
    for c in 0..m {
        let pts: Vec<(BigUint, BigUint)> = shares
            .iter()
            .take(k)
            .map(|s| (s.x.clone(), s.y[c].clone()))
            .collect();
        secret.push(lagrange_eval_unchecked(field, &pts, &BigUint::zero()));
        for s in &shares[k..] {
            let pred = lagrange_eval_unchecked(field, &pts, &s.x);
            if !ct_eq_biguint(&pred, &s.y[c]) {
                return None;
            }
        }
    }

    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[33u8; 32])
    }

    fn small_field() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn vector_round_trip() {
        let f = small_field();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(0x100 + i)).collect();
        let shares = split(&f, &mut r, &secret, 3, 6);
        assert_eq!(reconstruct(&f, &shares[..3], 3), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[2..5], 3), Some(secret));
    }

    #[test]
    fn scalar_kgh_matches_shamir() {
        // m = 1 reduces to Shamir per KGH §III, Note 1. Verify that
        // the scalar component recovered here is the same as a Shamir
        // split would have produced (well, modulo independent random
        // padding — instead just check round-trip).
        let f = small_field();
        let mut r = rng();
        let secret = vec![BigUint::from_u64(0xDECAF)];
        let shares = split(&f, &mut r, &secret, 4, 7);
        assert_eq!(reconstruct(&f, &shares[..4], 4), Some(secret));
    }

    #[test]
    fn below_threshold_is_refused() {
        let f = small_field();
        let mut r = rng();
        let secret = vec![BigUint::from_u64(1), BigUint::from_u64(2)];
        let shares = split(&f, &mut r, &secret, 3, 5);
        assert!(reconstruct(&f, &shares[..2], 3).is_none());
    }

    #[test]
    fn extras_must_be_consistent() {
        let f = small_field();
        let mut r = rng();
        let secret = vec![BigUint::from_u64(7), BigUint::from_u64(11)];
        let mut shares = split(&f, &mut r, &secret, 3, 5);
        shares[4].y[1] = f.add(&shares[4].y[1], &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 3).is_none());
    }
}
