//! Blakley–Meadows 1984, *Security of Ramp Schemes* — a `(k, L, n)`
//! ramp generalisation of Blakley's hyperplane scheme.
//!
//! Construction. Place the length-`L` secret `(s_1, …, s_L) ∈ GF(p)^L`
//! in the first `L` coordinates of a point `P ∈ GF(p)^k`, fill the
//! remaining `k − L` coordinates with uniform random padding, and emit
//! `n` random hyperplanes through `P`:
//!
//! ```text
//!     a_1 y_1 + … + a_{k−1} y_{k−1} + y_k = b
//! ```
//!
//! with `a_j` uniform in `GF(p)` and `b` chosen so the equation holds
//! at `P`. Any `k` shares solve a linear system for `P` (and hence for
//! every `s_j`); any `k − L` shares fix `P` only on an `L`-dimensional
//! affine subspace, leaving the secret coordinate-vector *statistically*
//! uniform over `GF(p)^L`. Intermediate counts leak partial coordinates.
//!
//! Secrecy is **statistical, not unconditional**. The projection of the
//! solution subspace onto the secret coordinates is surjective iff the
//! `t × (k − L)` "padding-column" sub-matrix `A_R` of the constraints
//! has full rank `t = k − L`. With `a_j` uniform random and the
//! constant `y_k`-coefficient pinned to `1`, `Pr[A_R singular]` is
//! `O(t / p)` — exponentially small for cryptographic-size `p`, but
//! nonzero. Conditional on the singular event the secret distribution
//! given the shares is not exactly uniform. For the bundled `2^61 − 1`
//! field the probability of a singular configuration is `≤ 2^−61`,
//! which we accept; callers needing strictly perfect secrecy should
//! apply rejection sampling on the share matrix or use the
//! `crate::yamamoto` polynomial form instead.
//!
//! This is the geometric counterpart to `crate::yamamoto`, which gives
//! the polynomial-evaluation form of the same `(k, L, n)` ramp idea.
//!
//! Robustness note: as in `crate::blakley`, when *exactly* `k` shares
//! are supplied there is no redundancy and a tampered share produces
//! a wrong-but-plausible secret silently. Pass extras (`>k`) to invoke
//! the consistency check.

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::secure::ct_eq_biguint;

/// One trustee's hyperplane equation
/// `a_1 y_1 + … + a_{k−1} y_{k−1} + y_k = b`. The `y_k` coefficient is
/// fixed at 1 by construction and is not stored.
#[derive(Clone, Eq, PartialEq)]
pub struct Share {
    pub a: Vec<BigUint>,
    pub b: BigUint,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Share(<elided>)")
    }
}

/// Distribute `n` `(k, L, n)`-Blakley–Meadows shares of a length-`L`
/// secret. The first `L` coordinates of the internal point are the
/// secret; the remaining `k − L` are uniform random padding.
///
/// # Panics
/// - `secret.len() == 0`,
/// - `k < secret.len() + 1` — we need at least one padding coordinate
///   so that `k − L > 0`; with `L = k` every share would directly leak
///   each `s_j`. (The strict-`(k, n)` case `L = 1` is `crate::blakley`.)
/// - `k < 2`, `n < k`,
/// - any `s_j >= p`.
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &[BigUint],
    k: usize,
    n: usize,
) -> Vec<Share> {
    let l = secret.len();
    assert!(l >= 1, "secret must be non-empty");
    assert!(k >= 2, "k must be at least 2");
    assert!(l < k, "L must be < k (need ≥ 1 padding coordinate)");
    assert!(n >= k, "n must be at least k");
    for s in secret {
        assert!(s < field.modulus(), "every secret coordinate must be < p");
    }

    // Internal point P = (s_1, …, s_L, r_{L+1}, …, r_k).
    let mut point: Vec<BigUint> = Vec::with_capacity(k);
    for s in secret {
        point.push(s.clone());
    }
    for _ in l..k {
        point.push(field.random(rng));
    }

    // Singularity guard on the first k shares — see `crate::blakley`
    // for the same pattern. The paper-level "any k shares
    // reconstruct" claim demands a non-singular leading-k block.
    const MAX_RESAMPLE: usize = 64;
    let mut shares: Vec<Share> = Vec::with_capacity(n);
    for share_idx in 0..n {
        let mut attempt = 0usize;
        loop {
            let mut a: Vec<BigUint> = Vec::with_capacity(k - 1);
            for _ in 0..(k - 1) {
                a.push(field.random(rng));
            }
            let mut b = point[k - 1].clone();
            for j in 0..(k - 1) {
                let term = field.mul(&a[j], &point[j]);
                b = field.add(&b, &term);
            }
            let candidate = Share { a, b };
            if share_idx < k {
                shares.push(candidate);
                if first_k_full_rank(field, &shares) {
                    break;
                }
                shares.pop();
                attempt += 1;
                assert!(
                    attempt < MAX_RESAMPLE,
                    "Blakley–Meadows split could not find a non-singular \
                     share within {MAX_RESAMPLE} resamples — field is too \
                     small for k = {k}",
                );
            } else {
                shares.push(candidate);
                break;
            }
        }
    }
    shares
}

/// Same first-k full-rank check as in `crate::blakley`, copied
/// locally so each module can be read independently.
#[allow(clippy::needless_range_loop)]
fn first_k_full_rank(field: &PrimeField, shares: &[Share]) -> bool {
    let k = shares.len();
    if k == 0 {
        return true;
    }
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for s in shares {
        let mut row = Vec::with_capacity(k);
        for c in &s.a {
            row.push(field.reduce(c));
        }
        row.push(BigUint::one());
        mat.push(row);
    }
    for col in 0..k {
        let mut pivot_row = None;
        for r in col..k {
            if !mat[r][col].is_zero() {
                pivot_row = Some(r);
                break;
            }
        }
        let Some(pr) = pivot_row else {
            return false;
        };
        if pr != col {
            mat.swap(pr, col);
        }
        let inv = match field.inv(&mat[col][col]) {
            Some(v) => v,
            None => return false,
        };
        for c in col..k {
            mat[col][c] = field.mul(&mat[col][c], &inv);
        }
        for r in 0..k {
            if r == col || mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..k {
                let term = field.mul(&factor, &mat[col][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
    }
    true
}

/// Recover the length-`L` secret from `k` (or more) shares by solving
/// the linear system. Extras beyond `k` are validated against the
/// recovered point; disagreement returns `None`.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn reconstruct(
    field: &PrimeField,
    shares: &[Share],
    k: usize,
    l: usize,
) -> Option<Vec<BigUint>> {
    if k < 2 || l == 0 || l >= k || shares.len() < k {
        return None;
    }
    for s in shares {
        if s.a.len() != k - 1 {
            return None;
        }
    }

    // Build the augmented k × (k + 1) matrix. Row i is
    //   [a^{(i)}_1, …, a^{(i)}_{k-1}, 1 | b^{(i)}].
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for s in shares.iter().take(k) {
        let mut row: Vec<BigUint> = Vec::with_capacity(k + 1);
        for c in &s.a {
            row.push(field.reduce(c));
        }
        row.push(BigUint::one());
        row.push(field.reduce(&s.b));
        mat.push(row);
    }

    for col in 0..k {
        let mut pivot_row = None;
        for r in col..k {
            if !mat[r][col].is_zero() {
                pivot_row = Some(r);
                break;
            }
        }
        let pr = pivot_row?;
        if pr != col {
            mat.swap(pr, col);
        }
        let inv = field.inv(&mat[col][col])?;
        for c in col..=k {
            mat[col][c] = field.mul(&mat[col][c], &inv);
        }
        for r in 0..k {
            if r == col || mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..=k {
                let term = field.mul(&factor, &mat[col][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
    }

    let point: Vec<BigUint> = (0..k).map(|i| mat[i][k].clone()).collect();

    for s in &shares[k..] {
        let mut lhs = point[k - 1].clone();
        for j in 0..(k - 1) {
            let term = field.mul(&s.a[j], &point[j]);
            lhs = field.add(&lhs, &term);
        }
        let rhs = field.reduce(&s.b);
        if !ct_eq_biguint(&lhs, &rhs) {
            return None;
        }
    }

    Some(point.into_iter().take(l).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x4Du8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn round_trip_l_equals_one_matches_blakley() {
        // (k=3, L=1, n=5): one-element secret in slot 0; (k − L) = 2
        // padding coords. Equivalent to blakley::split semantically.
        let f = small();
        let mut r = rng();
        let secret = vec![BigUint::from_u64(0xC0FFEE)];
        let shares = split(&f, &mut r, &secret, 3, 5);
        assert_eq!(shares.len(), 5);
        assert_eq!(reconstruct(&f, &shares[..3], 3, 1), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[1..4], 3, 1), Some(secret));
    }

    #[test]
    fn round_trip_l_greater_than_one() {
        // True ramp: L = 3, k = 5, n = 8.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(0x100 + i)).collect();
        let shares = split(&f, &mut r, &secret, 5, 8);
        assert_eq!(shares.len(), 8);
        assert_eq!(reconstruct(&f, &shares[..5], 5, 3), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[2..7], 5, 3), Some(secret));
    }

    #[test]
    fn extras_validated_and_tampering_rejected() {
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(|i| BigUint::from_u64(0x300 + i)).collect();
        let mut shares = split(&f, &mut r, &secret, 4, 7);
        // All 7 with k=4: extras 4..6 must validate.
        assert_eq!(reconstruct(&f, &shares, 4, 2), Some(secret.clone()));
        // Tamper extras[5].
        shares[5].b = f.add(&shares[5].b, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 4, 2).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = vec![BigUint::from_u64(7)];
        let shares = split(&f, &mut r, &secret, 4, 6);
        assert!(reconstruct(&f, &shares[..3], 4, 1).is_none());
    }

    #[test]
    #[should_panic(expected = "L must be < k")]
    fn split_rejects_l_equals_k() {
        // L = k = 2: would expose every secret coord directly via the
        // hyperplane equations (no padding).
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(BigUint::from_u64).collect();
        let _ = split(&f, &mut r, &secret, 2, 4);
    }

    #[test]
    #[should_panic(expected = "every secret coordinate must be < p")]
    fn split_rejects_oversize_coordinate() {
        let f = PrimeField::new(BigUint::from_u64(257));
        let mut r = rng();
        let _ = split(&f, &mut r, &[BigUint::from_u64(300)], 3, 5);
    }

    #[test]
    fn fuzz_round_trip() {
        // Random-ish fuzz across (k, L, n) shapes and seeds.
        for &(k, l, n) in &[(3usize, 1usize, 5usize), (4, 2, 7), (5, 3, 9), (6, 4, 10)] {
            for seed in 0u8..4 {
                let f = small();
                let mut r = ChaCha20Rng::from_seed(&[seed; 32]);
                let secret: Vec<BigUint> =
                    (1..=l).map(|i| BigUint::from_u64(seed as u64 * 100 + i as u64)).collect();
                let shares = split(&f, &mut r, &secret, k, n);
                assert_eq!(reconstruct(&f, &shares[..k], k, l), Some(secret.clone()));
                // Take a non-contiguous k-subset.
                let picked: Vec<Share> = (0..k).map(|i| shares[i + (n - k)].clone()).collect();
                assert_eq!(reconstruct(&f, &picked, k, l), Some(secret));
            }
        }
    }
}
