//! Blakley 1979, *Safeguarding Cryptographic Keys* — geometric (k, n)
//! threshold scheme.
//!
//! The secret is the first coordinate of a point `P = (s, r_1, …, r_{k−1})`
//! in `GF(p)^k` whose remaining coordinates are picked uniformly. Each
//! shareholder receives a single hyperplane equation
//!
//! ```text
//!     a_1 y_1 + a_2 y_2 + … + a_{k−1} y_{k−1} + y_k = b
//! ```
//!
//! whose `a_j` are uniform random in `GF(p)` and whose constant
//! `b = a_1 s + a_2 r_1 + … + a_{k−1} r_{k−2} + r_{k−1}` is chosen so
//! the hyperplane passes through `P`. The coefficient matrix of `k`
//! such equations is therefore a uniformly random `k × (k − 1)` block
//! over `GF(p)` augmented by an all-ones last column — *not* a
//! Vandermonde matrix; any structured-coefficient interpretation here
//! is wrong. With probability `1 − O(k / p)` the matrix has full rank
//! and the system has a unique solution, the first coordinate of which
//! is the secret. Any `k − 1` hyperplanes intersect in a one-
//! dimensional affine line, leaving the candidate secret uniform over
//! `GF(p)`.
//!
//! `k = 1` is forbidden (a single hyperplane in `GF(p)^1` is a point —
//! the secret would be in plaintext).

use crate::field::PrimeField;
use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::secure::ct_eq_biguint;

/// One trustee's hyperplane equation
/// `a_1 y_1 + … + a_{k−1} y_{k−1} + y_k = b`. The `y_k` coefficient is
/// fixed at 1 by construction and is not stored.
#[derive(Clone, Eq, PartialEq)]
pub struct Share {
    /// The `k − 1` leading coefficients `(a_1, …, a_{k−1})`.
    pub a: Vec<BigUint>,
    /// The right-hand side `b`.
    pub b: BigUint,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Share(<elided>)")
    }
}

/// Distribute `n` Blakley shares of a single field-element secret.
///
/// # Panics
/// - `k < 2` (a degree-zero linear equation `y_1 = b` would be the
///   secret itself).
/// - `n < k` (cannot reconstruct otherwise).
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    k: usize,
    n: usize,
) -> Vec<Share> {
    assert!(k >= 2, "k must be at least 2 (k = 1 would leak the secret)");
    assert!(n >= k, "n must be at least k");

    // Fixed point P = (s, r_1, …, r_{k-1}). The first coordinate is the
    // secret; the rest are uniform field elements that stay private.
    let mut point: Vec<BigUint> = Vec::with_capacity(k);
    point.push(field.reduce(secret));
    for _ in 1..k {
        point.push(field.random(rng));
    }

    // Generate shares with a singularity guard on the FIRST k. The
    // paper-level claim is "any k shares reconstruct"; we implement
    // it for the first-k path by re-sampling those shares until the
    // resulting linear system is non-singular. For large fields the
    // resample is essentially never triggered; the cap exists so
    // pathologically small fields cannot loop forever.
    const MAX_RESAMPLE: usize = 64;
    let mut shares: Vec<Share> = Vec::with_capacity(n);
    for share_idx in 0..n {
        let mut attempt = 0usize;
        loop {
            let mut a: Vec<BigUint> = Vec::with_capacity(k - 1);
            for _ in 0..(k - 1) {
                a.push(field.random(rng));
            }
            // b = a · point[0..k-1] + point[k-1].
            let mut b = point[k - 1].clone();
            for j in 0..(k - 1) {
                let term = field.mul(&a[j], &point[j]);
                b = field.add(&b, &term);
            }
            let candidate = Share { a, b };
            // Re-sample only the first k shares for the rank guard.
            // Beyond i = k, accept whatever the RNG produced.
            if share_idx < k {
                shares.push(candidate);
                if first_k_full_rank(field, &shares) {
                    break;
                }
                shares.pop();
                attempt += 1;
                assert!(
                    attempt < MAX_RESAMPLE,
                    "Blakley split could not find a non-singular share \
                     within {MAX_RESAMPLE} resamples — field is too small \
                     for k = {k}",
                );
            } else {
                shares.push(candidate);
                break;
            }
        }
    }
    shares
}

/// Return whether the partially-built `shares` (used as the first
/// `shares.len()` rows of the augmented system) form a full-rank
/// leading block. Used by `split` to reject singular first-k matrices.
#[allow(clippy::needless_range_loop)]
fn first_k_full_rank(field: &PrimeField, shares: &[Share]) -> bool {
    let k = shares.len();
    if k == 0 {
        return true;
    }
    let coeff_len = shares[0].a.len() + 1; // k columns: (k-1 a's) + the y_k coefficient (1)
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for s in shares {
        let mut row = Vec::with_capacity(coeff_len);
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

/// Recover the secret from `k` (or more) Blakley shares by solving the
/// linear system. Returns `None` if the system is singular (which
/// happens with vanishing probability for honestly produced shares but
/// must be guarded against), if shares are malformed, or if `k < 2`.
///
/// Extra shares beyond `k` are validated against the recovered point;
/// any extra share inconsistent with the point causes refusal.
#[must_use]
#[allow(clippy::needless_range_loop)] // index-driven Gaussian elimination
pub fn reconstruct(field: &PrimeField, shares: &[Share], k: usize) -> Option<BigUint> {
    if k < 2 || shares.len() < k {
        return None;
    }
    for s in shares {
        if s.a.len() != k - 1 {
            return None;
        }
    }

    // Build the augmented k×(k+1) matrix. Row i is
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

    // Gaussian elimination over GF(p) with full pivoting on the
    // leading k columns.
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

    Some(point[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[19u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn round_trip() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        for &(k, n) in &[(2usize, 3usize), (3, 5), (5, 9), (4, 7)] {
            let shares = split(&f, &mut r, &secret, k, n);
            assert_eq!(shares.len(), n);
            assert_eq!(reconstruct(&f, &shares[..k], k), Some(secret.clone()));
            assert_eq!(reconstruct(&f, &shares[1..1 + k], k), Some(secret.clone()));
        }
    }

    #[test]
    fn extra_shares_are_consistent() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(98765);
        let shares = split(&f, &mut r, &secret, 3, 6);
        // Using all 6 shares (k = 3) — extras are validated.
        assert_eq!(reconstruct(&f, &shares, 3), Some(secret));
    }

    #[test]
    fn tampered_extra_share_is_rejected() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(424242);
        let mut shares = split(&f, &mut r, &secret, 3, 5);
        shares[4].b = f.add(&shares[4].b, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = split(&f, &mut r, &secret, 4, 6);
        assert!(reconstruct(&f, &shares[..3], 4).is_none());
    }

    #[test]
    #[should_panic(expected = "k must be at least 2")]
    fn split_rejects_k_one() {
        let f = small();
        let mut r = rng();
        let _ = split(&f, &mut r, &BigUint::from_u64(1), 1, 3);
    }

    #[test]
    fn tampered_first_extra_share_is_rejected() {
        // The validation loop must cover the boundary at index k. A
        // bound like `k+1..n` would miss the first extra and let one
        // tampered share past silently.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xCAFE);
        let mut shares = split(&f, &mut r, &secret, 3, 5);
        shares[3].b = f.add(&shares[3].b, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn tampered_exactly_one_extra_share_rejected() {
        // n = k + 1 is the minimal case where extras-validation runs:
        // exactly one extra. An off-by-one in the loop bounds would
        // leave this case uncovered while passing the larger fuzz cases.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xBAD);
        let mut shares = split(&f, &mut r, &secret, 3, 4);
        shares[3].b = f.add(&shares[3].b, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn malformed_share_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let mut shares = split(&f, &mut r, &secret, 3, 4);
        // Wrong-length `a` vector — refuse rather than misinterpret.
        shares[0].a.push(BigUint::one());
        assert!(reconstruct(&f, &shares, 3).is_none());
    }
}
