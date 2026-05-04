//! Kothari 1984, *Generalized Linear Threshold Scheme* — unifies
//! Shamir 1979, Blakley 1979, and Karnin–Greene–Hellman 1983 under one
//! linear-algebra framework.
//!
//! Given a public `k × n` matrix `A` over `GF(p)` whose every `k`
//! columns are linearly independent (Kothari's *spreading* condition),
//! and a length-`k` row vector `u = (s, r_2, …, r_k)` with `s` the
//! secret and the remaining components uniform random, share `i` is
//!
//! ```text
//!     v_i = u · A_i = s · A_{1,i} + r_2 · A_{2,i} + … + r_k · A_{k,i}
//! ```
//!
//! Recovery from any `k` shares stacks the corresponding column-system
//! into a `k × k` matrix `A_S`, solves `u · A_S = v_S` for `u`, and
//! returns `s = u_1`. The spreading condition makes every such `A_S`
//! invertible. Specialisations the paper points out:
//!
//! - **Shamir 1979.** Take `A_{j,i} = i^{j-1}` (the Vandermonde matrix);
//!   then `v_i = u_1 + u_2·i + … + u_k·i^{k-1}` is a polynomial
//!   evaluation and the secret sits in the constant term.
//! - **Blakley 1979.** Take `A_{1,i} = α_i`, `A_{j,i} = β_{j,i}` with
//!   the last row all-ones; then each `v_i = b_i` is the right-hand
//!   side of a hyperplane equation `α_i s + Σ β_{j,i} r_j + r_k = b_i`.
//! - **Karnin–Greene–Hellman §II.** Take any user-supplied bank of
//!   `m`-column matrices `A_i` (vector secrets `s ∈ GF(p)^m`);
//!   `crate::kgh` instantiates this with the Vandermonde bank.
//!
//! This module exposes the *general* form: the caller supplies `A`
//! along with proof-by-construction (the spreading condition is checked
//! via Gaussian elimination on every `k`-subset, so we provide an
//! optional checker for small `n`).
//!
//! Threat model. Information-theoretic perfect secrecy below threshold
//! holds against a passive eavesdropper given uniform random `r_2..r_k`.
//! `BigUint` arithmetic in this crate is documented as *variable-time*,
//! so a co-located timing observer can in principle distinguish bit
//! lengths of operands during `field.mul`. Nothing here is constant-
//! time; do not deploy in side-channel-exposed environments.

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::secure::ct_eq_biguint;

/// Public matrix `A ∈ GF(p)^{k × n}` and its threshold `k`.
#[derive(Clone, Debug)]
pub struct LinearScheme {
    field: PrimeField,
    /// `A[r][c]` is the entry in row `r`, column `c`. Stored row-major.
    rows: Vec<Vec<BigUint>>,
    k: usize,
    n: usize,
}

impl LinearScheme {
    /// Wrap a public `k × n` matrix with no spreading-condition check.
    /// The caller is responsible for ensuring every `k` columns are
    /// linearly independent over `GF(p)`. Use [`Self::new_checked`] for
    /// a runtime check (exponential in `n` choose `k`).
    ///
    /// # Panics
    /// - `k < 2`,
    /// - `n < k`,
    /// - `rows.len() != k` or any `row.len() != n`.
    #[must_use]
    pub fn new(field: PrimeField, rows: Vec<Vec<BigUint>>, k: usize, n: usize) -> Self {
        assert!(k >= 2, "k must be at least 2");
        assert!(n >= k, "n must be at least k");
        assert_eq!(rows.len(), k, "rows.len() must equal k");
        for r in &rows {
            assert_eq!(r.len(), n, "every row must have n entries");
        }
        Self { field, rows, k, n }
    }

    /// Wrap a matrix and verify the spreading condition by exhaustively
    /// checking every `k`-subset of columns. Returns `None` if any
    /// such subset is linearly dependent.
    ///
    /// Cost is `C(n, k) · O(k^3)` field operations — fine for tests
    /// and small parameter sets, prohibitive for large `n`.
    #[must_use]
    pub fn new_checked(
        field: PrimeField,
        rows: Vec<Vec<BigUint>>,
        k: usize,
        n: usize,
    ) -> Option<Self> {
        let scheme = Self::new(field, rows, k, n);
        let mut indices = Vec::with_capacity(k);
        if scheme.spreading_holds(&mut indices, 0) {
            Some(scheme)
        } else {
            None
        }
    }

    fn spreading_holds(&self, indices: &mut Vec<usize>, start: usize) -> bool {
        if indices.len() == self.k {
            return self.submatrix_invertible(indices);
        }
        for c in start..self.n {
            indices.push(c);
            if !self.spreading_holds(indices, c + 1) {
                indices.pop();
                return false;
            }
            indices.pop();
        }
        true
    }

    /// Return true iff the `k × k` submatrix on the given `k` columns
    /// is invertible over the field.
    #[allow(clippy::needless_range_loop)]
    fn submatrix_invertible(&self, columns: &[usize]) -> bool {
        let k = self.k;
        let mut mat: Vec<Vec<BigUint>> = (0..k)
            .map(|r| columns.iter().map(|&c| self.rows[r][c].clone()).collect())
            .collect();
        // Plain row-reduction with no augmented column: just check that
        // every pivot can be located.
        for col in 0..k {
            let mut pivot_row = None;
            for r in col..k {
                if !mat[r][col].is_zero() {
                    pivot_row = Some(r);
                    break;
                }
            }
            let pr = match pivot_row {
                Some(p) => p,
                None => return false,
            };
            if pr != col {
                mat.swap(pr, col);
            }
            let inv = match self.field.inv(&mat[col][col]) {
                Some(v) => v,
                None => return false,
            };
            for c in col..k {
                mat[col][c] = self.field.mul(&mat[col][c], &inv);
            }
            for r in 0..k {
                if r == col || mat[r][col].is_zero() {
                    continue;
                }
                let factor = mat[r][col].clone();
                for c in col..k {
                    let term = self.field.mul(&factor, &mat[col][c]);
                    mat[r][c] = self.field.sub(&mat[r][c], &term);
                }
            }
        }
        true
    }

    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    #[must_use]
    pub fn field(&self) -> &PrimeField {
        &self.field
    }
}

/// Distribute the secret across all `n` trustees.
///
/// Returns `n` shares, one per column of `A`. Share `i` is `u · A_i`.
///
/// # Panics
/// - `secret >= p` — out-of-range inputs are rejected at the boundary
///   rather than silently reduced. Callers who need wrap-around must
///   call `field.reduce(secret)` themselves before invoking `split`.
#[must_use]
pub fn split<R: Csprng>(scheme: &LinearScheme, rng: &mut R, secret: &BigUint) -> Vec<BigUint> {
    assert!(
        secret < scheme.field.modulus(),
        "secret must be < field modulus; reduce explicitly if wrap-around is intended"
    );
    let mut u: Vec<BigUint> = Vec::with_capacity(scheme.k);
    u.push(secret.clone());
    for _ in 1..scheme.k {
        u.push(scheme.field.random(rng));
    }
    (0..scheme.n)
        .map(|c| {
            let mut acc = BigUint::zero();
            #[allow(clippy::needless_range_loop)]
            for r in 0..scheme.k {
                let term = scheme.field.mul(&u[r], &scheme.rows[r][c]);
                acc = scheme.field.add(&acc, &term);
            }
            acc
        })
        .collect()
}

/// Recover the secret from any `k` (or more) shares supplied as
/// `(column_index, value)` pairs. Returns `None` if fewer than `k` are
/// supplied, columns repeat, or the chosen submatrix is singular
/// (which violates the caller's spreading-condition assertion).
///
/// Extra shares beyond the first `k` are validated against the
/// recovered `u`; a disagreement returns `None`.
///
/// **Robustness limit.** When *exactly* `k` shares are supplied there
/// is no redundancy, so a tampered share produces a silently wrong
/// secret — the linear system has the same shape as Lagrange
/// interpolation in this regard. Pass extras (`shares.len() > k`) when
/// adversarial parties are in scope, or pair with [`crate::vss`] for
/// pre-validated shares.
#[must_use]
pub fn reconstruct(scheme: &LinearScheme, shares: &[(usize, BigUint)]) -> Option<BigUint> {
    let k = scheme.k;
    if shares.len() < k {
        return None;
    }
    for &(c, _) in shares {
        if c >= scheme.n {
            return None;
        }
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].0 == shares[j].0 {
                return None;
            }
        }
    }

    // Build the augmented system: `u · A_S = v_S`.
    // Equivalently, solve `A_S^T · u^T = v_S^T`.
    let used = &shares[..k];
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for (row_in_system, (col, val)) in used.iter().enumerate() {
        let mut row = Vec::with_capacity(k + 1);
        for r in 0..k {
            row.push(scheme.rows[r][*col].clone());
        }
        row.push(val.clone());
        let _ = row_in_system;
        mat.push(row);
    }
    let solution = gaussian_eliminate(&scheme.field, &mut mat)?;

    // Validate extras against the recovered u.
    for (col, val) in &shares[k..] {
        let mut acc = BigUint::zero();
        #[allow(clippy::needless_range_loop)]
        for r in 0..k {
            let term = scheme.field.mul(&solution[r], &scheme.rows[r][*col]);
            acc = scheme.field.add(&acc, &term);
        }
        if !ct_eq_biguint(&acc, val) {
            return None;
        }
    }

    Some(solution[0].clone())
}

/// In-place Gaussian elimination of a `k × (k + 1)` augmented matrix.
/// Returns `Some(solution_vector)` of length `k` on success, `None` if
/// the leading `k × k` block is singular.
#[allow(clippy::needless_range_loop)]
fn gaussian_eliminate(field: &PrimeField, mat: &mut [Vec<BigUint>]) -> Option<Vec<BigUint>> {
    let k = mat.len();
    if k == 0 {
        return Some(vec![]);
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
        let row_len = mat[col].len();
        for c in col..row_len {
            mat[col][c] = field.mul(&mat[col][c], &inv);
        }
        for r in 0..k {
            if r == col || mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..row_len {
                let term = field.mul(&factor, &mat[col][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
    }
    Some((0..k).map(|i| mat[i][k].clone()).collect())
}

/// Convenience: build the Vandermonde public matrix `A_{j,i} = i^{j-1}`
/// for `1 ≤ i ≤ n`, `1 ≤ j ≤ k`. Specialises the generalised scheme to
/// the Shamir-equivalent case.
///
/// # Panics
/// - `k < 2` or `n < k`,
/// - `n ≥ p` (need `n` distinct nonzero abscissae).
#[must_use]
pub fn vandermonde(field: PrimeField, k: usize, n: usize) -> LinearScheme {
    assert!(k >= 2 && n >= k, "need 2 ≤ k ≤ n");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n"
    );
    let mut rows: Vec<Vec<BigUint>> = (0..k).map(|_| Vec::with_capacity(n)).collect();
    for c in 0..n {
        let i = BigUint::from_u64((c + 1) as u64);
        let mut pow = BigUint::one();
        #[allow(clippy::needless_range_loop)]
        for r in 0..k {
            rows[r].push(pow.clone());
            pow = field.mul(&pow, &i);
        }
    }
    LinearScheme::new(field, rows, k, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x4Bu8; 32])
    }

    fn small() -> PrimeField {
        // 2^61 − 1 (Mersenne prime) — comfortably bigger than every
        // hex-y secret the tests use.
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    fn tiny() -> PrimeField {
        // Compact field for the spreading-condition checker tests.
        PrimeField::new(BigUint::from_u64(65_537))
    }

    #[test]
    fn vandermonde_round_trip() {
        let scheme = vandermonde(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = split(&scheme, &mut r, &secret);
        assert_eq!(shares.len(), 5);
        // Take any 3 columns to reconstruct.
        let pairs: Vec<(usize, BigUint)> = (0..3).map(|c| (c, shares[c].clone())).collect();
        assert_eq!(reconstruct(&scheme, &pairs), Some(secret.clone()));
        let pairs: Vec<(usize, BigUint)> = vec![
            (0, shares[0].clone()),
            (2, shares[2].clone()),
            (4, shares[4].clone()),
        ];
        assert_eq!(reconstruct(&scheme, &pairs), Some(secret));
    }

    #[test]
    fn extras_validated_and_tampering_rejected() {
        let scheme = vandermonde(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(42);
        let shares = split(&scheme, &mut r, &secret);
        let all: Vec<(usize, BigUint)> =
            (0..5).map(|c| (c, shares[c].clone())).collect();
        assert_eq!(reconstruct(&scheme, &all), Some(secret));

        let mut bad = all;
        bad[4].1 = scheme.field.add(&bad[4].1, &BigUint::from_u64(1));
        assert!(reconstruct(&scheme, &bad).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let scheme = vandermonde(small(), 4, 6);
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = split(&scheme, &mut r, &secret);
        let pairs: Vec<(usize, BigUint)> = (0..3).map(|c| (c, shares[c].clone())).collect();
        assert!(reconstruct(&scheme, &pairs).is_none());
    }

    #[test]
    fn duplicate_column_rejected() {
        let scheme = vandermonde(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&scheme, &mut r, &secret);
        let pairs = vec![
            (0, shares[0].clone()),
            (0, shares[0].clone()),
            (1, shares[1].clone()),
        ];
        assert!(reconstruct(&scheme, &pairs).is_none());
    }

    #[test]
    fn out_of_range_column_rejected() {
        let scheme = vandermonde(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&scheme, &mut r, &secret);
        let pairs = vec![
            (0, shares[0].clone()),
            (1, shares[1].clone()),
            (5, shares[0].clone()),
        ];
        assert!(reconstruct(&scheme, &pairs).is_none());
    }

    #[test]
    fn checked_constructor_accepts_vandermonde() {
        // Build the Vandermonde rows by hand and run new_checked.
        let f = tiny();
        let k = 3;
        let n = 5;
        let mut rows: Vec<Vec<BigUint>> = (0..k).map(|_| Vec::with_capacity(n)).collect();
        for c in 0..n {
            let i = BigUint::from_u64((c + 1) as u64);
            let mut pow = BigUint::one();
            #[allow(clippy::needless_range_loop)]
            for r in 0..k {
                rows[r].push(pow.clone());
                pow = f.mul(&pow, &i);
            }
        }
        assert!(LinearScheme::new_checked(f, rows, k, n).is_some());
    }

    #[test]
    fn exactly_k_shares_with_one_tamper_silently_wrong() {
        // AD #1 (P1): documents that the docstring's "robustness limit"
        // matches reality — no redundancy, tampered first-k yields a
        // wrong secret rather than None.
        let scheme = vandermonde(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = split(&scheme, &mut r, &secret);
        let mut bad = vec![
            (0, shares[0].clone()),
            (1, shares[1].clone()),
            (2, shares[2].clone()),
        ];
        bad[0].1 = scheme.field.add(&bad[0].1, &BigUint::from_u64(1));
        let got = reconstruct(&scheme, &bad).expect("k shares always solve");
        assert_ne!(got, secret);
    }

    #[test]
    #[should_panic(expected = "secret must be < field modulus")]
    fn split_rejects_oversize_secret() {
        // AD #2 (P1): split asserts on out-of-range inputs.
        let scheme = vandermonde(tiny(), 3, 5); // modulus 65537
        let mut r = rng();
        let _ = split(&scheme, &mut r, &BigUint::from_u64(70_000));
    }

    #[test]
    fn checked_constructor_rejects_repeated_column() {
        // Two identical columns destroys spreading.
        let f = tiny();
        let k = 2;
        let n = 3;
        let rows = vec![
            vec![
                BigUint::from_u64(1),
                BigUint::from_u64(1),
                BigUint::from_u64(2),
            ],
            vec![
                BigUint::from_u64(3),
                BigUint::from_u64(3),
                BigUint::from_u64(7),
            ],
        ];
        assert!(LinearScheme::new_checked(f, rows, k, n).is_none());
    }
}
