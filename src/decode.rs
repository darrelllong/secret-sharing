//! McEliece–Sarwate 1981 errors-and-erasures recovery via the
//! **Berlekamp–Welch** algorithm.
//!
//! McEliece–Sarwate §1 cites errors-and-erasures decoding of Reed–
//! Solomon codes (Berlekamp 1968, Sugiyama et al. 1976) as the
//! polynomial-time route to recovering Shamir secrets in the presence
//! of `t` tampered shares whenever the bound
//! `m − 2t ≥ k` (equivalently `m ≥ k + 2t`) holds.
//!
//! Berlekamp–Welch in field-element form: given `m` shares
//! `(x_i, y_i)` purportedly evaluating a polynomial `M(x)` of degree
//! `< k`, find polynomials `Q(x)` of degree `< k + t` and `E(x)` of
//! degree `≤ t` with `E ≢ 0` such that
//!
//! ```text
//! Q(x_i) = y_i · E(x_i)        for i = 1, …, m
//! ```
//!
//! Then `M(x) = Q(x) / E(x)` (exact division). The unknowns are the
//! `k + t` coefficients of `Q` and the `t + 1` coefficients of `E`,
//! a total of `k + 2t + 1` unknowns satisfying `m` linear equations.
//! With `m ≥ k + 2t` the homogeneous coefficient matrix has at least a
//! one-dimensional null space, and any non-zero kernel vector
//! corresponds to a valid `(Q, E)` (all such kernel vectors are scalar
//! multiples of the same `(Q^*, E^*)`).
//!
//! Complexity: one Gaussian elimination on an `m × (k + 2t + 1)`
//! matrix → `O(m · (k + 2t)^2)` field operations, plus `O(k · t)`
//! polynomial division. Polynomial in every input — the brute-force
//! `C(m, k)`-subset enumeration is gone.

use crate::field::PrimeField;
use crate::poly::horner;
use crate::secure::ct_eq_biguint;
use crate::shamir::Share;
use crate::bigint::BigUint;

/// Robust Shamir recovery against `max_errors` adversarially modified
/// shares, plus arbitrary erasures (via simply not supplying them).
/// Implements Berlekamp–Welch.
///
/// Returns `None` if:
/// - `k == 0` or `shares.len() < k + 2 * max_errors`,
/// - any share's `x` is zero, or any two shares share an `x`,
/// - the linear system has no non-zero solution (impossible above the
///   decoding radius — only happens if the caller exceeds it),
/// - polynomial division of `Q` by `E` is not exact (i.e. more than
///   `max_errors` shares are actually corrupted), or
/// - the resulting message polynomial fails the McEliece–Sarwate
///   agreement bound (defence-in-depth check).
///
/// **Beyond the decoding radius.** When the *actual* number of
/// tampered shares exceeds `max_errors`, multiple degree-`< k`
/// polynomials may simultaneously satisfy the agreement threshold
/// `≥ k + max_errors`. In that regime this function may return
/// `Some(wrong_secret)` rather than `None` — the routine returns the
/// first kernel-basis solution that passes the agreement check, not
/// the *unique* decoding (which does not exist beyond the radius).
/// Callers who need a fail-closed guarantee against unknown-error-
/// count adversarial inputs must layer authentication over the
/// shares (e.g. wrap with `crate::vss`).
#[must_use]
pub fn reconstruct_with_errors(
    field: &PrimeField,
    shares: &[Share],
    k: usize,
    max_errors: usize,
) -> Option<BigUint> {
    let m = shares.len();
    let needed = k.checked_add(2usize.checked_mul(max_errors)?)?;
    if k == 0 || m < needed {
        return None;
    }
    for s in shares {
        if s.x.is_zero() {
            return None;
        }
    }
    for i in 0..m {
        for j in (i + 1)..m {
            if shares[i].x == shares[j].x {
                return None;
            }
        }
    }

    if max_errors == 0 {
        // Pure Lagrange — no error-locator needed.
        let pts: Vec<(BigUint, BigUint)> = shares
            .iter()
            .take(k)
            .map(|s| (s.x.clone(), s.y.clone()))
            .collect();
        let secret = crate::poly::lagrange_eval_unchecked(field, &pts, &BigUint::zero());
        // Validate against extras (defence-in-depth).
        for s in &shares[k..] {
            let pred = crate::poly::lagrange_eval_unchecked(field, &pts, &s.x);
            if !ct_eq_biguint(&pred, &s.y) {
                return None;
            }
        }
        return Some(secret);
    }

    let t = max_errors;
    let q_len = k + t; // q_0 .. q_{k+t-1}
    let e_len = t + 1; // e_0 .. e_t
    let cols = q_len + e_len;

    // Build the m × cols coefficient matrix:
    //   row i: [1, x_i, …, x_i^{q_len-1}, -y_i, -y_i x_i, …, -y_i x_i^{e_len-1}]
    // representing Σ q_j x_i^j − y_i Σ e_j x_i^j = 0.
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(m);
    for s in shares {
        let mut row = Vec::with_capacity(cols);
        let mut pow = BigUint::one();
        let mut row_pows: Vec<BigUint> = Vec::with_capacity(q_len.max(e_len));
        for _ in 0..q_len.max(e_len) {
            row_pows.push(pow.clone());
            pow = field.mul(&pow, &s.x);
        }
        for p in row_pows.iter().take(q_len) {
            row.push(p.clone());
        }
        for p in row_pows.iter().take(e_len) {
            // − y_i · x_i^j
            row.push(field.neg(&field.mul(&s.y, p)));
        }
        mat.push(row);
    }

    // Gaussian elimination to reduced row echelon form. Track pivot
    // columns; the null-space basis is read off the free columns.
    let kernel = nullspace_basis(field, &mut mat, cols)?;

    // Try every kernel basis vector (almost always one) and pick the
    // (Q, E) pair that gives an exact division and a high-agreement M.
    for vec in kernel {
        // E must be nonzero — otherwise Q ≡ 0 too and the kernel vector
        // is trivial; skip.
        let q_coeffs: &[BigUint] = &vec[..q_len];
        let e_coeffs: &[BigUint] = &vec[q_len..];
        if e_coeffs.iter().all(|c| c.is_zero()) {
            continue;
        }
        // Polynomial divide Q by E. If the remainder is non-zero, this
        // particular kernel vector does not encode a valid codeword —
        // try the next one.
        let Some(m_coeffs) = poly_div_exact(field, q_coeffs, e_coeffs, k) else {
            continue;
        };
        // Sanity-check: polynomial agrees with at least k + t shares.
        // Use ct_eq so the agreement count's per-share branch latency
        // does not leak which shares lie on the recovered codeword.
        let mut agree = 0usize;
        for s in shares {
            let pred = horner(field, &m_coeffs, &s.x);
            if ct_eq_biguint(&pred, &s.y) {
                agree += 1;
            }
        }
        if agree >= k + t {
            return Some(horner(field, &m_coeffs, &BigUint::zero()));
        }
    }

    None
}

/// Reduce `mat` (m × cols) to reduced row-echelon form in place and
/// return a basis for its null space as a `Vec<Vec<BigUint>>`. Each
/// kernel vector has length `cols`. Returns `None` if the matrix has
/// trivial null space (only the zero vector).
#[allow(clippy::needless_range_loop)] // index-driven Gaussian elimination
fn nullspace_basis(
    field: &PrimeField,
    mat: &mut [Vec<BigUint>],
    cols: usize,
) -> Option<Vec<Vec<BigUint>>> {
    let m = mat.len();
    let mut pivot_cols: Vec<usize> = Vec::new();
    let mut row = 0;
    for col in 0..cols {
        if row >= m {
            break;
        }
        // Locate a pivot in column `col` at or below `row`.
        let mut pr = None;
        for r in row..m {
            if !mat[r][col].is_zero() {
                pr = Some(r);
                break;
            }
        }
        let Some(pr) = pr else {
            continue;
        };
        if pr != row {
            mat.swap(pr, row);
        }
        // Normalize so mat[row][col] = 1.
        let inv = field.inv(&mat[row][col])?;
        for c in col..cols {
            mat[row][c] = field.mul(&mat[row][c], &inv);
        }
        // Eliminate column `col` in every other row.
        for r in 0..m {
            if r == row {
                continue;
            }
            if mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..cols {
                let term = field.mul(&factor, &mat[row][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
        pivot_cols.push(col);
        row += 1;
    }

    let free_cols: Vec<usize> = (0..cols).filter(|c| !pivot_cols.contains(c)).collect();
    if free_cols.is_empty() {
        return None;
    }

    // For each free column f, build a kernel vector by setting the f-th
    // coordinate to 1 and other free coordinates to 0; then back-solve
    // the pivot rows.
    let mut basis: Vec<Vec<BigUint>> = Vec::with_capacity(free_cols.len());
    for &f in &free_cols {
        let mut v = vec![BigUint::zero(); cols];
        v[f] = BigUint::one();
        for (i, &pc) in pivot_cols.iter().enumerate() {
            // pivot row i says: x_{pc} + Σ_{c ∈ free} mat[i][c] · x_c = 0
            // ⇒ x_{pc} = − mat[i][f]   (since v[free] = e_f)
            v[pc] = field.neg(&mat[i][f]);
        }
        basis.push(v);
    }

    Some(basis)
}

/// Polynomial division `Q(x) / E(x)`. Returns the quotient (length
/// `expected_quot_len`) iff division is exact and the quotient has
/// length at most `expected_quot_len`. Coefficient layout matches
/// `poly::horner`: index 0 is the constant term.
fn poly_div_exact(
    field: &PrimeField,
    q: &[BigUint],
    e: &[BigUint],
    expected_quot_len: usize,
) -> Option<Vec<BigUint>> {
    // Strip leading-zero coefficients (highest-index entries).
    let strip = |v: &[BigUint]| -> Vec<BigUint> {
        let mut end = v.len();
        while end > 0 && v[end - 1].is_zero() {
            end -= 1;
        }
        v[..end].to_vec()
    };
    let mut rem = strip(q);
    let div = strip(e);
    if div.is_empty() {
        return None;
    }
    let deg_div = div.len() - 1;
    let lead_inv = field.inv(&div[deg_div])?;

    if rem.len() < div.len() {
        // Quotient is zero. Accept iff Q is also zero, otherwise not exact.
        if rem.is_empty() {
            return Some(vec![BigUint::zero(); expected_quot_len]);
        }
        return None;
    }

    let mut quot = vec![BigUint::zero(); rem.len() - deg_div];
    while rem.len() > deg_div {
        let deg_rem = rem.len() - 1;
        let coef = field.mul(&rem[deg_rem], &lead_inv);
        let shift = deg_rem - deg_div;
        quot[shift] = coef.clone();
        // rem -= coef · x^shift · div
        for j in 0..=deg_div {
            let term = field.mul(&coef, &div[j]);
            rem[shift + j] = field.sub(&rem[shift + j], &term);
        }
        // Trim
        while !rem.is_empty() && rem.last().unwrap().is_zero() {
            rem.pop();
        }
    }
    if !rem.is_empty() {
        return None;
    }
    if quot.len() > expected_quot_len {
        // Truncate trailing zeros if any; if non-zero entries remain
        // past `expected_quot_len`, the quotient has too high a degree.
        for c in &quot[expected_quot_len..] {
            if !c.is_zero() {
                return None;
            }
        }
        quot.truncate(expected_quot_len);
    } else {
        quot.resize(expected_quot_len, BigUint::zero());
    }
    Some(quot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::split;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[1u8; 32])
    }

    fn small_field() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn no_errors_matches_plain_reconstruct() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0x0C0D_EBAD_F00D);
        let shares = split(&f, &mut r, &secret, 3, 7);
        let got = reconstruct_with_errors(&f, &shares, 3, 0).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn corrects_one_tampered_share() {
        // (k, n) = (3, 7), max_errors = 1 needs m ≥ k + 2t = 5.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xABCD_1234);
        let mut shares = split(&f, &mut r, &secret, 3, 7);
        shares[4].y = f.add(&shares[4].y, &BigUint::from_u64(1));
        let got = reconstruct_with_errors(&f, &shares, 3, 1).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn corrects_two_tampered_shares() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xFEED_F00D);
        let mut shares = split(&f, &mut r, &secret, 3, 9);
        shares[1].y = f.add(&shares[1].y, &BigUint::from_u64(7));
        shares[6].y = f.add(&shares[6].y, &BigUint::from_u64(13));
        let got = reconstruct_with_errors(&f, &shares, 3, 2).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn corrects_three_tampered_shares() {
        // Larger configuration: (k, n) = (4, 11), t = 3 needs m ≥ 10.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0x1234_5678_9ABC);
        let mut shares = split(&f, &mut r, &secret, 4, 11);
        shares[0].y = f.add(&shares[0].y, &BigUint::from_u64(1));
        shares[5].y = BigUint::zero();
        shares[10].y = f.add(&shares[10].y, &BigUint::from_u64(99));
        let got = reconstruct_with_errors(&f, &shares, 4, 3).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn fails_above_decoding_radius() {
        // 3 errors against (k, n) = (3, 7) would need m ≥ 9 for t = 3.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xBAAA);
        let mut shares = split(&f, &mut r, &secret, 3, 7);
        for s in shares.iter_mut().take(3) {
            s.y = f.add(&s.y, &BigUint::from_u64(1));
        }
        // Even at t = 2 (m = 7 ≥ 7) the agreement bound fails because
        // the truth poly only matches 4 < k + t = 5 shares.
        assert!(reconstruct_with_errors(&f, &shares, 3, 2).is_none());
    }

    #[test]
    fn handles_erasures_via_omission() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0x1357_9BDF);
        let shares = split(&f, &mut r, &secret, 3, 7);
        let got = reconstruct_with_errors(&f, &shares[..4], 3, 0).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn rejects_below_radius() {
        // (k, n) = (3, 6), t = 2 needs m ≥ 7 — supply only 6, must refuse.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xAA);
        let shares = split(&f, &mut r, &secret, 3, 6);
        assert!(reconstruct_with_errors(&f, &shares, 3, 2).is_none());
    }

    #[test]
    fn poly_div_exact_basic() {
        // (x^2 + 3x + 2) / (x + 1) = x + 2
        let f = PrimeField::new(BigUint::from_u64(257));
        let q = vec![
            BigUint::from_u64(2),
            BigUint::from_u64(3),
            BigUint::from_u64(1),
        ];
        let e = vec![BigUint::from_u64(1), BigUint::from_u64(1)];
        let m = poly_div_exact(&f, &q, &e, 2).unwrap();
        assert_eq!(m, vec![BigUint::from_u64(2), BigUint::from_u64(1)]);
    }

    #[test]
    fn poly_div_inexact_returns_none() {
        // (x^2 + 1) / (x + 1) leaves remainder.
        let f = PrimeField::new(BigUint::from_u64(257));
        let q = vec![
            BigUint::from_u64(1),
            BigUint::from_u64(0),
            BigUint::from_u64(1),
        ];
        let e = vec![BigUint::from_u64(1), BigUint::from_u64(1)];
        assert!(poly_div_exact(&f, &q, &e, 2).is_none());
    }
}
