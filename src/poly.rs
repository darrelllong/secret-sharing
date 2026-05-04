//! Polynomial helpers shared by Shamir, the multi-secret extension,
//! the ramp scheme, and the errors-and-erasures decoder.
//!
//! Polynomials are stored as a coefficient vector
//! `c = [c_0, c_1, …, c_{d}]` representing
//! `c_0 + c_1 x + c_2 x^2 + … + c_d x^d`.

use crate::field::PrimeField;
use crate::bigint::BigUint;

/// Evaluate `f(x) = c_0 + c_1 x + … + c_{d} x^d` by Horner's rule.
#[must_use]
pub fn horner(field: &PrimeField, coeffs: &[BigUint], x: &BigUint) -> BigUint {
    let mut acc = BigUint::zero();
    for c in coeffs.iter().rev() {
        acc = field.add(&field.mul(&acc, x), c);
    }
    acc
}

/// Lagrange-evaluate the unique polynomial of degree `< points.len()`
/// passing through `points` at the abscissa `x_eval`.
///
/// Returns `None` if any two `x` coordinates collide (which makes the
/// system singular). Shamir 1979 §2 reduces to `lagrange_eval(.., 0)`.
#[must_use]
pub fn lagrange_eval(
    field: &PrimeField,
    points: &[(BigUint, BigUint)],
    x_eval: &BigUint,
) -> Option<BigUint> {
    let n = points.len();
    // Reduce every label modulo p before checking pairwise distinctness
    // — otherwise `x = 1` and `x = p + 1` look distinct but collide
    // inside the field, producing a zero denominator and a panic in
    // `lagrange_eval_unchecked`.
    let reduced: Vec<BigUint> = points.iter().map(|(x, _)| field.reduce(x)).collect();
    for r in &reduced {
        if r.is_zero() {
            // x = 0 is reserved for the secret; refuse honestly.
            return None;
        }
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if reduced[i] == reduced[j] {
                return None;
            }
        }
    }
    Some(lagrange_eval_unchecked(field, points, x_eval))
}

/// Inner Lagrange evaluator that assumes the caller has already
/// verified all `x` coordinates are distinct. Hot-path use only.
///
/// # Panics
/// Panics if two `x` coordinates collide. Use [`lagrange_eval`] from
/// any path that has not already validated input distinctness.
#[must_use]
pub fn lagrange_eval_unchecked(
    field: &PrimeField,
    points: &[(BigUint, BigUint)],
    x_eval: &BigUint,
) -> BigUint {
    let n = points.len();
    if n == 0 {
        return BigUint::zero();
    }
    let mut sum = BigUint::zero();
    for j in 0..n {
        let (xj, yj) = &points[j];
        let mut num = BigUint::one();
        let mut den = BigUint::one();
        for (i, (xi, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // L_j(x) = ∏_{i ≠ j} (x − x_i) / (x_j − x_i)
            num = field.mul(&num, &field.sub(x_eval, xi));
            den = field.mul(&den, &field.sub(xj, xi));
        }
        // `den` is a product of nonzero (xj − xi) factors in a prime
        // field, so it is nonzero and `inv` is guaranteed to succeed.
        let den_inv = field
            .inv(&den)
            .expect("Lagrange denominator nonzero given distinct x");
        let term = field.mul(yj, &field.mul(&num, &den_inv));
        sum = field.add(&sum, &term);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f257() -> PrimeField {
        PrimeField::new(BigUint::from_u64(257))
    }

    #[test]
    fn horner_matches_manual_eval() {
        // f(x) = 5 + 3x + 2x^2 → f(4) = 5 + 12 + 32 = 49
        let f = f257();
        let coeffs = vec![
            BigUint::from_u64(5),
            BigUint::from_u64(3),
            BigUint::from_u64(2),
        ];
        let v = horner(&f, &coeffs, &BigUint::from_u64(4));
        assert_eq!(v, BigUint::from_u64(49));
    }

    #[test]
    fn lagrange_recovers_polynomial() {
        // f(x) = 7 + 11x + 5x^2; sample at x = 1, 2, 3.
        let f = f257();
        let coeffs = vec![
            BigUint::from_u64(7),
            BigUint::from_u64(11),
            BigUint::from_u64(5),
        ];
        let pts: Vec<(BigUint, BigUint)> = (1..=3)
            .map(|i| {
                let x = BigUint::from_u64(i);
                let y = horner(&f, &coeffs, &x);
                (x, y)
            })
            .collect();
        // Constant term = secret = 7.
        assert_eq!(
            lagrange_eval(&f, &pts, &BigUint::zero()),
            Some(BigUint::from_u64(7))
        );
        // Should also reproduce f(4) = 7 + 44 + 80 = 131.
        assert_eq!(
            lagrange_eval(&f, &pts, &BigUint::from_u64(4)),
            Some(BigUint::from_u64(131))
        );
    }

    #[test]
    fn lagrange_rejects_duplicate_x() {
        let f = f257();
        let pts = vec![
            (BigUint::from_u64(1), BigUint::from_u64(7)),
            (BigUint::from_u64(1), BigUint::from_u64(8)),
        ];
        assert!(lagrange_eval(&f, &pts, &BigUint::zero()).is_none());
    }
}
