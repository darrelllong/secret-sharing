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
/// The per-point denominator inverses come from Montgomery's batch
/// trick: invert the single product `∏ den_j` with one extended-gcd
/// call, then peel off each individual inverse with two multiplies.
/// Inversion (several `div_rem` rounds inside `mod_inverse`) dominates
/// the cost of a reconstruction, so doing it once instead of k times
/// is the difference that matters as the threshold grows.
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

    // den[j] = ∏_{i≠j} (x_j − x_i); each factor is nonzero in a prime
    // field because the x's are distinct, so every den is invertible.
    let mut dens: Vec<BigUint> = Vec::with_capacity(n);
    for j in 0..n {
        let xj = &points[j].0;
        let mut den = BigUint::one();
        for (i, (xi, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            den = field.mul(&den, &field.sub(xj, xi));
        }
        dens.push(den);
    }

    // Batch inversion. Forward pass: prefix[j] = den_0 · … · den_{j−1}.
    let mut prefix: Vec<BigUint> = Vec::with_capacity(n);
    let mut acc = BigUint::one();
    for den in &dens {
        prefix.push(acc.clone());
        acc = field.mul(&acc, den);
    }
    // Backward pass: peel den_j off the running inverse so that
    // inv_acc always equals (den_0 · … · den_j)^{-1} entering step j.
    let mut inv_acc = field
        .inv(&acc)
        .expect("Lagrange denominator product nonzero given distinct x");
    let mut den_invs = vec![BigUint::zero(); n];
    for j in (0..n).rev() {
        den_invs[j] = field.mul(&inv_acc, &prefix[j]);
        inv_acc = field.mul(&inv_acc, &dens[j]);
    }

    let mut sum = BigUint::zero();
    for j in 0..n {
        let (_, yj) = &points[j];
        let mut num = BigUint::one();
        for (i, (xi, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // L_j(x) = ∏_{i ≠ j} (x − x_i) / (x_j − x_i)
            num = field.mul(&num, &field.sub(x_eval, xi));
        }
        let term = field.mul(yj, &field.mul(&num, &den_invs[j]));
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
