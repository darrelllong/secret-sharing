//! Shamir 1979 (k, n) threshold scheme, plus the Karnin–Greene–Hellman
//! 1983 §IV multi-secret extension.
//!
//! Single-secret form (Shamir §2):
//! - Pick a random degree-`(k − 1)` polynomial
//!   `q(x) = a_0 + a_1 x + … + a_{k-1} x^{k-1}` with `a_0 = D` and the
//!   remaining coefficients drawn uniformly from `[0, p)`.
//! - Trustee `i ∈ {1, …, n}` is given `(i, q(i) mod p)`.
//! - Any `k` shares interpolate `q(x)` and yield `D = q(0)`. Knowledge
//!   of `k − 1` or fewer shares is uniform over the `p` candidate
//!   secrets.
//!
//! Karnin–Greene–Hellman 1983 §IV (their equations 23–24, restated as
//! Note 1 in §III: the Vandermonde matrix scheme reduces to Shamir's
//! scheme with the polynomial `D(x) = u_1 + u_2 x + … + u_k x^{k-1}`):
//! pack `ℓ ≤ k` independent secrets into the lowest-order coefficients
//! `a_0, …, a_{ℓ-1}` and fill the upper coefficients with random
//! padding. Any `k` trustees recover all `ℓ` secrets simultaneously,
//! and any `k − 1` trustees learn nothing about any single secret.

use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::secure::{ct_eq_biguint, Zeroizing};

/// One trustee's piece: an `(x, y)` evaluation of the sharing
/// polynomial. The `x` coordinate is public and acts as the trustee's
/// label.
#[derive(Clone, Eq, PartialEq)]
pub struct Share {
    pub x: BigUint,
    pub y: BigUint,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Share(<elided>)")
    }
}

/// Shamir (k, n) split. `k` is the reconstruction threshold and `n` the
/// number of shares.
///
/// # Panics
/// - `k < 2` (a degree-0 polynomial would put the secret in every
///   share's `y`).
/// - `n < k`.
/// - `n ≥ p` — Shamir requires `n + 1` distinct nonzero abscissae in
///   `[0, p)`, hence `p > n`.
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
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );

    // Wrap the polynomial coefficients in `Zeroizing` so the secret
    // (a_0) and every random pad (a_1..a_{k-1}) get volatile-zeroed
    // when this function returns — even on early panic. The Vec's
    // BigUint elements still self-zeroize on Drop; Zeroizing is the
    // belt-and-braces guarantee that the *outer* allocation is also
    // scrubbed and not handed back to the allocator with residue.
    let mut coeffs = Zeroizing::new(Vec::<BigUint>::with_capacity(k));
    coeffs.push(field.reduce(secret));
    for _ in 1..k {
        coeffs.push(field.random(rng));
    }

    (1..=n)
        .map(|i| {
            let x = BigUint::from_u64(i as u64);
            let y = horner(field, &coeffs, &x);
            Share { x, y }
        })
        .collect()
}

/// Recover the Shamir secret from at least `k` shares using Lagrange
/// interpolation evaluated at `x = 0`. The first `k` shares are used to
/// fit a degree-`(k − 1)` polynomial; any extras are validated against
/// that polynomial and the function returns `None` if any disagrees,
/// so a caller cannot accidentally accept an inconsistent share set.
///
/// Returns `None` if:
/// - `shares.len() < k`,
/// - any share has a zero `x` modulo `p`,
/// - any two shares have `x` coordinates congruent modulo `p`,
/// - any extra share (index `≥ k`) disagrees with the polynomial fit
///   to the first `k`.
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[Share], k: usize) -> Option<BigUint> {
    if k == 0 || shares.len() < k {
        return None;
    }
    let xs: Vec<BigUint> = shares.iter().map(|s| field.reduce(&s.x)).collect();
    for x in &xs {
        if x.is_zero() {
            return None;
        }
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if xs[i] == xs[j] {
                return None;
            }
        }
    }
    let pts: Vec<(BigUint, BigUint)> = xs[..k]
        .iter()
        .zip(&shares[..k])
        .map(|(x, s)| (x.clone(), s.y.clone()))
        .collect();
    let secret = lagrange_eval(field, &pts, &BigUint::zero())?;

    for (x, s) in xs[k..].iter().zip(&shares[k..]) {
        let pred = lagrange_eval(field, &pts, x)?;
        if !ct_eq_biguint(&pred, &s.y) {
            return None;
        }
    }
    Some(secret)
}

/// Karnin–Greene–Hellman §IV multi-secret split. `secrets.len()` must
/// satisfy `1 ≤ ℓ ≤ k`. The first `ℓ` polynomial coefficients carry
/// the secrets in order; the remaining `k − ℓ` coefficients are random.
/// All `n` trustees still receive a single `(x, y)` share each.
///
/// # Panics
/// - `k < 2` (a degree-0 polynomial would put the secrets in every
///   share's `y`).
/// - `secrets.len()` outside `1..=k`.
/// - `n < k`.
/// - `n ≥ p`.
#[must_use]
pub fn split_multi<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secrets: &[BigUint],
    k: usize,
    n: usize,
) -> Vec<Share> {
    let l = secrets.len();
    assert!(k >= 2, "k must be at least 2 (k = 1 would leak the secret)");
    assert!(l >= 1 && l <= k, "need 1 ≤ ℓ ≤ k secrets");
    assert!(n >= k, "n must be at least k");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );

    // Same Zeroizing guard as `split` above; coefficients carry every
    // secret in `secrets` plus the random pad.
    let mut coeffs = Zeroizing::new(Vec::<BigUint>::with_capacity(k));
    for s in secrets {
        coeffs.push(field.reduce(s));
    }
    for _ in l..k {
        coeffs.push(field.random(rng));
    }

    (1..=n)
        .map(|i| {
            let x = BigUint::from_u64(i as u64);
            let y = horner(field, &coeffs, &x);
            Share { x, y }
        })
        .collect()
}

/// Recover all `ℓ` secrets from a multi-secret split.
///
/// Build the `k × k` Vandermonde linear system on the first `k` shares,
/// solve for `(a_0, …, a_{k-1})` by Gaussian elimination over the
/// field, and return the first `ell` coefficients. When more than `k`
/// shares are supplied the extras are used to verify the recovered
/// polynomial: any extra share whose `y` does not match the polynomial
/// causes the function to return `None` rather than silently accept a
/// corrupt or inconsistent set.
///
/// Returns `None` on:
/// - empty input or `shares.len() < k`,
/// - any share's `x` is zero modulo `p`, or any two labels are
///   congruent modulo `p`,
/// - `ell == 0` or `ell > k`,
/// - any extra share (index `≥ k`) inconsistent with the polynomial
///   recovered from the first `k`.
#[must_use]
#[allow(clippy::needless_range_loop)] // index-driven Gaussian elimination
pub fn reconstruct_multi(
    field: &PrimeField,
    shares: &[Share],
    k: usize,
    ell: usize,
) -> Option<Vec<BigUint>> {
    if ell == 0 || ell > k || shares.len() < k {
        return None;
    }
    // Validate the residues used by the Vandermonde system, including
    // extra shares that could otherwise alias a base point or the secret slot.
    let xs: Vec<BigUint> = shares.iter().map(|s| field.reduce(&s.x)).collect();
    for x in &xs {
        if x.is_zero() {
            return None;
        }
    }
    // Reject duplicate `x` residues anywhere in `shares` — a duplicate
    // among the first `k` makes the system singular, and a duplicate
    // spanning the consistency-check region would mask tampering.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if xs[i] == xs[j] {
                return None;
            }
        }
    }

    let used = &shares[..k];

    // Augmented Vandermonde system: row i is [1, x_i, x_i^2, …, x_i^{k-1} | y_i].
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for s in used {
        let mut row = Vec::with_capacity(k + 1);
        let mut x_pow = BigUint::one();
        for _ in 0..k {
            row.push(x_pow.clone());
            x_pow = field.mul(&x_pow, &s.x);
        }
        row.push(s.y.clone());
        mat.push(row);
    }

    // Gaussian elimination over GF(p). With distinct x_i the system is
    // nonsingular (Vandermonde determinant), so pivots are nonzero in
    // exact arithmetic; if a pivot turns out to be zero we abort.
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
            if r == col {
                continue;
            }
            if mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..=k {
                let term = field.mul(&factor, &mat[col][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
    }

    let coeffs: Vec<BigUint> = (0..k).map(|i| mat[i][k].clone()).collect();

    // Validate every extra share (index ≥ k) against the recovered
    // polynomial. Extras that disagree mean the caller supplied
    // inconsistent inputs — refuse rather than silently truncate.
    for s in &shares[k..] {
        let pred = crate::poly::horner(field, &coeffs, &s.x);
        if !ct_eq_biguint(&pred, &s.y) {
            return None;
        }
    }

    Some(coeffs.into_iter().take(ell).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[42u8; 32])
    }

    fn small_field() -> PrimeField {
        // 2^61 − 1 (Mersenne prime) — comfortably bigger than every
        // small (k, n) we exercise here, but small enough to be easy to
        // reason about during debugging.
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn basic_round_trip() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        for &(k, n) in &[(2usize, 3usize), (3, 5), (5, 9), (2, 7)] {
            let shares = split(&f, &mut r, &secret, k, n);
            assert_eq!(shares.len(), n);
            // Every k-subset reconstructs the same secret.
            assert_eq!(reconstruct(&f, &shares[..k], k), Some(secret.clone()));
            assert_eq!(reconstruct(&f, &shares[1..1 + k], k), Some(secret.clone()));
        }
    }

    #[test]
    fn k_minus_one_does_not_yield_secret() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(987_654_321);
        let shares = split(&f, &mut r, &secret, 4, 7);
        // Lagrange through k − 1 points still returns *some* value (it
        // pretends the polynomial has degree k − 2), but since the
        // upper coefficients are uniform, the chance of accidentally
        // matching the real secret is 1/p — vanishingly small here.
        // Below threshold: reconstruct must refuse rather than return
        // a uniformly-random "secret". Above threshold but with k − 1
        // points used, a 3-point Lagrange against the 4-degree
        // polynomial yields a value that is uniform over GF(p) — it
        // should not equal the real secret in any practical run.
        assert!(reconstruct(&f, &shares[..3], 4).is_none());
        let partial = reconstruct(&f, &shares[..3], 3);
        assert_ne!(partial, Some(secret));
    }

    #[test]
    fn duplicate_x_is_rejected() {
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let mut shares = split(&f, &mut r, &secret, 2, 3);
        shares[1].x = shares[0].x.clone();
        assert!(reconstruct(&f, &shares, 2).is_none());
    }

    #[test]
    fn multi_secret_recovers_all_secrets() {
        let f = small_field();
        let mut r = rng();
        let secrets: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(1000 + i)).collect();
        let shares = split_multi(&f, &mut r, &secrets, 4, 6);
        let recovered = reconstruct_multi(&f, &shares, 4, 3).expect("decode");
        assert_eq!(recovered, secrets);
    }

    #[test]
    fn multi_secret_threshold_holds() {
        // Same configuration as above; now feed only k − 1 shares.
        let f = small_field();
        let mut r = rng();
        let secrets: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(2000 + i)).collect();
        let shares = split_multi(&f, &mut r, &secrets, 4, 6);
        assert!(reconstruct_multi(&f, &shares[..3], 4, 3).is_none());
    }

    #[test]
    fn multi_secret_rejects_inconsistent_extra_share() {
        // A corrupted share past the first k must cause refusal, not
        // silent truncation.
        let f = small_field();
        let mut r = rng();
        let secrets: Vec<BigUint> = (1..=2).map(|i| BigUint::from_u64(50 + i)).collect();
        let mut shares = split_multi(&f, &mut r, &secrets, 3, 6);
        // shares[0..3] used to fit; shares[5] is an "extra" that we tamper.
        shares[5].y = f.add(&shares[5].y, &BigUint::from_u64(1));
        assert!(reconstruct_multi(&f, &shares, 3, 2).is_none());
    }

    #[test]
    fn reconstruct_below_threshold_returns_none() {
        // Below threshold, reconstruct must refuse rather than return a
        // uniform-random "secret" from a lower-degree fit.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xCAFE);
        let shares = split(&f, &mut r, &secret, 4, 7);
        assert!(reconstruct(&f, &shares[..3], 4).is_none());
    }

    #[test]
    fn reconstruct_rejects_inconsistent_extra_share() {
        // With > k shares, an extra that disagrees with the polynomial
        // fit to the first k must yield None.
        let f = small_field();
        let mut r = rng();
        let secret = BigUint::from_u64(0xBEEF);
        let mut shares = split(&f, &mut r, &secret, 3, 6);
        shares[5].y = f.add(&shares[5].y, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn reconstruct_rejects_extra_label_congruent_to_zero() {
        // q(x) = 7 + 3x. The extra x = p is reserved for the secret but
        // passes the raw zero-label check; its y also matches q(p), so
        // the consistency check cannot mask the missing residue check.
        let f = small_field();
        let shares = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
            Share {
                x: f.modulus().clone(),
                y: BigUint::from_u64(7),
            },
        ];
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn reconstruct_rejects_extra_duplicate_residue_with_matching_y() {
        // x = p + 1 aliases the first share in GF(p), with the matching
        // y from q(x) = 7 + 3x. Only the residue collision justifies
        // refusal; the extra consistency check would otherwise accept it.
        let f = small_field();
        let shares = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
            Share {
                x: f.modulus().add_ref(&BigUint::from_u64(1)),
                y: BigUint::from_u64(10),
            },
        ];
        assert!(reconstruct(&f, &shares, 3).is_none());
    }

    #[test]
    fn multi_secret_with_l_equals_one_matches_shamir() {
        // ℓ = 1 with arbitrary k, n must agree with plain Shamir.
        let f = small_field();
        let secret = BigUint::from_u64(0xDEAD_BEEF);
        let mut r1 = rng();
        let mut r2 = rng();
        let shares = split_multi(&f, &mut r1, std::slice::from_ref(&secret), 3, 5);
        let _ = split(&f, &mut r2, &secret, 3, 5); // exercise both code paths
        assert_eq!(
            reconstruct_multi(&f, &shares, 3, 1).map(|v| v[0].clone()),
            Some(secret)
        );
    }

    #[test]
    fn multi_secret_rejects_label_congruent_to_zero() {
        // x = p (≡ 0 mod p) is the secret's reserved abscissa; without
        // reduced-residue validation it would silently become the first
        // recovered secret. Values follow q(x)=7+3x, isolating the label defect.
        let f = small_field();
        // First k shares carry the zero residue (points from q = 7 + 3x).
        let first_k = vec![
            Share {
                x: f.modulus().clone(),
                y: BigUint::from_u64(7),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
        ];
        assert!(reconstruct_multi(&f, &first_k, 3, 1).is_none());
    }

    #[test]
    fn multi_secret_rejects_extra_zero_residue_with_matching_value() {
        let f = small_field();
        // q(0)=7: isolate label rejection from the consistency check.
        let extra = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
            Share {
                x: f.modulus().clone(),
                y: BigUint::from_u64(7),
            },
        ];
        assert!(reconstruct_multi(&f, &extra, 3, 1).is_none());
    }

    #[test]
    fn multi_secret_rejects_first_k_collision_compat_control() {
        // x = 1 and x = p + 1 collide in GF(p), making the Vandermonde
        // singular. The baseline already refused (singular pivot); this
        // stays as a compatibility control that the reduced-residue check
        // also refuses.
        let f = small_field();
        let shares = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: f.modulus().add_ref(&BigUint::from_u64(1)),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
        ];
        assert!(reconstruct_multi(&f, &shares, 3, 1).is_none());
    }

    #[test]
    fn multi_secret_rejects_extra_region_duplicate_residue_with_matching_y() {
        // Regression the baseline misses: an extra share (index ≥ k)
        // aliases share 0's residue (x = 1 + p ≡ 1) with the same y (10).
        // The baseline's extra validation evaluates the recovered
        // polynomial at raw x = 1 + p, which reduces to 1 and matches y,
        // so it would wrongly ACCEPT. The reduced-residue duplicate check
        // must refuse.
        let f = small_field();
        let shares = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: BigUint::from_u64(3),
                y: BigUint::from_u64(16),
            },
            Share {
                x: f.modulus().add_ref(&BigUint::from_u64(1)),
                y: BigUint::from_u64(10),
            },
        ];
        assert!(reconstruct_multi(&f, &shares, 3, 1).is_none());
    }

    #[test]
    fn multi_secret_distinct_nonzero_residue_above_p_still_works() {
        // A label above p with a distinct nonzero residue stays usable;
        // reduction must not over-reject. y kept while p is added to x.
        let f = small_field();
        let shares = vec![
            Share {
                x: BigUint::from_u64(1),
                y: BigUint::from_u64(10),
            },
            Share {
                x: BigUint::from_u64(2),
                y: BigUint::from_u64(13),
            },
            Share {
                x: f.modulus().add_ref(&BigUint::from_u64(3)),
                y: BigUint::from_u64(16),
            },
        ];
        assert_eq!(
            reconstruct_multi(&f, &shares, 3, 2),
            Some(vec![BigUint::from_u64(7), BigUint::from_u64(3)])
        );
    }
}
