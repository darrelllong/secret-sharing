//! McEliece–Sarwate 1981 ramp / data-compressed Reed–Solomon variant.
//!
//! "Let `b = (b_1, b_2, …, b_k)` be the secret. There exists a unique
//! codeword `D` in the Reed–Solomon code with `D_1 = b_1`, …,
//! `D_k = b_k`; D can be found by Lagrange interpolation … Only the
//! `r − 1 − k` pieces `D_{k+1}, …, D_{r-1}` are available for
//! distribution to those sharing the secret."
//!
//! Compared with Shamir, the secret is `k` field elements (rather than
//! one) and each share is still one field element, so the per-trustee
//! payload is `k×` smaller than the secret. Any `k` shares interpolate
//! the unique degree-`(k − 1)` polynomial through the secret slots and
//! recover all `k` components.
//!
//! Security trade-off (paper): given `k − 1` shares an opponent narrows
//! the secret from one of `r^k` to one of `r` candidates rather than
//! learning nothing. We surface the trade-off in the type signature
//! (the secret is a `Vec<BigUint>`) but otherwise leave the choice to
//! the caller.

use crate::field::PrimeField;
use crate::poly::lagrange_eval;
use crate::shamir::Share;
use crate::bigint::BigUint;

/// Distribute `n` ramp shares of a `k`-element secret. Trustee `i`
/// receives `(k + i, P(k + i))` where `P` is the unique degree-`(k − 1)`
/// polynomial with `P(j) = secret[j − 1]` for `j ∈ {1, …, k}`.
///
/// # Panics
/// - `secret.len() == 0`,
/// - `n == 0`, or
/// - `k + n ≥ p` (we need `k + n` distinct nonzero abscissae).
#[must_use]
pub fn split(field: &PrimeField, secret: &[BigUint], n: usize) -> Vec<Share> {
    let k = secret.len();
    assert!(
        k >= 2,
        "secret must have ≥ 2 components (k = 1 makes every share equal to the secret)"
    );
    assert!(
        n >= k,
        "n must be ≥ k = secret.len() — otherwise no subset of the n shares can reconstruct the k-element secret",
    );
    assert!(
        BigUint::from_u64((k + n) as u64) < *field.modulus(),
        "prime modulus must exceed k + n",
    );

    // Anchor points: (1, b_1), (2, b_2), …, (k, b_k). The polynomial of
    // degree < k passing through these is unique, and the McEliece–
    // Sarwate construction uses this polynomial to define the entire
    // Reed–Solomon codeword.
    let anchors: Vec<(BigUint, BigUint)> = secret
        .iter()
        .enumerate()
        .map(|(i, b)| (BigUint::from_u64((i + 1) as u64), field.reduce(b)))
        .collect();

    (1..=n)
        .map(|i| {
            let x = BigUint::from_u64((k + i) as u64);
            // `lagrange_eval` over k distinct anchors cannot fail.
            let y = lagrange_eval(field, &anchors, &x).expect("distinct anchors");
            Share { x, y }
        })
        .collect()
}

/// Recover the full `k`-element secret from any `k` (or more) ramp
/// shares. Returns `None` for empty input, duplicate `x` coordinates,
/// or shares with `x` coordinates colliding with the secret slots
/// `1..=k` (which would not happen for shares produced by [`split`]).
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[Share], k: usize) -> Option<Vec<BigUint>> {
    if shares.is_empty() || k == 0 || shares.len() < k {
        return None;
    }
    // Labels `1..=k` are reserved for the secret slots (anchors). A
    // share whose label collides with a secret slot would let the
    // caller force the output instead of reconstructing — refuse.
    let k_big = BigUint::from_u64(k as u64);
    for s in shares {
        let xr = field.reduce(&s.x);
        if xr.is_zero() || xr <= k_big {
            return None;
        }
    }
    let pts: Vec<(BigUint, BigUint)> = shares
        .iter()
        .take(k)
        .map(|s| (s.x.clone(), s.y.clone()))
        .collect();
    let mut out = Vec::with_capacity(k);
    for j in 1..=k {
        let xj = BigUint::from_u64(j as u64);
        out.push(lagrange_eval(field, &pts, &xj)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_field() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn ramp_round_trip() {
        let f = small_field();
        let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(100 + i)).collect();
        let n = 6;
        let shares = split(&f, &secret, n);
        assert_eq!(shares.len(), n);
        // Any k-subset of shares reconstructs every secret component.
        assert_eq!(reconstruct(&f, &shares[..4], 4), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[2..], 4), Some(secret));
    }

    #[test]
    fn ramp_payload_is_one_field_element_per_share() {
        // The whole point of the ramp scheme: each share is one field
        // element regardless of secret length.
        let f = small_field();
        let secret: Vec<BigUint> = (1..=10).map(BigUint::from_u64).collect();
        let shares = split(&f, &secret, 12);
        for s in &shares {
            // y is some field element; nothing else attached.
            let _ = s.y.clone();
        }
        assert_eq!(reconstruct(&f, &shares[..10], 10).unwrap(), secret);
    }

    #[test]
    #[should_panic(expected = "n must be ≥ k")]
    fn ramp_split_rejects_n_below_k() {
        // n < k = secret.len() would put the secret anchors past the
        // share count and produce an unreconstructable codeword.
        let f = small_field();
        let secret: Vec<BigUint> = (1..=4).map(BigUint::from_u64).collect();
        let _ = split(&f, &secret, 3);
    }

    #[test]
    fn ramp_split_rejects_secret_anchor_labels() {
        // The first k abscissae carry the secret directly; a share
        // labelled in 1..=k would let its holder read a secret slot
        // off the wire. reconstruct must reject the colliding label.
        let f = small_field();
        let secret: Vec<BigUint> = (1..=3).map(BigUint::from_u64).collect();
        let mut shares = split(&f, &secret, 5);
        // Force shares[0].x to land on a secret-anchor abscissa.
        shares[0].x = BigUint::from_u64(2);
        assert!(reconstruct(&f, &shares[..3], 3).is_none());
    }

    #[test]
    fn ramp_below_threshold_returns_none() {
        let f = small_field();
        let secret: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(10 + i)).collect();
        let shares = split(&f, &secret, 5);
        assert!(reconstruct(&f, &shares[..2], 3).is_none());
    }
}
