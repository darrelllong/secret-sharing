//! Yamamoto 1986, *Secret Sharing System Using `(k, L, n)` Threshold
//! Scheme* — generalised ramp scheme with three parameters.
//!
//! A `(k, L, n)` scheme distributes `n` shares of a length-`L` secret
//! `(s_1, …, s_L) ∈ GF(p)^L` such that
//!
//! - any `k` shares reconstruct the full secret,
//! - any `k − L` shares reveal nothing,
//! - intermediate sizes `t` with `k − L < t < k` leak proportional
//!   information about the secret, by Yamamoto's analysis.
//!
//! This generalises both Shamir 1979 (the `L = 1` special case) and
//! McEliece–Sarwate 1981 (the `L = k` "fully data-compressed" case
//! already implemented as `crate::ramp`).
//!
//! Construction (the "evaluation" form). Choose the unique
//! degree-`(k − 1)` polynomial `P(x)` over `GF(p)` such that
//!
//! - `P(j) = s_j` for `j = 1, …, L`, and
//! - `P(j) = u_j` for `j = L + 1, …, k`, where each `u_j` is a uniform
//!   random field element (the "padding" anchors).
//!
//! Trustee `i ∈ {1, …, n}` receives the share `(k + i, P(k + i))`. The
//! abscissae `1..=k` (secret slots and padding anchors) are disjoint
//! from the share abscissae `k+1..=k+n`, so the public point indexing
//! is unambiguous. Reconstruction Lagrange-interpolates `P` from any
//! `k` shares and reads off `P(1), …, P(L)`.

use crate::field::PrimeField;
use crate::poly::lagrange_eval;
use crate::secure::ct_eq_biguint;
use crate::shamir::Share;
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// Distribute `n` `(k, L, n)`-Yamamoto shares of a length-`L` secret.
///
/// # Panics
/// - `secret.len() == 0`,
/// - `k < secret.len()` (we need `L ≤ k`),
/// - `k < 2` (any `k = 1` trivially leaks each share's secret value),
/// - `n < k` (any reconstruction needs `k` shares, so `n` below `k`
///   produces an unreconstructable share set),
/// - `k + n ≥ p` (need that many distinct nonzero abscissae).
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
    assert!(l <= k, "L = secret.len() must be ≤ k");
    assert!(k >= 2, "k must be at least 2");
    assert!(n >= k, "n must be at least k (otherwise the share set is unreconstructable)");
    assert!(
        BigUint::from_u64((k + n) as u64) < *field.modulus(),
        "prime modulus must exceed k + n",
    );

    // Anchor set: L secret slots + (k - L) random padding slots, jointly
    // determining a unique degree-(k-1) polynomial.
    let mut anchors: Vec<(BigUint, BigUint)> = Vec::with_capacity(k);
    for (j, s) in secret.iter().enumerate() {
        anchors.push((BigUint::from_u64((j + 1) as u64), field.reduce(s)));
    }
    for j in l..k {
        anchors.push((BigUint::from_u64((j + 1) as u64), field.random(rng)));
    }

    (1..=n)
        .map(|i| {
            let x = BigUint::from_u64((k + i) as u64);
            // `lagrange_eval` on k distinct anchors cannot fail.
            let y = lagrange_eval(field, &anchors, &x).expect("distinct anchors");
            Share { x, y }
        })
        .collect()
}

/// Recover the length-`L` secret from any `k` (or more) Yamamoto
/// shares. Extras (beyond the first `k`) are validated against the
/// fitted polynomial — any disagreement returns `None`.
///
/// Returns `None` for empty input, fewer than `k` shares, duplicate or
/// zero `x` coordinates, or `L = 0`.
#[must_use]
pub fn reconstruct(
    field: &PrimeField,
    shares: &[Share],
    k: usize,
    l: usize,
) -> Option<Vec<BigUint>> {
    if shares.is_empty() || k < 2 || l == 0 || l > k || shares.len() < k {
        return None;
    }
    // Labels `1..=k` are reserved for the secret/padding anchors.
    // Refuse any share whose label collides with one of those anchors —
    // otherwise a caller could feed anchor-labelled "shares" and force
    // the reconstructed output rather than recovering from real shares.
    let k_big = BigUint::from_u64(k as u64);
    for s in shares {
        let xr = field.reduce(&s.x);
        if xr.is_zero() || xr <= k_big {
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
    let pts: Vec<(BigUint, BigUint)> = shares
        .iter()
        .take(k)
        .map(|s| (s.x.clone(), s.y.clone()))
        .collect();

    for s in &shares[k..] {
        let pred = lagrange_eval(field, &pts, &s.x)?;
        if !ct_eq_biguint(&pred, &s.y) {
            return None;
        }
    }

    let mut out = Vec::with_capacity(l);
    for j in 1..=l {
        let xj = BigUint::from_u64(j as u64);
        out.push(lagrange_eval(field, &pts, &xj)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0xCDu8; 32])
    }

    #[test]
    fn round_trip_l_equals_k() {
        // (k = L = 4, n = 7): every share's payload is one field element
        // and any k shares reconstruct all 4 secrets.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(0x100 + i)).collect();
        let shares = split(&f, &mut r, &secret, 4, 7);
        assert_eq!(shares.len(), 7);
        assert_eq!(reconstruct(&f, &shares[..4], 4, 4), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[3..], 4, 4), Some(secret));
    }

    #[test]
    fn round_trip_l_less_than_k() {
        // True ramp: L = 2, k = 5, n = 8.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(|i| BigUint::from_u64(0x300 + i)).collect();
        let shares = split(&f, &mut r, &secret, 5, 8);
        assert_eq!(shares.len(), 8);
        assert_eq!(reconstruct(&f, &shares[..5], 5, 2), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[2..7], 5, 2), Some(secret));
    }

    #[test]
    fn round_trip_l_equals_one_matches_shamir() {
        // L = 1: equivalent to Shamir with the secret at abscissa 1.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xF00D);
        let shares = split(&f, &mut r, std::slice::from_ref(&secret), 3, 5);
        let got = reconstruct(&f, &shares[..3], 3, 1).unwrap();
        assert_eq!(got, vec![secret]);
    }

    #[test]
    fn extras_validated_and_tampering_rejected() {
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=3).map(|i| BigUint::from_u64(0x500 + i)).collect();
        let mut shares = split(&f, &mut r, &secret, 4, 7);
        assert_eq!(reconstruct(&f, &shares, 4, 3), Some(secret.clone()));
        shares[5].y = f.add(&shares[5].y, &BigUint::from_u64(1));
        assert!(reconstruct(&f, &shares, 4, 3).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(|i| BigUint::from_u64(0x600 + i)).collect();
        let shares = split(&f, &mut r, &secret, 4, 6);
        assert!(reconstruct(&f, &shares[..3], 4, 2).is_none());
    }

    #[test]
    #[should_panic(expected = "L = secret.len() must be ≤ k")]
    fn split_rejects_l_greater_than_k() {
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=4).map(BigUint::from_u64).collect();
        let _ = split(&f, &mut r, &secret, 3, 5);
    }

    #[test]
    fn share_payload_is_one_field_element() {
        // Per-share storage is a single field element regardless of L —
        // the data-compression property of ramp schemes.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=6).map(BigUint::from_u64).collect();
        // (L=6, k=8, n=10): need n ≥ k, so 10 (not 5) trustees.
        let shares = split(&f, &mut r, &secret, 8, 10);
        for s in &shares {
            let _ = s.y.clone();
        }
        assert_eq!(shares.len(), 10);
        // Sanity: any k=8 of the 10 reconstructs all 6 secrets.
        assert_eq!(reconstruct(&f, &shares[..8], 8, 6), Some(secret));
    }

    #[test]
    #[should_panic(expected = "n must be at least k")]
    fn split_rejects_n_below_k() {
        // n < k would produce an unreconstructable share set; the
        // assertion in `split` must catch it.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(BigUint::from_u64).collect();
        let _ = split(&f, &mut r, &secret, 8, 5);
    }

    #[test]
    fn k_minus_l_shares_does_not_yield_secret() {
        // Yamamoto's headline claim is "any k − L shares reveal nothing."
        // The mechanical analogue here: with strictly fewer than k shares,
        // reconstruct must refuse rather than return a partial secret.
        let f = small();
        let mut r = rng();
        let secret: Vec<BigUint> = (1..=2).map(|i| BigUint::from_u64(0x1000 + i)).collect();
        let shares = split(&f, &mut r, &secret, 5, 8);
        // k − L = 3 shares: must refuse.
        assert!(reconstruct(&f, &shares[..3], 5, 2).is_none());
        // k − 1 = 4 shares (above the "nothing" threshold but still
        // below recovery): must also refuse.
        assert!(reconstruct(&f, &shares[..4], 5, 2).is_none());
    }
}
