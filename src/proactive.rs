//! Herzberg, Jarecki, Krawczyk, Yung 1995, *Proactive Secret Sharing
//! Or: How to Cope With Perpetual Leakage* — refresh Shamir shares
//! every epoch so that a corrupt player who only sees one epoch's
//! shares cannot accumulate enough to recover the secret over time.
//!
//! Construction (the bare *re-sharing* step). Each existing share
//! `(x_i, y_i)` of the secret `s` is the value at `x_i` of some
//! degree-`(k − 1)` polynomial `Q(x)` with `Q(0) = s`. To refresh:
//!
//! 1. Every player `i` privately samples a fresh polynomial
//!    `r_i(x) = a_{i,1} x + a_{i,2} x^2 + … + a_{i,k-1} x^{k-1}`
//!    of degree `≤ k − 1` with **zero constant term** — i.e.
//!    `r_i(0) = 0`.
//! 2. Player `i` sends `r_i(x_j)` to every other player `j`.
//! 3. Every player `j` updates `y_j ← y_j + Σ_i r_i(x_j)`.
//!
//! The new polynomial is `Q'(x) = Q(x) + Σ_i r_i(x)`. Since each `r_i`
//! has zero constant, `Q'(0) = Q(0) = s`, so the secret is preserved.
//! The new shares are independent of the old ones: an adversary who
//! recorded `< k` old shares plus `< k` new shares still has fewer
//! than `k` shares of *either* polynomial and learns nothing.
//!
//! In a real protocol Herzberg et al. wrap this with Feldman / Pedersen
//! commitments so each player can verify others' `r_i` contributions
//! before applying them. The bare re-sharing step is implementation-
//! complete here; a verifiable refresh would compose this module with
//! `crate::vss` (information-theoretic) or with a Feldman commitment
//! over a discrete-log group (we do not bundle one).
//!
//! Lost-share recovery. If a player's share is destroyed or
//! compromised, any qualified subset of the *current* shares
//! reconstructs the missing value via Lagrange evaluation at the lost
//! player's `x` — see [`recover_share`].

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::shamir::Share;

/// Refresh a set of Shamir shares: produce a fresh share vector for
/// the same secret, drawn from a different sharing polynomial.
///
/// The function simulates the protocol's all-to-all message exchange
/// in one process: it samples one zero-rooted contribution polynomial
/// per existing share, then adds every contributor's evaluation at
/// every recipient's `x_j` into that recipient's share. Order does not
/// matter because addition over `GF(p)` is commutative.
///
/// # Panics
/// - `k < 2`,
/// - `shares.len() < k` (cannot reconstruct ⇒ refresh would lose `s`).
///
/// Returns a vector with the same length and `x` coordinates as the
/// input; only the `y` values are new.
#[must_use]
pub fn refresh<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    shares: &[Share],
    k: usize,
) -> Vec<Share> {
    assert!(k >= 2, "k must be at least 2");
    assert!(
        shares.len() >= k,
        "input must have ≥ k shares to remain reconstructable"
    );
    // Reject duplicate or zero x-coordinates: would corrupt the
    // refreshed polynomial just like in plain Shamir.
    for s in shares {
        assert!(!s.x.is_zero(), "shares must have nonzero x");
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                shares[i].x, shares[j].x,
                "shares must have distinct x-coordinates"
            );
        }
    }

    // Each contributor `i` samples r_i(x) = sum_{d=1..k-1} a_{i,d} x^d.
    // We materialise the coefficient list with a leading zero so we can
    // call `horner` directly.
    let n = shares.len();
    let mut contributions: Vec<Vec<BigUint>> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut coeffs = Vec::with_capacity(k);
        coeffs.push(BigUint::zero()); // r_i(0) = 0
        for _ in 1..k {
            coeffs.push(field.random(rng));
        }
        contributions.push(coeffs);
    }

    // For each recipient, sum every contributor's r_i(x_j).
    shares
        .iter()
        .map(|recipient| {
            let mut new_y = recipient.y.clone();
            for r_i in &contributions {
                let delta = horner(field, r_i, &recipient.x);
                new_y = field.add(&new_y, &delta);
            }
            Share {
                x: recipient.x.clone(),
                y: new_y,
            }
        })
        .collect()
}

/// Recover the missing share at `x_lost` from any `k` (or more) live
/// shares of the current epoch, by Lagrange-evaluating the polynomial
/// fitted to the supplied shares.
///
/// When more than `k` shares are supplied, every extra is checked
/// against the polynomial fit to the first `k` and any disagreement
/// returns `None` — without this cross-check a single corrupt extra
/// (or an adversarially supplied wrong-share among the first `k`)
/// would silently poison the recovered value.
///
/// Returns `None` if fewer than `k` shares are supplied, any two share
/// the same `x`, any share's `x` equals `x_lost` (we cannot recover
/// what's already present), or any extra share is inconsistent with
/// the polynomial fitted to the first `k`.
#[must_use]
pub fn recover_share(
    field: &PrimeField,
    live: &[Share],
    k: usize,
    x_lost: &BigUint,
) -> Option<Share> {
    if k < 2 || live.len() < k {
        return None;
    }
    for s in live {
        if s.x == *x_lost {
            return None;
        }
        if s.x.is_zero() {
            return None;
        }
    }
    for i in 0..live.len() {
        for j in (i + 1)..live.len() {
            if live[i].x == live[j].x {
                return None;
            }
        }
    }
    let pts: Vec<(BigUint, BigUint)> = live
        .iter()
        .take(k)
        .map(|s| (s.x.clone(), s.y.clone()))
        .collect();
    // Validate every extra against the polynomial fit to the first k.
    for s in live.iter().skip(k) {
        let pred = lagrange_eval(field, &pts, &s.x)?;
        if pred != s.y {
            return None;
        }
    }
    let y_lost = lagrange_eval(field, &pts, x_lost)?;
    Some(Share {
        x: x_lost.clone(),
        y: y_lost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;
    use crate::shamir;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x70u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn refresh_preserves_secret() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = shamir::split(&f, &mut r, &secret, 3, 5);
        let fresh = refresh(&f, &mut r, &shares, 3);
        assert_eq!(fresh.len(), 5);
        // All x-coordinates unchanged.
        for (a, b) in shares.iter().zip(fresh.iter()) {
            assert_eq!(a.x, b.x);
        }
        // Same secret recovered from fresh shares.
        let recovered = shamir::reconstruct(&f, &fresh[..3], 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn refresh_actually_changes_share_values() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xBAD);
        let shares = shamir::split(&f, &mut r, &secret, 3, 5);
        let fresh = refresh(&f, &mut r, &shares, 3);
        // At least one share value should change. (Probabilistically
        // all of them change, but a single-y check is a sharper test.)
        let any_changed = shares.iter().zip(fresh.iter()).any(|(a, b)| a.y != b.y);
        assert!(any_changed, "refresh must change at least one y value");
    }

    #[test]
    fn many_refreshes_preserve_secret() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(42);
        let mut shares = shamir::split(&f, &mut r, &secret, 4, 7);
        for _ in 0..10 {
            shares = refresh(&f, &mut r, &shares, 4);
        }
        let recovered = shamir::reconstruct(&f, &shares[..4], 4).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn old_shares_do_not_combine_with_new() {
        // Half-old, half-new shares must NOT recover the secret —
        // they sit on different polynomials. Sanity that refresh truly
        // moves to a fresh polynomial.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(99);
        let shares = shamir::split(&f, &mut r, &secret, 4, 7);
        let fresh = refresh(&f, &mut r, &shares, 4);
        // Mix 2 old + 2 new — generally NOT a valid share set.
        let mixed: Vec<Share> = vec![
            shares[0].clone(),
            shares[1].clone(),
            fresh[2].clone(),
            fresh[3].clone(),
        ];
        let bad = shamir::reconstruct(&f, &mixed, 4);
        // It will return *some* value (Lagrange always does) but
        // (with overwhelming probability) not the secret.
        assert_ne!(bad, Some(secret));
    }

    #[test]
    fn recover_lost_share_round_trip() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xCAFE);
        let shares = shamir::split(&f, &mut r, &secret, 3, 5);
        // Suppose share index 2 (player 3) is lost. Use shares 0,1,3 —
        // any 3 live shares — to reconstruct it.
        let live: Vec<Share> = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
        let recovered = recover_share(&f, &live, 3, &shares[2].x).unwrap();
        assert_eq!(recovered, shares[2]);
    }

    #[test]
    fn recover_share_on_present_x_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = shamir::split(&f, &mut r, &secret, 3, 5);
        let attempt = recover_share(&f, &shares[..3], 3, &shares[0].x);
        assert!(attempt.is_none());
    }

    #[test]
    fn recover_share_below_threshold_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = shamir::split(&f, &mut r, &secret, 4, 6);
        let live: Vec<Share> = shares[..3].to_vec();
        let attempt = recover_share(&f, &live, 4, &BigUint::from_u64(99));
        assert!(attempt.is_none());
    }

    #[test]
    #[should_panic(expected = "k must be at least 2")]
    fn refresh_rejects_k_one() {
        let f = small();
        let mut r = rng();
        let dummy = vec![
            Share {
                x: BigUint::one(),
                y: BigUint::one(),
            },
        ];
        let _ = refresh(&f, &mut r, &dummy, 1);
    }

    #[test]
    #[should_panic(expected = "input must have ≥ k shares")]
    fn refresh_rejects_too_few_shares() {
        let f = small();
        let mut r = rng();
        let too_few = vec![Share {
            x: BigUint::one(),
            y: BigUint::one(),
        }];
        let _ = refresh(&f, &mut r, &too_few, 3);
    }

    #[test]
    fn recover_share_validates_extras() {
        // AD P0: with > k shares, an extra inconsistent with the first
        // k must produce None, not a poisoned recovered value.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0x55);
        let shares = shamir::split(&f, &mut r, &secret, 3, 6);
        // Lose share 5; supply shares 0..4 (5 live shares; one extra
        // tampered).
        let mut live: Vec<Share> = shares[..5].to_vec();
        live[3].y = f.add(&live[3].y, &BigUint::from_u64(1));
        let attempt = recover_share(&f, &live, 3, &shares[5].x);
        assert!(attempt.is_none(), "tampered extra must yield None");
    }

    #[test]
    fn refresh_then_recover_lost_share_pipeline() {
        // Realistic proactive cycle: refresh, lose a player, recover.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xDECAF);
        let mut shares = shamir::split(&f, &mut r, &secret, 3, 5);
        // Cycle A: refresh.
        shares = refresh(&f, &mut r, &shares, 3);
        // Lose player 3.
        let lost_x = shares[2].x.clone();
        let live: Vec<Share> = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
        let recovered = recover_share(&f, &live, 3, &lost_x).unwrap();
        // Insert back; reconstruct.
        let mut full: Vec<Share> = vec![
            shares[0].clone(),
            shares[1].clone(),
            recovered,
            shares[3].clone(),
            shares[4].clone(),
        ];
        full.sort_by(|a, b| a.x.cmp(&b.x));
        assert_eq!(shamir::reconstruct(&f, &full[..3], 3).unwrap(), secret);
    }
}
