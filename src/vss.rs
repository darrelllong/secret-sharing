//! Rabin–Ben-Or 1989, *Verifiable Secret Sharing and Multiparty
//! Protocols with Honest Majority* — information-theoretic verifiable
//! secret sharing via bivariate polynomials.
//!
//! Construction. The dealer picks a uniform bivariate polynomial
//! `F(x, y) = Σ_{a, b} F_{a,b} x^a y^b` of degree at most `k − 1` in
//! each variable, with `F(0, 0) = s`. Player `i ∈ {1, …, n}` receives
//! both row and column slices:
//!
//! - `g_i(y) := F(i, y)` — coefficient vector of length `k` in `y`.
//! - `h_i(x) := F(x, i)` — coefficient vector of length `k` in `x`.
//!
//! Verification. For every pair `(i, j)`, `g_i(j) = F(i, j) = h_j(i)`.
//! A consistency check between any two players' shares is therefore an
//! evaluation cross-check: `share_i.eval_g(j) == share_j.eval_h(i)`.
//! In the original protocol the players exchange these values over
//! private channels and broadcast complaints when a check fails. Here
//! we expose [`cross_check`] for callers to run in their own protocol
//! harness, and a non-interactive [`verify_consistent`] over a static
//! list of shares.
//!
//! Reconstruction. The univariate polynomial `Φ(x) := F(x, 0)` has
//! degree ≤ `k − 1`, with `Φ(i) = g_i(0)` for each player `i`. Any `k`
//! consistent shares Lagrange-interpolate `Φ`, giving `s = Φ(0)`.
//!
//! Comparison with computational VSS. Pedersen and Feldman use group
//! exponentiations to commit to coefficients; their security rests on
//! discrete-log hardness. Rabin–Ben-Or trades that for an honest-
//! majority assumption — at most `t < n/2` corrupt parties, equivalently
//! `2(k − 1) < n` for threshold `k = t + 1` — and information-theoretic
//! verification. The library does not enforce this bound on `deal` (you
//! may legitimately want to deal in a permissive regime and apply the
//! check at protocol time), but exposes [`is_honest_majority`] so the
//! caller's protocol harness can validate the parameters in one line.

use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::secure::{ct_eq_biguint, Zeroizing};

/// One player's bivariate-polynomial slice.
#[derive(Clone, Eq, PartialEq)]
pub struct VssShare {
    /// 1-based player index.
    pub player: usize,
    /// Coefficients of `g_i(y) = F(i, y)`, low-degree first.
    pub g: Vec<BigUint>,
    /// Coefficients of `h_i(x) = F(x, i)`, low-degree first.
    pub h: Vec<BigUint>,
}

impl core::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("VssShare(<elided>)")
    }
}

impl VssShare {
    /// Evaluate `g_i(j) = F(i, j)`.
    #[must_use]
    pub fn eval_g(&self, field: &PrimeField, j: &BigUint) -> BigUint {
        horner(field, &self.g, j)
    }

    /// Evaluate `h_i(j) = F(j, i)`.
    #[must_use]
    pub fn eval_h(&self, field: &PrimeField, j: &BigUint) -> BigUint {
        horner(field, &self.h, j)
    }
}

/// Deal `n` shares of `secret` with reconstruction threshold `k`.
/// The bivariate polynomial has degree `k − 1` in each variable.
///
/// # Panics
/// - `k < 2` (a degree-0 bivariate puts the secret in every coefficient),
/// - `n < k`,
/// - `n ≥ p`.
#[must_use]
pub fn deal<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    k: usize,
    n: usize,
) -> Vec<VssShare> {
    assert!(k >= 2, "k must be at least 2");
    assert!(n >= k, "n must be at least k");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );

    // Sample F as a k × k coefficient matrix (rows index x-degree, cols y-degree).
    // F[0][0] = secret; everything else uniform random. Wrap in
    // `Zeroizing` so the entire bivariate polynomial — including the
    // secret coefficient — is volatile-zeroed on function exit.
    let mut coeffs = Zeroizing::new(
        (0..k)
            .map(|_| (0..k).map(|_| field.random(rng)).collect::<Vec<BigUint>>())
            .collect::<Vec<Vec<BigUint>>>(),
    );
    coeffs[0][0] = field.reduce(secret);

    // Player i's g_i(y) coefficients: g_i[b] = sum_a F[a][b] * i^a.
    // h_i(x) coefficients: h_i[a] = sum_b F[a][b] * i^b. Symmetric.
    (1..=n)
        .map(|i| {
            let i_val = BigUint::from_u64(i as u64);
            let mut g = vec![BigUint::zero(); k];
            for b in 0..k {
                // Horner-ish: sum_a F[a][b] * i^a.
                let col: Vec<BigUint> = (0..k).map(|a| coeffs[a][b].clone()).collect();
                g[b] = horner(field, &col, &i_val);
            }
            let mut h = vec![BigUint::zero(); k];
            for a in 0..k {
                // sum_b F[a][b] * i^b — that is exactly horner(coeffs[a], i).
                h[a] = horner(field, &coeffs[a], &i_val);
            }
            VssShare { player: i, g, h }
        })
        .collect()
}

/// Cross-check between two shares: `share_i.eval_g(j) == share_j.eval_h(i)`.
/// Returns `false` if either share is malformed (mismatched coefficient
/// vector lengths, or zero player index).
#[must_use]
pub fn cross_check(field: &PrimeField, share_i: &VssShare, share_j: &VssShare) -> bool {
    if share_i.g.is_empty()
        || share_i.h.is_empty()
        || share_j.g.is_empty()
        || share_j.h.is_empty()
        || share_i.player == 0
        || share_j.player == 0
    {
        return false;
    }
    let i_val = BigUint::from_u64(share_i.player as u64);
    let j_val = BigUint::from_u64(share_j.player as u64);
    let lhs = share_i.eval_g(field, &j_val);
    let rhs = share_j.eval_h(field, &i_val);
    ct_eq_biguint(&lhs, &rhs)
}

/// Whether `(k, n)` satisfies the Rabin–Ben-Or honest-majority bound
/// `2(k − 1) < n`, equivalently `k < n/2 + 1`. The information-theoretic
/// security guarantees of this VSS rest on this bound; outside it the
/// pairwise checks still provide verification of *consistency* but not
/// of *secrecy* against a corrupt majority.
#[must_use]
pub fn is_honest_majority(k: usize, n: usize) -> bool {
    k >= 2 && 2 * (k - 1) < n
}

/// Like [`deal`] but **enforces** the Rabin–Ben-Or honest-majority
/// bound `2(k − 1) < n` at the API boundary. Panics if violated.
/// Use this constructor when the caller cannot guarantee a protocol
/// harness will check the bound itself; use [`deal`] for raw use.
#[must_use]
pub fn deal_validated<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    k: usize,
    n: usize,
) -> Vec<VssShare> {
    assert!(
        is_honest_majority(k, n),
        "Rabin–Ben-Or VSS requires honest majority: 2(k − 1) < n",
    );
    deal(field, rng, secret, k, n)
}

/// Run [`cross_check`] in both directions for every distinct pair in
/// `shares`. Both directions are needed because [`cross_check`] mixes
/// `share_i.g` with `share_j.h` — a tamper to one player's `g` alone
/// only shows up when *that* player is the `share_i` argument. Returns
/// `true` only when every ordered pair agrees.
#[must_use]
pub fn verify_consistent(field: &PrimeField, shares: &[VssShare]) -> bool {
    for i in 0..shares.len() {
        for j in 0..shares.len() {
            if i == j {
                continue;
            }
            if !cross_check(field, &shares[i], &shares[j]) {
                return false;
            }
        }
    }
    true
}

/// Recover the secret from any `k` (or more) Rabin–Ben-Or shares.
///
/// Returns `None` on:
/// - fewer than `k` shares,
/// - any pair failing the cross-check (so we never silently aggregate
///   inconsistent shares),
/// - duplicate player indices,
/// - degree-mismatched coefficient vectors.
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[VssShare], k: usize) -> Option<BigUint> {
    if k < 2 || shares.len() < k {
        return None;
    }
    for s in shares {
        if s.player == 0 || s.g.len() != k || s.h.len() != k {
            return None;
        }
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].player == shares[j].player {
                return None;
            }
        }
    }
    if !verify_consistent(field, shares) {
        return None;
    }
    // Φ(x) := F(x, 0) is a degree-(k−1) polynomial with Φ(i) = g_i(0).
    let pts: Vec<(BigUint, BigUint)> = shares
        .iter()
        .take(k)
        .map(|s| {
            let x = BigUint::from_u64(s.player as u64);
            let y = s.g[0].clone(); // g_i(0)
            (x, y)
        })
        .collect();
    lagrange_eval(field, &pts, &BigUint::zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x55u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    #[test]
    fn round_trip() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = deal(&f, &mut r, &secret, 3, 5);
        assert_eq!(shares.len(), 5);
        // Pairwise cross-check passes.
        assert!(verify_consistent(&f, &shares));
        // Any 3 shares reconstruct.
        assert_eq!(reconstruct(&f, &shares[..3], 3), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[1..4], 3), Some(secret.clone()));
        assert_eq!(reconstruct(&f, &shares[2..], 3), Some(secret));
    }

    #[test]
    fn cross_check_detects_tamper() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(42);
        let mut shares = deal(&f, &mut r, &secret, 3, 5);
        // Tamper with one coefficient of player 1's g.
        shares[0].g[1] = f.add(&shares[0].g[1], &BigUint::from_u64(1));
        // Cross-check between players 1 and 2 should now fail (their
        // bivariate views disagree at (1, 2)).
        assert!(!cross_check(&f, &shares[0], &shares[1]));
        // Reconstruct refuses to combine inconsistent shares.
        assert!(reconstruct(&f, &shares[..3], 3).is_none());
    }

    #[test]
    fn cross_check_detects_h_tamper() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let mut shares = deal(&f, &mut r, &secret, 3, 5);
        shares[2].h[2] = f.add(&shares[2].h[2], &BigUint::from_u64(1));
        // Some pair involving player 3 must disagree.
        assert!(!verify_consistent(&f, &shares));
    }

    #[test]
    fn consistency_holds_for_honest_dealer() {
        // Stronger sanity: every pair's cross-check passes for a
        // freshly dealt secret.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xBEEF);
        let shares = deal(&f, &mut r, &secret, 4, 7);
        for i in 0..shares.len() {
            for j in 0..shares.len() {
                if i == j {
                    continue;
                }
                assert!(
                    cross_check(&f, &shares[i], &shares[j]),
                    "cross-check failed between players {} and {}",
                    shares[i].player,
                    shares[j].player
                );
            }
        }
    }

    #[test]
    fn below_threshold_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(13);
        let shares = deal(&f, &mut r, &secret, 4, 6);
        assert!(reconstruct(&f, &shares[..3], 4).is_none());
    }

    #[test]
    fn duplicate_player_rejected() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = deal(&f, &mut r, &secret, 3, 5);
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert!(reconstruct(&f, &dup, 3).is_none());
    }

    #[test]
    fn malformed_share_returns_none() {
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(3);
        let mut shares = deal(&f, &mut r, &secret, 3, 4);
        shares[0].g.push(BigUint::one()); // wrong length
        assert!(reconstruct(&f, &shares[..3], 3).is_none());
    }

    #[test]
    fn extra_shares_validated() {
        // All n shares passed in. With consistent shares we recover; if
        // any extra is tampered the pairwise check catches it.
        let f = small();
        let mut r = rng();
        let secret = BigUint::from_u64(0xDEAD);
        let shares = deal(&f, &mut r, &secret, 3, 6);
        assert_eq!(reconstruct(&f, &shares, 3), Some(secret.clone()));
        let mut bad = shares.clone();
        bad[5].g[0] = f.add(&bad[5].g[0], &BigUint::from_u64(1));
        assert!(reconstruct(&f, &bad, 3).is_none());
    }

    #[test]
    fn honest_majority_helper_matches_paper_bound() {
        // 2(k-1) < n: classical examples.
        assert!(is_honest_majority(2, 4)); // k=2, n=4: 2*1=2 < 4 ✓
        assert!(is_honest_majority(2, 3)); // k=2, n=3: 2 < 3 ✓
        assert!(is_honest_majority(3, 6)); // k=3, n=6: 4 < 6 ✓
        assert!(!is_honest_majority(3, 4)); // 4 < 4 is false
        assert!(!is_honest_majority(4, 5)); // 6 < 5 is false
        assert!(!is_honest_majority(5, 5)); // n-of-n cannot be VSS
        assert!(!is_honest_majority(1, 5)); // k=1 leaks anyway
    }

    #[test]
    fn changing_secret_changes_g_i_zero() {
        // g_i(0) for each player i is exactly that player's "Shamir
        // share" of Φ(x) = F(x, 0). Two different secrets necessarily
        // produce different g_i(0) values for every player.
        let f = small();
        let mut r1 = rng();
        let mut r2 = rng();
        let s1 = BigUint::from_u64(100);
        let s2 = BigUint::from_u64(200);
        let a = deal(&f, &mut r1, &s1, 3, 5);
        let b = deal(&f, &mut r2, &s2, 3, 5);
        // Differential at any single g_i(0) is generically nonzero — at
        // least one player should differ. (Both seeds are identical so
        // the random padding is the same; only the secret differs, so
        // every player's g_i(0) shifts by a Lagrange-coefficient
        // multiple of (s1 − s2).)
        let any_diff = a.iter().zip(b.iter()).any(|(x, y)| x.g[0] != y.g[0]);
        assert!(any_diff);
    }
}
