//! Chor, Goldwasser, Micali, Awerbuch 1985, *Verifiable Secret Sharing
//! and Achieving Simultaneity in the Presence of Faults* — the
//! original computational VSS paper.
//!
//! The faithful 1985 protocol layers probabilistic encryption and zero-
//! knowledge interaction; for a self-contained Rust library that is a
//! lot of machinery for one bibliography entry. We implement the
//! discrete-log-commitment instantiation that became the standard
//! computational VSS template (and that Feldman 1987 later sharpened):
//!
//! 1. Public parameters: a prime `p`, a prime-order subgroup of order
//!    `q | (p − 1)`, and a generator `g` of that subgroup.
//! 2. Dealer samples a degree-`(k − 1)` polynomial `f(x) = a_0 + a_1 x
//!    + … + a_{k-1} x^{k-1}` over `GF(q)` with `a_0 = s`.
//! 3. Dealer broadcasts the *commitments* `c_i = g^{a_i} mod p` for
//!    `i = 0, …, k − 1`, and sends share `(j, f(j) mod q)` privately
//!    to player `j`.
//! 4. Player `j` accepts iff
//!    `g^{f(j)} ≡ ∏_{i=0}^{k-1} c_i^{j^i}  (mod p)`.
//! 5. Reconstruction is plain Shamir over `GF(q)` once shares pass
//!    verification.
//!
//! Security claim is **computational**: the dealer cannot lie about
//! `s` without breaking discrete log in the subgroup. Per-share secrecy
//! reduces to the IND-CPA security of the share channel (which is
//! caller-supplied; this module verifies, it does not encrypt).
//!
//! Group choice. Production deployments should use a 2048-bit RFC 3526
//! safe-prime group or a comparable Schnorr group. The bundled
//! [`small_test_group`] is a `(p = 23, q = 11, g = 4)` toy used by the
//! unit tests — useless for security, useful for fast end-to-end
//! correctness checks.
//!
//! Secret entropy. Because the dealer broadcasts `c_0 = g^s`, a low-
//! entropy secret can be brute-forced from `c_0` directly without
//! breaking discrete log: an attacker enumerates candidate `s'`,
//! computes `g^{s'}`, and compares. This is *not* a defect of the VSS
//! reduction — it follows from Feldman's leakage of `g^s` to all
//! parties — but callers must ensure `s` is drawn from a distribution
//! with entropy comparable to `log₂ q` (e.g. the secret IS a uniform
//! field element). Encrypt-then-share an arbitrary plaintext with a
//! random key and use the *key* as `s` if the underlying datum is
//! low-entropy.

use crate::bigint::{BigUint, MontgomeryCtx};
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::primes::{is_probable_prime, random_below};
use crate::secure::Zeroizing;

/// A Schnorr-style discrete-log group: prime `p`, subgroup order `q`
/// (also prime), generator `g` of the subgroup.
#[derive(Clone, Debug)]
pub struct DlogGroup {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    /// Montgomery context for `(Z/pZ)*` — enables `pow` without paying
    /// long-division-in-the-loop costs.
    mont: MontgomeryCtx,
}

impl DlogGroup {
    /// Wrap `(p, q, g)` after fully validating the Schnorr-group
    /// relations. Checks performed:
    ///
    /// - `p ≥ 3` and odd,
    /// - `p` is prime (Miller–Rabin via [`crate::primes::is_probable_prime`]),
    /// - `1 < q < p` and `q` is prime,
    /// - `q | (p − 1)`,
    /// - `g ≠ 0, 1 mod p`,
    /// - `g^q ≡ 1 mod p` — combined with `q` prime and `g ≠ 1`, this
    ///   pins the order of `g` to exactly `q`.
    ///
    /// Returns `None` if any check fails. The Miller–Rabin test is
    /// deterministic for `p, q < ~2^81` and probabilistic with
    /// false-positive rate `≤ 4^{-12}` above that.
    #[must_use]
    pub fn new(p: BigUint, q: BigUint, g: BigUint) -> Option<Self> {
        if p < BigUint::from_u64(3) {
            return None;
        }
        if !p.is_odd() {
            return None;
        }
        if !is_probable_prime(&p) {
            return None;
        }
        if q <= BigUint::one() || q >= p {
            return None;
        }
        if !is_probable_prime(&q) {
            return None;
        }
        // q | (p − 1) — verify by exact division, not by the weaker
        // 2q ≤ p − 1 plausibility test.
        let p_minus_1 = p.sub_ref(&BigUint::one());
        let (_, rem) = p_minus_1.div_rem(&q);
        if !rem.is_zero() {
            return None;
        }
        // Reduce g mod p BEFORE the identity check — `g = p + 1`
        // is not raw-one but reduces to 1 in (Z/pZ)*; accepting it
        // would let the dealer collapse every commitment to 1, killing
        // binding. The check must therefore be against the reduced
        // representative, not the raw input.
        let g = g.modulo(&p);
        if g.is_zero() || g == BigUint::one() {
            return None;
        }
        let mont = MontgomeryCtx::new(&p)?;
        // g^q ≡ 1 mod p AND q prime AND g ≠ 1 ⇒ ord(g) = q exactly.
        let one = mont.pow(&g, &q);
        if one != BigUint::one() {
            return None;
        }
        Some(Self { p, q, g, mont })
    }

    #[must_use]
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    #[must_use]
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    #[must_use]
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// `base^exp mod p` via the Montgomery context.
    #[must_use]
    pub fn pow(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        self.mont.pow(base, exp)
    }

    /// Multiplication in `(Z/pZ)*`, exposed for verification arithmetic.
    #[must_use]
    pub fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        BigUint::mod_mul(a, b, &self.p)
    }
}

/// One trustee's share: `(player_index, f(player_index) mod q)`.
#[derive(Clone, Eq, PartialEq)]
pub struct VssShare {
    pub player: usize,
    pub value: BigUint,
}

impl core::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("VssShare(<elided>)")
    }
}

/// Public commitment vector `c = (g^{a_0}, g^{a_1}, …, g^{a_{k-1}})`
/// broadcast by the dealer.
#[derive(Clone, Eq, PartialEq)]
pub struct Commitments {
    pub c: Vec<BigUint>,
}

impl core::fmt::Debug for Commitments {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Commitments(<elided>)")
    }
}

/// Deal `n` Shamir shares of `secret` over `GF(q)` together with
/// Feldman commitments to the polynomial coefficients.
///
/// # Panics
/// - `k < 2`,
/// - `n < k`,
/// - `n ≥ q` (every player needs a distinct nonzero abscissa in
///   `GF(q)`).
#[must_use]
pub fn deal<R: Csprng>(
    group: &DlogGroup,
    rng: &mut R,
    secret: &BigUint,
    k: usize,
    n: usize,
) -> (Vec<VssShare>, Commitments) {
    assert!(k >= 2, "k must be at least 2");
    assert!(n >= k, "n must be at least k");
    assert!(
        BigUint::from_u64(n as u64) < *group.q(),
        "subgroup order must exceed n",
    );
    assert!(secret < group.q(), "secret must be < q");

    let q_field = PrimeField::new_unchecked(group.q().clone());
    // Polynomial f(x) = a_0 + a_1 x + … + a_{k-1} x^{k-1} over GF(q),
    // with a_0 = secret. Wrap in `Zeroizing` so the secret coefficient
    // and the random pad are volatile-zeroed on function exit.
    let mut coeffs = Zeroizing::new(Vec::<BigUint>::with_capacity(k));
    coeffs.push(secret.clone());
    for _ in 1..k {
        let v = random_below(rng, group.q()).expect("q > 0");
        coeffs.push(v);
    }
    let commitments = Commitments {
        c: coeffs.iter().map(|a| group.pow(group.g(), a)).collect(),
    };
    let shares: Vec<VssShare> = (1..=n)
        .map(|j| {
            let x = BigUint::from_u64(j as u64);
            let y = horner(&q_field, &coeffs, &x);
            VssShare {
                player: j,
                value: y,
            }
        })
        .collect();
    (shares, commitments)
}

/// Verify a single share against the dealer's commitments.
/// Returns `true` iff `g^{share.value} ≡ ∏_i c_i^{j^i} mod p` and
/// every `c_i` lies in the order-`q` subgroup (i.e. `c_i^q ≡ 1 mod p`).
/// The subgroup-membership step is necessary for the discrete-log
/// security reduction: a malicious dealer who broadcasts a `c_i`
/// outside the subgroup escapes the binding argument.
#[must_use]
pub fn verify_share(group: &DlogGroup, commits: &Commitments, share: &VssShare) -> bool {
    if share.player == 0 {
        return false;
    }
    // Player abscissa must fit in GF(q); at j ≡ 0 mod q the share lies
    // on the secret abscissa and reconstruction would alias to the
    // secret directly.
    let j_big = BigUint::from_u64(share.player as u64);
    if j_big >= *group.q() {
        return false;
    }
    // Subgroup membership of every commitment.
    for c_i in &commits.c {
        if c_i.is_zero() {
            return false;
        }
        if group.pow(c_i, group.q()) != BigUint::one() {
            return false;
        }
    }
    let lhs = group.pow(group.g(), &share.value);
    // RHS: ∏ c_i^{j^i}. Since the polynomial is over GF(q), the
    // exponents `j^i` are taken mod q (the subgroup order).
    let q = group.q();
    let j = BigUint::from_u64(share.player as u64);
    let mut rhs = BigUint::one();
    let mut pow_j = BigUint::one(); // j^0
    for c_i in &commits.c {
        let term = group.pow(c_i, &pow_j);
        rhs = group.mul(&rhs, &term);
        // Update pow_j to j^{i+1} mod q.
        pow_j = BigUint::mod_mul(&pow_j, &j, q);
    }
    lhs == rhs
}

/// Reconstruct the secret from any `k` (or more) verified shares by
/// Lagrange interpolation in `GF(q)` evaluated at `x = 0`.
///
/// Returns `None` if fewer than `k` are supplied or `x`-coordinates
/// collide. Callers should run [`verify_share`] on every share *before*
/// invoking this — `reconstruct` does not re-check commitments.
#[must_use]
pub fn reconstruct(group: &DlogGroup, shares: &[VssShare], k: usize) -> Option<BigUint> {
    if k < 2 || shares.len() < k {
        return None;
    }
    let q_field = PrimeField::new_unchecked(group.q().clone());
    for s in shares {
        if s.player == 0 {
            return None;
        }
        // Reject players whose abscissa would alias the secret slot
        // (≡ 0 mod q) or any larger collision with another player.
        let j_big = BigUint::from_u64(s.player as u64);
        if j_big >= *group.q() {
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
    let pts: Vec<(BigUint, BigUint)> = shares
        .iter()
        .take(k)
        .map(|s| (BigUint::from_u64(s.player as u64), s.value.clone()))
        .collect();
    lagrange_eval(&q_field, &pts, &BigUint::zero())
}

/// A toy `(p = 23, q = 11, g = 4)` group used for the unit tests.
/// Insecure: discrete log is trivial here. **Do not use in production.**
#[must_use]
pub fn small_test_group() -> DlogGroup {
    DlogGroup::new(
        BigUint::from_u64(23),
        BigUint::from_u64(11),
        BigUint::from_u64(4),
    )
    .expect("hand-validated toy group")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0xC9u8; 32])
    }

    #[test]
    fn round_trip_3_of_5() {
        let group = small_test_group();
        let mut r = rng();
        // Secret < q = 11.
        let secret = BigUint::from_u64(7);
        let (shares, commits) = deal(&group, &mut r, &secret, 3, 5);
        assert_eq!(shares.len(), 5);
        assert_eq!(commits.c.len(), 3);
        // Every share verifies.
        for s in &shares {
            assert!(verify_share(&group, &commits, s), "player {} verifies", s.player);
        }
        // Any 3 reconstruct.
        assert_eq!(reconstruct(&group, &shares[..3], 3), Some(secret.clone()));
        assert_eq!(reconstruct(&group, &shares[2..5], 3), Some(secret));
    }

    #[test]
    fn tampered_share_fails_verification() {
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(3);
        let (mut shares, commits) = deal(&group, &mut r, &secret, 3, 5);
        // Add 1 to share 3's value (mod q = 11). Any deterministic
        // perturbation that lands on a different residue class breaks
        // verification.
        let q = BigUint::from_u64(11);
        shares[2].value = shares[2].value.add_ref(&BigUint::one()).modulo(&q);
        assert!(!verify_share(&group, &commits, &shares[2]));
        // Untampered shares still verify.
        for s in shares.iter().filter(|s| s.player != 3) {
            assert!(verify_share(&group, &commits, s));
        }
    }

    #[test]
    fn verify_rejects_oversized_player() {
        // AD: player abscissa j ≥ q aliases mod q; verify_share must
        // refuse before the equation could spuriously pass.
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(2);
        let (_shares, commits) = deal(&group, &mut r, &secret, 3, 5);
        // Synthesise a share with player == q (out of range).
        let bad = VssShare {
            player: 11,
            value: BigUint::zero(),
        };
        assert!(!verify_share(&group, &commits, &bad));
    }

    #[test]
    fn verify_rejects_non_subgroup_commitment() {
        // AD: a malicious dealer can put c_i outside the order-q
        // subgroup. Verification must catch this before applying the
        // discrete-log reduction.
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(2);
        let (shares, mut commits) = deal(&group, &mut r, &secret, 3, 5);
        // Replace c_0 with a non-subgroup element. In (Z/23)*, take
        // an element of order 22 (full group): we showed in
        // rejects_non_subgroup_generator that 5 has order 22.
        commits.c[0] = BigUint::from_u64(5);
        for s in &shares {
            assert!(!verify_share(&group, &commits, s));
        }
    }

    #[test]
    fn tampered_commitment_breaks_all_shares() {
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(5);
        let (shares, mut commits) = deal(&group, &mut r, &secret, 3, 5);
        // Tamper c_0 (the commitment to the secret coefficient).
        commits.c[0] = group.mul(&commits.c[0], &BigUint::from_u64(2));
        // Every share should now fail verification.
        for s in &shares {
            assert!(!verify_share(&group, &commits, s));
        }
    }

    #[test]
    fn below_threshold_reconstruct_returns_none() {
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(8);
        let (shares, _) = deal(&group, &mut r, &secret, 3, 5);
        assert!(reconstruct(&group, &shares[..2], 3).is_none());
    }

    #[test]
    fn duplicate_player_in_reconstruct_returns_none() {
        let group = small_test_group();
        let mut r = rng();
        let secret = BigUint::from_u64(2);
        let (shares, _) = deal(&group, &mut r, &secret, 3, 5);
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert!(reconstruct(&group, &dup, 3).is_none());
    }

    #[test]
    fn larger_group_round_trip() {
        // Slightly larger safe-prime group: p = 167, q = 83, g = ?
        // Verify a generator of the order-83 subgroup: 2^2 = 4 has
        // order dividing 83; if 4 ≠ 1, it equals 83 (only choices are
        // 1 and 83).
        let group = DlogGroup::new(
            BigUint::from_u64(167),
            BigUint::from_u64(83),
            BigUint::from_u64(4),
        )
        .expect("p=167, q=83 is a valid Schnorr group with g=4");
        let mut r = rng();
        let secret = BigUint::from_u64(42);
        let (shares, commits) = deal(&group, &mut r, &secret, 4, 7);
        for s in &shares {
            assert!(verify_share(&group, &commits, s));
        }
        assert_eq!(reconstruct(&group, &shares[..4], 4), Some(secret));
    }

    #[test]
    fn rejects_identity_generator_after_reduction() {
        // PEER-REVIEW (P0, second pass): `g = p + 1` reduces to 1 in
        // (Z/pZ)*; accepting it would let the dealer collapse every
        // commitment to 1 and break Feldman binding.
        let bad = DlogGroup::new(
            BigUint::from_u64(23),
            BigUint::from_u64(11),
            BigUint::from_u64(24), // 24 mod 23 == 1
        );
        assert!(bad.is_none());
    }

    #[test]
    fn rejects_non_subgroup_generator() {
        // g = 3 is not in the order-11 subgroup of (Z/23)*: 3^11 mod 23.
        // 3^2 = 9. 3^4 = 81 mod 23 = 81 - 3*23 = 12. 3^8 = 144 mod 23 = 144 - 6*23 = 6.
        // 3^11 = 3^8 · 3^2 · 3 = 6 · 9 · 3 = 162 mod 23 = 162 - 7*23 = 162 - 161 = 1?
        // Let me recompute: 6*9 = 54, 54 mod 23 = 54-46 = 8. 8 * 3 = 24 mod 23 = 1. So 3^11 = 1.
        // So 3 IS in the subgroup. Try g = 5: 5^11 mod 23.
        //   5^2 = 25 mod 23 = 2. 5^4 = 4. 5^8 = 16. 5^11 = 16 * 4 * 5 = 320 mod 23 = 320 - 13*23 = 320 - 299 = 21.
        //   Not 1, so g=5 has order > 11; it must be order 22 (the full group).
        let bad = DlogGroup::new(
            BigUint::from_u64(23),
            BigUint::from_u64(11),
            BigUint::from_u64(5),
        );
        assert!(bad.is_none());
    }

    #[test]
    fn rejects_even_modulus() {
        let bad = DlogGroup::new(
            BigUint::from_u64(22),
            BigUint::from_u64(11),
            BigUint::from_u64(4),
        );
        assert!(bad.is_none());
    }

    #[test]
    fn rejects_q_too_large() {
        // q ≥ p is nonsensical.
        let bad = DlogGroup::new(
            BigUint::from_u64(23),
            BigUint::from_u64(23),
            BigUint::from_u64(4),
        );
        assert!(bad.is_none());
    }
}
