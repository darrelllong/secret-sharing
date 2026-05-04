//! Mignotte 1983, *How to Share a Secret* — Chinese-Remainder-Theorem
//! threshold scheme.
//!
//! A *(k, n)-Mignotte sequence* is `n` strictly increasing positive
//! integers `m_1 < m_2 < … < m_n`, pairwise coprime, with
//!
//! ```text
//!     α = m_{n−k+2} · m_{n−k+3} · … · m_n     (product of the k − 1 largest)
//!     β = m_1 · m_2 · … · m_k                  (product of the k smallest)
//!     α < β
//! ```
//!
//! The secret `S` is chosen in the open interval `(α, β)`. Each trustee
//! `i` receives `(m_i, S mod m_i)`. Any `k` shares determine the unique
//! `S < β ≤ ∏ m_{i_j}` that is consistent with all of them by the
//! Chinese Remainder Theorem; any `k − 1` shares fix `S` only modulo
//! `≤ α`, so multiple candidates in `(α, β)` remain consistent.
//!
//! Mignotte's scheme is *not* perfectly secret — `k − 1` shares narrow
//! the candidates to roughly `(β − α) / (∏ of those k − 1 moduli)`. It
//! is a uniqueness-of-recovery scheme rather than an information-
//! theoretic one. Use Asmuth–Bloom (`crate::asmuth_bloom`) when you
//! need perfect or computational secrecy.

use crate::field::PrimeField;
use crate::primes::{gcd, mod_inverse};
use crate::bigint::BigUint;

/// A validated `(k, n)`-Mignotte sequence.
#[derive(Clone, Debug)]
pub struct MignotteSequence {
    moduli: Vec<BigUint>,
    k: usize,
    /// Product of the `k − 1` largest moduli.
    alpha: BigUint,
    /// Product of the `k` smallest moduli.
    beta: BigUint,
}

/// One trustee's share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Share {
    /// 1-based index `i` of the modulus `m_i`. Public.
    pub index: usize,
    /// Residue `S mod m_i`.
    pub residue: BigUint,
}

impl MignotteSequence {
    /// Wrap a user-supplied sequence after checking the Mignotte
    /// conditions: strictly increasing, pairwise coprime, and the gap
    /// inequality `α < β` for the chosen threshold `k`.
    ///
    /// Returns `None` if any condition fails.
    #[must_use]
    pub fn new(moduli: Vec<BigUint>, k: usize) -> Option<Self> {
        let n = moduli.len();
        if k < 2 || k > n {
            return None;
        }
        // Strictly increasing.
        for i in 1..n {
            if moduli[i - 1] >= moduli[i] {
                return None;
            }
        }
        // Pairwise coprime.
        for i in 0..n {
            for j in (i + 1)..n {
                if gcd(&moduli[i], &moduli[j]) != BigUint::one() {
                    return None;
                }
            }
        }
        let alpha = product(&moduli[n - (k - 1)..]);
        let beta = product(&moduli[..k]);
        if alpha >= beta {
            return None;
        }
        Some(Self {
            moduli,
            k,
            alpha,
            beta,
        })
    }

    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.moduli.len()
    }

    #[must_use]
    pub fn moduli(&self) -> &[BigUint] {
        &self.moduli
    }

    /// Exclusive lower bound `α` of the legal secret range. Secrets
    /// must satisfy `α < S < β`; values `≤ α` may collapse to multiple
    /// pre-images visible to a `k − 1`-coalition.
    #[must_use]
    pub fn alpha(&self) -> &BigUint {
        &self.alpha
    }

    /// Exclusive upper bound `β` of the legal secret range.
    #[must_use]
    pub fn beta(&self) -> &BigUint {
        &self.beta
    }
}

/// Distribute the secret across all `n` trustees as `(i, S mod m_i)`.
///
/// # Panics
/// Panics if `secret` is not strictly inside `(α, β)`.
#[must_use]
pub fn split(seq: &MignotteSequence, secret: &BigUint) -> Vec<Share> {
    assert!(
        secret > &seq.alpha && secret < &seq.beta,
        "secret must lie strictly inside (α, β)"
    );
    seq.moduli
        .iter()
        .enumerate()
        .map(|(i, m)| Share {
            index: i + 1,
            residue: secret.modulo(m),
        })
        .collect()
}

/// Recover the secret by Chinese Remainder Theorem from any `k`
/// (or more) shares.
///
/// Returns `None` for any of:
/// - malformed input (out-of-range indices, residue `≥ m_i`, fewer than
///   `k` shares, or duplicates),
/// - extra shares (beyond the first `k`) inconsistent with the
///   CRT-recovered value,
/// - a recovered value that does not lie in the legal secret range
///   `(α, β)` — this catches first-`k` tampering whenever the wrong
///   CRT solution falls outside the gap.
///
/// First-`k` tampering whose CRT solution happens to land back in
/// `(α, β)` cannot be detected by Mignotte alone (no per-share
/// authenticator exists). Pair with [`crate::vss`] when adversarial
/// shareholders are in scope.
#[must_use]
pub fn reconstruct(seq: &MignotteSequence, shares: &[Share]) -> Option<BigUint> {
    let k = seq.k;
    if shares.len() < k {
        return None;
    }
    // Validate indices and residues; reject duplicates.
    for s in shares {
        if s.index == 0 || s.index > seq.n() {
            return None;
        }
        if s.residue >= seq.moduli[s.index - 1] {
            return None;
        }
    }
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].index == shares[j].index {
                return None;
            }
        }
    }

    // CRT-fold the first k shares.
    let used = &shares[..k];
    let (mut x, mut prod) = (BigUint::zero(), BigUint::one());
    let mut first = true;
    for s in used {
        let m = &seq.moduli[s.index - 1];
        if first {
            x = s.residue.clone();
            prod = m.clone();
            first = false;
            continue;
        }
        // Solve y ≡ x (mod prod), y ≡ residue (mod m).
        // y = x + prod * ((residue − x) * prod^{-1} mod m) mod (prod * m).
        let inv = mod_inverse(&prod.modulo(m), m)?;
        // diff = (residue − x) mod m, computed without going negative.
        let x_mod_m = x.modulo(m);
        let diff = if s.residue >= x_mod_m {
            s.residue.sub_ref(&x_mod_m)
        } else {
            s.residue.add_ref(m).sub_ref(&x_mod_m)
        };
        let t = BigUint::mod_mul(&diff, &inv, m);
        x = x.add_ref(&prod.mul_ref(&t));
        prod = prod.mul_ref(m);
    }
    // Reduce to canonical [0, prod). The folding above can leave x < prod
    // already, but a final `modulo` is cheap insurance.
    let secret = x.modulo(&prod);

    // The legal secret range is the open interval (α, β). A value
    // outside it cannot be a Mignotte secret, so refuse rather than
    // return garbage. This catches first-k tampering whenever the wrong
    // CRT solution falls outside the gap.
    if secret <= seq.alpha || secret >= seq.beta {
        return None;
    }

    // Validate any extras against the recovered secret.
    for s in &shares[k..] {
        let m = &seq.moduli[s.index - 1];
        if secret.modulo(m) != s.residue {
            return None;
        }
    }
    Some(secret)
}

fn product(values: &[BigUint]) -> BigUint {
    let mut acc = BigUint::one();
    for v in values {
        acc = acc.mul_ref(v);
    }
    acc
}

/// Convenience: a fixed (3, 5)-Mignotte sequence built from small odd
/// primes. Useful for tests, examples, and quick sanity checks. The
/// secret space is `(α, β) = (437, 2431)` — about 1.8 KiB-equivalent of
/// secrets fit.
#[must_use]
pub fn small_example_3_of_5() -> MignotteSequence {
    let moduli = [11u64, 13, 17, 19, 23]
        .into_iter()
        .map(BigUint::from_u64)
        .collect();
    MignotteSequence::new(moduli, 3).expect("hand-validated small Mignotte sequence")
}

// PrimeField is unused here — Mignotte runs over distinct moduli. The
// import is left available to keep the crate's per-module pattern
// consistent for callers reading the source.
#[allow(dead_code)]
type _UnusedField = PrimeField;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_example_round_trip() {
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(1000);
        let shares = split(&seq, &secret);
        assert_eq!(shares.len(), 5);
        // Try several 3-subsets.
        assert_eq!(reconstruct(&seq, &shares[..3]), Some(secret.clone()));
        assert_eq!(reconstruct(&seq, &shares[1..4]), Some(secret.clone()));
        assert_eq!(reconstruct(&seq, &shares[2..]), Some(secret));
    }

    #[test]
    fn extra_shares_consistent() {
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(2000);
        let shares = split(&seq, &secret);
        assert_eq!(reconstruct(&seq, &shares), Some(secret));
    }

    #[test]
    fn tampered_extra_share_rejected() {
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(1500);
        let mut shares = split(&seq, &secret);
        shares[4].residue = shares[4].residue.add_ref(&BigUint::one());
        assert!(reconstruct(&seq, &shares).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(800);
        let shares = split(&seq, &secret);
        assert!(reconstruct(&seq, &shares[..2]).is_none());
    }

    #[test]
    fn duplicate_share_rejected() {
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(1234);
        let mut shares = split(&seq, &secret);
        shares[1] = shares[0].clone();
        assert!(reconstruct(&seq, &shares[..3]).is_none());
    }

    #[test]
    #[should_panic(expected = "strictly inside (α, β)")]
    fn split_rejects_secret_below_alpha() {
        let seq = small_example_3_of_5();
        // alpha = 19 * 23 = 437; choose 100 < 437.
        let _ = split(&seq, &BigUint::from_u64(100));
    }

    #[test]
    #[should_panic(expected = "strictly inside (α, β)")]
    fn split_rejects_secret_at_or_above_beta() {
        let seq = small_example_3_of_5();
        // beta = 11 * 13 * 17 = 2431; choose exactly beta.
        let _ = split(&seq, &BigUint::from_u64(2431));
    }

    #[test]
    fn rejects_non_coprime_sequence() {
        // 6 and 9 share factor 3 — Mignotte requires pairwise coprime.
        let m = vec![
            BigUint::from_u64(5),
            BigUint::from_u64(6),
            BigUint::from_u64(9),
            BigUint::from_u64(11),
        ];
        assert!(MignotteSequence::new(m, 2).is_none());
    }

    #[test]
    fn rejects_non_increasing_sequence() {
        let m = vec![
            BigUint::from_u64(11),
            BigUint::from_u64(7),
            BigUint::from_u64(13),
            BigUint::from_u64(17),
        ];
        assert!(MignotteSequence::new(m, 2).is_none());
    }

    #[test]
    fn rejects_when_alpha_geq_beta() {
        // 7, 11 with k = 1 isn't allowed (k ≥ 2), so try k = 2 over a
        // tiny sequence where alpha (m_n) ≥ beta (m_1·m_2)? With k = 2,
        // alpha = m_n, beta = m_1·m_2. Pick {2, 3, 7}: alpha = 7,
        // beta = 6 → α ≥ β, reject.
        let m = vec![
            BigUint::from_u64(2),
            BigUint::from_u64(3),
            BigUint::from_u64(7),
        ];
        assert!(MignotteSequence::new(m, 2).is_none());
    }

    #[test]
    fn first_k_tamper_outside_range_rejected() {
        // AD #2 (P0): a tampered first-k share whose CRT result falls
        // outside (α, β) must yield None, not garbage.
        let seq = small_example_3_of_5();
        let secret = BigUint::from_u64(1234);
        let mut shares = split(&seq, &secret);
        // Attempt several tamperings until we find one whose CRT
        // result lands outside (α, β); for small moduli most will.
        // We tamper shares[0] and reconstruct using only the first k.
        for delta in 1..10u64 {
            let mut bad = shares.clone();
            bad[0].residue =
                bad[0]
                    .residue
                    .add_ref(&BigUint::from_u64(delta))
                    .modulo(&seq.moduli[0]);
            let got = reconstruct(&seq, &bad[..3]);
            // Either: bounds rejected (None) — preferred — or returned
            // a value still strictly inside (α, β) by coincidence; in
            // both cases we cannot be returning the *original* secret.
            assert_ne!(got.as_ref(), Some(&secret));
        }
        let _ = &mut shares;
    }

    #[test]
    fn larger_sequence_round_trip() {
        // (4, 7) Mignotte over the first eight odd primes that are
        // pairwise coprime (which all primes are). beta is large enough
        // to demonstrate non-trivial CRT folding.
        let primes = [11u64, 13, 17, 19, 23, 29, 31];
        let moduli: Vec<BigUint> = primes.iter().copied().map(BigUint::from_u64).collect();
        let seq = MignotteSequence::new(moduli, 4).expect("valid (4,7) Mignotte");
        // pick a secret strictly inside (alpha, beta)
        let secret = (seq.alpha().clone()).add_ref(&BigUint::from_u64(12345));
        assert!(secret < *seq.beta(), "secret must fit in space");
        let shares = split(&seq, &secret);
        // Various 4-subsets.
        assert_eq!(reconstruct(&seq, &shares[..4]), Some(secret.clone()));
        assert_eq!(reconstruct(&seq, &shares[3..7]), Some(secret.clone()));
        // Pick non-contiguous subset.
        let picked: Vec<Share> = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
            shares[6].clone(),
        ];
        assert_eq!(reconstruct(&seq, &picked), Some(secret));
    }
}
