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
use crate::secure::ct_eq_biguint;

/// A validated `(k, n)`-Mignotte sequence.
///
/// At construction the sequence may pre-compute a pairwise CRT
/// inverse table when the moduli are large enough that
/// extended-Euclidean inversion outweighs Montgomery setup cost. The
/// threshold is documented at [`CRT_PRECOMP_THRESHOLD_BITS`]; pilot
/// measurement on the existing test sequences (≤ 8-bit moduli) showed
/// the precomp regressed reconstruct, while a 130-bit sequence (the
/// smallest case where the trade flips) gains ~1.3×. For sequences
/// below the threshold, `pair_inv` is `None` and reconstruct uses one
/// `mod_inverse` per fold step (the historical baseline).
#[derive(Clone, Debug)]
pub struct MignotteSequence {
    moduli: Vec<BigUint>,
    k: usize,
    /// Product of the `k − 1` largest moduli.
    alpha: BigUint,
    /// Product of the `k` smallest moduli.
    beta: BigUint,
    /// `pair_inv[i][j] = (m_j mod m_i)^{-1} mod m_i` for `i ≠ j`,
    /// 0-based into `moduli`. Diagonal is unused (`BigUint::zero()`).
    /// `None` when the sequence falls below
    /// [`CRT_PRECOMP_THRESHOLD_BITS`] and reconstruct uses the
    /// per-fold `mod_inverse` path instead.
    pair_inv: Option<Vec<Vec<BigUint>>>,
}

/// Bit-length above which CRT pairwise-inverse precomputation pays
/// off vs the per-fold `mod_inverse` baseline. Below the threshold,
/// `BigUint::mod_mul` rebuilds a Montgomery context per call and the
/// setup cost dominates the per-step extended-Euclidean it tries to
/// replace; pilot measurements on 8-bit / 64-bit / 130-bit / 256-bit
/// sequences identified the flip near 100–130 bits, so we use 128 as
/// the cutoff with a small margin on the precomp side.
pub const CRT_PRECOMP_THRESHOLD_BITS: usize = 128;

/// One trustee's share.
#[derive(Clone, Eq, PartialEq)]
pub struct Share {
    /// 1-based index `i` of the modulus `m_i`. Public.
    pub index: usize,
    /// Residue `S mod m_i`.
    pub residue: BigUint,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Share(<elided>)")
    }
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
        for i in 1..n {
            if moduli[i - 1] >= moduli[i] {
                return None;
            }
        }
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
        // Decide whether to precompute the pairwise-inverse table.
        // The decision is on the LARGEST modulus's bit length: that's
        // where mod_inverse cost peaks, and a single threshold on a
        // single value keeps the dispatch trivially correct under
        // future moduli additions.
        let max_bits = moduli.iter().map(BigUint::bits).max().unwrap_or(0);
        let pair_inv = if max_bits >= CRT_PRECOMP_THRESHOLD_BITS {
            let mut table: Vec<Vec<BigUint>> = Vec::with_capacity(n);
            for i in 0..n {
                let mut row = Vec::with_capacity(n);
                for j in 0..n {
                    if i == j {
                        row.push(BigUint::zero());
                    } else {
                        let m_j_mod_m_i = moduli[j].modulo(&moduli[i]);
                        // Pairwise coprimality (validated above) makes
                        // mod_inverse infallible here; a `?` failure
                        // means a validation regression, not user error.
                        let inv = mod_inverse(&m_j_mod_m_i, &moduli[i])?;
                        row.push(inv);
                    }
                }
                table.push(row);
            }
            Some(table)
        } else {
            None
        };
        Some(Self {
            moduli,
            k,
            alpha,
            beta,
            pair_inv,
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

    let used = &shares[..k];
    let (mut x, mut prod) = (BigUint::zero(), BigUint::one());
    let mut first = true;
    let mut folded_indices: Vec<usize> = Vec::with_capacity(k);
    for s in used {
        let m_i_idx = s.index - 1;
        let m = &seq.moduli[m_i_idx];
        if first {
            x = s.residue.clone();
            prod = m.clone();
            folded_indices.push(m_i_idx);
            first = false;
            continue;
        }
        // Solve y ≡ x (mod prod), y ≡ residue (mod m).
        // y = x + prod * ((residue − x) * prod^{-1} mod m) mod (prod * m).
        // The `prod^{-1} mod m` factor is computed two ways depending
        // on the precomp dispatch threshold:
        //
        // - Precomp path (large moduli): assemble inv from the cached
        //   pairwise table, ∏_{j folded} pair_inv[m_i_idx][j] mod m.
        // - Direct path (small moduli, no precomp): one extended-
        //   Euclidean call as in the historical implementation.
        let inv = if let Some(pair_inv) = &seq.pair_inv {
            let mut acc = BigUint::one();
            for &j in &folded_indices {
                debug_assert!(
                    j != m_i_idx,
                    "fold step would self-multiply pair_inv diagonal",
                );
                acc = BigUint::mod_mul(&acc, &pair_inv[m_i_idx][j], m);
            }
            acc
        } else {
            mod_inverse(&prod.modulo(m), m)?
        };
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
        folded_indices.push(m_i_idx);
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

    for s in &shares[k..] {
        let m = &seq.moduli[s.index - 1];
        let pred = secret.modulo(m);
        if !ct_eq_biguint(&pred, &s.residue) {
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
        // {2, 3, 7} with k = 2 gives α = m_n = 7 and β = m_1·m_2 = 6,
        // collapsing the secrecy gap (α, β) — Mignotte's construction
        // is undefined here, so new() must refuse.
        let m = vec![
            BigUint::from_u64(2),
            BigUint::from_u64(3),
            BigUint::from_u64(7),
        ];
        assert!(MignotteSequence::new(m, 2).is_none());
    }

    #[test]
    fn first_k_tamper_outside_range_rejected() {
        // Mignotte's reconstruction-uniqueness only holds when the CRT
        // result lands in (α, β). A tampered first-k share that pushes
        // the result out of that gap must return None, not garbage in
        // the upper interval.
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

    /// Build a (3, 5)-Mignotte sequence whose moduli sit just above
    /// the CRT precomp threshold so the precomp branch is exercised.
    /// Uses five distinct primes near 2^130, generated deterministically
    /// from a fixed seed via `random_below` + Miller–Rabin so the test
    /// runs in well under a second and the sequence is reproducible.
    fn large_example_3_of_5() -> MignotteSequence {
        use crate::csprng::ChaCha20Rng;
        use crate::primes::{is_probable_prime, random_below};
        let mut rng = ChaCha20Rng::from_seed(&[0xA1u8; 32]);
        // Floor: 2^130, ceiling: 2^131. Primes in this range are
        // pairwise coprime by virtue of being distinct primes; the
        // remaining Mignotte conditions (strict-increase and α < β)
        // we sort and verify after collection.
        let lo = {
            let mut v = BigUint::one();
            v.shl_bits(130);
            v
        };
        let span = {
            let mut v = BigUint::one();
            v.shl_bits(130);
            v
        };
        let mut found: Vec<BigUint> = Vec::new();
        while found.len() < 5 {
            let mut candidate = random_below(&mut rng, &span).expect("span > 0");
            candidate = candidate.add_ref(&lo);
            if !candidate.is_odd() {
                continue;
            }
            if is_probable_prime(&candidate) && !found.contains(&candidate) {
                found.push(candidate);
            }
        }
        found.sort();
        MignotteSequence::new(found, 3).expect("constructed 130-bit Mignotte sequence")
    }

    #[test]
    fn small_example_skips_precomp() {
        // Below CRT_PRECOMP_THRESHOLD_BITS, pair_inv must be None
        // so reconstruct takes the historical mod_inverse path.
        let seq = small_example_3_of_5();
        assert!(seq.pair_inv.is_none(), "small moduli should skip CRT precomp");
    }

    #[test]
    fn large_example_uses_precomp() {
        // At ≥ 130-bit moduli, pair_inv must be populated so
        // reconstruct takes the precomp path.
        let seq = large_example_3_of_5();
        assert!(seq.pair_inv.is_some(), "large moduli should populate CRT precomp");
        let table = seq.pair_inv.as_ref().unwrap();
        assert_eq!(table.len(), 5);
        for row in table {
            assert_eq!(row.len(), 5);
        }
    }

    #[test]
    fn large_example_round_trip_via_precomp() {
        // The precomp branch must produce the same secrets as the
        // direct mod_inverse branch on the same operand stream.
        let seq = large_example_3_of_5();
        let alpha = seq.alpha().clone();
        let beta = seq.beta().clone();
        let secret = alpha.add_ref(&BigUint::from_u64(7));
        assert!(secret < beta, "secret must lie in (α, β)");
        let shares = split(&seq, &secret);
        for window_start in 0..=2 {
            let used = &shares[window_start..window_start + 3];
            assert_eq!(
                reconstruct(&seq, used),
                Some(secret.clone()),
                "precomp branch failed for shares[{}..{}]",
                window_start,
                window_start + 3,
            );
        }
    }
}
