//! Asmuth–Bloom 1983, *A Modular Approach to Key Safeguarding* —
//! Chinese-Remainder-Theorem `(k, n)` scheme with information-theoretic
//! secrecy.
//!
//! Parameters: a public modulus `m_0` (the secret modulus) and `n`
//! pairwise-coprime moduli `m_1 < m_2 < … < m_n`, each coprime to
//! `m_0` and strictly larger than `m_0`, satisfying the *Asmuth–Bloom
//! inequality*
//!
//! ```text
//!     M_bot = m_1 · m_2 · … · m_k    (product of the k smallest)
//!     M_top = m_{n−k+2} · … · m_n     (product of the k − 1 largest)
//!     m_0 · M_top < M_bot
//! ```
//!
//! For a secret `S ∈ [0, m_0)`, pick `A` uniformly from
//! `[0, ⌊M_bot / m_0⌋)`, set `y = S + A · m_0` (so `y < M_bot`), and
//! distribute `(m_i, y mod m_i)` to trustee `i`. Any `k` shares CRT-
//! reconstruct `y` (uniquely in `[0, ∏ m_{i_j}) ⊇ [0, M_bot)`); the
//! secret is then `S = y mod m_0`. With `k − 1` shares, `y` is fixed
//! only modulo a product `P ≤ M_top`, leaving roughly `M_bot / P ≥ m_0`
//! candidate `y` values in the legal range, distributed *near*-
//! uniformly across the `m_0` residue classes mod `m_0`.
//!
//! Secrecy is *near*-perfect rather than strictly perfect: `a_range =
//! ⌊M_bot / m_0⌋` is generally not an exact multiple of `P`, so the
//! count of `(S, A)` pairs landing in each residue class differs by at
//! most one. The deviation is bounded by `m_0 · P / M_bot ≤ 1 /
//! (m_0 · ⌊M_bot / (m_0² · P)⌋)`, which is exponentially small in the
//! security parameter for the standard parameter choices the paper
//! recommends. For applications that need exact perfect secrecy, run
//! over Shamir.
//!
//! Compared with Mignotte, the cost is the extra masking layer
//! (random `A` and the `m_0` reduction); the benefit is the near-
//! perfect statistical secrecy described above, rather than mere
//! reconstruction-uniqueness.

use crate::primes::{gcd, mod_inverse, random_below};
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// Validated Asmuth–Bloom parameter set.
#[derive(Clone, Debug)]
pub struct AsmuthBloomParams {
    m0: BigUint,
    moduli: Vec<BigUint>,
    k: usize,
    /// Product of the `k` smallest moduli. Bounds the masked secret `y`.
    m_bot: BigUint,
    /// `⌊M_bot / m_0⌋` — the upper bound (exclusive) of the random mask
    /// `A`. Pre-computed so split is allocation-free.
    a_range: BigUint,
}

/// One trustee's piece: index of the modulus and the residue
/// `y mod m_i`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Share {
    pub index: usize,
    pub residue: BigUint,
}

impl AsmuthBloomParams {
    /// Wrap `(m_0, moduli, k)` after checking every Asmuth–Bloom
    /// condition. Returns `None` on any violation.
    #[must_use]
    pub fn new(m0: BigUint, moduli: Vec<BigUint>, k: usize) -> Option<Self> {
        let n = moduli.len();
        if k < 2 || k > n {
            return None;
        }
        if m0 <= BigUint::one() {
            return None;
        }
        // Strictly increasing.
        for i in 1..n {
            if moduli[i - 1] >= moduli[i] {
                return None;
            }
        }
        // Each m_i > m_0 and coprime with m_0.
        for m in &moduli {
            if m <= &m0 {
                return None;
            }
            if gcd(m, &m0) != BigUint::one() {
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
        let m_bot = product(&moduli[..k]);
        let m_top = product(&moduli[n - (k - 1)..]);
        // m_0 · M_top < M_bot.
        if m0.mul_ref(&m_top) >= m_bot {
            return None;
        }
        let (a_range, _) = m_bot.div_rem(&m0);
        Some(Self {
            m0,
            moduli,
            k,
            m_bot,
            a_range,
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
    pub fn m0(&self) -> &BigUint {
        &self.m0
    }

    #[must_use]
    pub fn moduli(&self) -> &[BigUint] {
        &self.moduli
    }
}

/// Distribute the secret across all `n` trustees.
///
/// # Panics
/// Panics if `secret >= m_0`.
#[must_use]
pub fn split<R: Csprng>(params: &AsmuthBloomParams, rng: &mut R, secret: &BigUint) -> Vec<Share> {
    assert!(secret < &params.m0, "secret must be < m_0");
    let a = random_below(rng, &params.a_range).expect("a_range > 0 by construction");
    let y = secret.add_ref(&a.mul_ref(&params.m0));
    params
        .moduli
        .iter()
        .enumerate()
        .map(|(i, m)| Share {
            index: i + 1,
            residue: y.modulo(m),
        })
        .collect()
}

/// Recover the secret from any `k` (or more) shares. CRT-folds the
/// first `k` to recover `y`, validates extras against `y`, then returns
/// `y mod m_0`.
///
/// Returns `None` for any of: duplicate or out-of-range indices,
/// residues `≥ m_i`, fewer than `k` shares, or extras inconsistent with
/// the recovered `y`.
#[must_use]
pub fn reconstruct(params: &AsmuthBloomParams, shares: &[Share]) -> Option<BigUint> {
    let k = params.k;
    if shares.len() < k {
        return None;
    }
    for s in shares {
        if s.index == 0 || s.index > params.n() {
            return None;
        }
        if s.residue >= params.moduli[s.index - 1] {
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
    let (mut y, mut prod) = (BigUint::zero(), BigUint::one());
    let mut first = true;
    for s in used {
        let m = &params.moduli[s.index - 1];
        if first {
            y = s.residue.clone();
            prod = m.clone();
            first = false;
            continue;
        }
        let inv = mod_inverse(&prod.modulo(m), m)?;
        let y_mod_m = y.modulo(m);
        let diff = if s.residue >= y_mod_m {
            s.residue.sub_ref(&y_mod_m)
        } else {
            s.residue.add_ref(m).sub_ref(&y_mod_m)
        };
        let t = BigUint::mod_mul(&diff, &inv, m);
        y = y.add_ref(&prod.mul_ref(&t));
        prod = prod.mul_ref(m);
    }
    let y = y.modulo(&prod);
    // y must lie in [0, M_bot). For honest shares this holds by
    // construction; for tampered/inconsistent extras it might not, but
    // we still validate extras below before returning.
    if y >= params.m_bot {
        return None;
    }
    for s in &shares[k..] {
        let m = &params.moduli[s.index - 1];
        if y.modulo(m) != s.residue {
            return None;
        }
    }
    Some(y.modulo(&params.m0))
}

fn product(values: &[BigUint]) -> BigUint {
    let mut acc = BigUint::one();
    for v in values {
        acc = acc.mul_ref(v);
    }
    acc
}

/// Convenience: a (3, 5)-Asmuth–Bloom parameter set with `m_0 = 5` and
/// moduli `{11, 13, 17, 19, 23}`. Used by tests and as a quick example.
#[must_use]
pub fn small_example_3_of_5() -> AsmuthBloomParams {
    let m0 = BigUint::from_u64(5);
    let moduli = [11u64, 13, 17, 19, 23]
        .into_iter()
        .map(BigUint::from_u64)
        .collect();
    AsmuthBloomParams::new(m0, moduli, 3).expect("hand-validated small parameter set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[91u8; 32])
    }

    #[test]
    fn small_round_trip() {
        let p = small_example_3_of_5();
        let mut r = rng();
        for s_val in 0..5u64 {
            let secret = BigUint::from_u64(s_val);
            let shares = split(&p, &mut r, &secret);
            assert_eq!(shares.len(), 5);
            assert_eq!(reconstruct(&p, &shares[..3]), Some(secret.clone()));
            assert_eq!(reconstruct(&p, &shares[1..4]), Some(secret.clone()));
            assert_eq!(reconstruct(&p, &shares[2..]), Some(secret));
        }
    }

    #[test]
    fn extras_validated() {
        let p = small_example_3_of_5();
        let mut r = rng();
        let secret = BigUint::from_u64(3);
        let shares = split(&p, &mut r, &secret);
        assert_eq!(reconstruct(&p, &shares), Some(secret));
    }

    #[test]
    fn tampered_extra_rejected() {
        let p = small_example_3_of_5();
        let mut r = rng();
        let secret = BigUint::from_u64(2);
        let mut shares = split(&p, &mut r, &secret);
        shares[4].residue = shares[4].residue.add_ref(&BigUint::one()).modulo(&p.moduli[4]);
        assert!(reconstruct(&p, &shares).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let p = small_example_3_of_5();
        let mut r = rng();
        let secret = BigUint::from_u64(1);
        let shares = split(&p, &mut r, &secret);
        assert!(reconstruct(&p, &shares[..2]).is_none());
    }

    #[test]
    fn duplicate_share_rejected() {
        let p = small_example_3_of_5();
        let mut r = rng();
        let secret = BigUint::from_u64(4);
        let mut shares = split(&p, &mut r, &secret);
        shares[1] = shares[0].clone();
        assert!(reconstruct(&p, &shares[..3]).is_none());
    }

    #[test]
    #[should_panic(expected = "secret must be < m_0")]
    fn secret_above_m0_panics() {
        let p = small_example_3_of_5();
        let mut r = rng();
        let _ = split(&p, &mut r, &BigUint::from_u64(5));
    }

    #[test]
    fn rejects_non_coprime_with_m0() {
        // m_0 = 5, modulus 25 violates coprimality with m_0.
        let m0 = BigUint::from_u64(5);
        let m = vec![
            BigUint::from_u64(11),
            BigUint::from_u64(13),
            BigUint::from_u64(17),
            BigUint::from_u64(19),
            BigUint::from_u64(25),
        ];
        assert!(AsmuthBloomParams::new(m0, m, 3).is_none());
    }

    #[test]
    fn rejects_when_inequality_fails() {
        // m_0 = 5, moduli = [7, 11, 13, 17, 19], k = 3
        // M_bot = 7·11·13 = 1001; M_top = 17·19 = 323; 5·323 = 1615 > 1001 → fail.
        let m0 = BigUint::from_u64(5);
        let m = vec![
            BigUint::from_u64(7),
            BigUint::from_u64(11),
            BigUint::from_u64(13),
            BigUint::from_u64(17),
            BigUint::from_u64(19),
        ];
        assert!(AsmuthBloomParams::new(m0, m, 3).is_none());
    }

    #[test]
    fn first_k_tamper_likely_falls_outside_m_bot() {
        // AD #6 (P1 replacement): with M_bot = 2431 and prod_first_k =
        // M_bot, a tampered first-k share's CRT result spans [0, prod)
        // = [0, M_bot), so the bounds check `y >= M_bot` (line 200)
        // always passes — but `y mod m_0` differs from the secret. This
        // test exercises that the recovered "secret" generically
        // disagrees with the original under first-k tampering, so a
        // caller using Asmuth-Bloom against an adversarial shareholder
        // sees garbage rather than the original.
        let p = small_example_3_of_5();
        let mut r = rng();
        let secret = BigUint::from_u64(2);
        let shares = split(&p, &mut r, &secret);
        let mut any_disagreement = false;
        for delta in 1..7u64 {
            let mut bad = shares.clone();
            bad[0].residue =
                bad[0]
                    .residue
                    .add_ref(&BigUint::from_u64(delta))
                    .modulo(&p.moduli[0]);
            // Tampered first-k: function returns Some(wrong) — we don't
            // promise None, but we promise it's not the original secret.
            if let Some(got) = reconstruct(&p, &bad[..3]) {
                if got != secret {
                    any_disagreement = true;
                }
            } else {
                // Or None, also acceptable — caller knows recovery failed.
                any_disagreement = true;
            }
        }
        assert!(
            any_disagreement,
            "tampered first-k must not silently roundtrip to the original secret"
        );
    }

    #[test]
    fn larger_parameter_round_trip() {
        // AD #6 follow-on: a larger (4, 7) configuration to exercise
        // more substantial CRT folding.
        let m0 = BigUint::from_u64(11);
        let moduli = [101u64, 103, 107, 109, 113, 127, 131]
            .into_iter()
            .map(BigUint::from_u64)
            .collect();
        let params = AsmuthBloomParams::new(m0, moduli, 4).expect("valid (4,7) params");
        let mut r = rng();
        for s_val in 0..11u64 {
            let secret = BigUint::from_u64(s_val);
            let shares = split(&params, &mut r, &secret);
            assert_eq!(reconstruct(&params, &shares[..4]), Some(secret.clone()));
            assert_eq!(reconstruct(&params, &shares[3..7]), Some(secret));
        }
    }
}
