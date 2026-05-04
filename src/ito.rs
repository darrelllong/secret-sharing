//! Ito–Saito–Nishizeki 1989, *Secret Sharing Scheme Realising General
//! Access Structure* — cumulative-array realisation of an arbitrary
//! monotone access structure over `n` parties.
//!
//! Inputs: an access structure `A ⊆ 2^{1..=n}` described by its set of
//! *maximal forbidden coalitions* `Q* = {F_1, …, F_t}` — the maximal
//! subsets that should NOT recover the secret. Equivalently, `A` is the
//! upward closure of the complements; a coalition `Q` is qualified iff
//! `Q ⊄ F_i` for every `i`.
//!
//! Construction. Pick `r_1, …, r_{t-1}` uniformly in `GF(p)` and set
//! `r_t = s − Σ_{i<t} r_i`, so `Σ_i r_i = s`. Player `j` receives the
//! sub-share set `{ (i, r_i) : j ∉ F_i }`.
//!
//! Recovery. A qualified coalition `Q` covers every forbidden index `i`
//! (because `Q ⊄ F_i` ⇒ ∃ `j ∈ Q` with `j ∉ F_i` ⇒ that `j` holds
//! `r_i`). Sum the `t` distinct `r_i` to recover `s`.
//!
//! Threshold case sanity check. For `(k, n)` thresholds the maximal
//! forbidden coalitions are exactly the `(k − 1)`-element subsets of
//! `{1..=n}`, so `t = C(n, k − 1)` and per-player share size is
//! `C(n − 1, k − 1)`. Cumulative-array shares are exponential in
//! `min(k, n − k)`; for compact threshold sharing prefer Shamir.
//!
//! Robustness note. ISN is *not* error-correcting. When a coalition is
//! exactly minimal each `r_i` is contributed by a single player, so a
//! tampered sub-share has no redundant copy to disagree with — the
//! reconstructor accepts the player's value and returns a wrong sum.
//! When the coalition is super-minimal, sub-shares overlap and our
//! `reconstruct` cross-checks them, returning `None` on disagreement.

use crate::field::PrimeField;
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// A validated access structure over `n` parties (1-based) described by
/// its maximal forbidden coalitions.
#[derive(Clone, Debug)]
pub struct AccessStructure {
    n: usize,
    /// Each coalition is sorted by player index for canonical comparison.
    forbidden: Vec<Vec<usize>>,
}

impl AccessStructure {
    /// Wrap the access structure after checking:
    /// - every player index is in `1..=n`,
    /// - each coalition is internally non-duplicated,
    /// - no coalition is a subset of another (i.e. they are maximal),
    /// - no coalition equals the full party set (the empty access
    ///   structure is degenerate; use `n + 1`-of-`n` if that's intended,
    ///   which we forbid up front).
    ///
    /// Returns `None` if any check fails.
    #[must_use]
    pub fn new(n: usize, mut forbidden: Vec<Vec<usize>>) -> Option<Self> {
        if n == 0 || forbidden.is_empty() {
            return None;
        }
        for f in &mut forbidden {
            f.sort_unstable();
            f.dedup();
            if f.iter().any(|&j| j == 0 || j > n) {
                return None;
            }
            if f.len() == n {
                // Full party set is forbidden ⇒ no qualified coalition.
                return None;
            }
        }
        // Maximality: no coalition is a subset of another.
        for i in 0..forbidden.len() {
            for j in 0..forbidden.len() {
                if i == j {
                    continue;
                }
                if is_subset(&forbidden[i], &forbidden[j]) {
                    return None;
                }
            }
        }
        Some(Self { n, forbidden })
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Number of maximal forbidden coalitions = number of `r_i` parts.
    #[must_use]
    pub fn t(&self) -> usize {
        self.forbidden.len()
    }

    /// Whether a given coalition is qualified under this access
    /// structure. Useful for testing reconstruction inputs.
    #[must_use]
    pub fn qualifies(&self, coalition: &[usize]) -> bool {
        let mut sorted = coalition.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        // Q is qualified iff for every F: Q ⊄ F (i.e. ∃ j ∈ Q with j ∉ F).
        self.forbidden.iter().all(|f| !is_subset(&sorted, f))
    }
}

fn is_subset(small: &[usize], large: &[usize]) -> bool {
    // Both inputs are sorted, deduped.
    let (mut i, mut j) = (0usize, 0usize);
    while i < small.len() {
        while j < large.len() && large[j] < small[i] {
            j += 1;
        }
        if j == large.len() || large[j] != small[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// One player's share: a list of `(forbidden_index, r_i)` pairs for
/// every forbidden coalition that does NOT contain this player.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlayerShare {
    /// Player ID, 1-based.
    pub player: usize,
    /// `(i, r_i)` for every `i ∈ {0..t}` such that `player ∉ F_i`.
    pub parts: Vec<(usize, BigUint)>,
}

/// Distribute `n` shares of the secret across the access structure.
/// Returns a `PlayerShare` for each player `1..=n`.
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    structure: &AccessStructure,
) -> Vec<PlayerShare> {
    let t = structure.t();
    // r_1, …, r_{t-1} uniform; r_t chosen so Σ r_i = s.
    let mut rs: Vec<BigUint> = Vec::with_capacity(t);
    let mut sum = BigUint::zero();
    for _ in 0..(t - 1) {
        let v = field.random(rng);
        sum = field.add(&sum, &v);
        rs.push(v);
    }
    rs.push(field.sub(&field.reduce(secret), &sum));

    // Per-player parts.
    (1..=structure.n())
        .map(|player| {
            let parts: Vec<(usize, BigUint)> = (0..t)
                .filter(|&i| !structure.forbidden[i].contains(&player))
                .map(|i| (i, rs[i].clone()))
                .collect();
            PlayerShare { player, parts }
        })
        .collect()
}

/// Reconstruct the secret from the supplied players' shares. The set of
/// players whose shares are passed in must be qualified — otherwise the
/// union of their `parts` will not cover every `r_i` and the function
/// returns `None`.
///
/// Also returns `None` on:
/// - duplicate player IDs,
/// - shares whose `parts` indices are out of range or contradict the
///   access structure (e.g. a player claiming to hold `r_i` for an `i`
///   such that `player ∈ F_i`),
/// - inconsistent `r_i` reported by two players whose `parts` overlap
///   on the same `i` (one of them tampered).
///
/// Tampering detection is *only* available when sub-shares overlap.
/// In a *minimal* qualified coalition each `r_i` is held by exactly
/// one party, leaving no redundancy to expose tampering — the function
/// returns the *wrong* secret rather than `None`. ISN is not error-
/// correcting; for adversarial parties use [`crate::vss`].
#[must_use]
pub fn reconstruct(
    field: &PrimeField,
    structure: &AccessStructure,
    shares: &[PlayerShare],
) -> Option<BigUint> {
    if shares.is_empty() {
        return None;
    }
    let t = structure.t();

    // No duplicate player IDs.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].player == shares[j].player {
                return None;
            }
        }
    }

    // Validate every (player, part) against the structure: a player can
    // only legitimately hold `r_i` for an `i` whose forbidden coalition
    // does not contain them.
    for s in shares {
        if s.player == 0 || s.player > structure.n() {
            return None;
        }
        for (i, _) in &s.parts {
            if *i >= t {
                return None;
            }
            if structure.forbidden[*i].contains(&s.player) {
                return None;
            }
        }
    }

    // Collect r_i, cross-checking duplicates from different players.
    let mut collected: Vec<Option<BigUint>> = vec![None; t];
    for s in shares {
        for (i, r) in &s.parts {
            match &collected[*i] {
                Some(prev) if prev != r => return None,
                _ => collected[*i] = Some(r.clone()),
            }
        }
    }
    // Coalition is qualified iff every r_i was collected.
    let mut sum = BigUint::zero();
    for slot in &collected {
        let v = slot.as_ref()?;
        sum = field.add(&sum, v);
    }
    Some(sum)
}

/// Helper: build the canonical `(k, n)` threshold access structure as
/// the family of all `(k − 1)`-element subsets. Useful for tests and to
/// verify that ISN reduces to Shamir-style thresholds.
///
/// # Panics
/// - `k < 2` or `k > n`.
#[must_use]
pub fn threshold_access_structure(n: usize, k: usize) -> AccessStructure {
    assert!(k >= 2 && k <= n, "need 2 ≤ k ≤ n");
    let mut combos: Vec<Vec<usize>> = Vec::new();
    let mut cur = Vec::with_capacity(k - 1);
    fn rec(start: usize, n: usize, want: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == want {
            out.push(cur.clone());
            return;
        }
        for j in start..=n {
            cur.push(j);
            rec(j + 1, n, want, cur, out);
            cur.pop();
        }
    }
    rec(1, n, k - 1, &mut cur, &mut combos);
    AccessStructure::new(n, combos).expect("threshold structure is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0xA1u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64(65_537))
    }

    #[test]
    fn two_of_three_threshold_via_isn() {
        // (2, 3) threshold ↔ maximal forbidden = {{1}, {2}, {3}}.
        let f = small();
        let mut r = rng();
        let s = threshold_access_structure(3, 2);
        let secret = BigUint::from_u64(42);
        let shares = split(&f, &mut r, &secret, &s);
        // Each player should hold 2 of the 3 r_i.
        for sh in &shares {
            assert_eq!(sh.parts.len(), 2);
        }
        // Any 2 players reconstruct.
        for &(i, j) in &[(0usize, 1usize), (0, 2), (1, 2)] {
            let pair = vec![shares[i].clone(), shares[j].clone()];
            assert_eq!(reconstruct(&f, &s, &pair), Some(secret.clone()));
        }
        // Single player cannot.
        for sh in &shares {
            let solo = vec![sh.clone()];
            assert!(reconstruct(&f, &s, &solo).is_none());
        }
    }

    #[test]
    fn explicit_non_threshold_structure() {
        // 4 parties; access structure: {1, 2} OR {3, 4} OR {1, 3} qualify.
        // Maximal forbidden coalitions: every coalition that doesn't
        // include any of those minimal qualified pairs.
        // Minimal qualifies: {1,2}, {3,4}, {1,3}.
        // Forbidden are subsets of {1..4} not containing any of them.
        // Let's enumerate maximal forbidden by hand:
        //   - {2, 4}: doesn't contain {1,2} (no 1), {3,4} (no 3), {1,3} (no 1 or 3). Forbidden.
        //   - {1, 4}: doesn't contain {1,2} (no 2), {3,4} (no 3), {1,3} (no 3). Forbidden.
        //   - {2, 3}: doesn't contain {1,2} (no 1), {3,4} (no 4), {1,3} (no 1). Forbidden.
        // So maximal forbidden ⊇ {{1,4}, {2,3}, {2,4}}. Any 3-element set
        // contains at least one of {1,2}, {3,4}, {1,3}? Check {1,2,4}:
        //   contains {1,2} ⇒ qualified. Check {1,3,4}: contains {1,3} ⇒
        //   qualified. Check {2,3,4}: contains {3,4} ⇒ qualified. So all
        //   3-element supersets are qualified ⇒ {1,4}, {2,3}, {2,4} are
        //   indeed maximal.
        let f = small();
        let mut r = rng();
        let structure = AccessStructure::new(
            4,
            vec![vec![1, 4], vec![2, 3], vec![2, 4]],
        )
        .unwrap();
        assert!(structure.qualifies(&[1, 2]));
        assert!(structure.qualifies(&[3, 4]));
        assert!(structure.qualifies(&[1, 3]));
        assert!(!structure.qualifies(&[1, 4]));
        assert!(!structure.qualifies(&[2, 3]));
        assert!(!structure.qualifies(&[2, 4]));

        let secret = BigUint::from_u64(0xC0DE);
        let shares = split(&f, &mut r, &secret, &structure);

        // Each minimal qualified pair recovers the secret.
        for &(i, j) in &[(0usize, 1usize), (2, 3), (0, 2)] {
            let pair = vec![shares[i].clone(), shares[j].clone()];
            assert_eq!(reconstruct(&f, &structure, &pair), Some(secret.clone()));
        }
        // Any forbidden pair fails.
        for &(i, j) in &[(0usize, 3usize), (1, 2), (1, 3)] {
            let pair = vec![shares[i].clone(), shares[j].clone()];
            assert!(reconstruct(&f, &structure, &pair).is_none());
        }
    }

    #[test]
    fn rejects_subset_in_maximality_check() {
        // {1, 2} ⊂ {1, 2, 3} so they cannot both be maximal.
        let res = AccessStructure::new(4, vec![vec![1, 2], vec![1, 2, 3]]);
        assert!(res.is_none());
    }

    #[test]
    fn rejects_full_party_set() {
        let res = AccessStructure::new(3, vec![vec![1, 2, 3]]);
        assert!(res.is_none());
    }

    #[test]
    fn rejects_out_of_range_player() {
        let res = AccessStructure::new(3, vec![vec![0, 1]]);
        assert!(res.is_none());
        let res = AccessStructure::new(3, vec![vec![1, 4]]);
        assert!(res.is_none());
    }

    #[test]
    fn tampered_subshare_with_overlap_is_rejected() {
        // Tampering is only detectable when two players in the
        // coalition both hold the same r_i. For (2, 3) thresholds the
        // full coalition {1, 2, 3} provides that overlap on every r_i,
        // so any single-share tamper is caught.
        let f = small();
        let mut r = rng();
        let s = threshold_access_structure(3, 2);
        let secret = BigUint::from_u64(99);
        let mut shares = split(&f, &mut r, &secret, &s);
        // Tamper with player 1's first sub-share. Player 1's parts cover
        // every F_i not containing 1; for (2,3) those are F_1={2} and
        // F_2={3}, both of which are also held by another player in the
        // full coalition.
        shares[0].parts[0].1 = f.add(&shares[0].parts[0].1, &BigUint::from_u64(1));
        let coalition = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        assert!(reconstruct(&f, &s, &coalition).is_none());
    }

    #[test]
    fn single_source_tamper_in_minimal_coalition_undetectable() {
        // Documented limitation: ISN is not error-correcting. With a
        // minimal qualified coalition each r_i is held by exactly one
        // player, so a tamper has no redundancy to expose it. The
        // recovered "secret" will differ from the original; the function
        // returns Some(garbage) rather than None.
        let f = small();
        let mut r = rng();
        let s = threshold_access_structure(3, 2);
        let secret = BigUint::from_u64(99);
        let mut shares = split(&f, &mut r, &secret, &s);
        shares[0].parts[0].1 = f.add(&shares[0].parts[0].1, &BigUint::from_u64(1));
        let pair = vec![shares[0].clone(), shares[1].clone()];
        let got = reconstruct(&f, &s, &pair).expect("reconstruction succeeds without overlap");
        assert_ne!(got, secret);
    }

    #[test]
    fn duplicate_player_rejected() {
        let f = small();
        let mut r = rng();
        let s = threshold_access_structure(3, 2);
        let secret = BigUint::from_u64(7);
        let shares = split(&f, &mut r, &secret, &s);
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&f, &s, &dup).is_none());
    }

    #[test]
    fn fabricated_part_for_player_in_forbidden_set_rejected() {
        // Player 1 should not hold r_0 if F_0 = {1}. Construct a
        // PlayerShare where player 1 dishonestly claims to hold r_0 for
        // F_0 = {1}.
        let f = small();
        let mut r = rng();
        let s = threshold_access_structure(3, 2);
        let secret = BigUint::from_u64(1);
        let shares = split(&f, &mut r, &secret, &s);
        let mut bad = shares[0].clone();
        // Find any forbidden coalition that contains player 1 and inject.
        let i_bad = (0..s.t())
            .find(|&i| s.forbidden[i].contains(&1))
            .expect("player 1 is in some F_i");
        bad.parts.push((i_bad, BigUint::from_u64(0)));
        let pair = vec![bad, shares[1].clone()];
        assert!(reconstruct(&f, &s, &pair).is_none());
    }
}
