//! Benaloh–Leichter 1988, *Generalized Secret Sharing and Monotone
//! Functions* — distribute a secret along a monotone Boolean formula.
//!
//! The access structure is given as a Boolean formula `T` over party
//! identifiers, built from leaves (atoms) and the connectives `AND`
//! and `OR`. Distribute walks `T` top-down:
//!
//! - At a **leaf** labelled with party `j`, hand `j` the current value.
//! - At an **AND** node with `m` children, additively split the current
//!   value into `m` random pieces summing to it (mod `p`), and recurse
//!   on each child with the corresponding piece.
//! - At an **OR** node with `m` children, recurse on each child with
//!   the same value.
//!
//! Reconstruction. A coalition `C` is qualified iff its leaves satisfy
//! `T` under the assignment "true ⇔ in `C`". Recovery walks `T`
//! bottom-up using only the share fragments held by `C`: an AND node
//! requires all children's recoveries to succeed (sum); an OR node
//! requires any one child's recovery to succeed.
//!
//! Each party may receive multiple share fragments — one per leaf in
//! `T` labelled with their identifier. A `ShareFragment::path` records
//! which leaf the fragment belongs to so reconstruction can match
//! fragments to subtrees.
//!
//! Compared with `crate::ito`. Ito–Saito–Nishizeki realises any
//! monotone access structure with cumulative arrays (per-player share
//! size = number of maximal forbidden coalitions). Benaloh–Leichter
//! often produces smaller shares for structures with succinct formula
//! representations — share size is the number of leaves labelled with
//! each player, which can be polynomial when the formula is.
//!
//! Robustness note. Benaloh–Leichter is *not* error-correcting. The OR
//! reconstructor returns the first child whose subtree recovers, with
//! no cross-check against other children — so a tampered first branch
//! silently yields the wrong value. We do detect direct contradictions
//! (two parties claiming the same `path` with different values) and
//! reject those, but corruption inside an AND-subtree of an OR-branch
//! is intentionally not noticed. Use `crate::vss` when adversarial
//! parties are in scope.

use crate::field::PrimeField;
use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::secure::ct_eq_biguint;

/// Monotone Boolean formula. Leaves are 1-based party identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Formula {
    /// A single-party atom: party `usize` is the trustee for this leaf.
    Party(usize),
    /// All children must reconstruct.
    And(Vec<Formula>),
    /// At least one child must reconstruct.
    Or(Vec<Formula>),
}

/// Convenience constructors so test callers read like the formula
/// notation in the paper.
impl Formula {
    #[must_use]
    pub fn party(j: usize) -> Self {
        Formula::Party(j)
    }
    #[must_use]
    pub fn and(children: Vec<Formula>) -> Self {
        Formula::And(children)
    }
    #[must_use]
    pub fn or(children: Vec<Formula>) -> Self {
        Formula::Or(children)
    }
}

/// One leaf-bound piece of secret. `path` is the sequence of child
/// indices from the formula root down to the leaf — this lets the
/// reconstruction routine match a fragment to a specific leaf in `T`
/// without depending on player identifier alone.
#[derive(Clone, Eq, PartialEq)]
pub struct ShareFragment {
    pub path: Vec<u32>,
    pub value: BigUint,
}

impl core::fmt::Debug for ShareFragment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("ShareFragment(<elided>)")
    }
}

/// Everything one party receives: their identifier and the fragments
/// for every leaf labelled with that identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct PlayerShare {
    pub player: usize,
    pub fragments: Vec<ShareFragment>,
}

impl core::fmt::Debug for PlayerShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("PlayerShare(<elided>)")
    }
}

/// Distribute the secret along the formula, returning one
/// [`PlayerShare`] per party that appears at least once in `T`. Players
/// not mentioned in `T` get no fragments.
///
/// # Panics
/// Panics on a degenerate formula (empty AND or OR), or on a leaf with
/// player identifier 0 (we use 1-based identifiers throughout).
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    formula: &Formula,
) -> Vec<PlayerShare> {
    let mut out: Vec<(usize, ShareFragment)> = Vec::new();
    distribute(field, rng, formula, &field.reduce(secret), &mut Vec::new(), &mut out);
    // Group by player.
    let mut grouped: std::collections::BTreeMap<usize, Vec<ShareFragment>> =
        std::collections::BTreeMap::new();
    for (p, frag) in out {
        grouped.entry(p).or_default().push(frag);
    }
    grouped
        .into_iter()
        .map(|(player, fragments)| PlayerShare { player, fragments })
        .collect()
}

/// Walk `formula` along `path` (a sequence of child indices). Return
/// the party identifier at the leaf if the path resolves to one,
/// `None` if the path runs off the tree or terminates on an internal
/// node.
fn leaf_party_at_path(formula: &Formula, path: &[u32]) -> Option<usize> {
    let mut node = formula;
    for &step in path {
        match node {
            Formula::Party(_) => return None, // path overshoots the leaf
            Formula::And(children) | Formula::Or(children) => {
                node = children.get(step as usize)?;
            }
        }
    }
    match node {
        Formula::Party(p) => Some(*p),
        _ => None, // path stops on an internal node
    }
}

fn distribute<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    node: &Formula,
    value: &BigUint,
    path: &mut Vec<u32>,
    out: &mut Vec<(usize, ShareFragment)>,
) {
    match node {
        Formula::Party(j) => {
            assert!(*j != 0, "player identifiers are 1-based");
            out.push((
                *j,
                ShareFragment {
                    path: path.clone(),
                    value: value.clone(),
                },
            ));
        }
        Formula::And(children) => {
            assert!(!children.is_empty(), "AND node must have children");
            let m = children.len();
            let mut sum = BigUint::zero();
            let mut pieces: Vec<BigUint> = Vec::with_capacity(m);
            for _ in 0..(m - 1) {
                let v = field.random(rng);
                sum = field.add(&sum, &v);
                pieces.push(v);
            }
            pieces.push(field.sub(value, &sum));
            for (j, (child, piece)) in children.iter().zip(pieces.iter()).enumerate() {
                path.push(j as u32);
                distribute(field, rng, child, piece, path, out);
                path.pop();
            }
        }
        Formula::Or(children) => {
            assert!(!children.is_empty(), "OR node must have children");
            for (j, child) in children.iter().enumerate() {
                path.push(j as u32);
                distribute(field, rng, child, value, path, out);
                path.pop();
            }
        }
    }
}

/// Recover the secret from the supplied players' share fragments.
/// Returns `None` if the fragments do not cover any qualified coalition
/// of `formula` (i.e. no satisfying leaf assignment).
#[must_use]
pub fn reconstruct(
    field: &PrimeField,
    formula: &Formula,
    shares: &[PlayerShare],
) -> Option<BigUint> {
    // Reject duplicate player IDs and accumulate fragments by path. If
    // multiple fragments arrive for the same path (whether from the
    // same player or two different players claiming it), they must
    // agree exactly — disagreement is a tamper indicator and yields None.
    //
    // **Path-ownership check.** Every fragment a player submits must
    // correspond to a leaf in `formula` actually labelled with THAT
    // player. Without this check a malicious player can attach a
    // forged fragment for someone else's leaf path and influence the
    // OR/AND recovery — exactly the attack the previous test
    // `solo_forger_at_others_path_yields_wrong_value` documented.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].player == shares[j].player {
                return None;
            }
        }
    }
    for s in shares {
        for f in &s.fragments {
            match leaf_party_at_path(formula, &f.path) {
                Some(p) if p == s.player => {}
                _ => return None,
            }
        }
    }
    let mut by_path: std::collections::HashMap<Vec<u32>, BigUint> =
        std::collections::HashMap::new();
    for s in shares {
        for f in &s.fragments {
            if let Some(prev) = by_path.get(&f.path) {
                if !ct_eq_biguint(prev, &f.value) {
                    return None;
                }
            } else {
                by_path.insert(f.path.clone(), f.value.clone());
            }
        }
    }
    recover(field, formula, &mut Vec::new(), &by_path)
}

fn recover(
    field: &PrimeField,
    node: &Formula,
    path: &mut Vec<u32>,
    by_path: &std::collections::HashMap<Vec<u32>, BigUint>,
) -> Option<BigUint> {
    match node {
        Formula::Party(_) => by_path.get(path).cloned(),
        Formula::And(children) => {
            let mut sum = BigUint::zero();
            for (j, child) in children.iter().enumerate() {
                path.push(j as u32);
                let part = recover(field, child, path, by_path);
                path.pop();
                sum = field.add(&sum, &part?);
            }
            Some(sum)
        }
        Formula::Or(children) => {
            for (j, child) in children.iter().enumerate() {
                path.push(j as u32);
                let part = recover(field, child, path, by_path);
                path.pop();
                if let Some(v) = part {
                    return Some(v);
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x77u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64(65_537))
    }

    fn pick(shares: &[PlayerShare], players: &[usize]) -> Vec<PlayerShare> {
        shares
            .iter()
            .filter(|s| players.contains(&s.player))
            .cloned()
            .collect()
    }

    #[test]
    fn two_of_three_via_formula() {
        // T = (P1 AND P2) OR (P1 AND P3) OR (P2 AND P3).
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![
            Formula::and(vec![Formula::party(1), Formula::party(2)]),
            Formula::and(vec![Formula::party(1), Formula::party(3)]),
            Formula::and(vec![Formula::party(2), Formula::party(3)]),
        ]);
        let secret = BigUint::from_u64(0xBEEF);
        let shares = split(&f, &mut r, &secret, &formula);
        // Each player appears in two AND clauses → two fragments each.
        for s in &shares {
            assert_eq!(s.fragments.len(), 2, "player {} fragment count", s.player);
        }
        for &(a, b) in &[(1usize, 2usize), (1, 3), (2, 3)] {
            let coalition = pick(&shares, &[a, b]);
            assert_eq!(
                reconstruct(&f, &formula, &coalition),
                Some(secret.clone()),
                "qualified pair ({a},{b})"
            );
        }
        // Singletons fail.
        for j in 1..=3 {
            let solo = pick(&shares, &[j]);
            assert!(reconstruct(&f, &formula, &solo).is_none(), "singleton {j}");
        }
    }

    #[test]
    fn nested_formula() {
        // T = P1 AND (P2 OR (P3 AND P4)). Qualifying coalitions:
        // {1,2}, {1,3,4}, {1,2,3}, {1,2,4}, {1,2,3,4}, {1,3,4}.
        let f = small();
        let mut r = rng();
        let formula = Formula::and(vec![
            Formula::party(1),
            Formula::or(vec![
                Formula::party(2),
                Formula::and(vec![Formula::party(3), Formula::party(4)]),
            ]),
        ]);
        let secret = BigUint::from_u64(0xC0DE);
        let shares = split(&f, &mut r, &secret, &formula);

        // Qualifying.
        for q in &[vec![1, 2], vec![1, 3, 4], vec![1, 2, 3, 4]] {
            let c = pick(&shares, q);
            assert_eq!(reconstruct(&f, &formula, &c), Some(secret.clone()), "qualifies {q:?}");
        }
        // Forbidden.
        for q in &[vec![1usize], vec![2, 3, 4], vec![1, 3], vec![1, 4]] {
            let c = pick(&shares, q);
            assert!(reconstruct(&f, &formula, &c).is_none(), "forbidden {q:?}");
        }
    }

    #[test]
    fn or_root_replicates() {
        // T = P1 OR P2: each party alone reconstructs.
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![Formula::party(1), Formula::party(2)]);
        let secret = BigUint::from_u64(7);
        let shares = split(&f, &mut r, &secret, &formula);
        // Each player has one fragment (one leaf each).
        for s in &shares {
            assert_eq!(s.fragments.len(), 1);
            assert_eq!(s.fragments[0].value, secret);
        }
        let solo = pick(&shares, &[1]);
        assert_eq!(reconstruct(&f, &formula, &solo), Some(secret));
    }

    #[test]
    fn and_root_requires_all() {
        // T = P1 AND P2 AND P3: only the full coalition reconstructs.
        let f = small();
        let mut r = rng();
        let formula = Formula::and(vec![
            Formula::party(1),
            Formula::party(2),
            Formula::party(3),
        ]);
        let secret = BigUint::from_u64(0x1234);
        let shares = split(&f, &mut r, &secret, &formula);
        for s in &shares {
            assert_eq!(s.fragments.len(), 1);
        }
        // Sum of all three pieces equals the secret.
        let sum = shares
            .iter()
            .map(|s| s.fragments[0].value.clone())
            .fold(BigUint::zero(), |a, b| f.add(&a, &b));
        assert_eq!(sum, secret);
        // Full coalition recovers.
        assert_eq!(reconstruct(&f, &formula, &shares), Some(secret));
        // Any 2 fail.
        for &(a, b) in &[(1usize, 2usize), (1, 3), (2, 3)] {
            let pair = pick(&shares, &[a, b]);
            assert!(reconstruct(&f, &formula, &pair).is_none());
        }
    }

    #[test]
    fn duplicate_player_rejected() {
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![
            Formula::and(vec![Formula::party(1), Formula::party(2)]),
            Formula::and(vec![Formula::party(1), Formula::party(3)]),
        ]);
        let secret = BigUint::from_u64(99);
        let shares = split(&f, &mut r, &secret, &formula);
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&f, &formula, &dup).is_none());
    }

    #[test]
    fn or_tamper_returns_wrong_value_first_branch_wins() {
        // Documents the non-error-correcting property: the OR returns
        // the first child whose subtree recovers, with no cross-check.
        // If we tamper the first AND-branch, recovery succeeds (the AND
        // still sums) but the result is wrong. The second branch — which
        // would have produced the right answer — is never consulted.
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![
            Formula::and(vec![Formula::party(1), Formula::party(2)]),
            Formula::and(vec![Formula::party(1), Formula::party(3)]),
        ]);
        let secret = BigUint::from_u64(33);
        let mut shares = split(&f, &mut r, &secret, &formula);
        let p1 = shares.iter_mut().find(|s| s.player == 1).unwrap();
        // Find the fragment with the lexicographically smaller path —
        // that is the first OR-branch child, evaluated first by `recover`.
        p1.fragments.sort_by(|a, b| a.path.cmp(&b.path));
        p1.fragments[0].value = f.add(&p1.fragments[0].value, &BigUint::from_u64(1));
        let coalition = pick(&shares, &[1, 2, 3]);
        let got = reconstruct(&f, &formula, &coalition).expect("OR's first branch still 'recovers'");
        assert_ne!(got, secret);
    }

    #[test]
    fn solo_forger_at_others_path_is_rejected() {
        // PEER-REVIEW P1: a player attaching a fragment for a leaf
        // path labelled with a different player must be rejected.
        // `reconstruct` enforces path-ownership: every supplied
        // fragment's path must resolve to a leaf labelled with the
        // submitting player.
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![Formula::party(1), Formula::party(2)]);
        let secret = BigUint::from_u64(77);
        let shares = split(&f, &mut r, &secret, &formula);
        let p2_path = shares
            .iter()
            .find(|s| s.player == 2)
            .unwrap()
            .fragments[0]
            .path
            .clone();
        let mut p1 = shares.iter().find(|s| s.player == 1).unwrap().clone();
        // Forged fragment: player 1 claiming a leaf labelled with 2.
        p1.fragments.push(ShareFragment {
            path: p2_path,
            value: BigUint::from_u64(0xDEAD),
        });
        let coalition = vec![p1];
        assert!(reconstruct(&f, &formula, &coalition).is_none());
    }

    #[test]
    fn dishonest_replication_across_players_rejected() {
        // If two parties both claim the same `path` with different
        // values, that's a hard contradiction — treat as tamper.
        let f = small();
        let mut r = rng();
        let formula = Formula::or(vec![Formula::party(1), Formula::party(2)]);
        let secret = BigUint::from_u64(55);
        let shares = split(&f, &mut r, &secret, &formula);
        // Forge a fragment at player 2's leaf path with a wrong value
        // and attach it to player 1. (The genuine player 2 has the
        // correct value at that path.)
        let p2 = shares.iter().find(|s| s.player == 2).unwrap().clone();
        let mut p1 = shares.iter().find(|s| s.player == 1).unwrap().clone();
        p1.fragments.push(ShareFragment {
            path: p2.fragments[0].path.clone(),
            value: f.add(&p2.fragments[0].value, &BigUint::from_u64(1)),
        });
        let conflict = vec![p1, p2];
        assert!(reconstruct(&f, &formula, &conflict).is_none());
    }
}
