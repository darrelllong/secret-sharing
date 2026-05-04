//! Brickell 1989, *Some Ideal Secret Sharing Schemes* — vector-space
//! construction in which every player holds exactly one field element,
//! achieving the optimal share-size lower bound (the *ideal* property).
//!
//! Construction. The dealer publishes a target vector
//! `t ∈ GF(p)^m` (we canonicalise to `t = e_1`) and a per-player
//! vector `v_j ∈ GF(p)^m`. To share `s ∈ GF(p)`:
//!
//! 1. Pick a uniform random `u ∈ GF(p)^m` with `⟨u, t⟩ = s`. Equivalently
//!    `u_1 = s` and `u_2, …, u_m` uniform.
//! 2. Player `j` receives `share_j = ⟨v_j, u⟩`.
//!
//! A coalition `A` is qualified iff `t ∈ span{v_j : j ∈ A}`, in which
//! case there exist coefficients `c_j` such that `Σ c_j v_j = t`, and
//! the secret is recovered as `Σ c_j · share_j = ⟨t, u⟩ = s`.
//!
//! Relation to other schemes in this crate:
//!
//! - **Special case of `crate::karchmer_wigderson`** with one row per
//!   player. We delegate to `SpanProgram` internally rather than
//!   re-implement the linear algebra; this module is the ergonomic
//!   one-vector-per-player surface.
//! - **Generalises `crate::shamir`** by an explicit basis change: if
//!   `v_j = (1, j, j^2, …, j^{k-1})` you get the polynomial-evaluation
//!   form. Brickell's contribution was to identify *non-threshold*
//!   access structures admitting an ideal scheme — equivalently
//!   monotone access structures realised by some matroid.
//!
//! Per-player share is one field element regardless of `m`; this is
//! the *ideal* property that the paper's title advertises.

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::karchmer_wigderson::{self, SpanProgram};

/// A Brickell-style scheme: one vector `v_j ∈ GF(p)^m` per player.
#[derive(Clone, Debug)]
pub struct Scheme {
    inner: SpanProgram,
}

impl Scheme {
    /// Wrap per-player vectors into a Brickell scheme. Vectors are
    /// indexed by 1-based player ID — `vectors[j-1]` is `v_j`.
    ///
    /// # Panics
    /// - `vectors` is empty,
    /// - vectors have inconsistent lengths.
    #[must_use]
    pub fn new(field: PrimeField, vectors: Vec<Vec<BigUint>>) -> Self {
        assert!(!vectors.is_empty(), "need at least one player vector");
        let m = vectors[0].len();
        for v in &vectors {
            assert_eq!(v.len(), m, "all vectors must have the same length m");
        }
        let labels: Vec<usize> = (1..=vectors.len()).collect();
        Self {
            inner: SpanProgram::new(field, vectors, labels),
        }
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.inner.n()
    }

    #[must_use]
    pub fn m(&self) -> usize {
        self.inner.m()
    }

    #[must_use]
    pub fn field(&self) -> &PrimeField {
        self.inner.field()
    }

    #[must_use]
    pub fn qualifies(&self, coalition: &[usize]) -> bool {
        self.inner.qualifies(coalition)
    }
}

/// One trustee's piece: 1-based player ID + the inner-product value.
/// Per-player payload is one field element regardless of `m`.
#[derive(Clone, Eq, PartialEq)]
pub struct Share {
    pub player: usize,
    pub value: BigUint,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Secret-bearing: do not print field contents.
        f.write_str("Share(<elided>)")
    }
}

/// Distribute the secret across all `n` players. Returns one `Share`
/// per player.
///
/// # Panics
/// Panics if `secret >= p`.
#[must_use]
pub fn split<R: Csprng>(scheme: &Scheme, rng: &mut R, secret: &BigUint) -> Vec<Share> {
    // Re-use the MSP path. Each Brickell player has exactly one row,
    // so each `PlayerShare` returned by KW carries exactly one fragment.
    let inner_shares = karchmer_wigderson::split(&scheme.inner, rng, secret);
    inner_shares
        .into_iter()
        .map(|ps| {
            assert_eq!(
                ps.fragments.len(),
                1,
                "Brickell invariant: one row per player",
            );
            Share {
                player: ps.player,
                value: ps.fragments.into_iter().next().unwrap().1,
            }
        })
        .collect()
}

/// Recover the secret from a qualified coalition. Returns `None` if
/// the coalition is unqualified, contains duplicates, or names a
/// player out of range.
///
/// **Robustness limit.** Brickell allocates one fragment per player,
/// so reconstruction has no redundancy: a tampered `Share.value`
/// produces a wrong secret silently. Pair with `crate::vss` if
/// adversarial parties are in scope.
///
/// **Modular vs. integer span.** `qualifies` and `reconstruct` both
/// reason about linear independence *over the field* `GF(p)`, not over
/// `Q` or `Z`. User-supplied vectors whose intended access structure
/// is described in integer terms may admit chance modular dependencies
/// that turn an "unqualified" coalition into a qualified one over
/// `GF(p)`. Choose `p` large relative to the integer entries.
#[must_use]
pub fn reconstruct(scheme: &Scheme, shares: &[Share]) -> Option<BigUint> {
    // Translate back into MSP `PlayerShare` form. The row index for
    // player `p` is `p - 1` (we labelled them sequentially in `new`).
    let inner: Vec<karchmer_wigderson::PlayerShare> = shares
        .iter()
        .map(|s| {
            let row_idx = s.player.checked_sub(1)?;
            Some(karchmer_wigderson::PlayerShare {
                player: s.player,
                fragments: vec![(row_idx, s.value.clone())],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    karchmer_wigderson::reconstruct(&scheme.inner, &inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0xB7u8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    fn pick(shares: &[Share], wanted: &[usize]) -> Vec<Share> {
        shares
            .iter()
            .filter(|s| wanted.contains(&s.player))
            .cloned()
            .collect()
    }

    #[test]
    fn shamir_via_vandermonde_vectors() {
        // Brickell (k, n) over Vandermonde vectors v_j = (1, j, j^2, …, j^{k-1}).
        // Reconstruction is Lagrange interpolation in disguise.
        let f = small();
        let k = 3;
        let n = 5;
        let vectors: Vec<Vec<BigUint>> = (1..=n)
            .map(|j| {
                let mut row = Vec::with_capacity(k);
                let mut pow = BigUint::one();
                let j_val = BigUint::from_u64(j as u64);
                for _ in 0..k {
                    row.push(pow.clone());
                    pow = f.mul(&pow, &j_val);
                }
                row
            })
            .collect();
        let scheme = Scheme::new(f, vectors);
        let mut r = rng();
        let secret = BigUint::from_u64(0xCAFE);
        let shares = split(&scheme, &mut r, &secret);
        // Per-player share: one field element each.
        for s in &shares {
            let _ = s.value.clone();
        }
        // Any 3 reconstruct.
        for &(a, b, c) in &[(1usize, 2, 3), (1, 3, 5), (2, 4, 5)] {
            assert_eq!(
                reconstruct(&scheme, &pick(&shares, &[a, b, c])),
                Some(secret.clone()),
                "subset ({a},{b},{c})",
            );
        }
        // Two fail.
        for &(a, b) in &[(1usize, 2), (3, 5)] {
            assert!(reconstruct(&scheme, &pick(&shares, &[a, b])).is_none());
        }
    }

    #[test]
    fn non_threshold_ideal_structure() {
        // Brickell's flagship example: a non-threshold access
        // structure realised ideally. Vectors over GF(p)^2:
        //   v_1 = (1, 0)
        //   v_2 = (1, 1)
        //   v_3 = (1, 2)
        //   v_4 = (0, 1)
        // Target e_1 = (1, 0).
        //   {1}: v_1 = (1, 0) = e_1. Qualified.
        //   {2, 3}: span{(1,1), (1,2)} = GF(p)^2 ⊇ e_1. Qualified.
        //   {2}: span{(1,1)} ≠ e_1. Unqualified.
        //   {3}: span{(1,2)} ≠ e_1. Unqualified.
        //   {4}: span{(0,1)} ≠ e_1. Unqualified.
        //   {2, 4}: span{(1,1),(0,1)} = GF(p)^2 ⊇ e_1. Qualified.
        //   {3, 4}: span{(1,2),(0,1)} = GF(p)^2 ⊇ e_1. Qualified.
        let f = small();
        let v = vec![
            vec![BigUint::one(), BigUint::zero()],
            vec![BigUint::one(), BigUint::one()],
            vec![BigUint::one(), BigUint::from_u64(2)],
            vec![BigUint::zero(), BigUint::one()],
        ];
        let scheme = Scheme::new(f, v);

        for &q in &[
            &[1usize][..],
            &[2, 3],
            &[2, 4],
            &[3, 4],
            &[1, 2],
            &[1, 2, 3, 4],
        ] {
            assert!(scheme.qualifies(q), "{q:?} should qualify");
        }
        for &uq in &[&[2usize][..], &[3], &[4], &[]] {
            assert!(!scheme.qualifies(uq), "{uq:?} should NOT qualify");
        }

        let mut r = rng();
        let secret = BigUint::from_u64(33);
        let shares = split(&scheme, &mut r, &secret);
        // Solo recovery for player 1 (since v_1 = e_1).
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[1])), Some(secret.clone()));
        // {2, 3} also recovers.
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[2, 3])), Some(secret.clone()));
        // Unqualified {2} fails.
        assert!(reconstruct(&scheme, &pick(&shares, &[2])).is_none());
    }

    #[test]
    fn duplicate_player_rejected() {
        let f = small();
        let v: Vec<Vec<BigUint>> = (1..=3)
            .map(|j| vec![BigUint::one(), BigUint::from_u64(j as u64)])
            .collect();
        let scheme = Scheme::new(f, v);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&scheme, &mut r, &secret);
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&scheme, &dup).is_none());
    }

    #[test]
    fn duplicate_player_with_different_value_rejected() {
        // Adversarial twin: same player ID, different value. The
        // duplicate-player rejection must catch this even when the
        // values diverge (no equality short-circuit).
        let f = small();
        let v: Vec<Vec<BigUint>> = (1..=3)
            .map(|j| vec![BigUint::one(), BigUint::from_u64(j as u64)])
            .collect();
        let scheme = Scheme::new(f.clone(), v);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&scheme, &mut r, &secret);
        let mut twin = shares[0].clone();
        twin.value = f.add(&twin.value, &BigUint::from_u64(1));
        let bad = vec![shares[0].clone(), twin];
        assert!(reconstruct(&scheme, &bad).is_none());
    }

    #[test]
    fn out_of_range_player_rejected() {
        let f = small();
        let v: Vec<Vec<BigUint>> = (1..=2)
            .map(|j| vec![BigUint::one(), BigUint::from_u64(j as u64)])
            .collect();
        let scheme = Scheme::new(f, v);
        let bad = vec![
            Share {
                player: 0, // 0 is invalid (1-based)
                value: BigUint::one(),
            },
            Share {
                player: 1,
                value: BigUint::one(),
            },
        ];
        assert!(reconstruct(&scheme, &bad).is_none());
    }

    #[test]
    fn share_payload_is_one_field_element() {
        // The "ideal" claim in concrete form.
        let f = small();
        let m = 7; // arbitrary; ideal means per-share size is independent of m.
        let v: Vec<Vec<BigUint>> = (1..=4)
            .map(|j| {
                let mut row = vec![BigUint::zero(); m];
                row[0] = BigUint::one();
                row[1] = BigUint::from_u64(j as u64);
                row
            })
            .collect();
        let scheme = Scheme::new(f, v);
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = split(&scheme, &mut r, &secret);
        assert_eq!(shares.len(), 4);
        for s in &shares {
            // value is exactly one BigUint regardless of m.
            let _ = s.value.clone();
        }
    }
}
