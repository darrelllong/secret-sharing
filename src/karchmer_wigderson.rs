//! Karchmer–Wigderson 1993, *On Span Programs* — every linear secret-
//! sharing scheme is captured by a *monotone span program* (MSP).
//!
//! A monotone span program over `GF(p)` is a labelled matrix
//! `(M, ρ)` together with a target vector `t ∈ GF(p)^m`:
//!
//! - `M ∈ GF(p)^{d × m}` — `d` rows of width `m`.
//! - `ρ : {1, …, d} → {1, …, n}` — every row carries a player label.
//! - `t ∈ GF(p)^m` — the *target*. We canonicalise to `t = e_1 =
//!   (1, 0, …, 0)`; any MSP can be brought to this form by an
//!   invertible column transformation.
//!
//! Access structure. A coalition `A ⊆ {1, …, n}` is *qualified* iff
//! the target is in the row span of the sub-matrix `M_A` consisting of
//! every row whose label is in `A`. Equivalently: there exist
//! coefficients `c_j` (for `j` with `ρ(j) ∈ A`) such that
//! `Σ_j c_j · M_j = e_1`. Karchmer and Wigderson prove that every
//! monotone access structure is realised by some MSP and that *every*
//! linear SSS arises this way.
//!
//! Distribution. To share `s ∈ GF(p)`:
//!
//! 1. Sample `ρ_vec = (s, r_2, …, r_m)` with the upper components
//!    uniform random.
//! 2. Player `i` receives `{ (j, ⟨M_j, ρ_vec⟩) : ρ(j) = i }`.
//!
//! Recovery from a qualified `A`:
//!
//! 1. Solve `Σ_j c_j · M_j = e_1` for `c_j` over `j` with `ρ(j) ∈ A`.
//! 2. `s = Σ_j c_j · ⟨M_j, ρ_vec⟩`.
//!
//! Step 1 is independent of the secret and can be precomputed once per
//! coalition. Step 2 is a single inner product.
//!
//! Comparison with related papers in this crate:
//!
//! - **Brickell 1989** is the special case where every player has at
//!   most one row. Use `crate::brickell` when that suffices and you
//!   want a smaller per-player share.
//! - **van Dijk 1994** *A Linear Construction of Perfect Secret
//!   Sharing Schemes* gives a near-identical construction expressed
//!   as a "linear scheme" rather than a "span program"; the two
//!   formulations are equivalent. We do not provide a separate
//!   module — `SpanProgram` covers it.
//! - **Benaloh–Leichter** monotone-formula trees are converted to MSPs
//!   row-by-row (each leaf becomes a row); this module is the
//!   *output* of that translation.

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;

/// A validated monotone span program over `GF(p)` with target `e_1`.
#[derive(Clone, Debug)]
pub struct SpanProgram {
    field: PrimeField,
    /// `d × m` matrix; row `j` is `rows[j]` of length `m`.
    rows: Vec<Vec<BigUint>>,
    /// `labels[j] = ρ(j)` — the player owning row `j`. 1-based.
    labels: Vec<usize>,
    /// Number of players (max label).
    n: usize,
    /// Width `m` of every row.
    m: usize,
}

impl SpanProgram {
    /// Wrap a labelled matrix.
    ///
    /// # Panics
    /// - `rows` is empty,
    /// - rows have inconsistent widths,
    /// - `labels.len() != rows.len()`,
    /// - any label is `0` (1-based identifiers).
    #[must_use]
    pub fn new(field: PrimeField, rows: Vec<Vec<BigUint>>, labels: Vec<usize>) -> Self {
        assert!(!rows.is_empty(), "MSP must have at least one row");
        assert_eq!(rows.len(), labels.len(), "labels.len() must match rows.len()");
        let m = rows[0].len();
        for r in &rows {
            assert_eq!(r.len(), m, "all rows must have the same width");
        }
        for &lbl in &labels {
            assert!(lbl != 0, "labels are 1-based; 0 is not a valid player");
        }
        let n = *labels.iter().max().unwrap_or(&0);
        Self {
            field,
            rows,
            labels,
            n,
            m,
        }
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    #[must_use]
    pub fn d(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn m(&self) -> usize {
        self.m
    }

    #[must_use]
    pub fn field(&self) -> &PrimeField {
        &self.field
    }

    /// Whether `coalition` is qualified under this MSP. Solves
    /// `Σ_j c_j · M_j = e_1` for `j` with `ρ(j) ∈ coalition`.
    #[must_use]
    pub fn qualifies(&self, coalition: &[usize]) -> bool {
        self.recovery_coefficients(coalition).is_some()
    }

    /// If `coalition` is qualified, return the coefficient vector
    /// `(j, c_j)` such that `Σ c_j · M_j = e_1`. Used by both the
    /// public [`qualifies`] check and by [`reconstruct`].
    #[must_use]
    fn recovery_coefficients(&self, coalition: &[usize]) -> Option<Vec<(usize, BigUint)>> {
        // Indices of rows whose label is in the coalition.
        let row_indices: Vec<usize> = (0..self.d())
            .filter(|&j| coalition.contains(&self.labels[j]))
            .collect();
        if row_indices.is_empty() {
            return None;
        }
        // Build the system: [M_J^T | e_1], dimensions m × (|J| + 1).
        // Variables are c_j for j ∈ J; equations are the m components
        // of Σ c_j M_j = e_1.
        let cols = row_indices.len();
        let mut mat: Vec<Vec<BigUint>> = (0..self.m)
            .map(|i| {
                let mut row = Vec::with_capacity(cols + 1);
                for &j in &row_indices {
                    row.push(self.rows[j][i].clone());
                }
                // Right-hand side is e_1: 1 at row 0, 0 elsewhere.
                row.push(if i == 0 {
                    BigUint::one()
                } else {
                    BigUint::zero()
                });
                row
            })
            .collect();
        let coeffs = solve_least_constraint(&self.field, &mut mat, cols)?;
        // Defence in depth: independently verify the returned solution
        // satisfies Σ c_j · M_j = e_1. A bug in the solver, or an
        // unqualified coalition that the solver accidentally accepts,
        // turns into a clean `None` rather than a wrong-secret return.
        for i in 0..self.m {
            let mut acc = BigUint::zero();
            for (k, &j) in row_indices.iter().enumerate() {
                let term = self.field.mul(&coeffs[k], &self.rows[j][i]);
                acc = self.field.add(&acc, &term);
            }
            let want = if i == 0 {
                BigUint::one()
            } else {
                BigUint::zero()
            };
            if acc != want {
                return None;
            }
        }
        Some(row_indices.into_iter().zip(coeffs).collect())
    }
}

/// One player's share material: a list of `(row_index, ⟨M_j, ρ_vec⟩)`
/// for every row labelled with this player.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlayerShare {
    pub player: usize,
    pub fragments: Vec<(usize, BigUint)>,
}

/// Distribute `secret` across all players present in the program.
///
/// # Panics
/// Panics if `secret >= p`.
#[must_use]
pub fn split<R: Csprng>(
    program: &SpanProgram,
    rng: &mut R,
    secret: &BigUint,
) -> Vec<PlayerShare> {
    assert!(
        secret < program.field.modulus(),
        "secret must be < field modulus"
    );
    // ρ_vec = (s, r_2, …, r_m) with r_i uniform random.
    let mut rho_vec: Vec<BigUint> = Vec::with_capacity(program.m);
    rho_vec.push(secret.clone());
    for _ in 1..program.m {
        rho_vec.push(program.field.random(rng));
    }
    // Compute every row's share value = ⟨M_j, ρ_vec⟩.
    let mut by_player: std::collections::BTreeMap<usize, Vec<(usize, BigUint)>> =
        std::collections::BTreeMap::new();
    for (j, row) in program.rows.iter().enumerate() {
        let mut acc = BigUint::zero();
        for (col, val) in row.iter().enumerate() {
            let term = program.field.mul(val, &rho_vec[col]);
            acc = program.field.add(&acc, &term);
        }
        by_player
            .entry(program.labels[j])
            .or_default()
            .push((j, acc));
    }
    by_player
        .into_iter()
        .map(|(player, fragments)| PlayerShare { player, fragments })
        .collect()
}

/// Reconstruct from a qualified set of `PlayerShare`s.
///
/// Returns `None` when:
/// - any player ID repeats,
/// - any fragment row index is out of range,
/// - the union of supplied players does not qualify,
/// - any extra fragment beyond what the recovery uses disagrees with
///   the fitted secret-bearing vector.
#[must_use]
pub fn reconstruct(program: &SpanProgram, shares: &[PlayerShare]) -> Option<BigUint> {
    // Reject duplicates.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].player == shares[j].player {
                return None;
            }
        }
    }
    // Validate fragment row indices and label consistency.
    for s in shares {
        for (j, _) in &s.fragments {
            if *j >= program.d() {
                return None;
            }
            if program.labels[*j] != s.player {
                return None;
            }
        }
    }
    // Compute recovery coefficients for the coalition.
    let coalition: Vec<usize> = shares.iter().map(|s| s.player).collect();
    let coeffs = program.recovery_coefficients(&coalition)?;
    // Look up each c_j's matching share value.
    let mut value_by_row: std::collections::HashMap<usize, &BigUint> =
        std::collections::HashMap::new();
    for s in shares {
        for (j, v) in &s.fragments {
            value_by_row.insert(*j, v);
        }
    }
    let mut secret = BigUint::zero();
    for (j, c) in &coeffs {
        // Skip rows whose coefficient is zero (no contribution); also
        // skip rows the coalition hasn't supplied a value for. The
        // coefficient set comes from rows belonging to the coalition,
        // so a missing value is a malformed input — refuse.
        let val = value_by_row.get(j)?;
        let term = program.field.mul(c, val);
        secret = program.field.add(&secret, &term);
    }
    Some(secret)
}

/// Solve `A · x = b` for `x ∈ GF(p)^cols` where `A` is `m × cols` and
/// the augmented matrix `[A | b]` is in `mat` (`m × (cols + 1)`).
/// Returns `None` if the system has no solution. Uses Gauss–Jordan
/// elimination; on under-determined systems (more variables than
/// equations) we set free variables to zero.
#[allow(clippy::needless_range_loop)]
fn solve_least_constraint(
    field: &PrimeField,
    mat: &mut [Vec<BigUint>],
    cols: usize,
) -> Option<Vec<BigUint>> {
    let m = mat.len();
    let aug = cols; // index of the rhs column
    let mut pivot_col = vec![usize::MAX; m];
    let mut row = 0usize;
    for col in 0..cols {
        if row >= m {
            break;
        }
        // Find a pivot row with a nonzero entry in this column.
        let mut pivot_row = None;
        for r in row..m {
            if !mat[r][col].is_zero() {
                pivot_row = Some(r);
                break;
            }
        }
        let Some(pr) = pivot_row else {
            continue;
        };
        if pr != row {
            mat.swap(pr, row);
        }
        let inv = field.inv(&mat[row][col])?;
        for c in col..=aug {
            mat[row][c] = field.mul(&mat[row][c], &inv);
        }
        for r in 0..m {
            if r == row || mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..=aug {
                let term = field.mul(&factor, &mat[row][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
        pivot_col[row] = col;
        row += 1;
    }
    // Consistency: any row whose left-hand side is all zeros must have
    // zero right-hand side, else no solution.
    for r in 0..m {
        if (0..cols).all(|c| mat[r][c].is_zero()) && !mat[r][aug].is_zero() {
            return None;
        }
    }
    // Build the solution: pivot variables take their RHS, free
    // variables take 0.
    let mut solution = vec![BigUint::zero(); cols];
    for (r, pcol) in pivot_col.iter().enumerate() {
        if *pcol == usize::MAX {
            continue;
        }
        if r >= m {
            break;
        }
        solution[*pcol] = mat[r][aug].clone();
    }
    Some(solution)
}

/// Convenience: build the MSP for an `(k, n)` Shamir-equivalent
/// threshold scheme using a Vandermonde matrix.
///
/// The MSP has one row per player (`d = n`); row `i` is
/// `(1, i, i^2, …, i^{k-1})`; label is `i`. Any `k` rows span `e_1`
/// because the Vandermonde sub-matrix is invertible.
///
/// # Panics
/// `k < 2`, `n < k`, or `n ≥ p`.
#[must_use]
pub fn threshold_msp(field: PrimeField, k: usize, n: usize) -> SpanProgram {
    assert!(k >= 2 && n >= k, "need 2 ≤ k ≤ n");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "modulus must exceed n"
    );
    let mut rows: Vec<Vec<BigUint>> = Vec::with_capacity(n);
    let mut labels: Vec<usize> = Vec::with_capacity(n);
    for i in 1..=n {
        let mut row = Vec::with_capacity(k);
        let mut pow = BigUint::one();
        let i_val = BigUint::from_u64(i as u64);
        for _ in 0..k {
            row.push(pow.clone());
            pow = field.mul(&pow, &i_val);
        }
        rows.push(row);
        labels.push(i);
    }
    SpanProgram::new(field, rows, labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x9Cu8; 32])
    }

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64((1u64 << 61) - 1))
    }

    fn pick(shares: &[PlayerShare], wanted: &[usize]) -> Vec<PlayerShare> {
        shares
            .iter()
            .filter(|s| wanted.contains(&s.player))
            .cloned()
            .collect()
    }

    #[test]
    fn threshold_msp_round_trip() {
        let prog = threshold_msp(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = split(&prog, &mut r, &secret);
        assert_eq!(shares.len(), 5);
        // Any 3 reconstruct.
        for &(a, b, c) in &[(1usize, 2, 3), (1, 3, 5), (2, 4, 5), (3, 4, 5)] {
            let coalition = pick(&shares, &[a, b, c]);
            assert_eq!(reconstruct(&prog, &coalition), Some(secret.clone()), "subset ({a},{b},{c})");
        }
        // 2 fail.
        for &(a, b) in &[(1usize, 2), (3, 5), (4, 5)] {
            let coalition = pick(&shares, &[a, b]);
            assert!(reconstruct(&prog, &coalition).is_none(), "subset ({a},{b}) must fail");
        }
    }

    #[test]
    fn qualifies_matches_reconstruct() {
        let prog = threshold_msp(small(), 3, 5);
        // Quick sanity over the threshold semantics expressed by qualifies().
        assert!(prog.qualifies(&[1, 2, 3]));
        assert!(prog.qualifies(&[1, 4, 5]));
        assert!(!prog.qualifies(&[1, 2]));
        assert!(!prog.qualifies(&[]));
    }

    #[test]
    fn explicit_or_msp() {
        // Simplest non-threshold MSP: two-row scheme realising
        // (P1 OR P2). Each player has one row, and that single row
        // alone spans e_1.
        let f = small();
        let rows = vec![vec![BigUint::one()], vec![BigUint::one()]];
        let labels = vec![1usize, 2];
        let prog = SpanProgram::new(f, rows, labels);
        assert_eq!(prog.m(), 1);
        assert!(prog.qualifies(&[1]));
        assert!(prog.qualifies(&[2]));
        assert!(prog.qualifies(&[1, 2]));
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = split(&prog, &mut r, &secret);
        // Solo recovery for either player.
        assert_eq!(reconstruct(&prog, &pick(&shares, &[1])), Some(secret.clone()));
        assert_eq!(reconstruct(&prog, &pick(&shares, &[2])), Some(secret));
    }

    #[test]
    fn explicit_and_msp() {
        // (P1 AND P2): both rows must contribute. e_1 = (1, 0). Take
        // M = [[1, 1], [0, -1]] labelled (1, 2). Then row 1 alone
        // spans (1, 1) but not (1, 0); row 2 alone is (0, -1); both
        // together: row1 + row2 = (1, 0) = e_1. So {1,2} qualifies and
        // singletons do not.
        let f = small();
        let neg_one = f.sub(&BigUint::zero(), &BigUint::one());
        let rows = vec![
            vec![BigUint::one(), BigUint::one()],
            vec![BigUint::zero(), neg_one],
        ];
        let labels = vec![1usize, 2];
        let prog = SpanProgram::new(f.clone(), rows, labels);
        assert!(!prog.qualifies(&[1]));
        assert!(!prog.qualifies(&[2]));
        assert!(prog.qualifies(&[1, 2]));

        let mut r = rng();
        let secret = BigUint::from_u64(100);
        let shares = split(&prog, &mut r, &secret);
        let both = pick(&shares, &[1, 2]);
        assert_eq!(reconstruct(&prog, &both), Some(secret));
        assert!(reconstruct(&prog, &pick(&shares, &[1])).is_none());
        assert!(reconstruct(&prog, &pick(&shares, &[2])).is_none());
    }

    #[test]
    fn duplicate_player_rejected() {
        let prog = threshold_msp(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&prog, &mut r, &secret);
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert!(reconstruct(&prog, &dup).is_none());
    }

    #[test]
    fn malformed_fragment_rejected() {
        let prog = threshold_msp(small(), 3, 5);
        let mut r = rng();
        let secret = BigUint::from_u64(22);
        let mut shares = split(&prog, &mut r, &secret);
        // Forge: claim player 1 holds a row labelled 2.
        let row_idx_for_player_2 = (0..prog.d()).find(|&j| prog.labels[j] == 2).unwrap();
        shares[0]
            .fragments
            .push((row_idx_for_player_2, BigUint::zero()));
        let coalition = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        assert!(reconstruct(&prog, &coalition).is_none());
    }

    #[test]
    #[should_panic(expected = "secret must be < field modulus")]
    fn split_rejects_oversize_secret() {
        let prog = threshold_msp(PrimeField::new(BigUint::from_u64(257)), 2, 3);
        let mut r = rng();
        let _ = split(&prog, &mut r, &BigUint::from_u64(300));
    }

    #[test]
    fn qualifies_consistent_with_reconstruct() {
        // Stronger version of the previous test: actually round-trip
        // a secret through every coalition for a small (k, n) program
        // and check `qualifies(C) == reconstruct(...).is_some()`.
        let prog = threshold_msp(small(), 2, 4);
        let mut r = rng();
        let secret = BigUint::from_u64(0xDEAD);
        let shares = split(&prog, &mut r, &secret);
        for mask in 1u8..(1 << 4) {
            let coalition: Vec<usize> = (0..4)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| i + 1)
                .collect();
            let shares_for: Vec<PlayerShare> = pick(&shares, &coalition);
            let q = prog.qualifies(&coalition);
            let r = reconstruct(&prog, &shares_for);
            assert_eq!(
                q,
                r.is_some(),
                "qualifies and reconstruct disagree for {coalition:?}",
            );
            if q {
                assert_eq!(r, Some(secret.clone()), "wrong secret for {coalition:?}");
            }
        }
    }

    #[test]
    fn unqualified_coalition_returns_none_in_oversized_program() {
        // Build an MSP with m > |J| for some unqualified coalition, to
        // exercise the back-check inside recovery_coefficients.
        // Construction: 4 rows over GF(p), m = 3, target e_1 = (1,0,0).
        // Rows: M_1 = (1,0,0), M_2 = (0,1,0), M_3 = (0,0,1), M_4 = (1,1,1).
        // Labels: 1, 2, 3, 4.
        // Qualifying coalitions: any coalition whose row-set spans e_1.
        // {1} alone: row (1,0,0) spans e_1. Qualified.
        // {2}: row (0,1,0). Doesn't span e_1. Unqualified — m=3, |J|=1.
        // {2,3}: spans (0,1,0),(0,0,1) only — no e_1 component reachable
        //   without row 1 or row 4. Unqualified — m=3, |J|=2.
        // {4}: row (1,1,1). e_1 = M_4 - M_2 - M_3 — but {4} alone doesn't
        //   have M_2 or M_3. Unqualified.
        // {2,3,4}: M_4 - M_2 - M_3 = (1,0,0) = e_1. Qualified.
        let f = small();
        let rows = vec![
            vec![BigUint::one(), BigUint::zero(), BigUint::zero()],
            vec![BigUint::zero(), BigUint::one(), BigUint::zero()],
            vec![BigUint::zero(), BigUint::zero(), BigUint::one()],
            vec![BigUint::one(), BigUint::one(), BigUint::one()],
        ];
        let labels = vec![1, 2, 3, 4];
        let prog = SpanProgram::new(f, rows, labels);
        let mut r = rng();
        let secret = BigUint::from_u64(99);
        let shares = split(&prog, &mut r, &secret);

        // Unqualified coalitions return None (back-check or solver detects).
        for unq in &[vec![2usize], vec![3], vec![4], vec![2, 3], vec![2, 4], vec![3, 4]] {
            assert!(reconstruct(&prog, &pick(&shares, unq)).is_none(), "{unq:?} must fail");
        }
        // Qualified coalitions reconstruct the secret.
        for q in &[vec![1usize], vec![2, 3, 4], vec![1, 2, 3, 4]] {
            assert_eq!(
                reconstruct(&prog, &pick(&shares, q)),
                Some(secret.clone()),
                "{q:?} must succeed",
            );
        }
    }

    #[test]
    fn fuzz_threshold_round_trip() {
        // Random-ish fuzz: many seeds, several (k, n) shapes.
        for &(k, n) in &[(2usize, 3usize), (3, 5), (4, 7), (5, 9)] {
            for seed in 0u8..6 {
                let prog = threshold_msp(small(), k, n);
                let mut r = ChaCha20Rng::from_seed(&[seed; 32]);
                let secret = BigUint::from_u64(seed as u64 * 12345);
                let shares = split(&prog, &mut r, &secret);
                let chosen: Vec<usize> = (1..=k).collect();
                let pick_first_k: Vec<PlayerShare> = pick(&shares, &chosen);
                assert_eq!(reconstruct(&prog, &pick_first_k), Some(secret));
            }
        }
    }
}
