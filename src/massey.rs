//! Massey 1993, *Minimal Codewords and Secret Sharing* — a linear-code
//! framing of the Karchmer–Wigderson / Brickell construction.
//!
//! Setup. The dealer publishes a `k × (n + 1)` generator matrix `G`
//! over `GF(p)` of a linear code `C`. Column `0` is the *secret slot*;
//! columns `1, …, n` belong to players `1, …, n`.
//!
//! Distribution. Pick a random message `m ∈ GF(p)^k` such that the
//! resulting codeword `c = m · G` has `c_0 = s`. Player `j` receives
//! `c_j = ⟨m, G_{:, j}⟩`.
//!
//! Reconstruction. A coalition `A ⊆ {1, …, n}` is *qualified* iff the
//! secret column `G_{:, 0}` lies in the span of `{ G_{:, j} : j ∈ A }`.
//! Massey's theorem states that the minimal qualified sets correspond
//! to *minimal codewords of the dual code* `C^⊥` whose first coordinate
//! is nonzero — hence the title. Concretely we recover by solving
//! `Σ_{j ∈ A} α_j · G_{:, j} = G_{:, 0}` for `(α_j)`; if a solution
//! exists, `s = Σ_{j ∈ A} α_j · c_j`. Both steps are Gaussian
//! elimination.
//!
//! Relation to other schemes:
//!
//! - With `k = 2` and `G_{:, j} = (1, j)^T`, this reduces to a
//!   Reed–Solomon `(2, n)` Shamir scheme.
//! - More generally Massey's framework is equivalent to
//!   `crate::karchmer_wigderson` after a basis change carrying
//!   `G_{:, 0}` onto `e_1`. We do not delegate, so the column-zero
//!   semantics stay primary in the public API.

use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::field::PrimeField;
use crate::secure::ct_eq_biguint;

/// A Massey scheme: a `k × (n + 1)` generator matrix over `GF(p)`.
#[derive(Clone, Debug)]
pub struct CodeScheme {
    field: PrimeField,
    /// `k × (n + 1)` generator matrix in row-major form. `g[r][c]` is
    /// row `r`, column `c`. Column `0` is the secret column.
    g: Vec<Vec<BigUint>>,
    k: usize,
    n: usize,
}

impl CodeScheme {
    /// Wrap a generator matrix.
    ///
    /// # Panics
    /// - empty `g`,
    /// - inconsistent row widths,
    /// - column `0` is the all-zero vector (every codeword has
    ///   `c_0 = 0`, so the scheme cannot share an arbitrary secret —
    ///   we reject this configuration up front).
    #[must_use]
    pub fn new(field: PrimeField, g: Vec<Vec<BigUint>>) -> Self {
        assert!(!g.is_empty(), "generator matrix must have at least one row");
        let width = g[0].len();
        assert!(width >= 2, "matrix must have ≥ 2 columns (secret + at least one player)");
        for row in &g {
            assert_eq!(row.len(), width, "all rows must have equal length");
        }
        let k = g.len();
        let n = width - 1;
        // Reduce every entry modulo p so downstream comparisons and
        // inversions operate on canonical representatives. Without
        // this, a non-canonical matrix can pass `is_zero()` while
        // being a multiple of p (causing `field.inv` to panic in
        // `split`), or break the qualification check by comparing a
        // reduced accumulator against a raw entry.
        let g: Vec<Vec<BigUint>> = g
            .into_iter()
            .map(|row| row.into_iter().map(|x| field.reduce(&x)).collect())
            .collect();
        // Column 0 must have at least one nonzero entry — checked AFTER
        // reduction so `0 mod p` cannot sneak past as "raw nonzero".
        assert!(
            (0..k).any(|r| !g[r][0].is_zero()),
            "column 0 (secret column) must have a nonzero entry mod p",
        );
        Self { field, g, k, n }
    }

    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    #[must_use]
    pub fn field(&self) -> &PrimeField {
        &self.field
    }

    /// Whether `coalition` (players given as 1-based indices into the
    /// non-zero columns) is qualified — `G_{:, 0}` lies in the span of
    /// `{ G_{:, j} : j ∈ coalition }`.
    #[must_use]
    pub fn qualifies(&self, coalition: &[usize]) -> bool {
        self.recovery_coefficients(coalition).is_some()
    }

    /// Solve `Σ α_j G_{:, j} = G_{:, 0}` for `(α_j)` over `j ∈ coalition`.
    fn recovery_coefficients(&self, coalition: &[usize]) -> Option<Vec<(usize, BigUint)>> {
        // Validate column indices: each must be in 1..=n.
        for &j in coalition {
            if j == 0 || j > self.n {
                return None;
            }
        }
        // Build an augmented k × (|coalition| + 1) matrix where row r
        // is (G[r][j] for j in coalition, G[r][0]).
        let cols = coalition.len();
        if cols == 0 {
            return None;
        }
        let mut mat: Vec<Vec<BigUint>> = (0..self.k)
            .map(|r| {
                let mut row = Vec::with_capacity(cols + 1);
                for &j in coalition {
                    row.push(self.g[r][j].clone());
                }
                row.push(self.g[r][0].clone());
                row
            })
            .collect();
        let coeffs = solve(&self.field, &mut mat, cols)?;
        // Defence in depth: re-evaluate Σ α_j G[:, j] and compare with
        // G[:, 0]. If the solver returned a wrong solution we report
        // None instead of producing a bogus secret downstream.
        for r in 0..self.k {
            let mut acc = BigUint::zero();
            for (k, &j) in coalition.iter().enumerate() {
                let term = self.field.mul(&coeffs[k], &self.g[r][j]);
                acc = self.field.add(&acc, &term);
            }
            if !ct_eq_biguint(&acc, &self.g[r][0]) {
                return None;
            }
        }
        Some(coalition.iter().copied().zip(coeffs).collect())
    }
}

/// One trustee's share: 1-based column index and the codeword value at
/// that column.
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

/// Distribute the secret across all `n` players.
///
/// # Panics
/// Panics if `secret >= p`.
#[must_use]
pub fn split<R: Csprng>(scheme: &CodeScheme, rng: &mut R, secret: &BigUint) -> Vec<Share> {
    assert!(
        secret < scheme.field.modulus(),
        "secret must be < field modulus"
    );
    // Pick the message m ∈ GF(p)^k subject to the linear constraint
    // ⟨m, G[:, 0]⟩ = s. Find any row r* with G[r*][0] != 0 — guaranteed
    // by the constructor — set the other m_r uniform random, then
    // solve for m_{r*}.
    let r_star = (0..scheme.k)
        .find(|&r| !scheme.g[r][0].is_zero())
        .expect("constructor guarantees a nonzero entry in column 0");
    let mut m: Vec<BigUint> = vec![BigUint::zero(); scheme.k];
    let mut sum = BigUint::zero();
    #[allow(clippy::needless_range_loop)]
    for r in 0..scheme.k {
        if r == r_star {
            continue;
        }
        let v = scheme.field.random(rng);
        let term = scheme.field.mul(&v, &scheme.g[r][0]);
        sum = scheme.field.add(&sum, &term);
        m[r] = v;
    }
    // m[r_star] = (s - sum) / G[r_star][0]
    let diff = scheme.field.sub(secret, &sum);
    let inv = scheme
        .field
        .inv(&scheme.g[r_star][0])
        .expect("nonzero entry has an inverse in a prime field");
    m[r_star] = scheme.field.mul(&diff, &inv);

    (1..=scheme.n)
        .map(|j| {
            let mut acc = BigUint::zero();
            #[allow(clippy::needless_range_loop)]
            for r in 0..scheme.k {
                let term = scheme.field.mul(&m[r], &scheme.g[r][j]);
                acc = scheme.field.add(&acc, &term);
            }
            Share {
                player: j,
                value: acc,
            }
        })
        .collect()
}

/// Recover the secret from a qualified coalition. Returns `None` on
/// duplicates, out-of-range columns, or unqualified coalitions.
#[must_use]
pub fn reconstruct(scheme: &CodeScheme, shares: &[Share]) -> Option<BigUint> {
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].player == shares[j].player {
                return None;
            }
        }
    }
    let coalition: Vec<usize> = shares.iter().map(|s| s.player).collect();
    let coeffs = scheme.recovery_coefficients(&coalition)?;
    let mut value_by_player: std::collections::HashMap<usize, &BigUint> =
        std::collections::HashMap::new();
    for s in shares {
        value_by_player.insert(s.player, &s.value);
    }
    let mut secret = BigUint::zero();
    for (j, alpha) in &coeffs {
        let v = value_by_player.get(j)?;
        let term = scheme.field.mul(alpha, v);
        secret = scheme.field.add(&secret, &term);
    }
    Some(secret)
}

/// Solve `A · x = b` for `x ∈ GF(p)^cols` where the augmented matrix
/// `[A | b]` is in `mat` (`m × (cols + 1)`). Returns `None` if the
/// system has no solution. Free variables default to zero.
#[allow(clippy::needless_range_loop)]
fn solve(
    field: &PrimeField,
    mat: &mut [Vec<BigUint>],
    cols: usize,
) -> Option<Vec<BigUint>> {
    let m = mat.len();
    let aug = cols;
    let mut pivot_col = vec![usize::MAX; m];
    let mut row = 0usize;
    for col in 0..cols {
        if row >= m {
            break;
        }
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
    for r in 0..m {
        if (0..cols).all(|c| mat[r][c].is_zero()) && !mat[r][aug].is_zero() {
            return None;
        }
    }
    let mut sol = vec![BigUint::zero(); cols];
    for r in 0..m {
        if pivot_col[r] != usize::MAX {
            sol[pivot_col[r]] = mat[r][aug].clone();
        }
    }
    Some(sol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0xA5u8; 32])
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
    fn shamir_2_of_n_via_2_by_n_plus_1_generator() {
        // (2, 3) Shamir as Massey: G is 2 × 4 with column 0 the secret
        // slot, columns 1..3 the player slots. Choose
        //   G = [ 1 1 1 1
        //         0 1 2 3 ]
        // — column 0 = (1, 0)^T (the constant-term slot), column j > 0
        // = (1, j)^T (evaluations of the Shamir polynomial). Any 2
        // columns from {1, 2, 3} are linearly independent (Vandermonde
        // 2-minor), so any 2 players reconstruct.
        let f = small();
        let g = vec![
            vec![
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
            ],
            vec![
                BigUint::zero(),
                BigUint::one(),
                BigUint::from_u64(2),
                BigUint::from_u64(3),
            ],
        ];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::from_u64(0xC0FFEE);
        let shares = split(&scheme, &mut r, &secret);
        assert_eq!(shares.len(), 3);
        for &(a, b) in &[(1usize, 2usize), (1, 3), (2, 3)] {
            assert_eq!(
                reconstruct(&scheme, &pick(&shares, &[a, b])),
                Some(secret.clone()),
                "subset ({a},{b})",
            );
        }
        // Single-share fails.
        for j in 1..=3 {
            assert!(reconstruct(&scheme, &pick(&shares, &[j])).is_none());
        }
    }

    #[test]
    fn or_access_structure_via_repeated_column() {
        // n = 2 OR scheme via G = [1 1 1] (1-row code; secret column
        // and both player columns are the same). Either player alone
        // recovers because G[:, 1] = G[:, 0] = (1).
        let f = small();
        let g = vec![vec![BigUint::one(), BigUint::one(), BigUint::one()]];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::from_u64(7);
        let shares = split(&scheme, &mut r, &secret);
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[1])), Some(secret.clone()));
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[2])), Some(secret));
    }

    #[test]
    #[should_panic(expected = "column 0")]
    fn rejects_zero_secret_column() {
        // If column 0 is all zeros, c_0 ≡ 0 — the scheme cannot share
        // any nonzero secret. Reject up front.
        let f = small();
        let g = vec![
            vec![BigUint::zero(), BigUint::one(), BigUint::one()],
            vec![BigUint::zero(), BigUint::zero(), BigUint::one()],
        ];
        let _ = CodeScheme::new(f, g);
    }

    #[test]
    fn duplicate_player_rejected() {
        let f = small();
        let g = vec![
            vec![
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
            ],
            vec![
                BigUint::zero(),
                BigUint::one(),
                BigUint::from_u64(2),
                BigUint::from_u64(3),
            ],
        ];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::from_u64(11);
        let shares = split(&scheme, &mut r, &secret);
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&scheme, &dup).is_none());
    }

    #[test]
    fn out_of_range_player_rejected() {
        let f = small();
        let g = vec![
            vec![BigUint::one(), BigUint::one(), BigUint::one()],
            vec![BigUint::zero(), BigUint::one(), BigUint::from_u64(2)],
        ];
        let scheme = CodeScheme::new(f, g);
        let bad = vec![
            Share {
                player: 0,
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
    fn round_trip_with_secret_zero() {
        // AD test-coverage gap: the secret=0 path inside `split` is
        // exercised here.
        let f = small();
        let g = vec![
            vec![
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
            ],
            vec![
                BigUint::zero(),
                BigUint::one(),
                BigUint::from_u64(2),
                BigUint::from_u64(3),
            ],
        ];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::zero();
        let shares = split(&scheme, &mut r, &secret);
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[1, 2])), Some(secret));
    }

    #[test]
    fn r_star_in_middle_row_round_trip() {
        // AD test-coverage gap: previous tests all had a nonzero entry
        // in column 0 of row 0, so r_star = 0 always. Here row 0 of
        // column 0 is zero; the constructor finds r_star = 1.
        let f = small();
        let g = vec![
            vec![
                BigUint::zero(),
                BigUint::one(),
                BigUint::one(),
                BigUint::one(),
            ],
            vec![
                BigUint::one(),
                BigUint::one(),
                BigUint::from_u64(2),
                BigUint::from_u64(3),
            ],
        ];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::from_u64(0xBEEF);
        let shares = split(&scheme, &mut r, &secret);
        // Two columns that span column 0 = (0, 1)^T: any pair of
        // {1, 2, 3} works because rows are full rank.
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[1, 2])), Some(secret));
    }

    #[test]
    fn unqualified_coalition_returns_none() {
        // G is 3 × 5. Choose G so that columns {1, 2} alone do not
        // span column 0.
        //   col 0 = (1, 0, 0)
        //   col 1 = (0, 1, 0)
        //   col 2 = (0, 0, 1)
        //   col 3 = (1, 1, 0)  — col_3 = col_0 + col_1, so {1, 3}
        //                         qualifies but {1, 2} alone doesn't
        //                         (col_1+col_2 = (0,1,1), no col_0 in
        //                         their span).
        //   col 4 = (1, 0, 0)  — col_4 = col_0; {4} alone qualifies.
        let f = small();
        let g = vec![
            vec![
                BigUint::one(),
                BigUint::zero(),
                BigUint::zero(),
                BigUint::one(),
                BigUint::one(),
            ],
            vec![
                BigUint::zero(),
                BigUint::one(),
                BigUint::zero(),
                BigUint::one(),
                BigUint::zero(),
            ],
            vec![
                BigUint::zero(),
                BigUint::zero(),
                BigUint::one(),
                BigUint::zero(),
                BigUint::zero(),
            ],
        ];
        let scheme = CodeScheme::new(f, g);
        let mut r = rng();
        let secret = BigUint::from_u64(99);
        let shares = split(&scheme, &mut r, &secret);

        // {1, 2}: unqualified.
        assert!(reconstruct(&scheme, &pick(&shares, &[1, 2])).is_none());
        // {2, 3}: span{(0,1,0),(0,0,1)} = does not contain col 0 = (1,0,0). Unqualified.
        assert!(reconstruct(&scheme, &pick(&shares, &[2, 3])).is_none());
        // {1, 3}: col_3 - col_1 = (1, 0, 0) = col_0. Qualified.
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[1, 3])), Some(secret.clone()));
        // {4}: col_4 = col_0. Qualified solo.
        assert_eq!(reconstruct(&scheme, &pick(&shares, &[4])), Some(secret));
    }
}
