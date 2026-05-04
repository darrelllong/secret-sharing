//! Naor–Shamir 1994, *Visual Cryptography* — encrypt a black-and-white
//! image as `n` share images such that physically stacking *any* `k`
//! transparencies (bitwise OR) reveals the secret while fewer than `k`
//! reveal nothing.
//!
//! This module implements the canonical `(n, n)` construction (every
//! share is required) from Naor–Shamir §3, which is the cleanest
//! instance of their general `(k, n)` family. The `(2, 2)` case is the
//! widely-cited "two transparency" scheme; larger `n` follows the same
//! basis-matrix recipe.
//!
//! Construction. Each pixel of the secret expands to `m = 2^{n − 1}`
//! sub-pixels per share. Two `n × m` *basis matrices* are used:
//!
//! - `C_0` (white pixel): columns are indexed by *even*-cardinality
//!   subsets of `{1, …, n}`. Entry `(i, σ)` is `1` iff `i ∈ σ`.
//! - `C_1` (black pixel): columns are indexed by *odd*-cardinality
//!   subsets of `{1, …, n}`.
//!
//! For a white pixel the dealer applies a uniform random column
//! permutation `π` to `C_0` and hands row `i` to share `i`; for a black
//! pixel the same with `C_1`. The bitwise OR of all `n` rows of `C_0`
//! has Hamming weight `2^{n − 1} − 1` (one zero per row by parity);
//! the OR of all `n` rows of `C_1` has weight `2^{n − 1}` (no zeros) —
//! a one-sub-pixel contrast that the eye reads as "lighter" vs.
//! "darker." Below threshold the two OR distributions coincide.
//!
//! Per-pixel storage blow-up is `m = 2^{n − 1}`. For `n = 2`, `m = 2`
//! (the textbook example); for `n = 3`, `m = 4`; for `n = 4`, `m = 8`.
//! The construction exists for all `n ≥ 2` but the storage cost grows
//! exponentially — Naor–Shamir's paper trades it down for general
//! `(k, n)` schemes that we do not implement here.
//!
//! API. Images are `Vec<Vec<bool>>` of equal-length rows: `true` =
//! black pixel. A single secret pixel becomes a `1 × m` block in each
//! share; an `H × W` secret becomes an `H × (W · m)` share image.

use crate::csprng::Csprng;

/// Number of sub-pixels per secret pixel for an `(n, n)` scheme.
#[must_use]
pub fn pixel_expansion(n: usize) -> usize {
    assert!(n >= 2, "n must be at least 2");
    1usize << (n - 1)
}

/// Build the two basis matrices `C_0` (white) and `C_1` (black) for an
/// `(n, n)` scheme. Returns `(C0, C1)` where each is an `n × m` matrix
/// of booleans (`true` = black).
fn basis_matrices(n: usize) -> (Vec<Vec<bool>>, Vec<Vec<bool>>) {
    let m = pixel_expansion(n);
    // Enumerate every subset of {1..=n} via its bitmask (1 << (i-1)).
    // A subset's parity is the popcount of the bitmask.
    let mut even_subsets: Vec<u64> = Vec::new();
    let mut odd_subsets: Vec<u64> = Vec::new();
    for mask in 0..(1u64 << n) {
        if mask.count_ones() % 2 == 0 {
            even_subsets.push(mask);
        } else {
            odd_subsets.push(mask);
        }
    }
    debug_assert_eq!(even_subsets.len(), m);
    debug_assert_eq!(odd_subsets.len(), m);

    let mut c0: Vec<Vec<bool>> = vec![vec![false; m]; n];
    let mut c1: Vec<Vec<bool>> = vec![vec![false; m]; n];
    #[allow(clippy::needless_range_loop)]
    for (col, mask) in even_subsets.iter().enumerate() {
        for i in 0..n {
            c0[i][col] = mask & (1u64 << i) != 0;
        }
    }
    #[allow(clippy::needless_range_loop)]
    for (col, mask) in odd_subsets.iter().enumerate() {
        for i in 0..n {
            c1[i][col] = mask & (1u64 << i) != 0;
        }
    }
    (c0, c1)
}

/// Sample a uniformly random permutation of `[0, m)` using
/// Fisher–Yates with rejection-sampled indices.
fn random_permutation<R: Csprng>(rng: &mut R, m: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..m).collect();
    // Fisher–Yates from the back.
    for i in (1..m).rev() {
        let j = bounded_index(rng, i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Uniform integer in `[0, bound)` via rejection sampling on enough
/// random bytes to cover the next power of two ≥ bound.
fn bounded_index<R: Csprng>(rng: &mut R, bound: usize) -> usize {
    assert!(bound > 0);
    if bound == 1 {
        return 0;
    }
    let bits = (usize::BITS - (bound - 1).leading_zeros()) as usize; // ceil(log2(bound))
    let bytes = bits.div_ceil(8);
    let excess = bytes * 8 - bits;
    let top_mask: u8 = if excess == 0 { 0xFF } else { 0xFFu8 >> excess };
    let mut buf = vec![0u8; bytes];
    loop {
        rng.fill_bytes(&mut buf);
        buf[0] &= top_mask;
        let mut acc = 0usize;
        for &b in &buf {
            acc = (acc << 8) | (b as usize);
        }
        if acc < bound {
            return acc;
        }
    }
}

/// Encrypt `secret` (an `H × W` boolean image) into `n` share images
/// each of dimensions `H × (W · m)` where `m = 2^{n − 1}`.
///
/// # Panics
/// - `n < 2`,
/// - `secret` is empty,
/// - rows of `secret` have unequal lengths.
#[must_use]
pub fn split_n_of_n<R: Csprng>(
    rng: &mut R,
    secret: &[Vec<bool>],
    n: usize,
) -> Vec<Vec<Vec<bool>>> {
    assert!(n >= 2, "n must be at least 2");
    assert!(!secret.is_empty(), "secret image must not be empty");
    let h = secret.len();
    let w = secret[0].len();
    assert!(w > 0, "secret rows must be non-empty");
    for row in secret {
        assert_eq!(row.len(), w, "secret rows must be equal length");
    }
    let m = pixel_expansion(n);
    let (c0, c1) = basis_matrices(n);

    let mut shares: Vec<Vec<Vec<bool>>> = (0..n)
        .map(|_| (0..h).map(|_| Vec::with_capacity(w * m)).collect())
        .collect();

    #[allow(clippy::needless_range_loop)]
    for y in 0..h {
        for x in 0..w {
            let basis = if secret[y][x] { &c1 } else { &c0 };
            let perm = random_permutation(rng, m);
            for i in 0..n {
                for &col in &perm {
                    shares[i][y].push(basis[i][col]);
                }
            }
        }
    }

    shares
}

/// Stack `shares` by bitwise OR — the physical "place transparencies
/// on top of each other" operation. All shares must have identical
/// dimensions; returns `None` otherwise.
///
/// **Below-threshold caveat.** This function does NOT enforce that
/// the share count equals the `n` used at split. If you stack only
/// `n′ < n` shares of an `(n, n)` scheme and pass the result to
/// [`decode`] with the original `n`, every per-pixel block will have
/// Hamming weight `< m − 1` (or sometimes `m − 1` by chance), so
/// `decode` will refuse with `None` for the typical case and may
/// occasionally classify a white pixel correctly by coincidence —
/// either way the resulting image is not a faithful decode of the
/// secret. Callers are responsible for tracking how many shares were
/// stacked and only invoking `decode` when all `n` are present.
#[must_use]
pub fn stack(shares: &[Vec<Vec<bool>>]) -> Option<Vec<Vec<bool>>> {
    if shares.is_empty() {
        return None;
    }
    let h = shares[0].len();
    let w = if h > 0 { shares[0][0].len() } else { 0 };
    for s in shares {
        if s.len() != h {
            return None;
        }
        for row in s {
            if row.len() != w {
                return None;
            }
        }
    }
    let mut out = vec![vec![false; w]; h];
    for s in shares {
        for y in 0..h {
            for x in 0..w {
                out[y][x] |= s[y][x];
            }
        }
    }
    Some(out)
}

/// Decode a stacked image back to the secret resolution by reading the
/// per-pixel block of `m` sub-pixels: a fully-black block (Hamming
/// weight `m`) decodes to `true`; an all-but-one-black block (weight
/// `m − 1`) decodes to `false`. Returns `None` if any block has any
/// other Hamming weight (which means the input was not produced by
/// `(n, n)` stacking).
///
/// **Caller's responsibility:** `n` must match the value used when
/// `split_n_of_n` was called. The stacked image carries no metadata
/// recording its provenance, so passing the wrong `n` either fails the
/// `total_w.is_multiple_of(m)` check (loud) or — by chance — slips
/// through with a coincidentally-valid Hamming weight per
/// re-partitioned block (silent wrong decode). Persist `n` alongside
/// shares; do not infer it.
#[must_use]
pub fn decode(stacked: &[Vec<bool>], n: usize) -> Option<Vec<Vec<bool>>> {
    assert!(n >= 2, "n must be at least 2");
    let m = pixel_expansion(n);
    let h = stacked.len();
    if h == 0 {
        return Some(Vec::new());
    }
    let total_w = stacked[0].len();
    if !total_w.is_multiple_of(m) {
        return None;
    }
    let w = total_w / m;
    let mut out = vec![vec![false; w]; h];
    for y in 0..h {
        if stacked[y].len() != total_w {
            return None;
        }
        for x in 0..w {
            let block = &stacked[y][x * m..(x + 1) * m];
            let weight = block.iter().filter(|&&b| b).count();
            if weight == m {
                out[y][x] = true;
            } else if weight + 1 == m {
                out[y][x] = false;
            } else {
                return None;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[0x76u8; 32])
    }

    fn checker(h: usize, w: usize) -> Vec<Vec<bool>> {
        (0..h)
            .map(|y| (0..w).map(|x| (x + y) % 2 == 0).collect())
            .collect()
    }

    #[test]
    fn pixel_expansion_table() {
        assert_eq!(pixel_expansion(2), 2);
        assert_eq!(pixel_expansion(3), 4);
        assert_eq!(pixel_expansion(4), 8);
    }

    #[test]
    fn basis_matrices_have_expected_shape_n2() {
        let (c0, c1) = basis_matrices(2);
        // m = 2; even subsets: {} and {1,2}; odd: {1} and {2}.
        // C_0: row i indicates "is i in subset σ".
        //   col 0 (subset {}): both rows 0
        //   col 1 (subset {1,2}): both rows 1
        // C_1:
        //   col 0 (subset {1}): row 0 = 1, row 1 = 0
        //   col 1 (subset {2}): row 0 = 0, row 1 = 1
        assert_eq!(c0[0], vec![false, true]);
        assert_eq!(c0[1], vec![false, true]);
        assert_eq!(c1[0], vec![true, false]);
        assert_eq!(c1[1], vec![false, true]);
    }

    #[test]
    fn round_trip_2_of_2() {
        let mut r = rng();
        let secret = checker(4, 4);
        let shares = split_n_of_n(&mut r, &secret, 2);
        assert_eq!(shares.len(), 2);
        // Per-share image dimensions: 4 × (4 · 2) = 4 × 8.
        for s in &shares {
            assert_eq!(s.len(), 4);
            for row in s {
                assert_eq!(row.len(), 8);
            }
        }
        let stacked = stack(&shares).unwrap();
        let decoded = decode(&stacked, 2).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn round_trip_3_of_3() {
        let mut r = rng();
        let secret = checker(3, 5);
        let shares = split_n_of_n(&mut r, &secret, 3);
        assert_eq!(shares.len(), 3);
        let m = pixel_expansion(3);
        for s in &shares {
            assert_eq!(s.len(), 3);
            for row in s {
                assert_eq!(row.len(), 5 * m);
            }
        }
        let stacked = stack(&shares).unwrap();
        let decoded = decode(&stacked, 3).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn round_trip_4_of_4() {
        let mut r = rng();
        let secret = checker(2, 6);
        let shares = split_n_of_n(&mut r, &secret, 4);
        let stacked = stack(&shares).unwrap();
        let decoded = decode(&stacked, 4).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn fewer_than_n_shares_are_indistinguishable_from_random_at_white_pixel() {
        // Below-threshold sanity. With (n, n) and only n-1 shares
        // stacked, the resulting Hamming weight per pixel block matches
        // the same distribution for both white and black source
        // pixels — so no pixel can be classified.
        // Concrete check: stack n-1 shares for a *white* pixel and a
        // *black* pixel, count blacks; the counts should be equal.
        // Use n = 3 so it's easy to reason about: m = 4, n - 1 = 2.
        let mut r = rng();
        let n = 3;
        // 1×2 secret: one white (false), one black (true).
        let secret = vec![vec![false, true]];
        let shares = split_n_of_n(&mut r, &secret, n);
        // Stack the first 2 shares only.
        let partial = stack(&shares[..2]).unwrap();
        // Per-block weights at columns 0 and 1.
        let m = pixel_expansion(n);
        let weight_white: usize = partial[0][0..m].iter().filter(|&&b| b).count();
        let weight_black: usize = partial[0][m..2 * m].iter().filter(|&&b| b).count();
        // For (3, 3) Naor-Shamir, the 2-of-3 stack yields the same
        // weight distribution for both pixel colours: 3 of 4 sub-pixels
        // are black in both cases (the missing position is uniformly
        // random). Verify the counts agree.
        assert_eq!(weight_white, weight_black);
    }

    #[test]
    fn share_alone_carries_no_distinguishing_information() {
        // Each share, viewed in isolation, is a sequence of m-bit
        // blocks each having Hamming weight ⌈m / 2⌉ (one row of either
        // basis matrix). So the per-block weights of share 0 are the
        // same for white and black secret pixels.
        let mut r = rng();
        let n = 3;
        let m = pixel_expansion(n);
        let secret = vec![vec![false, true]];
        let shares = split_n_of_n(&mut r, &secret, n);
        let weight_white: usize = shares[0][0][0..m].iter().filter(|&&b| b).count();
        let weight_black: usize = shares[0][0][m..2 * m].iter().filter(|&&b| b).count();
        assert_eq!(weight_white, weight_black);
    }

    #[test]
    fn decode_rejects_malformed_block() {
        // A block whose Hamming weight is neither m nor m-1 is not a
        // legal stacked output of (n, n).
        let n = 2;
        let m = pixel_expansion(n);
        let mut bad = vec![vec![false; m]];
        bad[0][0] = false; // weight 0, illegal (need m or m-1).
        assert!(decode(&bad, n).is_none());
    }

    #[test]
    fn stack_rejects_mismatched_dimensions() {
        let a: Vec<Vec<bool>> = vec![vec![false, true]];
        let b: Vec<Vec<bool>> = vec![vec![false, true, false]];
        assert!(stack(&[a, b]).is_none());
    }
}
