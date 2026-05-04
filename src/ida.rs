//! Rabin 1989, *Efficient Dispersal of Information for Security, Load
//! Balancing, and Fault Tolerance* — Information Dispersal Algorithm
//! (IDA).
//!
//! IDA is **not** a secret-sharing scheme — it offers no information-
//! theoretic secrecy. It is the optimal-rate erasure-coding companion:
//! a file `F` of size `|F|` bytes is split into `n` pieces of size
//! `|F| / k` bytes each, and any `k` of them reconstruct `F`. Total
//! storage is `(n / k) · |F|`, the minimum possible for a code that
//! tolerates `n − k` erasures.
//!
//! Construction. Encode `F` as a sequence of degree-`(k − 1)` polynomial
//! coefficient blocks `(b_{0}, b_{1}, …, b_{k − 1}) ∈ GF(p)^k`. For each
//! block, evaluate the polynomial `P(x) = b_0 + b_1 x + … + b_{k−1}
//! x^{k−1}` at the `n` distinct trustee labels `1..=n`. Trustee `j`
//! holds one field-element evaluation per block, in order. Reconstruct
//! by Lagrange-interpolating `P` from any `k` evaluations and reading
//! off its coefficients.
//!
//! Compared with `crate::ramp` (McEliece–Sarwate), the trade-off is
//! flipped: ramp distributes evaluations *outside* the secret slots
//! `1..=k` so that `k − 1` shares leak only one residue class of
//! candidate secrets per block; IDA distributes only evaluations and
//! anyone with `k` shares reconstructs in full. IDA is appropriate when
//! the data is non-secret (load-balancing replication, RAID-like
//! erasure coding) but not when secrecy is required.
//!
//! Wire format (per share):
//! ```text
//! version : u8         = 0x02
//! label   : u8         = trustee index 1..=255
//! length  : u32 (BE)   = byte-length of the original file
//! evals   : [u8; ...]  = concatenated big-endian field-element evaluations,
//!                          one per (k-element) coefficient block
//! ```

use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::bigint::BigUint;

const SHARE_VERSION: u8 = 0x02;
const HEADER_LEN: usize = 1 + 1 + 4;

/// Number of plaintext bytes that fit safely in one field element.
/// Identical to `crate::bytes::block_len` — kept local so IDA can be
/// read independently.
#[must_use]
fn block_len(field: &PrimeField) -> usize {
    let bits = field.modulus().bits();
    assert!(bits >= 9, "field too small for byte-block IDA");
    (bits - 1) / 8
}

#[must_use]
fn share_elem_len(field: &PrimeField) -> usize {
    field.modulus().bits().div_ceil(8)
}

/// Disperse `data` into `n` shares, any `k` of which reconstruct `data`.
///
/// # Panics
/// - `k < 2`,
/// - `n < k` or `n > 255`,
/// - `n ≥ p`,
/// - `field` is too small (see [`block_len`]).
#[must_use]
pub fn split(field: &PrimeField, data: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    assert!(k >= 2, "k must be at least 2");
    assert!(n >= k, "n must be at least k");
    assert!(n <= 255, "byte-encoded shares support up to 255 trustees");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );
    let bl = block_len(field);
    let sl = share_elem_len(field);

    // Pad the data with zeros up to a whole number of (k · bl)-byte
    // groups, since each group becomes one degree-(k−1) polynomial.
    let group = k * bl;
    let pad = (group - (data.len() % group)) % group;
    let mut padded = Vec::with_capacity(data.len() + pad);
    padded.extend_from_slice(data);
    padded.resize(data.len() + pad, 0);
    let num_groups = padded.len() / group;

    let mut shares: Vec<Vec<u8>> = (1..=n)
        .map(|i| {
            let mut v = Vec::with_capacity(HEADER_LEN + num_groups * sl);
            v.push(SHARE_VERSION);
            v.push(i as u8);
            v.extend_from_slice(&(data.len() as u32).to_be_bytes());
            v
        })
        .collect();

    // For each group of k blocks, treat the bytes as polynomial
    // coefficients and evaluate at every trustee label.
    for g in 0..num_groups {
        let mut coeffs: Vec<BigUint> = Vec::with_capacity(k);
        for j in 0..k {
            let start = g * group + j * bl;
            let block = &padded[start..start + bl];
            coeffs.push(BigUint::from_be_bytes(block));
        }
        for (i, share) in shares.iter_mut().enumerate() {
            let x = BigUint::from_u64((i + 1) as u64);
            let y = horner(field, &coeffs, &x);
            share.extend_from_slice(&field_element_to_bytes(&y, sl));
        }
    }

    shares
}

/// Reconstruct the original `data` from any `k` (or more) shares.
/// Extras are validated against the unique polynomial fit to the first
/// `k` and disagreement returns `None`.
///
/// Returns `None` on malformed shares (bad version, mismatched length
/// header, duplicate label, label `0`, payload not a multiple of the
/// element width, or insufficient shares).
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[&[u8]], k: usize) -> Option<Vec<u8>> {
    if k < 2 || shares.len() < k {
        return None;
    }
    let bl = block_len(field);
    let sl = share_elem_len(field);

    let mut parsed: Vec<(u8, &[u8])> = Vec::with_capacity(shares.len());
    let mut data_len: Option<usize> = None;
    for s in shares {
        if s.len() < HEADER_LEN || s[0] != SHARE_VERSION {
            return None;
        }
        let label = s[1];
        if label == 0 {
            return None;
        }
        let len = u32::from_be_bytes([s[2], s[3], s[4], s[5]]) as usize;
        if let Some(prev) = data_len {
            if prev != len {
                return None;
            }
        } else {
            data_len = Some(len);
        }
        let payload = &s[HEADER_LEN..];
        if payload.len() % sl != 0 {
            return None;
        }
        parsed.push((label, payload));
    }
    let data_len = data_len?;
    let group = k * bl;
    let pad = (group - (data_len % group)) % group;
    let padded_len = data_len + pad;
    let num_groups = padded_len / group;
    for (_, payload) in &parsed {
        if payload.len() != num_groups * sl {
            return None;
        }
    }
    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            if parsed[i].0 == parsed[j].0 {
                return None;
            }
        }
    }

    let mut out = Vec::with_capacity(padded_len);
    for g in 0..num_groups {
        let pts: Vec<(BigUint, BigUint)> = parsed
            .iter()
            .take(k)
            .map(|(label, payload)| {
                let x = BigUint::from_u64(*label as u64);
                let y = BigUint::from_be_bytes(&payload[g * sl..(g + 1) * sl]);
                (x, y)
            })
            .collect();
        // Recover k coefficients by interpolating P at x = 1, 2, …, k —
        // wait: we want the polynomial *coefficients*, not its values.
        // Use the multi-secret Vandermonde solve: build the linear
        // system Vc = y where V_{i,j} = (label_i)^j and y_i is the
        // evaluation. Solve for c.
        let coeffs = vandermonde_solve(field, &pts)?;
        // Validate extras against the recovered coefficient vector.
        for (label, payload) in parsed.iter().skip(k) {
            let x = BigUint::from_u64(*label as u64);
            let y = BigUint::from_be_bytes(&payload[g * sl..(g + 1) * sl]);
            if horner(field, &coeffs, &x) != y {
                return None;
            }
        }
        // Append every coefficient as a `bl`-byte chunk in order.
        // For honest shares each coefficient is < 2^(8·bl) by
        // construction; tampering can produce values that exceed bl
        // bytes, in which case we refuse rather than panic.
        for c in &coeffs {
            let bytes = field_element_to_bytes_checked(c, bl)?;
            out.extend_from_slice(&bytes);
        }
    }

    out.truncate(data_len);
    Some(out)
}

/// Solve the augmented `k × (k+1)` Vandermonde system for the
/// polynomial coefficients given `k` `(x, y)` evaluation points. Helper
/// for IDA's reconstruction path; mirrors the `shamir::reconstruct_multi`
/// elimination but local to this module so IDA can be read on its own.
#[allow(clippy::needless_range_loop)]
fn vandermonde_solve(
    field: &PrimeField,
    points: &[(BigUint, BigUint)],
) -> Option<Vec<BigUint>> {
    let k = points.len();
    let mut mat: Vec<Vec<BigUint>> = Vec::with_capacity(k);
    for (x, y) in points {
        let mut row = Vec::with_capacity(k + 1);
        let mut x_pow = BigUint::one();
        for _ in 0..k {
            row.push(x_pow.clone());
            x_pow = field.mul(&x_pow, x);
        }
        row.push(y.clone());
        mat.push(row);
    }
    for col in 0..k {
        let mut pivot_row = None;
        for r in col..k {
            if !mat[r][col].is_zero() {
                pivot_row = Some(r);
                break;
            }
        }
        let pr = pivot_row?;
        if pr != col {
            mat.swap(pr, col);
        }
        let inv = field.inv(&mat[col][col])?;
        for c in col..=k {
            mat[col][c] = field.mul(&mat[col][c], &inv);
        }
        for r in 0..k {
            if r == col || mat[r][col].is_zero() {
                continue;
            }
            let factor = mat[r][col].clone();
            for c in col..=k {
                let term = field.mul(&factor, &mat[col][c]);
                mat[r][c] = field.sub(&mat[r][c], &term);
            }
        }
    }
    Some((0..k).map(|i| mat[i][k].clone()).collect())
}

fn field_element_to_bytes(value: &BigUint, width: usize) -> Vec<u8> {
    let mut be = value.to_be_bytes();
    if be.len() < width {
        let mut padded = vec![0u8; width - be.len()];
        padded.append(&mut be);
        padded
    } else if be.len() == width {
        be
    } else {
        let extra = be.len() - width;
        assert!(
            be[..extra].iter().all(|&b| b == 0),
            "field element exceeds requested encoding width",
        );
        be[extra..].to_vec()
    }
}

/// Like [`field_element_to_bytes`] but returns `None` instead of
/// panicking when the value exceeds `width` bytes. Used on the
/// reconstruction path, where tampered coefficients can be out of range
/// and a None result is the right escape hatch for a callable contract.
fn field_element_to_bytes_checked(value: &BigUint, width: usize) -> Option<Vec<u8>> {
    let mut be = value.to_be_bytes();
    if be.len() < width {
        let mut padded = vec![0u8; width - be.len()];
        padded.append(&mut be);
        Some(padded)
    } else if be.len() == width {
        Some(be)
    } else {
        let extra = be.len() - width;
        if be[..extra].iter().all(|&b| b == 0) {
            Some(be[extra..].to_vec())
        } else {
            None
        }
    }
}

// `lagrange_eval` is unused in IDA's hot path (we want coefficients,
// not interpolated values), but kept imported by the surrounding crate
// for the symmetry with `bytes.rs` / `ramp.rs`.
#[allow(dead_code)]
fn _ensure_lagrange_path_compiles(field: &PrimeField, pts: &[(BigUint, BigUint)]) -> Option<BigUint> {
    lagrange_eval(field, pts, &BigUint::zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::mersenne127;

    fn f() -> PrimeField {
        PrimeField::new(mersenne127())
    }

    #[test]
    fn round_trip_short() {
        let field = f();
        let data = b"information dispersal - quick brown fox".to_vec();
        let shares = split(&field, &data, 3, 6);
        assert_eq!(shares.len(), 6);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert_eq!(reconstruct(&field, &refs[..3], 3).unwrap(), data);
        assert_eq!(reconstruct(&field, &refs[2..5], 3).unwrap(), data);
    }

    #[test]
    fn round_trip_long() {
        // 1 KiB exercises many polynomial blocks.
        let field = f();
        let data: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let shares = split(&field, &data, 5, 9);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert_eq!(reconstruct(&field, &refs[..5], 5).unwrap(), data);
        // Pick a non-contiguous 5-subset.
        let picked: Vec<&[u8]> = vec![refs[0], refs[2], refs[4], refs[6], refs[8]];
        assert_eq!(reconstruct(&field, &picked, 5).unwrap(), data);
    }

    #[test]
    fn share_size_is_data_over_k() {
        // Each share's payload is exactly num_groups · sl bytes, where
        // num_groups = ⌈|data| / (k · bl)⌉. Asserting the formula
        // outright is the strict |F|/k claim — minus the necessary
        // ceiling rounding.
        let field = f();
        let data: Vec<u8> = (0..1500u32).map(|i| (i & 0xFF) as u8).collect();
        let k = 3;
        let bl = block_len(&field);
        let sl = share_elem_len(&field);
        let shares = split(&field, &data, k, 5);
        let group = k * bl;
        let num_groups = data.len().div_ceil(group);
        let expected_payload = num_groups * sl;
        assert_eq!(shares[0].len() - HEADER_LEN, expected_payload);
        // For large `|data|` the ceiling overhead is at most one extra
        // group of `sl` bytes per share, so per-share payload is in
        // [|data|/k · (sl/bl), |data|/k · (sl/bl) + sl).
        let ratio = sl as f64 / bl as f64;
        let lower = (data.len() as f64) / (k as f64) * ratio;
        let upper = lower + sl as f64;
        assert!(
            expected_payload as f64 >= lower && (expected_payload as f64) < upper,
            "payload {} not in [{}, {})",
            expected_payload,
            lower,
            upper
        );
    }

    #[test]
    fn round_trip_empty() {
        let field = f();
        let data: Vec<u8> = Vec::new();
        let shares = split(&field, &data, 2, 3);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert_eq!(reconstruct(&field, &refs[..2], 2).unwrap(), data);
    }

    #[test]
    fn corrupted_extra_rejected() {
        let field = f();
        let data = b"please don't corrupt me".to_vec();
        let mut shares = split(&field, &data, 3, 5);
        shares[4][HEADER_LEN] ^= 0x01;
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&field, &refs, 3).is_none());
    }

    #[test]
    fn below_threshold_returns_none() {
        let field = f();
        let data = b"need three shares".to_vec();
        let shares = split(&field, &data, 3, 5);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&field, &refs[..2], 3).is_none());
    }

    #[test]
    fn malformed_version_rejected() {
        let field = f();
        let data = b"x".to_vec();
        let mut shares = split(&field, &data, 2, 3);
        shares[0][0] = 0xFF;
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&field, &refs[..2], 2).is_none());
    }

    #[test]
    fn first_k_tamper_does_not_panic() {
        // AD #3 (P0): a tampered share within the first k could push a
        // recovered "coefficient" past 2^(8·bl), which previously
        // panicked in `field_element_to_bytes`. Now we return either
        // None (if a coefficient overflows bl bytes) or a wrong-but-
        // typed Vec<u8>; we never panic.
        let field = f();
        let data: Vec<u8> = (0..120u8).collect();
        let shares = split(&field, &data, 3, 5);
        // Tamper many bytes of share[0] to maximise the chance that at
        // least one recovered coefficient overflows bl.
        let mut bad = shares.clone();
        for offset in 0..16 {
            bad[0][HEADER_LEN + offset] = bad[0][HEADER_LEN + offset].wrapping_add(0x37);
        }
        let refs: Vec<&[u8]> = bad.iter().map(Vec::as_slice).collect();
        // Must not panic. Either None (overflow) or Some(wrong) is OK;
        // the property under test is "no unwinding."
        let _ = reconstruct(&field, &refs[..3], 3);
    }

    #[test]
    fn duplicate_label_rejected() {
        let field = f();
        let data = b"hi".to_vec();
        let mut shares = split(&field, &data, 2, 3);
        shares[1][1] = shares[0][1];
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&field, &refs[..2], 2).is_none());
    }
}
