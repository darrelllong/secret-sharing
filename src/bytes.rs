//! Byte-string Shamir.
//!
//! Practical secrets are byte arrays (AES keys, passphrases, files),
//! not single-element `BigUint`s. Shamir 1979 §2 already foresees this:
//! "If the number `D` is long, it is advisable to break it into shorter
//! blocks of bits (which are handled separately) in order to avoid
//! multiprecision arithmetic operations." We implement that here by
//! chunking the secret into field-sized blocks, running Shamir on each
//! block independently with a shared set of trustee abscissae, and
//! serializing the resulting byte-shares with a small header.
//!
//! Wire format (per share):
//! ```text
//! version : u8         = 0x01
//! x       : u8         = trustee label (1..=255)
//! length  : u32 (BE)   = byte-length of the original secret
//! blocks  : [u8; ...]  = concatenated big-endian fixed-width chunks
//!                         (one per polynomial; width = block_len)
//! ```
//!
//! `block_len` is derived from the field modulus: each polynomial
//! evaluation is one field element, which we encode as `block_len`
//! big-endian bytes where `block_len = ceil((p.bits() − 1) / 8)`. This
//! ensures every plaintext block (which is `< 2^{block_len·8} ≤ p`)
//! fits in one field element.

use crate::field::PrimeField;
use crate::poly::{horner, lagrange_eval};
use crate::bigint::BigUint;
use crate::csprng::Csprng;
use crate::secure::ct_eq_biguint;

const SHARE_VERSION: u8 = 0x01;
const HEADER_LEN: usize = 1 + 1 + 4;

/// Number of plaintext bytes that fit safely in one field element.
/// Equals `floor((p.bits() − 1) / 8)`, so every plaintext block
/// `b ∈ [0, 2^{8·block_len}) ⊂ [0, p)`.
#[must_use]
pub fn block_len(field: &PrimeField) -> usize {
    let bits = field.modulus().bits();
    assert!(bits >= 9, "field too small for byte-block Shamir");
    (bits - 1) / 8
}

/// Number of bytes needed to losslessly serialize an arbitrary field
/// element (an evaluation `y_i = q(x_i)`). Equals `ceil(p.bits() / 8)`,
/// which is at least one byte longer than [`block_len`] for primes
/// whose bit-length is a multiple of 8 (e.g. `2^127 − 1` ⇒ 16-byte
/// shares for 15-byte plaintext blocks).
#[must_use]
fn share_elem_len(field: &PrimeField) -> usize {
    field.modulus().bits().div_ceil(8)
}

/// Split a byte-string secret into `n` byte-encoded shares with
/// threshold `k`.
///
/// # Panics
/// - `k < 2` (a degree-0 polynomial would put the plaintext in every
///   share's payload),
/// - `n < k` or `n > 255` (label encoding is one byte),
/// - `n ≥ p`,
/// - `field` is too small (see [`block_len`]).
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &[u8],
    k: usize,
    n: usize,
) -> Vec<Vec<u8>> {
    assert!(k >= 2, "k must be at least 2 (k = 1 would leak the secret)");
    assert!(n >= k, "n must be at least k");
    assert!(n <= 255, "byte-encoded shares support up to 255 trustees");
    assert!(
        BigUint::from_u64(n as u64) < *field.modulus(),
        "prime modulus must exceed n",
    );
    // The wire format encodes secret.len() in a 4-byte length header;
    // refuse anything that would silently truncate.
    assert!(
        secret.len() <= u32::MAX as usize,
        "secret length must fit in u32 (wire-format length header is 4 bytes)",
    );
    let bl = block_len(field);
    let sl = share_elem_len(field);

    // Pad the secret with zero bytes up to a whole number of blocks.
    let pad = (bl - (secret.len() % bl)) % bl;
    let mut padded = Vec::with_capacity(secret.len() + pad);
    padded.extend_from_slice(secret);
    padded.resize(secret.len() + pad, 0);
    let num_blocks = padded.len() / bl;

    let mut shares: Vec<Vec<u8>> = (1..=n)
        .map(|i| {
            let mut hdr = Vec::with_capacity(HEADER_LEN + num_blocks * sl);
            hdr.push(SHARE_VERSION);
            hdr.push(i as u8);
            hdr.extend_from_slice(&(secret.len() as u32).to_be_bytes());
            hdr
        })
        .collect();

    // For each plaintext block, run a fresh degree-(k−1) polynomial
    // and append every trustee's evaluation to that trustee's share.
    for block_idx in 0..num_blocks {
        let block = &padded[block_idx * bl..(block_idx + 1) * bl];
        let secret_elem = BigUint::from_be_bytes(block);
        let mut coeffs: Vec<BigUint> = Vec::with_capacity(k);
        coeffs.push(field.reduce(&secret_elem));
        for _ in 1..k {
            coeffs.push(field.random(rng));
        }
        for (i, share) in shares.iter_mut().enumerate() {
            let x = BigUint::from_u64((i + 1) as u64);
            let y = horner(field, &coeffs, &x);
            let bytes = field_element_to_bytes(&y, sl);
            share.extend_from_slice(&bytes);
        }
    }

    shares
}

/// Recover the original byte-string from any `k` (or more) shares.
///
/// Returns `None` on:
/// - empty input or `shares.len() < k`,
/// - any malformed share (bad version, length mismatch, label collision),
/// - duplicate or zero `x` labels,
/// - any extra share (index `≥ k`) that disagrees with the first `k`.
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[&[u8]], k: usize) -> Option<Vec<u8>> {
    if k == 0 || shares.len() < k {
        return None;
    }
    let bl = block_len(field);
    let sl = share_elem_len(field);

    // Parse every share's header. All must agree on the secret length.
    let mut parsed: Vec<(u8, &[u8])> = Vec::with_capacity(shares.len());
    let mut secret_len: Option<usize> = None;
    for s in shares {
        if s.len() < HEADER_LEN || s[0] != SHARE_VERSION {
            return None;
        }
        let label = s[1];
        if label == 0 {
            return None;
        }
        let len = u32::from_be_bytes([s[2], s[3], s[4], s[5]]) as usize;
        if let Some(prev) = secret_len {
            if prev != len {
                return None;
            }
        } else {
            secret_len = Some(len);
        }
        let payload = &s[HEADER_LEN..];
        if payload.len() % sl != 0 {
            return None;
        }
        parsed.push((label, payload));
    }
    let secret_len = secret_len?;
    let pad = (bl - (secret_len % bl)) % bl;
    let padded_len = secret_len + pad;
    let num_blocks = padded_len / bl;
    for (_, payload) in &parsed {
        if payload.len() != num_blocks * sl {
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

    // For each block, run Lagrange across the k chosen shares; verify
    // the remaining `len − k` shares agree.
    let mut out = Vec::with_capacity(padded_len);
    for block_idx in 0..num_blocks {
        let mut pts: Vec<(BigUint, BigUint)> = Vec::with_capacity(k);
        for (label, payload) in parsed.iter().take(k) {
            let x = BigUint::from_u64(*label as u64);
            let y = BigUint::from_be_bytes(&payload[block_idx * sl..(block_idx + 1) * sl]);
            // Reject non-canonical encodings — `y` MUST be `< p`.
            // Without this check a tampered share carrying y' = y + k·p
            // (still fitting in `sl` bytes when `sl > p.bits()/8`)
            // would reduce internally to the legitimate y and pass.
            if y >= *field.modulus() {
                return None;
            }
            pts.push((x, y));
        }
        let secret_y = lagrange_eval(field, &pts, &BigUint::zero())?;
        for (label, payload) in parsed.iter().skip(k) {
            let x = BigUint::from_u64(*label as u64);
            let y = BigUint::from_be_bytes(&payload[block_idx * sl..(block_idx + 1) * sl]);
            if y >= *field.modulus() {
                return None;
            }
            let pred = lagrange_eval(field, &pts, &x)?;
            if !ct_eq_biguint(&pred, &y) {
                return None;
            }
            let _ = label;
        }
        // Plaintext block is `bl` bytes (lower half of the field
        // element); strip leading zeros that the share encoder added.
        // For honest shares the recovered value always fits in `bl`
        // bytes; tampering of the first k can produce a wider value,
        // in which case we refuse rather than panic.
        let bytes = field_element_to_bytes_checked(&secret_y, bl)?;
        out.extend_from_slice(&bytes);
    }

    out.truncate(secret_len);
    Some(out)
}

/// Like [`field_element_to_bytes`] but returns `None` instead of
/// panicking when the value exceeds `width` bytes. Used on the
/// reconstruction path where tampered first-k shares can produce a
/// recovered field element wider than the plaintext block.
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

/// Big-endian, fixed-width serialization of a field element.
/// Pads with leading zeros if the value has fewer than `width` bytes;
/// strips leading zeros if it has more, but panics in release builds
/// if any of those leading bytes are non-zero (a value that would not
/// fit in `width` bytes is a contract violation and turning it into
/// silent truncation could hide an upstream bug).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::mersenne127;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[9u8; 32])
    }

    #[test]
    fn block_len_for_mersenne127_is_15() {
        // 2^127 − 1 has 127 bits → block_len = floor(126 / 8) = 15.
        let f = PrimeField::new(mersenne127());
        assert_eq!(block_len(&f), 15);
    }

    #[test]
    fn round_trip_short_secret() {
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret = b"hello, secret!".to_vec();
        let shares = split(&f, &mut r, &secret, 2, 4);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        let got = reconstruct(&f, &refs[..2], 2).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn round_trip_multi_block_secret() {
        // 64 bytes spans multiple 15-byte blocks → exercises chunking.
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret: Vec<u8> = (0..64u8).collect();
        let shares = split(&f, &mut r, &secret, 3, 7);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        let got = reconstruct(&f, &refs[2..5], 3).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn round_trip_empty_secret() {
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret: Vec<u8> = Vec::new();
        let shares = split(&f, &mut r, &secret, 2, 3);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        let got = reconstruct(&f, &refs[..2], 2).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn below_threshold_returns_none() {
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret = b"32-byte secret like an AES key!!".to_vec();
        let shares = split(&f, &mut r, &secret, 3, 5);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&f, &refs[..2], 3).is_none());
    }

    #[test]
    fn corrupted_extra_is_rejected() {
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret = b"do not corrupt me!".to_vec();
        let mut shares = split(&f, &mut r, &secret, 3, 5);
        // Flip one byte of the last share's first block (header is intact).
        shares[4][HEADER_LEN] ^= 0x01;
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&f, &refs, 3).is_none());
    }

    #[test]
    fn malformed_version_is_rejected() {
        let f = PrimeField::new(mersenne127());
        let mut r = rng();
        let secret = b"x".to_vec();
        let mut shares = split(&f, &mut r, &secret, 2, 3);
        shares[0][0] = 0xFF;
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        assert!(reconstruct(&f, &refs[..2], 2).is_none());
    }
}
