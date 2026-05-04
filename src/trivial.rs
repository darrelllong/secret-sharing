//! Karnin–Greene–Hellman 1983 §I trivial n-of-n split.
//!
//! "Divide the secret key `s` into `n` pieces `v_1, …, v_n` in a manner
//! such that no information about `s` is learned from `n − 1` pieces."
//! Pick `v_1, …, v_{n-1}` independently and uniformly on `S`, then take
//! the last piece so that all pieces sum to the secret. Reconstruction
//! requires every piece — there is no `k < n` threshold.
//!
//! Two flavours are exposed:
//!
//! - [`split`] / [`reconstruct`] over `GF(p)` for a generic prime.
//! - [`split_xor`] / [`reconstruct_xor`] over `GF(2)^L` (byte-wise XOR),
//!   which is the `q = 2` special case the paper calls out as an
//!   immediately useful application to bit strings.

use crate::field::PrimeField;
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// Split a `GF(p)` element into `n` additive shares whose sum is the
/// secret.
///
/// # Panics
/// Panics if `n < 2`. The trivial scheme is meaningful only for `n ≥ 2`
/// — `n = 1` would distribute the secret in plaintext.
#[must_use]
pub fn split<R: Csprng>(
    field: &PrimeField,
    rng: &mut R,
    secret: &BigUint,
    n: usize,
) -> Vec<BigUint> {
    assert!(n >= 2, "n must be at least 2 (n = 1 would leak the secret)");
    let secret = field.reduce(secret);
    let mut shares = Vec::with_capacity(n);
    let mut sum = BigUint::zero();
    for _ in 0..(n - 1) {
        let v = field.random(rng);
        sum = field.add(&sum, &v);
        shares.push(v);
    }
    // Final piece chosen so the sum equals the secret.
    shares.push(field.sub(&secret, &sum));
    shares
}

/// Recover the secret as `Σ v_i mod p`. Returns `0` for an empty input.
#[must_use]
pub fn reconstruct(field: &PrimeField, shares: &[BigUint]) -> BigUint {
    let mut sum = BigUint::zero();
    for v in shares {
        sum = field.add(&sum, v);
    }
    sum
}

/// XOR split over byte strings (the `q = 2` case applied "to successive
/// bits of the key", per Karnin–Greene–Hellman §I). Each share has the
/// same length as the secret.
///
/// # Panics
/// Panics if `n < 2`. As with [`split`], `n = 1` would emit the secret
/// in plaintext.
#[must_use]
pub fn split_xor<R: Csprng>(rng: &mut R, secret: &[u8], n: usize) -> Vec<Vec<u8>> {
    assert!(n >= 2, "n must be at least 2 (n = 1 would leak the secret)");
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut last = secret.to_vec();
    for _ in 0..(n - 1) {
        let mut v = vec![0u8; secret.len()];
        rng.fill_bytes(&mut v);
        for (a, b) in last.iter_mut().zip(v.iter()) {
            *a ^= *b;
        }
        shares.push(v);
    }
    shares.push(last);
    shares
}

/// XOR every byte of every share.
///
/// # Panics
/// Panics if the supplied shares are not all the same length.
#[must_use]
pub fn reconstruct_xor(shares: &[Vec<u8>]) -> Vec<u8> {
    if shares.is_empty() {
        return Vec::new();
    }
    let len = shares[0].len();
    let mut out = vec![0u8; len];
    for s in shares {
        assert_eq!(s.len(), len, "share length mismatch");
        for (a, b) in out.iter_mut().zip(s.iter()) {
            *a ^= *b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[7u8; 32])
    }

    #[test]
    fn additive_round_trip() {
        let f = PrimeField::new(BigUint::from_u64(65_537));
        let mut r = rng();
        let secret = BigUint::from_u64(12_345);
        for n in 2..=6 {
            let shares = split(&f, &mut r, &secret, n);
            assert_eq!(shares.len(), n);
            assert_eq!(reconstruct(&f, &shares), secret);
        }
    }

    #[test]
    fn additive_misses_secret_with_one_dropped() {
        // Karnin–Greene–Hellman §I: any `n − 1` pieces leak nothing —
        // operationally, the partial sum is statistically uniform.
        let f = PrimeField::new(BigUint::from_u64(65_537));
        let mut r = rng();
        let secret = BigUint::from_u64(12_345);
        let shares = split(&f, &mut r, &secret, 4);
        let partial = reconstruct(&f, &shares[..3]);
        // Whatever it is, it should not coincidentally equal the secret.
        assert_ne!(partial, secret);
    }

    #[test]
    #[should_panic(expected = "n must be at least 2")]
    fn additive_split_rejects_n_one() {
        // n = 1 would hand the lone trustee the secret in plaintext.
        let f = PrimeField::new(BigUint::from_u64(65_537));
        let mut r = rng();
        let _ = split(&f, &mut r, &BigUint::from_u64(1), 1);
    }

    #[test]
    #[should_panic(expected = "n must be at least 2")]
    fn xor_split_rejects_n_one() {
        let mut r = rng();
        let _ = split_xor(&mut r, b"x", 1);
    }

    #[test]
    fn xor_round_trip() {
        let mut r = rng();
        let secret = b"my super secret payload".to_vec();
        for n in 2..=5 {
            let shares = split_xor(&mut r, &secret, n);
            assert_eq!(shares.len(), n);
            for s in &shares {
                assert_eq!(s.len(), secret.len());
            }
            assert_eq!(reconstruct_xor(&shares), secret);
        }
    }

    #[test]
    fn xor_with_one_random_share_is_uniform_like() {
        // Sanity: dropping any one share leaves an XOR of the remaining
        // n−1 random masks, which has no relation to the secret.
        let mut r = rng();
        let secret = vec![0xAA; 16];
        let shares = split_xor(&mut r, &secret, 4);
        let partial = reconstruct_xor(&shares[..3]);
        assert_ne!(partial, secret);
    }
}
