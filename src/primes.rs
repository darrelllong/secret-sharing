//! The primes-module subset this crate actually uses, copied verbatim
//! from `cryptography/src/public_key/primes.rs` so we have no
//! dependency on the sibling crate.
//!
//! Three functions are kept:
//! - [`gcd`] — Euclidean algorithm; needed by Mignotte / Asmuth–Bloom
//!   for the pairwise-coprime checks.
//! - [`mod_inverse`] — extended Euclidean algorithm, needed by every
//!   field inverse (Lagrange, CRT folding, Montgomery setup).
//! - [`random_below`] — uniform sampling in `[0, n)` via rejection
//!   sampling against the next power of two; the workhorse for every
//!   `field.random` call.
//!
//! The omitted helpers from the original `primes.rs` (probable-prime
//! testing, prime sampling, lcm, mod_pow) are not used by any scheme
//! in this crate.

use crate::bigint::{BigInt, BigUint};
use crate::csprng::Csprng;

/// Greatest common divisor by the Euclidean algorithm.
#[must_use]
pub fn gcd(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    let mut current = lhs.clone();
    let mut next = rhs.clone();
    while !next.is_zero() {
        let remainder = current.modulo(&next);
        current = next;
        next = remainder;
    }
    current
}

/// Modular inverse `a^{-1} mod n`, or `None` if `gcd(a, n) ≠ 1`.
///
/// Extended Euclidean algorithm tracking the Bézout coefficient that
/// witnesses the gcd as a linear combination of `a` and `n`.
#[must_use]
pub fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    if n.is_zero() {
        return None;
    }

    let mut t = BigInt::zero();
    let mut new_t = BigInt::from_biguint(BigUint::one());
    let mut r = n.clone();
    let mut new_r = a.modulo(n);

    while !new_r.is_zero() {
        let (quotient, remainder) = r.div_rem(&new_r);
        let next_t = t.sub_ref(&new_t.mul_biguint_ref(&quotient));
        t = new_t;
        new_t = next_t;
        r = new_r;
        new_r = remainder;
    }

    if !r.is_one() {
        return None;
    }

    Some(t.modulo_positive(n))
}

/// Uniformly random `BigUint` in `[0, upper_exclusive)`. Returns `None`
/// when `upper_exclusive == 0`.
///
/// Rejection sampling against the next power of two: draw `bits =
/// upper.bits()` random bits via the supplied CSPRNG, retry if the
/// candidate is `≥ upper`. Expected retries are below 2 because the
/// candidate range is at most twice `upper`.
#[must_use]
pub fn random_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    if upper_exclusive.is_zero() {
        return None;
    }

    let bits = upper_exclusive.bits();
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    let excess_bits = bytes.len() * 8 - bits;
    let top_mask = 0xff_u8 >> excess_bits;

    loop {
        rng.fill_bytes(&mut bytes);
        bytes[0] &= top_mask;
        let candidate = BigUint::from_be_bytes(&bytes);
        // Scrub the buffer between iterations: candidate values can be
        // private (e.g. Shamir polynomial coefficients).
        for b in bytes.iter_mut() {
            *b = 0;
        }
        if candidate < *upper_exclusive {
            return Some(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csprng::ChaCha20Rng;

    #[test]
    fn gcd_small_values() {
        assert_eq!(
            gcd(&BigUint::from_u64(48), &BigUint::from_u64(18)),
            BigUint::from_u64(6)
        );
    }

    #[test]
    fn modular_inverse_small_values() {
        assert_eq!(
            mod_inverse(&BigUint::from_u64(11), &BigUint::from_u64(16)),
            Some(BigUint::from_u64(3))
        );
        assert_eq!(
            mod_inverse(&BigUint::from_u64(23), &BigUint::from_u64(46)),
            None
        );
    }

    #[test]
    fn random_below_is_in_range() {
        let mut rng = ChaCha20Rng::from_seed(&[7u8; 32]);
        let upper = BigUint::from_u64(1000);
        for _ in 0..100 {
            let x = random_below(&mut rng, &upper).unwrap();
            assert!(x < upper);
        }
    }

    #[test]
    fn random_below_zero_is_none() {
        let mut rng = ChaCha20Rng::from_seed(&[0u8; 32]);
        assert!(random_below(&mut rng, &BigUint::zero()).is_none());
    }
}
