//! The primes-module subset this crate actually uses, copied verbatim
//! from `cryptography/src/public_key/primes.rs` so we have no
//! dependency on the sibling crate.
//!
//! Functions exposed:
//! - [`gcd`] — Euclidean algorithm; needed by Mignotte / Asmuth–Bloom
//!   for the pairwise-coprime checks.
//! - [`mod_inverse`] — extended Euclidean algorithm, needed by every
//!   field inverse (Lagrange, CRT folding, Montgomery setup).
//! - [`mod_pow`] — square-and-multiply modular exponentiation; used
//!   by the Miller–Rabin primality tests below.
//! - [`random_below`] — uniform sampling in `[0, n)` via rejection
//!   sampling against the next power of two; the workhorse for every
//!   `field.random` call.
//! - [`is_probable_prime`] — deterministic Miller–Rabin against a
//!   fixed witness set; sound for `n < 2^81`. Called by
//!   [`crate::field::PrimeField::new`] to validate caller-supplied
//!   moduli at construction. **Does not carry a probabilistic error
//!   bound for larger `n`** — see its docstring.
//! - [`is_probable_prime_random`] — random-witness Miller–Rabin with
//!   the standard `4^{-rounds}` error bound. Use this for primes
//!   above the deterministic range.

use crate::bigint::{BigInt, BigUint};
use crate::csprng::Csprng;
use crate::secure::Zeroizing;

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

/// Modular exponentiation `base^exp mod n`. Used by [`is_probable_prime`].
#[must_use]
pub fn mod_pow(base: &BigUint, exp: &BigUint, n: &BigUint) -> BigUint {
    if n.is_one() {
        return BigUint::zero();
    }
    let mut result = BigUint::one();
    let mut acc = base.modulo(n);
    let bits = exp.bits();
    for i in 0..bits {
        if exp.bit(i) {
            result = BigUint::mod_mul(&result, &acc, n);
        }
        if i + 1 < bits {
            acc = BigUint::mod_mul(&acc, &acc, n);
        }
    }
    result
}

/// Deterministic Miller–Rabin probable-prime test using a fixed
/// witness set `{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}`.
///
/// **Sound for `n < 3.317 × 10^24` (≈ 2^81).** Above that, this
/// routine is *not* probabilistic in the textbook sense — a fixed
/// witness set lets an adversarial caller construct strong
/// pseudoprimes that fool every base in the set with probability 1.
/// For arbitrary-size moduli supplied at construction, use
/// [`is_probable_prime_random`] with a CSPRNG and fresh random
/// witnesses; only the random-witness variant carries the
/// `4^{-rounds}` Miller–Rabin error bound.
///
/// `crate::field::PrimeField::new` calls this routine; consequently
/// it is fully validated only for `p < 2^81`. For larger primes the
/// caller must independently know `p` is prime (use
/// `PrimeField::new_unchecked`) or run [`is_probable_prime_random`]
/// themselves first.
#[must_use]
pub fn is_probable_prime(n: &BigUint) -> bool {
    if n < &BigUint::from_u64(2) {
        return false;
    }
    // Trial division by small primes — cheap rejection.
    for &p in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let p_big = BigUint::from_u64(p);
        if n == &p_big {
            return true;
        }
        if n.modulo(&p_big).is_zero() {
            return false;
        }
    }
    // Write n - 1 = d · 2^s with d odd.
    let n_minus_1 = n.sub_ref(&BigUint::one());
    let mut d = n_minus_1.clone();
    let mut s = 0usize;
    while !d.is_odd() {
        d.shr1();
        s += 1;
    }
    // Deterministic witness set for n < 3.3 · 10^24 (sufficient for
    // most cryptographic-size primes a caller might supply).
    const BASES: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    'witness: for &base in BASES {
        let a = BigUint::from_u64(base);
        if a >= *n {
            continue;
        }
        let mut x = mod_pow(&a, &d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 0..(s - 1) {
            x = BigUint::mod_mul(&x, &x, n);
            if x == n_minus_1 {
                continue 'witness;
            }
            if x.is_one() {
                return false;
            }
        }
        return false;
    }
    true
}

/// Miller–Rabin probable-prime test with `rounds` *random* witnesses
/// drawn from `[2, n − 2]` via the supplied CSPRNG. False-positive
/// rate ≤ `4^{-rounds}` against any caller-chosen `n`, even those
/// constructed adversarially to fool fixed witness sets.
///
/// `rounds = 40` gives 2^{-80} false-positive rate — the standard
/// cryptographic bound. Use this routine for primes outside the
/// deterministic range of [`is_probable_prime`] (~ 2^81).
#[must_use]
pub fn is_probable_prime_random<R: Csprng>(rng: &mut R, n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from_u64(2) {
        return false;
    }
    // Trial-divide by tiny primes for cheap rejection.
    for &p in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let p_big = BigUint::from_u64(p);
        if n == &p_big {
            return true;
        }
        if n.modulo(&p_big).is_zero() {
            return false;
        }
    }
    let n_minus_1 = n.sub_ref(&BigUint::one());
    let mut d = n_minus_1.clone();
    let mut s = 0usize;
    while !d.is_odd() {
        d.shr1();
        s += 1;
    }
    let n_minus_3 = n.sub_ref(&BigUint::from_u64(3));
    'witness: for _ in 0..rounds {
        // Random witness in [2, n - 2] = 2 + random_below(n - 3).
        let r = match random_below(rng, &n_minus_3) {
            Some(v) => v.add_ref(&BigUint::from_u64(2)),
            None => return false,
        };
        let mut x = mod_pow(&r, &d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 0..(s - 1) {
            x = BigUint::mod_mul(&x, &x, n);
            if x == n_minus_1 {
                continue 'witness;
            }
            if x.is_one() {
                return false;
            }
        }
        return false;
    }
    true
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
    // Wrap the candidate-bytes buffer in `Zeroizing` so it is volatile-
    // zeroed on EVERY exit path (loop iteration, Some-return, panic
    // unwind). Each iteration overwrites the bytes anyway, but the
    // wrapper guarantees the *final* candidate's bytes are scrubbed
    // before the function returns.
    let mut bytes_holder = Zeroizing::new(vec![0u8; bits.div_ceil(8)]);
    let excess_bits = bytes_holder.len() * 8 - bits;
    let top_mask = 0xff_u8 >> excess_bits;

    loop {
        rng.fill_bytes(&mut bytes_holder);
        bytes_holder[0] &= top_mask;
        let candidate = BigUint::from_be_bytes(&bytes_holder);
        if candidate < *upper_exclusive {
            return Some(candidate);
            // bytes_holder is volatile-zeroed and dropped here.
        }
        // Loop iteration overwrites the next iteration's bytes.
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
    fn miller_rabin_accepts_known_primes() {
        for &p in &[2u64, 3, 5, 7, 11, 13, 65521, 65537, (1u64 << 31) - 1, (1u64 << 61) - 1] {
            assert!(is_probable_prime(&BigUint::from_u64(p)), "{p} is prime");
        }
    }

    #[test]
    fn miller_rabin_random_round_trip() {
        let mut rng = ChaCha20Rng::from_seed(&[0x11u8; 32]);
        for &p in &[
            2u64, 3, 5, 7, 11, 13, 65537, (1u64 << 31) - 1, (1u64 << 61) - 1,
        ] {
            assert!(
                is_probable_prime_random(&mut rng, &BigUint::from_u64(p), 16),
                "{p} prime under random-witness MR",
            );
        }
        for &n in &[4u64, 6, 9, 25, 91, 561, 1105, 65535] {
            assert!(!is_probable_prime_random(&mut rng, &BigUint::from_u64(n), 16));
        }
    }

    #[test]
    fn miller_rabin_rejects_composites() {
        for &n in &[0u64, 1, 4, 6, 9, 15, 49, 91, 561, 1105, 1729, 65535] {
            assert!(!is_probable_prime(&BigUint::from_u64(n)), "{n} is not prime");
        }
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
