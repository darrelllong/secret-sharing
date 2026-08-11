//! Primality and modular-arithmetic helpers, on the [`rump`] crate.
//!
//! The deterministic functions re-export from rump at their old paths.
//! What stays native is the randomized Miller-Rabin variant, composed
//! over rump's per-round [`rump::miller_rabin_witness`] primitive and
//! driven by this crate's [`Csprng`].

use crate::bigint::BigUint;
use crate::csprng::Csprng;

pub use rump::{gcd, is_probable_prime, mod_inverse, mod_pow};

/// Adapter presenting any [`Csprng`] as a [`rump::Rng`] source. The trait
/// shapes are identical; a blanket implementation of the foreign trait is
/// not ours to write.
struct CsprngSource<'a, R: Csprng>(&'a mut R);

impl<R: Csprng> rump::Rng for CsprngSource<'_, R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

/// Draw a random integer in `[0, upper_exclusive)`.
#[must_use]
pub fn random_below<R: Csprng>(rng: &mut R, upper_exclusive: &BigUint) -> Option<BigUint> {
    rump::random_below(&mut CsprngSource(rng), upper_exclusive)
}

/// Miller-Rabin with `rounds` uniformly random witnesses in `[2, n − 2]`.
///
/// The fixed-base [`is_probable_prime`] is deterministic and fast; this
/// variant trades determinism for witness unpredictability. Each round is
/// one [`rump::miller_rabin_witness`] test.
#[must_use]
pub fn is_probable_prime_random<R: Csprng>(rng: &mut R, n: &BigUint, rounds: usize) -> bool {
    let two = BigUint::from_u64(2);
    if n < &two {
        return false;
    }
    if !is_probable_prime(n) {
        // The deterministic sieve and fixed bases already reject it — and
        // they accept every prime, so a rejection here is final.
        return false;
    }
    if n <= &BigUint::from_u64(3) {
        return true;
    }

    let n_minus_3 = n.sub_ref(&BigUint::from_u64(3));
    for _ in 0..rounds {
        let Some(draw) = random_below(rng, &n_minus_3) else {
            return false;
        };
        let witness = draw.add_ref(&two);
        if rump::miller_rabin_witness(n, &witness) {
            return false;
        }
    }
    true
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
        for &p in &[
            2u64,
            3,
            5,
            7,
            11,
            13,
            65521,
            65537,
            (1u64 << 31) - 1,
            (1u64 << 61) - 1,
        ] {
            assert!(is_probable_prime(&BigUint::from_u64(p)), "{p} is prime");
        }
    }

    #[test]
    fn miller_rabin_random_round_trip() {
        let mut rng = ChaCha20Rng::from_seed(&[0x11u8; 32]);
        for &p in &[
            2u64,
            3,
            5,
            7,
            11,
            13,
            65537,
            (1u64 << 31) - 1,
            (1u64 << 61) - 1,
        ] {
            assert!(
                is_probable_prime_random(&mut rng, &BigUint::from_u64(p), 16),
                "{p} prime under random-witness MR",
            );
        }
        for &n in &[4u64, 6, 9, 25, 91, 561, 1105, 65535] {
            assert!(!is_probable_prime_random(
                &mut rng,
                &BigUint::from_u64(n),
                16
            ));
        }
    }

    #[test]
    fn miller_rabin_rejects_composites() {
        for &n in &[0u64, 1, 4, 6, 9, 15, 49, 91, 561, 1105, 1729, 65535] {
            assert!(
                !is_probable_prime(&BigUint::from_u64(n)),
                "{n} is not prime"
            );
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
