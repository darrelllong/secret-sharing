//! Prime-field arithmetic on top of the sibling crate's `BigUint`.
//!
//! Shamir 1979 places its scheme over `Z/pZ` for a prime `p > max(D, n)`,
//! and the Karnin–Greene–Hellman / McEliece–Sarwate generalizations
//! retain that field (or its extension `GF(p^m)`). All polynomial
//! manipulations in the rest of the crate go through this wrapper so the
//! modulus is fixed once and the operations read directly off the papers.

use cryptography::public_key::primes::{mod_inverse, random_below};
use cryptography::vt::BigUint;
use cryptography::Csprng;

/// Prime modulus and the four finite-field operations needed by Shamir,
/// the KGH matrix scheme, and the McEliece–Sarwate decoder.
#[derive(Clone, Debug)]
pub struct PrimeField {
    p: BigUint,
}

impl PrimeField {
    /// Wrap a prime modulus. The caller is responsible for ensuring `p`
    /// is in fact prime — primality is not re-verified here.
    ///
    /// # Panics
    /// Panics if `p ≤ 1`.
    #[must_use]
    pub fn new(p: BigUint) -> Self {
        assert!(p > BigUint::one(), "modulus must be > 1");
        Self { p }
    }

    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Reduce an arbitrary `BigUint` into `[0, p)`.
    #[must_use]
    pub fn reduce(&self, a: &BigUint) -> BigUint {
        a.modulo(&self.p)
    }

    /// `a + b mod p`. Inputs need not be pre-reduced.
    #[must_use]
    pub fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let s = a.add_ref(b);
        s.modulo(&self.p)
    }

    /// `a − b mod p`. Inputs need not be pre-reduced.
    #[must_use]
    pub fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let a = self.reduce(a);
        let b = self.reduce(b);
        if a >= b {
            a.sub_ref(&b)
        } else {
            // a + (p − b), guaranteed < p since a < b < p.
            a.add_ref(&self.p).sub_ref(&b)
        }
    }

    /// `−a mod p`.
    #[must_use]
    pub fn neg(&self, a: &BigUint) -> BigUint {
        let a = self.reduce(a);
        if a.is_zero() {
            BigUint::zero()
        } else {
            self.p.sub_ref(&a)
        }
    }

    /// `a · b mod p`.
    #[must_use]
    pub fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        BigUint::mod_mul(a, b, &self.p)
    }

    /// Multiplicative inverse `a^{-1} mod p`, or `None` if `a ≡ 0`.
    #[must_use]
    pub fn inv(&self, a: &BigUint) -> Option<BigUint> {
        let a = self.reduce(a);
        if a.is_zero() {
            return None;
        }
        mod_inverse(&a, &self.p)
    }

    /// Uniformly random element of `[0, p)`.
    ///
    /// # Panics
    /// Cannot panic: `random_below` only fails on a zero modulus, which
    /// `PrimeField::new` rejects up front. The `expect` is a defensive
    /// compile-time-style assertion of that invariant.
    #[must_use]
    pub fn random<R: Csprng>(&self, rng: &mut R) -> BigUint {
        random_below(rng, &self.p).expect("modulus > 0")
    }
}

/// Mersenne prime `2^127 − 1`. A convenient default for moderate-size
/// secrets: every 16-byte block fits in one field element.
#[must_use]
pub fn mersenne127() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(127);
    v.sub_ref(&BigUint::one())
}

/// Mersenne prime `2^521 − 1`. Useful when the secret is up to 64 bytes.
#[must_use]
pub fn mersenne521() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(521);
    v.sub_ref(&BigUint::one())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> PrimeField {
        PrimeField::new(BigUint::from_u64(257))
    }

    #[test]
    fn add_sub_round_trip() {
        let f = small();
        let a = BigUint::from_u64(123);
        let b = BigUint::from_u64(200);
        let s = f.add(&a, &b);
        assert_eq!(f.sub(&s, &b), a);
        assert_eq!(f.sub(&s, &a), b);
    }

    #[test]
    fn sub_underflow_wraps() {
        let f = small();
        let a = BigUint::from_u64(5);
        let b = BigUint::from_u64(10);
        // 5 − 10 ≡ 252 (mod 257)
        assert_eq!(f.sub(&a, &b), BigUint::from_u64(252));
    }

    #[test]
    fn neg_round_trip() {
        let f = small();
        for i in 0u64..20 {
            let a = BigUint::from_u64(i);
            assert_eq!(f.add(&a, &f.neg(&a)), BigUint::zero());
        }
    }

    #[test]
    fn inv_round_trip() {
        let f = small();
        for i in 1u64..20 {
            let a = BigUint::from_u64(i);
            let inv = f.inv(&a).expect("nonzero invertible mod prime");
            assert_eq!(f.mul(&a, &inv), BigUint::one());
        }
        assert!(f.inv(&BigUint::zero()).is_none());
    }

    #[test]
    fn mersenne127_value() {
        let p = mersenne127();
        assert_eq!(p.bits(), 127);
        // Spot-check: p + 1 == 2^127.
        let next = p.add_ref(&BigUint::one());
        let mut two_pow_127 = BigUint::one();
        two_pow_127.shl_bits(127);
        assert_eq!(next, two_pow_127);
    }
}
