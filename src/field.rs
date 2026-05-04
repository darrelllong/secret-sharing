//! Prime-field arithmetic on top of the sibling crate's `BigUint`.
//!
//! Shamir 1979 places its scheme over `Z/pZ` for a prime `p > max(D, n)`,
//! and the Karnin–Greene–Hellman / McEliece–Sarwate generalizations
//! retain that field (or its extension `GF(p^m)`). All polynomial
//! manipulations in the rest of the crate go through this wrapper so the
//! modulus is fixed once and the operations read directly off the papers.

use crate::primes::{is_probable_prime, mod_inverse, random_below};
use crate::bigint::BigUint;
use crate::csprng::Csprng;

/// Internal discriminator for prime moduli with closed-form reductions.
/// Selected at construction (one BigUint comparison per `new*`); chosen
/// branch of [`PrimeField::mul`] routes through a specialised mul-mod
/// that skips Montgomery setup and limb arithmetic.
#[derive(Clone, Debug)]
enum FieldKind {
    Generic,
    /// `p = 2^127 − 1`. Operands fit in two `u64`s; reduction is one
    /// fold of the high 127 bits into the low 127 bits, plus a final
    /// conditional subtract.
    Mersenne127,
}

/// Prime modulus and the four finite-field operations needed by Shamir,
/// the KGH matrix scheme, and the McEliece–Sarwate decoder.
#[derive(Clone, Debug)]
pub struct PrimeField {
    p: BigUint,
    kind: FieldKind,
}

fn detect_kind(p: &BigUint) -> FieldKind {
    if p == &mersenne127() {
        FieldKind::Mersenne127
    } else {
        FieldKind::Generic
    }
}

impl PrimeField {
    /// Wrap a prime modulus. **Validates primality** via Miller–Rabin
    /// (deterministic for `p < ~2^81`, otherwise probabilistic with
    /// false-positive rate `≤ 4^{-12}`).
    ///
    /// # Panics
    /// Panics if `p ≤ 1` or if `p` fails the Miller–Rabin test.
    /// Use [`Self::new_unchecked`] when the caller has independently
    /// verified primality (e.g. for the bundled Mersenne primes) and
    /// wants to skip the check.
    #[must_use]
    pub fn new(p: BigUint) -> Self {
        assert!(p > BigUint::one(), "modulus must be > 1");
        assert!(
            is_probable_prime(&p),
            "modulus must be prime (Miller–Rabin test)",
        );
        let kind = detect_kind(&p);
        Self { p, kind }
    }

    /// Wrap a modulus *without* primality validation. Use only when
    /// the caller independently knows `p` is prime (e.g. it came from
    /// [`crate::field::mersenne127`] or [`mersenne521`], or from a
    /// trusted public parameter). Mis-use silently produces a non-
    /// field that breaks every security claim in the crate.
    ///
    /// # Panics
    /// Panics if `p ≤ 1`.
    #[must_use]
    pub fn new_unchecked(p: BigUint) -> Self {
        assert!(p > BigUint::one(), "modulus must be > 1");
        let kind = detect_kind(&p);
        Self { p, kind }
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
        match self.kind {
            FieldKind::Mersenne127 => mersenne127_mul(a, b),
            FieldKind::Generic => BigUint::mod_mul(a, b, &self.p),
        }
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

/// `a · b mod (2^127 − 1)` without invoking Montgomery setup or
/// allocating limb scratch. The 254-bit product is computed by a
/// 2 × 2 schoolbook on `u128` partial products; reduction exploits
/// `2^127 ≡ 1 (mod p)` with one fold of bits 127..253 into bits
/// 0..126, a second fold of bit 127 of the resulting 128-bit sum,
/// and one final conditional subtract.
///
/// Inputs whose bit length exceeds 127 take a one-time slow-path
/// reduction via [`BigUint::modulo`] before the fast multiply. The
/// crate's internal callers always feed reduced operands, so this
/// branch is exercised only by direct external callers that handed
/// the field a > 127-bit value.
fn mersenne127_mul(a: &BigUint, b: &BigUint) -> BigUint {
    let p = mersenne127();
    let a128 = if a.bits() <= 127 {
        a.low_u128()
    } else {
        a.modulo(&p).low_u128()
    };
    let b128 = if b.bits() <= 127 {
        b.low_u128()
    } else {
        b.modulo(&p).low_u128()
    };
    BigUint::from_u128(mul_mod_mersenne127(a128, b128))
}

#[inline]
fn mul_mod_mersenne127(a: u128, b: u128) -> u128 {
    // 2 × 2 schoolbook → 256 bits in [r0, r1, r2, r3].
    let al = a as u64;
    let ah = (a >> 64) as u64;
    let bl = b as u64;
    let bh = (b >> 64) as u64;

    let p00 = u128::from(al) * u128::from(bl);
    let p01 = u128::from(al) * u128::from(bh);
    let p10 = u128::from(ah) * u128::from(bl);
    let p11 = u128::from(ah) * u128::from(bh);

    let r0 = p00 as u64;
    // mid sums the column at position 64; ≤ 3 · (2^64 − 1) so fits in u128.
    let mid = (p00 >> 64) + u128::from(p01 as u64) + u128::from(p10 as u64);
    let r1 = mid as u64;
    let mid_hi = (mid >> 64) + (p01 >> 64) + (p10 >> 64) + u128::from(p11 as u64);
    let r2 = mid_hi as u64;
    let r3 = ((mid_hi >> 64) + (p11 >> 64)) as u64;

    // Mersenne fold: 2^127 ≡ 1 mod p, so bits 127..253 add into bits 0..126.
    let low = u128::from(r0) | (u128::from(r1 & 0x7FFF_FFFF_FFFF_FFFF) << 64);
    let high_lo = (r1 >> 63) | (r2 << 1);
    let high_hi = (r2 >> 63) | (r3 << 1);
    let high = u128::from(high_lo) | (u128::from(high_hi) << 64);
    let sum = low + high; // < 2 · 2^127 = 2^128, fits in u128

    // Second fold: bit 127 of sum (since sum can still exceed p).
    let mask127 = (1u128 << 127) - 1; // = p
    let folded = (sum & mask127) + (sum >> 127);

    // folded ∈ [0, p + 1]; one final conditional subtract.
    if folded >= mask127 { folded - mask127 } else { folded }
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
    #[should_panic(expected = "modulus must be prime")]
    fn new_rejects_composite_modulus() {
        // A composite modulus has zero divisors, so `inv` would silently
        // fail on shares landing in the wrong residue class; the safe
        // constructor must screen p with primality before returning.
        // 255 = 3 · 5 · 17.
        let _ = PrimeField::new(BigUint::from_u64(255));
    }

    #[test]
    fn new_unchecked_skips_primality_check() {
        // The escape hatch is documented as caller's responsibility.
        // Construction succeeds even on a composite modulus; security
        // claims do not hold until the caller has independently
        // verified primality.
        let f = PrimeField::new_unchecked(BigUint::from_u64(255));
        assert_eq!(f.modulus(), &BigUint::from_u64(255));
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

    #[test]
    fn mersenne127_mul_matches_generic_on_random_fuzz() {
        // The fast Mersenne path must agree with the generic Montgomery
        // mul on every input; exercise both endpoints of the operand
        // range (low limb only, both limbs full, near-p) plus a uniform
        // sample from the whole field.
        use crate::csprng::ChaCha20Rng;
        let p = mersenne127();
        let fast = PrimeField::new_unchecked(p.clone());
        // Force the generic path by wrapping a clone in an unchecked
        // field with a kind-blind detect — easiest is to reach into the
        // module: build a Generic-kind field directly.
        let generic = PrimeField {
            p: p.clone(),
            kind: FieldKind::Generic,
        };

        // Edge cases.
        let edges = [
            BigUint::zero(),
            BigUint::one(),
            BigUint::from_u64(2),
            p.sub_ref(&BigUint::one()), // p − 1
            p.clone(),                  // input == p reduces to 0
        ];
        for a in &edges {
            for b in &edges {
                assert_eq!(fast.mul(a, b), generic.mul(a, b), "mismatch on edge case");
            }
        }

        // Random fuzz.
        let mut r = ChaCha20Rng::from_seed(&[0x4Au8; 32]);
        for _ in 0..256 {
            let a = fast.random(&mut r);
            let b = fast.random(&mut r);
            assert_eq!(fast.mul(&a, &b), generic.mul(&a, &b));
        }
    }

    #[test]
    fn mersenne127_mul_handles_unreduced_inputs() {
        // Operands whose bit length exceeds 127 must take the slow-path
        // reduction inside mersenne127_mul and still match the generic
        // mul path.
        let p = mersenne127();
        let fast = PrimeField::new_unchecked(p.clone());
        let generic = PrimeField {
            p: p.clone(),
            kind: FieldKind::Generic,
        };
        // a = p + 5 (128 bits), b = 2p + 3 (128 bits).
        let a = p.add_ref(&BigUint::from_u64(5));
        let b = p.add_ref(&p).add_ref(&BigUint::from_u64(3));
        assert_eq!(fast.mul(&a, &b), generic.mul(&a, &b));
    }
}
