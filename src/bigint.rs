//! Self-contained bigint foundation, copied verbatim from
//! `cryptography/src/public_key/bigint.rs` so this crate has no
//! external arithmetic dependency. The only local change is inlining
//! `zeroize_slice` so the `BigUint` Drop impl does not pull in the
//! sibling crate's `ct` module.
//!
//! Representation: little-endian `u64` limbs. Algorithms — schoolbook
//! multiplication, Karatsuba above a threshold, bitwise long division —
//! are intentionally simple so the scheme code reads as the published
//! formulas with no arithmetic backend in the way.

use core::cmp::Ordering;
use core::sync::atomic::{compiler_fence, Ordering as AtomicOrdering};

/// Zero a slice with volatile writes the optimiser is not allowed to
/// elide. Local copy of `cryptography::ct::zeroize_slice`. No longer
/// invoked from `BigUint::drop` (that path scrubs the full capacity
/// directly, not just the live `[0..len]` slice), but kept as a
/// utility for any future caller that wants to scrub a fixed-len
/// stack array.
#[allow(dead_code)]
fn zeroize_slice<T: Copy + Default>(slice: &mut [T]) {
    for item in slice.iter_mut() {
        // SAFETY: `item` is a valid `&mut T` for the duration of this
        // call. Volatile-storing through the raw pointer prevents the
        // optimiser from eliding the write.
        unsafe {
            core::ptr::write_volatile(core::ptr::from_mut::<T>(item), T::default());
        }
    }
    compiler_fence(AtomicOrdering::SeqCst);
}

// Heuristic crossover where the recursive split starts beating schoolbook in
// this pure-Rust implementation on our benchmark hardware.
const KARATSUBA_THRESHOLD_LIMBS: usize = 32;
// Limit highly lopsided splits; beyond this ratio the extra recursion/temporary
// cost usually outweighs Karatsuba's multiplication count reduction.
const KARATSUBA_MAX_IMBALANCE: usize = 2;

/// Sign of a [`BigInt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sign {
    /// Strictly positive value.
    Positive,
    /// Strictly negative value.
    Negative,
    /// Zero.
    Zero,
}

/// Unsigned multiprecision integer stored as little-endian `u64` limbs.
///
/// Both `PartialEq` and `Debug` are implemented manually to avoid
/// leaking secret-derived limbs:
///
/// - `PartialEq::eq` compares all limbs in a single OR-fold so the
///   timing depends only on the larger of the two limb counts (which
///   is a public function of the modulus, not of the secret bits).
/// - `Debug::fmt` prints `BigUint(<elided>)`. Any panic backtrace,
///   `dbg!`, `assert_eq!` failure message, or log statement that
///   formats a `BigUint` reveals nothing about the integer's value.
///
/// The Drop impl below volatile-zeroes the entire allocated capacity
/// of the limb buffer (not just `[0..len]`), so high-significance
/// limbs from intermediate products are not left in heap residue.
#[derive(Clone)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl Eq for BigUint {}

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        // Constant-in-limb-count OR-fold. Pad the shorter operand
        // with zero limbs (`limb_or_zero`), then accumulate `lhs ^
        // rhs` across every position without short-circuiting.
        let n = self.limbs.len().max(other.limbs.len());
        let mut acc: u64 = 0;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            acc |= a ^ b;
        }
        acc == 0
    }
}

impl core::fmt::Debug for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BigUint(<elided>)")
    }
}

/// Signed multiprecision integer used by later public-key helpers.
/// `Debug` and `PartialEq` are derived now that `BigUint` itself uses
/// constant-time comparison and elided Debug output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigInt {
    sign: Sign,
    magnitude: BigUint,
}

/// Montgomery arithmetic context for a fixed odd modulus.
///
/// Public-key schemes spend most of their time doing repeated modular
/// multiplication under one long-lived odd modulus. Precomputing the
/// Montgomery constants once avoids paying the setup cost on every multiply
/// while keeping the scheme code readable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MontgomeryCtx {
    modulus: BigUint,
    // n0_inv = -n^{-1} mod 2^64 (Montgomery reduction coefficient).
    n0_inv: u64,
    // R^2 mod n with R = 2^(64 * limbs(n)): conversion factor into Montgomery form.
    r2_mod: BigUint,
    // 1 encoded in Montgomery form, i.e. R mod n.
    one_mont: BigUint,
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Ordering assumes normalized limb vectors (no most-significant zero
        // limbs). All constructors/arithmetic paths call `normalize()`.
        debug_assert!(
            self.limbs.last().copied() != Some(0),
            "BigUint invariant: no leading zero limbs",
        );
        debug_assert!(
            other.limbs.last().copied() != Some(0),
            "BigUint invariant: no leading zero limbs",
        );
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        for (&lhs, &rhs) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match lhs.cmp(&rhs) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }

        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BigUint {
    /// Construct zero.
    #[must_use]
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    /// Construct one.
    #[must_use]
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Construct from a machine word.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![value] }
        }
    }

    /// Construct from a `u128`.
    ///
    /// # Panics
    ///
    /// Panics only if the internal limb split invariants fail unexpectedly.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return Self::zero();
        }

        let lo =
            u64::try_from(value & u128::from(u64::MAX)).expect("low 64 bits always fit into u64");
        let hi = u64::try_from(value >> 64).expect("high 64 bits always fit into u64");
        if hi == 0 {
            Self { limbs: vec![lo] }
        } else {
            Self {
                limbs: vec![lo, hi],
            }
        }
    }

    /// Decode big-endian bytes.
    ///
    /// Internally, limb 0 always stores the least-significant 64 bits.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }

        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        let mut acc = 0u64;
        let mut shift = 0u32;

        // Walk bytes from least-significant (last byte of the big-endian input)
        // to most-significant, packing eight bytes at a time into a 64-bit limb.
        // When `shift` reaches 64, the current limb is full — push it and start
        // the next one.  Any remaining bytes at the end form a partial limb.
        for &byte in bytes.iter().rev() {
            acc |= u64::from(byte) << shift;
            shift += 8;
            if shift == 64 {
                limbs.push(acc);
                acc = 0;
                shift = 0;
            }
        }

        if shift != 0 {
            limbs.push(acc);
        }

        let mut out = Self { limbs };
        out.normalize();
        out
    }

    /// Encode as big-endian bytes without leading zero bytes.
    ///
    /// Internally, limb 0 stores the least-significant 64 bits, so encoding
    /// walks the limbs in reverse order and strips only the leading zero bytes
    /// introduced by the fixed-width `u64` representation.
    ///
    /// # Panics
    ///
    /// Panics only if the internal representation is corrupt and a non-zero
    /// value contains no non-zero bytes.
    #[must_use]
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }

        let first_nonzero = out
            .iter()
            .position(|&byte| byte != 0)
            .expect("non-zero bigint must encode to at least one non-zero byte");
        out.drain(0..first_nonzero);
        out
    }

    /// Big-endian serialization at a caller-supplied fixed byte width
    /// — pads or truncates to exactly `byte_width` bytes.
    ///
    /// Used by [`crate::secure::ct_eq_biguint_padded`] to avoid the
    /// leading-non-zero-byte scan inside `to_be_bytes`, which would
    /// otherwise leak the operand's bit length through scan latency.
    ///
    /// **Residual side-channel.** The implementation copies the
    /// operand's limb buffer into a `byte_width`-sized scratch via
    /// `core::ptr::copy_nonoverlapping`, copying exactly
    /// `min(byte_width.div_ceil(8), self.limbs.len())` limbs. That
    /// copy length depends on the operand's normalised limb count —
    /// itself a function of the operand's high-bit position. The
    /// leak is an *upper bound on the secret bit length*, granular
    /// to one limb (8 bytes); compare with `to_be_bytes`'s byte-
    /// granular leading-zero scan. For schemes where both operands
    /// are reduced field elements (the modulus is public, so all
    /// reduced elements share the same limb count), the limb count
    /// is constant and the residual leak vanishes.
    ///
    /// # Panics
    /// Panics if the value's actual byte length exceeds `byte_width`
    /// — i.e. some limb beyond index `byte_width.div_ceil(8) − 1` is
    /// non-zero, or the trim-to-`byte_width` step would discard a
    /// non-zero leading byte. `byte_width = 0` is legal only for the
    /// zero value.
    #[must_use]
    pub fn to_be_bytes_padded(&self, byte_width: usize) -> Vec<u8> {
        if byte_width == 0 {
            assert!(self.is_zero(), "value does not fit in 0 bytes");
            return Vec::new();
        }
        let limb_width = byte_width.div_ceil(8);
        // Any high limb beyond `limb_width` must be zero — otherwise
        // the value spills past `byte_width` bytes.
        for i in limb_width..self.limbs.len() {
            assert!(
                self.limbs[i] == 0,
                "value does not fit in {byte_width} bytes",
            );
        }
        // Materialise a `limb_width`-sized limb scratch by a single
        // memcpy of the live limbs (the `copy_n` count is the only
        // operand-dependent quantity — see the residual-leak note in
        // the docstring). The tail of the scratch stays zero.
        let mut padded_limbs = vec![0u64; limb_width];
        let copy_n = self.limbs.len().min(limb_width);
        if copy_n > 0 {
            // SAFETY: `self.limbs.as_ptr()` is valid for `self.limbs.len()`
            // contiguous u64 reads; `copy_n ≤ self.limbs.len()`.
            // `padded_limbs.as_mut_ptr()` is valid for `limb_width`
            // contiguous u64 writes; `copy_n ≤ limb_width`. Source
            // and destination are non-overlapping (separate Vec
            // allocations).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.limbs.as_ptr(),
                    padded_limbs.as_mut_ptr(),
                    copy_n,
                );
            }
        }
        // Convert little-endian limb scratch to big-endian byte buffer.
        // The number of iterations is fixed at `limb_width`, no per-
        // iteration branch on operand limb count.
        let mut out = vec![0u8; limb_width * 8];
        for (i, limb) in padded_limbs.iter().enumerate().take(limb_width) {
            let dst_end = limb_width * 8 - i * 8;
            let dst_start = dst_end - 8;
            out[dst_start..dst_end].copy_from_slice(&limb.to_be_bytes());
        }
        // Scrub the limb scratch — it holds a verbatim copy of secret
        // limbs and is about to be dropped.
        for w in padded_limbs.iter_mut() {
            // SAFETY: `w` is a valid `&mut u64`.
            unsafe { core::ptr::write_volatile(w, 0u64) };
        }
        compiler_fence(AtomicOrdering::SeqCst);
        // If the rounded-up limb width gave more bytes than requested,
        // trim the leading bytes. Those bytes MUST be zero — otherwise
        // the value did not fit in `byte_width` bytes.
        if out.len() > byte_width {
            let trim = out.len() - byte_width;
            assert!(
                out[..trim].iter().all(|&b| b == 0),
                "value does not fit in {byte_width} bytes",
            );
            out.drain(..trim);
        }
        out
    }

    /// Return the low 128 bits as a `u128`. Used by hot-path field
    /// implementations that have already pinned their operand range
    /// (e.g. Mersenne-127 reduction). Bits beyond position 127 are
    /// silently dropped.
    #[must_use]
    pub fn low_u128(&self) -> u128 {
        let lo = self.limbs.first().copied().unwrap_or(0);
        let hi = self.limbs.get(1).copied().unwrap_or(0);
        u128::from(lo) | (u128::from(hi) << 64)
    }

    /// Return whether the value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Return whether the value is odd.
    #[must_use]
    pub fn is_odd(&self) -> bool {
        !self.is_zero() && (self.limbs[0] & 1) == 1
    }

    /// Return whether the value is exactly one.
    #[must_use]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    /// Number of significant bits.
    ///
    /// # Panics
    ///
    /// Panics only if the internal representation is corrupt and a non-zero
    /// value contains no limbs.
    #[must_use]
    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let top = *self
            .limbs
            .last()
            .expect("non-zero bigint has at least one limb");
        let top_bits = (u64::BITS - top.leading_zeros()) as usize;
        (self.limbs.len() - 1) * 64 + top_bits
    }

    /// Integer square root: the largest `r` such that `r^2 <= self`.
    #[must_use]
    pub fn sqrt_floor(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        if self.is_one() {
            return Self::one();
        }

        let mut low = Self::one();
        let mut high = Self::zero();
        // Choose `high` so the search starts with `low^2 <= self < high^2`.
        // Setting bit `ceil(bits(self) / 2)` makes
        // `high = 2^ceil(bits(self)/2)`, so `high^2 >= 2^bits(self) > self`.
        // That gives the binary search a proved upper bound from the start.
        high.set_bit(self.bits().div_ceil(2));

        while {
            let next_low = low.add_ref(&Self::one());
            next_low < high
        } {
            let mut middle = low.add_ref(&high);
            middle.shr1();
            let square = middle.square_ref();
            if square <= *self {
                low = middle;
            } else {
                high = middle;
            }
        }

        low
    }

    /// Test bit `index`.
    #[must_use]
    pub fn bit(&self, index: usize) -> bool {
        let limb = index / 64;
        let shift = index % 64;
        if limb >= self.limbs.len() {
            false
        } else {
            ((self.limbs[limb] >> shift) & 1) == 1
        }
    }

    /// Set bit `index`.
    pub fn set_bit(&mut self, index: usize) {
        let limb = index / 64;
        let shift = index % 64;
        if self.limbs.len() <= limb {
            self.limbs.resize(limb + 1, 0);
        }
        self.limbs[limb] |= 1u64 << shift;
    }

    /// Add another bigint in place.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `u128` accumulator cannot be split back
    /// into `u64` limbs, which would indicate a logic error.
    pub fn add_assign_ref(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }

        if self.limbs.len() < other.limbs.len() {
            self.limbs.resize(other.limbs.len(), 0);
        }

        let mut carry = 0u128;
        for i in 0..other.limbs.len() {
            let sum = u128::from(self.limbs[i]) + u128::from(other.limbs[i]) + carry;
            self.limbs[i] = low_u64(sum);
            carry = sum >> 64;
        }

        let mut i = other.limbs.len();
        while carry != 0 && i < self.limbs.len() {
            let sum = u128::from(self.limbs[i]) + carry;
            self.limbs[i] = low_u64(sum);
            carry = sum >> 64;
            i += 1;
        }

        if carry != 0 {
            self.limbs
                .push(u64::try_from(carry).expect("final carry from u64 addition is at most 1"));
        }
    }

    /// Return `self + other`.
    #[must_use]
    pub fn add_ref(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.add_assign_ref(other);
        out
    }

    /// Subtract another bigint in place. Panics if `self < other`.
    ///
    /// # Panics
    ///
    /// Panics if `self < other`.
    pub fn sub_assign_ref(&mut self, other: &Self) {
        assert!((*self).cmp(other) != Ordering::Less, "BigUint underflow");
        if other.is_zero() {
            return;
        }

        let mut borrow = 0u128;
        for i in 0..self.limbs.len() {
            let lhs = u128::from(self.limbs[i]);
            let rhs = if i < other.limbs.len() {
                u128::from(other.limbs[i])
            } else {
                0
            };

            let subtrahend = rhs + borrow;
            if lhs >= subtrahend {
                self.limbs[i] = low_u64(lhs - subtrahend);
                borrow = 0;
            } else {
                self.limbs[i] = low_u64((1u128 << 64) + lhs - subtrahend);
                borrow = 1;
            }
        }

        self.normalize();
    }

    /// Return `self - other`. Panics if `self < other`.
    #[must_use]
    pub fn sub_ref(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.sub_assign_ref(other);
        out
    }

    /// Multiply two big integers.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `u128` accumulators cannot be split back
    /// into `u64` limbs, which would indicate a logic error.
    #[must_use]
    pub fn mul_ref(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        if Self::should_use_karatsuba(self, other) {
            return self.mul_karatsuba_ref(other);
        }

        Self::mul_schoolbook_ref(self, other)
    }

    /// Multiply a value by itself.
    #[must_use]
    pub fn square_ref(&self) -> Self {
        self.mul_ref(self)
    }

    fn split_at_limb(&self, split: usize) -> (Self, Self) {
        let low_end = split.min(self.limbs.len());
        let mut low = Self {
            limbs: self.limbs[..low_end].to_vec(),
        };
        low.normalize();

        if split >= self.limbs.len() {
            return (low, Self::zero());
        }

        let mut high = Self {
            limbs: self.limbs[split..].to_vec(),
        };
        high.normalize();
        (low, high)
    }

    fn should_use_karatsuba(lhs: &Self, rhs: &Self) -> bool {
        let short = lhs.limbs.len().min(rhs.limbs.len());
        let long = lhs.limbs.len().max(rhs.limbs.len());
        short >= KARATSUBA_THRESHOLD_LIMBS && long <= short * KARATSUBA_MAX_IMBALANCE
    }

    fn mul_karatsuba_ref(&self, other: &Self) -> Self {
        let split = self.limbs.len().max(other.limbs.len()) / 2;
        if split == 0 {
            return Self::mul_schoolbook_ref(self, other);
        }

        let (a0, a1) = self.split_at_limb(split);
        let (b0, b1) = other.split_at_limb(split);
        if a1.is_zero() || b1.is_zero() {
            return Self::mul_schoolbook_ref(self, other);
        }

        let z0 = a0.mul_ref(&b0);
        let z2 = a1.mul_ref(&b1);

        let a_sum = a0.add_ref(&a1);
        let b_sum = b0.add_ref(&b1);
        let mut z1 = a_sum.mul_ref(&b_sum);
        z1.sub_assign_ref(&z0);
        z1.sub_assign_ref(&z2);

        let mut out = z0;
        z1.shl_bits(split * 64);
        out.add_assign_ref(&z1);

        let mut z2_shifted = z2;
        z2_shifted.shl_bits(split * 128);
        out.add_assign_ref(&z2_shifted);
        out
    }

    fn mul_schoolbook_ref(lhs: &Self, rhs: &Self) -> Self {
        let mut out = vec![0u64; lhs.limbs.len() + rhs.limbs.len()];
        for (i, &lhs_limb) in lhs.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &rhs_limb) in rhs.limbs.iter().enumerate() {
                let idx = i + j;
                let acc =
                    u128::from(out[idx]) + u128::from(lhs_limb) * u128::from(rhs_limb) + carry;
                out[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + rhs.limbs.len();
            while carry != 0 {
                let acc = u128::from(out[idx]) + carry;
                out[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        let mut result = Self { limbs: out };
        // A normalized non-zero multiplicand and multiplier cannot produce a
        // spuriously zero high limb except through the carry chain itself, so
        // one post-pass normalization is enough.
        result.normalize();
        result
    }

    /// Shift left by one bit.
    pub fn shl1(&mut self) {
        if self.is_zero() {
            return;
        }

        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }

        if carry != 0 {
            self.limbs.push(carry);
        }
        // A left shift on an already-normalized value cannot introduce a
        // leading zero limb, so no normalize() pass is required here.
    }

    /// Shift right by one bit.
    pub fn shr1(&mut self) {
        if self.is_zero() {
            return;
        }

        let mut carry = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let next = (*limb & 1) << 63;
            *limb = (*limb >> 1) | carry;
            carry = next;
        }

        self.normalize();
    }

    /// XOR another bigint into `self` in place (GF(2^m) field addition).
    ///
    /// Extends `self.limbs` with zeros if shorter than `other.limbs`, then
    /// XORs each corresponding limb pair.  The result is normalized to strip
    /// any leading zero limbs produced by XOR cancellation.
    pub fn bitxor_assign(&mut self, other: &BigUint) {
        if self.limbs.len() < other.limbs.len() {
            self.limbs.resize(other.limbs.len(), 0);
        }
        for (s, &o) in self.limbs.iter_mut().zip(other.limbs.iter()) {
            *s ^= o;
        }
        self.normalize();
    }

    /// Left-shift by `n` bits.
    ///
    /// Implemented as `n / 64` full-limb shifts (inserting zero limbs at the
    /// low end) followed by up to 63 single-bit left shifts, which avoids
    /// undefined behaviour from shifting a `u64` by 64 or more positions.
    pub fn shl_bits(&mut self, n: usize) {
        if self.is_zero() || n == 0 {
            return;
        }
        let limb_shifts = n / 64;
        let bit_shifts = n % 64;
        // Full-limb shift: prepend zeros at the low (index 0) end.
        if limb_shifts > 0 {
            let mut new_limbs = vec![0u64; limb_shifts];
            new_limbs.extend_from_slice(&self.limbs);
            self.limbs = new_limbs;
        }
        // Remaining bit-level shift (0 < bit_shifts < 64, so 64 - bit_shifts is safe).
        if bit_shifts > 0 {
            let mut carry = 0u64;
            for limb in &mut self.limbs {
                let next_carry = *limb >> (64 - bit_shifts);
                *limb = (*limb << bit_shifts) | carry;
                carry = next_carry;
            }
            if carry != 0 {
                self.limbs.push(carry);
            }
        }
        // A left-shift on a normalized value cannot introduce a leading zero
        // limb, so no normalize() pass is needed here.
    }

    /// Compute `self mod modulus`.
    #[must_use]
    pub fn modulo(&self, modulus: &Self) -> Self {
        let (_, remainder) = self.div_rem(modulus);
        remainder
    }

    /// Compute the remainder modulo a machine word.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn rem_u64(&self, modulus: u64) -> u64 {
        assert!(modulus != 0, "division by zero");
        if self.is_zero() {
            return 0;
        }

        let mut remainder = 0u128;
        // Horner's method in base `2^64`: carry the remainder of the already
        // processed high limbs, then append the next limb as the next base
        // digit before reducing again.
        for &limb in self.limbs.iter().rev() {
            let acc = (remainder << 64) | u128::from(limb);
            remainder = acc % u128::from(modulus);
        }

        u64::try_from(remainder).expect("remainder modulo u64 fits into u64")
    }

    /// Compute `(lhs * rhs) mod modulus`.
    ///
    /// Odd moduli use a fresh Montgomery context so the common public-key path
    /// avoids the division-heavy fallback. Even moduli keep the old
    /// double-and-add reducer because Montgomery requires an odd modulus.
    /// Rewriting one multiplicand as `y - 1` plus one extra add can change the
    /// operand parity, but it does not change the modulus parity; the core
    /// Montgomery requirement is `gcd(R, n) = 1`, so an even modulus still
    /// needs a non-Montgomery path.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn mod_mul(lhs: &Self, rhs: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        if modulus == &Self::one() {
            return Self::zero();
        }
        if let Some(ctx) = MontgomeryCtx::new(modulus) {
            return ctx.mul(lhs, rhs);
        }
        Self::mod_mul_plain(lhs, rhs, modulus)
    }

    /// Compute `(lhs * rhs) mod modulus` using the simple double-and-add
    /// fallback implementation.
    ///
    /// The result is mathematically correct, but repeated division-based
    /// reduction makes it much slower than Montgomery multiplication for the
    /// odd moduli that dominate public-key code. The current scheme code only
    /// reaches this path for even moduli, so it remains as the explicit
    /// fallback and readable reference for non-Montgomery cases.
    #[must_use]
    pub(crate) fn mod_mul_plain(lhs: &Self, rhs: &Self, modulus: &Self) -> Self {
        if lhs.is_zero() || rhs.is_zero() {
            return Self::zero();
        }

        let mut a = lhs.modulo(modulus);
        let mut b = rhs.clone();
        let mut out = Self::zero();
        while !b.is_zero() {
            if b.is_odd() {
                out = out.add_ref(&a).modulo(modulus);
            }
            a = a.add_ref(&a).modulo(modulus);
            b.shr1();
        }
        out
    }

    /// Return `(quotient, remainder)` for Euclidean division. Panics on zero divisor.
    ///
    /// # Panics
    ///
    /// Panics if `divisor == 0`.
    #[must_use]
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "division by zero");
        if self.cmp(divisor) == Ordering::Less {
            return (Self::zero(), self.clone());
        }

        let mut quotient = Self::zero();
        let mut remainder = Self::zero();

        // Bit-by-bit long division. `remainder` holds the partially
        // reconstructed dividend prefix; each step shifts it left, appends the
        // next source bit, and subtracts the divisor if the prefix is already
        // large enough.
        for bit in (0..self.bits()).rev() {
            remainder.shl1();
            if self.bit(bit) {
                if remainder.is_zero() {
                    remainder.limbs.push(1);
                } else {
                    remainder.limbs[0] |= 1;
                }
            }

            if remainder.cmp(divisor) != Ordering::Less {
                remainder.sub_assign_ref(divisor);
                quotient.set_bit(bit);
            }
        }

        (quotient, remainder)
    }

    fn normalize(&mut self) {
        // Canonical representation invariant:
        // - zero has `limbs.is_empty()`
        // - non-zero values have a non-zero top limb
        while self.limbs.last().copied() == Some(0) {
            self.limbs.pop();
        }
    }

    fn limb_or_zero(&self, idx: usize) -> u64 {
        self.limbs.get(idx).copied().unwrap_or(0)
    }

    fn montgomery_mul_odd_with_workspace(
        lhs: &Self,
        rhs: &Self,
        modulus: &Self,
        n0_inv: u64,
        workspace: &mut Vec<u64>,
    ) -> Self {
        debug_assert!(modulus.is_odd(), "Montgomery path requires an odd modulus");
        let width = modulus.limbs.len();
        // `2 * width` limbs hold the schoolbook product. The extra two limbs
        // are carry headroom so neither pass can run off the end.
        let needed = width * 2 + 2;
        if workspace.len() != needed {
            workspace.resize(needed, 0);
        } else {
            workspace.fill(0);
        }

        // First pass: accumulate the ordinary product `lhs * rhs`.
        for i in 0..width {
            let lhs_limb = lhs.limb_or_zero(i);
            let mut carry = 0u128;
            for j in 0..width {
                let idx = i + j;
                let acc = u128::from(workspace[idx])
                    + u128::from(lhs_limb) * u128::from(rhs.limb_or_zero(j))
                    + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + width;
            while carry != 0 {
                let acc = u128::from(workspace[idx]) + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        // Second pass: Montgomery reduction. Choose `m` so the current low
        // limb cancels modulo `2^64`, then add `m * modulus`. Each round
        // zeros one more low limb; after `width` rounds the discarded low half
        // accounts for the implicit division by `R = 2^(64w)`, so the high
        // half is `lhs * rhs * R^-1 mod n`. That is why copying out
        // `workspace[width..]` yields the Montgomery product.
        for i in 0..width {
            let m = workspace[i].wrapping_mul(n0_inv);
            let mut carry = 0u128;
            for j in 0..width {
                let idx = i + j;
                let acc = u128::from(workspace[idx])
                    + u128::from(m) * u128::from(modulus.limb_or_zero(j))
                    + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
            }

            let mut idx = i + width;
            while carry != 0 {
                let acc = u128::from(workspace[idx]) + carry;
                workspace[idx] = low_u64(acc);
                carry = acc >> 64;
                idx += 1;
            }
        }

        let mut out = Self {
            limbs: workspace[width..=(width * 2)].to_vec(),
        };
        out.normalize();
        // Montgomery reduction leaves a value in `[0, 2n)`, so at most one
        // subtraction is needed to return to the canonical residue range.
        if out >= *modulus {
            out.sub_assign_ref(modulus);
        }
        out
    }
}

impl MontgomeryCtx {
    fn encode_with_workspace(&self, value: &BigUint, workspace: &mut Vec<u64>) -> BigUint {
        if value.is_zero() {
            return BigUint::zero();
        }

        BigUint::montgomery_mul_odd_with_workspace(
            &value.modulo(&self.modulus),
            &self.r2_mod,
            &self.modulus,
            self.n0_inv,
            workspace,
        )
    }

    fn decode_with_workspace(&self, value: &BigUint, workspace: &mut Vec<u64>) -> BigUint {
        BigUint::montgomery_mul_odd_with_workspace(
            value,
            &BigUint::one(),
            &self.modulus,
            self.n0_inv,
            workspace,
        )
    }

    fn pow_encoded_with_workspace(
        &self,
        base_mont: &BigUint,
        exponent: &BigUint,
        workspace: &mut Vec<u64>,
    ) -> BigUint {
        if self.modulus == BigUint::one() {
            return BigUint::zero();
        }

        let mut result = self.one_mont.clone();
        let mut power = base_mont.clone();

        for bit in 0..exponent.bits() {
            if exponent.bit(bit) {
                result = BigUint::montgomery_mul_odd_with_workspace(
                    &result,
                    &power,
                    &self.modulus,
                    self.n0_inv,
                    workspace,
                );
            }
            power = BigUint::montgomery_mul_odd_with_workspace(
                &power,
                &power,
                &self.modulus,
                self.n0_inv,
                workspace,
            );
        }

        self.decode_with_workspace(&result, workspace)
    }

    /// Build a Montgomery context for a non-zero odd modulus.
    #[must_use]
    pub fn new(modulus: &BigUint) -> Option<Self> {
        if modulus.is_zero() || !modulus.is_odd() {
            return None;
        }

        let n0_inv = montgomery_n0_inv(modulus.limbs[0]);

        // With `w` limbs, Montgomery arithmetic uses `R = 2^(64w)`. `R^2 mod
        // n` is the standard conversion factor for entering the Montgomery
        // domain because `montgomery_mul(a, R^2) = a * R^2 * R^-1 = aR`, the
        // Montgomery encoding of the ordinary residue `a`.
        let mut r2 = BigUint::zero();
        r2.set_bit(modulus.limbs.len() * 128);
        let r2_mod = r2.modulo(modulus);

        // `R mod n` is the Montgomery encoding of 1, stored so exponentiation
        // can start its accumulator in the correct domain.
        let mut r = BigUint::zero();
        r.set_bit(modulus.limbs.len() * 64);
        let one_mont = r.modulo(modulus);

        Some(Self {
            modulus: modulus.clone(),
            n0_inv,
            r2_mod,
            one_mont,
        })
    }

    /// Return the odd modulus this context was built for.
    #[must_use]
    pub fn modulus(&self) -> &BigUint {
        &self.modulus
    }

    /// Convert an ordinary residue into Montgomery form.
    #[must_use]
    pub fn encode(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        self.encode_with_workspace(value, &mut workspace)
    }

    /// Convert a Montgomery residue back to the ordinary representation.
    #[must_use]
    pub fn decode(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        self.decode_with_workspace(value, &mut workspace)
    }

    /// Multiply two ordinary residues modulo the context modulus.
    #[must_use]
    pub fn mul(&self, lhs: &BigUint, rhs: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let lhs_mont = self.encode_with_workspace(lhs, &mut workspace);
        let rhs_mont = self.encode_with_workspace(rhs, &mut workspace);
        let product_mont = BigUint::montgomery_mul_odd_with_workspace(
            &lhs_mont,
            &rhs_mont,
            &self.modulus,
            self.n0_inv,
            &mut workspace,
        );
        self.decode_with_workspace(&product_mont, &mut workspace)
    }

    /// Square one ordinary residue modulo the context modulus.
    #[must_use]
    pub fn square(&self, value: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let value_mont = self.encode_with_workspace(value, &mut workspace);
        let square_mont = BigUint::montgomery_mul_odd_with_workspace(
            &value_mont,
            &value_mont,
            &self.modulus,
            self.n0_inv,
            &mut workspace,
        );
        self.decode_with_workspace(&square_mont, &mut workspace)
    }

    /// Compute `base^exponent mod modulus` inside the context.
    #[must_use]
    pub fn pow(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        let base_mont = self.encode_with_workspace(&base.modulo(&self.modulus), &mut workspace);
        self.pow_encoded_with_workspace(&base_mont, exponent, &mut workspace)
    }

    /// Compute `base^exponent mod modulus` with `base` already in Montgomery form.
    ///
    /// This is useful when callers reuse the same base and can cache the
    /// encoded value once.
    #[must_use]
    pub fn pow_encoded(&self, base_mont: &BigUint, exponent: &BigUint) -> BigUint {
        let mut workspace = Vec::new();
        self.pow_encoded_with_workspace(base_mont, exponent, &mut workspace)
    }
}

impl Drop for BigUint {
    fn drop(&mut self) {
        // BigUint backs private exponents, prime factors, polynomial
        // coefficients, and Lagrange intermediates. Volatile-zero the
        // ENTIRE allocated capacity of the limb vector — not just
        // `[0..len]` — because intermediate products and `normalize()`
        // truncations leave high-significance secret limbs in the
        // tail `[len..capacity)`, which the regular `zeroize_slice`
        // (which walks `as_mut_slice()` = `[0..len]`) misses.
        let cap = self.limbs.capacity();
        if cap > 0 {
            let raw = self.limbs.as_mut_ptr();
            for i in 0..cap {
                // SAFETY: i ∈ [0, cap) addresses a u64 inside the
                // allocation we own; volatile writes are sound.
                unsafe { core::ptr::write_volatile(raw.add(i), 0u64) };
            }
            compiler_fence(AtomicOrdering::SeqCst);
        }
    }
}

#[inline]
fn low_u64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).expect("masked low 64 bits always fit into u64")
}

fn montgomery_n0_inv(n0: u64) -> u64 {
    debug_assert!(n0 & 1 == 1, "Montgomery path requires an odd modulus");
    // Newton iteration in Z_(2^64): each step doubles the number of correct
    // low bits in the inverse of `n0`. Six iterations are enough to converge
    // to the full 64-bit inverse, and Montgomery reduction wants `-n0^-1`.
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

impl BigInt {
    /// Construct zero.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            sign: Sign::Zero,
            magnitude: BigUint::zero(),
        }
    }

    /// Construct from an explicit sign and magnitude.
    #[must_use]
    pub fn from_parts(sign: Sign, magnitude: BigUint) -> Self {
        if magnitude.is_zero() {
            return Self::zero();
        }

        let canonical_sign = match sign {
            Sign::Zero => Sign::Positive,
            other => other,
        };

        Self {
            sign: canonical_sign,
            magnitude,
        }
    }

    /// Construct a non-negative signed integer from an unsigned value.
    #[must_use]
    pub fn from_biguint(magnitude: BigUint) -> Self {
        Self::from_parts(Sign::Positive, magnitude)
    }

    /// Return the sign.
    #[must_use]
    pub fn sign(&self) -> Sign {
        self.sign
    }

    /// Return the absolute value.
    #[must_use]
    pub fn magnitude(&self) -> &BigUint {
        &self.magnitude
    }

    /// Negate the integer.
    #[must_use]
    pub fn negated(&self) -> Self {
        let sign = match self.sign {
            Sign::Positive => Sign::Negative,
            Sign::Negative => Sign::Positive,
            Sign::Zero => Sign::Zero,
        };
        Self {
            sign,
            magnitude: self.magnitude.clone(),
        }
    }

    /// Return `self + other`.
    #[must_use]
    pub fn add_ref(&self, other: &Self) -> Self {
        match (self.sign, other.sign) {
            (Sign::Zero, _) => other.clone(),
            (_, Sign::Zero) => self.clone(),
            (Sign::Positive, Sign::Positive) => {
                Self::from_parts(Sign::Positive, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Negative, Sign::Negative) => {
                Self::from_parts(Sign::Negative, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Positive, Sign::Negative) => self.sub_ref(&other.negated()),
            (Sign::Negative, Sign::Positive) => other.sub_ref(&self.negated()),
        }
    }

    /// Return `self - other`.
    #[must_use]
    pub fn sub_ref(&self, other: &Self) -> Self {
        match (self.sign, other.sign) {
            (_, Sign::Zero) => self.clone(),
            (Sign::Zero, _) => other.negated(),
            (Sign::Positive, Sign::Negative) => {
                Self::from_parts(Sign::Positive, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Negative, Sign::Positive) => {
                Self::from_parts(Sign::Negative, self.magnitude.add_ref(&other.magnitude))
            }
            (Sign::Positive, Sign::Positive) => match self.magnitude.cmp(&other.magnitude) {
                Ordering::Greater => {
                    Self::from_parts(Sign::Positive, self.magnitude.sub_ref(&other.magnitude))
                }
                Ordering::Less => {
                    Self::from_parts(Sign::Negative, other.magnitude.sub_ref(&self.magnitude))
                }
                Ordering::Equal => Self::zero(),
            },
            (Sign::Negative, Sign::Negative) => match self.magnitude.cmp(&other.magnitude) {
                Ordering::Greater => {
                    Self::from_parts(Sign::Negative, self.magnitude.sub_ref(&other.magnitude))
                }
                Ordering::Less => {
                    Self::from_parts(Sign::Positive, other.magnitude.sub_ref(&self.magnitude))
                }
                Ordering::Equal => Self::zero(),
            },
        }
    }

    /// Return `self * factor` for a non-negative factor.
    #[must_use]
    pub fn mul_biguint_ref(&self, factor: &BigUint) -> Self {
        if factor.is_zero() || self.sign == Sign::Zero {
            return Self::zero();
        }

        Self::from_parts(self.sign, self.magnitude.mul_ref(factor))
    }

    /// Reduce modulo a positive modulus and return the least non-negative residue.
    ///
    /// # Panics
    ///
    /// Panics if `modulus == 0`.
    #[must_use]
    pub fn modulo_positive(&self, modulus: &BigUint) -> BigUint {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        match self.sign {
            Sign::Zero => BigUint::zero(),
            Sign::Positive => self.magnitude.modulo(modulus),
            Sign::Negative => {
                let rem = self.magnitude.modulo(modulus);
                if rem.is_zero() {
                    BigUint::zero()
                } else {
                    modulus.sub_ref(&rem)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BigInt, BigUint, MontgomeryCtx, Sign};

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *state
    }

    fn seeded_biguint(words: usize, state: &mut u64) -> BigUint {
        let mut limbs = Vec::with_capacity(words);
        for _ in 0..words {
            limbs.push(lcg_next(state));
        }
        if words > 0 && limbs[words - 1] == 0 {
            limbs[words - 1] = 1;
        }
        BigUint { limbs }
    }

    #[test]
    fn bytes_roundtrip() {
        let value =
            BigUint::from_be_bytes(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22]);
        assert_eq!(
            value.to_be_bytes(),
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22]
        );
    }

    #[test]
    fn add_sub_mul_small_values() {
        let a = BigUint::from_u128(1_000_000_000_000);
        let b = BigUint::from_u128(777_777_777_777);
        assert_eq!(a.add_ref(&b), BigUint::from_u128(1_777_777_777_777));
        assert_eq!(
            a.sub_ref(&BigUint::from_u64(1)),
            BigUint::from_u128(999_999_999_999)
        );
        assert_eq!(
            a.mul_ref(&b),
            BigUint::from_u128(777_777_777_777_000_000_000_000)
        );
    }

    #[test]
    fn square_ref_matches_mul_ref() {
        let mut seed = 0x9e37_79b9_7f4a_7c15;
        for words in [1usize, 2, 8, 32, 48] {
            for _ in 0..8 {
                let value = seeded_biguint(words, &mut seed);
                assert_eq!(value.square_ref(), value.mul_ref(&value));
            }
        }
    }

    #[test]
    fn karatsuba_dispatch_matches_schoolbook() {
        let mut seed = 0x243f_6a88_85a3_08d3;
        for words in [32usize, 40, 64] {
            for _ in 0..6 {
                let lhs = seeded_biguint(words, &mut seed);
                let rhs = seeded_biguint(words, &mut seed);
                let dispatched = lhs.mul_ref(&rhs);
                let schoolbook = BigUint::mul_schoolbook_ref(&lhs, &rhs);
                assert_eq!(dispatched, schoolbook);
            }
        }
    }

    #[test]
    fn division_roundtrip() {
        let dividend = BigUint::from_u128(1_234_567_890_123_456_789);
        let divisor = BigUint::from_u64(37);
        let (q, r) = dividend.div_rem(&divisor);
        assert_eq!(q, BigUint::from_u128(33_366_699_733_066_399));
        assert_eq!(r, BigUint::from_u64(26));
        assert_eq!(q.mul_ref(&divisor).add_ref(&r), dividend);
    }

    #[test]
    fn sqrt_floor_small_values() {
        assert_eq!(BigUint::from_u64(0).sqrt_floor(), BigUint::from_u64(0));
        assert_eq!(BigUint::from_u64(1).sqrt_floor(), BigUint::from_u64(1));
        assert_eq!(BigUint::from_u64(2).sqrt_floor(), BigUint::from_u64(1));
        assert_eq!(BigUint::from_u64(15).sqrt_floor(), BigUint::from_u64(3));
        assert_eq!(BigUint::from_u64(16).sqrt_floor(), BigUint::from_u64(4));
        assert_eq!(BigUint::from_u64(17).sqrt_floor(), BigUint::from_u64(4));
        assert_eq!(
            BigUint::from_u128(17_184_849_881).sqrt_floor(),
            BigUint::from_u64(131_090)
        );
    }

    #[test]
    fn mod_mul_matches_small_arithmetic() {
        let a = BigUint::from_u64(123_456_789);
        let b = BigUint::from_u64(987_654_321);
        let m = BigUint::from_u64(1_000_000_007);
        assert_eq!(BigUint::mod_mul(&a, &b, &m), BigUint::from_u64(259_106_859));
    }

    #[test]
    fn montgomery_mod_pow_matches_small_arithmetic() {
        let ctx = MontgomeryCtx::new(&BigUint::from_u64(1_000_000_007))
            .expect("odd modulus builds a context");
        let base = BigUint::from_u64(123_456_789);
        let exponent = BigUint::from_u64(65_537);
        assert_eq!(ctx.pow(&base, &exponent), BigUint::from_u64(560_583_526));
    }

    #[test]
    fn montgomery_ctx_mul_matches_small_arithmetic() {
        let ctx = MontgomeryCtx::new(&BigUint::from_u64(1_000_000_007))
            .expect("odd modulus builds a context");
        let a = BigUint::from_u64(123_456_789);
        let b = BigUint::from_u64(987_654_321);
        assert_eq!(ctx.mul(&a, &b), BigUint::from_u64(259_106_859));
    }

    #[test]
    fn mod_mul_even_modulus_uses_fallback_path() {
        let a = BigUint::from_u64(37);
        let b = BigUint::from_u64(19);
        let modulus = BigUint::from_u64(100);
        assert_eq!(BigUint::mod_mul(&a, &b, &modulus), BigUint::from_u64(3));
    }

    #[test]
    fn bigint_sign_normalization() {
        let zero = BigInt::from_parts(Sign::Negative, BigUint::zero());
        assert_eq!(zero.sign(), Sign::Zero);

        let value = BigInt::from_parts(Sign::Positive, BigUint::from_u64(7));
        assert_eq!(value.negated().sign(), Sign::Negative);
        assert_eq!(value.magnitude(), &BigUint::from_u64(7));
    }

    #[test]
    fn bigint_add_sub_and_modulo() {
        let a = BigInt::from_biguint(BigUint::from_u64(10));
        let b = BigInt::from_parts(Sign::Negative, BigUint::from_u64(3));
        assert_eq!(a.add_ref(&b), BigInt::from_biguint(BigUint::from_u64(7)));
        assert_eq!(
            b.sub_ref(&a),
            BigInt::from_parts(Sign::Negative, BigUint::from_u64(13))
        );
        assert_eq!(
            BigInt::from_parts(Sign::Negative, BigUint::from_u64(3))
                .modulo_positive(&BigUint::from_u64(11)),
            BigUint::from_u64(8)
        );
    }
}
