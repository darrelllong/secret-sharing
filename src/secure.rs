//! Secret-handling helpers — `Zeroize` / `Zeroizing<T>` drop guards
//! and a constant-time `BigUint` comparison.
//!
//! Threat model the crate inherits from `BigUint` is "variable-time
//! arithmetic, no side-channel resistance." This module is the
//! defence-in-depth that we *can* add on top:
//!
//! 1. **Memory residue.** Every secret-bearing intermediate `Vec`,
//!    `[u8; N]`, or `BigUint` allocated inside the scheme code is
//!    wrapped in [`Zeroizing<T>`]. Its `Drop` impl zeros the contents
//!    via `core::ptr::write_volatile` followed by
//!    `core::sync::atomic::compiler_fence(SeqCst)` so the optimiser
//!    cannot elide the scrub on a soon-to-be-freed allocation.
//! 2. **Equality leaks.** Direct `==` on `BigUint` compares limbs
//!    until the first mismatch — its early-exit timing reveals the
//!    leading bits in common between two secret-derived values. Use
//!    [`ct_eq_biguint`] for any equality check that touches a share,
//!    a polynomial coefficient, or any other secret-derived value.
//!
//! What this module does **not** fix:
//!
//! - The arithmetic itself (`mul`, `add`, `sub`, `inv`, `pow`) remains
//!   variable-time. Co-located timing observers can still recover
//!   secret-bit-length information from the running time of those
//!   operations.
//! - Stack residue inside `BigUint` arithmetic is not addressed —
//!   intermediate workspaces inside `bigint::montgomery_mul_odd_*` and
//!   friends live on the stack and are not scrubbed before the frame
//!   is reused.
//! - Memory-mapping / `mlock` to keep secret pages out of swap. That
//!   is platform-specific and should be done at the application
//!   layer.
//!
//! These limits are documented honestly so the user knows where the
//! defence in depth ends.

use crate::bigint::BigUint;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};

/// Volatile-write the value to its zero state. The compiler is
/// forbidden from eliding the write because it goes through
/// `core::ptr::write_volatile`.
pub trait Zeroize {
    fn zeroize(&mut self);
}

#[inline]
fn vol_write_byte(b: &mut u8) {
    // SAFETY: `b` is a valid `&mut u8` for the duration of this call.
    unsafe {
        core::ptr::write_volatile(core::ptr::from_mut::<u8>(b), 0u8);
    }
}

impl Zeroize for u8 {
    fn zeroize(&mut self) {
        vol_write_byte(self);
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            vol_write_byte(b);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            vol_write_byte(b);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        // Volatile-zero the *entire* capacity, not just the live
        // [0..len] window. Pushed-then-truncated residue between len
        // and capacity is otherwise left in place and re-handed-out by
        // the allocator on next reuse.
        let cap = self.capacity();
        if cap > 0 {
            let raw = self.as_mut_ptr();
            for i in 0..cap {
                // SAFETY: i in [0, capacity) is in-bounds of the
                // allocation we own. Writing zero bytes is sound.
                unsafe { core::ptr::write_volatile(raw.add(i), 0u8) };
            }
            compiler_fence(Ordering::SeqCst);
        }
        // SAFETY: the volatile-write loop above wrote a valid `u8`
        // (the zero pattern) into every slot of [0, capacity); setting
        // len = capacity then immediately truncating to 0 keeps the
        // Vec's len/cap invariant. We use clear() rather than
        // set_len(0) so future Drop on the Vec runs nothing — for
        // u8 there is no Drop to worry about either way.
        self.clear();
    }
}

impl Zeroize for BigUint {
    fn zeroize(&mut self) {
        // BigUint already zeroes its limb buffer in its own Drop, so
        // explicit mid-life scrub is just "drop and reset to zero".
        let me = core::mem::replace(self, BigUint::zero());
        drop(me);
    }
}

impl Zeroize for Vec<BigUint> {
    fn zeroize(&mut self) {
        // Order matters: run per-element Drop FIRST (clears the limb
        // buffer of every secret BigUint), THEN clear() to drop the
        // BigUint::zero() replacements (still owning their headers),
        // THEN byte-scrub the now-dead capacity. Any implementation
        // detail of `BigUint::zero()` (cap = 0 today, could change
        // tomorrow) is irrelevant: Drop already freed every interior
        // allocation before we touch the bytes.
        for v in self.iter_mut() {
            v.zeroize();
        }
        self.clear();
        let cap_bytes = self.capacity() * core::mem::size_of::<BigUint>();
        if cap_bytes > 0 {
            let raw = self.as_mut_ptr() as *mut u8;
            for i in 0..cap_bytes {
                // SAFETY: the Vec is logically empty (len = 0) after
                // clear(), and i ∈ [0, cap_bytes) is in-bounds of the
                // capacity allocation we own; volatile byte writes
                // into dead capacity bytes do not violate any
                // invariant of the (now-empty) Vec.
                unsafe { core::ptr::write_volatile(raw.add(i), 0u8) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

impl Zeroize for Vec<Vec<BigUint>> {
    fn zeroize(&mut self) {
        // Same Drop-then-byte-scrub order as `Vec<BigUint>`.
        for inner in self.iter_mut() {
            inner.zeroize();
        }
        self.clear();
        let cap_bytes = self.capacity() * core::mem::size_of::<Vec<BigUint>>();
        if cap_bytes > 0 {
            let raw = self.as_mut_ptr() as *mut u8;
            for i in 0..cap_bytes {
                unsafe { core::ptr::write_volatile(raw.add(i), 0u8) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

/// Drop guard that calls `zeroize()` on the inner value when it goes
/// out of scope — including on early return, panic unwind, or any
/// other path that destroys the wrapper.
///
/// Use to wrap any secret-derived intermediate value so it cannot
/// survive the function's exit:
///
/// ```ignore
/// let mut coeffs = Zeroizing::new(Vec::with_capacity(k));
/// for _ in 0..k { coeffs.push(field.random(rng)); }
/// // ...use coeffs...
/// // At end of scope, coeffs is volatile-zeroed and dropped.
/// ```
pub struct Zeroizing<T: Zeroize> {
    inner: ManuallyDrop<T>,
}

impl<T: Zeroize> Zeroizing<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: ManuallyDrop::new(inner),
        }
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        // SAFETY: drop the inner value normally after the volatile
        // scrub. ManuallyDrop::drop is the canonical way to invoke
        // T's destructor on a manually-managed slot.
        unsafe {
            ManuallyDrop::drop(&mut self.inner);
        }
    }
}

impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize + core::fmt::Debug> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't actually print the inner value — that would leak it.
        f.write_str("Zeroizing(<elided>)")
    }
}

/// Constant-time equality of two `BigUint`s, OR-folding every byte of
/// the maximum byte-length without short-circuiting on the first
/// mismatch.
///
/// `==` on `BigUint` compares limb counts first and short-circuits on
/// any mismatching limb; both branches leak. `ct_eq_biguint` pads the
/// shorter operand to the longer's byte length and reads through every
/// byte position before returning.
///
/// **Residual leak: byte length.** This routine calls
/// `BigUint::to_be_bytes`, which itself walks the limbs and skips
/// leading zeros — so its running time depends on the *bit length* of
/// each operand. The OR-fold loop after that is constant in the
/// padded length but the prefix is not. For a strictly-constant-time
/// comparison fix the byte width up front and use
/// [`ct_eq_biguint_padded`] instead — it skips `to_be_bytes`'s
/// length-dependent leading-zero scan by demanding the caller-supplied
/// `byte_width`.
///
/// Use anywhere that compares a secret-derived value:
///
/// - share `y` cross-checks in [`crate::shamir::reconstruct`] and
///   [`crate::vss::verify_consistent`],
/// - the recovery-coefficient back-check in
///   [`crate::karchmer_wigderson`] / [`crate::massey`].
///
/// The byte buffers used for the comparison are themselves zeroized
/// before this function returns.
#[must_use]
pub fn ct_eq_biguint(a: &BigUint, b: &BigUint) -> bool {
    let mut a_be = a.to_be_bytes();
    let mut b_be = b.to_be_bytes();
    let max_len = a_be.len().max(b_be.len());
    // Allocate the comparison buffers up front at the padded length;
    // copy bytes directly into the right offset. This avoids the
    // earlier `append/drain` pattern that left the original
    // `to_be_bytes` allocation un-scrubbed when reassigned.
    let mut a_buf = vec![0u8; max_len];
    let mut b_buf = vec![0u8; max_len];
    a_buf[max_len - a_be.len()..].copy_from_slice(&a_be);
    b_buf[max_len - b_be.len()..].copy_from_slice(&b_be);
    // Scrub the original to_be_bytes buffers — they were the source
    // for the copy, hold a verbatim copy of the secret bytes, and are
    // about to be dropped.
    a_be.zeroize();
    b_be.zeroize();
    let mut acc: u8 = 0;
    for i in 0..max_len {
        acc |= a_buf[i] ^ b_buf[i];
    }
    let result = acc == 0;
    // Scrub the comparison buffers themselves before they drop.
    a_buf.zeroize();
    b_buf.zeroize();
    result
}

/// Padded-width equality routed through
/// [`BigUint::to_be_bytes_padded`].
///
/// Improvements over [`ct_eq_biguint`]:
///
/// - The OR-fold runs over a fixed `byte_width` regardless of operand
///   bit length.
/// - The byte materialisation does not short-circuit on a leading
///   non-zero byte (the `to_be_bytes` leak), so the per-byte timing is
///   constant in `byte_width`.
///
/// **Residual side-channel.** [`BigUint::to_be_bytes_padded`] copies
/// `min(byte_width.div_ceil(8), operand.limbs.len())` u64 limbs via
/// `core::ptr::copy_nonoverlapping`; the copy length depends on the
/// operand's normalised limb count. For schemes where both operands
/// are reduced field elements (limb count = `modulus.bits().div_ceil(64)`,
/// a public quantity), the copy length is constant and the residual
/// leak vanishes. For unreduced operands the leak is bounded to one
/// limb (8 bytes) of upper-bound information about the secret bit
/// length — a strict improvement over the byte-granular leading-zero
/// scan inside `to_be_bytes`.
///
/// Pass `byte_width = field.modulus().bits().div_ceil(8)` when both
/// operands are known to be reduced field elements.
///
/// # Panics
/// Panics (via [`BigUint::to_be_bytes_padded`]) if either operand's
/// actual byte length exceeds `byte_width` — that indicates a caller
/// contract violation, not a runtime mismatch worth converting to
/// `false`.
#[must_use]
pub fn ct_eq_biguint_padded(a: &BigUint, b: &BigUint, byte_width: usize) -> bool {
    let mut a_buf = a.to_be_bytes_padded(byte_width);
    let mut b_buf = b.to_be_bytes_padded(byte_width);
    let mut acc: u8 = 0;
    for i in 0..byte_width {
        acc |= a_buf[i] ^ b_buf[i];
    }
    let result = acc == 0;
    // Both buffers hold a verbatim padded copy of secret-derived
    // bytes. Volatile-zero before drop.
    a_buf.zeroize();
    b_buf.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_byte_array() {
        let mut a = [0xFFu8; 16];
        a.zeroize();
        assert_eq!(a, [0u8; 16]);
    }

    #[test]
    fn zeroize_vec_u8_clears_and_truncates() {
        let mut v = vec![0xABu8; 32];
        v.zeroize();
        assert!(v.is_empty(), "Zeroize<Vec<u8>> should clear the logical length");
    }

    #[test]
    fn zeroize_vec_biguint_replaces_each_with_zero_then_clears() {
        let mut v: Vec<BigUint> = (1..=4).map(BigUint::from_u64).collect();
        v.zeroize();
        assert!(v.is_empty());
    }

    #[test]
    fn zeroizing_drops_with_scrub() {
        // Drop a Zeroizing<Vec<u8>> in an inner scope and confirm it
        // releases its memory (no use-after-drop is observable, but we
        // can at least confirm no panic from the volatile path).
        {
            let mut z = Zeroizing::new(vec![0xCDu8; 64]);
            z[0] = 0xEF; // exercise DerefMut
            assert_eq!(z[0], 0xEF);
        }
        // No assertion on freed memory — Drop runs successfully is the
        // contract being verified.
    }

    #[test]
    fn ct_eq_matches_eq_for_equal_values() {
        for n in [0u64, 1, 0xFF, 0xFFFF, 0xCAFE_BABE_DEAD_BEEF] {
            let a = BigUint::from_u64(n);
            let b = BigUint::from_u64(n);
            assert!(ct_eq_biguint(&a, &b), "equal values must compare true");
        }
    }

    #[test]
    fn ct_eq_distinguishes_unequal_values_of_same_bit_length() {
        let a = BigUint::from_u64(0x8000_0000);
        let b = BigUint::from_u64(0x8000_0001);
        assert!(!ct_eq_biguint(&a, &b));
    }

    #[test]
    fn ct_eq_handles_different_byte_lengths() {
        let small = BigUint::from_u64(7);
        let mut big = BigUint::one();
        big.shl_bits(80);
        big = big.add_ref(&small);
        // big has many more bytes than small but they are unequal.
        assert!(!ct_eq_biguint(&small, &big));
        // Same value padded both ways: equal.
        let small2 = BigUint::from_u64(7);
        assert!(ct_eq_biguint(&small, &small2));
    }

    #[test]
    fn ct_eq_padded_constant_byte_width() {
        // Two values that share a long zero prefix must compare equal,
        // and two that differ only in the low byte must compare
        // unequal — both at the same fixed byte width with no
        // short-circuit on the leading-zero scan.
        let zero = BigUint::zero();
        let one = BigUint::one();
        assert!(ct_eq_biguint_padded(&zero, &zero, 16));
        assert!(!ct_eq_biguint_padded(&zero, &one, 16));
    }

    #[test]
    #[should_panic(expected = "value does not fit in 8 bytes")]
    fn ct_eq_padded_panics_on_oversize_operand() {
        // Caller contract: byte_width must be ≥ each operand's actual
        // byte length. We surface a panic rather than silently
        // returning `false`, so a caller using the wrong width gets a
        // loud signal at the call site.
        let big = {
            let mut v = BigUint::one();
            v.shl_bits(80);
            v
        };
        let _ = ct_eq_biguint_padded(&big, &big, 8);
    }

    #[test]
    fn ct_eq_handles_zero_and_one() {
        assert!(ct_eq_biguint(&BigUint::zero(), &BigUint::zero()));
        assert!(ct_eq_biguint(&BigUint::one(), &BigUint::one()));
        assert!(!ct_eq_biguint(&BigUint::zero(), &BigUint::one()));
    }

    #[test]
    fn end_to_end_secret_round_trip_with_security_layer() {
        // Pin the contract that scheme code keeps working after the
        // Zeroizing/ct_eq scrubbing wrappers were threaded through.
        // Exercise:
        //   - shamir split (uses Zeroizing<Vec<BigUint>> for coeffs)
        //   - shamir reconstruct (uses ct_eq_biguint for extras check)
        //   - vss deal + reconstruct (Zeroizing<Vec<Vec<BigUint>>>
        //     for the bivariate matrix; ct_eq_biguint inside cross_check)
        //   - cgma_vss deal + verify + reconstruct (Zeroizing<Vec<BigUint>>
        //     for f's coefficients)
        //   - proactive refresh (Zeroizing<Vec<Vec<BigUint>>> for the
        //     refresh-contribution polynomials)
        // Every path must round-trip the original secret exactly; no
        // None, no garbage, no mismatch.
        use crate::field::{mersenne127, PrimeField};
        use crate::{cgma_vss, csprng::ChaCha20Rng, proactive, shamir, vss};

        let f = PrimeField::new(mersenne127());
        let mut rng = ChaCha20Rng::from_seed(&[0x99u8; 32]);
        let secret = BigUint::from_u64(0xCAFE_BABE);

        // Shamir end-to-end with extras (exercises ct_eq_biguint).
        let shares = shamir::split(&f, &mut rng, &secret, 3, 5);
        let recovered = shamir::reconstruct(&f, &shares, 3).expect("shamir round-trip");
        assert!(
            ct_eq_biguint(&recovered, &secret),
            "shamir secret survives Zeroizing+ct_eq layer"
        );

        // VSS end-to-end with pairwise verification (exercises
        // ct_eq_biguint inside cross_check).
        let vss_shares = vss::deal(&f, &mut rng, &secret, 3, 5);
        assert!(vss::verify_consistent(&f, &vss_shares));
        let vss_recovered =
            vss::reconstruct(&f, &vss_shares[..3], 3).expect("vss round-trip");
        assert!(ct_eq_biguint(&vss_recovered, &secret));

        // CGMA-VSS end-to-end with verify_share (exercises Zeroizing
        // around the polynomial coefficient vector).
        let group = cgma_vss::small_test_group();
        let small_secret = BigUint::from_u64(7); // < q = 11
        let (cgma_shares, commits) = cgma_vss::deal(&group, &mut rng, &small_secret, 3, 5);
        for s in &cgma_shares {
            assert!(cgma_vss::verify_share(&group, &commits, s));
        }
        let cgma_recovered =
            cgma_vss::reconstruct(&group, &cgma_shares[..3], 3).expect("cgma round-trip");
        assert!(ct_eq_biguint(&cgma_recovered, &small_secret));

        // Proactive refresh: Zeroizing wraps the contribution polys;
        // refreshed shares must still reconstruct the same secret.
        let refreshed = proactive::refresh(&f, &mut rng, &shares, 3);
        let refreshed_recovered =
            shamir::reconstruct(&f, &refreshed[..3], 3).expect("post-refresh round-trip");
        assert!(
            ct_eq_biguint(&refreshed_recovered, &secret),
            "secret preserved across refresh + reconstruct"
        );
    }

    #[test]
    fn debug_does_not_leak_inner_value() {
        let z = Zeroizing::new(vec![0xDEu8; 8]);
        let printed = format!("{:?}", z);
        assert!(printed.contains("elided"));
        assert!(!printed.contains("0xDE"));
        assert!(!printed.contains("222"));
    }
}
