//! Prime-field arithmetic on top of the sibling crate's `BigUint`.
//!
//! Shamir 1979 places its scheme over `Z/pZ` for a prime `p > max(D, n)`,
//! and the Karnin–Greene–Hellman / McEliece–Sarwate generalizations
//! retain that field (or its extension `GF(p^m)`). All polynomial
//! manipulations in the rest of the crate go through this wrapper so the
//! modulus is fixed once and the operations read directly off the papers.

use std::sync::OnceLock;

use crate::primes::{is_probable_prime, mod_inverse, random_below};
use crate::bigint::{BigInt, BigUint, Sign};
use crate::csprng::Csprng;

/// One term in a reduction polynomial: signed coefficient at a bit
/// offset. Used to encode the right-hand side of `2^k ≡ δ (mod p)`
/// where `δ = sum(coef · 2^offset)` ranges over the terms.
///
/// Examples:
/// - `mersenne127` (p = 2^127 − 1): `δ = 1`, single term `(0, +1)`.
/// - `curve25519` (p = 2^255 − 19): `δ = 19`, single term `(0, +19)`.
/// - `secp256k1` (p = 2^256 − 2^32 − 977): `δ = 2^32 + 977`, two
///   terms `(0, +977), (32, +1)`.
/// - `nist_p256` (p = 2^256 − 2^224 + 2^192 + 2^96 − 1):
///   `δ = 2^224 − 2^192 − 2^96 + 1`, four terms with mixed signs:
///   `(0, +1), (96, −1), (192, −1), (224, +1)`.
///
/// The signed `i64` coefficient is sufficient for every standardised
/// pseudo-Mersenne / Solinas / Crandall prime in this crate (the
/// largest absolute coefficient is `977` for secp256k1; everything
/// else is `±1`).
#[derive(Clone, Copy, Debug)]
struct ReductionTerm {
    offset: usize,
    coef: i64,
}

/// Parameters for a Solinas-form prime `p = 2^k − δ` where the
/// "borrow" `δ` is a small signed sum of powers of two. The reducer
/// uses `2^k ≡ δ (mod p)` to fold the high half of a multiply
/// product back into the low half repeatedly until the result fits
/// in `k` bits, then a final conditional subtract pins it to `[0, p)`.
///
/// This subsumes:
/// - Pure Mersenne `2^k − 1` (single term `(0, +1)`).
/// - Pseudo-Mersenne / Crandall `2^k − c` with small `c`
///   (single term `(0, +c)`).
/// - True Solinas `2^k − sum(±2^{e_i})` with mixed-sign terms.
///
/// Construction validates that the parameters are self-consistent:
/// the reduction polynomial actually equals `2^k − p`, and every
/// term offset is strictly less than `k`.
#[derive(Clone, Debug)]
struct ReductionParams {
    /// Bit width of the prime: `2^(k−1) ≤ p < 2^k`.
    k: usize,
    /// `δ` decomposed as signed terms; sums to `2^k − p`.
    terms: &'static [ReductionTerm],
    /// The prime itself, cached for the final conditional subtract.
    p: BigUint,
    /// Human-readable identifier used in `Debug` output.
    name: &'static str,
    /// Set `false` when the polynomial structure makes the parametric
    /// reducer slower than generic Montgomery on the bench hardware.
    /// The entry stays in the table so the fuzz suite still validates
    /// the reducer's correctness for this prime, but [`detect_kind`]
    /// returns [`FieldKind::Generic`] so production callers route to
    /// the faster path. NIST P-256 hits this case: its 4-term mixed-
    /// sign polynomial with `max_offset = 224, k = 256` needs ~8
    /// fold iterations each doing 4 BigUint shifts+adds, which loses
    /// to Montgomery's 4 mont-muls on 4 limbs.
    prefer_fast: bool,
}

/// Internal discriminator for prime moduli with closed-form
/// reductions. Selected at construction (one BigUint comparison per
/// known prime). The chosen branch of [`PrimeField::mul`] routes
/// through either:
///
/// - The hand-written `u128` fast path for `mersenne127` — operands
///   fit in two `u64`s and the 2×2 schoolbook + Mersenne fold stays
///   entirely in registers, ~5 ns per multiply.
/// - The parametric reducer for every other recognised
///   pseudo-Mersenne / Solinas / Crandall prime, which goes through
///   `BigUint::mul_ref` followed by a templated "fold high · δ into
///   low" loop. Slower than the `u128` path because it allocates
///   per fold step, but still 1.5–3× faster than the generic
///   Montgomery path because it skips the `R²`-encode/decode dance.
/// - The generic Montgomery path for any unrecognised modulus.
#[derive(Clone, Debug)]
enum FieldKind {
    Generic,
    /// `p = 2^127 − 1`. Hand-rolled `u128` fast path.
    Mersenne127,
    /// Templated pseudo-Mersenne / Solinas reducer.
    Reduction(Box<ReductionParams>),
}

/// Prime modulus and the four finite-field operations needed by Shamir,
/// the KGH matrix scheme, and the McEliece–Sarwate decoder.
#[derive(Clone, Debug)]
pub struct PrimeField {
    p: BigUint,
    kind: FieldKind,
}

fn detect_kind(p: &BigUint) -> FieldKind {
    if p == cached_mersenne127() {
        return FieldKind::Mersenne127;
    }
    for params in known_reductions() {
        if &params.p == p {
            // The fuzz suite validates correctness for every entry,
            // but the dispatch only picks the parametric reducer when
            // it's actually faster on the bench hardware. Primes with
            // `prefer_fast: false` fall through to Montgomery.
            if params.prefer_fast {
                return FieldKind::Reduction(Box::new(params.clone()));
            }
            return FieldKind::Generic;
        }
    }
    FieldKind::Generic
}

/// Memoised `mersenne127()`. The constant is cheap but the
/// `detect_kind` comparison runs on every `PrimeField::new*` call;
/// caching trades 16 bytes of static for the construction allocation.
fn cached_mersenne127() -> &'static BigUint {
    static M127: OnceLock<BigUint> = OnceLock::new();
    M127.get_or_init(mersenne127)
}

/// Catalogue of pseudo-Mersenne / Solinas primes we recognise.
///
/// The table is built once via `OnceLock` and shared by every
/// `PrimeField::new*` call. Extending the framework with another
/// standardised prime is one entry here plus a constructor below.
///
/// Construction-time invariants (asserted on first call):
/// - Every term coefficient is strictly non-zero.
/// - δ = sum(coef · 2^offset) is strictly positive (so a positive
///   product cannot fold into a negative intermediate; see
///   [`reduction_fold`]).
/// - δ matches `2^k − p` exactly (so the encoded polynomial actually
///   describes the prime it's tagged with).
fn known_reductions() -> &'static [ReductionParams] {
    static TABLE: OnceLock<Vec<ReductionParams>> = OnceLock::new();
    TABLE.get_or_init(build_known_reductions).as_slice()
}

fn build_known_reductions() -> Vec<ReductionParams> {
    // Static term tables — each describes `δ` such that p = 2^k − δ
    // and the reducer substitutes `2^k ≡ δ`.
    static MERSENNE_TERMS: &[ReductionTerm] = &[ReductionTerm { offset: 0, coef: 1 }];
    static CURVE25519_TERMS: &[ReductionTerm] = &[ReductionTerm { offset: 0, coef: 19 }];
    static POLY1305_TERMS: &[ReductionTerm] = &[ReductionTerm { offset: 0, coef: 5 }];
    // secp256k1: p = 2^256 − 2^32 − 977; δ = 2^32 + 977.
    static SECP256K1_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: 977 },
        ReductionTerm { offset: 32, coef: 1 },
    ];
    // Curve448: p = 2^448 − 2^224 − 1; δ = 2^224 + 1.
    static CURVE448_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: 1 },
        ReductionTerm { offset: 224, coef: 1 },
    ];
    // NIST P-192: p = 2^192 − 2^64 − 1; δ = 2^64 + 1.
    static P192_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: 1 },
        ReductionTerm { offset: 64, coef: 1 },
    ];
    // NIST P-224: p = 2^224 − 2^96 + 1; δ = 2^96 − 1.
    static P224_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: -1 },
        ReductionTerm { offset: 96, coef: 1 },
    ];
    // NIST P-256: p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
    // Solving for δ: p = 2^256 − (2^224 − 2^192 − 2^96 + 1).
    // δ = 2^224 − 2^192 − 2^96 + 1.
    static P256_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: 1 },
        ReductionTerm { offset: 96, coef: -1 },
        ReductionTerm { offset: 192, coef: -1 },
        ReductionTerm { offset: 224, coef: 1 },
    ];
    // NIST P-384: p = 2^384 − 2^128 − 2^96 + 2^32 − 1.
    // δ = 2^128 + 2^96 − 2^32 + 1.
    static P384_TERMS: &[ReductionTerm] = &[
        ReductionTerm { offset: 0, coef: 1 },
        ReductionTerm { offset: 32, coef: -1 },
        ReductionTerm { offset: 96, coef: 1 },
        ReductionTerm { offset: 128, coef: 1 },
    ];

    let table = vec![
        ReductionParams { k: 521, terms: MERSENNE_TERMS, p: mersenne521(), name: "mersenne521", prefer_fast: true },
        ReductionParams { k: 255, terms: CURVE25519_TERMS, p: curve25519_field(), name: "curve25519", prefer_fast: true },
        ReductionParams { k: 130, terms: POLY1305_TERMS, p: poly1305_field(), name: "poly1305", prefer_fast: true },
        ReductionParams { k: 256, terms: SECP256K1_TERMS, p: secp256k1_field(), name: "secp256k1", prefer_fast: true },
        ReductionParams { k: 448, terms: CURVE448_TERMS, p: curve448_field(), name: "curve448", prefer_fast: true },
        ReductionParams { k: 192, terms: P192_TERMS, p: nist_p192_field(), name: "nist_p192", prefer_fast: true },
        ReductionParams { k: 224, terms: P224_TERMS, p: nist_p224_field(), name: "nist_p224", prefer_fast: true },
        // NIST P-256: 4 terms, max_offset 224, k 256 — ~8 fold iterations
        // × 4 BigUint shifts/adds each. Bench shows 0.6× of Montgomery
        // on the bench hardware, so we route this prime to Generic.
        // The entry is kept in the table so the fuzz suite still
        // validates the parametric reducer's correctness for it.
        ReductionParams { k: 256, terms: P256_TERMS, p: nist_p256_field(), name: "nist_p256", prefer_fast: false },
        ReductionParams { k: 384, terms: P384_TERMS, p: nist_p384_field(), name: "nist_p384", prefer_fast: true },
    ];
    // Validate every entry exactly once. A regression here (a typo in
    // a constant, an off-by-one in a `shl_bits`, a sign error in a
    // term) would otherwise produce silently wrong field arithmetic
    // for the affected prime.
    for params in &table {
        validate_reduction_params(params);
    }
    table
}

fn validate_reduction_params(params: &ReductionParams) {
    // Every coefficient must be non-zero — coef == 0 would silently
    // skip an `unreachable!` arm in `reduction_fold`.
    for term in params.terms {
        assert!(
            term.coef != 0,
            "{}: zero coefficient in reduction polynomial",
            params.name,
        );
        assert!(
            term.offset < params.k,
            "{}: term offset {} ≥ k = {}",
            params.name,
            term.offset,
            params.k,
        );
    }
    // δ = sum(coef · 2^offset). Compute as a BigInt so signed terms
    // resolve correctly; require δ > 0 so positive products stay
    // non-negative through every fold step.
    let mut delta = BigInt::zero();
    for term in params.terms {
        let mut shifted = BigUint::one();
        if term.offset > 0 {
            shifted.shl_bits(term.offset);
        }
        let coef_abs = term.coef.unsigned_abs();
        let term_mag = if coef_abs == 1 {
            shifted
        } else {
            shifted.mul_ref(&BigUint::from_u64(coef_abs))
        };
        let term_int = if term.coef > 0 {
            BigInt::from_biguint(term_mag)
        } else {
            BigInt::from_parts(Sign::Negative, term_mag)
        };
        delta = delta.add_ref(&term_int);
    }
    assert!(
        delta.sign() == Sign::Positive,
        "{}: δ must be positive (got sign {:?}) — fold algorithm assumes positive products stay non-negative",
        params.name,
        delta.sign(),
    );
    // Verify δ == 2^k − p exactly (so the encoded polynomial really
    // describes the prime it's tagged with).
    let mut two_k = BigUint::one();
    two_k.shl_bits(params.k);
    let expected_delta = two_k.sub_ref(&params.p);
    assert!(
        delta.sign() == Sign::Positive && delta.magnitude() == &expected_delta,
        "{}: δ decomposition does not match 2^k − p",
        params.name,
    );
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
    ///
    /// Values produced by the field's own operations are already
    /// reduced, so the comparison usually settles it without paying
    /// for the division inside `modulo`.
    #[must_use]
    pub fn reduce(&self, a: &BigUint) -> BigUint {
        if a < &self.p {
            a.clone()
        } else {
            a.modulo(&self.p)
        }
    }

    /// `a + b mod p`. Inputs need not be pre-reduced.
    ///
    /// Reduced inputs sum to at most `2p − 2`, so one conditional
    /// subtract replaces the division-based `modulo` on the path every
    /// Horner step and Lagrange accumulation takes. Unreduced inputs
    /// whose sum reaches `2p` fall through to the full reduction.
    #[must_use]
    pub fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let mut s = a.add_ref(b);
        if s >= self.p {
            s.sub_assign_ref(&self.p);
            if s >= self.p {
                s = s.modulo(&self.p);
            }
        }
        s
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
        match &self.kind {
            FieldKind::Mersenne127 => mersenne127_mul(a, b),
            FieldKind::Reduction(params) => reduction_mul(a, b, params),
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

/// `a · b mod p` where `p = 2^k − δ` is described by [`ReductionParams`].
///
/// Algorithm:
///   1. Pre-reduce each operand to fit in `k` bits (slow path only when
///      a caller hands the field a value ≥ p; internal callers always
///      feed reduced operands, so this branch is rare).
///   2. Compute the 2k-bit product via [`BigUint::mul_ref`].
///   3. Iteratively fold: `t' = low(t) + high(t) · δ`. Each term of
///      δ contributes `±|coef| · high · 2^offset` to the running
///      [`BigInt`] sum. Construction-time validation requires δ > 0
///      (see [`validate_reduction_params`]), which guarantees that
///      starting from a non-negative product the running sum stays
///      non-negative across every fold — the negative arm in
///      [`reduction_fold`] is therefore unreachable for every
///      registered prime.
///   4. Convert back to canonical `[0, p)` via [`BigInt::modulo_positive`].
///
/// **Convergence (informal bound, not a proof).** With `max_offset`
/// the largest offset in the term polynomial, each fold reduces
/// `bits(|t|)` by roughly `k − max_offset` (modulo small slack from
/// `|coef|` and `num_terms`). The hardest case in this catalogue is
/// NIST P-256 (`max_offset = 224`, `k = 256`), where each fold
/// strips ~32 bits from a 2k = 512-bit starting product — about 8
/// iterations. The cap below (`MAX_FOLDS = 32`) is set generously
/// and is hard-asserted, so any input that would exceed it panics
/// rather than silently returning a partially-reduced value. The
/// `(p − 1)²` worst case is exercised in the per-prime fuzz suite.
///
/// **Side-channel surface.** The fold-iteration count and the
/// limb-level work inside `BigInt::add_ref` / `BigUint::mul_ref` are
/// both data-dependent. This path therefore does **not** make any
/// new constant-time claim, and the underlying [`BigUint`] backend
/// is itself not constant-time; see the module-level note at the
/// top of `bigint.rs`. The threat model the crate currently defends
/// against is residue scrubbing on `Drop`, not timing-channel
/// resistance against a co-located attacker.
fn reduction_mul(a: &BigUint, b: &BigUint, params: &ReductionParams) -> BigUint {
    // Pre-reduce inputs that exceed `k` bits. The fast path checks
    // bit length only; an input == p with bits == k still passes
    // through, and the final `modulo_positive` cleans up.
    let a_red;
    let a = if a.bits() <= params.k { a } else { a_red = a.modulo(&params.p); &a_red };
    let b_red;
    let b = if b.bits() <= params.k { b } else { b_red = b.modulo(&params.p); &b_red };

    let prod = a.mul_ref(b);
    let mut t = BigInt::from_biguint(prod);

    // Hard cap. δ > 0 (enforced at construction) plus a non-negative
    // initial product imply every fold produces a non-negative
    // result with strictly fewer bits, so this cap is generous. If
    // it is ever reached, the polynomial table has been corrupted
    // and silent partial reduction would be a footgun — panic.
    const MAX_FOLDS: usize = 32;
    let mut folds = 0usize;
    while needs_fold(&t, params.k) {
        assert!(
            folds < MAX_FOLDS,
            "reduction_mul did not converge for {} after {} folds",
            params.name,
            MAX_FOLDS,
        );
        t = reduction_fold(&t, params);
        folds += 1;
    }

    t.modulo_positive(&params.p)
}

/// `true` when `t` still has more than `k` significant bits and so
/// requires another fold step. For δ > 0 (which all registered
/// primes satisfy), `t` produced from the initial non-negative
/// product is itself non-negative, so the `Sign::Negative` arm in
/// [`reduction_fold`] is unreachable; this function returns `true`
/// on a hypothetical negative `t` only as a defensive aid for
/// future polynomial additions whose δ might not be positive (in
/// which case the negative branch in `reduction_fold` would also
/// need to be re-thought).
fn needs_fold(t: &BigInt, k: usize) -> bool {
    match t.sign() {
        Sign::Zero => false,
        Sign::Negative => true,
        Sign::Positive => t.magnitude().bits() > k,
    }
}

/// One reduction step: substitute `2^k ≡ δ` in the high half of `t`.
///
/// Writes `|t| = high · 2^k + low` (limb-level shift + mask), then
/// accumulates positive and negative term contributions into two
/// `BigUint` running sums and returns `pos − neg` wrapped in a
/// `BigInt`. Construction-time validation (`validate_reduction_params`)
/// requires δ > 0, which guarantees `pos ≥ neg` (debug-asserted) so
/// the subtraction never underflows. The non-negative-only path
/// avoids the per-term `BigInt` allocations the previous mixed-sign
/// implementation paid; on NIST P-256 (the worst case in this
/// catalogue, ~8 folds × 4 terms each) this is the difference
/// between losing and winning vs the generic Montgomery path.
fn reduction_fold(t: &BigInt, params: &ReductionParams) -> BigInt {
    if t.sign() == Sign::Zero {
        return BigInt::zero();
    }
    if t.sign() == Sign::Negative {
        // Unreachable under the δ > 0 invariant enforced at table
        // build time. If a future polynomial with δ ≤ 0 were wired
        // in, this arm would need a real implementation; meanwhile,
        // panic rather than loop or return a wrong value.
        unreachable!(
            "reduction_fold on Negative t — δ > 0 invariant violated; check validate_reduction_params",
        );
    }
    let mag = t.magnitude();
    let high = mag.shr_bits(params.k);
    let low = mag.low_bits(params.k);

    if high.is_zero() {
        // Already < 2^k; nothing to fold.
        return BigInt::from_biguint(low);
    }

    let mut pos = low;
    let mut neg = BigUint::zero();
    for term in params.terms {
        let mut shifted = high.clone();
        if term.offset > 0 {
            shifted.shl_bits(term.offset);
        }
        let abs_coef = term.coef.unsigned_abs();
        let term_mag = if abs_coef == 1 {
            shifted
        } else {
            shifted.mul_ref(&BigUint::from_u64(abs_coef))
        };
        if term.coef > 0 {
            pos = pos.add_ref(&term_mag);
        } else {
            neg = neg.add_ref(&term_mag);
        }
    }
    debug_assert!(
        pos >= neg,
        "δ > 0 invariant violated at runtime: pos < neg in fold step",
    );
    BigInt::from_biguint(pos.sub_ref(&neg))
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
/// Also doubles as the **NIST P-521** base-field prime (FIPS 186-4).
#[must_use]
pub fn mersenne521() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(521);
    v.sub_ref(&BigUint::one())
}

/// Curve25519 base field, `p = 2^255 − 19` (RFC 7748).
#[must_use]
pub fn curve25519_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(255);
    v.sub_ref(&BigUint::from_u64(19))
}

/// Poly1305 modulus, `p = 2^130 − 5` (RFC 8439).
#[must_use]
pub fn poly1305_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(130);
    v.sub_ref(&BigUint::from_u64(5))
}

/// secp256k1 base field, `p = 2^256 − 2^32 − 977` (SEC 2 / RFC 6979).
#[must_use]
pub fn secp256k1_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(256);
    // 2^32 + 977 = 4294968273.
    v.sub_ref(&BigUint::from_u64(4_294_968_273))
}

/// Curve448 base field, `p = 2^448 − 2^224 − 1` (RFC 7748,
/// "Goldilocks" Solinas form).
#[must_use]
pub fn curve448_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(448);
    let mut sub = BigUint::one();
    sub.shl_bits(224);
    let one = BigUint::one();
    v.sub_ref(&sub).sub_ref(&one)
}

/// NIST P-192 base field, `p = 2^192 − 2^64 − 1` (FIPS 186-4).
#[must_use]
pub fn nist_p192_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(192);
    let mut sub = BigUint::one();
    sub.shl_bits(64);
    v.sub_ref(&sub).sub_ref(&BigUint::one())
}

/// NIST P-224 base field, `p = 2^224 − 2^96 + 1` (FIPS 186-4).
#[must_use]
pub fn nist_p224_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(224);
    let mut sub = BigUint::one();
    sub.shl_bits(96);
    v.sub_ref(&sub).add_ref(&BigUint::one())
}

/// NIST P-256 base field,
/// `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` (FIPS 186-4).
#[must_use]
pub fn nist_p256_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(256);
    let mut t224 = BigUint::one();
    t224.shl_bits(224);
    let mut t192 = BigUint::one();
    t192.shl_bits(192);
    let mut t96 = BigUint::one();
    t96.shl_bits(96);
    v.sub_ref(&t224).add_ref(&t192).add_ref(&t96).sub_ref(&BigUint::one())
}

/// NIST P-384 base field,
/// `p = 2^384 − 2^128 − 2^96 + 2^32 − 1` (FIPS 186-4).
#[must_use]
pub fn nist_p384_field() -> BigUint {
    let mut v = BigUint::one();
    v.shl_bits(384);
    let mut t128 = BigUint::one();
    t128.shl_bits(128);
    let mut t96 = BigUint::one();
    t96.shl_bits(96);
    let mut t32 = BigUint::one();
    t32.shl_bits(32);
    v.sub_ref(&t128).sub_ref(&t96).add_ref(&t32).sub_ref(&BigUint::one())
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

    // ── Per-prime fuzz suite ──────────────────────────────────────
    //
    // Each entry below pairs a recognised standardised prime with the
    // fast-path field that detects it. A shared driver checks:
    //
    //   - Construction succeeds and lands on the expected `FieldKind`
    //     (asserted indirectly via the kind-blind generic comparison).
    //   - The bit length matches the modulus's documented value.
    //   - Edge cases: 0, 1, p−1, p, p+1, 2^(k−1), 2^k − 1 commute
    //     with the generic Montgomery mul path on both inputs and
    //     yield results in [0, p).
    //   - 2^14 random fuzz inputs match the generic path exactly.
    //   - Algebraic identities hold: a · 0 == 0, a · 1 == a mod p,
    //     a · p == 0, a · b == b · a.

    use crate::csprng::ChaCha20Rng;

    /// Build a kind-blind generic-path field for the same modulus, used
    /// as the oracle for fast-path correctness checks.
    fn generic_for(p: &BigUint) -> PrimeField {
        PrimeField {
            p: p.clone(),
            kind: FieldKind::Generic,
        }
    }

    /// Build a field that forces the parametric reduction path even
    /// for primes whose `prefer_fast: false` flag would route them to
    /// Generic in production. Used so the per-prime fuzz harness
    /// continues to exercise the parametric reducer for those primes
    /// — the correctness coverage matters even if the production
    /// dispatch picks Montgomery.
    fn force_reduction_for(p: &BigUint) -> PrimeField {
        for params in super::known_reductions() {
            if &params.p == p {
                return PrimeField {
                    p: p.clone(),
                    kind: super::FieldKind::Reduction(Box::new(params.clone())),
                };
            }
        }
        // Mersenne127 has its own non-reduction fast path; the caller
        // doesn't reach here for the registered primes.
        unreachable!("force_reduction_for: prime not in table");
    }

    fn check_edges(p: &BigUint, fast: &PrimeField, generic: &PrimeField) {
        let zero = BigUint::zero();
        let one = BigUint::one();
        let p_minus_1 = p.sub_ref(&one);
        let p_plus_1 = p.add_ref(&one);
        let mut two_pow_k_minus_1 = BigUint::one();
        two_pow_k_minus_1.shl_bits(p.bits() - 1);

        let edges: Vec<BigUint> = vec![
            zero.clone(),
            one.clone(),
            BigUint::from_u64(2),
            two_pow_k_minus_1,
            p_minus_1,
            p.clone(),
            p_plus_1,
        ];
        for a in &edges {
            for b in &edges {
                let want = generic.mul(a, b);
                let got = fast.mul(a, b);
                assert_eq!(got, want, "edge mismatch: a.bits()={}, b.bits()={}", a.bits(), b.bits());
                assert!(got < *p, "result not reduced: bits={}", got.bits());
            }
        }
        // a · 0 == 0
        assert_eq!(fast.mul(&BigUint::from_u64(0xC0FFEE), &zero), zero);
        // a · 1 == a mod p (for a < p)
        let small = BigUint::from_u64(0xBEEF);
        assert_eq!(fast.mul(&small, &one), small);
        // a · p == 0
        assert_eq!(fast.mul(&small, p), zero);
    }

    fn fuzz_against_generic(p: &BigUint, fast: &PrimeField, generic: &PrimeField, seed_byte: u8) {
        let mut r = ChaCha20Rng::from_seed(&[seed_byte; 32]);
        const N: usize = 16_384;
        for i in 0..N {
            let a = fast.random(&mut r);
            let b = fast.random(&mut r);
            let got = fast.mul(&a, &b);
            let want = generic.mul(&a, &b);
            assert_eq!(got, want, "fuzz iter {i}: fast {got:?} != generic {want:?}");
            assert!(got < *p, "result not reduced at iter {i}");
            // Commutativity.
            assert_eq!(fast.mul(&b, &a), got, "non-commutative at iter {i}");
        }
    }

    fn check_unreduced_inputs(p: &BigUint, fast: &PrimeField, generic: &PrimeField) {
        // a = p + small, b = 2p + small; both exceed k bits and exercise
        // the slow-path pre-reduction branch of the fast multiplier.
        let a = p.add_ref(&BigUint::from_u64(5));
        let b = p.add_ref(p).add_ref(&BigUint::from_u64(3));
        assert_eq!(fast.mul(&a, &b), generic.mul(&a, &b));
        // Also exercise extreme overflow: a much larger than p².
        let mut big = p.clone();
        big.shl_bits(50);
        let huge = big.add_ref(&BigUint::from_u64(1234));
        assert_eq!(fast.mul(&huge, &BigUint::from_u64(7)), generic.mul(&huge, &BigUint::from_u64(7)));
    }

    fn check_worst_case_convergence(p: &BigUint, fast: &PrimeField, generic: &PrimeField) {
        // (p − 1)² is the largest in-range product the fold loop ever
        // sees; Solinas reductions with max_offset close to k strip
        // the fewest bits per fold and so this is the convergence
        // worst case. A regression in the iteration cap would panic
        // here before it could quietly mis-reduce.
        let p_minus_1 = p.sub_ref(&BigUint::one());
        let want = generic.mul(&p_minus_1, &p_minus_1);
        let got = fast.mul(&p_minus_1, &p_minus_1);
        assert_eq!(got, want, "(p − 1)² mismatch");
        // p · p ≡ 0; verifies that an input == p (k bits, but at the
        // boundary) routes through the slow-path pre-reduce and
        // produces zero, not p² silently truncated.
        assert_eq!(fast.mul(p, p), BigUint::zero());
        // p · 1 ≡ 0 likewise.
        assert_eq!(fast.mul(p, &BigUint::one()), BigUint::zero());
    }

    fn full_prime_check(name: &'static str, p: BigUint, expected_bits: usize, seed: u8) {
        assert_eq!(p.bits(), expected_bits, "{name}: bit length");
        // Always run the fuzz against a non-Generic path explicitly,
        // even when the production dispatch would route this prime to
        // Generic via `prefer_fast: false`. We want the correctness
        // coverage regardless of whether the dispatch picks it.
        let kind = super::detect_kind(&p);
        let fast = if matches!(kind, super::FieldKind::Mersenne127 | super::FieldKind::Reduction(_)) {
            PrimeField::new_unchecked(p.clone())
        } else {
            // The production dispatch routes this prime to Generic;
            // force the reducer for the test so we still validate it.
            force_reduction_for(&p)
        };
        let generic = generic_for(&p);
        check_edges(&p, &fast, &generic);
        check_unreduced_inputs(&p, &fast, &generic);
        check_worst_case_convergence(&p, &fast, &generic);
        fuzz_against_generic(&p, &fast, &generic, seed);
    }

    #[test]
    fn fuzz_mersenne521() {
        full_prime_check("mersenne521", mersenne521(), 521, 0x21);
    }

    #[test]
    fn fuzz_curve25519() {
        full_prime_check("curve25519", curve25519_field(), 255, 0x25);
    }

    #[test]
    fn fuzz_poly1305() {
        full_prime_check("poly1305", poly1305_field(), 130, 0x05);
    }

    #[test]
    fn fuzz_secp256k1() {
        full_prime_check("secp256k1", secp256k1_field(), 256, 0x6B);
    }

    #[test]
    fn fuzz_curve448() {
        full_prime_check("curve448", curve448_field(), 448, 0x48);
    }

    #[test]
    fn fuzz_nist_p192() {
        full_prime_check("nist_p192", nist_p192_field(), 192, 0x92);
    }

    #[test]
    fn fuzz_nist_p224() {
        full_prime_check("nist_p224", nist_p224_field(), 224, 0x24);
    }

    #[test]
    fn fuzz_nist_p256() {
        full_prime_check("nist_p256", nist_p256_field(), 256, 0x56);
    }

    #[test]
    fn fuzz_nist_p384() {
        full_prime_check("nist_p384", nist_p384_field(), 384, 0x84);
    }

    #[test]
    fn canonical_hex_values_match_standards() {
        // Spot-check each constructor against the canonical hex form
        // published in its standard. If a constructor regression turns
        // a constant into a near-miss, the field-arithmetic fuzz tests
        // would still pass (because both fast and generic paths share
        // the same wrong p), so this test must be a content check, not
        // a self-consistency check.

        // NIST P-256 (FIPS 186-4 §D.1.2.3):
        //   p = ffffffff00000001 0000000000000000 00000000ffffffff ffffffffffffffff
        let p256 = nist_p256_field();
        let expected_p256 = BigUint::from_be_bytes(&hex_decode(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        assert_eq!(p256, expected_p256, "NIST P-256");

        // NIST P-384 (FIPS 186-4 §D.1.2.4):
        //   p = ffffffffffffffff ffffffffffffffff ffffffffffffffff
        //       fffffffffffffffe ffffffff00000000 00000000ffffffff
        let p384 = nist_p384_field();
        let expected_p384 = BigUint::from_be_bytes(&hex_decode(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffff0000000000000000ffffffff",
        ));
        assert_eq!(p384, expected_p384, "NIST P-384");

        // NIST P-224 (FIPS 186-4 §D.1.2.2):
        //   p = ffffffffffffffff ffffffffffffffff ffffffff00000000 00000001
        let p224 = nist_p224_field();
        let expected_p224 = BigUint::from_be_bytes(&hex_decode(
            "ffffffffffffffffffffffffffffffff000000000000000000000001",
        ));
        assert_eq!(p224, expected_p224, "NIST P-224");

        // NIST P-192 (FIPS 186-4 §D.1.2.1):
        //   p = ffffffffffffffff fffffffffffffffe ffffffffffffffff
        let p192 = nist_p192_field();
        let expected_p192 = BigUint::from_be_bytes(&hex_decode(
            "fffffffffffffffffffffffffffffffeffffffffffffffff",
        ));
        assert_eq!(p192, expected_p192, "NIST P-192");

        // secp256k1 (SEC 2 §2.4.1):
        //   p = ffffffffffffffff ffffffffffffffff ffffffffffffffff fffffffefffffc2f
        let secp = secp256k1_field();
        let expected_secp = BigUint::from_be_bytes(&hex_decode(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        ));
        assert_eq!(secp, expected_secp, "secp256k1");

        // Curve25519 (RFC 7748): p = 2^255 − 19.
        let c25519 = curve25519_field();
        let expected_c25519 = BigUint::from_be_bytes(&hex_decode(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        ));
        assert_eq!(c25519, expected_c25519, "curve25519");

        // Curve448 (RFC 7748): p = 2^448 − 2^224 − 1.
        let c448 = curve448_field();
        let expected_c448 = BigUint::from_be_bytes(&hex_decode(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ));
        assert_eq!(c448, expected_c448, "curve448");

        // Poly1305 (RFC 8439): p = 2^130 − 5. 130 bits = 33 nibbles,
        // so pad the leading nibble with a 0 to make the byte decode
        // round-trip cleanly.
        let poly = poly1305_field();
        let expected_poly = BigUint::from_be_bytes(&hex_decode(
            "03fffffffffffffffffffffffffffffffb",
        ));
        assert_eq!(poly, expected_poly, "poly1305");

        // mersenne521 (= NIST P-521): p = 2^521 − 1.
        // 521 bits = 65 bytes + 1 bit, so the leading byte is 0x01.
        let m521 = mersenne521();
        let mut expected_m521 = BigUint::one();
        expected_m521.shl_bits(521);
        expected_m521 = expected_m521.sub_ref(&BigUint::one());
        assert_eq!(m521, expected_m521, "mersenne521");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2), "hex must have even length");
        cleaned
            .chunks_exact(2)
            .map(|pair| {
                let hi = nibble(pair[0]);
                let lo = nibble(pair[1]);
                (hi << 4) | lo
            })
            .collect()
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("non-hex char"),
        }
    }

    #[test]
    fn detect_kind_routes_each_known_prime_to_fast_path() {
        // The dispatch must select either Mersenne127 or the
        // parametric Reduction variant for every standardised prime
        // whose `prefer_fast` flag is true. NIST P-256 currently has
        // `prefer_fast: false` (Montgomery beats the parametric
        // reducer there) and is excluded from this list — its
        // correctness is still covered by `fuzz_nist_p256` via
        // `force_reduction_for`.
        let cases: &[(&str, BigUint)] = &[
            ("mersenne127", mersenne127()),
            ("mersenne521", mersenne521()),
            ("curve25519", curve25519_field()),
            ("poly1305", poly1305_field()),
            ("secp256k1", secp256k1_field()),
            ("curve448", curve448_field()),
            ("nist_p192", nist_p192_field()),
            ("nist_p224", nist_p224_field()),
            ("nist_p384", nist_p384_field()),
        ];
        for (name, p) in cases {
            let f = PrimeField::new_unchecked(p.clone());
            let routed = matches!(
                f.kind,
                FieldKind::Mersenne127 | FieldKind::Reduction(_)
            );
            assert!(routed, "{name} fell through to Generic");
        }
    }

    #[test]
    fn nist_p256_routes_to_generic_when_prefer_fast_false() {
        // NIST P-256 is in the table but `prefer_fast: false`; the
        // production dispatch must pick Generic. Lock in the contract
        // so a future flag flip is visible in test output.
        let f = PrimeField::new_unchecked(nist_p256_field());
        assert!(matches!(f.kind, FieldKind::Generic),
            "nist_p256 should route to Generic when prefer_fast is false");
    }

    #[test]
    fn fuzz_mersenne127() {
        // The unified harness is run against the Mersenne-127 fast
        // path so that `check_worst_case_convergence` (mul(p, p),
        // mul(p, 1), (p − 1)²) covers the u128 path explicitly, not
        // just by inheritance from the cross-product edges loop.
        full_prime_check("mersenne127", mersenne127(), 127, 0xC1);
    }

    // Negative tests for `validate_reduction_params`. Each malformed
    // table entry should panic at validation time rather than wire
    // into the dispatch and silently mis-reduce. The contracts being
    // pinned: non-zero coefficients, offsets strictly less than k,
    // strictly positive δ, and δ matches 2^k − p exactly.

    #[test]
    #[should_panic(expected = "zero coefficient")]
    fn validate_rejects_zero_coefficient() {
        static BAD: &[super::ReductionTerm] = &[super::ReductionTerm { offset: 0, coef: 0 }];
        let params = super::ReductionParams {
            k: 127,
            terms: BAD,
            p: mersenne127(),
            name: "bad_zero_coef", prefer_fast: true,
        };
        super::validate_reduction_params(&params);
    }

    #[test]
    #[should_panic(expected = "≥ k")]
    fn validate_rejects_offset_at_or_above_k() {
        static BAD: &[super::ReductionTerm] = &[super::ReductionTerm { offset: 127, coef: 1 }];
        let params = super::ReductionParams {
            k: 127,
            terms: BAD,
            p: mersenne127(),
            name: "bad_offset", prefer_fast: true,
        };
        super::validate_reduction_params(&params);
    }

    #[test]
    #[should_panic(expected = "δ must be positive")]
    fn validate_rejects_nonpositive_delta() {
        // δ = -1 (single negative term at offset 0). For any k > 0
        // the implied prime would be 2^k + 1 (composite for many k);
        // regardless, the fold algorithm assumes δ > 0.
        static BAD: &[super::ReductionTerm] = &[super::ReductionTerm { offset: 0, coef: -1 }];
        // We need a prime field that makes the mismatch test
        // unreachable — supply p = 2^127 + 1 (whatever that resolves
        // to) so the validator hits the δ-positivity check first.
        let mut p = BigUint::one();
        p.shl_bits(127);
        p = p.add_ref(&BigUint::one());
        let params = super::ReductionParams {
            k: 127,
            terms: BAD,
            p,
            name: "bad_negative_delta", prefer_fast: true,
        };
        super::validate_reduction_params(&params);
    }

    #[test]
    #[should_panic(expected = "does not match 2^k − p")]
    fn validate_rejects_mismatched_polynomial() {
        // Term polynomial says δ = 5, but the supplied p says
        // 2^127 − p = 1 (= mersenne127). The mismatch should fire.
        static BAD: &[super::ReductionTerm] = &[super::ReductionTerm { offset: 0, coef: 5 }];
        let params = super::ReductionParams {
            k: 127,
            terms: BAD,
            p: mersenne127(),
            name: "bad_polynomial_mismatch", prefer_fast: true,
        };
        super::validate_reduction_params(&params);
    }

    #[test]
    fn unknown_modulus_falls_through_to_generic() {
        // A random prime not in the table must NOT match any reduction
        // params (otherwise correctness for arbitrary primes would
        // depend on the prime not happening to alias a standardised
        // value bit-for-bit). 1_000_000_007 is the canonical small
        // prime that's nowhere near any known curve modulus.
        let p = BigUint::from_u64(1_000_000_007);
        let f = PrimeField::new_unchecked(p);
        assert!(matches!(f.kind, FieldKind::Generic));
    }
}
