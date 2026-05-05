// Implementation of secret_sharing::big_uint.
//
// Algorithms are direct translations of the Rust BigUint at
// `../../src/bigint.rs`. Every operation produces the same byte
// stream when serialised via `to_be_bytes`, so callers on either
// side of the FFI boundary can round-trip values bit-for-bit.

#include "secret_sharing/bigint.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace secret_sharing {

namespace {

// Karatsuba dispatch heuristic — same crossover as the Rust impl.
constexpr std::size_t KARATSUBA_THRESHOLD_LIMBS = 32;
constexpr std::size_t KARATSUBA_MAX_IMBALANCE = 2;

// Volatile-zero a contiguous u64 buffer; the optimiser must not
// elide these stores since the buffer is about to be freed back to
// the allocator. Mirrors `BigUint::Drop` in the Rust crate.
void volatile_zero_u64(std::uint64_t* p, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        // SAFETY: caller passes a valid contiguous range we own.
        // volatile write through the raw pointer prevents elision.
        auto* vp = static_cast<volatile std::uint64_t*>(p + i);
        *vp = 0U;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

}  // namespace

big_uint::big_uint(std::uint64_t v) {
    if (v != 0) {
        limbs_.push_back(v);
    }
}

big_uint big_uint::from_u128(__uint128_t v) {
    big_uint out;
    if (v == 0) {
        return out;
    }
    auto lo = static_cast<std::uint64_t>(v);
    auto hi = static_cast<std::uint64_t>(v >> 64U);
    if (hi == 0) {
        out.limbs_.push_back(lo);
    } else {
        out.limbs_.push_back(lo);
        out.limbs_.push_back(hi);
    }
    return out;
}

big_uint big_uint::one() {
    big_uint v;
    v.limbs_.push_back(1);
    return v;
}

big_uint big_uint::from_be_bytes(std::span<std::uint8_t const> bytes) {
    big_uint out;
    if (bytes.empty()) {
        return out;
    }
    out.limbs_.reserve((bytes.size() + 7) / 8);
    std::uint64_t acc = 0;
    std::uint32_t shift = 0;
    // Walk bytes least-significant first (i.e. last byte of input).
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        acc |= static_cast<std::uint64_t>(*it) << shift;
        shift += 8;
        if (shift == 64) {
            out.limbs_.push_back(acc);
            acc = 0;
            shift = 0;
        }
    }
    if (shift != 0) {
        out.limbs_.push_back(acc);
    }
    out.normalise();
    return out;
}

big_uint::~big_uint() {
    auto cap = limbs_.capacity();
    if (cap > 0) {
        volatile_zero_u64(limbs_.data(), cap);
    }
}

void big_uint::normalise() noexcept {
    while (!limbs_.empty() && limbs_.back() == 0) {
        limbs_.pop_back();
    }
}

bool big_uint::is_one() const noexcept {
    return limbs_.size() == 1 && limbs_[0] == 1;
}

bool big_uint::is_odd() const noexcept {
    return !is_zero() && ((limbs_[0] & 1U) == 1);
}

std::size_t big_uint::bits() const noexcept {
    if (is_zero()) {
        return 0;
    }
    auto top = limbs_.back();
    auto top_bits = static_cast<std::size_t>(64 - std::countl_zero(top));
    return (limbs_.size() - 1) * 64 + top_bits;
}

bool big_uint::bit(std::size_t index) const noexcept {
    auto limb = index / 64;
    auto shift = index % 64;
    if (limb >= limbs_.size()) {
        return false;
    }
    return ((limbs_[limb] >> shift) & 1U) == 1;
}

void big_uint::set_bit(std::size_t index) {
    auto limb = index / 64;
    auto shift = index % 64;
    if (limbs_.size() <= limb) {
        limbs_.resize(limb + 1, 0);
    }
    limbs_[limb] |= static_cast<std::uint64_t>(1) << shift;
}

std::vector<std::uint8_t> big_uint::to_be_bytes() const {
    if (is_zero()) {
        return {0};
    }
    std::vector<std::uint8_t> out;
    out.reserve(limbs_.size() * 8);
    for (auto it = limbs_.rbegin(); it != limbs_.rend(); ++it) {
        auto limb = *it;
        for (int byte = 7; byte >= 0; --byte) {
            out.push_back(static_cast<std::uint8_t>(limb >> (byte * 8)));
        }
    }
    auto first_nonzero = std::find_if(out.begin(), out.end(), [](auto b) { return b != 0; });
    if (first_nonzero == out.end()) {
        throw std::logic_error("non-zero big_uint encoded to all zeros");
    }
    out.erase(out.begin(), first_nonzero);
    return out;
}

bool operator==(big_uint const& a, big_uint const& b) noexcept {
    auto n = std::max(a.limbs_.size(), b.limbs_.size());
    std::uint64_t acc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        acc |= a.limb_or_zero(i) ^ b.limb_or_zero(i);
    }
    return acc == 0;
}

std::strong_ordering operator<=>(big_uint const& a, big_uint const& b) noexcept {
    if (auto cmp = a.limbs_.size() <=> b.limbs_.size(); cmp != 0) {
        return cmp;
    }
    for (std::size_t i = a.limbs_.size(); i-- > 0;) {
        if (auto cmp = a.limbs_[i] <=> b.limbs_[i]; cmp != 0) {
            return cmp;
        }
    }
    return std::strong_ordering::equal;
}

void big_uint::add_assign_ref(big_uint const& other) {
    if (other.is_zero()) {
        return;
    }
    if (limbs_.size() < other.limbs_.size()) {
        limbs_.resize(other.limbs_.size(), 0);
    }
    __uint128_t carry = 0;
    for (std::size_t i = 0; i < other.limbs_.size(); ++i) {
        __uint128_t sum = static_cast<__uint128_t>(limbs_[i])
            + static_cast<__uint128_t>(other.limbs_[i]) + carry;
        limbs_[i] = static_cast<std::uint64_t>(sum);
        carry = sum >> 64U;
    }
    std::size_t i = other.limbs_.size();
    while (carry != 0 && i < limbs_.size()) {
        __uint128_t sum = static_cast<__uint128_t>(limbs_[i]) + carry;
        limbs_[i] = static_cast<std::uint64_t>(sum);
        carry = sum >> 64U;
        ++i;
    }
    if (carry != 0) {
        limbs_.push_back(static_cast<std::uint64_t>(carry));
    }
}

big_uint big_uint::add_ref(big_uint const& other) const {
    big_uint out = *this;
    out.add_assign_ref(other);
    return out;
}

void big_uint::sub_assign_ref(big_uint const& other) {
    if (*this < other) {
        throw std::underflow_error("big_uint underflow");
    }
    if (other.is_zero()) {
        return;
    }
    __uint128_t borrow = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
        __uint128_t lhs = limbs_[i];
        __uint128_t rhs = i < other.limbs_.size() ? other.limbs_[i] : 0;
        __uint128_t subtrahend = rhs + borrow;
        if (lhs >= subtrahend) {
            limbs_[i] = static_cast<std::uint64_t>(lhs - subtrahend);
            borrow = 0;
        } else {
            limbs_[i] = static_cast<std::uint64_t>((static_cast<__uint128_t>(1) << 64U)
                                                   + lhs - subtrahend);
            borrow = 1;
        }
    }
    normalise();
}

big_uint big_uint::sub_ref(big_uint const& other) const {
    big_uint out = *this;
    out.sub_assign_ref(other);
    return out;
}

bool big_uint::should_use_karatsuba(big_uint const& lhs, big_uint const& rhs) noexcept {
    auto shorter = std::min(lhs.limbs_.size(), rhs.limbs_.size());
    auto longer = std::max(lhs.limbs_.size(), rhs.limbs_.size());
    return shorter >= KARATSUBA_THRESHOLD_LIMBS && longer <= shorter * KARATSUBA_MAX_IMBALANCE;
}

big_uint big_uint::mul_schoolbook(big_uint const& lhs, big_uint const& rhs) {
    if (lhs.is_zero() || rhs.is_zero()) {
        return zero();
    }
    std::vector<std::uint64_t> out(lhs.limbs_.size() + rhs.limbs_.size(), 0);
    for (std::size_t i = 0; i < lhs.limbs_.size(); ++i) {
        __uint128_t carry = 0;
        for (std::size_t j = 0; j < rhs.limbs_.size(); ++j) {
            __uint128_t acc = static_cast<__uint128_t>(out[i + j])
                + static_cast<__uint128_t>(lhs.limbs_[i]) * static_cast<__uint128_t>(rhs.limbs_[j])
                + carry;
            out[i + j] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
        }
        std::size_t idx = i + rhs.limbs_.size();
        while (carry != 0) {
            __uint128_t acc = static_cast<__uint128_t>(out[idx]) + carry;
            out[idx] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
            ++idx;
        }
    }
    big_uint result;
    result.limbs_ = std::move(out);
    result.normalise();
    return result;
}

std::pair<big_uint, big_uint> big_uint::split_at_limb(std::size_t split) const {
    auto low_end = std::min(split, limbs_.size());
    big_uint low;
    low.limbs_.assign(limbs_.begin(), limbs_.begin() + static_cast<std::ptrdiff_t>(low_end));
    low.normalise();
    if (split >= limbs_.size()) {
        return {std::move(low), zero()};
    }
    big_uint high;
    high.limbs_.assign(limbs_.begin() + static_cast<std::ptrdiff_t>(split), limbs_.end());
    high.normalise();
    return {std::move(low), std::move(high)};
}

big_uint big_uint::mul_karatsuba(big_uint const& lhs, big_uint const& rhs) {
    auto split = std::max(lhs.limbs_.size(), rhs.limbs_.size()) / 2;
    if (split == 0) {
        return mul_schoolbook(lhs, rhs);
    }
    auto [a0, a1] = lhs.split_at_limb(split);
    auto [b0, b1] = rhs.split_at_limb(split);
    if (a1.is_zero() || b1.is_zero()) {
        return mul_schoolbook(lhs, rhs);
    }
    auto z0 = a0.mul_ref(b0);
    auto z2 = a1.mul_ref(b1);
    auto a_sum = a0.add_ref(a1);
    auto b_sum = b0.add_ref(b1);
    auto z1 = a_sum.mul_ref(b_sum);
    z1.sub_assign_ref(z0);
    z1.sub_assign_ref(z2);

    big_uint out = std::move(z0);
    z1.shl_bits(split * 64);
    out.add_assign_ref(z1);

    big_uint z2_shifted = std::move(z2);
    z2_shifted.shl_bits(split * 128);
    out.add_assign_ref(z2_shifted);
    return out;
}

big_uint big_uint::mul_ref(big_uint const& other) const {
    if (is_zero() || other.is_zero()) {
        return zero();
    }
    if (should_use_karatsuba(*this, other)) {
        return mul_karatsuba(*this, other);
    }
    return mul_schoolbook(*this, other);
}

void big_uint::shl1() {
    if (is_zero()) {
        return;
    }
    std::uint64_t carry = 0;
    for (auto& limb : limbs_) {
        auto next_carry = limb >> 63U;
        limb = (limb << 1U) | carry;
        carry = next_carry;
    }
    if (carry != 0) {
        limbs_.push_back(carry);
    }
}

void big_uint::shr1() {
    if (is_zero()) {
        return;
    }
    std::uint64_t carry = 0;
    for (std::size_t i = limbs_.size(); i-- > 0;) {
        auto next_carry = (limbs_[i] & 1U) << 63U;
        limbs_[i] = (limbs_[i] >> 1U) | carry;
        carry = next_carry;
    }
    normalise();
}

void big_uint::shl_bits(std::size_t n) {
    if (is_zero() || n == 0) {
        return;
    }
    auto limb_shifts = n / 64;
    auto bit_shifts = static_cast<std::uint32_t>(n % 64);
    if (limb_shifts > 0) {
        std::vector<std::uint64_t> next(limb_shifts, 0);
        next.insert(next.end(), limbs_.begin(), limbs_.end());
        limbs_ = std::move(next);
    }
    if (bit_shifts > 0) {
        std::uint64_t carry = 0;
        for (auto& limb : limbs_) {
            auto next_carry = limb >> (64U - bit_shifts);
            limb = (limb << bit_shifts) | carry;
            carry = next_carry;
        }
        if (carry != 0) {
            limbs_.push_back(carry);
        }
    }
}

big_uint big_uint::shr_bits(std::size_t n) const {
    if (n == 0) {
        return *this;
    }
    auto limb_shifts = n / 64;
    auto bit_shifts = static_cast<std::uint32_t>(n % 64);
    if (limb_shifts >= limbs_.size()) {
        return zero();
    }
    big_uint out;
    out.limbs_.assign(limbs_.begin() + static_cast<std::ptrdiff_t>(limb_shifts), limbs_.end());
    if (bit_shifts > 0) {
        std::uint64_t carry = 0;
        for (std::size_t i = out.limbs_.size(); i-- > 0;) {
            auto next_carry = out.limbs_[i] << (64U - bit_shifts);
            out.limbs_[i] = (out.limbs_[i] >> bit_shifts) | carry;
            carry = next_carry;
        }
    }
    out.normalise();
    return out;
}

big_uint big_uint::low_bits(std::size_t k) const {
    if (k == 0) {
        return zero();
    }
    auto limb_count = k / 64;
    auto bit_remainder = static_cast<std::uint32_t>(k % 64);
    big_uint out;
    auto take = std::min(limb_count, limbs_.size());
    out.limbs_.assign(limbs_.begin(), limbs_.begin() + static_cast<std::ptrdiff_t>(take));
    if (bit_remainder != 0 && limb_count < limbs_.size()) {
        std::uint64_t mask = (static_cast<std::uint64_t>(1) << bit_remainder) - 1;
        out.limbs_.push_back(limbs_[limb_count] & mask);
    }
    out.normalise();
    return out;
}

std::pair<big_uint, big_uint> big_uint::div_rem(big_uint const& divisor) const {
    if (divisor.is_zero()) {
        throw std::domain_error("division by zero");
    }
    if (*this < divisor) {
        return {zero(), *this};
    }
    big_uint quotient;
    big_uint remainder;
    for (std::size_t bit_idx = bits(); bit_idx-- > 0;) {
        remainder.shl1();
        if (bit(bit_idx)) {
            if (remainder.is_zero()) {
                remainder.limbs_.push_back(1);
            } else {
                remainder.limbs_[0] |= 1U;
            }
        }
        if (!(remainder < divisor)) {
            remainder.sub_assign_ref(divisor);
            quotient.set_bit(bit_idx);
        }
    }
    return {std::move(quotient), std::move(remainder)};
}

__uint128_t big_uint::low_u128() const noexcept {
    auto lo = limb_or_zero(0);
    auto hi = limb_or_zero(1);
    return static_cast<__uint128_t>(lo) | (static_cast<__uint128_t>(hi) << 64U);
}

big_uint big_uint::mod_mul_plain(big_uint const& lhs, big_uint const& rhs,
                                 big_uint const& modulus) {
    if (lhs.is_zero() || rhs.is_zero()) {
        return zero();
    }
    auto a = lhs.modulo(modulus);
    auto b = rhs;
    big_uint out;
    while (!b.is_zero()) {
        if (b.is_odd()) {
            out = out.add_ref(a).modulo(modulus);
        }
        a = a.add_ref(a).modulo(modulus);
        b.shr1();
    }
    return out;
}

big_uint big_uint::mod_mul(big_uint const& lhs, big_uint const& rhs, big_uint const& modulus) {
    if (modulus.is_zero()) {
        throw std::domain_error("modulus must be non-zero");
    }
    if (modulus == one()) {
        return zero();
    }
    if (auto ctx = montgomery_ctx::make(modulus)) {
        return ctx->mul(lhs, rhs);
    }
    return mod_mul_plain(lhs, rhs, modulus);
}

// ── montgomery_ctx ────────────────────────────────────────────────

namespace {

// Newton iteration in Z_(2^64): six steps converge to the full 64-bit
// inverse, matching the Rust `montgomery_n0_inv`.
std::uint64_t montgomery_n0_inv(std::uint64_t n0) {
    std::uint64_t inv = 1;
    for (int i = 0; i < 6; ++i) {
        // inv ← inv · (2 − n0 · inv)
        std::uint64_t prod = n0 * inv;
        std::uint64_t two_minus = static_cast<std::uint64_t>(2) - prod;
        inv = inv * two_minus;
    }
    // Rust returns -inv via wrapping_neg.
    return static_cast<std::uint64_t>(0) - inv;
}

}  // namespace

big_uint big_uint::montgomery_mul_odd_with_workspace(big_uint const& lhs, big_uint const& rhs,
                                                      big_uint const& modulus,
                                                      std::uint64_t n0_inv,
                                                      std::vector<std::uint64_t>& workspace) {
    auto width = modulus.limbs().size();
    auto needed = width * 2 + 2;
    if (workspace.size() != needed) {
        workspace.assign(needed, 0);
    } else {
        std::fill(workspace.begin(), workspace.end(), 0);
    }
    auto lhs_limb = [&](std::size_t i) {
        return i < lhs.limbs().size() ? lhs.limbs()[i] : std::uint64_t{0};
    };
    auto rhs_limb = [&](std::size_t i) {
        return i < rhs.limbs().size() ? rhs.limbs()[i] : std::uint64_t{0};
    };
    auto mod_limb = [&](std::size_t i) {
        return i < modulus.limbs().size() ? modulus.limbs()[i] : std::uint64_t{0};
    };

    // Pass 1: schoolbook product into workspace.
    for (std::size_t i = 0; i < width; ++i) {
        auto a = lhs_limb(i);
        __uint128_t carry = 0;
        for (std::size_t j = 0; j < width; ++j) {
            __uint128_t acc = static_cast<__uint128_t>(workspace[i + j])
                + static_cast<__uint128_t>(a) * static_cast<__uint128_t>(rhs_limb(j)) + carry;
            workspace[i + j] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
        }
        std::size_t idx = i + width;
        while (carry != 0) {
            __uint128_t acc = static_cast<__uint128_t>(workspace[idx]) + carry;
            workspace[idx] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
            ++idx;
        }
    }

    // Pass 2: Montgomery reduction.
    for (std::size_t i = 0; i < width; ++i) {
        std::uint64_t m = workspace[i] * n0_inv;
        __uint128_t carry = 0;
        for (std::size_t j = 0; j < width; ++j) {
            __uint128_t acc = static_cast<__uint128_t>(workspace[i + j])
                + static_cast<__uint128_t>(m) * static_cast<__uint128_t>(mod_limb(j)) + carry;
            workspace[i + j] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
        }
        std::size_t idx = i + width;
        while (carry != 0) {
            __uint128_t acc = static_cast<__uint128_t>(workspace[idx]) + carry;
            workspace[idx] = static_cast<std::uint64_t>(acc);
            carry = acc >> 64U;
            ++idx;
        }
    }

    // Result = workspace[width .. 2*width + 1] (one extra limb for carry).
    big_uint out;
    out.limbs_.assign(workspace.begin() + static_cast<std::ptrdiff_t>(width),
                      workspace.begin() + static_cast<std::ptrdiff_t>(width * 2 + 1));
    out.normalise();
    if (!(out < modulus)) {
        out.sub_assign_ref(modulus);
    }
    return out;
}

std::optional<montgomery_ctx> montgomery_ctx::make(big_uint const& modulus) {
    if (modulus.is_zero() || !modulus.is_odd()) {
        return std::nullopt;
    }
    montgomery_ctx ctx;
    ctx.modulus_ = modulus;
    ctx.n0_inv_ = montgomery_n0_inv(modulus.limbs()[0]);

    big_uint r2;
    r2.set_bit(modulus.limbs().size() * 128);
    ctx.r2_mod_ = r2.modulo(modulus);

    big_uint r;
    r.set_bit(modulus.limbs().size() * 64);
    ctx.one_mont_ = r.modulo(modulus);
    return ctx;
}

big_uint montgomery_ctx::encode(big_uint const& value) const {
    if (value.is_zero()) {
        return big_uint::zero();
    }
    std::vector<std::uint64_t> workspace;
    return big_uint::montgomery_mul_odd_with_workspace(value.modulo(modulus_), r2_mod_, modulus_, n0_inv_,
                                         workspace);
}

big_uint montgomery_ctx::decode(big_uint const& value) const {
    std::vector<std::uint64_t> workspace;
    return big_uint::montgomery_mul_odd_with_workspace(value, big_uint::one(), modulus_, n0_inv_, workspace);
}

big_uint montgomery_ctx::mont_mul(big_uint const& lhs, big_uint const& rhs) const {
    std::vector<std::uint64_t> workspace;
    return big_uint::montgomery_mul_odd_with_workspace(lhs, rhs, modulus_, n0_inv_, workspace);
}

big_uint montgomery_ctx::mul(big_uint const& lhs, big_uint const& rhs) const {
    auto a_mont = encode(lhs);
    auto b_mont = encode(rhs);
    auto prod_mont = mont_mul(a_mont, b_mont);
    return decode(prod_mont);
}

big_uint montgomery_ctx::square(big_uint const& value) const {
    auto v_mont = encode(value);
    auto sq_mont = mont_mul(v_mont, v_mont);
    return decode(sq_mont);
}

// Mirrors the Rust threshold: under 64 bits the binary
// square-and-multiply scan beats the 4-bit window scheme (the
// 14-multiply table-build cost dominates short exponents). Above the
// threshold the window scheme amortises that setup over the longer
// body and wins. cgma_vss exponents are 256-bit so they always take
// the window path.
constexpr std::size_t POW_WINDOW_THRESHOLD_BITS = 64;

big_uint montgomery_ctx::pow(big_uint const& base, big_uint const& exponent) const {
    if (modulus_ == big_uint::one()) {
        return big_uint::zero();
    }
    if (exponent.is_zero()) {
        return big_uint::one().modulo(modulus_);
    }
    auto base_mont = encode(base.modulo(modulus_));
    if (exponent.bits() < POW_WINDOW_THRESHOLD_BITS) {
        // Binary square-and-multiply: n squarings + ~n/2 multiplies,
        // no setup cost. Wins for short exponents.
        auto result = one_mont_;
        auto power = base_mont;
        for (std::size_t bit_idx = 0; bit_idx < exponent.bits(); ++bit_idx) {
            if (exponent.bit(bit_idx)) {
                result = mont_mul(result, power);
            }
            power = mont_mul(power, power);
        }
        return decode(result);
    }
    // 4-bit fixed-window MSB-first scan. n squarings + n/4 multiplies
    // + 14 setup multiplies; the body savings dominate the setup
    // once n ≥ ~56 bits, hence the 64-bit threshold above.
    constexpr std::size_t WINDOW_BITS = 4;
    constexpr std::size_t TABLE_SIZE = 1U << WINDOW_BITS;

    std::vector<big_uint> table;
    table.reserve(TABLE_SIZE);
    table.push_back(one_mont_);
    table.push_back(base_mont);
    for (std::size_t i = 2; i < TABLE_SIZE; ++i) {
        table.push_back(mont_mul(table[i - 1], base_mont));
    }

    // Read `width` bits ending at bit `top`, MSB-first into a table
    // index. width is in [1, WINDOW_BITS]; top ≥ width − 1 by the
    // remaining-bits invariant maintained by the caller.
    auto read_window = [&](std::size_t top, std::size_t width) -> std::size_t {
        std::size_t idx = 0;
        for (std::size_t i = 0; i < width; ++i) {
            idx <<= 1U;
            if (exponent.bit(top - i)) {
                idx |= 1U;
            }
        }
        return idx;
    };

    std::size_t n_bits = exponent.bits();
    std::size_t leading = n_bits % WINDOW_BITS;
    std::size_t initial_width = leading > 0 ? leading : WINDOW_BITS;
    std::size_t remaining = n_bits;
    std::size_t initial_top = remaining - 1;
    auto initial_idx = read_window(initial_top, initial_width);
    auto result = table[initial_idx];
    remaining -= initial_width;

    while (remaining > 0) {
        for (std::size_t i = 0; i < WINDOW_BITS; ++i) {
            result = mont_mul(result, result);
        }
        std::size_t top = remaining - 1;
        auto idx = read_window(top, WINDOW_BITS);
        if (idx != 0) {
            result = mont_mul(result, table[idx]);
        }
        remaining -= WINDOW_BITS;
    }
    return decode(result);
}

}  // namespace secret_sharing
