#include "secret_sharing/field.hpp"

#include <stdexcept>

namespace secret_sharing {

namespace {

// Mersenne-127 fast path. Mirrors `field::mul_mod_mersenne127`
// in the Rust crate, including the exact bit pattern of the fold.
__uint128_t mul_mod_mersenne127(__uint128_t a, __uint128_t b) {
    auto al = static_cast<std::uint64_t>(a);
    auto ah = static_cast<std::uint64_t>(a >> 64U);
    auto bl = static_cast<std::uint64_t>(b);
    auto bh = static_cast<std::uint64_t>(b >> 64U);

    auto p00 = static_cast<__uint128_t>(al) * static_cast<__uint128_t>(bl);
    auto p01 = static_cast<__uint128_t>(al) * static_cast<__uint128_t>(bh);
    auto p10 = static_cast<__uint128_t>(ah) * static_cast<__uint128_t>(bl);
    auto p11 = static_cast<__uint128_t>(ah) * static_cast<__uint128_t>(bh);

    auto r0 = static_cast<std::uint64_t>(p00);
    auto mid = (p00 >> 64U) + static_cast<__uint128_t>(static_cast<std::uint64_t>(p01))
        + static_cast<__uint128_t>(static_cast<std::uint64_t>(p10));
    auto r1 = static_cast<std::uint64_t>(mid);
    auto mid_hi = (mid >> 64U) + (p01 >> 64U) + (p10 >> 64U)
        + static_cast<__uint128_t>(static_cast<std::uint64_t>(p11));
    auto r2 = static_cast<std::uint64_t>(mid_hi);
    auto r3 = static_cast<std::uint64_t>((mid_hi >> 64U) + (p11 >> 64U));

    auto low = static_cast<__uint128_t>(r0)
        | (static_cast<__uint128_t>(r1 & 0x7FFF'FFFF'FFFF'FFFFULL) << 64U);
    auto high_lo = (r1 >> 63U) | (r2 << 1U);
    auto high_hi = (r2 >> 63U) | (r3 << 1U);
    auto high = static_cast<__uint128_t>(high_lo) | (static_cast<__uint128_t>(high_hi) << 64U);
    auto sum = low + high;

    auto mask127 = (static_cast<__uint128_t>(1) << 127U) - 1;
    auto folded = (sum & mask127) + (sum >> 127U);
    return folded >= mask127 ? folded - mask127 : folded;
}

big_uint mersenne127_mul(big_uint const& a, big_uint const& b, big_uint const& p) {
    auto a128 = a.bits() <= 127 ? a.low_u128() : a.modulo(p).low_u128();
    auto b128 = b.bits() <= 127 ? b.low_u128() : b.modulo(p).low_u128();
    return big_uint::from_u128(mul_mod_mersenne127(a128, b128));
}

}  // namespace

big_uint mersenne127() {
    auto v = big_uint::one();
    v.shl_bits(127);
    return v.sub_ref(big_uint::one());
}

prime_field::prime_field(big_uint p) : p_(std::move(p)), kind_(detect(p_)) {
    if (!(p_ > big_uint::one())) {
        throw std::invalid_argument("modulus must be > 1");
    }
}

prime_field::kind prime_field::detect(big_uint const& p) {
    if (p == mersenne127()) {
        return kind::mersenne127;
    }
    return kind::generic;
}

big_uint prime_field::add(big_uint const& a, big_uint const& b) const {
    return a.add_ref(b).modulo(p_);
}

big_uint prime_field::sub(big_uint const& a, big_uint const& b) const {
    auto ar = reduce(a);
    auto br = reduce(b);
    if (ar >= br) {
        return ar.sub_ref(br);
    }
    return ar.add_ref(p_).sub_ref(br);
}

big_uint prime_field::neg(big_uint const& a) const {
    auto ar = reduce(a);
    if (ar.is_zero()) {
        return big_uint::zero();
    }
    return p_.sub_ref(ar);
}

big_uint prime_field::mul(big_uint const& a, big_uint const& b) const {
    switch (kind_) {
    case kind::mersenne127:
        return mersenne127_mul(a, b, p_);
    case kind::generic:
        return big_uint::mod_mul(a, b, p_);
    }
    throw std::logic_error("prime_field::mul: unknown kind");
}

std::optional<big_uint> prime_field::inv(big_uint const& a) const {
    auto ar = reduce(a);
    if (ar.is_zero()) {
        return std::nullopt;
    }
    return mod_inverse(ar, p_);
}

big_uint prime_field::random(csprng& rng) const {
    auto v = random_below(rng, p_);
    if (!v) {
        throw std::logic_error("modulus must be > 0");
    }
    return std::move(*v);
}

// ── helpers ───────────────────────────────────────────────────────

std::optional<big_uint> mod_inverse(big_uint const& a, big_uint const& modulus) {
    // Extended Euclidean over signed values, matching the Rust impl.
    if (modulus.is_zero() || modulus.is_one()) {
        return std::nullopt;
    }
    if (a.is_zero()) {
        return std::nullopt;
    }

    // Use big_uint with explicit sign tracking.
    enum class sign { plus, minus };
    struct sint {
        sign s;
        big_uint mag;
    };

    auto sint_zero = sint{sign::plus, big_uint::zero()};
    auto sint_one = sint{sign::plus, big_uint::one()};
    auto sub = [](sint const& x, sint const& y) -> sint {
        // x − y
        if (x.s == sign::plus && y.s == sign::plus) {
            if (x.mag >= y.mag) {
                return {sign::plus, x.mag.sub_ref(y.mag)};
            }
            return {sign::minus, y.mag.sub_ref(x.mag)};
        }
        if (x.s == sign::minus && y.s == sign::minus) {
            if (y.mag >= x.mag) {
                return {sign::plus, y.mag.sub_ref(x.mag)};
            }
            return {sign::minus, x.mag.sub_ref(y.mag)};
        }
        // Mixed signs: result has x's sign and magnitude is the sum.
        return {x.s, x.mag.add_ref(y.mag)};
    };
    auto mul_then_sub = [&](sint const& x, sint const& y, big_uint const& q) -> sint {
        // x − q·y, with q a non-negative big_uint.
        auto mag = q.mul_ref(y.mag);
        sint qy{y.s, std::move(mag)};
        return sub(x, qy);
    };
    auto canon = [&](sint const& v) -> big_uint {
        if (v.s == sign::plus) {
            return v.mag.modulo(modulus);
        }
        auto r = v.mag.modulo(modulus);
        if (r.is_zero()) {
            return big_uint::zero();
        }
        return modulus.sub_ref(r);
    };

    big_uint old_r = a;
    big_uint r = modulus;
    sint old_s = sint_one;
    sint s_v = sint_zero;

    while (!r.is_zero()) {
        auto [q, rem] = old_r.div_rem(r);
        old_r = std::move(r);
        r = std::move(rem);
        auto next_s = mul_then_sub(old_s, s_v, q);
        old_s = std::move(s_v);
        s_v = std::move(next_s);
    }

    if (!old_r.is_one()) {
        return std::nullopt;
    }
    return canon(old_s);
}

std::optional<big_uint> random_below(csprng& rng, big_uint const& modulus) {
    if (modulus.is_zero()) {
        return std::nullopt;
    }
    auto bits = modulus.bits();
    auto bytes = (bits + 7) / 8;
    auto top_byte_mask = static_cast<std::uint8_t>(0xFFU >> ((8 - (bits % 8)) % 8));
    std::vector<std::uint8_t> buf(bytes);
    while (true) {
        rng.fill_bytes(std::span<std::uint8_t>{buf.data(), buf.size()});
        if (top_byte_mask != 0xFFU) {
            buf[0] &= top_byte_mask;
        }
        auto candidate = big_uint::from_be_bytes(std::span<std::uint8_t const>{buf.data(), buf.size()});
        if (candidate < modulus) {
            return candidate;
        }
    }
}

}  // namespace secret_sharing
