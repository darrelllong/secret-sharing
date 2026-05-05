#include "secret_sharing/field.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace secret_sharing {

namespace {

// ── Mersenne-127 u128 fast path ───────────────────────────────────

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

// ── Parametric pseudo-Mersenne / Solinas reducer ──────────────────

bool reduction_fold_in_place(big_uint& t, detail::reduction_params const& params);

big_uint reduction_mul(big_uint const& a, big_uint const& b,
                       detail::reduction_params const& params) {
    big_uint a_red;
    big_uint const* a_use = &a;
    if (a.bits() > params.k) {
        a_red = a.modulo(params.p);
        a_use = &a_red;
    }
    big_uint b_red;
    big_uint const* b_use = &b;
    if (b.bits() > params.k) {
        b_red = b.modulo(params.p);
        b_use = &b_red;
    }
    auto t = a_use->mul_ref(*b_use);

    // δ > 0 invariant (enforced at construction) plus a non-negative
    // initial product imply every fold produces a non-negative
    // result with strictly fewer bits, so the cap is generous. The
    // hard assert panics rather than silently returning a partially
    // reduced value if it's ever reached.
    constexpr std::size_t MAX_FOLDS = 32;
    std::size_t folds = 0;
    while (t.bits() > params.k) {
        if (folds >= MAX_FOLDS) {
            throw std::runtime_error(std::string{"reduction_mul did not converge for "}
                                     + params.name);
        }
        if (!reduction_fold_in_place(t, params)) {
            // Implementation invariant violated: pos < neg implies δ ≤ 0.
            throw std::runtime_error(
                std::string{"δ > 0 invariant violated at runtime for "} + params.name);
        }
        ++folds;
    }
    if (!(t < params.p)) {
        t.sub_assign_ref(params.p);
    }
    return t;
}

// One reduction step in place. Writes `|t| = high · 2^k + low`
// (limb-level shift + mask), then accumulates positive and negative
// term contributions into two `big_uint` running sums and assigns
// `pos − neg` back to `t`. Returns false if `pos < neg` — that
// would mean the δ > 0 invariant has been violated, and the caller
// converts it to a panic. For the registered primes this branch is
// unreachable.
bool reduction_fold_in_place(big_uint& t, detail::reduction_params const& params) {
    auto high = t.shr_bits(params.k);
    auto low = t.low_bits(params.k);
    if (high.is_zero()) {
        t = std::move(low);
        return true;
    }
    big_uint pos = std::move(low);
    big_uint neg = big_uint::zero();
    for (auto const& term : params.terms) {
        auto shifted = high;
        if (term.offset > 0) {
            shifted.shl_bits(term.offset);
        }
        std::uint64_t abs_coef = static_cast<std::uint64_t>(
            term.coef >= 0 ? term.coef : -term.coef);
        auto term_mag = abs_coef == 1 ? std::move(shifted)
                                      : shifted.mul_ref(big_uint{abs_coef});
        if (term.coef > 0) {
            pos.add_assign_ref(term_mag);
        } else {
            neg.add_assign_ref(term_mag);
        }
    }
    if (pos < neg) {
        return false;
    }
    pos.sub_assign_ref(neg);
    t = std::move(pos);
    return true;
}

// ── Catalogue ─────────────────────────────────────────────────────

std::vector<std::shared_ptr<detail::reduction_params const>> const& known_reductions() {
    static std::once_flag once;
    static std::vector<std::shared_ptr<detail::reduction_params const>> table;
    std::call_once(once, [] {
        auto make = [](std::size_t k, std::vector<detail::reduction_term> terms, big_uint p,
                       char const* name, bool prefer_fast) {
            auto params = detail::reduction_params{
                k, std::move(terms), std::move(p), name, prefer_fast};
            return std::make_shared<detail::reduction_params const>(std::move(params));
        };
        table.push_back(make(521, {{0, 1}}, mersenne521(), "mersenne521", true));
        table.push_back(make(255, {{0, 19}}, curve25519_field(), "curve25519", true));
        table.push_back(make(130, {{0, 5}}, poly1305_field(), "poly1305", true));
        table.push_back(
            make(256, {{0, 977}, {32, 1}}, secp256k1_field(), "secp256k1", true));
        table.push_back(
            make(448, {{0, 1}, {224, 1}}, curve448_field(), "curve448", true));
        table.push_back(
            make(192, {{0, 1}, {64, 1}}, nist_p192_field(), "nist_p192", true));
        table.push_back(
            make(224, {{0, -1}, {96, 1}}, nist_p224_field(), "nist_p224", true));
        table.push_back(
            make(256, {{0, 1}, {96, -1}, {192, -1}, {224, 1}}, nist_p256_field(),
                 "nist_p256", false));
        table.push_back(
            make(384, {{0, 1}, {32, -1}, {96, 1}, {128, 1}}, nist_p384_field(),
                 "nist_p384", true));
        // Validate every entry exactly once. Any constant-table
        // typo (zero coef, offset ≥ k, δ ≤ 0, δ ≠ 2^k − p) panics
        // here at first use.
        for (auto const& params : table) {
            // Coefficient and offset checks.
            for (auto const& term : params->terms) {
                if (term.coef == 0) {
                    throw std::logic_error(std::string{params->name}
                                           + ": zero coefficient in reduction polynomial");
                }
                if (term.offset >= params->k) {
                    throw std::logic_error(std::string{params->name} + ": term offset ≥ k");
                }
            }
            // δ = sum(coef · 2^offset) computed as a signed sum.
            big_uint delta_pos;
            big_uint delta_neg;
            for (auto const& term : params->terms) {
                auto shifted = big_uint::one();
                if (term.offset > 0) {
                    shifted.shl_bits(term.offset);
                }
                std::uint64_t abs_coef = static_cast<std::uint64_t>(
                    term.coef >= 0 ? term.coef : -term.coef);
                auto mag = abs_coef == 1 ? std::move(shifted)
                                         : shifted.mul_ref(big_uint{abs_coef});
                if (term.coef > 0) {
                    delta_pos.add_assign_ref(mag);
                } else {
                    delta_neg.add_assign_ref(mag);
                }
            }
            if (!(delta_pos > delta_neg)) {
                throw std::logic_error(std::string{params->name}
                                       + ": δ must be positive");
            }
            auto delta = delta_pos.sub_ref(delta_neg);
            // Verify δ == 2^k − p exactly.
            big_uint two_k = big_uint::one();
            two_k.shl_bits(params->k);
            auto expected_delta = two_k.sub_ref(params->p);
            if (delta != expected_delta) {
                throw std::logic_error(std::string{params->name}
                                       + ": δ does not match 2^k − p");
            }
        }
    });
    return table;
}

big_uint const& cached_mersenne127() {
    static big_uint const m127 = mersenne127();
    return m127;
}

}  // namespace

// ── Catalogue prime constructors ──────────────────────────────────

big_uint mersenne127() {
    auto v = big_uint::one();
    v.shl_bits(127);
    return v.sub_ref(big_uint::one());
}

big_uint mersenne521() {
    auto v = big_uint::one();
    v.shl_bits(521);
    return v.sub_ref(big_uint::one());
}

big_uint curve25519_field() {
    auto v = big_uint::one();
    v.shl_bits(255);
    return v.sub_ref(big_uint{19});
}

big_uint poly1305_field() {
    auto v = big_uint::one();
    v.shl_bits(130);
    return v.sub_ref(big_uint{5});
}

big_uint secp256k1_field() {
    auto v = big_uint::one();
    v.shl_bits(256);
    // 2^32 + 977 = 4294968273.
    return v.sub_ref(big_uint{4'294'968'273ULL});
}

big_uint curve448_field() {
    auto v = big_uint::one();
    v.shl_bits(448);
    auto sub = big_uint::one();
    sub.shl_bits(224);
    return v.sub_ref(sub).sub_ref(big_uint::one());
}

big_uint nist_p192_field() {
    auto v = big_uint::one();
    v.shl_bits(192);
    auto sub = big_uint::one();
    sub.shl_bits(64);
    return v.sub_ref(sub).sub_ref(big_uint::one());
}

big_uint nist_p224_field() {
    auto v = big_uint::one();
    v.shl_bits(224);
    auto sub = big_uint::one();
    sub.shl_bits(96);
    return v.sub_ref(sub).add_ref(big_uint::one());
}

big_uint nist_p256_field() {
    auto v = big_uint::one();
    v.shl_bits(256);
    auto t224 = big_uint::one();
    t224.shl_bits(224);
    auto t192 = big_uint::one();
    t192.shl_bits(192);
    auto t96 = big_uint::one();
    t96.shl_bits(96);
    return v.sub_ref(t224).add_ref(t192).add_ref(t96).sub_ref(big_uint::one());
}

big_uint nist_p384_field() {
    auto v = big_uint::one();
    v.shl_bits(384);
    auto t128 = big_uint::one();
    t128.shl_bits(128);
    auto t96 = big_uint::one();
    t96.shl_bits(96);
    auto t32 = big_uint::one();
    t32.shl_bits(32);
    return v.sub_ref(t128).sub_ref(t96).add_ref(t32).sub_ref(big_uint::one());
}

// ── prime_field ───────────────────────────────────────────────────

prime_field::prime_field(big_uint p) : p_(std::move(p)) {
    if (!(p_ > big_uint::one())) {
        throw std::invalid_argument("modulus must be > 1");
    }
    kind_ = detect(p_, params_);
}

prime_field::kind prime_field::detect(big_uint const& p,
                                      std::shared_ptr<detail::reduction_params const>& params_out) {
    if (p == cached_mersenne127()) {
        return kind::mersenne127;
    }
    for (auto const& params : known_reductions()) {
        if (params->p == p) {
            if (params->prefer_fast) {
                params_out = params;
                return kind::reduction;
            }
            return kind::generic;
        }
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
    case kind::reduction:
        return reduction_mul(a, b, *params_);
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
    if (modulus.is_zero() || modulus.is_one()) {
        return std::nullopt;
    }
    if (a.is_zero()) {
        return std::nullopt;
    }

    enum class sign : std::uint8_t { plus, minus };
    struct sint {
        sign s;
        big_uint mag;
    };

    auto sint_zero = sint{sign::plus, big_uint::zero()};
    auto sint_one = sint{sign::plus, big_uint::one()};
    auto sub = [](sint const& x, sint const& y) -> sint {
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
        return {x.s, x.mag.add_ref(y.mag)};
    };
    auto mul_then_sub = [&](sint const& x, sint const& y, big_uint const& q) -> sint {
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
        auto candidate = big_uint::from_be_bytes(
            std::span<std::uint8_t const>{buf.data(), buf.size()});
        if (candidate < modulus) {
            return candidate;
        }
    }
}

}  // namespace secret_sharing
