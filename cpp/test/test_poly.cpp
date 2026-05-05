#include "secret_sharing/poly.hpp"

#include <gtest/gtest.h>

#include <array>
#include <vector>

namespace {
namespace ss = secret_sharing;
ss::big_uint from_u64(std::uint64_t v) { return ss::big_uint(v); }
}  // namespace

TEST(poly, horner_evaluates_polynomial) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    // f(x) = 5 + 3x + 2x², f(4) = 5 + 12 + 32 = 49.
    std::vector<ss::big_uint> coeffs{from_u64(5), from_u64(3), from_u64(2)};
    auto v = ss::horner(f, std::span<ss::big_uint const>{coeffs.data(), coeffs.size()},
                        from_u64(4));
    EXPECT_EQ(v, from_u64(49));
}

TEST(poly, lagrange_recovers_value_at_zero) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    // Polynomial f(x) = 7 + 11x + 5x²; sample at x = 1, 2, 3.
    std::vector<ss::big_uint> coeffs{from_u64(7), from_u64(11), from_u64(5)};
    std::vector<std::pair<ss::big_uint, ss::big_uint>> pts;
    for (auto x : {1u, 2u, 3u}) {
        auto x_big = from_u64(x);
        auto y = ss::horner(f, std::span<ss::big_uint const>{coeffs.data(), coeffs.size()}, x_big);
        pts.emplace_back(x_big, y);
    }
    auto recovered = ss::lagrange_eval(
        f, std::span<std::pair<ss::big_uint, ss::big_uint> const>{pts.data(), pts.size()},
        ss::big_uint::zero());
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(*recovered, from_u64(7));
}

TEST(poly, lagrange_rejects_duplicate_abscissae) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    std::vector<std::pair<ss::big_uint, ss::big_uint>> pts{
        {from_u64(2), from_u64(13)},
        {from_u64(2), from_u64(99)},  // duplicate x
    };
    auto r = ss::lagrange_eval(
        f, std::span<std::pair<ss::big_uint, ss::big_uint> const>{pts.data(), pts.size()},
        ss::big_uint::zero());
    EXPECT_FALSE(r.has_value());
}
