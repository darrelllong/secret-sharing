#include "secret_sharing/field.hpp"

#include <gtest/gtest.h>

#include <array>

namespace {
namespace ss = secret_sharing;

ss::big_uint from_u64(std::uint64_t v) { return ss::big_uint(v); }
}  // namespace

TEST(prime_field, mersenne127_construction) {
    auto p = ss::mersenne127();
    EXPECT_EQ(p.bits(), 127u);
    auto next = p.add_ref(ss::big_uint::one());
    auto two_pow = ss::big_uint::one();
    two_pow.shl_bits(127);
    EXPECT_EQ(next, two_pow);
}

TEST(prime_field, add_sub_round_trip) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    auto a = from_u64(123);
    auto b = from_u64(200);
    auto s = f.add(a, b);
    EXPECT_EQ(f.sub(s, b), a);
    EXPECT_EQ(f.sub(s, a), b);
}

TEST(prime_field, sub_underflow_wraps) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    auto a = from_u64(5);
    auto b = from_u64(10);
    EXPECT_EQ(f.sub(a, b), from_u64(252));
}

TEST(prime_field, neg_round_trip) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    for (std::uint64_t i = 0; i < 20; ++i) {
        auto a = from_u64(i);
        EXPECT_EQ(f.add(a, f.neg(a)), ss::big_uint::zero());
    }
}

TEST(prime_field, inv_round_trip) {
    auto f = ss::prime_field::new_unchecked(from_u64(257));
    for (std::uint64_t i = 1; i < 20; ++i) {
        auto a = from_u64(i);
        auto inv = f.inv(a);
        ASSERT_TRUE(inv.has_value());
        EXPECT_EQ(f.mul(a, *inv), ss::big_uint::one());
    }
    EXPECT_FALSE(f.inv(ss::big_uint::zero()).has_value());
}

TEST(prime_field, mersenne127_mul_matches_generic) {
    auto p = ss::mersenne127();
    auto fast = ss::prime_field::new_unchecked(p);
    // Edge cases.
    auto edges = std::vector<ss::big_uint>{
        ss::big_uint::zero(), ss::big_uint::one(), from_u64(2),
        p.sub_ref(ss::big_uint::one()), p,
    };
    for (auto const& a : edges) {
        for (auto const& b : edges) {
            auto fast_res = fast.mul(a, b);
            auto generic_res = ss::big_uint::mod_mul(a, b, p);
            EXPECT_EQ(fast_res, generic_res)
                << "mismatch on edges; a.bits=" << a.bits() << " b.bits=" << b.bits();
            EXPECT_LT(fast_res, p);
        }
    }
}

TEST(prime_field, mersenne127_unreduced_inputs) {
    auto p = ss::mersenne127();
    auto fast = ss::prime_field::new_unchecked(p);
    auto a = p.add_ref(from_u64(5));
    auto b = p.add_ref(p).add_ref(from_u64(3));
    auto fast_res = fast.mul(a, b);
    auto generic_res = ss::big_uint::mod_mul(a, b, p);
    EXPECT_EQ(fast_res, generic_res);
}
