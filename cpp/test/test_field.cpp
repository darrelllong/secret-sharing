#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

namespace ss = secret_sharing;

ss::big_uint from_u64(std::uint64_t v) { return ss::big_uint(v); }

ss::chacha20_rng make_rng(std::uint8_t byte) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(byte);
    return ss::chacha20_rng::from_seed(seed);
}

void full_prime_check(char const* name, ss::big_uint p, std::size_t expected_bits,
                      std::uint8_t seed) {
    ASSERT_EQ(p.bits(), expected_bits) << name;
    auto fast = ss::prime_field::new_unchecked(p);
    // Generic path: we can't easily build a Generic-kind field for a
    // prime that's in the catalogue. The dispatch already routes the
    // Mersenne-127 prime to its u128 path; we use big_uint::mod_mul
    // directly as the oracle, which is exactly the code generic
    // dispatch runs.
    auto generic_oracle = ss::prime_field::new_unchecked(p);  // same; oracle is via mod_mul below
    (void)generic_oracle;
    // Build a synthetic "always generic" oracle via direct mod_mul.
    struct mod_mul_oracle {
        ss::big_uint p;
        ss::big_uint mul(ss::big_uint const& a, ss::big_uint const& b) const {
            return ss::big_uint::mod_mul(a, b, p);
        }
    } oracle{p};

    auto edges_check = [&] {
        ss::big_uint two_pow = ss::big_uint::one();
        two_pow.shl_bits(p.bits() - 1);
        std::vector<ss::big_uint> edges{
            ss::big_uint::zero(),
            ss::big_uint::one(),
            from_u64(2),
            two_pow,
            p.sub_ref(ss::big_uint::one()),
            p,
            p.add_ref(ss::big_uint::one()),
        };
        for (auto const& a : edges) {
            for (auto const& b : edges) {
                auto fast_res = fast.mul(a, b);
                auto oracle_res = oracle.mul(a, b);
                ASSERT_EQ(fast_res, oracle_res)
                    << name << " edge mismatch a.bits=" << a.bits() << " b.bits=" << b.bits();
                ASSERT_LT(fast_res, p);
            }
        }
    };
    edges_check();

    // Unreduced inputs.
    auto a = p.add_ref(from_u64(5));
    auto b = p.add_ref(p).add_ref(from_u64(3));
    EXPECT_EQ(fast.mul(a, b), oracle.mul(a, b)) << name;

    // Worst case.
    auto p_minus_1 = p.sub_ref(ss::big_uint::one());
    EXPECT_EQ(fast.mul(p_minus_1, p_minus_1), oracle.mul(p_minus_1, p_minus_1)) << name;
    EXPECT_EQ(fast.mul(p, p), ss::big_uint::zero()) << name;

    // Random fuzz.
    auto rng = make_rng(seed);
    constexpr std::size_t N = 16'384;
    for (std::size_t i = 0; i < N; ++i) {
        auto x = fast.random(rng);
        auto y = fast.random(rng);
        auto fast_res = fast.mul(x, y);
        auto oracle_res = oracle.mul(x, y);
        ASSERT_EQ(fast_res, oracle_res) << name << " fuzz " << i;
        ASSERT_LT(fast_res, p);
    }
}

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
    EXPECT_EQ(f.sub(from_u64(5), from_u64(10)), from_u64(252));
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

// ── Per-prime fuzz suite (16 384 random multiplies each) ──────────

TEST(prime_field, fuzz_mersenne127) {
    full_prime_check("mersenne127", ss::mersenne127(), 127, 0xC1);
}

TEST(prime_field, fuzz_mersenne521) {
    full_prime_check("mersenne521", ss::mersenne521(), 521, 0x21);
}

TEST(prime_field, fuzz_curve25519) {
    full_prime_check("curve25519", ss::curve25519_field(), 255, 0x25);
}

TEST(prime_field, fuzz_poly1305) {
    full_prime_check("poly1305", ss::poly1305_field(), 130, 0x05);
}

TEST(prime_field, fuzz_secp256k1) {
    full_prime_check("secp256k1", ss::secp256k1_field(), 256, 0x6B);
}

TEST(prime_field, fuzz_curve448) {
    full_prime_check("curve448", ss::curve448_field(), 448, 0x48);
}

TEST(prime_field, fuzz_nist_p192) {
    full_prime_check("nist_p192", ss::nist_p192_field(), 192, 0x92);
}

TEST(prime_field, fuzz_nist_p224) {
    full_prime_check("nist_p224", ss::nist_p224_field(), 224, 0x24);
}

TEST(prime_field, fuzz_nist_p256) {
    // Recognised but routed through Generic in production. The fast
    // path is still validated for correctness here — that matters
    // because a future flag flip should not regress the parametric
    // reducer's behaviour.
    full_prime_check("nist_p256", ss::nist_p256_field(), 256, 0x56);
}

TEST(prime_field, fuzz_nist_p384) {
    full_prime_check("nist_p384", ss::nist_p384_field(), 384, 0x84);
}

TEST(prime_field, unknown_modulus_falls_through) {
    // 1_000_000_007 is the canonical small prime nowhere near any
    // catalogue value. Construction must succeed and dispatch
    // through Generic without surprises.
    auto f = ss::prime_field::new_unchecked(from_u64(1'000'000'007));
    auto a = from_u64(123'456);
    auto b = from_u64(789'012);
    EXPECT_EQ(f.mul(a, b), ss::big_uint::mod_mul(a, b, from_u64(1'000'000'007)));
}
