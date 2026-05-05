#include "secret_sharing/shamir.hpp"

#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"

#include <gtest/gtest.h>

#include <array>
#include <stdexcept>
#include <vector>

namespace {

namespace ss = secret_sharing;

ss::big_uint from_u64(std::uint64_t v) { return ss::big_uint(v); }

ss::chacha20_rng make_rng(std::uint8_t byte) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(byte);
    return ss::chacha20_rng::from_seed(seed);
}

ss::prime_field small_field() {
    // 2^61 − 1 — small Mersenne prime, easy to reason about.
    auto p = ss::big_uint::one();
    p.shl_bits(61);
    return ss::prime_field::new_unchecked(p.sub_ref(ss::big_uint::one()));
}

}  // namespace

TEST(shamir, basic_round_trip) {
    auto f = small_field();
    auto rng = make_rng(0x42);
    auto secret = from_u64(0xC0FFEEull);
    for (auto kn : std::initializer_list<std::pair<std::size_t, std::size_t>>{
             {2, 3}, {3, 5}, {5, 9}, {2, 7}}) {
        auto [k, n] = kn;
        auto shares = ss::shamir::split(f, rng, secret, k, n);
        EXPECT_EQ(shares.size(), n);
        auto recovered = ss::shamir::reconstruct(
            f, std::span<ss::share const>{shares.data(), k}, k);
        ASSERT_TRUE(recovered.has_value());
        EXPECT_EQ(*recovered, secret);
    }
}

TEST(shamir, below_threshold_returns_nullopt) {
    auto f = small_field();
    auto rng = make_rng(0x33);
    auto shares = ss::shamir::split(f, rng, from_u64(0xCAFE), 4, 7);
    auto r = ss::shamir::reconstruct(f, std::span<ss::share const>{shares.data(), 3}, 4);
    EXPECT_FALSE(r.has_value());
}

TEST(shamir, duplicate_x_rejected) {
    auto f = small_field();
    auto rng = make_rng(0x77);
    auto shares = ss::shamir::split(f, rng, from_u64(7), 2, 3);
    shares[1].x = shares[0].x;
    auto r = ss::shamir::reconstruct(f, std::span<ss::share const>{shares.data(), shares.size()}, 2);
    EXPECT_FALSE(r.has_value());
}

TEST(shamir, tampered_extra_share_rejected) {
    auto f = small_field();
    auto rng = make_rng(0xA1);
    auto secret = from_u64(0xBEEF);
    auto shares = ss::shamir::split(f, rng, secret, 3, 6);
    shares[5].y = f.add(shares[5].y, ss::big_uint::one());
    auto r = ss::shamir::reconstruct(f, std::span<ss::share const>{shares.data(), shares.size()}, 3);
    EXPECT_FALSE(r.has_value());
}

TEST(shamir, k_one_rejected) {
    auto f = small_field();
    auto rng = make_rng(0x55);
    EXPECT_THROW(
        { auto v = ss::shamir::split(f, rng, from_u64(1), 1, 5); (void)v; },
        std::invalid_argument);
}

TEST(shamir, n_below_k_rejected) {
    auto f = small_field();
    auto rng = make_rng(0x55);
    EXPECT_THROW(
        { auto v = ss::shamir::split(f, rng, from_u64(1), 5, 3); (void)v; },
        std::invalid_argument);
}
