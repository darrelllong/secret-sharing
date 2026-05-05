#include "secret_sharing/csprng.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

namespace {
namespace ss = secret_sharing;
}

TEST(chacha20_rng, deterministic_from_seed) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    auto a = ss::chacha20_rng::from_seed(seed);
    auto b = ss::chacha20_rng::from_seed(seed);
    std::array<std::uint8_t, 200> ba{};
    std::array<std::uint8_t, 200> bb{};
    a.fill_bytes({ba.data(), ba.size()});
    b.fill_bytes({bb.data(), bb.size()});
    EXPECT_EQ(ba, bb);
}

TEST(chacha20_rng, different_seeds_differ) {
    std::array<std::uint8_t, 32> s1{};
    s1.fill(0x01);
    std::array<std::uint8_t, 32> s2{};
    s2.fill(0x02);
    auto a = ss::chacha20_rng::from_seed(s1);
    auto b = ss::chacha20_rng::from_seed(s2);
    std::array<std::uint8_t, 64> ba{};
    std::array<std::uint8_t, 64> bb{};
    a.fill_bytes({ba.data(), ba.size()});
    b.fill_bytes({bb.data(), bb.size()});
    EXPECT_NE(ba, bb);
}

TEST(chacha20_rng, rfc7539_zero_key_zero_nonce_test_vector) {
    // RFC 7539 §2.4.2: key = all zeros, nonce = zeros, counter = 0.
    // First 64 bytes of keystream:
    //   76b8e0ada0f13d90405d6ae55386bd28
    //   bdd219b8a08ded1aa836efcc8b770dc7
    //   da41597c5157488d7724e03fb8d84a37
    //   6a43b8f41518a11cc387b669b2ee6586
    std::array<std::uint8_t, 32> seed{};
    auto rng = ss::chacha20_rng::from_seed(seed);
    std::array<std::uint8_t, 64> got{};
    rng.fill_bytes({got.data(), got.size()});
    constexpr std::array<std::uint8_t, 64> expected{
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
        0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86,
    };
    EXPECT_EQ(got, expected);
}

TEST(chacha20_rng, short_and_long_fills_agree) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0xFF);
    auto rng_a = ss::chacha20_rng::from_seed(seed);
    std::array<std::uint8_t, 200> single{};
    rng_a.fill_bytes({single.data(), single.size()});

    auto rng_b = ss::chacha20_rng::from_seed(seed);
    std::array<std::uint8_t, 200> split{};
    std::size_t written = 0;
    for (auto chunk : {1u, 7u, 64u, 50u, 1u, 77u}) {
        auto end = std::min(written + chunk, split.size());
        rng_b.fill_bytes({split.data() + written, end - written});
        written = end;
    }
    rng_b.fill_bytes({split.data() + written, split.size() - written});
    EXPECT_EQ(single, split);
}
