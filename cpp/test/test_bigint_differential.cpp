// Differential tests against deterministic vectors generated from the
// pinned Rust/rump reference implementation. The vector header is produced
// by `cargo run --release --example dump_bigint_vectors`; regenerate it
// with `cpp/scripts/regen_bigint_vectors.sh` after intentional reference
// changes, and verify it with `cpp/scripts/check_bigint_vectors.sh`.

#include "bigint_differential_vectors.inc"
#include "secret_sharing/bigint.hpp"
#include "secret_sharing/field.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace ss = secret_sharing;

std::vector<std::uint8_t> hex_decode(std::string_view hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);

    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(c - 'a' + 10);
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(c - 'A' + 10);
        }
        throw std::runtime_error("bad hex char");
    };

    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

ss::big_uint big_from_hex(std::string_view hex) {
    auto bytes = hex_decode(hex);
    return ss::big_uint::from_be_bytes(std::span<std::uint8_t const>{bytes.data(), bytes.size()});
}

}  // namespace

TEST(bigint_differential, matches_pinned_rump_vectors) {
    for (auto const& vector : BIGINT_DIFF_VECTORS) {
        SCOPED_TRACE(std::string{vector.operation} + " " + vector.lhs + " " + vector.rhs);

        auto const lhs = big_from_hex(vector.lhs);
        auto const rhs = big_from_hex(vector.rhs);
        auto const first = big_from_hex(vector.first);

        if (vector.operation == std::string_view{"add"}) {
            EXPECT_EQ(lhs.add_ref(rhs), first);
        } else if (vector.operation == std::string_view{"sub"}) {
            EXPECT_GE(lhs, rhs);
            EXPECT_EQ(lhs.sub_ref(rhs), first);
        } else if (vector.operation == std::string_view{"mul"}) {
            EXPECT_EQ(lhs.mul_ref(rhs), first);
        } else if (vector.operation == std::string_view{"div_rem"}) {
            auto [quotient, remainder] = lhs.div_rem(rhs);
            EXPECT_EQ(quotient, first);
            EXPECT_EQ(remainder, big_from_hex(vector.second));
        } else if (vector.operation == std::string_view{"modulo"}) {
            EXPECT_EQ(lhs.modulo(rhs), first);
        } else if (vector.operation == std::string_view{"mod_mul"}) {
            EXPECT_EQ(ss::big_uint::mod_mul(lhs, rhs, big_from_hex(vector.second)), first);
        } else if (vector.operation == std::string_view{"inverse"}) {
            auto const got = ss::mod_inverse(lhs, rhs);
            ASSERT_TRUE(got.has_value());
            EXPECT_EQ(*got, first);
        } else {
            FAIL() << "unsupported generated operation";
        }
    }
}
