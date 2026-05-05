// libFuzzer harness for Shamir round-trip over Mersenne-127.
//
// Pulls (k, n, secret) from the input, splits, reconstructs, and
// verifies the recovered secret equals the input modulo p. Also
// exercises tampered-extra rejection and below-threshold refusal so
// any regression in the contract is caught.

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"
#include "secret_sharing/shamir.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace ss = secret_sharing;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (size < 32 + 16 + 2) {
        return 0;
    }
    std::array<std::uint8_t, 32> seed_bytes{};
    for (std::size_t i = 0; i < 32; ++i) {
        seed_bytes[i] = data[i];
    }
    auto rng = ss::chacha20_rng::from_seed(seed_bytes);
    auto secret_bytes = std::span<std::uint8_t const>{data + 32, 16};
    auto p = ss::mersenne127();
    auto f = ss::prime_field::new_unchecked(p);
    auto secret = ss::big_uint::from_be_bytes(secret_bytes).modulo(p);

    std::size_t k = 2 + (data[48] % 4);          // k in {2, 3, 4, 5}
    std::size_t n = k + (data[49] % 4);          // n in {k, k+1, k+2, k+3}

    auto shares = ss::shamir::split(f, rng, secret, k, n);
    if (shares.size() != n) {
        __builtin_trap();
    }

    // Round-trip via first k.
    auto recovered = ss::shamir::reconstruct(
        f, std::span<ss::share const>{shares.data(), k}, k);
    if (!recovered || *recovered != secret) {
        __builtin_trap();
    }

    // Below threshold must refuse.
    if (k > 2) {
        auto refused = ss::shamir::reconstruct(
            f, std::span<ss::share const>{shares.data(), k - 1}, k);
        if (refused.has_value()) {
            __builtin_trap();
        }
    }

    // Tampered extra must be detected when n > k.
    if (n > k) {
        auto tampered = shares;
        tampered.back().y = f.add(tampered.back().y, ss::big_uint::one());
        auto bad = ss::shamir::reconstruct(
            f, std::span<ss::share const>{tampered.data(), tampered.size()}, k);
        if (bad.has_value()) {
            __builtin_trap();
        }
    }
    return 0;
}
