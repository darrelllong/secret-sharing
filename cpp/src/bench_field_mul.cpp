// Per-prime mul-mod throughput micro-benchmark, mirroring the Rust
// `examples/bench_field_mul.rs`. Times every catalogue prime under
// the production dispatch (which routes nist_p256 to Generic) plus
// the same operand stream through `big_uint::mod_mul` directly so
// the comparison is apples-to-apples.

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ss = secret_sharing;

namespace {

constexpr std::size_t WARMUP = 50;
constexpr std::size_t ITERS = 200;

struct row {
    char const* name;
    std::size_t bits;
    std::uint64_t fast_ns;
    std::uint64_t generic_ns;
};

std::uint64_t median(std::vector<std::uint64_t>& samples) {
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

template <typename Op>
std::uint64_t time_op(std::size_t iters, std::size_t warmup, Op&& op,
                      std::vector<std::pair<ss::big_uint, ss::big_uint>> const& pairs) {
    for (std::size_t i = 0; i < warmup && i < pairs.size(); ++i) {
        std::ignore = op(pairs[i].first, pairs[i].second);
    }
    std::vector<std::uint64_t> samples;
    samples.reserve(iters);
    for (std::size_t i = 0; i < iters && warmup + i < pairs.size(); ++i) {
        auto const& pair = pairs[warmup + i];
        auto t0 = std::chrono::steady_clock::now();
        auto r = op(pair.first, pair.second);
        auto t1 = std::chrono::steady_clock::now();
        samples.push_back(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
        asm volatile("" : : "r"(&r) : "memory");
    }
    return median(samples);
}

row run(char const* name, ss::big_uint p) {
    auto bits = p.bits();
    ss::prime_field fast = ss::prime_field::new_unchecked(p);
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0xA7);
    auto rng = ss::chacha20_rng::from_seed(seed);
    std::vector<std::pair<ss::big_uint, ss::big_uint>> pairs;
    pairs.reserve(WARMUP + ITERS);
    for (std::size_t i = 0; i < WARMUP + ITERS; ++i) {
        pairs.emplace_back(fast.random(rng), fast.random(rng));
    }

    auto fast_ns = time_op(
        ITERS, WARMUP, [&](ss::big_uint const& a, ss::big_uint const& b) { return fast.mul(a, b); },
        pairs);
    auto generic_ns = time_op(
        ITERS, WARMUP,
        [&](ss::big_uint const& a, ss::big_uint const& b) {
            return ss::big_uint::mod_mul(a, b, p);
        },
        pairs);
    return {name, bits, fast_ns, generic_ns};
}

std::string fmt_ns(std::uint64_t ns) {
    if (ns < 1'000) {
        return std::to_string(ns) + " ns";
    }
    if (ns < 1'000'000) {
        return std::to_string(static_cast<double>(ns) / 1'000.0).substr(0, 5) + " µs";
    }
    return std::to_string(static_cast<double>(ns) / 1'000'000.0).substr(0, 5) + " ms";
}

}  // namespace

int main() {
    std::cerr << "benching field::mul across registered primes (C++)...\n";
    std::array<row, 10> rows{{
        run("mersenne127", ss::mersenne127()),
        run("poly1305", ss::poly1305_field()),
        run("nist_p192", ss::nist_p192_field()),
        run("nist_p224", ss::nist_p224_field()),
        run("curve25519", ss::curve25519_field()),
        run("nist_p256", ss::nist_p256_field()),
        run("secp256k1", ss::secp256k1_field()),
        run("nist_p384", ss::nist_p384_field()),
        run("curve448", ss::curve448_field()),
        run("mersenne521", ss::mersenne521()),
    }};
    std::cout << "\n## Field multiplication: fast path vs Montgomery generic (C++)\n\n";
    std::cout << "| Prime          | bits |  fast path |   generic   | speedup |\n";
    std::cout << "|----------------|-----:|-----------:|------------:|--------:|\n";
    for (auto const& r : rows) {
        auto speedup = static_cast<double>(r.generic_ns) / static_cast<double>(r.fast_ns);
        std::cout << "| `" << r.name << "`";
        for (std::size_t i = std::string{r.name}.size(); i < 13; ++i) {
            std::cout << ' ';
        }
        std::cout << "| " << r.bits << " | " << fmt_ns(r.fast_ns) << " | " << fmt_ns(r.generic_ns)
                  << " | " << speedup << "× |\n";
    }
    return 0;
}
