// Pilot-bench dispatcher for the C++ port. Mirrors the Rust
// `pilot_ss` binary: takes one operation name on the command line,
// runs it `iters(base)` times, prints `ms/op` to stdout in the
// single-column CSV form pilot-bench reads as the performance
// indicator. The op set is deliberately the subset of the Rust
// dispatcher that the C++ port covers — Shamir over GF(2^127 − 1) at
// k = 3, n = 5, with a `*_4kb` variant that chunks 4 KiB into 274
// 15-byte blocks (same chunk schedule as Rust's `*_split_4kb`).
#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"
#include "secret_sharing/shamir.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ss = secret_sharing;

namespace {

constexpr std::size_t K = 3;
constexpr std::size_t N = 5;

constexpr std::size_t SECRET_BYTES = 4096;
constexpr std::size_t CHUNK_BYTES = 15;

std::size_t iters(std::size_t base) {
    static int scale = []() {
        if (auto const* env = std::getenv("PILOT_SS_ITERS_PERCENT")) {
            try {
                int v = std::stoi(env);
                if (v < 1) {
                    return 1;
                }
                if (v > 100) {
                    return 100;
                }
                return v;
            } catch (...) {
                return 25;
            }
        }
        return 25;
    }();
    auto out = (base * static_cast<std::size_t>(scale) + 99) / 100;
    return out > 0 ? out : 1;
}

ss::chacha20_rng make_rng() {
    // Deterministic seeding from /dev/urandom — same threat model as
    // the Rust binary's OsRng-seeded ChaCha20.
    std::array<std::uint8_t, 32> seed{};
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f.read(reinterpret_cast<char*>(seed.data()), seed.size())) {
        throw std::runtime_error("/dev/urandom read failed");
    }
    return ss::chacha20_rng::from_seed(seed);
}

ss::prime_field make_field() {
    return ss::prime_field::new_unchecked(ss::mersenne127());
}

double ms_per_op(std::chrono::nanoseconds elapsed, std::size_t n_iter) {
    auto ns = static_cast<double>(elapsed.count());
    return ns / 1'000'000.0 / static_cast<double>(n_iter);
}

std::vector<ss::big_uint> chunks_4kb(ss::chacha20_rng& rng) {
    std::vector<std::uint8_t> bytes(SECRET_BYTES);
    rng.fill_bytes(std::span<std::uint8_t>{bytes.data(), bytes.size()});
    std::vector<ss::big_uint> chunks;
    auto n = (SECRET_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;
    chunks.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        auto start = i * CHUNK_BYTES;
        auto end = std::min(start + CHUNK_BYTES, SECRET_BYTES);
        chunks.push_back(ss::big_uint::from_be_bytes(
            std::span<std::uint8_t const>{bytes.data() + start, end - start}));
    }
    return chunks;
}

template <typename F>
double time_loop(std::size_t n_iter, F&& body) {
    auto t0 = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < n_iter; ++i) {
        body();
    }
    auto t1 = std::chrono::steady_clock::now();
    return ms_per_op(t1 - t0, n_iter);
}

double bench_shamir_split(ss::chacha20_rng& rng) {
    auto f = make_field();
    auto secret = f.random(rng);
    auto n_iter = iters(2000);
    return time_loop(n_iter, [&] {
        auto shares = ss::shamir::split(f, rng, secret, K, N);
        // Prevent dead-code elimination.
        asm volatile("" : : "r"(shares.data()) : "memory");
    });
}

double bench_shamir_reconstruct(ss::chacha20_rng& rng) {
    auto f = make_field();
    auto secret = f.random(rng);
    auto shares = ss::shamir::split(f, rng, secret, K, N);
    auto n_iter = iters(2000);
    return time_loop(n_iter, [&] {
        auto recovered = ss::shamir::reconstruct(
            f, std::span<ss::share const>{shares.data(), K}, K);
        asm volatile("" : : "r"(&recovered) : "memory");
    });
}

double bench_shamir_split_4kb(ss::chacha20_rng& rng) {
    auto f = make_field();
    auto chunks = chunks_4kb(rng);
    auto n_iter = iters(20);
    return time_loop(n_iter, [&] {
        for (auto const& s : chunks) {
            auto shares = ss::shamir::split(f, rng, s, K, N);
            asm volatile("" : : "r"(shares.data()) : "memory");
        }
    });
}

double bench_shamir_reconstruct_4kb(ss::chacha20_rng& rng) {
    auto f = make_field();
    auto chunks = chunks_4kb(rng);
    std::vector<std::vector<ss::share>> shared;
    shared.reserve(chunks.size());
    for (auto const& s : chunks) {
        shared.push_back(ss::shamir::split(f, rng, s, K, N));
    }
    auto n_iter = iters(20);
    return time_loop(n_iter, [&] {
        for (auto const& shares : shared) {
            auto r = ss::shamir::reconstruct(
                f, std::span<ss::share const>{shares.data(), K}, K);
            asm volatile("" : : "r"(&r) : "memory");
        }
    });
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: pilot_ss_cpp <operation>\n";
        return 1;
    }
    std::string_view op{argv[1]};
    auto rng = make_rng();
    double ms = 0.0;
    if (op == "shamir_split") {
        ms = bench_shamir_split(rng);
    } else if (op == "shamir_reconstruct") {
        ms = bench_shamir_reconstruct(rng);
    } else if (op == "shamir_split_4kb") {
        ms = bench_shamir_split_4kb(rng);
    } else if (op == "shamir_reconstruct_4kb") {
        ms = bench_shamir_reconstruct_4kb(rng);
    } else {
        std::cerr << "unknown operation: " << op << '\n';
        return 2;
    }
    std::cout << ms << '\n';
    return 0;
}
