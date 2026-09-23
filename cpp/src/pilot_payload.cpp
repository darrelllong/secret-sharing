// Pilot latency for a complete payload; matches pilot_payload.rs for Shamir.
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <vector>

#include "secret_sharing/shamir.hpp"

namespace ss = secret_sharing;
int main(int argc, char** argv) {
    if (argc != 4 || std::string_view(argv[1]) != "shamir")
        return 1;
    bool reconstruct = std::string_view(argv[2]) == "reconstruct";
    if (!reconstruct && std::string_view(argv[2]) != "split")
        return 1;
    auto size = std::stoul(argv[3]);
    if (size != 64 && size != 1024)
        return 1;
    std::vector<std::uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>(i * 73 + 41);
    ss::prime_field field = ss::prime_field::new_unchecked(ss::mersenne127());
    std::array<std::uint8_t, 32> seed{};
    seed.fill(53);
    auto rng = ss::chacha20_rng::from_seed(seed);
    std::vector<ss::big_uint> secrets;
    std::vector<std::vector<ss::share>> shares;
    for (std::size_t i = 0; i < size; i += 15) {
        secrets.push_back(
            ss::big_uint::from_be_bytes({data.data() + i, std::min(std::size_t{15}, size - i)})
        );
        shares.push_back(ss::shamir::split(field, rng, secrets.back(), 3, 5));
        auto recovered = ss::shamir::reconstruct(field, {shares.back().data(), 3}, 3);
        if (!recovered || *recovered != secrets.back())
            return 2;
    }
    auto duration = std::chrono::milliseconds(20);
    if (auto env = std::getenv("PILOT_PAYLOAD_MS"))
        duration = std::chrono::milliseconds(std::stoul(env));
    auto start = std::chrono::steady_clock::now();
    std::uint64_t count = 0;
    do {
        if (reconstruct) {
            for (auto const& part : shares) {
                auto result = ss::shamir::reconstruct(field, {part.data(), 3}, 3);
                if (!result)
                    return 2;
                asm volatile("" : : "r"(&*result) : "memory");
            }
        } else {
            for (auto const& secret : secrets) {
                auto result = ss::shamir::split(field, rng, secret, 3, 5);
                asm volatile("" : : "r"(result.data()) : "memory");
            }
        }
        ++count;
    } while (std::chrono::steady_clock::now() - start < duration);
    auto elapsed =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    std::cout << std::setprecision(12) << elapsed / static_cast<double>(count) << '\n';
}
