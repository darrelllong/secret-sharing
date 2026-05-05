#include "secret_sharing/shamir.hpp"

#include "secret_sharing/poly.hpp"

#include <stdexcept>

namespace secret_sharing::shamir {

std::vector<share> split(prime_field const& f, csprng& rng, big_uint const& secret, std::size_t k,
                         std::size_t n) {
    if (k < 2) {
        throw std::invalid_argument("k must be at least 2 (k = 1 would leak the secret)");
    }
    if (n < k) {
        throw std::invalid_argument("n must be at least k");
    }
    if (!(big_uint(static_cast<std::uint64_t>(n)) < f.modulus())) {
        throw std::invalid_argument("prime modulus must exceed n");
    }

    std::vector<big_uint> coeffs;
    coeffs.reserve(k);
    coeffs.push_back(f.reduce(secret));
    for (std::size_t i = 1; i < k; ++i) {
        coeffs.push_back(f.random(rng));
    }

    std::vector<share> out;
    out.reserve(n);
    for (std::size_t i = 1; i <= n; ++i) {
        big_uint x{static_cast<std::uint64_t>(i)};
        auto y = horner(f, std::span<big_uint const>{coeffs.data(), coeffs.size()}, x);
        out.push_back(share{std::move(x), std::move(y)});
    }
    return out;
}

std::optional<big_uint> reconstruct(prime_field const& f, std::span<share const> shares,
                                    std::size_t k) {
    if (k == 0 || shares.size() < k) {
        return std::nullopt;
    }
    for (auto const& s : shares) {
        if (s.x.is_zero()) {
            return std::nullopt;
        }
    }
    for (std::size_t i = 0; i < shares.size(); ++i) {
        for (std::size_t j = i + 1; j < shares.size(); ++j) {
            if (shares[i].x == shares[j].x) {
                return std::nullopt;
            }
        }
    }
    std::vector<std::pair<big_uint, big_uint>> pts;
    pts.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        pts.emplace_back(shares[i].x, shares[i].y);
    }
    auto secret = lagrange_eval(
        f, std::span<std::pair<big_uint, big_uint> const>{pts.data(), pts.size()},
        big_uint::zero());
    if (!secret) {
        return std::nullopt;
    }

    // Validate extras against the fitted polynomial — same contract as
    // the Rust impl: any extra share past the first k that disagrees
    // causes a None return rather than silent acceptance.
    for (std::size_t i = k; i < shares.size(); ++i) {
        auto pred = lagrange_eval(
            f, std::span<std::pair<big_uint, big_uint> const>{pts.data(), pts.size()},
            shares[i].x);
        if (!pred || !(*pred == shares[i].y)) {
            return std::nullopt;
        }
    }
    return secret;
}

}  // namespace secret_sharing::shamir
