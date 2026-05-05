// Shamir 1979 (k, n) threshold scheme. Wire format and reconstruction
// outputs match the Rust `secret_sharing::shamir` exactly: shares with
// the same (x, y) field elements, the same Lagrange interpolation,
// the same extras-validation contract.
#pragma once

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"
#include "secret_sharing/field.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace secret_sharing {

struct share {
    big_uint x;
    big_uint y;

    friend bool operator==(share const&, share const&) = default;
};

namespace shamir {

[[nodiscard]] std::vector<share> split(prime_field const& f, csprng& rng,
                                       big_uint const& secret, std::size_t k, std::size_t n);

[[nodiscard]] std::optional<big_uint> reconstruct(prime_field const& f,
                                                  std::span<share const> shares, std::size_t k);

}  // namespace shamir

}  // namespace secret_sharing
