// Polynomial helpers used by Shamir / KGH / ramp / decode. All
// operate over a `prime_field`.
#pragma once

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/field.hpp"

#include <optional>
#include <span>

namespace secret_sharing {

// Horner evaluation of the polynomial whose coefficients are
// `coefficients[0] + coefficients[1] · x + ...` at point `x`.
[[nodiscard]] big_uint horner(prime_field const& f, std::span<big_uint const> coefficients,
                              big_uint const& x);

// Lagrange interpolation through `(x_i, y_i)` pairs evaluated at
// `target`. Returns nullopt iff any two abscissae collide.
[[nodiscard]] std::optional<big_uint> lagrange_eval(
    prime_field const& f, std::span<std::pair<big_uint, big_uint> const> points,
    big_uint const& target);

}  // namespace secret_sharing
