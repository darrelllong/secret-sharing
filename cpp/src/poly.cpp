#include "secret_sharing/poly.hpp"

namespace secret_sharing {

big_uint horner(prime_field const& f, std::span<big_uint const> coefficients,
                big_uint const& x) {
    if (coefficients.empty()) {
        return big_uint::zero();
    }
    auto acc = coefficients.back();
    for (std::size_t i = coefficients.size() - 1; i-- > 0;) {
        acc = f.mul(acc, x);
        acc = f.add(acc, coefficients[i]);
    }
    return acc;
}

std::optional<big_uint> lagrange_eval(prime_field const& f,
                                      std::span<std::pair<big_uint, big_uint> const> points,
                                      big_uint const& target) {
    if (points.empty()) {
        return std::nullopt;
    }
    auto const n = points.size();

    // den[i] = ∏_{j≠i} (x_i − x_j). A zero factor means two abscissae
    // collide (possibly only after reduction mod p), which makes the
    // interpolation system singular — report that instead of dividing
    // by zero.
    std::vector<big_uint> dens;
    dens.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        auto const& xi = points[i].first;
        big_uint den = big_uint::one();
        for (std::size_t j = 0; j < n; ++j) {
            if (j == i) {
                continue;
            }
            auto diff = f.sub(xi, points[j].first);
            if (diff.is_zero()) {
                return std::nullopt;  // duplicate abscissa
            }
            den = f.mul(den, diff);
        }
        dens.push_back(std::move(den));
    }

    // Montgomery batch inversion: invert the single product of all
    // denominators with one extended-gcd call, then peel off each
    // individual inverse with two multiplies. Inversion dominates the
    // cost of a reconstruction, so this is the difference between one
    // inversion and k of them. Forward pass builds the prefix
    // products; the backward pass keeps inv_acc equal to
    // (den_0 · … · den_i)⁻¹ entering step i.
    std::vector<big_uint> prefix;  // prefix[i] = den_0 · … · den_{i−1}
    prefix.reserve(n);
    big_uint acc = big_uint::one();
    for (auto const& den : dens) {
        prefix.push_back(acc);
        acc = f.mul(acc, den);
    }
    auto product_inv = f.inv(acc);
    if (!product_inv) {
        return std::nullopt;  // unreachable: every den is nonzero
    }
    big_uint inv_acc = std::move(*product_inv);
    std::vector<big_uint> den_invs(n);
    for (std::size_t i = n; i-- > 0;) {
        den_invs[i] = f.mul(inv_acc, prefix[i]);
        inv_acc = f.mul(inv_acc, dens[i]);
    }

    big_uint result = big_uint::zero();
    for (std::size_t i = 0; i < n; ++i) {
        auto const& yi = points[i].second;
        big_uint num = big_uint::one();
        for (std::size_t j = 0; j < n; ++j) {
            if (j == i) {
                continue;
            }
            // L_i(x) = ∏_{j≠i} (x − x_j) / (x_i − x_j)
            num = f.mul(num, f.sub(target, points[j].first));
        }
        result = f.add(result, f.mul(yi, f.mul(num, den_invs[i])));
    }
    return result;
}

}  // namespace secret_sharing
