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
    big_uint result = big_uint::zero();
    for (std::size_t i = 0; i < points.size(); ++i) {
        auto const& [xi, yi] = points[i];
        big_uint num = big_uint::one();
        big_uint den = big_uint::one();
        for (std::size_t j = 0; j < points.size(); ++j) {
            if (j == i) {
                continue;
            }
            auto const& xj = points[j].first;
            num = f.mul(num, f.sub(target, xj));
            auto diff = f.sub(xi, xj);
            if (diff.is_zero()) {
                return std::nullopt;  // duplicate abscissa
            }
            den = f.mul(den, diff);
        }
        auto den_inv = f.inv(den);
        if (!den_inv) {
            return std::nullopt;
        }
        auto term = f.mul(yi, f.mul(num, *den_inv));
        result = f.add(result, term);
    }
    return result;
}

}  // namespace secret_sharing
