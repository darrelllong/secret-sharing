// Bit-compatible prime-field arithmetic.
//
// `prime_field` mirrors the Rust `PrimeField`: a wrapped prime modulus
// plus the four field operations Shamir / KGH / McEliece-Sarwate need.
// `mersenne127()` is recognised at construction and routed through a
// hand-rolled `u128` fast path; every other modulus takes the
// generic Montgomery path.
#pragma once

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"

#include <optional>

namespace secret_sharing {

// 2^127 − 1, Mersenne prime. Same value as Rust's `mersenne127()`.
big_uint mersenne127();

class prime_field {
public:
    explicit prime_field(big_uint p);
    static prime_field new_unchecked(big_uint p) { return prime_field(std::move(p)); }

    [[nodiscard]] big_uint const& modulus() const noexcept { return p_; }

    [[nodiscard]] big_uint reduce(big_uint const& a) const { return a.modulo(p_); }
    [[nodiscard]] big_uint add(big_uint const& a, big_uint const& b) const;
    [[nodiscard]] big_uint sub(big_uint const& a, big_uint const& b) const;
    [[nodiscard]] big_uint neg(big_uint const& a) const;
    [[nodiscard]] big_uint mul(big_uint const& a, big_uint const& b) const;
    [[nodiscard]] std::optional<big_uint> inv(big_uint const& a) const;
    [[nodiscard]] big_uint random(csprng& rng) const;

private:
    enum class kind { generic, mersenne127 };

    big_uint p_;
    kind kind_;

    static kind detect(big_uint const& p);
};

// Modular inverse via extended Euclidean. Returns nullopt if `a` and
// `modulus` are not coprime (in particular if `a == 0`).
std::optional<big_uint> mod_inverse(big_uint const& a, big_uint const& modulus);

// Uniform sample of `[0, modulus)` from the supplied CSPRNG. Mirrors
// `secret_sharing::primes::random_below`.
std::optional<big_uint> random_below(csprng& rng, big_uint const& modulus);

}  // namespace secret_sharing
