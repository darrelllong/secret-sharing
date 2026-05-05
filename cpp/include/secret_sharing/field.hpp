// Bit-compatible prime-field arithmetic.
//
// `prime_field` mirrors the Rust `PrimeField`. At construction time it
// recognises the standardised primes the Rust crate's catalogue covers
// and dispatches to the same fast paths:
//
// - `mersenne127`: hand-rolled `u128` 2 × 2 schoolbook + Mersenne fold.
// - `mersenne521`, `curve25519`, `poly1305`, `secp256k1`, `curve448`,
//   `nist_p192`, `nist_p224`, `nist_p384`: the parametric pseudo-
//   Mersenne / Solinas reducer that uses `2^k ≡ δ (mod p)` to fold the
//   high half of the product back into the low half.
// - `nist_p256`: recognised but routed through generic Montgomery
//   (its 4-term mixed-sign polynomial loses to Montgomery on this
//   hardware); a `prefer_fast` flag in the catalogue records the
//   decision so the parametric reducer is still validated under the
//   per-prime fuzz harness.
// - Anything else: generic Montgomery via `big_uint::mod_mul`.
#pragma once

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/csprng.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace secret_sharing {

// Forward declarations of catalogue primes.
big_uint mersenne127();
big_uint mersenne521();
big_uint curve25519_field();
big_uint poly1305_field();
big_uint secp256k1_field();
big_uint curve448_field();
big_uint nist_p192_field();
big_uint nist_p224_field();
big_uint nist_p256_field();
big_uint nist_p384_field();

namespace detail {

// One term in a reduction polynomial: signed coefficient at a bit
// offset. The signed `i64` coefficient covers every catalogue entry
// (largest absolute coefficient is 977 for secp256k1; everything
// else is ±1).
struct reduction_term {
    std::size_t offset;
    std::int64_t coef;
};

// Parameters for a Solinas-form prime `p = 2^k − δ` where `δ` is a
// small signed sum of powers of two. Mirrors the Rust
// `ReductionParams` exactly, including the `prefer_fast` opt-out
// flag for primes whose parametric reducer measurably loses to
// Montgomery on the bench hardware.
struct reduction_params {
    std::size_t k;
    std::vector<reduction_term> terms;  // owned, lifetime tied to params
    big_uint p;
    char const* name;
    bool prefer_fast;
};

}  // namespace detail

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
    enum class kind : std::uint8_t { generic, mersenne127, reduction };

    big_uint p_;
    kind kind_;
    std::shared_ptr<detail::reduction_params const> params_;  // populated iff kind_ == reduction

    static kind detect(big_uint const& p,
                       std::shared_ptr<detail::reduction_params const>& params_out);

    friend struct field_test_access;
};

// Modular inverse via extended Euclidean. Returns nullopt if `a` and
// `modulus` are not coprime (in particular if `a == 0`).
std::optional<big_uint> mod_inverse(big_uint const& a, big_uint const& modulus);

// Uniform sample of `[0, modulus)` from the supplied CSPRNG. Mirrors
// `secret_sharing::primes::random_below`.
std::optional<big_uint> random_below(csprng& rng, big_uint const& modulus);

}  // namespace secret_sharing
