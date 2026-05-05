// Bit-compatible C++ port of `secret_sharing::bigint`.
//
// Storage and conventions match the Rust BigUint exactly:
// - Little-endian limb vector of `std::uint64_t`.
// - Normalised: no trailing zero limbs.
// - Zero is represented by an empty limb vector.
// - `to_be_bytes` / `from_be_bytes` produce the same byte strings as
//   the Rust implementation, so shares serialised by either side
//   round-trip through both.
//
// The destructor volatile-zeros the entire allocated capacity (not
// just the live `[0..len]`) so high-significance secret limbs from
// intermediate products do not leak into freed allocator pages.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace secret_sharing {

class big_uint;

class big_uint {
public:
    big_uint() = default;
    explicit big_uint(std::uint64_t v);
    static big_uint from_u128(__uint128_t v);
    static big_uint from_be_bytes(std::span<std::uint8_t const> bytes);
    static big_uint zero() { return {}; }
    static big_uint one();

    big_uint(big_uint const&) = default;
    big_uint(big_uint&&) noexcept = default;
    big_uint& operator=(big_uint const&) = default;
    big_uint& operator=(big_uint&&) noexcept = default;
    ~big_uint();

    [[nodiscard]] bool is_zero() const noexcept { return limbs_.empty(); }
    [[nodiscard]] bool is_one() const noexcept;
    [[nodiscard]] bool is_odd() const noexcept;
    [[nodiscard]] std::size_t bits() const noexcept;
    [[nodiscard]] bool bit(std::size_t index) const noexcept;
    void set_bit(std::size_t index);

    [[nodiscard]] std::vector<std::uint8_t> to_be_bytes() const;

    // Comparisons, all constant-in-limb-count to match the Rust impl.
    friend bool operator==(big_uint const&, big_uint const&) noexcept;
    friend std::strong_ordering operator<=>(big_uint const&, big_uint const&) noexcept;

    // Arithmetic — mirrors Rust API names.
    [[nodiscard]] big_uint add_ref(big_uint const& other) const;
    void add_assign_ref(big_uint const& other);
    [[nodiscard]] big_uint sub_ref(big_uint const& other) const;
    void sub_assign_ref(big_uint const& other);
    [[nodiscard]] big_uint mul_ref(big_uint const& other) const;
    [[nodiscard]] big_uint square_ref() const { return mul_ref(*this); }

    void shl1();
    void shr1();
    void shl_bits(std::size_t n);
    [[nodiscard]] big_uint shr_bits(std::size_t n) const;
    [[nodiscard]] big_uint low_bits(std::size_t k) const;

    [[nodiscard]] std::pair<big_uint, big_uint> div_rem(big_uint const& divisor) const;
    [[nodiscard]] big_uint modulo(big_uint const& modulus) const {
        return div_rem(modulus).second;
    }

    // (lhs · rhs) mod modulus. Dispatches to Montgomery for odd
    // modulus, double-and-add fallback otherwise.
    static big_uint mod_mul(big_uint const& lhs, big_uint const& rhs, big_uint const& modulus);

    // Low 128 bits as a u128. Used by the mersenne127 fast path.
    [[nodiscard]] __uint128_t low_u128() const noexcept;

    // Internal accessor for adjacent modules; not part of the
    // user-facing API. Returns a const span for safety.
    [[nodiscard]] std::span<std::uint64_t const> limbs() const noexcept {
        return {limbs_.data(), limbs_.size()};
    }

private:
    std::vector<std::uint64_t> limbs_;

    void normalise() noexcept;
    [[nodiscard]] std::uint64_t limb_or_zero(std::size_t i) const noexcept {
        return i < limbs_.size() ? limbs_[i] : 0;
    }

    static big_uint mul_schoolbook(big_uint const& lhs, big_uint const& rhs);
    static big_uint mul_karatsuba(big_uint const& lhs, big_uint const& rhs);
    [[nodiscard]] std::pair<big_uint, big_uint> split_at_limb(std::size_t split) const;
    static bool should_use_karatsuba(big_uint const& lhs, big_uint const& rhs) noexcept;

    static big_uint mod_mul_plain(big_uint const& lhs, big_uint const& rhs,
                                  big_uint const& modulus);

    // Montgomery multiplication step shared by `montgomery_ctx`.
    // Private because callers should go through `mod_mul` or
    // `montgomery_ctx`; the function operates on limb buffers and
    // assumes its inputs are already in Montgomery domain.
    static big_uint montgomery_mul_odd_with_workspace(
        big_uint const& lhs, big_uint const& rhs, big_uint const& modulus,
        std::uint64_t n0_inv, std::vector<std::uint64_t>& workspace);

    friend class montgomery_ctx;
};

// Montgomery arithmetic context for a fixed odd modulus. Built once,
// reused for every multiplication / exponentiation under the same
// modulus.
class montgomery_ctx {
public:
    static std::optional<montgomery_ctx> make(big_uint const& modulus);

    [[nodiscard]] big_uint const& modulus() const noexcept { return modulus_; }

    // base^exp mod modulus.
    [[nodiscard]] big_uint pow(big_uint const& base, big_uint const& exponent) const;

    // (lhs · rhs) mod modulus.
    [[nodiscard]] big_uint mul(big_uint const& lhs, big_uint const& rhs) const;

    // Square one ordinary residue.
    [[nodiscard]] big_uint square(big_uint const& value) const;

private:
    montgomery_ctx() = default;

    big_uint modulus_;
    std::uint64_t n0_inv_ = 0;
    big_uint r2_mod_;
    big_uint one_mont_;

    [[nodiscard]] big_uint encode(big_uint const& value) const;
    [[nodiscard]] big_uint decode(big_uint const& value) const;
    [[nodiscard]] big_uint mont_mul(big_uint const& lhs, big_uint const& rhs) const;
};

}  // namespace secret_sharing
