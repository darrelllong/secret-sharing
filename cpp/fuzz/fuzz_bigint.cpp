// libFuzzer harness for BigUint arithmetic.
//
// Splits the input into two byte slices and exercises every public
// arithmetic operation on the corresponding BigUints. The check is
// algebraic identities that must hold under any inputs:
//   - (a + b) − b == a
//   - (a · b) == (b · a)
//   - a · 0 == 0, a · 1 == a
//   - low_bits(k) + (shr_bits(k) << k) == a
//   - mod_mul agrees with `(a · b) % m` computed via div_rem
//
// Any panic / UB / sanitiser hit aborts the fuzzer immediately.

#include "secret_sharing/bigint.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace ss = secret_sharing;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (size < 4) {
        return 0;
    }
    // Split: first byte = a length (0..min(size-1, 64)),
    // remaining bytes are concatenated (a, b, m). Cap each at 64
    // bytes so the schoolbook stays under a millisecond.
    std::size_t a_len = data[0] % 65;
    std::size_t b_len = data[1] % 65;
    std::size_t m_len = data[2] % 65;
    std::size_t pos = 3;
    if (pos + a_len + b_len + m_len > size) {
        return 0;
    }
    std::span<std::uint8_t const> a_bytes{data + pos, a_len};
    pos += a_len;
    std::span<std::uint8_t const> b_bytes{data + pos, b_len};
    pos += b_len;
    std::span<std::uint8_t const> m_bytes{data + pos, m_len};

    auto a = ss::big_uint::from_be_bytes(a_bytes);
    auto b = ss::big_uint::from_be_bytes(b_bytes);
    auto m = ss::big_uint::from_be_bytes(m_bytes);

    // Identities that must hold for every (a, b).
    auto sum = a.add_ref(b);
    if (sum.sub_ref(b) != a) {
        __builtin_trap();
    }
    if (a.mul_ref(b) != b.mul_ref(a)) {
        __builtin_trap();
    }
    if (!a.mul_ref(ss::big_uint::zero()).is_zero()) {
        __builtin_trap();
    }
    if (a.mul_ref(ss::big_uint::one()) != a) {
        __builtin_trap();
    }

    // Bit-split round-trip at random k.
    if (size >= 4) {
        std::size_t k = (data[3] * 4) % (a.bits() + 8);
        auto high = a.shr_bits(k);
        auto low = a.low_bits(k);
        auto reconstituted = high;
        reconstituted.shl_bits(k);
        reconstituted.add_assign_ref(low);
        if (reconstituted != a) {
            __builtin_trap();
        }
    }

    // mod_mul matches (a·b) mod m for non-zero m.
    if (!m.is_zero()) {
        auto via_mod = a.mul_ref(b).modulo(m);
        auto via_mod_mul = ss::big_uint::mod_mul(a, b, m);
        if (via_mod != via_mod_mul) {
            __builtin_trap();
        }
    }
    return 0;
}
