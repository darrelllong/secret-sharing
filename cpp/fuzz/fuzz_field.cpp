// libFuzzer harness for prime_field over Mersenne-127.
//
// Compares the fast-path `prime_field::mul` (which dispatches to the
// u128 Mersenne reducer) against the generic `BigUint::mod_mul`
// (Montgomery). Any divergence signals a transcription bug in the
// fast path or a bit-stream regression vs the Rust impl.

#include "secret_sharing/bigint.hpp"
#include "secret_sharing/field.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace ss = secret_sharing;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (size < 32) {
        return 0;
    }
    auto p = ss::mersenne127();
    ss::prime_field f = ss::prime_field::new_unchecked(p);

    auto a = ss::big_uint::from_be_bytes({data, 16});
    auto b = ss::big_uint::from_be_bytes({data + 16, 16});

    auto fast = f.mul(a, b);
    auto generic = ss::big_uint::mod_mul(a, b, p);
    if (fast != generic) {
        __builtin_trap();
    }
    if (!(fast < p)) {
        __builtin_trap();
    }
    return 0;
}
