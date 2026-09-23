// Observe scratch storage before free, including failed allocations.
#include "secret_sharing/bigint.hpp"

#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
struct allocation { void* pointer; std::size_t size; };
allocation allocations[32]{};
bool watching = false;
unsigned attempts = 0;
unsigned fail_at = 0;
unsigned dirty = 0;
}

void* operator new(std::size_t size) {
    if (watching && ++attempts == fail_at) throw std::bad_alloc();
    void* pointer = std::malloc(size ? size : 1);
    if (!pointer) throw std::bad_alloc();
    if (watching) {
        bool saved = false;
        for (auto& item : allocations) {
            if (!item.pointer) { item = {pointer, size}; saved = true; break; }
        }
        if (!saved) std::abort();
    }
    return pointer;
}

void operator delete(void* pointer) noexcept {
    if (watching && pointer) {
        for (auto& item : allocations) {
            if (item.pointer == pointer) {
                auto bytes = static_cast<unsigned char const*>(pointer);
                for (std::size_t i = 0; i < item.size; ++i) {
                    if (bytes[i] != 0) { ++dirty; break; }
                }
                item = {};
            }
        }
    }
    std::free(pointer);
}

void operator delete(void* pointer, std::size_t) noexcept { ::operator delete(pointer); }

int main() {
    using secret_sharing::big_uint;
    auto divisor = big_uint::from_u128(
        (static_cast<__uint128_t>(0x923456789abcdef1ULL) << 64) | 0x123456789abcdef1ULL);
    auto dividend = divisor.mul_ref(big_uint(17)).add_ref(big_uint(42));
    unsigned failures = 0;
    bool completed = false;
    for (fail_at = 1; fail_at <= 8; ++fail_at) {
        attempts = 0;
        watching = true;
        try {
            auto result = dividend.div_rem(divisor);
            if (result.first.low_u128() != 17 || result.second.low_u128() != 42) return 2;
            completed = true;
        } catch (std::bad_alloc const&) {
            ++failures;
        }
        watching = false;
        for (auto const& item : allocations) if (item.pointer) return 3;
    }
    std::printf("allocation failures: %u; uncleared frees: %u\n", failures, dirty);
    return completed && failures >= 3 && dirty == 0 ? 0 : 1;
}
