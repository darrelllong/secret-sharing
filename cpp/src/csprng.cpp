#include "secret_sharing/csprng.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstring>
#include <stdexcept>

namespace secret_sharing {

namespace {

constexpr std::uint32_t C0 = 0x6170'7865;
constexpr std::uint32_t C1 = 0x3320'646E;
constexpr std::uint32_t C2 = 0x7962'2D32;
constexpr std::uint32_t C3 = 0x6B20'6574;

inline void quarter_round(std::array<std::uint32_t, 16>& s, std::size_t a, std::size_t b,
                          std::size_t c, std::size_t d) {
    s[a] = s[a] + s[b];
    s[d] ^= s[a];
    s[d] = std::rotl(s[d], 16);

    s[c] = s[c] + s[d];
    s[b] ^= s[c];
    s[b] = std::rotl(s[b], 12);

    s[a] = s[a] + s[b];
    s[d] ^= s[a];
    s[d] = std::rotl(s[d], 8);

    s[c] = s[c] + s[d];
    s[b] ^= s[c];
    s[b] = std::rotl(s[b], 7);
}

template <typename T>
inline void volatile_zero(T* p, std::size_t n) noexcept {
    auto* vp = static_cast<volatile T*>(p);
    for (std::size_t i = 0; i < n; ++i) {
        vp[i] = T{};
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

}  // namespace

chacha20_rng::chacha20_rng(std::array<std::uint32_t, 8> key) : key_(key) {}

chacha20_rng chacha20_rng::from_seed(std::array<std::uint8_t, 32> const& seed) {
    std::array<std::uint32_t, 8> key{};
    for (std::size_t i = 0; i < 8; ++i) {
        key[i] = static_cast<std::uint32_t>(seed[i * 4])
            | (static_cast<std::uint32_t>(seed[i * 4 + 1]) << 8U)
            | (static_cast<std::uint32_t>(seed[i * 4 + 2]) << 16U)
            | (static_cast<std::uint32_t>(seed[i * 4 + 3]) << 24U);
    }
    return chacha20_rng{key};
}

chacha20_rng::~chacha20_rng() {
    volatile_zero(key_.data(), key_.size());
    volatile_zero(nonce_.data(), nonce_.size());
    auto* counter_p = static_cast<volatile std::uint32_t*>(&counter_);
    *counter_p = 0;
    volatile_zero(buf_.data(), buf_.size());
    auto* pos_p = static_cast<volatile std::size_t*>(&buf_pos_);
    *pos_p = 0;
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

void chacha20_rng::refill() {
    std::array<std::uint32_t, 16> state{C0,      C1,      C2,      C3,      key_[0], key_[1],
                                        key_[2], key_[3], key_[4], key_[5], key_[6], key_[7],
                                        counter_, nonce_[0], nonce_[1], nonce_[2]};
    auto init = state;

    for (int round = 0; round < 10; ++round) {
        // Column rounds.
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }

    for (std::size_t i = 0; i < 16; ++i) {
        state[i] = state[i] + init[i];
    }
    for (std::size_t i = 0; i < 16; ++i) {
        auto word = state[i];
        buf_[i * 4 + 0] = static_cast<std::uint8_t>(word);
        buf_[i * 4 + 1] = static_cast<std::uint8_t>(word >> 8U);
        buf_[i * 4 + 2] = static_cast<std::uint8_t>(word >> 16U);
        buf_[i * 4 + 3] = static_cast<std::uint8_t>(word >> 24U);
    }

    // Increment counter; carry into nonce on overflow. Treats
    // (counter, nonce) as one 128-bit block index (matching Rust).
    std::uint32_t prev = counter_;
    counter_ += 1;
    bool carry = counter_ < prev;
    if (carry) {
        for (auto& slot : nonce_) {
            std::uint32_t before = slot;
            slot += 1;
            if (slot >= before) {
                carry = false;
                break;
            }
        }
        if (carry && nonce_[0] == 0 && nonce_[1] == 0 && nonce_[2] == 0 && counter_ == 0) {
            throw std::overflow_error(
                "chacha20_rng exhausted: 2^128 blocks generated under one key");
        }
    }
    buf_pos_ = 0;

    volatile_zero(state.data(), state.size());
    volatile_zero(init.data(), init.size());
}

void chacha20_rng::fill_bytes(std::span<std::uint8_t> out) {
    std::size_t written = 0;
    while (written < out.size()) {
        if (buf_pos_ == 64) {
            refill();
        }
        auto want = std::min(out.size() - written, std::size_t{64} - buf_pos_);
        std::memcpy(out.data() + written, buf_.data() + buf_pos_, want);
        buf_pos_ += want;
        written += want;
    }
}

}  // namespace secret_sharing
