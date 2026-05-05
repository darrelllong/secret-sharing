// Bit-compatible ChaCha20 CSPRNG, RFC 7539 conformant.
//
// Stream output matches `secret_sharing::csprng::ChaCha20Rng` exactly
// for the same 32-byte seed: same 16-word state with the
// `"expand 32-byte k"` constants, same 20-round (10 column-diagonal
// double round) schedule, same per-block counter / nonce update.
// The destructor volatile-zeros the key, nonce, counter, and the
// 64-byte block buffer.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace secret_sharing {

// Minimal CSPRNG interface, mirrors the Rust trait.
class csprng {
public:
    virtual ~csprng() = default;
    virtual void fill_bytes(std::span<std::uint8_t> out) = 0;
};

class chacha20_rng final : public csprng {
public:
    static chacha20_rng from_seed(std::array<std::uint8_t, 32> const& seed);

    chacha20_rng() = delete;
    chacha20_rng(chacha20_rng const&) = delete;
    chacha20_rng& operator=(chacha20_rng const&) = delete;
    chacha20_rng(chacha20_rng&&) noexcept = default;
    chacha20_rng& operator=(chacha20_rng&&) noexcept = default;
    ~chacha20_rng() override;

    void fill_bytes(std::span<std::uint8_t> out) override;

private:
    chacha20_rng(std::array<std::uint32_t, 8> key);

    std::array<std::uint32_t, 8> key_{};
    std::array<std::uint32_t, 3> nonce_{};
    std::uint32_t counter_ = 0;
    std::array<std::uint8_t, 64> buf_{};
    std::size_t buf_pos_ = 64;  // empty buffer -> refill on next read

    void refill();
};

}  // namespace secret_sharing
