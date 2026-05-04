//! Self-contained cryptographically-secure pseudorandom number
//! generator interface. Defines the [`Csprng`] trait every scheme uses
//! to draw randomness, plus a small ChaCha20-based [`ChaCha20Rng`]
//! generator and an [`OsRng`] entropy source for seeding it from the
//! operating system.
//!
//! ChaCha20 follows RFC 7539: 16-word state initialised with the
//! constants `"expand 32-byte k"`, a 256-bit key, a 32-bit counter, and
//! a 96-bit nonce; 20 rounds are executed as 10 column / diagonal
//! double-rounds; the output block is the round result added word-wise
//! to the initial state. The CSPRNG wrapper holds 64-byte blocks in a
//! buffer and increments the counter per block.
//!
//! Production seeding. Callers should construct [`OsRng`] and pass it
//! to [`ChaCha20Rng::from_os_entropy`]:
//!
//! ```no_run
//! use secret_sharing::{ChaCha20Rng, csprng::OsRng};
//! let mut os = OsRng::new().expect("operating-system entropy unavailable");
//! let mut rng = ChaCha20Rng::from_os_entropy(&mut os);
//! // pass &mut rng to any scheme.
//! ```
//!
//! `OsRng` reads from `/dev/urandom` on Unix-like targets (macOS,
//! Linux, *BSD). On targets where `/dev/urandom` is not available the
//! constructor returns `Err`; callers must supply their own
//! `Csprng` implementation in that case (e.g. wrapping a hardware RNG
//! or a platform-native API). The trait is the boundary, not the
//! bundled generator.

/// Minimal CSPRNG interface: produce arbitrary numbers of pseudo-random
/// bytes.
pub trait Csprng {
    /// Fill `out` with pseudo-random bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);
}

/// ChaCha20-based CSPRNG, RFC 7539 conformant. Seeded from a 32-byte
/// key; the nonce and counter both start at zero, so the deterministic
/// stream is fully determined by the seed.
///
/// On `Drop` the key, nonce, counter, and the 64-byte keystream buffer
/// are all volatile-zeroed so the secret seed material cannot persist
/// in freed memory. See [`crate::secure`] for the `Zeroize` machinery.
///
/// `ChaCha20Rng` deliberately does **not** implement `Clone`. Cloning a
/// CSPRNG would byte-copy the secret key and the buffered keystream
/// into a fresh allocation outside of the original's `Drop` reach,
/// silently doubling the residue surface. If you need two independent
/// streams, seed two separate generators from the same `OsRng`.
pub struct ChaCha20Rng {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    buf: [u8; 64],
    buf_pos: usize,
}

impl core::fmt::Debug for ChaCha20Rng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't print the key or buffered keystream — both are
        // secret-derived. Just identify the type and the position.
        f.debug_struct("ChaCha20Rng")
            .field("buf_pos", &self.buf_pos)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Drop for ChaCha20Rng {
    fn drop(&mut self) {
        // Volatile-zero every field that derives from the seed.
        for w in self.key.iter_mut() {
            // SAFETY: `w` is a valid `&mut u32` for the duration.
            unsafe { core::ptr::write_volatile(w, 0u32) };
        }
        for w in self.nonce.iter_mut() {
            unsafe { core::ptr::write_volatile(w, 0u32) };
        }
        unsafe { core::ptr::write_volatile(&mut self.counter, 0u32) };
        for b in self.buf.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0u8) };
        }
        unsafe { core::ptr::write_volatile(&mut self.buf_pos, 0usize) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl ChaCha20Rng {
    /// Seed a fresh `ChaCha20Rng` from the operating-system entropy
    /// pool by drawing a 32-byte key from the supplied [`OsRng`]. This
    /// is the recommended construction in production: do not seed from
    /// a fixed byte array except for tests and reproducible benches.
    #[must_use]
    pub fn from_os_entropy(os: &mut OsRng) -> Self {
        let mut seed = [0u8; 32];
        os.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Construct a generator from a 32-byte seed used as the ChaCha20
    /// key. Nonce and counter start at zero.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut key = [0u32; 8];
        for (i, k) in key.iter_mut().enumerate() {
            *k = u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ]);
        }
        Self {
            key,
            nonce: [0; 3],
            counter: 0,
            // `buf_pos == buf.len()` means "buffer empty, refill on
            // next read."
            buf: [0; 64],
            buf_pos: 64,
        }
    }

    fn refill(&mut self) {
        // RFC 7539 ChaCha20 constants: ASCII "expand 32-byte k".
        const C0: u32 = 0x6170_7865;
        const C1: u32 = 0x3320_646e;
        const C2: u32 = 0x7962_2d32;
        const C3: u32 = 0x6b20_6574;

        let mut state: [u32; 16] = [
            C0,
            C1,
            C2,
            C3,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            self.counter,
            self.nonce[0],
            self.nonce[1],
            self.nonce[2],
        ];
        let mut init = state;

        for _ in 0..10 {
            // Column rounds.
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            // Diagonal rounds.
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            state[i] = state[i].wrapping_add(init[i]);
        }
        for (i, word) in state.iter().enumerate() {
            self.buf[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        // Increment the 32-bit block counter, then carry into the
        // 96-bit nonce on overflow. This treats (counter, nonce) as a
        // single 128-bit block index, so the keystream period is
        // 2^128 64-byte blocks — vastly beyond any practical use, and
        // free of the 256 GiB key/nonce-reuse footgun that pure 32-bit
        // counter wrap would create.
        let (next, carry) = self.counter.overflowing_add(1);
        self.counter = next;
        if carry {
            for slot in self.nonce.iter_mut() {
                let (v, c) = slot.overflowing_add(1);
                *slot = v;
                if !c {
                    break;
                }
            }
            // If every nonce word overflowed we have exhausted the
            // entire 128-bit space. Refuse to continue — keystream
            // reuse from this point would silently leak the secret.
            assert!(
                !(self.nonce[0] == 0 && self.nonce[1] == 0 && self.nonce[2] == 0
                    && self.counter == 0),
                "ChaCha20Rng exhausted: 2^128 blocks generated under one key",
            );
        }
        self.buf_pos = 0;

        // Stack residue scrub. `state` and `init` carry both the key
        // (rows 4..12 of the initial block) and the keystream (rows
        // 0..16 of the post-round state). Volatile-zero them before
        // returning so the optimiser cannot leave the secret in the
        // freed stack frame.
        for w in state.iter_mut() {
            // SAFETY: `w` is a valid `&mut u32`.
            unsafe { core::ptr::write_volatile(w, 0u32) };
        }
        // Scrub `init` THROUGH ITS LIVE BINDING — not a copy. A
        // value-copy `let mut init_scrub = init;` would zero the copy
        // and leave the original `init` slot untouched in the stack
        // frame.
        for w in init.iter_mut() {
            unsafe { core::ptr::write_volatile(w, 0u32) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);

    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

impl Csprng for ChaCha20Rng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        // Walk through `out` in chunks of "remaining bytes in the
        // current block." Keeps copy_from_slice on whole runs rather
        // than a per-byte loop.
        let mut written = 0;
        while written < out.len() {
            if self.buf_pos == 64 {
                self.refill();
            }
            let want = (out.len() - written).min(64 - self.buf_pos);
            out[written..written + want]
                .copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + want]);
            self.buf_pos += want;
            written += want;
        }
    }
}

/// Operating-system entropy source. Reads from `/dev/urandom` on
/// Unix-like targets; constructor returns `Err` on platforms where
/// `/dev/urandom` is not available.
///
/// `OsRng` keeps an open file handle for the process lifetime, so
/// repeated `fill_bytes` calls do not pay the open-file cost. It is
/// the supported way to seed [`ChaCha20Rng`] in production:
///
/// ```no_run
/// use secret_sharing::{ChaCha20Rng, csprng::OsRng};
/// let mut os = OsRng::new().unwrap();
/// let mut rng = ChaCha20Rng::from_os_entropy(&mut os);
/// ```
///
/// `Debug` is implemented manually to avoid leaking the file
/// descriptor number through `{:?}` — the formatted output identifies
/// only the type.
pub struct OsRng {
    file: std::fs::File,
}

impl core::fmt::Debug for OsRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OsRng(<entropy source, fd elided>)")
    }
}

impl OsRng {
    /// Open `/dev/urandom`. Returns `Err` if the device is not
    /// readable (typical on Windows, sandboxes without `/dev`, or
    /// `no_std`-style targets).
    pub fn new() -> std::io::Result<Self> {
        let file = std::fs::File::open("/dev/urandom")?;
        Ok(Self { file })
    }
}

impl Csprng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        use std::io::Read;
        // Loop on partial reads — `read` is allowed to return short.
        let mut written = 0;
        while written < out.len() {
            let n = self
                .file
                .read(&mut out[written..])
                .expect("/dev/urandom read failed");
            assert!(n > 0, "/dev/urandom unexpectedly returned 0 bytes");
            written += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_buffer_deterministically_from_seed() {
        let mut a = ChaCha20Rng::from_seed(&[0x42u8; 32]);
        let mut b = ChaCha20Rng::from_seed(&[0x42u8; 32]);
        let mut buf_a = [0u8; 200];
        let mut buf_b = [0u8; 200];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = ChaCha20Rng::from_seed(&[0x01u8; 32]);
        let mut b = ChaCha20Rng::from_seed(&[0x02u8; 32]);
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_ne!(buf_a, buf_b);
    }

    #[test]
    fn matches_rfc7539_test_vector_zero_key_zero_nonce() {
        // RFC 7539 §2.4.2 test vector: key = all zeros, nonce = zeros,
        // counter = 0, first 64 bytes of keystream:
        //   76b8e0ada0f13d90405d6ae55386bd28
        //   bdd219b8a08ded1aa836efcc8b770dc7
        //   da41597c5157488d7724e03fb8d84a37
        //   6a43b8f41518a11cc387b669b2ee6586
        let mut rng = ChaCha20Rng::from_seed(&[0u8; 32]);
        let mut got = [0u8; 64];
        rng.fill_bytes(&mut got);
        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn os_rng_fills_buffer_with_distinct_bytes() {
        // Smoke: two consecutive 32-byte draws from /dev/urandom should
        // not be all-zero and should not be byte-identical. Probability
        // of either failure is ~ 2^-256.
        let Ok(mut os) = OsRng::new() else {
            // /dev/urandom unavailable on this target — skip.
            return;
        };
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        os.fill_bytes(&mut a);
        os.fill_bytes(&mut b);
        assert!(a.iter().any(|&v| v != 0), "all-zero draw is overwhelmingly unlikely");
        assert_ne!(a, b, "two draws should differ");
    }

    #[test]
    fn chacha20_from_os_entropy_does_not_panic() {
        let Ok(mut os) = OsRng::new() else {
            return;
        };
        let mut rng = ChaCha20Rng::from_os_entropy(&mut os);
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&v| v != 0));
    }

    #[test]
    fn chacha20_drop_does_not_panic() {
        // Smoke: ChaCha20Rng's Drop performs many volatile writes. This
        // test exists so any regression that breaks Drop (e.g. UB
        // introduced by a refactor) trips on `cargo test`.
        for _ in 0..10 {
            let mut rng = ChaCha20Rng::from_seed(&[0xA7u8; 32]);
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            // rng dropped here.
        }
    }

    #[test]
    fn supports_short_and_long_fills() {
        let mut rng = ChaCha20Rng::from_seed(&[0xFFu8; 32]);
        let mut single_call = [0u8; 200];
        rng.fill_bytes(&mut single_call);

        let mut rng2 = ChaCha20Rng::from_seed(&[0xFFu8; 32]);
        let mut split = [0u8; 200];
        // Drip the same 200 bytes through many short calls — must agree.
        let mut written = 0;
        for chunk in [1, 7, 64, 50, 1, 77].iter().copied() {
            let end = (written + chunk).min(split.len());
            rng2.fill_bytes(&mut split[written..end]);
            written = end;
        }
        rng2.fill_bytes(&mut split[written..]);
        assert_eq!(single_call, split);
    }
}
