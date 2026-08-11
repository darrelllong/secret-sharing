//! Multiprecision integers, re-exported from the [`rump`] crate.
//!
//! The arithmetic this crate carried in-tree — the same lineage as the
//! cryptography crate's — now lives in
//! [rump](https://github.com/darrelllong/rump) (crates.io package
//! `rust-mp`), extracted so one audited implementation serves every
//! consumer. rump carries the guarantees this module always made: pure
//! safe Rust apart from one audited volatile-scrub helper, limbs wiped on
//! drop, and explicitly variable-time operation — plus the kernels this
//! fork predated (Knuth Algorithm D division, word-level Montgomery
//! multiplication).
//!
//! This module remains so existing paths keep working.

pub use rump::{BigInt, BigUint, MontgomeryCtx, Sign};
