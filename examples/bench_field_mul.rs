//! Per-prime micro-benchmark for `PrimeField::mul`.
//!
//! Times the field multiplier on every standardised prime that the
//! pseudo-Mersenne / Solinas dispatch recognises, comparing the
//! specialised fast path against the generic Montgomery path. Output
//! is a Markdown table on stdout; intended to be captured into
//! `benchmarks/field_mul_<host>.md` after a release run.
//!
//! Methodology is the legacy `examples/bench.rs` style — a coarse
//! `Instant` timer with 50 warmup + 200 measured iterations, median
//! latency. This is the same regime as the kiviat radars; the
//! pilot-bench tables in PERFORMANCE.md remain the authoritative
//! CI'd measurement layer for whole-scheme throughputs. Run once
//! with `cargo run --release --example bench_field_mul`.

use std::time::Instant;

use secret_sharing::csprng::ChaCha20Rng;
use secret_sharing::field::{
    curve25519_field, curve448_field, mersenne127, mersenne521, nist_p192_field,
    nist_p224_field, nist_p256_field, nist_p384_field, poly1305_field, secp256k1_field,
    PrimeField,
};
use secret_sharing::BigUint;

const WARMUP: usize = 50;
const ITERS: usize = 200;
const SEED: [u8; 32] = [0xA7; 32];

struct Row {
    name: &'static str,
    bits: usize,
    fast_ns: u128,
    generic_ns: u128,
}

fn time_mul(field: &PrimeField, rng: &mut ChaCha20Rng) -> u128 {
    // Pre-generate a buffer of operands so the per-iteration cost is
    // dominated by `mul` and not by RNG draws.
    let n_ops = WARMUP + ITERS;
    let pairs: Vec<(BigUint, BigUint)> = (0..n_ops)
        .map(|_| (field.random(rng), field.random(rng)))
        .collect();
    // Warmup.
    for (a, b) in pairs.iter().take(WARMUP) {
        std::hint::black_box(field.mul(a, b));
    }
    // Measure.
    let mut samples = Vec::with_capacity(ITERS);
    for (a, b) in pairs.iter().skip(WARMUP) {
        let t0 = Instant::now();
        let r = field.mul(a, b);
        samples.push(t0.elapsed().as_nanos());
        std::hint::black_box(r);
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn run(name: &'static str, p: BigUint) -> Row {
    let bits = p.bits();
    let fast = PrimeField::new_unchecked(p.clone());
    // Force the generic Montgomery path by constructing a separate
    // field through `new_unchecked` on a clone — same `p`, but we
    // measure the dispatch overhead the same way for both. To
    // actually compare paths we need two timing runs with different
    // `kind`s; we accomplish that by wrapping the same `p` in a
    // freshly-built field whose dispatch lookup is bypassed via the
    // public API.
    //
    // Since `FieldKind` is module-private, we time the generic path
    // by a value that's never matched by `detect_kind`: shift `p`
    // by zero and re-build (still dispatches through the table —
    // no help). The clean way is to expose a test-only construction;
    // instead, we time `BigUint::mod_mul` directly, which is the
    // exact code the generic path runs.
    let mut rng = ChaCha20Rng::from_seed(&SEED);
    let fast_ns = time_mul(&fast, &mut rng);

    // Generic-path timing: drive `BigUint::mod_mul` with the same
    // operand stream so the comparison is apples-to-apples.
    let mut rng = ChaCha20Rng::from_seed(&SEED);
    let n_ops = WARMUP + ITERS;
    let pairs: Vec<(BigUint, BigUint)> = (0..n_ops)
        .map(|_| (fast.random(&mut rng), fast.random(&mut rng)))
        .collect();
    for (a, b) in pairs.iter().take(WARMUP) {
        std::hint::black_box(BigUint::mod_mul(a, b, &p));
    }
    let mut samples = Vec::with_capacity(ITERS);
    for (a, b) in pairs.iter().skip(WARMUP) {
        let t0 = Instant::now();
        let r = BigUint::mod_mul(a, b, &p);
        samples.push(t0.elapsed().as_nanos());
        std::hint::black_box(r);
    }
    samples.sort_unstable();
    let generic_ns = samples[samples.len() / 2];

    Row { name, bits, fast_ns, generic_ns }
}

fn fmt_ns(ns: u128) -> String {
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.2} µs", (ns as f64) / 1_000.0)
    } else {
        format!("{:.2} ms", (ns as f64) / 1_000_000.0)
    }
}

fn main() {
    eprintln!("benching field::mul across registered primes...");

    let rows = [
        run("mersenne127", mersenne127()),
        run("poly1305", poly1305_field()),
        run("nist_p192", nist_p192_field()),
        run("nist_p224", nist_p224_field()),
        run("curve25519", curve25519_field()),
        run("nist_p256", nist_p256_field()),
        run("secp256k1", secp256k1_field()),
        run("nist_p384", nist_p384_field()),
        run("curve448", curve448_field()),
        run("mersenne521", mersenne521()),
    ];

    println!();
    println!("## Field multiplication: fast path vs Montgomery generic\n");
    println!("Methodology: Apple-silicon release build, `Instant` timer,");
    println!("50 warmup + 200 measured iterations, median latency.\n");
    println!("| Prime          | bits |  fast path |   generic   | speedup |");
    println!("|----------------|-----:|-----------:|------------:|--------:|");
    for r in &rows {
        let speedup = r.generic_ns as f64 / r.fast_ns as f64;
        println!(
            "| `{:<13}`| {:>4} | {:>10} | {:>11} | {:>5.2}× |",
            r.name,
            r.bits,
            fmt_ns(r.fast_ns),
            fmt_ns(r.generic_ns),
            speedup,
        );
    }
}
