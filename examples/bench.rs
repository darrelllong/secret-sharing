//! Performance benchmark for the secret-sharing crate.
//!
//! Runs split + reconstruct for every scheme that maps cleanly to a
//! "single integer secret of N bits" model, at four secret sizes
//! (128 / 256 / 512 / 1024 bits) with `(k, n) = (3, 5)`. Emits:
//!
//!   - a Markdown table to stdout
//!   - one SVG kiviat (radar) chart per scheme family into `assets/`
//!
//! Run:
//!
//!   cargo run --release --example bench
//!
//! Methodology:
//!
//! - 50 warmup iterations + 200 measured iterations per (scheme, size).
//! - Median (not mean) latency reported, for resistance to GC / OS
//!   scheduling noise.
//! - For schemes whose secret model is one field element, we vary the
//!   prime-field bit width: Mersenne-127 (128-bit equivalent),
//!   2^255 − 19 (Curve25519 base field, "256-bit"), Mersenne-521
//!   ("512-bit"), and a 1024-bit prime (RFC 2412 OAKLEY group 2).
//! - For schemes with vector secrets, we use a length-`L` vector at
//!   the same field size (so total secret bits ≈ L · field_bits).
//! - For byte-string schemes (`bytes`, `ida`) we keep the field at
//!   Mersenne-127 and pass a byte string of `bits / 8` bytes.
//! - CRT schemes (`mignotte`, `asmuth_bloom`) and visual cryptography
//!   are excluded — their secret-size model differs structurally.

use std::time::Instant;

use secret_sharing::{
    benaloh_leichter as bl, blakley, blakley_meadows, brickell, bytes, cgma_vss,
    csprng::OsRng,
    decode::reconstruct_with_errors,
    field::{mersenne127, mersenne521},
    ida, ito, karchmer_wigderson as kw, kgh, kothari, massey, proactive, ramp, shamir,
    trivial, vss, yamamoto,
    BigUint, ChaCha20Rng, Csprng, PrimeField,
};

const K: usize = 3;
const N: usize = 5;
const WARMUP: usize = 50;
const ITERS: usize = 200;

#[derive(Clone, Copy)]
enum Family {
    Threshold,
    Ramp,
    Vss,
    Other,
}

struct Result {
    scheme: &'static str,
    family: Family,
    /// One latency (ns) per secret-size (128, 256, 512, 1024).
    splits: [u128; 4],
    recons: [u128; 4],
}

const SECRET_BITS: [usize; 4] = [128, 256, 512, 1024];

fn primes_for_sizes() -> [PrimeField; 4] {
    // 128-bit equivalent: 2^127 − 1 (Mersenne).
    let p128 = mersenne127();
    // 256-bit equivalent: 2^255 − 19 (Curve25519 base field).
    let p256 = {
        let mut v = BigUint::one();
        v.shl_bits(255);
        v.sub_ref(&BigUint::from_u64(19))
    };
    // 512-bit equivalent: 2^521 − 1 (Mersenne).
    let p512 = mersenne521();
    // 1024-bit: OAKLEY group 2 prime (RFC 2412), the canonical
    // 1024-bit safe prime used for DH.
    let p1024 = oakley_group2_prime();
    [
        PrimeField::new(p128),
        PrimeField::new(p256),
        PrimeField::new(p512),
        PrimeField::new(p1024),
    ]
}

fn oakley_group2_prime() -> BigUint {
    // RFC 2412 OAKLEY group 2 1024-bit prime.
    // p = 2^1024 - 2^960 - 1 + 2^64 * (floor(2^894 * pi) + 129093)
    // We hardcode the resulting hex.
    let hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
               020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
               4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
               EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    BigUint::from_be_bytes(&bytes)
}

/// Production code seeds via `OsRng` (`/dev/urandom`); see HOWTO.md.
/// The bench keeps a *deterministic* fixed-byte seed so consecutive
/// runs produce comparable timings — random seeds would add per-run
/// variance from differing limb-length distributions inside BigUint.
/// The OS entropy path is exercised once at startup as a smoke check.
fn rng_for(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(&[seed; 32])
}

fn os_smoke_check() {
    let mut os = OsRng::new().expect("OsRng (`/dev/urandom`) unavailable");
    let mut probe = [0u8; 32];
    os.fill_bytes(&mut probe);
    assert!(probe.iter().any(|&b| b != 0), "/dev/urandom produced all zeros");
    let _rng_smoke = ChaCha20Rng::from_os_entropy(&mut os);
}

fn random_secret_in_field(field: &PrimeField, rng: &mut impl Csprng) -> BigUint {
    field.random(rng)
}

fn median(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn time_block<R, F: FnMut() -> R>(iters: usize, warmup: usize, mut body: F) -> u128 {
    for _ in 0..warmup {
        let _ = body();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let r = body();
        samples.push(t0.elapsed().as_nanos());
        std::hint::black_box(r);
    }
    median(&mut samples)
}

// ── per-scheme runners ─────────────────────────────────────────────

fn bench_shamir(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x42);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || {
            shamir::split(field, &mut r, &secret, K, N)
        });
        let shares = shamir::split(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            shamir::reconstruct(field, &shares[..K], K).unwrap()
        });
    }
    Result { scheme: "shamir", family: Family::Threshold, splits, recons }
}

fn bench_blakley(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x19);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || {
            blakley::split(field, &mut r, &secret, K, N)
        });
        let shares = blakley::split(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            blakley::reconstruct(field, &shares[..K], K).unwrap()
        });
    }
    Result { scheme: "blakley", family: Family::Threshold, splits, recons }
}

fn bench_kothari(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let scheme = kothari::vandermonde(field.clone(), K, N);
        let mut r = rng_for(0x4B);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || {
            kothari::split(&scheme, &mut r, &secret)
        });
        let shares = kothari::split(&scheme, &mut r, &secret);
        let pairs: Vec<(usize, BigUint)> = (0..K).map(|c| (c, shares[c].clone())).collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            kothari::reconstruct(&scheme, &pairs).unwrap()
        });
    }
    Result { scheme: "kothari", family: Family::Threshold, splits, recons }
}

fn bench_kw(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let prog = kw::threshold_msp(field.clone(), K, N);
        let mut r = rng_for(0x9C);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || kw::split(&prog, &mut r, &secret));
        let shares = kw::split(&prog, &mut r, &secret);
        let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            kw::reconstruct(&prog, &coalition).unwrap()
        });
    }
    Result { scheme: "karchmer_wigderson", family: Family::Threshold, splits, recons }
}

fn bench_brickell(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        // Vandermonde vectors v_j = (1, j, j^2).
        let vectors: Vec<Vec<BigUint>> = (1..=N)
            .map(|j| {
                let mut row = Vec::with_capacity(K);
                let mut pow = BigUint::one();
                let j_val = BigUint::from_u64(j as u64);
                for _ in 0..K {
                    row.push(pow.clone());
                    pow = field.mul(&pow, &j_val);
                }
                row
            })
            .collect();
        let scheme = brickell::Scheme::new(field.clone(), vectors);
        let mut r = rng_for(0xB7);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || brickell::split(&scheme, &mut r, &secret));
        let shares = brickell::split(&scheme, &mut r, &secret);
        let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            brickell::reconstruct(&scheme, &coalition).unwrap()
        });
    }
    Result { scheme: "brickell", family: Family::Threshold, splits, recons }
}

fn bench_massey(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        // (2, n) Shamir as a Massey code: G is 2 × (n+1).
        let mut g = vec![vec![BigUint::one(); N + 1], vec![BigUint::zero(); N + 1]];
        #[allow(clippy::needless_range_loop)]
        for j in 1..=N {
            g[1][j] = BigUint::from_u64(j as u64);
        }
        let scheme = massey::CodeScheme::new(field.clone(), g);
        let mut r = rng_for(0xA5);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || massey::split(&scheme, &mut r, &secret));
        let shares = massey::split(&scheme, &mut r, &secret);
        // Massey wants > k = 2 shares for our (2, n) example; use first 2.
        let coalition: Vec<_> = shares.iter().take(2).cloned().collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            massey::reconstruct(&scheme, &coalition).unwrap()
        });
    }
    Result { scheme: "massey", family: Family::Threshold, splits, recons }
}

fn bench_trivial(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x07);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || trivial::split(field, &mut r, &secret, N));
        let shares = trivial::split(field, &mut r, &secret, N);
        recons[idx] = time_block(ITERS, WARMUP, || trivial::reconstruct(field, &shares));
    }
    Result { scheme: "trivial (n-of-n)", family: Family::Other, splits, recons }
}

fn bench_ito(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let structure = ito::threshold_access_structure(N, K);
        let mut r = rng_for(0xA1);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || {
            ito::split(field, &mut r, &secret, &structure)
        });
        let shares = ito::split(field, &mut r, &secret, &structure);
        let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            ito::reconstruct(field, &structure, &coalition).unwrap()
        });
    }
    Result { scheme: "ito (k-of-n via ISN)", family: Family::Other, splits, recons }
}

fn bench_benaloh_leichter(fields: &[PrimeField; 4]) -> Result {
    // Formula: (P1 AND P2) OR (P1 AND P3) OR (P2 AND P3)
    let formula = bl::Formula::or(vec![
        bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(2)]),
        bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(3)]),
        bl::Formula::and(vec![bl::Formula::party(2), bl::Formula::party(3)]),
    ]);
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x77);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || {
            bl::split(field, &mut r, &secret, &formula)
        });
        let shares = bl::split(field, &mut r, &secret, &formula);
        let pair: Vec<_> = shares.iter().take(2).cloned().collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            bl::reconstruct(field, &formula, &pair).unwrap()
        });
    }
    Result { scheme: "benaloh_leichter (2-of-3)", family: Family::Other, splits, recons }
}

fn bench_ramp(fields: &[PrimeField; 4]) -> Result {
    // Ramp with k = K elements: total secret bits ≈ K · field_bits.
    // For a fair "one secret of N bits" comparison, we use k=3 elements
    // summing to roughly N bits — i.e. each element ≈ N/3 bits. We
    // approximate by using the same-size field and just secret of K
    // elements at that field's full size.
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x10);
        let secret: Vec<BigUint> = (0..K).map(|_| field.random(&mut r)).collect();
        splits[idx] = time_block(ITERS, WARMUP, || ramp::split(field, &secret, N));
        let shares = ramp::split(field, &secret, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            ramp::reconstruct(field, &shares[..K], K).unwrap()
        });
    }
    Result { scheme: "ramp", family: Family::Ramp, splits, recons }
}

fn bench_yamamoto(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    let l = K; // L = k for max compression in this benchmark.
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0xCD);
        let secret: Vec<BigUint> = (0..l).map(|_| field.random(&mut r)).collect();
        splits[idx] = time_block(ITERS, WARMUP, || {
            yamamoto::split(field, &mut r, &secret, K, N)
        });
        let shares = yamamoto::split(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            yamamoto::reconstruct(field, &shares[..K], K, l).unwrap()
        });
    }
    Result { scheme: "yamamoto", family: Family::Ramp, splits, recons }
}

fn bench_blakley_meadows(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    let l = K - 1; // L < k constraint; pick maximum L.
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x4D);
        let secret: Vec<BigUint> = (0..l).map(|_| field.random(&mut r)).collect();
        splits[idx] = time_block(ITERS, WARMUP, || {
            blakley_meadows::split(field, &mut r, &secret, K, N)
        });
        let shares = blakley_meadows::split(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            blakley_meadows::reconstruct(field, &shares[..K], K, l).unwrap()
        });
    }
    Result { scheme: "blakley_meadows", family: Family::Ramp, splits, recons }
}

fn bench_kgh(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    let m = K; // vector secret length.
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x33);
        let secret: Vec<BigUint> = (0..m).map(|_| field.random(&mut r)).collect();
        splits[idx] = time_block(ITERS, WARMUP, || kgh::split(field, &mut r, &secret, K, N));
        let shares = kgh::split(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            kgh::reconstruct(field, &shares[..K], K).unwrap()
        });
    }
    Result { scheme: "kgh (matrix)", family: Family::Ramp, splits, recons }
}

fn bench_vss(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x55);
        let secret = random_secret_in_field(field, &mut r);
        splits[idx] = time_block(ITERS, WARMUP, || vss::deal(field, &mut r, &secret, K, N));
        let shares = vss::deal(field, &mut r, &secret, K, N);
        recons[idx] = time_block(ITERS, WARMUP, || {
            vss::reconstruct(field, &shares[..K], K).unwrap()
        });
    }
    Result { scheme: "vss (Rabin-Ben-Or)", family: Family::Vss, splits, recons }
}

fn bench_cgma_vss() -> Result {
    // cgma_vss is over a fixed Schnorr group; secret-bit dimension does
    // not directly map to a prime field. We bench at the toy group for
    // all four sizes (yielding the same number 4×) so the radar still
    // includes it, with a clear note in PERFORMANCE.md.
    let group = cgma_vss::small_test_group();
    let mut r = rng_for(0xC9);
    let secret = BigUint::from_u64(7);

    let split_med = time_block(ITERS, WARMUP, || cgma_vss::deal(&group, &mut r, &secret, K, N));
    let (shares, commits) = cgma_vss::deal(&group, &mut r, &secret, K, N);
    // Verification + reconstruct for the recon side.
    let recon_med = time_block(ITERS, WARMUP, || {
        for s in &shares {
            std::hint::black_box(cgma_vss::verify_share(&group, &commits, s));
        }
        cgma_vss::reconstruct(&group, &shares[..K], K).unwrap()
    });
    Result {
        scheme: "cgma_vss (toy 23/11/4 group)",
        family: Family::Vss,
        splits: [split_med; 4],
        recons: [recon_med; 4],
    }
}

fn bench_proactive(fields: &[PrimeField; 4]) -> Result {
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, field) in fields.iter().enumerate() {
        let mut r = rng_for(0x70);
        let secret = random_secret_in_field(field, &mut r);
        let shares0 = shamir::split(field, &mut r, &secret, K, N);
        // "split" timing = cost of one refresh epoch.
        splits[idx] = time_block(ITERS, WARMUP, || {
            proactive::refresh(field, &mut r, &shares0, K)
        });
        // "reconstruct" timing = lost-share recovery cost.
        let live = vec![shares0[0].clone(), shares0[1].clone(), shares0[3].clone()];
        recons[idx] = time_block(ITERS, WARMUP, || {
            proactive::recover_share(field, &live, K, &shares0[2].x).unwrap()
        });
    }
    Result { scheme: "proactive (refresh/recover)", family: Family::Other, splits, recons }
}

fn bench_bytes() -> Result {
    let field = PrimeField::new(mersenne127());
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, &bits) in SECRET_BITS.iter().enumerate() {
        let secret = vec![0xC3u8; bits / 8];
        let mut r = rng_for(0x09);
        splits[idx] = time_block(ITERS, WARMUP, || {
            bytes::split(&field, &mut r, &secret, K, N)
        });
        let shares = bytes::split(&field, &mut r, &secret, K, N);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            bytes::reconstruct(&field, &refs[..K], K).unwrap()
        });
    }
    Result { scheme: "bytes (chunked Shamir)", family: Family::Other, splits, recons }
}

fn bench_ida() -> Result {
    let field = PrimeField::new(mersenne127());
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, &bits) in SECRET_BITS.iter().enumerate() {
        let data = vec![0x5Au8; bits / 8];
        splits[idx] = time_block(ITERS, WARMUP, || ida::split(&field, &data, K, N));
        let shares = ida::split(&field, &data, K, N);
        let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        recons[idx] = time_block(ITERS, WARMUP, || {
            ida::reconstruct(&field, &refs[..K], K).unwrap()
        });
    }
    Result { scheme: "ida (Reed-Solomon)", family: Family::Other, splits, recons }
}

fn bench_decode() -> Result {
    // Berlekamp-Welch decode with t = 1 tampered share at n=11, k=K.
    let field = PrimeField::new(mersenne127());
    let mut splits = [0u128; 4];
    let mut recons = [0u128; 4];
    for (idx, _bits) in SECRET_BITS.iter().enumerate() {
        let mut r = rng_for(0x5A);
        let secret = field.random(&mut r);
        let shares0 = shamir::split(&field, &mut r, &secret, K, 11);
        splits[idx] = time_block(ITERS, WARMUP, || {
            shamir::split(&field, &mut r, &secret, K, 11)
        });
        // Inject one tampered share.
        let mut tampered = shares0.clone();
        tampered[3].y = field.add(&tampered[3].y, &BigUint::from_u64(1));
        recons[idx] = time_block(ITERS, WARMUP, || {
            reconstruct_with_errors(&field, &tampered, K, 1).unwrap()
        });
    }
    Result {
        scheme: "decode (Berlekamp-Welch, t=1)",
        family: Family::Other,
        splits,
        recons,
    }
}

// ── Markdown table emission ────────────────────────────────────────

fn human_ns(ns: u128) -> String {
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.1} µs", (ns as f64) / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2} ms", (ns as f64) / 1_000_000.0)
    } else {
        format!("{:.2} s", (ns as f64) / 1_000_000_000.0)
    }
}

fn print_table(results: &[Result]) {
    println!("\n## Split (k=3, n=5)\n");
    println!("| Scheme | 128-bit | 256-bit | 512-bit | 1024-bit |");
    println!("|--------|---------|---------|---------|----------|");
    for r in results {
        println!(
            "| `{}` | {} | {} | {} | {} |",
            r.scheme,
            human_ns(r.splits[0]),
            human_ns(r.splits[1]),
            human_ns(r.splits[2]),
            human_ns(r.splits[3]),
        );
    }
    println!("\n## Reconstruct (k=3, first k shares)\n");
    println!("| Scheme | 128-bit | 256-bit | 512-bit | 1024-bit |");
    println!("|--------|---------|---------|---------|----------|");
    for r in results {
        println!(
            "| `{}` | {} | {} | {} | {} |",
            r.scheme,
            human_ns(r.recons[0]),
            human_ns(r.recons[1]),
            human_ns(r.recons[2]),
            human_ns(r.recons[3]),
        );
    }
}

// ── SVG kiviat (radar) ─────────────────────────────────────────────

const SVG_W: f64 = 640.0;
const SVG_H: f64 = 720.0;
const CX: f64 = 320.0;
const CY: f64 = 290.0;
const RADIUS: f64 = 220.0;
const RINGS: usize = 6;

/// Build a single radar showing operations/sec across N axes (one per
/// scheme) and `series.len()` overlapping polygons (one per secret
/// size). The radial scale is logarithmic ops/sec — farther from
/// centre = faster.
fn build_radar_svg(
    title: &str,
    subtitle: &str,
    axis_labels: &[&str],
    // series[i] = (label, color, values_in_ops_per_sec_per_axis).
    series: &[(&str, &str, Vec<f64>)],
    min_value: f64,
    max_value: f64,
) -> String {
    let n = axis_labels.len();
    let angles: Vec<f64> = (0..n)
        .map(|i| -std::f64::consts::FRAC_PI_2 + 2.0 * std::f64::consts::PI * (i as f64) / (n as f64))
        .collect();

    let polar = |r: f64, a: f64| (CX + r * a.cos(), CY + r * a.sin());

    let mut s = String::new();
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{:.0}\" height=\"{:.0}\" \
         viewBox=\"0 0 {:.0} {:.0}\" role=\"img\" aria-labelledby=\"title desc\">\n",
        SVG_W, SVG_H, SVG_W, SVG_H
    ));
    s.push_str(&format!("  <title id=\"title\">{}</title>\n", title));
    s.push_str(&format!("  <desc id=\"desc\">{}</desc>\n", subtitle));
    s.push_str("  <style>\n");
    s.push_str("    .bg { fill: #fbf8f1; }\n");
    s.push_str("    .grid { fill: none; stroke: #c9c2b7; stroke-width: 1; }\n");
    s.push_str("    .axis { stroke: #a79d90; stroke-width: 1; }\n");
    s.push_str("    .label { fill: #342f29; font: 11px ui-sans-serif, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; }\n");
    s.push_str("    .small { fill: #6b6257; font: 10px ui-sans-serif, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; }\n");
    s.push_str("  </style>\n");
    s.push_str(&format!(
        "  <rect class=\"bg\" x=\"0\" y=\"0\" width=\"{:.0}\" height=\"{:.0}\" rx=\"16\" />\n",
        SVG_W, SVG_H
    ));

    // Concentric rings.
    for ring in 1..=RINGS {
        let r = RADIUS * (ring as f64) / (RINGS as f64);
        let pts: Vec<(f64, f64)> = angles.iter().map(|&a| polar(r, a)).collect();
        let pts_str: String = pts
            .iter()
            .map(|(x, y)| format!("{:.1},{:.1}", x, y))
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!("  <polygon class=\"grid\" points=\"{}\" />\n", pts_str));
    }

    // Spokes.
    for &a in &angles {
        let (x2, y2) = polar(RADIUS, a);
        s.push_str(&format!(
            "  <line class=\"axis\" x1=\"{:.0}\" y1=\"{:.0}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
            CX, CY, x2, y2
        ));
    }

    // Series polygons.
    let value_radius = |value: f64| -> f64 {
        let v = value.clamp(min_value, max_value);
        let span = (max_value / min_value).log10();
        RADIUS * (v / min_value).log10() / span
    };
    for (label, color, values) in series {
        let pts: Vec<(f64, f64)> = angles
            .iter()
            .zip(values.iter())
            .map(|(&a, &v)| polar(value_radius(v), a))
            .collect();
        let pts_str: String = pts
            .iter()
            .map(|(x, y)| format!("{:.1},{:.1}", x, y))
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!(
            "  <polygon points=\"{}\" fill=\"{}\" fill-opacity=\"0.18\" stroke=\"{}\" stroke-width=\"2\" />\n",
            pts_str, color, color
        ));
        // Sample circles at each vertex for readability.
        for (x, y) in &pts {
            s.push_str(&format!(
                "  <circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"3\" fill=\"{}\" />\n",
                x, y, color
            ));
        }
        let _ = label;
    }

    // Axis labels.
    let label_offset = 22.0;
    for (i, &lbl) in axis_labels.iter().enumerate() {
        let (x, y) = polar(RADIUS + label_offset, angles[i]);
        let anchor = if x < CX - 20.0 {
            "end"
        } else if x > CX + 20.0 {
            "start"
        } else {
            "middle"
        };
        s.push_str(&format!(
            "  <text class=\"label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"{}\">{}</text>\n",
            x, y + 4.0, anchor, lbl
        ));
    }

    // Radial scale labels along the rightward spoke.
    for ring in 1..=RINGS {
        let r = RADIUS * (ring as f64) / (RINGS as f64);
        let span = (max_value / min_value).log10();
        let v = min_value * 10f64.powf(span * (ring as f64) / (RINGS as f64));
        s.push_str(&format!(
            "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
            CX + 4.0,
            CY - r,
            human_ops(v)
        ));
    }

    // Title + subtitle.
    s.push_str(&format!(
        "  <text class=\"label\" x=\"20\" y=\"{:.0}\" font-weight=\"bold\">{}</text>\n",
        SVG_H - 90.0,
        title
    ));
    s.push_str(&format!(
        "  <text class=\"small\" x=\"20\" y=\"{:.0}\">{}</text>\n",
        SVG_H - 75.0,
        subtitle
    ));

    // Legend.
    let mut lx = 20.0;
    let ly = SVG_H - 40.0;
    for (label, color, _) in series {
        s.push_str(&format!(
            "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"14\" height=\"14\" fill=\"{}\" rx=\"2\" />\n",
            lx, ly, color
        ));
        s.push_str(&format!(
            "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
            lx + 20.0,
            ly + 11.0,
            label
        ));
        lx += 20.0 + 8.0 * (label.len() as f64) + 24.0;
    }

    s.push_str("</svg>\n");
    s
}

fn human_ops(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.1}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.0}k", v / 1_000.0)
    } else {
        format!("{:.0}", v)
    }
}

fn ops_per_sec(ns: u128) -> f64 {
    if ns == 0 {
        f64::INFINITY
    } else {
        1_000_000_000.0 / (ns as f64)
    }
}

const SIZE_COLORS: [&str; 4] = ["#0f766e", "#1d4ed8", "#b45309", "#b91c1c"];
const SIZE_LABELS: [&str; 4] = ["128-bit", "256-bit", "512-bit", "1024-bit"];

fn emit_family_svg(
    family: Family,
    family_name: &str,
    file: &str,
    results: &[Result],
) -> std::io::Result<()> {
    let in_family: Vec<&Result> = results
        .iter()
        .filter(|r| matches!((family, r.family),
            (Family::Threshold, Family::Threshold)
            | (Family::Ramp, Family::Ramp)
            | (Family::Vss, Family::Vss)
            | (Family::Other, Family::Other)
        ))
        .collect();
    if in_family.len() < 2 {
        eprintln!("[skip] not enough schemes in family {family_name}");
        return Ok(());
    }
    // Radars with only 2 axes degenerate to a line; pad with a single
    // synthetic axis if needed for visual readability. Kept here as a
    // caller-side handler instead of inside `build_radar_svg`.
    if in_family.len() == 2 {
        // Just emit a 2-axis radar; SVG handles it (will look like a
        // bowtie). Acceptable for the small VSS family.
    }
    let axis_labels: Vec<&str> = in_family.iter().map(|r| r.scheme).collect();

    let series: Vec<(&str, &str, Vec<f64>)> = SIZE_LABELS
        .iter()
        .enumerate()
        .map(|(i, lbl)| {
            let values: Vec<f64> = in_family
                .iter()
                .map(|r| ops_per_sec(r.splits[i] + r.recons[i]))
                .collect();
            (*lbl, SIZE_COLORS[i], values)
        })
        .collect();

    // Choose log range from data.
    let mut all: Vec<f64> = series.iter().flat_map(|(_, _, v)| v.iter().copied()).collect();
    all.retain(|v| v.is_finite() && *v > 0.0);
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let lo = all.first().copied().unwrap_or(1.0).max(1.0);
    let hi = all.last().copied().unwrap_or(1_000_000.0).max(lo * 10.0);
    // Round outward to a clean decade.
    let lo = 10f64.powf(lo.log10().floor());
    let hi = 10f64.powf(hi.log10().ceil());

    let title = format!("{family_name}: split + reconstruct (ops/sec, log scale)");
    let subtitle =
        "k=3, n=5; per-axis = scheme; per-polygon = secret-size (ChaCha20Rng, ARM64 release build)";
    let svg = build_radar_svg(&title, subtitle, &axis_labels, &series, lo, hi);
    std::fs::write(file, svg)?;
    eprintln!("wrote {file}");
    Ok(())
}

fn main() -> std::io::Result<()> {
    os_smoke_check();
    let fields = primes_for_sizes();

    let mut results: Vec<Result> = Vec::new();
    eprintln!("benching threshold schemes...");
    results.push(bench_shamir(&fields));
    results.push(bench_blakley(&fields));
    results.push(bench_kothari(&fields));
    results.push(bench_kw(&fields));
    results.push(bench_brickell(&fields));
    results.push(bench_massey(&fields));

    eprintln!("benching ramp / vector schemes...");
    results.push(bench_ramp(&fields));
    results.push(bench_yamamoto(&fields));
    results.push(bench_blakley_meadows(&fields));
    results.push(bench_kgh(&fields));

    eprintln!("benching VSS schemes...");
    results.push(bench_vss(&fields));
    results.push(bench_cgma_vss());

    eprintln!("benching other schemes...");
    results.push(bench_trivial(&fields));
    results.push(bench_ito(&fields));
    results.push(bench_benaloh_leichter(&fields));
    results.push(bench_proactive(&fields));
    results.push(bench_bytes());
    results.push(bench_ida());
    results.push(bench_decode());

    print_table(&results);

    eprintln!("\nemitting kiviat SVGs...");
    emit_family_svg(
        Family::Threshold,
        "Threshold schemes",
        "assets/threshold-throughput-radar.svg",
        &results,
    )?;
    emit_family_svg(
        Family::Ramp,
        "Ramp / vector schemes",
        "assets/ramp-throughput-radar.svg",
        &results,
    )?;
    emit_family_svg(
        Family::Vss,
        "Verifiable secret sharing",
        "assets/vss-throughput-radar.svg",
        &results,
    )?;
    emit_family_svg(
        Family::Other,
        "Other schemes",
        "assets/other-throughput-radar.svg",
        &results,
    )?;

    Ok(())
}
