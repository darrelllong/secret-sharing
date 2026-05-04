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
    asmuth_bloom, benaloh_leichter as bl, blakley, blakley_meadows, brickell, bytes, cgma_vss,
    csprng::OsRng,
    decode::reconstruct_with_errors,
    field::{mersenne127, mersenne521},
    ida, ito, karchmer_wigderson as kw, kgh, kothari, massey, mignotte, proactive, ramp, shamir,
    trivial, visual, vss, yamamoto,
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
    // not directly map to a prime field. We bench at the RFC 5114 §2.3
    // 2048-bit / 256-bit-subgroup group for all four sizes (yielding
    // the same number 4×) so the radar still includes it.
    let group = cgma_vss::rfc5114_modp_2048_256();
    let mut r = rng_for(0xC9);
    let secret = BigUint::from_u64(0x1234_5678_9abc_def0);

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
        scheme: "cgma_vss (RFC 5114 §2.3, 2048/256)",
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

// ── Non-radar benches: schemes whose perf model doesn't fit `bits` ─────────

/// One sample point on a 1-D scaling curve: x-axis label + (split, recon) ns.
struct ScalingPoint {
    x_label: String,
    /// Numeric x for plotting (log or linear, caller's choice).
    x_value: f64,
    split_ns: u128,
    recon_ns: u128,
}

/// Hand-built Mignotte sequences whose `β` (smallest-`k`-product)
/// straddles a target bit width. Picked to be pairwise coprime
/// odd-prime-or-coprime moduli; validated by `MignotteSequence::new`.
fn mignotte_curve() -> Vec<(usize, mignotte::MignotteSequence)> {
    // (target β bit-width, m_1..m_n). Each sequence chosen so that
    //   β = m_1·m_2·m_3 ≈ 2^target,  α = m_4·m_5 < β,
    // and any two consecutive moduli are coprime (consecutive odd
    // primes / coprime products are easy to pick by hand).
    let raw: [(usize, &[u64]); 3] = [
        // ~16-bit β: bundled small example.
        (16, &[11, 13, 17, 19, 23]),
        // ~64-bit β: 5 distinct primes near 2^22 (each ~22 bits;
        // β ≈ 2^66). Listed strictly increasing.
        (64, &[4_194_247, 4_194_271, 4_194_277, 4_194_287, 4_194_301]),
        // ~128-bit β: 5 distinct primes near 2^43 (each ~43 bits;
        // β ≈ 2^129). Listed strictly increasing.
        (
            128,
            &[
                8_796_093_022_039,
                8_796_093_022_069,
                8_796_093_022_103,
                8_796_093_022_117,
                8_796_093_022_151,
            ],
        ),
    ];
    raw.into_iter()
        .map(|(bits, moduli)| {
            let big: Vec<BigUint> = moduli.iter().copied().map(BigUint::from_u64).collect();
            let seq = mignotte::MignotteSequence::new(big, K)
                .unwrap_or_else(|| panic!("Mignotte seq for {bits}-bit β failed validation"));
            (bits, seq)
        })
        .collect()
}

fn asmuth_bloom_curve() -> Vec<(usize, asmuth_bloom::AsmuthBloomParams)> {
    // Asmuth–Bloom requires m_0 · M_top < M_bot. With (k, n)=(3, 5)
    // and roughly equal m_i ≈ 2^d, we need m_0 < 2^d. Hand-pick
    // m_0 small relative to the m_i. Validation happens in `new`.
    let raw: [(usize, u64, &[u64]); 3] = [
        // ~12-bit secret-modulus path: bundled small example.
        // m_0 = 5; M_bot = 2431, M_top = 437, 5·437 = 2185 < 2431. Good.
        (12, 5, &[11, 13, 17, 19, 23]),
        // ~22-bit m_0 with 22-bit other moduli.
        // M_bot ≈ 2^66, M_top ≈ 2^44, 2^22 · 2^44 = 2^66. Just barely;
        // shrink m_0 to 2^16 to leave headroom.
        (
            16,
            65_521,
            &[4_194_247, 4_194_271, 4_194_277, 4_194_287, 4_194_301],
        ),
        // 32-bit m_0 with 43-bit other moduli.
        // M_bot ≈ 2^129, M_top ≈ 2^86, 2^32 · 2^86 = 2^118 < 2^129. Good.
        (
            32,
            4_294_967_291,
            &[
                8_796_093_022_039,
                8_796_093_022_069,
                8_796_093_022_103,
                8_796_093_022_117,
                8_796_093_022_151,
            ],
        ),
    ];
    raw.into_iter()
        .map(|(bits, m0, moduli)| {
            let m0 = BigUint::from_u64(m0);
            let big: Vec<BigUint> = moduli.iter().copied().map(BigUint::from_u64).collect();
            let p = asmuth_bloom::AsmuthBloomParams::new(m0, big, K)
                .unwrap_or_else(|| panic!("Asmuth-Bloom params for {bits}-bit m_0 invalid"));
            (bits, p)
        })
        .collect()
}

fn bench_mignotte_scaling() -> Vec<ScalingPoint> {
    mignotte_curve()
        .into_iter()
        .map(|(bits, seq)| {
            // Secret strictly inside (alpha, beta). Use alpha + 1.
            let secret = seq.alpha().add_ref(&BigUint::from_u64(1));
            let split_ns = time_block(ITERS, WARMUP, || mignotte::split(&seq, &secret));
            let shares = mignotte::split(&seq, &secret);
            let recon_ns = time_block(ITERS, WARMUP, || {
                mignotte::reconstruct(&seq, &shares[..K]).unwrap()
            });
            ScalingPoint {
                x_label: format!("≈2^{bits}"),
                x_value: bits as f64,
                split_ns,
                recon_ns,
            }
        })
        .collect()
}

fn bench_asmuth_bloom_scaling() -> Vec<ScalingPoint> {
    let mut r = rng_for(0x91);
    asmuth_bloom_curve()
        .into_iter()
        .map(|(bits, params)| {
            // Pick a random secret < m_0. Use a small fixed value to
            // avoid biasing by secret bit-length.
            let secret = BigUint::from_u64(1);
            let split_ns = time_block(ITERS, WARMUP, || {
                asmuth_bloom::split(&params, &mut r, &secret)
            });
            let shares = asmuth_bloom::split(&params, &mut r, &secret);
            let recon_ns = time_block(ITERS, WARMUP, || {
                asmuth_bloom::reconstruct(&params, &shares[..K]).unwrap()
            });
            ScalingPoint {
                x_label: format!("m_0≈2^{bits}"),
                x_value: bits as f64,
                split_ns,
                recon_ns,
            }
        })
        .collect()
}

fn bench_visual_by_n() -> Vec<ScalingPoint> {
    // Fixed 8×8 image; vary n in 2..=5 (per-pixel expansion 2^(n-1)).
    let mut r = rng_for(0x76);
    let secret: Vec<Vec<bool>> = (0..8)
        .map(|y| (0..8).map(|x| (x + y) % 2 == 0).collect())
        .collect();
    (2..=5usize)
        .map(|n| {
            let split_ns = time_block(ITERS, WARMUP, || visual::split_n_of_n(&mut r, &secret, n));
            let shares = visual::split_n_of_n(&mut r, &secret, n);
            let recon_ns = time_block(ITERS, WARMUP, || {
                let stacked = visual::stack(&shares).unwrap();
                visual::decode(&stacked, n).unwrap()
            });
            ScalingPoint {
                x_label: format!("n={n}"),
                x_value: n as f64,
                split_ns,
                recon_ns,
            }
        })
        .collect()
}

fn bench_visual_by_pixels() -> Vec<ScalingPoint> {
    // Fixed n=3; vary image side in {4, 8, 16, 32, 64}.
    let mut r = rng_for(0x77);
    let n = 3;
    [4usize, 8, 16, 32, 64]
        .into_iter()
        .map(|side| {
            let secret: Vec<Vec<bool>> = (0..side)
                .map(|y| (0..side).map(|x| (x + y) % 2 == 0).collect())
                .collect();
            let split_ns = time_block(50, 10, || visual::split_n_of_n(&mut r, &secret, n));
            let shares = visual::split_n_of_n(&mut r, &secret, n);
            let recon_ns = time_block(50, 10, || {
                let stacked = visual::stack(&shares).unwrap();
                visual::decode(&stacked, n).unwrap()
            });
            ScalingPoint {
                x_label: format!("{side}×{side}"),
                x_value: (side * side) as f64,
                split_ns,
                recon_ns,
            }
        })
        .collect()
}

fn bench_cgma_vss_by_group() -> Vec<ScalingPoint> {
    // Four Schnorr groups of increasing modulus size, capped by the
    // RFC 5114 §2.3 standard at 2048 bits.
    let groups: Vec<(usize, cgma_vss::DlogGroup)> = vec![
        (5, cgma_vss::small_test_group()),
        (
            8,
            cgma_vss::DlogGroup::new(
                BigUint::from_u64(167),
                BigUint::from_u64(83),
                BigUint::from_u64(4),
            )
            .expect("(167, 83, 4) Schnorr group"),
        ),
        (1024, oakley_group2_dlog_group()),
        (2048, cgma_vss::rfc5114_modp_2048_256()),
    ];
    let mut out = Vec::new();
    let mut r = rng_for(0xC9);
    for (bits, group) in groups {
        let secret = BigUint::from_u64(1);
        let split_ns = time_block(50, 10, || cgma_vss::deal(&group, &mut r, &secret, K, N));
        let (shares, commits) = cgma_vss::deal(&group, &mut r, &secret, K, N);
        let recon_ns = time_block(50, 10, || {
            for s in &shares {
                std::hint::black_box(cgma_vss::verify_share(&group, &commits, s));
            }
            cgma_vss::reconstruct(&group, &shares[..K], K).unwrap()
        });
        out.push(ScalingPoint {
            x_label: format!("{bits}-bit"),
            x_value: bits as f64,
            split_ns,
            recon_ns,
        });
    }
    out
}

fn oakley_group2_dlog_group() -> cgma_vss::DlogGroup {
    // p = OAKLEY group 2 (1024-bit safe prime). q = (p−1)/2 is prime.
    // g = 4 = 2^2 lies in the order-q subgroup since 2 generates the
    // full (Z/pZ)*; squaring lands in the index-2 subgroup of order q.
    let p = oakley_group2_prime();
    let q = {
        let p_minus_1 = p.sub_ref(&BigUint::one());
        let (half, _) = p_minus_1.div_rem(&BigUint::from_u64(2));
        half
    };
    let g = BigUint::from_u64(4);
    cgma_vss::DlogGroup::new(p, q, g).expect("OAKLEY group 2 with g=4")
}

// ── Cold-cache: first-iteration latency vs warm median. ────────────

struct ColdResult {
    scheme: &'static str,
    cold_split_ns: u128,
    warm_split_ns: u128,
    cold_recon_ns: u128,
    warm_recon_ns: u128,
}

/// One pass: time a single split + a single reconstruct with NO
/// warmup, return ns. Bench at the 128-bit prime field for all
/// scalar schemes.
fn cold_one<S, R, OS, ORet>(mut split_fn: S, mut recon_fn: R) -> (u128, u128)
where
    S: FnMut() -> OS,
    R: FnMut(&OS) -> ORet,
{
    // No warmup at all.
    let t0 = Instant::now();
    let shares = split_fn();
    let split_ns = t0.elapsed().as_nanos();
    let t1 = Instant::now();
    let _ = recon_fn(&shares);
    let recon_ns = t1.elapsed().as_nanos();
    (split_ns, recon_ns)
}

/// Aggregate cold-cache numbers for the eight most-used schemes. The
/// "cold" measurement is a fresh process boot's first call; we
/// approximate it by running just before any warmup.
fn bench_cold_cache(fields: &[PrimeField; 4], warm_results: &[Result]) -> Vec<ColdResult> {
    let field = &fields[0]; // 128-bit Mersenne for all scalar schemes.
    let mut r = rng_for(0xC0);
    let secret = field.random(&mut r);
    let mut out: Vec<ColdResult> = Vec::new();

    let warm_lookup = |name: &str| -> (u128, u128) {
        warm_results
            .iter()
            .find(|w| w.scheme == name)
            .map(|w| (w.splits[0], w.recons[0]))
            .unwrap_or((0, 0))
    };

    // shamir
    {
        let mut r = rng_for(0xC1);
        let s = field.random(&mut r);
        let (cs, cr) = cold_one(
            || shamir::split(field, &mut r, &s, K, N),
            |sh| shamir::reconstruct(field, &sh[..K], K).unwrap(),
        );
        let (ws, wr) = warm_lookup("shamir");
        out.push(ColdResult { scheme: "shamir", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // blakley
    {
        let mut r = rng_for(0xC2);
        let s = field.random(&mut r);
        let (cs, cr) = cold_one(
            || blakley::split(field, &mut r, &s, K, N),
            |sh| blakley::reconstruct(field, &sh[..K], K).unwrap(),
        );
        let (ws, wr) = warm_lookup("blakley");
        out.push(ColdResult { scheme: "blakley", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // kothari
    {
        let scheme = kothari::vandermonde(field.clone(), K, N);
        let mut r = rng_for(0xC3);
        let s = field.random(&mut r);
        let (cs, cr) = cold_one(
            || kothari::split(&scheme, &mut r, &s),
            |sh| {
                let pairs: Vec<(usize, BigUint)> =
                    (0..K).map(|c| (c, sh[c].clone())).collect();
                kothari::reconstruct(&scheme, &pairs).unwrap()
            },
        );
        let (ws, wr) = warm_lookup("kothari");
        out.push(ColdResult { scheme: "kothari", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // ramp
    {
        let mut r = rng_for(0xC4);
        let secret_vec: Vec<BigUint> = (0..K).map(|_| field.random(&mut r)).collect();
        let (cs, cr) = cold_one(
            || ramp::split(field, &secret_vec, N),
            |sh| ramp::reconstruct(field, &sh[..K], K).unwrap(),
        );
        let (ws, wr) = warm_lookup("ramp");
        out.push(ColdResult { scheme: "ramp", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // vss
    {
        let mut r = rng_for(0xC5);
        let s = field.random(&mut r);
        let (cs, cr) = cold_one(
            || vss::deal(field, &mut r, &s, K, N),
            |sh| vss::reconstruct(field, &sh[..K], K).unwrap(),
        );
        let (ws, wr) = warm_lookup("vss (Rabin-Ben-Or)");
        out.push(ColdResult { scheme: "vss", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // bytes
    {
        let mut r = rng_for(0xC6);
        let data = vec![0xC3u8; 16];
        let (cs, cr) = cold_one(
            || bytes::split(field, &mut r, &data, K, N),
            |sh| {
                let refs: Vec<&[u8]> = sh.iter().map(Vec::as_slice).collect();
                bytes::reconstruct(field, &refs[..K], K).unwrap()
            },
        );
        let (ws, wr) = warm_lookup("bytes (chunked Shamir)");
        out.push(ColdResult { scheme: "bytes", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // ida
    {
        let data = vec![0x5Au8; 16];
        let (cs, cr) = cold_one(
            || ida::split(field, &data, K, N),
            |sh| {
                let refs: Vec<&[u8]> = sh.iter().map(Vec::as_slice).collect();
                ida::reconstruct(field, &refs[..K], K).unwrap()
            },
        );
        let (ws, wr) = warm_lookup("ida (Reed-Solomon)");
        out.push(ColdResult { scheme: "ida", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }

    // trivial
    {
        let mut r = rng_for(0xC7);
        let s = field.random(&mut r);
        let (cs, cr) = cold_one(
            || trivial::split(field, &mut r, &s, N),
            |sh| trivial::reconstruct(field, sh),
        );
        let (ws, wr) = warm_lookup("trivial (n-of-n)");
        out.push(ColdResult { scheme: "trivial", cold_split_ns: cs, warm_split_ns: ws, cold_recon_ns: cr, warm_recon_ns: wr });
    }
    let _ = secret;
    out
}

// ── New SVG helpers: line chart and horizontal bar chart. ──────────

const LINE_W: f64 = 640.0;
const LINE_H: f64 = 420.0;

/// Build a line chart: each series is `(label, color, points)` where
/// each point is `(x_label, x_value, y_value_ns)`. y axis is log-ns;
/// x axis is linear in x_value.
/// Per-line series passed to `build_line_svg`: label, colour, and a
/// vector of `(x_label, x_value, y_value)` data points.
type LineSeries<'a> = (&'a str, &'a str, Vec<(String, f64, f64)>);

fn build_line_svg(
    title: &str,
    subtitle: &str,
    x_axis_label: &str,
    series: &[LineSeries],
) -> String {
    // Collect bounds.
    let xs: Vec<f64> = series
        .iter()
        .flat_map(|(_, _, pts)| pts.iter().map(|p| p.1))
        .collect();
    let ys: Vec<f64> = series
        .iter()
        .flat_map(|(_, _, pts)| pts.iter().map(|p| p.2))
        .filter(|y| *y > 0.0 && y.is_finite())
        .collect();
    let xmin = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let xmax = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let ymin_raw = ys.iter().cloned().fold(f64::INFINITY, f64::min);
    let ymax_raw = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let ymin = 10f64.powf(ymin_raw.log10().floor());
    let ymax = 10f64.powf(ymax_raw.log10().ceil());

    let plot_x0 = 80.0_f64;
    let plot_x1 = LINE_W - 30.0;
    let plot_y0 = 60.0_f64;
    let plot_y1 = LINE_H - 90.0;
    let pw = plot_x1 - plot_x0;
    let ph = plot_y1 - plot_y0;

    let map_x = |x: f64| -> f64 {
        if (xmax - xmin).abs() < f64::EPSILON {
            plot_x0 + pw / 2.0
        } else {
            plot_x0 + pw * (x - xmin) / (xmax - xmin)
        }
    };
    let map_y = |y: f64| -> f64 {
        if y <= 0.0 {
            return plot_y1;
        }
        let span = (ymax / ymin).log10();
        plot_y1 - ph * (y / ymin).log10() / span
    };

    let mut s = String::new();
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{:.0}\" height=\"{:.0}\" viewBox=\"0 0 {:.0} {:.0}\" role=\"img\">\n",
        LINE_W, LINE_H, LINE_W, LINE_H
    ));
    s.push_str(&format!("  <title>{}</title>\n", title));
    s.push_str("  <style>\n");
    s.push_str("    .bg { fill: #fbf8f1; }\n");
    s.push_str("    .grid { stroke: #c9c2b7; stroke-width: 1; fill: none; }\n");
    s.push_str("    .axis { stroke: #6b6257; stroke-width: 1.5; fill: none; }\n");
    s.push_str("    .label { fill: #342f29; font: 11px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("    .small { fill: #6b6257; font: 10px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("    .title { fill: #342f29; font: bold 13px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("  </style>\n");
    s.push_str(&format!(
        "  <rect class=\"bg\" x=\"0\" y=\"0\" width=\"{:.0}\" height=\"{:.0}\" rx=\"12\" />\n",
        LINE_W, LINE_H
    ));
    // Plot frame.
    s.push_str(&format!(
        "  <line class=\"axis\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
        plot_x0, plot_y1, plot_x1, plot_y1
    ));
    s.push_str(&format!(
        "  <line class=\"axis\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
        plot_x0, plot_y0, plot_x0, plot_y1
    ));
    // Y gridlines + tick labels at each decade.
    let mut decade = ymin;
    while decade <= ymax + 0.001 {
        let y = map_y(decade);
        s.push_str(&format!(
            "  <line class=\"grid\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
            plot_x0, y, plot_x1, y
        ));
        s.push_str(&format!(
            "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>\n",
            plot_x0 - 6.0,
            y + 3.0,
            human_ns(decade as u128)
        ));
        decade *= 10.0;
    }
    // X tick labels: pick from first series' x_labels.
    if let Some((_, _, pts)) = series.first() {
        for (lbl, xv, _) in pts {
            let x = map_x(*xv);
            s.push_str(&format!(
                "  <line class=\"grid\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
                x, plot_y0, x, plot_y1
            ));
            s.push_str(&format!(
                "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>\n",
                x,
                plot_y1 + 14.0,
                lbl
            ));
        }
    }
    // Series.
    for (label, color, pts) in series {
        let path: String = pts
            .iter()
            .enumerate()
            .map(|(i, (_, xv, yv))| {
                let cmd = if i == 0 { "M" } else { "L" };
                format!("{} {:.1} {:.1}", cmd, map_x(*xv), map_y(*yv))
            })
            .collect::<Vec<_>>()
            .join(" ");
        s.push_str(&format!(
            "  <path d=\"{}\" stroke=\"{}\" stroke-width=\"2\" fill=\"none\" />\n",
            path, color
        ));
        for (_, xv, yv) in pts {
            s.push_str(&format!(
                "  <circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"3.5\" fill=\"{}\" />\n",
                map_x(*xv),
                map_y(*yv),
                color
            ));
        }
        let _ = label;
    }
    // Title + axis labels.
    s.push_str(&format!(
        "  <text class=\"title\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
        plot_x0, plot_y0 - 30.0, title
    ));
    s.push_str(&format!(
        "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
        plot_x0, plot_y0 - 14.0, subtitle
    ));
    s.push_str(&format!(
        "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>\n",
        (plot_x0 + plot_x1) / 2.0,
        plot_y1 + 32.0,
        x_axis_label
    ));
    s.push_str(&format!(
        "  <text class=\"small\" x=\"20\" y=\"{:.1}\" transform=\"rotate(-90 20 {:.1})\" text-anchor=\"middle\">latency (log scale)</text>\n",
        (plot_y0 + plot_y1) / 2.0,
        (plot_y0 + plot_y1) / 2.0,
    ));
    // Legend.
    let mut lx = plot_x0;
    let ly = LINE_H - 22.0;
    for (label, color, _) in series {
        s.push_str(&format!(
            "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"12\" height=\"12\" fill=\"{}\" rx=\"2\" />\n",
            lx, ly, color
        ));
        s.push_str(&format!(
            "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
            lx + 18.0,
            ly + 10.0,
            label
        ));
        lx += 28.0 + 8.0 * (label.len() as f64);
    }
    s.push_str("</svg>\n");
    s
}

/// Build a horizontal bar chart with two bars per row (for cold vs warm).
/// `rows = (label, cold_ns, warm_ns)`.
fn build_bar_svg(title: &str, subtitle: &str, rows: &[(String, u128, u128)]) -> String {
    let n = rows.len() as f64;
    let row_h = 30.0;
    let bar_h = 11.0;
    let plot_x0 = 130.0;
    let plot_x1 = 600.0;
    let plot_w = plot_x1 - plot_x0;
    let plot_y0 = 60.0;
    let height = plot_y0 + n * row_h + 70.0;

    let max_ns: u128 = rows
        .iter()
        .flat_map(|(_, c, w)| [*c, *w])
        .max()
        .unwrap_or(1)
        .max(1);
    // Log scale: clamp min at 100ns.
    let min_ns_f = 100.0_f64;
    let max_ns_f = max_ns as f64;
    let ymax = 10f64.powf(max_ns_f.log10().ceil());
    let map_w = |ns: u128| -> f64 {
        let v = (ns as f64).max(min_ns_f);
        let span = (ymax / min_ns_f).log10();
        plot_w * (v / min_ns_f).log10() / span
    };

    let mut s = String::new();
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"640\" height=\"{:.0}\" viewBox=\"0 0 640 {:.0}\" role=\"img\">\n",
        height, height
    ));
    s.push_str(&format!("  <title>{}</title>\n", title));
    s.push_str("  <style>\n");
    s.push_str("    .bg { fill: #fbf8f1; }\n");
    s.push_str("    .grid { stroke: #c9c2b7; stroke-width: 1; }\n");
    s.push_str("    .label { fill: #342f29; font: 11px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("    .small { fill: #6b6257; font: 10px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("    .title { fill: #342f29; font: bold 13px ui-sans-serif, -apple-system, sans-serif; }\n");
    s.push_str("  </style>\n");
    s.push_str(&format!(
        "  <rect class=\"bg\" x=\"0\" y=\"0\" width=\"640\" height=\"{:.0}\" rx=\"12\" />\n",
        height
    ));
    s.push_str(&format!(
        "  <text class=\"title\" x=\"20\" y=\"30\">{}</text>\n",
        title
    ));
    s.push_str(&format!(
        "  <text class=\"small\" x=\"20\" y=\"46\">{}</text>\n",
        subtitle
    ));
    // Decade gridlines on the x-axis.
    let mut decade = min_ns_f;
    while decade <= ymax + 0.001 {
        let x = plot_x0 + map_w(decade as u128);
        s.push_str(&format!(
            "  <line class=\"grid\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" />\n",
            x,
            plot_y0,
            x,
            plot_y0 + n * row_h + 4.0
        ));
        s.push_str(&format!(
            "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>\n",
            x,
            plot_y0 + n * row_h + 18.0,
            human_ns(decade as u128)
        ));
        decade *= 10.0;
    }
    for (i, (label, cold_ns, warm_ns)) in rows.iter().enumerate() {
        let y_top = plot_y0 + (i as f64) * row_h;
        // Label.
        s.push_str(&format!(
            "  <text class=\"label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>\n",
            plot_x0 - 8.0,
            y_top + bar_h + 5.0,
            label
        ));
        // Cold bar (top).
        s.push_str(&format!(
            "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"#b91c1c\" rx=\"2\" />\n",
            plot_x0,
            y_top,
            map_w(*cold_ns).max(1.0),
            bar_h
        ));
        // Warm bar (bottom).
        s.push_str(&format!(
            "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"#0f766e\" rx=\"2\" />\n",
            plot_x0,
            y_top + bar_h + 1.0,
            map_w(*warm_ns).max(1.0),
            bar_h
        ));
        // Ratio annotation (cold / warm).
        if *warm_ns > 0 {
            let ratio = (*cold_ns as f64) / (*warm_ns as f64);
            s.push_str(&format!(
                "  <text class=\"small\" x=\"{:.1}\" y=\"{:.1}\">cold/warm = {:.1}×</text>\n",
                plot_x0 + map_w(*cold_ns).max(1.0) + 8.0,
                y_top + bar_h + 5.0,
                ratio
            ));
        }
    }
    // Legend.
    let ly = plot_y0 + n * row_h + 38.0;
    s.push_str(&format!(
        "  <rect x=\"20\" y=\"{:.1}\" width=\"12\" height=\"12\" fill=\"#b91c1c\" rx=\"2\" /><text class=\"small\" x=\"38\" y=\"{:.1}\">cold (first call)</text>\n",
        ly,
        ly + 10.0
    ));
    s.push_str(&format!(
        "  <rect x=\"160\" y=\"{:.1}\" width=\"12\" height=\"12\" fill=\"#0f766e\" rx=\"2\" /><text class=\"small\" x=\"178\" y=\"{:.1}\">warm median</text>\n",
        ly,
        ly + 10.0
    ));
    s.push_str("</svg>\n");
    s
}

fn print_vss_table(results: &[Result]) {
    let in_family: Vec<&Result> = results
        .iter()
        .filter(|r| matches!(r.family, Family::Vss))
        .collect();
    if in_family.is_empty() {
        return;
    }
    println!("\n## VSS family — split / reconstruct (k=3, n=5)\n");
    println!(
        "Two schemes only (`vss`, `cgma_vss`). A radar with two axes \
         degenerates to a line; the table is the honest format here."
    );
    println!();
    println!(
        "| Scheme | op | 128-bit | 256-bit | 512-bit | 1024-bit |"
    );
    println!(
        "|--------|----|---------|---------|---------|----------|"
    );
    for r in &in_family {
        println!(
            "| `{}` | split       | {} | {} | {} | {} |",
            r.scheme,
            human_ns(r.splits[0]),
            human_ns(r.splits[1]),
            human_ns(r.splits[2]),
            human_ns(r.splits[3]),
        );
        println!(
            "| `{}` | reconstruct | {} | {} | {} | {} |",
            r.scheme,
            human_ns(r.recons[0]),
            human_ns(r.recons[1]),
            human_ns(r.recons[2]),
            human_ns(r.recons[3]),
        );
    }
    println!();
    println!(
        "Caveat: `cgma_vss` columns are constant because the bench \
         uses the fixed RFC 5114 §2.3 (2048/256) Schnorr group at \
         every secret-bit setting. For the actual scaling with group \
         size, see the `cgma-vss-scaling` chart and table below."
    );
}

fn print_scaling_table(title: &str, points: &[ScalingPoint]) {
    println!("\n## {title}\n");
    println!("| Parameter | split | reconstruct |");
    println!("|-----------|-------|-------------|");
    for p in points {
        println!(
            "| `{}` | {} | {} |",
            p.x_label,
            human_ns(p.split_ns),
            human_ns(p.recon_ns)
        );
    }
}

fn print_cold_table(rows: &[ColdResult]) {
    println!("\n## Cold-cache vs warm median (first call vs 200-iter median)\n");
    println!("| Scheme | cold split | warm split | cold recon | warm recon | cold/warm split | cold/warm recon |");
    println!("|--------|-----------|-----------|-----------|-----------|----------------|----------------|");
    for r in rows {
        let s_ratio = if r.warm_split_ns == 0 {
            "—".to_string()
        } else {
            format!("{:.1}×", r.cold_split_ns as f64 / r.warm_split_ns as f64)
        };
        let r_ratio = if r.warm_recon_ns == 0 {
            "—".to_string()
        } else {
            format!("{:.1}×", r.cold_recon_ns as f64 / r.warm_recon_ns as f64)
        };
        println!(
            "| `{}` | {} | {} | {} | {} | {} | {} |",
            r.scheme,
            human_ns(r.cold_split_ns),
            human_ns(r.warm_split_ns),
            human_ns(r.cold_recon_ns),
            human_ns(r.warm_recon_ns),
            s_ratio,
            r_ratio,
        );
    }
}

fn emit_scaling_line_svg(
    title: &str,
    subtitle: &str,
    x_axis_label: &str,
    points: &[ScalingPoint],
    file: &str,
) -> std::io::Result<()> {
    let split_pts: Vec<(String, f64, f64)> = points
        .iter()
        .map(|p| (p.x_label.clone(), p.x_value, p.split_ns as f64))
        .collect();
    let recon_pts: Vec<(String, f64, f64)> = points
        .iter()
        .map(|p| (p.x_label.clone(), p.x_value, p.recon_ns as f64))
        .collect();
    let series = [
        ("split", "#0f766e", split_pts),
        ("reconstruct", "#1d4ed8", recon_pts),
    ];
    let svg = build_line_svg(title, subtitle, x_axis_label, &series);
    std::fs::write(file, svg)?;
    eprintln!("wrote {file}");
    Ok(())
}

fn emit_cold_bar_svg(rows: &[ColdResult], file: &str) -> std::io::Result<()> {
    // Two SVGs would be cleaner, but the cold/warm comparison reads
    // best as one chart per operation. Use split first.
    let split_rows: Vec<(String, u128, u128)> = rows
        .iter()
        .map(|r| (r.scheme.to_string(), r.cold_split_ns, r.warm_split_ns))
        .collect();
    let svg = build_bar_svg(
        "Cold-cache vs warm median (split, 128-bit field)",
        "First-iteration latency in red, 200-iteration warm median in teal; log x-axis",
        &split_rows,
    );
    std::fs::write(file, svg)?;
    eprintln!("wrote {file}");
    Ok(())
}

fn emit_cold_recon_bar_svg(rows: &[ColdResult], file: &str) -> std::io::Result<()> {
    let recon_rows: Vec<(String, u128, u128)> = rows
        .iter()
        .map(|r| (r.scheme.to_string(), r.cold_recon_ns, r.warm_recon_ns))
        .collect();
    let svg = build_bar_svg(
        "Cold-cache vs warm median (reconstruct, 128-bit field)",
        "First-iteration latency in red, 200-iteration warm median in teal; log x-axis",
        &recon_rows,
    );
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
    // The VSS family has only two schemes (vss + cgma_vss), so a
    // radar would degenerate to a 2-axis bowtie that conveys no
    // shape. Emit a Markdown table to PERFORMANCE.md instead.
    print_vss_table(&results);
    emit_family_svg(
        Family::Other,
        "Other schemes",
        "assets/other-throughput-radar.svg",
        &results,
    )?;

    // ── Non-radar dimensions ───────────────────────────────────────
    eprintln!("\nbenching non-radar dimensions...");

    eprintln!("  Mignotte by legal-range bit width...");
    let mignotte_pts = bench_mignotte_scaling();
    print_scaling_table("Mignotte by legal-range bit width (k=3, n=5)", &mignotte_pts);
    emit_scaling_line_svg(
        "Mignotte: latency vs legal-range bit width",
        "k=3, n=5; secret picked just inside (α, β); log y, linear x in bits",
        "approximate β bit width",
        &mignotte_pts,
        "assets/mignotte-scaling.svg",
    )?;

    eprintln!("  Asmuth-Bloom by m_0 bit width...");
    let ab_pts = bench_asmuth_bloom_scaling();
    print_scaling_table("Asmuth-Bloom by m_0 bit width (k=3, n=5)", &ab_pts);
    emit_scaling_line_svg(
        "Asmuth-Bloom: latency vs m_0 bit width",
        "k=3, n=5; secret = 1 mod m_0; log y, linear x in bits",
        "m_0 bit width",
        &ab_pts,
        "assets/asmuth-bloom-scaling.svg",
    )?;

    eprintln!("  Visual cryptography by n (8×8 image)...");
    let vis_n = bench_visual_by_n();
    print_scaling_table("Visual cryptography by n (8×8 image)", &vis_n);
    emit_scaling_line_svg(
        "Visual cryptography (n, n): latency vs n",
        "8×8 secret image; per-pixel expansion = 2^(n-1)",
        "n (number of shares = threshold)",
        &vis_n,
        "assets/visual-by-n.svg",
    )?;

    eprintln!("  Visual cryptography by image size (n=3)...");
    let vis_pix = bench_visual_by_pixels();
    print_scaling_table("Visual cryptography by pixel count (n=3)", &vis_pix);
    emit_scaling_line_svg(
        "Visual cryptography (3, 3): latency vs image area",
        "fixed n=3; image scales W×H from 4×4 to 64×64",
        "image area (pixels, label = side×side)",
        &vis_pix,
        "assets/visual-by-pixels.svg",
    )?;

    eprintln!("  CGMA-VSS by Schnorr group bit width...");
    let cgma_pts = bench_cgma_vss_by_group();
    print_scaling_table("CGMA-VSS by Schnorr group bit width (k=3, n=5)", &cgma_pts);
    emit_scaling_line_svg(
        "CGMA-VSS: latency vs Schnorr group bit width",
        "k=3, n=5; toy (23) → small (167) → 1024-bit OAKLEY group 2 → 2048-bit RFC 5114 §2.3",
        "Schnorr prime p bit width",
        &cgma_pts,
        "assets/cgma-vss-scaling.svg",
    )?;

    eprintln!("  Cold-cache (first-iteration latency)...");
    let cold = bench_cold_cache(&fields, &results);
    print_cold_table(&cold);
    emit_cold_bar_svg(&cold, "assets/cold-cache-split.svg")?;
    emit_cold_recon_bar_svg(&cold, "assets/cold-cache-reconstruct.svg")?;

    Ok(())
}
