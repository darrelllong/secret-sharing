//! Per-operation latency benchmark for pilot-bench.
//!
//! Usage: `pilot_ss <operation>` — runs the named operation N times
//! (scaled by `PILOT_SS_ITERS_PERCENT`, default 25) and prints
//! `ms/op` to stdout in CSV form so pilot-bench can read it as the
//! single performance index. Pilot-bench drives this binary
//! repeatedly until the requested confidence-interval width is
//! reached; see `scripts/bench_pilot.sh`.
//!
//! Operations available — every scheme in the crate at a fixed
//! representative parameterisation:
//!
//! Threshold (k=3, n=5, Mersenne-127 unless noted):
//!   shamir_split, shamir_reconstruct
//!   blakley_split, blakley_reconstruct
//!   kothari_split, kothari_reconstruct
//!   karchmer_wigderson_split, karchmer_wigderson_reconstruct
//!   brickell_split, brickell_reconstruct
//!   massey_split, massey_reconstruct
//!
//! Ramp / vector (k=3, n=5):
//!   ramp_split, ramp_reconstruct
//!   yamamoto_split, yamamoto_reconstruct
//!   blakley_meadows_split, blakley_meadows_reconstruct
//!   kgh_split, kgh_reconstruct
//!
//! VSS:
//!   vss_split, vss_reconstruct
//!   cgma_vss_split, cgma_vss_reconstruct  (RFC 5114 §2.3 — 2048-bit p, 256-bit q)
//!
//! CRT (small example sequences):
//!   mignotte_split, mignotte_reconstruct
//!   asmuth_bloom_split, asmuth_bloom_reconstruct
//!
//! Other:
//!   trivial_split, trivial_reconstruct
//!   ito_split, ito_reconstruct
//!   benaloh_leichter_split, benaloh_leichter_reconstruct
//!   proactive_refresh, proactive_recover
//!   bytes_split_16, bytes_reconstruct_16  (16-byte secret)
//!   ida_split_16, ida_reconstruct_16
//!   decode_reconstruct_t1                 (n=11, t=1, Berlekamp-Welch)
//!   visual_split_3_8, visual_decode_3_8   (n=3, 8x8 image)

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use secret_sharing::{
    asmuth_bloom, benaloh_leichter as bl, blakley, blakley_meadows, brickell, bytes, cgma_vss,
    csprng::{Csprng, OsRng},
    decode::reconstruct_with_errors,
    field::{mersenne127, PrimeField},
    ida, ito, karchmer_wigderson as kw, kgh, kothari, massey, mignotte, proactive, ramp, shamir,
    trivial, visual, vss, yamamoto, BigUint, ChaCha20Rng,
};

const K: usize = 3;
const N: usize = 5;

fn ms_per_op(elapsed: std::time::Duration, n: usize) -> f64 {
    elapsed.as_secs_f64() * 1000.0 / n as f64
}

fn iters(base: usize) -> usize {
    static SCALE_PERCENT: OnceLock<usize> = OnceLock::new();
    let scale = *SCALE_PERCENT.get_or_init(|| {
        std::env::var("PILOT_SS_ITERS_PERCENT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .map(|v| v.clamp(1, 100))
            .unwrap_or(25)
    });
    base.saturating_mul(scale).div_ceil(100).max(1)
}

fn rng() -> ChaCha20Rng {
    // Production seeding via OsRng; the bench is not measuring
    // throughput where ChaCha20 startup dominates, so seeding once
    // per pilot-bench round is fine.
    let mut os = OsRng::new().expect("/dev/urandom");
    ChaCha20Rng::from_os_entropy(&mut os)
}

fn field() -> PrimeField {
    PrimeField::new_unchecked(mersenne127())
}

// 4 KiB block experiment: chunk 4096 bytes into 15-byte pieces (120 bits,
// safely under the Mersenne-127 modulus 2^127 − 1). Each `*_4kb` op
// processes ⌈4096 / 15⌉ = 274 chunks per call so its ms/op number is the
// per-block latency for a 4 KiB secret.
const SECRET_BYTES: usize = 4096;
const CHUNK_BYTES: usize = 15;

fn chunks_4kb(rng: &mut ChaCha20Rng) -> Vec<BigUint> {
    let mut bytes = vec![0u8; SECRET_BYTES];
    rng.fill_bytes(&mut bytes);
    let n_chunks = SECRET_BYTES.div_ceil(CHUNK_BYTES);
    (0..n_chunks)
        .map(|i| {
            let start = i * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(SECRET_BYTES);
            BigUint::from_be_bytes(&bytes[start..end])
        })
        .collect()
}

/// Build a (3, 5)-Mignotte sequence with 130-bit moduli — above
/// `CRT_PRECOMP_THRESHOLD_BITS` so reconstruct exercises the
/// pairwise-inverse precomp branch. Deterministic seed makes the
/// sequence reproducible across runs.
fn build_large_mignotte_3_of_5() -> mignotte::MignotteSequence {
    use secret_sharing::primes::{is_probable_prime, random_below};
    let mut rng = ChaCha20Rng::from_seed(&[0xA1u8; 32]);
    let mut lo = BigUint::one();
    lo.shl_bits(130);
    let mut span = BigUint::one();
    span.shl_bits(130);
    let mut found: Vec<BigUint> = Vec::new();
    while found.len() < 5 {
        let mut candidate = random_below(&mut rng, &span).expect("span > 0");
        candidate = candidate.add_ref(&lo);
        if !candidate.is_odd() {
            continue;
        }
        if is_probable_prime(&candidate) && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    found.sort();
    mignotte::MignotteSequence::new(found, 3).expect("valid 130-bit sequence")
}

fn main() {
    let op = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pilot_ss <operation>");
        std::process::exit(1);
    });

    let ms: f64 = match op.as_str() {
        "shamir_split" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(shamir::split(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "shamir_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = shamir::split(&f, &mut r, &s, K, N);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(shamir::reconstruct(&f, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_split" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(blakley::split(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = blakley::split(&f, &mut r, &s, K, N);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(blakley::reconstruct(&f, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kothari_split" => {
            let scheme = kothari::vandermonde(field(), K, N);
            let mut r = rng();
            let s = scheme.field().random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kothari::split(&scheme, &mut r, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kothari_reconstruct" => {
            let scheme = kothari::vandermonde(field(), K, N);
            let mut r = rng();
            let s = scheme.field().random(&mut r);
            let shares = kothari::split(&scheme, &mut r, &s);
            let pairs: Vec<(usize, BigUint)> = (0..K).map(|c| (c, shares[c].clone())).collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kothari::reconstruct(&scheme, &pairs).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "karchmer_wigderson_split" => {
            let prog = kw::threshold_msp(field(), K, N);
            let mut r = rng();
            let s = prog.field().random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kw::split(&prog, &mut r, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "karchmer_wigderson_reconstruct" => {
            let prog = kw::threshold_msp(field(), K, N);
            let mut r = rng();
            let s = prog.field().random(&mut r);
            let shares = kw::split(&prog, &mut r, &s);
            let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kw::reconstruct(&prog, &coalition).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "brickell_split" => {
            let f = field();
            let vectors: Vec<Vec<BigUint>> = (1..=N)
                .map(|j| {
                    let mut row = Vec::with_capacity(K);
                    let mut pow = BigUint::one();
                    let j_val = BigUint::from_u64(j as u64);
                    for _ in 0..K {
                        row.push(pow.clone());
                        pow = f.mul(&pow, &j_val);
                    }
                    row
                })
                .collect();
            let scheme = brickell::Scheme::new(f.clone(), vectors);
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(brickell::split(&scheme, &mut r, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "brickell_reconstruct" => {
            let f = field();
            let vectors: Vec<Vec<BigUint>> = (1..=N)
                .map(|j| {
                    let mut row = Vec::with_capacity(K);
                    let mut pow = BigUint::one();
                    let j_val = BigUint::from_u64(j as u64);
                    for _ in 0..K {
                        row.push(pow.clone());
                        pow = f.mul(&pow, &j_val);
                    }
                    row
                })
                .collect();
            let scheme = brickell::Scheme::new(f.clone(), vectors);
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = brickell::split(&scheme, &mut r, &s);
            let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(brickell::reconstruct(&scheme, &coalition).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "massey_split" => {
            let f = field();
            let mut g = vec![vec![BigUint::one(); N + 1], vec![BigUint::zero(); N + 1]];
            #[allow(clippy::needless_range_loop)]
            for j in 1..=N {
                g[1][j] = BigUint::from_u64(j as u64);
            }
            let scheme = massey::CodeScheme::new(f.clone(), g);
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(massey::split(&scheme, &mut r, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "massey_reconstruct" => {
            let f = field();
            let mut g = vec![vec![BigUint::one(); N + 1], vec![BigUint::zero(); N + 1]];
            #[allow(clippy::needless_range_loop)]
            for j in 1..=N {
                g[1][j] = BigUint::from_u64(j as u64);
            }
            let scheme = massey::CodeScheme::new(f.clone(), g);
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = massey::split(&scheme, &mut r, &s);
            let coalition: Vec<_> = shares.iter().take(2).cloned().collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(massey::reconstruct(&scheme, &coalition).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ramp_split" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ramp::split(&f, &s, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ramp_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let shares = ramp::split(&f, &s, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ramp::reconstruct(&f, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "yamamoto_split" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(yamamoto::split(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "yamamoto_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let shares = yamamoto::split(&f, &mut r, &s, K, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(yamamoto::reconstruct(&f, &shares[..K], K, K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_meadows_split" => {
            let f = field();
            let mut r = rng();
            let l = K - 1;
            let s: Vec<BigUint> = (0..l).map(|_| f.random(&mut r)).collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(blakley_meadows::split(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_meadows_reconstruct" => {
            let f = field();
            let mut r = rng();
            let l = K - 1;
            let s: Vec<BigUint> = (0..l).map(|_| f.random(&mut r)).collect();
            let shares = blakley_meadows::split(&f, &mut r, &s, K, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(blakley_meadows::reconstruct(&f, &shares[..K], K, l).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kgh_split" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kgh::split(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kgh_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s: Vec<BigUint> = (0..K).map(|_| f.random(&mut r)).collect();
            let shares = kgh::split(&f, &mut r, &s, K, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(kgh::reconstruct(&f, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "vss_split" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(vss::deal(&f, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "vss_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = vss::deal(&f, &mut r, &s, K, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(vss::reconstruct(&f, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "cgma_vss_split" => {
            let group = cgma_vss::rfc5114_modp_2048_256();
            let mut r = rng();
            let s = BigUint::from_u64(0x1234_5678_9abc_def0); // < q (256-bit)
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(cgma_vss::deal(&group, &mut r, &s, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "cgma_vss_reconstruct" => {
            let group = cgma_vss::rfc5114_modp_2048_256();
            let mut r = rng();
            let s = BigUint::from_u64(0x1234_5678_9abc_def0);
            let (shares, commits) = cgma_vss::deal(&group, &mut r, &s, K, N);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for sh in &shares {
                    black_box(cgma_vss::verify_share(&group, &commits, sh));
                }
                black_box(cgma_vss::reconstruct(&group, &shares[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "mignotte_split" => {
            let seq = mignotte::small_example_3_of_5();
            let s = seq.alpha().add_ref(&BigUint::from_u64(1));
            let n_iter = iters(5000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(mignotte::split(&seq, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "mignotte_reconstruct" => {
            let seq = mignotte::small_example_3_of_5();
            let s = seq.alpha().add_ref(&BigUint::from_u64(1));
            let shares = mignotte::split(&seq, &s);
            let n_iter = iters(5000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(mignotte::reconstruct(&seq, &shares[..K]).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "mignotte_reconstruct_large" => {
            // 130-bit moduli — above CRT_PRECOMP_THRESHOLD_BITS, so
            // reconstruct exercises the precomp branch. The sequence
            // is built deterministically from a fixed CSPRNG seed
            // for reproducibility.
            let seq = build_large_mignotte_3_of_5();
            let s = seq.alpha().add_ref(&BigUint::from_u64(1));
            let shares = mignotte::split(&seq, &s);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(mignotte::reconstruct(&seq, &shares[..K]).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "asmuth_bloom_split" => {
            let params = asmuth_bloom::small_example_3_of_5();
            let mut r = rng();
            let s = BigUint::from_u64(1);
            let n_iter = iters(5000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(asmuth_bloom::split(&params, &mut r, &s));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "asmuth_bloom_reconstruct" => {
            let params = asmuth_bloom::small_example_3_of_5();
            let mut r = rng();
            let s = BigUint::from_u64(1);
            let shares = asmuth_bloom::split(&params, &mut r, &s);
            let n_iter = iters(5000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(asmuth_bloom::reconstruct(&params, &shares[..K]).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "trivial_split" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(10_000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(trivial::split(&f, &mut r, &s, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "trivial_reconstruct" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = trivial::split(&f, &mut r, &s, N);
            let n_iter = iters(20_000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(trivial::reconstruct(&f, &shares));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ito_split" => {
            let f = field();
            let structure = ito::threshold_access_structure(N, K);
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(5000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ito::split(&f, &mut r, &s, &structure));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ito_reconstruct" => {
            let f = field();
            let structure = ito::threshold_access_structure(N, K);
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = ito::split(&f, &mut r, &s, &structure);
            let coalition: Vec<_> = shares.iter().take(K).cloned().collect();
            let n_iter = iters(10_000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ito::reconstruct(&f, &structure, &coalition).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "benaloh_leichter_split" => {
            let f = field();
            let formula = bl::Formula::or(vec![
                bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(2)]),
                bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(3)]),
                bl::Formula::and(vec![bl::Formula::party(2), bl::Formula::party(3)]),
            ]);
            let mut r = rng();
            let s = f.random(&mut r);
            let n_iter = iters(20_000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(bl::split(&f, &mut r, &s, &formula));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "benaloh_leichter_reconstruct" => {
            let f = field();
            let formula = bl::Formula::or(vec![
                bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(2)]),
                bl::Formula::and(vec![bl::Formula::party(1), bl::Formula::party(3)]),
                bl::Formula::and(vec![bl::Formula::party(2), bl::Formula::party(3)]),
            ]);
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = bl::split(&f, &mut r, &s, &formula);
            let pair: Vec<_> = shares.iter().take(2).cloned().collect();
            let n_iter = iters(20_000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(bl::reconstruct(&f, &formula, &pair).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "proactive_refresh" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = shamir::split(&f, &mut r, &s, K, N);
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(proactive::refresh(&f, &mut r, &shares, K));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "proactive_recover" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let shares = shamir::split(&f, &mut r, &s, K, N);
            let live = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
            let lost_x = shares[2].x.clone();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(proactive::recover_share(&f, &live, K, &lost_x).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "bytes_split_16" => {
            let f = field();
            let mut r = rng();
            let secret = vec![0xC3u8; 16];
            let n_iter = iters(1000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(bytes::split(&f, &mut r, &secret, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "bytes_reconstruct_16" => {
            let f = field();
            let mut r = rng();
            let secret = vec![0xC3u8; 16];
            let shares = bytes::split(&f, &mut r, &secret, K, N);
            let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
            let n_iter = iters(1000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(bytes::reconstruct(&f, &refs[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ida_split_16" => {
            let f = field();
            let data = vec![0x5Au8; 16];
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ida::split(&f, &data, K, N));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "ida_reconstruct_16" => {
            let f = field();
            let data = vec![0x5Au8; 16];
            let shares = ida::split(&f, &data, K, N);
            let refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(ida::reconstruct(&f, &refs[..K], K).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "decode_reconstruct_t1" => {
            let f = field();
            let mut r = rng();
            let s = f.random(&mut r);
            let mut shares = shamir::split(&f, &mut r, &s, K, 11);
            shares[3].y = f.add(&shares[3].y, &BigUint::from_u64(1));
            let n_iter = iters(200);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(reconstruct_with_errors(&f, &shares, K, 1).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "visual_split_3_8" => {
            let mut r = rng();
            let secret: Vec<Vec<bool>> = (0..8)
                .map(|y| (0..8).map(|x| (x + y) % 2 == 0).collect())
                .collect();
            let n_iter = iters(500);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                black_box(visual::split_n_of_n(&mut r, &secret, 3));
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "visual_decode_3_8" => {
            let mut r = rng();
            let secret: Vec<Vec<bool>> = (0..8)
                .map(|y| (0..8).map(|x| (x + y) % 2 == 0).collect())
                .collect();
            let shares = visual::split_n_of_n(&mut r, &secret, 3);
            let n_iter = iters(2000);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                let stacked = visual::stack(&shares).unwrap();
                black_box(visual::decode(&stacked, 3).unwrap());
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "shamir_split_4kb" => {
            let f = field();
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(shamir::split(&f, &mut r, s, K, N));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "shamir_reconstruct_4kb" => {
            let f = field();
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let share_chunks: Vec<Vec<shamir::Share>> = chunks
                .iter()
                .map(|s| shamir::split(&f, &mut r, s, K, N))
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for shares in &share_chunks {
                    black_box(shamir::reconstruct(&f, &shares[..K], K).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_split_4kb" => {
            let f = field();
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(blakley::split(&f, &mut r, s, K, N));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "blakley_reconstruct_4kb" => {
            let f = field();
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let share_chunks: Vec<_> = chunks
                .iter()
                .map(|s| blakley::split(&f, &mut r, s, K, N))
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for shares in &share_chunks {
                    black_box(blakley::reconstruct(&f, &shares[..K], K).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kothari_split_4kb" => {
            let scheme = kothari::vandermonde(field(), K, N);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(kothari::split(&scheme, &mut r, s));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "kothari_reconstruct_4kb" => {
            let scheme = kothari::vandermonde(field(), K, N);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let share_chunks: Vec<Vec<(usize, BigUint)>> = chunks
                .iter()
                .map(|s| {
                    let shares = kothari::split(&scheme, &mut r, s);
                    (0..K).map(|c| (c, shares[c].clone())).collect()
                })
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for pairs in &share_chunks {
                    black_box(kothari::reconstruct(&scheme, pairs).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "karchmer_wigderson_split_4kb" => {
            let prog = kw::threshold_msp(field(), K, N);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(kw::split(&prog, &mut r, s));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "karchmer_wigderson_reconstruct_4kb" => {
            let prog = kw::threshold_msp(field(), K, N);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let coalition_chunks: Vec<Vec<_>> = chunks
                .iter()
                .map(|s| {
                    let shares = kw::split(&prog, &mut r, s);
                    shares.iter().take(K).cloned().collect()
                })
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for coalition in &coalition_chunks {
                    black_box(kw::reconstruct(&prog, coalition).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "brickell_split_4kb" => {
            let f = field();
            let vectors: Vec<Vec<BigUint>> = (1..=N)
                .map(|j| {
                    let mut row = Vec::with_capacity(K);
                    let mut pow = BigUint::one();
                    let j_val = BigUint::from_u64(j as u64);
                    for _ in 0..K {
                        row.push(pow.clone());
                        pow = f.mul(&pow, &j_val);
                    }
                    row
                })
                .collect();
            let scheme = brickell::Scheme::new(f.clone(), vectors);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(brickell::split(&scheme, &mut r, s));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "brickell_reconstruct_4kb" => {
            let f = field();
            let vectors: Vec<Vec<BigUint>> = (1..=N)
                .map(|j| {
                    let mut row = Vec::with_capacity(K);
                    let mut pow = BigUint::one();
                    let j_val = BigUint::from_u64(j as u64);
                    for _ in 0..K {
                        row.push(pow.clone());
                        pow = f.mul(&pow, &j_val);
                    }
                    row
                })
                .collect();
            let scheme = brickell::Scheme::new(f.clone(), vectors);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let coalition_chunks: Vec<Vec<_>> = chunks
                .iter()
                .map(|s| {
                    let shares = brickell::split(&scheme, &mut r, s);
                    shares.iter().take(K).cloned().collect()
                })
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for coalition in &coalition_chunks {
                    black_box(brickell::reconstruct(&scheme, coalition).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "massey_split_4kb" => {
            let f = field();
            let mut g = vec![vec![BigUint::one(); N + 1], vec![BigUint::zero(); N + 1]];
            #[allow(clippy::needless_range_loop)]
            for j in 1..=N {
                g[1][j] = BigUint::from_u64(j as u64);
            }
            let scheme = massey::CodeScheme::new(f.clone(), g);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for s in &chunks {
                    black_box(massey::split(&scheme, &mut r, s));
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        "massey_reconstruct_4kb" => {
            let f = field();
            let mut g = vec![vec![BigUint::one(); N + 1], vec![BigUint::zero(); N + 1]];
            #[allow(clippy::needless_range_loop)]
            for j in 1..=N {
                g[1][j] = BigUint::from_u64(j as u64);
            }
            let scheme = massey::CodeScheme::new(f.clone(), g);
            let mut r = rng();
            let chunks = chunks_4kb(&mut r);
            let coalition_chunks: Vec<Vec<_>> = chunks
                .iter()
                .map(|s| {
                    let shares = massey::split(&scheme, &mut r, s);
                    shares.iter().take(2).cloned().collect()
                })
                .collect();
            let n_iter = iters(20);
            let t0 = Instant::now();
            for _ in 0..n_iter {
                for coalition in &coalition_chunks {
                    black_box(massey::reconstruct(&scheme, coalition).unwrap());
                }
            }
            ms_per_op(t0.elapsed(), n_iter)
        }
        other => {
            eprintln!("unknown operation: {other}");
            std::process::exit(2);
        }
    };

    // Pilot-bench reads CSV from stdout: column 0 is the PI value.
    println!("{ms}");
}
