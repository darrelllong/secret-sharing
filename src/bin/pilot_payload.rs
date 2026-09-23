//! Pilot input: latency in ms for one complete 64-byte or 1 KiB payload.
//! Setup, input encoding and a checked round trip happen before timing.
use secret_sharing::{
    asmuth_bloom, benaloh_leichter as bl, blakley, blakley_meadows, brickell, bytes, cgma_vss, ida,
    ito, karchmer_wigderson as kw, kgh, kothari, massey, mignotte, ramp, shamir, trivial, visual,
    vss, yamamoto, BigUint, ChaCha20Rng, PrimeField,
};
use std::fmt::Debug;
use std::hint::black_box;
use std::time::{Duration, Instant};
const K: usize = 3;
const N: usize = 5;

fn measure<S: PartialEq + Debug, C>(
    secrets: &[S],
    reconstruct: bool,
    mut split: impl FnMut(&S) -> C,
    recover: impl Fn(&C) -> S,
) -> f64 {
    let shares: Vec<_> = secrets.iter().map(&mut split).collect();
    for (secret, share) in secrets.iter().zip(&shares) {
        assert_eq!(&recover(share), secret, "round trip before timing");
    }
    let duration = Duration::from_millis(
        std::env::var("PILOT_PAYLOAD_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20),
    );
    let start = Instant::now();
    let mut count = 0u64;
    loop {
        if reconstruct {
            for share in &shares {
                black_box(recover(black_box(share)));
            }
        } else {
            for secret in secrets {
                black_box(split(black_box(secret)));
            }
        }
        count += 1;
        if start.elapsed() >= duration {
            break;
        }
    }
    start.elapsed().as_secs_f64() * 1000.0 / count as f64
}

fn chunks(data: &[u8], width: usize) -> Vec<BigUint> {
    data.chunks(width).map(BigUint::from_be_bytes).collect()
}
fn vectors(values: &[BigUint], width: usize) -> Vec<Vec<BigUint>> {
    values
        .chunks(width)
        .map(|part| {
            let mut v = part.to_vec();
            v.resize(width, BigUint::zero());
            v
        })
        .collect()
}
// Nearby 131-bit primes satisfy the (3,5) CRT bounds with a 127-bit m0.
fn crt_moduli() -> Vec<BigUint> {
    let mut candidate = BigUint::one();
    candidate.shl_bits(130);
    candidate = candidate.add_ref(&BigUint::one());
    let mut moduli = Vec::new();
    while moduli.len() < N {
        if secret_sharing::primes::is_probable_prime(&candidate) {
            moduli.push(candidate.clone());
        }
        candidate = candidate.add_ref(&BigUint::from_u64(2));
    }
    moduli
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: pilot_payload METHOD split|reconstruct 64|1024"
    );
    let reconstruct = match args[2].as_str() {
        "split" => false,
        "reconstruct" => true,
        _ => panic!("unknown phase"),
    };
    let size: usize = args[3].parse().expect("payload size");
    assert!(matches!(size, 64 | 1024));
    // Same non-secret payload and seed in both language drivers.
    let data: Vec<u8> = (0..size)
        .map(|i| (i.wrapping_mul(73).wrapping_add(41)) as u8)
        .collect();
    let f = PrimeField::new_unchecked(secret_sharing::mersenne127());
    let mut rng = ChaCha20Rng::from_seed(&[53; 32]);
    let scalar = chunks(&data, 15);
    let ms = match args[1].as_str() {
        "shamir" => measure(
            &scalar,
            reconstruct,
            |s| shamir::split(&f, &mut rng, s, K, N),
            |s| shamir::reconstruct(&f, &s[..K], K).unwrap(),
        ),
        "blakley" => measure(
            &scalar,
            reconstruct,
            |s| blakley::split(&f, &mut rng, s, K, N),
            |s| blakley::reconstruct(&f, &s[..K], K).unwrap(),
        ),
        "kothari" => {
            let scheme = kothari::vandermonde(f.clone(), K, N);
            measure(
                &scalar,
                reconstruct,
                |s| {
                    kothari::split(&scheme, &mut rng, s)
                        .into_iter()
                        .enumerate()
                        .collect::<Vec<_>>()
                },
                |s| kothari::reconstruct(&scheme, &s[..K]).unwrap(),
            )
        }
        "karchmer_wigderson" => {
            let scheme = kw::threshold_msp(f.clone(), K, N);
            measure(
                &scalar,
                reconstruct,
                |s| kw::split(&scheme, &mut rng, s),
                |s| kw::reconstruct(&scheme, &s[..K]).unwrap(),
            )
        }
        "brickell" => {
            let rows = (1..=N)
                .map(|j| {
                    let x = BigUint::from_u64(j as u64);
                    vec![BigUint::one(), x.clone(), f.mul(&x, &x)]
                })
                .collect();
            let scheme = brickell::Scheme::new(f.clone(), rows);
            measure(
                &scalar,
                reconstruct,
                |s| brickell::split(&scheme, &mut rng, s),
                |s| brickell::reconstruct(&scheme, &s[..K]).unwrap(),
            )
        }
        "massey" => {
            let matrix = (0..K)
                .map(|power| {
                    (0..=N)
                        .map(|j| BigUint::from_u64((j as u64).pow(power as u32)))
                        .collect()
                })
                .collect();
            let scheme = massey::CodeScheme::new(f.clone(), matrix);
            measure(
                &scalar,
                reconstruct,
                |s| massey::split(&scheme, &mut rng, s),
                |s| massey::reconstruct(&scheme, &s[..K]).unwrap(),
            )
        }
        "ramp" => measure(
            &vectors(&scalar, K),
            reconstruct,
            |s| ramp::split(&f, s, N),
            |s| ramp::reconstruct(&f, &s[..K], K).unwrap(),
        ),
        "yamamoto" => measure(
            &vectors(&scalar, K - 1),
            reconstruct,
            |s| yamamoto::split(&f, &mut rng, s, K, N),
            |s| yamamoto::reconstruct(&f, &s[..K], K, K - 1).unwrap(),
        ),
        "blakley_meadows" => measure(
            &vectors(&scalar, K - 1),
            reconstruct,
            |s| blakley_meadows::split(&f, &mut rng, s, K, N),
            |s| blakley_meadows::reconstruct(&f, &s[..K], K, K - 1).unwrap(),
        ),
        "kgh" => measure(
            &vectors(&scalar, K),
            reconstruct,
            |s| kgh::split(&f, &mut rng, s, K, N),
            |s| kgh::reconstruct(&f, &s[..K], K).unwrap(),
        ),
        "vss" => measure(
            &scalar,
            reconstruct,
            |s| vss::deal(&f, &mut rng, s, K, N),
            |s| vss::reconstruct(&f, &s[..K], K).unwrap(),
        ),
        "cgma_vss" => {
            let group = cgma_vss::rfc5114_modp_2048_256();
            measure(
                &chunks(&data, 31),
                reconstruct,
                |s| cgma_vss::deal(&group, &mut rng, s, K, N),
                |(s, commitments)| {
                    for share in &s[..K] {
                        assert!(cgma_vss::verify_share(&group, commitments, share));
                    }
                    cgma_vss::reconstruct(&group, &s[..K], K).unwrap()
                },
            )
        }
        "mignotte" => {
            let seq = mignotte::MignotteSequence::new(crt_moduli(), K).unwrap();
            let base = seq.alpha().add_ref(&BigUint::one());
            let encoded: Vec<_> = scalar.iter().map(|s| base.add_ref(s)).collect();
            measure(
                &encoded,
                reconstruct,
                |s| mignotte::split(&seq, s),
                |s| mignotte::reconstruct(&seq, &s[..K]).unwrap(),
            )
        }
        "asmuth_bloom" => {
            let params = asmuth_bloom::AsmuthBloomParams::new(
                secret_sharing::mersenne127(),
                crt_moduli(),
                K,
            )
            .unwrap();
            measure(
                &scalar,
                reconstruct,
                |s| asmuth_bloom::split(&params, &mut rng, s),
                |s| asmuth_bloom::reconstruct(&params, &s[..K]).unwrap(),
            )
        }
        "trivial" => measure(
            &scalar,
            reconstruct,
            |s| trivial::split(&f, &mut rng, s, N),
            |s| trivial::reconstruct(&f, s),
        ),
        "trivial_xor" => measure(
            std::slice::from_ref(&data),
            reconstruct,
            |s| trivial::split_xor(&mut rng, s, N),
            |s| trivial::reconstruct_xor(s),
        ),
        "ito" => {
            let structure = ito::threshold_access_structure(N, K);
            measure(
                &scalar,
                reconstruct,
                |s| ito::split(&f, &mut rng, s, &structure),
                |s| ito::reconstruct(&f, &structure, &s[..K]).unwrap(),
            )
        }
        "benaloh_leichter" => {
            let clauses = (1..=N)
                .flat_map(|a| {
                    ((a + 1)..=N).flat_map(move |b| {
                        ((b + 1)..=N).map(move |c| {
                            bl::Formula::and(vec![
                                bl::Formula::party(a),
                                bl::Formula::party(b),
                                bl::Formula::party(c),
                            ])
                        })
                    })
                })
                .collect();
            let formula = bl::Formula::or(clauses);
            measure(
                &scalar,
                reconstruct,
                |s| bl::split(&f, &mut rng, s, &formula),
                |s| bl::reconstruct(&f, &formula, &s[..K]).unwrap(),
            )
        }
        "bytes" => measure(
            std::slice::from_ref(&data),
            reconstruct,
            |s| bytes::split(&f, &mut rng, s, K, N),
            |s| {
                let refs: Vec<_> = s[..K].iter().map(Vec::as_slice).collect();
                bytes::reconstruct(&f, &refs, K).unwrap()
            },
        ),
        "ida" => measure(
            std::slice::from_ref(&data),
            reconstruct,
            |s| ida::split(&f, s, K, N),
            |s| {
                let refs: Vec<_> = s[..K].iter().map(Vec::as_slice).collect();
                ida::reconstruct(&f, &refs, K).unwrap()
            },
        ),
        "visual" => {
            let pixels: Vec<Vec<bool>> = data
                .iter()
                .map(|b| (0..8).rev().map(|i| b & (1 << i) != 0).collect())
                .collect();
            measure(
                &[pixels],
                reconstruct,
                |s| visual::split_n_of_n(&mut rng, s, 3),
                |s| visual::decode(&visual::stack(s).unwrap(), 3).unwrap(),
            )
        }
        _ => panic!("unknown method"),
    };
    println!("{ms:.9}");
}
