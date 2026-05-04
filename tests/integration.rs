//! End-to-end exercise: real Mersenne-127 field, byte secrets, every
//! scheme in the crate.

use secret_sharing::{
    decode::reconstruct_with_errors,
    field::{mersenne127, PrimeField},
    poly,
    ramp, shamir, trivial,
    BigUint, ChaCha20Rng, Share,
};

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(&[seed; 32])
}

fn pick_field() -> PrimeField {
    PrimeField::new(mersenne127())
}

fn secret_from_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_be_bytes(bytes)
}

#[test]
fn shamir_round_trip_on_real_field() {
    let f = pick_field();
    let mut r = rng(0xA5);
    let secret = secret_from_bytes(b"the quick brown");
    let shares = shamir::split(&f, &mut r, &secret, 3, 7);
    assert_eq!(shamir::reconstruct(&f, &shares[..3], 3), Some(secret.clone()));
    assert_eq!(shamir::reconstruct(&f, &shares[2..6], 3), Some(secret));
}

#[test]
fn shamir_then_decode_with_errors() {
    let f = pick_field();
    let mut r = rng(0x5A);
    let secret = secret_from_bytes(b"recover me ok!?!");
    let mut shares = shamir::split(&f, &mut r, &secret, 4, 11);
    // Corrupt three shares — within radius for (m=11, k=4, t=3): 11 ≥ 4 + 6.
    shares[2].y = f.add(&shares[2].y, &BigUint::from_u64(1));
    shares[5].y = BigUint::zero();
    shares[9].y = f.add(&shares[9].y, &BigUint::from_u64(99));
    let recovered = reconstruct_with_errors(&f, &shares, 4, 3).expect("decoder");
    assert_eq!(recovered, secret);
}

#[test]
fn ramp_compresses_then_recovers() {
    // Pack 5 distinct field elements as the secret. Each share is one
    // field element, so per-trustee payload is 5× smaller than the
    // secret itself (the McEliece–Sarwate compression trade-off).
    let f = pick_field();
    let secret: Vec<BigUint> = (0..5).map(|i| BigUint::from_u64(0x1000 + i)).collect();
    let shares = ramp::split(&f, &secret, 8);
    assert_eq!(ramp::reconstruct(&f, &shares[..5], 5).as_ref(), Some(&secret));
    assert_eq!(ramp::reconstruct(&f, &shares[3..], 5).as_ref(), Some(&secret));
}

#[test]
fn trivial_xor_byte_secret() {
    let mut r = rng(0x33);
    let secret = b"top secret 256-bit AES key 32 bytes!".to_vec();
    let shares = trivial::split_xor(&mut r, &secret, 5);
    // All five required for reconstruction.
    assert_eq!(trivial::reconstruct_xor(&shares), secret);
    // Any four still XOR to something — but it should not equal the secret.
    let partial = trivial::reconstruct_xor(&shares[..4]);
    assert_ne!(partial, secret);
}

#[test]
fn multi_secret_extension_round_trip() {
    let f = pick_field();
    let mut r = rng(0x77);
    let secrets: Vec<BigUint> = (1..=4).map(|i| BigUint::from_u64(900 + i)).collect();
    let shares = shamir::split_multi(&f, &mut r, &secrets, 5, 9);
    let got = shamir::reconstruct_multi(&f, &shares[..5], 5, 4).unwrap();
    assert_eq!(got, secrets);
    // Five different shares — same answer.
    let got2 = shamir::reconstruct_multi(&f, &shares[4..], 5, 4).unwrap();
    assert_eq!(got2, secrets);
}

#[test]
fn poly_helpers_visible_for_external_use() {
    // Sanity check that the polynomial helpers are reachable from
    // outside the crate (e.g. for users implementing their own scheme
    // on top of `PrimeField`).
    let f = pick_field();
    let pts: Vec<(BigUint, BigUint)> = (1..=3)
        .map(|i| {
            (
                BigUint::from_u64(i),
                BigUint::from_u64(i * i + 2 * i + 1), // (i+1)^2
            )
        })
        .collect();
    let v = poly::lagrange_eval(&f, &pts, &BigUint::zero()).unwrap();
    assert_eq!(v, BigUint::one());

    let coeffs = vec![BigUint::one(), BigUint::from_u64(2), BigUint::one()]; // (x+1)^2
    assert_eq!(
        poly::horner(&f, &coeffs, &BigUint::from_u64(4)),
        BigUint::from_u64(25),
    );
}

#[test]
fn share_struct_is_clone_eq_debug() {
    let s = Share {
        x: BigUint::from_u64(1),
        y: BigUint::from_u64(2),
    };
    let t = s.clone();
    assert_eq!(s, t);
    let _ = format!("{s:?}");
}
