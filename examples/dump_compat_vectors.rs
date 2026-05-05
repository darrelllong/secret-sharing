//! Print the bit-compatible test vectors that the C++ port consumes
//! in `cpp/test/test_compat.cpp`. Output is plain text on stdout —
//! capture it via `cargo run --release --example dump_compat_vectors >
//! cpp/test/compat_vectors.inc` and the C++ test references the same
//! constants.

use secret_sharing::{
    field::{
        curve25519_field, curve448_field, mersenne127, mersenne521, nist_p192_field,
        nist_p224_field, nist_p256_field, nist_p384_field, poly1305_field, secp256k1_field,
        PrimeField,
    },
    shamir, BigUint, ChaCha20Rng, Csprng,
};

fn print_bytes(label: &str, bytes: &[u8]) {
    print!("{label}");
    for &b in bytes {
        print!("{b:02x}");
    }
    println!();
}

fn main() {
    // ChaCha20 keystream from seed 0xA7.
    {
        let mut rng = ChaCha20Rng::from_seed(&[0xA7u8; 32]);
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out);
        print_bytes("CHACHA20_A7_64 = ", &out);
    }

    // BigUint multiplications. Operands are big-endian hex strings;
    // products are mathematical (not modular), big-endian.
    let cases: &[(&str, &str)] = &[
        ("01", "01"),
        ("ff", "ff"),
        ("deadbeef", "cafebabe"),
        ("0123456789abcdef", "fedcba9876543210"),
    ];
    for (a_hex, b_hex) in cases {
        let a = BigUint::from_be_bytes(&hex_decode(a_hex));
        let b = BigUint::from_be_bytes(&hex_decode(b_hex));
        let prod = a.mul_ref(&b);
        let bytes = prod.to_be_bytes();
        print_bytes(&format!("MUL {a_hex} x {b_hex} = "), &bytes);
    }

    // Per-prime mul-mod vectors. Each entry is (prime_name, a_hex,
    // b_hex, a*b mod p as hex). Operands are deterministic across
    // primes so the C++ side can pin the same residues. The C++ test
    // builds the same prime via its constructor and verifies the
    // fast path produces the exact byte string Rust did.
    let prime_table: &[(&str, BigUint)] = &[
        ("mersenne127", mersenne127()),
        ("mersenne521", mersenne521()),
        ("curve25519", curve25519_field()),
        ("poly1305", poly1305_field()),
        ("secp256k1", secp256k1_field()),
        ("curve448", curve448_field()),
        ("nist_p192", nist_p192_field()),
        ("nist_p224", nist_p224_field()),
        ("nist_p256", nist_p256_field()),
        ("nist_p384", nist_p384_field()),
    ];
    let operand_a_hex = "deadbeefcafebabe0123456789abcdef";
    let operand_b_hex = "fedcba9876543210cafef00dba5eba11";
    for (name, p) in prime_table {
        let f = PrimeField::new_unchecked(p.clone());
        let a = BigUint::from_be_bytes(&hex_decode(operand_a_hex)).modulo(p);
        let b = BigUint::from_be_bytes(&hex_decode(operand_b_hex)).modulo(p);
        let prod = f.mul(&a, &b);
        print_bytes(&format!("FIELD_MUL {name} = "), &prod.to_be_bytes());
    }

    // Shamir shares with seed [0xC1; 32], secret = 0xC0FFEEDEADBEEF,
    // k = 3, n = 5 over Mersenne-127. The C++ test reconstructs from
    // these exact (x, y) byte strings.
    {
        let f = PrimeField::new_unchecked(mersenne127());
        let mut rng = ChaCha20Rng::from_seed(&[0xC1u8; 32]);
        let secret = BigUint::from_u64(0xC0FFEE_DEADBEEFu64);
        let shares = shamir::split(&f, &mut rng, &secret, 3, 5);
        for s in &shares {
            print_bytes(
                &format!("SHAMIR x = "),
                &s.x.to_be_bytes(),
            );
            print_bytes(
                &format!("SHAMIR y = "),
                &s.y.to_be_bytes(),
            );
        }
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(cleaned.len().is_multiple_of(2), "even hex");
    cleaned
        .chunks_exact(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}
fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("bad hex"),
    }
}
