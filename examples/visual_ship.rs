//! Working visual-cryptography demo on a real image.
//!
//! Reads a binary PBM (`P4`) image, runs `crate::visual::split_n_of_n`
//! to produce `n` cryptographic shares, writes each share to a PBM
//! file, and verifies recovery by stacking + decoding.
//!
//! ```sh
//! cargo run --release --example visual_ship -- assets/ship_of_fools.pbm /tmp/ship 3
//! # writes /tmp/ship.share1.pbm … /tmp/ship.share3.pbm + /tmp/ship.recovered.pbm
//! ```
//!
//! Why PBM and not PNG. PBM (Netpbm 1-bit binary, format magic `P4`)
//! is lossless and has a trivially-decodable header — `P4\n<W> <H>\n`
//! followed by row-padded packed bits. PNG is also lossless but
//! mandates DEFLATE-compressed `IDAT` chunks; supporting PNG without
//! external dependencies would mean shipping ~500 LOC of inflate /
//! deflate inside this example. This crate's "no external
//! dependencies" rule applies to examples too, so the demo uses PBM.
//! Convert in either direction with ImageMagick or sips:
//!
//! ```sh
//! magick share1.pbm share1.png        # PBM → PNG
//! magick image.png -monochrome image.pbm # PNG → PBM (1-bit)
//! ```
//!
//! Note on the bundled `assets/ship_of_fools.png`: it is actually a
//! JPEG with a `.png` extension, so it would not have round-tripped
//! losslessly anyway. The companion `assets/ship_of_fools.pbm` was
//! produced by the `magick … -monochrome` recipe above and IS
//! losslessly preserved through the split / stack / decode cycle.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use secret_sharing::{csprng::OsRng, visual, ChaCha20Rng};

fn main() {
    let mut args = env::args().skip(1);
    let input: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("assets/ship_of_fools.pbm"));
    let output_prefix: String = args.next().unwrap_or_else(|| "/tmp/ship".to_string());
    let n: usize = args
        .next()
        .and_then(|a| a.parse().ok())
        .unwrap_or(2);

    eprintln!("input          : {}", input.display());
    eprintln!("output prefix  : {}.share<i>.pbm / {}.recovered.pbm", output_prefix, output_prefix);
    eprintln!("n shares       : {n}");

    let secret = read_pbm(&input);
    let h = secret.len();
    let w = if h > 0 { secret[0].len() } else { 0 };
    let m = visual::pixel_expansion(n);
    eprintln!("secret image   : {w} × {h}");
    eprintln!("share image    : {} × {h} (per-pixel expansion = {m})", w * m);

    // Production seeding via OsRng → ChaCha20Rng (per the crate's
    // documented entropy-source pattern). Visual cryptography is
    // information-theoretically secure provided the share permutations
    // are uniformly random.
    let mut rng = ChaCha20Rng::from_os_entropy(
        &mut OsRng::new().expect("/dev/urandom"),
    );

    eprintln!("splitting … ");
    let shares = visual::split_n_of_n(&mut rng, &secret, n);

    for (i, share) in shares.iter().enumerate() {
        let path = format!("{output_prefix}.share{}.pbm", i + 1);
        write_pbm(&path, share);
        eprintln!("  wrote {path}");
    }

    eprintln!("stacking + decoding … ");
    let stacked = visual::stack(&shares).expect("share dimensions agree");
    let recovered = visual::decode(&stacked, n).expect("honest stack decodes cleanly");
    assert_eq!(
        recovered, secret,
        "round-trip failed: recovered image does not match the secret",
    );

    let recovered_path = format!("{output_prefix}.recovered.pbm");
    write_pbm(&recovered_path, &recovered);
    eprintln!("  wrote {recovered_path}");

    let stacked_path = format!("{output_prefix}.stacked.pbm");
    write_pbm(&stacked_path, &stacked);
    eprintln!("  wrote {stacked_path}");

    eprintln!("done — round-trip recovered the secret bit-for-bit");
}

/// Read a Netpbm binary `P4` (1-bit) file into `Vec<Vec<bool>>` —
/// `true` = black, `false` = white.
fn read_pbm(path: &std::path::Path) -> Vec<Vec<bool>> {
    let mut file = fs::File::open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut all = Vec::new();
    file.read_to_end(&mut all).expect("read");

    // Header: "P4\n<W> <H>\n" with optional comment lines starting "#".
    // Walk byte-by-byte to find the end of the third whitespace-
    // separated token (after dropping any "# …\n" comment lines).
    let magic = &all[..2];
    assert_eq!(magic, b"P4", "expected binary PBM (magic P4); got {:?}", magic);
    let mut idx = 2usize;

    let mut tokens: Vec<String> = Vec::new();
    while tokens.len() < 2 {
        // Skip whitespace.
        while idx < all.len() && all[idx].is_ascii_whitespace() {
            idx += 1;
        }
        // Skip comments.
        if idx < all.len() && all[idx] == b'#' {
            while idx < all.len() && all[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }
        // Read token until whitespace.
        let start = idx;
        while idx < all.len() && !all[idx].is_ascii_whitespace() {
            idx += 1;
        }
        tokens.push(String::from_utf8(all[start..idx].to_vec()).expect("ascii token"));
    }
    // The byte AFTER the height token is the single header-terminating
    // whitespace; raster begins right after that one whitespace byte.
    assert!(idx < all.len() && all[idx].is_ascii_whitespace());
    idx += 1;

    let w: usize = tokens[0].parse().expect("width parses");
    let h: usize = tokens[1].parse().expect("height parses");
    let row_bytes = w.div_ceil(8);
    let needed = row_bytes * h;
    assert!(
        idx + needed <= all.len(),
        "raster truncated: need {needed} bytes after header, have {}",
        all.len() - idx,
    );
    let raster = &all[idx..idx + needed];

    let mut out: Vec<Vec<bool>> = Vec::with_capacity(h);
    for y in 0..h {
        let row_start = y * row_bytes;
        let mut row = Vec::with_capacity(w);
        for x in 0..w {
            let byte = raster[row_start + x / 8];
            // P4 packs bits MSB-first; bit set = black = true.
            let bit = (byte >> (7 - (x % 8))) & 1;
            row.push(bit == 1);
        }
        out.push(row);
    }
    out
}

/// Write a `Vec<Vec<bool>>` to a binary `P4` PBM file. `true` = black.
fn write_pbm(path: &str, image: &[Vec<bool>]) {
    let h = image.len();
    let w = if h > 0 { image[0].len() } else { 0 };
    for row in image {
        assert_eq!(row.len(), w, "image rows must be equal length");
    }
    let row_bytes = w.div_ceil(8);
    let mut buf = Vec::with_capacity(16 + row_bytes * h);
    buf.extend_from_slice(format!("P4\n{w} {h}\n").as_bytes());
    for row in image {
        let mut byte = 0u8;
        let mut count = 0u32;
        for (x, &bit) in row.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - (x % 8));
            }
            count += 1;
            if count == 8 {
                buf.push(byte);
                byte = 0;
                count = 0;
            }
        }
        if count > 0 {
            buf.push(byte);
        }
    }
    fs::File::create(path)
        .and_then(|mut f| f.write_all(&buf))
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
}
