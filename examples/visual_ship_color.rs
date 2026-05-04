//! Colour visual cryptography on a real image.
//!
//! Naor-Shamir visual cryptography is fundamentally 1-bit per pixel.
//! To preserve colour we run it three times — once per CMY channel —
//! and recombine the recovered planes back into RGB. The result is
//! halftoned (each smooth tone becomes a pattern of dots) but the
//! colour information IS recovered when the shares are stacked.
//!
//! ```sh
//! cargo run --release --example visual_ship_color -- \
//!     assets/ship_of_fools.ppm /tmp/ship_color 3
//! # writes per-share colour PPMs and a recovered colour PPM.
//! ```
//!
//! Pipeline per channel:
//!   1. RGB pixel → CMY tone (C = 255 - R, M = 255 - G, Y = 255 - B).
//!      CMY because transparencies are subtractive — ink blocks light.
//!   2. Floyd-Steinberg dithering reduces each 8-bit CMY plane to a
//!      1-bit "ink / no ink" plane.
//!   3. `visual::split_n_of_n` runs on each plane independently.
//!   4. Each output share owns three bit-planes; flattening them
//!      into RGB gives a colour PPM where stacking n shares
//!      physically reproduces the halftoned secret.
//!   5. Per-channel `stack` + `decode` recover each plane; recombine
//!      → halftoned-secret-with-colour PPM.
//!
//! Round-trip verification is per channel (`assert_eq!` on the
//! recovered Boolean plane vs. the halftoned input plane). The
//! example also writes the halftoned input back out as
//! `<prefix>.halftoned.ppm` so the recovered output can be compared
//! against the lossless reference (NOT the original RGB source —
//! Floyd-Steinberg loses information by design).

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use secret_sharing::{csprng::OsRng, visual, ChaCha20Rng};

type Plane = Vec<Vec<bool>>;

fn main() {
    let mut args = env::args().skip(1);
    let input: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("assets/ship_of_fools.ppm"));
    let output_prefix: String = args
        .next()
        .unwrap_or_else(|| "/tmp/ship_color".to_string());
    let n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(3);

    eprintln!("input          : {}", input.display());
    eprintln!("output prefix  : {output_prefix}.share<i>.ppm");
    eprintln!("n shares       : {n}");

    let (w, h, rgb) = read_ppm(&input);
    eprintln!("secret image   : {w} × {h} (RGB)");

    let m = visual::pixel_expansion(n);
    eprintln!("share image    : {} × {h} (per-pixel expansion = {m})", w * m);

    // Decompose to CMY 8-bit planes, halftone each to 1-bit.
    let (mut c, mut my, mut yl) = (
        rgb_channel(&rgb, w, h, |r, _, _| 255 - r),
        rgb_channel(&rgb, w, h, |_, g, _| 255 - g),
        rgb_channel(&rgb, w, h, |_, _, b| 255 - b),
    );
    let c_bits = floyd_steinberg(&mut c, w, h);
    let m_bits = floyd_steinberg(&mut my, w, h);
    let y_bits = floyd_steinberg(&mut yl, w, h);

    write_ppm(
        &format!("{output_prefix}.halftoned.ppm"),
        w,
        h,
        &cmy_to_rgb(&c_bits, &m_bits, &y_bits, w, h),
    );
    eprintln!("  wrote {output_prefix}.halftoned.ppm (lossless reference for the round-trip)");

    let mut rng = ChaCha20Rng::from_os_entropy(
        &mut OsRng::new().expect("/dev/urandom"),
    );

    eprintln!("splitting C, M, Y planes …");
    let c_shares = visual::split_n_of_n(&mut rng, &c_bits, n);
    let m_shares = visual::split_n_of_n(&mut rng, &m_bits, n);
    let y_shares = visual::split_n_of_n(&mut rng, &y_bits, n);

    let share_w = w * m;
    for i in 0..n {
        let path = format!("{output_prefix}.share{}.ppm", i + 1);
        let rgb_share = cmy_to_rgb(&c_shares[i], &m_shares[i], &y_shares[i], share_w, h);
        write_ppm(&path, share_w, h, &rgb_share);
        eprintln!("  wrote {path}");
    }

    eprintln!("stacking + decoding each channel …");
    let c_stack = visual::stack(&c_shares).expect("C share dims agree");
    let m_stack = visual::stack(&m_shares).expect("M share dims agree");
    let y_stack = visual::stack(&y_shares).expect("Y share dims agree");

    let c_rec = visual::decode(&c_stack, n).expect("C honest stack decodes");
    let m_rec = visual::decode(&m_stack, n).expect("M honest stack decodes");
    let y_rec = visual::decode(&y_stack, n).expect("Y honest stack decodes");

    assert_eq!(c_rec, c_bits, "C-channel round-trip failed");
    assert_eq!(m_rec, m_bits, "M-channel round-trip failed");
    assert_eq!(y_rec, y_bits, "Y-channel round-trip failed");

    let recovered = cmy_to_rgb(&c_rec, &m_rec, &y_rec, w, h);
    let recovered_path = format!("{output_prefix}.recovered.ppm");
    write_ppm(&recovered_path, w, h, &recovered);
    eprintln!("  wrote {recovered_path}");

    let stacked_rgb = cmy_to_rgb(&c_stack, &m_stack, &y_stack, share_w, h);
    let stacked_path = format!("{output_prefix}.stacked.ppm");
    write_ppm(&stacked_path, share_w, h, &stacked_rgb);
    eprintln!("  wrote {stacked_path}");

    eprintln!("done — every CMY plane round-tripped bit-for-bit");
}

/// Pull one channel out of a packed RGB raster as an 8-bit plane.
fn rgb_channel(rgb: &[u8], w: usize, h: usize, f: impl Fn(u8, u8, u8) -> u8) -> Vec<Vec<i32>> {
    let mut out = Vec::with_capacity(h);
    for y in 0..h {
        let mut row = Vec::with_capacity(w);
        for x in 0..w {
            let i = (y * w + x) * 3;
            row.push(f(rgb[i], rgb[i + 1], rgb[i + 2]) as i32);
        }
        out.push(row);
    }
    out
}

/// Floyd-Steinberg dither an 8-bit single-channel plane to a 1-bit
/// plane. `true` means "ink present" (i.e. the channel value is high
/// enough to be quantised to 255 in CMY space → blocks that primary).
fn floyd_steinberg(plane: &mut [Vec<i32>], w: usize, h: usize) -> Plane {
    let mut bits = vec![vec![false; w]; h];
    for y in 0..h {
        for x in 0..w {
            let old = plane[y][x];
            let new_val = if old > 127 { 255 } else { 0 };
            bits[y][x] = new_val == 255;
            let err = old - new_val;
            // 7/16 → (x+1, y)
            if x + 1 < w {
                plane[y][x + 1] += err * 7 / 16;
            }
            if y + 1 < h {
                // 3/16 → (x-1, y+1)
                if x > 0 {
                    plane[y + 1][x - 1] += err * 3 / 16;
                }
                // 5/16 → (x, y+1)
                plane[y + 1][x] += err * 5 / 16;
                // 1/16 → (x+1, y+1)
                if x + 1 < w {
                    plane[y + 1][x + 1] += err / 16;
                }
            }
        }
    }
    bits
}

/// Recombine three CMY 1-bit planes into a packed RGB raster.
/// Subtractive: ink set in C blocks red, etc.
fn cmy_to_rgb(c: &Plane, m: &Plane, y: &Plane, w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 3];
    for row in 0..h {
        for col in 0..w {
            let i = (row * w + col) * 3;
            out[i] = if c[row][col] { 0 } else { 255 };
            out[i + 1] = if m[row][col] { 0 } else { 255 };
            out[i + 2] = if y[row][col] { 0 } else { 255 };
        }
    }
    out
}

/// Read a Netpbm `P6` (binary RGB) file into `(w, h, packed_rgb)`.
fn read_ppm(path: &std::path::Path) -> (usize, usize, Vec<u8>) {
    let mut file = fs::File::open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut all = Vec::new();
    file.read_to_end(&mut all).expect("read");

    assert_eq!(&all[..2], b"P6", "expected binary PPM (magic P6)");
    let mut idx = 2usize;

    let mut tokens: Vec<String> = Vec::new();
    while tokens.len() < 3 {
        while idx < all.len() && all[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx < all.len() && all[idx] == b'#' {
            while idx < all.len() && all[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }
        let start = idx;
        while idx < all.len() && !all[idx].is_ascii_whitespace() {
            idx += 1;
        }
        tokens.push(String::from_utf8(all[start..idx].to_vec()).expect("ascii token"));
    }
    assert!(idx < all.len() && all[idx].is_ascii_whitespace());
    idx += 1;

    let w: usize = tokens[0].parse().expect("width");
    let h: usize = tokens[1].parse().expect("height");
    let maxval: u32 = tokens[2].parse().expect("maxval");
    assert_eq!(maxval, 255, "only 8-bit-per-channel PPMs supported");

    let needed = w * h * 3;
    assert!(idx + needed <= all.len(), "raster truncated");
    (w, h, all[idx..idx + needed].to_vec())
}

/// Write a packed RGB raster as a Netpbm `P6` file.
fn write_ppm(path: &str, w: usize, h: usize, rgb: &[u8]) {
    assert_eq!(rgb.len(), w * h * 3);
    let mut buf = Vec::with_capacity(32 + rgb.len());
    buf.extend_from_slice(format!("P6\n{w} {h}\n255\n").as_bytes());
    buf.extend_from_slice(rgb);
    fs::File::create(path)
        .and_then(|mut f| f.write_all(&buf))
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
}
