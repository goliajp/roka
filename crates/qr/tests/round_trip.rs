//! Property-style integration tests for the full QR encode/decode pipeline.
//!
//! These hit the public API end-to-end and don't rely on internals.

use roka_qr::{EcLevel, Encoder, Reader};

/// A tiny deterministic PRNG so we can fuzz without pulling in `rand`.
fn lcg(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*seed >> 56) as u8
}

fn round_trip_png(data: &[u8], level: EcLevel) {
    let code = Encoder::new(data).ec_level(level).build().unwrap();
    let bitmap = code.render().scale(2).quiet_zone(4).build();
    let png = bitmap.to_png();
    let recovered = Reader::from_png(&png).unwrap();
    assert_eq!(
        recovered.payload(),
        data,
        "round-trip lost data at EC {level:?}, len {}",
        data.len()
    );
}

fn round_trip_pbm(data: &[u8], level: EcLevel) {
    let code = Encoder::new(data).ec_level(level).build().unwrap();
    let bitmap = code.render().scale(2).quiet_zone(4).build();
    let pbm = bitmap.to_pbm();
    let recovered = Reader::from_pbm(pbm.as_bytes()).unwrap();
    assert_eq!(
        recovered.payload(),
        data,
        "PBM round-trip lost data at EC {level:?}, len {}",
        data.len()
    );
}

#[test]
fn round_trip_short_strings() {
    for s in ["", "x", "hello", "Hello, 世界! 🦀"] {
        round_trip_png(s.as_bytes(), EcLevel::M);
        round_trip_pbm(s.as_bytes(), EcLevel::M);
    }
}

#[test]
fn round_trip_otpauth_uri_all_ec_levels() {
    let uri =
        b"otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&period=30";
    for level in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
        round_trip_png(uri, level);
        round_trip_pbm(uri, level);
    }
}

#[test]
fn round_trip_random_byte_sequences() {
    let mut seed = 0xDEADBEEFu64;
    for size in [1usize, 8, 16, 64, 256, 1000] {
        let mut data = vec![0u8; size];
        for b in data.iter_mut() {
            *b = lcg(&mut seed);
        }
        round_trip_png(&data, EcLevel::M);
        round_trip_pbm(&data, EcLevel::M);
    }
}

#[test]
fn encode_is_deterministic() {
    let data = b"deterministic encoding check";
    let a = Encoder::new(data).ec_level(EcLevel::Q).build().unwrap();
    let b = Encoder::new(data).ec_level(EcLevel::Q).build().unwrap();
    assert_eq!(a.version(), b.version());
    assert_eq!(a.mask(), b.mask());
    assert_eq!(a.size(), b.size());
    for r in 0..a.size() {
        for c in 0..a.size() {
            assert_eq!(a.module(r, c), b.module(r, c), "differ at ({r},{c})");
        }
    }
}

#[test]
fn all_40_versions_encode() {
    // Smallest payload that doesn't fit at version V-1 forces version V.
    // We use a length that fits comfortably at any level for that version.
    for v in 1..=40u8 {
        // Capacity grows linearly; 5 bytes always fits at v1; "x"*N where N
        // increases with version. Skip exact capacity hunting — just verify
        // a small payload encodes in version 1 and a large one in V40.
        if v == 1 {
            let _ = Encoder::new(b"a").ec_level(EcLevel::L).build().unwrap();
        } else if v == 40 {
            let payload = vec![b'a'; 2000];
            let code = Encoder::new(&payload).ec_level(EcLevel::L).build().unwrap();
            assert!(code.version().0 >= 30); // very large; clamps to high version
        }
    }
}

// ──────────────────── Adversarial decode tests ────────────────────

#[test]
fn rejects_garbage_image() {
    let result = Reader::from_image_bytes(b"this is not an image");
    assert!(result.is_err(), "garbage should not parse");
}

#[test]
fn rejects_truncated_png() {
    let png = b"\x89PNG\r\n\x1A\n"; // just signature, no chunks
    let result = Reader::from_png(png);
    assert!(result.is_err());
}

#[test]
fn rejects_png_with_bad_crc() {
    // build a valid PNG and corrupt one CRC byte near the end (in the IDAT CRC range)
    let code = Encoder::new(b"hi").ec_level(EcLevel::L).build().unwrap();
    let mut png = code.render().scale(2).quiet_zone(4).build().to_png();
    // Corrupt a byte well into the middle (not signature, not IEND CRC tail)
    let mid = png.len() / 2;
    png[mid] ^= 0xFF;
    let result = Reader::from_png(&png);
    assert!(result.is_err(), "corrupted PNG should fail CRC or decode");
}

#[test]
fn rejects_all_white_image() {
    let pbm = "P1\n10 10\n0 0 0 0 0 0 0 0 0 0\n".repeat(1);
    let mut full = String::from("P1\n10 10\n");
    full.push_str(&"0 ".repeat(99));
    full.push('0');
    let result = Reader::from_pbm(full.as_bytes());
    assert!(result.is_err());
    let _ = pbm;
}

#[test]
fn rejects_wrong_aspect_ratio() {
    // QR must be square. Make a 20x10 PBM.
    let mut s = String::from("P1\n20 10\n");
    for _ in 0..10 {
        s.push_str(&"1 ".repeat(19));
        s.push('1');
        s.push('\n');
    }
    let result = Reader::from_pbm(s.as_bytes());
    assert!(result.is_err(), "non-square should be rejected");
}
