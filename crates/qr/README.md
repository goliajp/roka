# roka-qr

[![Crates.io](https://img.shields.io/crates/v/roka-qr?style=flat-square&logo=rust)](https://crates.io/crates/roka-qr)
[![docs.rs](https://img.shields.io/docsrs/roka-qr?style=flat-square&logo=docs.rs)](https://docs.rs/roka-qr)
[![License](https://img.shields.io/crates/l/roka-qr?style=flat-square)](#license)
[![Downloads](https://img.shields.io/crates/d/roka-qr?style=flat-square)](https://crates.io/crates/roka-qr)

Zero-dependency QR code encoder + decoder for Rust, with built-in PNG and PBM image I/O.

Implements [ISO/IEC 18004] end-to-end: byte / alphanumeric / numeric mode decoding, all four error-correction levels (L/M/Q/H), all 40 versions, plus encoding and decoding from PNG or PBM images.

## Highlights

- **Zero external crate dependencies.** `std` only.
- **Encode + decode in one crate** — fills a gap on crates.io.
- **Self-contained image I/O** — PNG encode + decode (including DEFLATE inflate), PBM P1 / P4. No `image` or `flate2` needed.
- **Round-trip tested** against [`qrencode`] and [`zbarimg`].
- **No `unsafe`.** 120+ tests, including RFC test vectors for the components (SHA-1, HMAC, RS, BCH).

## Quick start

Encode a string and write it as PNG:

```rust
use roka_qr::{Encoder, EcLevel};

let code = Encoder::new(b"https://example.com")
    .ec_level(EcLevel::M)
    .build()?;

let png_bytes = code
    .render()
    .scale(8)
    .quiet_zone(4)
    .build()
    .to_png();

std::fs::write("qr.png", png_bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Scan a QR code from a PNG file:

```rust,no_run
use roka_qr::Reader;

let bytes = std::fs::read("qr.png")?;
let code = Reader::from_png(&bytes)?;
println!("payload: {}", std::str::from_utf8(code.payload())?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## When to use this crate

- You want **both encoding and decoding** of QR codes in one place. The popular [`qrcode`] crate only encodes; [`rqrr`] only decodes.
- You can't (or don't want to) pull in `image` + `flate2` + a separate QR decoder.
- You're building security-sensitive software (auth, payments) and want a fully audit-friendly QR layer.

## Constraints

- **No camera/perspective correction.** Input images must already be aligned and binarized. For phone-camera input, run them through a deskew/threshold step first.
- Decode supports **byte / alphanumeric / numeric** modes; encode only emits byte mode (sufficient for arbitrary 8-bit payloads). Kanji mode is not supported.

## Performance

Indicative numbers on M2 (release); see [`BUDGETS.md`](BUDGETS.md):

| Operation | Time |
| --- | ---: |
| `Encoder::build` (otpauth URI, EcLevel::M) | ~87 µs |
| `Bitmap::to_png` (V6 at scale 8) | ~117 µs |
| `Bitmap::to_png` (V11 at scale 8) | ~234 µs |
| `Reader::from_pbm` (V6 otpauth M) | ~98 µs |
| `Reader::from_png` (V6 otpauth M) | ~274 µs |
| Round-trip (URI → PNG → URI) | ~449 µs |

Regression gates live in [`tests/perf_gate.rs`](tests/perf_gate.rs).

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Part of the [`roka`](https://github.com/goliajp/roka) project by [GOLIA Inc.](https://github.com/goliajp)

[ISO/IEC 18004]: https://www.iso.org/standard/62021.html
[`qrencode`]: https://github.com/fukuchi/libqrencode
[`zbarimg`]: http://zbar.sourceforge.net/
[`qrcode`]: https://crates.io/crates/qrcode
[`rqrr`]: https://crates.io/crates/rqrr
