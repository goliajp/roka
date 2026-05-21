# roka-qr

Zero-dependency QR code encoder + decoder for Rust, with built-in PNG and PBM
image I/O. Part of the [`roka`](https://github.com/goliajp/roka) project.

> **0.0.1 is a placeholder release** that reserves the name on crates.io.
> The real API ships in **0.1.0**.

## What's coming in 0.1.0

- QR codec covering ISO/IEC 18004 v1–40, all four EC levels (L/M/Q/H).
- Byte / alphanumeric / numeric mode, multi-segment payloads.
- Self-contained image I/O: PNG (encode + decode, including DEFLATE inflate) and
  PBM P1/P4. No external crates required — `std` only.
- Round-trip tested against `qrencode` and `zbarimg`.

## License

Dual-licensed under MIT or Apache 2.0.
