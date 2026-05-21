# roka-totp

Zero-dependency TOTP / HOTP implementation for Rust, with optional QR code
support via [`roka-qr`](https://crates.io/crates/roka-qr). Part of the
[`roka`](https://github.com/goliajp/roka) project.

> **0.0.1 is a placeholder release** that reserves the name on crates.io.
> The real API ships in **0.1.0**.

## What's coming in 0.1.0

- RFC 6238 TOTP + RFC 4226 HOTP, with SHA-1 / SHA-256 / SHA-512 algorithms.
- otpauth URI build + parse.
- Base32 secret encoding with grouped-display helper.
- Optional `qr` feature: generate the QR code for an `otpauth://` URI directly
  (PNG / PBM / ASCII art), or scan an image and recover the OTP — all via
  `roka-qr`, no external image deps.
- Pure `std` (and `no_std` + `alloc` exploration in mind).

## License

Dual-licensed under MIT or Apache 2.0.
