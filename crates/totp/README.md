# roka-totp

[![Crates.io](https://img.shields.io/crates/v/roka-totp?style=flat-square&logo=rust)](https://crates.io/crates/roka-totp)
[![docs.rs](https://img.shields.io/docsrs/roka-totp?style=flat-square&logo=docs.rs)](https://docs.rs/roka-totp)
[![License](https://img.shields.io/crates/l/roka-totp?style=flat-square)](#license)
[![Downloads](https://img.shields.io/crates/d/roka-totp?style=flat-square)](https://crates.io/crates/roka-totp)

Zero-dependency TOTP / HOTP implementation for Rust.

Implements [RFC 6238] (TOTP) and [RFC 4226] (HOTP). Brings its own SHA-1, HMAC-SHA1, and Base32 — no crypto crate is pulled in, no `unsafe` is used.

## Highlights

- **Zero external crate dependencies.** `std` only.
- **No `unsafe`.**
- **RFC test vectors verified** — SHA-1 (RFC 3174), HMAC (RFC 2202), HOTP (RFC 4226 Appendix D), TOTP (RFC 6238 Appendix B).
- **Type-safe API** — `Secret` newtype, `Algorithm` enum, builder pattern.
- **otpauth URI build** ready for QR pairing.

## Quick start

```rust
use roka_totp::{Totp, Secret};

let secret = Secret::from_base32("JBSWY3DPEHPK3PXP")?;
let totp = Totp::builder(secret)
    .issuer("Acme")
    .account("alice@example.com")
    .build();

let code = totp.code_now();        // current OTP, e.g. "847529"
let uri = totp.uri();              // otpauth://totp/Acme:alice... for QR pairing

// Verify a user-entered code against the current window ± 1 step
match totp.verify(&user_input, totp_unix_now(), 1) {
    Some(offset) => println!("ok (offset {offset} windows)"),
    None => println!("reject"),
}
# fn totp_unix_now() -> u64 { 0 }
# let user_input = String::new();
# Ok::<(), roka_totp::Error>(())
```

## When to use this crate

- You want **minimal supply-chain risk** for your authentication path. `roka-totp` has zero transitive dependencies — anyone can audit the whole code path from base32 secret to 6-digit code in an afternoon.
- You're targeting **embedded / WASM / no-std-ish** environments where pulling in RustCrypto + serde is excessive.
- You want **QR generation built in** — pair with [`roka-qr`](https://crates.io/crates/roka-qr) and ship a complete 2FA stack with no other deps.

## Performance

Indicative numbers on M2 (release); see [`BUDGETS.md`](BUDGETS.md):

| Operation | Time |
| --- | ---: |
| `Secret::from_base32` (16 bytes) | ~84 ns |
| `Totp::code_at` | ~900 ns |
| `Totp::verify` (match, ±1 window) | ~1.8 µs |
| `Totp::uri` | ~815 ns |

Regression gates live in [`tests/perf_gate.rs`](tests/perf_gate.rs).

## Roadmap

- 0.1.0 — current API surface (SHA-1 only).
- 0.2.0 — `Algorithm::Sha256` / `Algorithm::Sha512` (otpauth URI standard).
- 0.2.x — `Totp::from_uri` parsing.
- Later — `no_std + alloc` support.

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Part of the [`roka`](https://github.com/goliajp/roka) project by [GOLIA Inc.](https://github.com/goliajp)

[RFC 4226]: https://datatracker.ietf.org/doc/html/rfc4226
[RFC 6238]: https://datatracker.ietf.org/doc/html/rfc6238
