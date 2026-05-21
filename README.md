# roka

> コインロッカー — deposit a secret, retrieve a one-time code.

Zero-dependency QR + TOTP toolkit for Rust. Two crates:

| Crate | What it does |
|-------|--------------|
| [`roka-qr`](roka-qr/) | QR code encoder + decoder with built-in PNG/PBM I/O. Pure Rust, `std` only. |
| [`roka-totp`](roka-totp/) | TOTP / HOTP with optional QR code generation and scanning (via `roka-qr`). |

## Status

🚧 **0.0.1 placeholder releases only.** The real 0.1.0 ships after API polish.
Source for the working prototype lives in the
[`lab10-2fa`](https://github.com/goliajp/labs) experimental lab.

## Goals

- **Zero external crate dependencies.** Only `std`.
- **No unsafe.**
- **Encode + decode in one crate** — fills a gap on crates.io.
- **Audit-friendly code** with detailed comments.
- **Round-trip tested** against `qrencode` and `zbarimg`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option.

Brought to you by [GOLIA Inc.](https://github.com/goliajp)
