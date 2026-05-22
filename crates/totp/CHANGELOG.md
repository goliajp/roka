# Changelog

All notable changes to `roka-totp` will be documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Planned

- `Algorithm::Sha256` and `Algorithm::Sha512` (the otpauth URI standard
  supports both; many enterprise tools use SHA-256 specifically).
- `Totp::from_uri(&str)` parsing of an `otpauth://` URI.
- Optional `qr` feature wiring [`roka-qr`](https://crates.io/crates/roka-qr)
  for end-to-end QR pairing.
- `no_std + alloc` support.

## [0.1.0] — 2026-05-22

First public-API release.

### Added

- `Totp` + `TotpBuilder` for time-based one-time passwords (RFC 6238).
- `Hotp` for counter-based one-time passwords (RFC 4226).
- `Secret` newtype with base32 encode/decode and a `Debug` impl that
  redacts the contents.
- `Algorithm` enum (currently `Sha1`-only; reserved for future expansion).
- `Error` enum (`InvalidBase32` / `InvalidUri`).
- otpauth URI build via `Totp::uri()`.
- 30+ tests, including the RFC 4226 Appendix D HOTP vectors and the RFC 6238
  Appendix B TOTP vectors (SHA-1 8-digit values).
- Performance regression gates in `tests/perf_gate.rs` (release-mode only).

## [0.0.1] — 2026-05-22

- Namespace placeholder release.
