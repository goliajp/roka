# Changelog

All notable changes to `roka-qr` will be documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Planned

- Camera-input deskew / perspective correction.
- Encoder support for alphanumeric and numeric mode emission (currently only
  byte mode is emitted; decoder already handles all three).
- `no_std + alloc` support.

## [0.1.0] — 2026-05-22

First public-API release.

### Added

- `Encoder` builder for QR code generation (v1–v40, EC levels L/M/Q/H).
- `Reader` factory for QR code decoding from PNG / PBM bytes.
- `Code` struct exposing version, EC level, mask, module matrix, and recovered
  payload.
- `RenderBuilder` for converting a `Code` into a `Bitmap` with configurable
  scale and quiet zone.
- `Bitmap::to_png` / `Bitmap::to_pbm` for image serialization.
- `Error` enum (`DataTooLarge` / `InvalidImage` / `Corrupted` / `Unsupported`).
- Internal building blocks: GF(256) arithmetic, Reed-Solomon encode/decode,
  BCH(15,5) and BCH(18,6), full DEFLATE inflate **and deflate** (fixed
  Huffman + LZ77), PNG encode + decode, PBM P1/P4 I/O.
- PNG encoder with smart filter (None / Up) selection — typical QR image
  compresses ≈33× vs the raw pixel buffer.
- 120+ tests, including RFC vectors and end-to-end round-trip property tests.
- Performance regression gates in `tests/perf_gate.rs` (release-mode only).

## [0.0.1] — 2026-05-22

- Namespace placeholder release.
