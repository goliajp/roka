# roka-qr performance budgets

Enforced by `tests/perf_gate.rs`. Run `cargo test -p roka-qr --test perf_gate`.

Budgets are set with **~5–10× headroom** above the best observed local number.
The point is to catch order-of-magnitude regressions, not to chase micro-perf.

## End-to-end paths

| Path | Budget | Best observed (M2, release) | Headroom |
| --- | ---: | ---: | ---: |
| `Encoder::build` (otpauth URI, EcLevel::M) | 1.0 ms | ~115 µs | ~9× |
| `Encoder::build` (otpauth URI, EcLevel::H) | 2.5 ms | ~211 µs | ~12× |
| `Bitmap::to_png` (V6 @ scale 8) | 1.5 ms | ~255 µs | ~6× |
| `Reader::from_pbm` (V6 otpauth M) | 800 µs | ~133 µs | ~6× |
| `Reader::from_png` (V6 otpauth M) | 1.5 ms | ~246 µs | ~6× |
| Round-trip (URI → PNG → URI) | 3.0 ms | ~630 µs | ~5× |

## Why these matter

- `Encoder::build` runs on every QR generation — the bottleneck on the
  authenticator-pairing side.
- `Reader::from_*` runs on every scan — the bottleneck on the
  read-and-compute-OTP side.
- `Bitmap::to_png` is the actual byte-shuffling output stage; users with QR
  code generation in a tight loop (server-side QR mint) hit this most.

## Methodology

Each test runs the target op in a tight Rust loop, measures wall-clock
elapsed per iteration with `std::time::Instant`, takes the **median** of
100 samples to filter out scheduler jitter, and asserts that the median is
under the budget.

Re-measure after any change to the codec/image-IO modules:

```bash
cargo bench -p roka-qr --bench codec
```

A bench run posts P95 + P99 + median; if any new "best observed" is more than
2× worse than what's listed above, update this table and bump the budget
proportionally (or fix the regression — usually the right call).
