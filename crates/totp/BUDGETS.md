# roka-totp performance budgets

Enforced by `tests/perf_gate.rs`. Run `cargo test -p roka-totp --test perf_gate`.

Budgets are set with **~5–20× headroom** above the best observed local number.

## Hot paths

| Path | Budget | Best observed (M2, release) | Headroom |
| --- | ---: | ---: | ---: |
| `Secret::from_base32` (16-byte secret) | 5 µs | ~84 ns | ~60× |
| `Totp::code_at` | 10 µs | ~900 ns | ~11× |
| `Totp::verify` (match, ±1 window) | 20 µs | ~1.8 µs | ~11× |
| `Totp::verify` (miss, ±1 window) | 20 µs | ~2.7 µs | ~7× |
| `Totp::uri` | 10 µs | ~815 ns | ~12× |

## Why these matter

- `code_at` runs on every OTP generation (server-side verification, watcher
  loops, anything that needs the current code).
- `verify` runs on every login attempt. The miss case is what attackers force,
  so the gap between match and miss should stay small to avoid timing leaks.
- `Secret::from_base32` runs once per session setup; tiny anyway.

## Methodology

Median of 100 samples in a tight Rust loop, measured with
`std::time::Instant`. Re-measure with `cargo bench -p roka-totp --bench otp`.
