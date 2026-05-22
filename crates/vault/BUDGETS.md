# roka-vault performance budgets

Enforced by `tests/perf_gate.rs`. Run `cargo test -p roka-vault --release --test perf_gate`.

Budgets sit at **~2× the best observed local number** for hot primitives, and
**1.5× for PBKDF2** (since user-facing unlock latency is the budget that matters
most to the product).

## Hot paths

| Path | Budget | Best observed (M2, release) | Headroom |
| --- | ---: | ---: | ---: |
| `sha256` (1 KB) | 6 µs | ~2.9 µs | ~2× |
| `hmac_sha256` (1 KB) | 8 µs | ~3.5 µs | ~2× |
| `chacha20` keystream (1 KB) | 3 µs | ~1.3 µs | ~2× |
| `poly1305` (1 KB) | 1.5 µs | ~530 ns | ~3× |
| `aead::encrypt` (4 KB) | 20 µs | ~7.6 µs | ~3× |
| `aead::decrypt` (4 KB) | 20 µs | ~7.2 µs | ~3× |
| **`pbkdf2_hmac_sha256` (600k iter)** | **500 ms** | **~216 ms** | **~2.3×** |
| `Vault::seal` (5 accounts @ 10k iter) | 8 ms | ~3.5 ms | ~2× |
| `Vault::open` (5 accounts @ 10k iter) | 8 ms | ~3.6 ms | ~2× |

The **PBKDF2 600k budget is the load-bearing one** — it's the time the user
waits between typing the master password and seeing accounts. Anything past
500 ms feels broken; anything below 200 ms feels instant. We currently sit
just inside the latter on M2.

## Throughput in human terms

- SHA-256: ≈ 350 MB/s — fast enough that for any realistic vault size the hash
  is a rounding error.
- ChaCha20: ≈ 800 MB/s — same.
- Poly1305: ≈ 2 GB/s — basically free.

So the only knob worth tuning is iteration count, not the primitives.

## Methodology

Median of 50 samples in a tight Rust loop, measured with `std::time::Instant`.
Re-measure with `cargo bench -p roka-vault --bench crypto`.

The PBKDF2 gate **only runs in release mode** — see `tests/perf_gate.rs` for
the `cfg!(debug_assertions)` skip. Debug PBKDF2 is ~10-30× slower and would
either need an inflated budget or skipping.
