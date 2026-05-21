//! Micro-benchmarks for the roka-totp hot paths.
//!
//! Run with: `cargo bench -p roka-totp`.

use criterion::{Criterion, criterion_group, criterion_main};

// Stub — filled in by task 24.

fn bench_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| b.iter(|| 1u32 + 1));
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
