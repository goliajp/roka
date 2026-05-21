//! Micro-benchmarks for the roka-qr hot paths.
//!
//! Run with: `cargo bench -p roka-qr`.

use criterion::{Criterion, criterion_group, criterion_main};

// Stub — filled in by task 23.

fn bench_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| b.iter(|| 1u32 + 1));
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
