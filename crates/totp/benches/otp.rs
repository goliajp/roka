//! Micro-benchmarks for the roka-totp hot paths.
//!
//! Run with `cargo bench -p roka-totp`. Measurements drive the budgets in
//! [`BUDGETS.md`](../BUDGETS.md) and the regression test in
//! [`tests/perf_gate.rs`](../tests/perf_gate.rs).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use roka_totp::{Secret, Totp};

const BASE32_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn bench_secret_decode(c: &mut Criterion) {
    c.bench_function("Secret::from_base32", |b| {
        b.iter(|| Secret::from_base32(black_box(BASE32_SECRET)).unwrap());
    });
}

fn bench_code_at(c: &mut Criterion) {
    let totp = Totp::builder(Secret::from_base32(BASE32_SECRET).unwrap())
        .issuer("Acme")
        .account("alice@example.com")
        .build();
    c.bench_function("Totp::code_at(0)", |b| {
        b.iter(|| totp.code_at(black_box(0)));
    });
    c.bench_function("Totp::code_at(now)", |b| {
        b.iter(|| totp.code_at(black_box(1_700_000_000)));
    });
}

fn bench_verify(c: &mut Criterion) {
    let totp = Totp::builder(Secret::from_base32(BASE32_SECRET).unwrap()).build();
    let code = totp.code_at(0);
    c.bench_function("Totp::verify_match", |b| {
        b.iter(|| totp.verify(black_box(&code), black_box(0), 1));
    });
    c.bench_function("Totp::verify_miss", |b| {
        b.iter(|| totp.verify(black_box("000000"), black_box(0), 1));
    });
}

fn bench_uri(c: &mut Criterion) {
    let totp = Totp::builder(Secret::from_base32(BASE32_SECRET).unwrap())
        .issuer("Acme")
        .account("alice@example.com")
        .build();
    c.bench_function("Totp::uri", |b| {
        b.iter(|| black_box(&totp).uri());
    });
}

criterion_group!(benches, bench_secret_decode, bench_code_at, bench_verify, bench_uri);
criterion_main!(benches);
