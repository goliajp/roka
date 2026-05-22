//! Micro-benchmarks for the vault crypto primitives.
//!
//! Run with `cargo bench -p roka-vault`. These drive `BUDGETS.md` and the
//! perf gate in `tests/perf_gate.rs`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use roka_vault::aead;
use roka_vault::chacha20::ChaCha20;
use roka_vault::hmac::hmac_sha256;
use roka_vault::pbkdf2::pbkdf2_hmac_sha256;
use roka_vault::poly1305::poly1305;
use roka_vault::sha256::sha256;
use roka_vault::{Account, Vault};

const KEY: [u8; 32] = [0xa5; 32];
const NONCE: [u8; 12] = [0x42; 12];

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [64usize, 1024, 16 * 1024] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &data, |b, d| {
            b.iter(|| sha256(black_box(d)));
        });
    }
    group.finish();
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha256");
    for size in [32usize, 1024] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &data, |b, d| {
            b.iter(|| hmac_sha256(black_box(&KEY), black_box(d)));
        });
    }
    group.finish();
}

fn bench_pbkdf2(c: &mut Criterion) {
    let mut group = c.benchmark_group("pbkdf2_sha256");
    for iter in [10_000u32, 100_000, 600_000] {
        group.bench_with_input(BenchmarkId::new("iter", iter), &iter, |b, &it| {
            b.iter(|| pbkdf2_hmac_sha256(black_box(b"password"), black_box(b"NaCl_salt_yum"), it, 32));
        });
    }
    group.finish();
}

fn bench_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20");
    for size in [64usize, 1024, 16 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &n| {
            b.iter(|| {
                let mut buf = vec![0u8; n];
                let mut cc = ChaCha20::new(black_box(&KEY), black_box(&NONCE), 0);
                cc.apply_keystream(&mut buf);
                black_box(buf);
            });
        });
    }
    group.finish();
}

fn bench_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly1305");
    for size in [64usize, 1024, 16 * 1024] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &data, |b, d| {
            b.iter(|| poly1305(black_box(&KEY), black_box(d)));
        });
    }
    group.finish();
}

fn bench_aead_round_trip(c: &mut Criterion) {
    let aad = b"vault-header";
    let pt = vec![0u8; 4096];
    c.bench_function("aead/encrypt_4KB", |b| {
        b.iter(|| aead::encrypt(black_box(&KEY), black_box(&NONCE), black_box(aad), black_box(&pt)));
    });
    let combined = aead::encrypt(&KEY, &NONCE, aad, &pt);
    c.bench_function("aead/decrypt_4KB", |b| {
        b.iter(|| aead::decrypt(black_box(&KEY), black_box(&NONCE), black_box(aad), black_box(&combined)));
    });
}

fn bench_vault_seal_open(c: &mut Criterion) {
    // 5 typical accounts, like a real personal vault.
    let mut v = Vault::new();
    for i in 0..5 {
        v.add(Account {
            issuer: format!("Service{i}"),
            account: format!("user{i}@example.com"),
            secret: vec![0xa5; 20],
        });
    }
    let rand = [0x42u8; 28];
    // Sealing dominated by PBKDF2; benchmark with low iterations so each
    // iteration of criterion fits in seconds. Real PBKDF2 cost is benched
    // separately in `bench_pbkdf2`.
    c.bench_function("vault/seal_10k_iter", |b| {
        b.iter(|| v.seal_with(black_box(b"password"), black_box(&rand), 10_000));
    });
    let sealed = v.seal_with(b"password", &rand, 10_000);
    c.bench_function("vault/open_10k_iter", |b| {
        b.iter(|| Vault::open(black_box(&sealed), black_box(b"password")).unwrap());
    });
}

criterion_group!(
    benches,
    bench_sha256,
    bench_hmac_sha256,
    bench_pbkdf2,
    bench_chacha20,
    bench_poly1305,
    bench_aead_round_trip,
    bench_vault_seal_open
);
criterion_main!(benches);
