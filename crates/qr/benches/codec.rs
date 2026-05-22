//! Micro-benchmarks for the roka-qr hot paths.
//!
//! Run with `cargo bench -p roka-qr`. Measurements drive the budgets in
//! [`BUDGETS.md`](../BUDGETS.md) and the regression test in
//! [`tests/perf_gate.rs`](../tests/perf_gate.rs).
//!
//! Hot paths exercised here (in approximate order of expense per QR operation):
//!
//! - `Encoder::build` — full encode (URI → module matrix)
//! - `code.render().build()` — matrix → bitmap (scale + quiet zone)
//! - `bitmap.to_png()` — bitmap → PNG bytes (stored DEFLATE blocks)
//! - `Reader::from_png` — PNG → module matrix → payload
//! - `Reader::from_pbm` — PBM → module matrix → payload (no DEFLATE)

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use roka_qr::{EcLevel, Encoder, Reader};

const SHORT_URI: &[u8] = b"https://example.com";
const OTPAUTH_URI: &[u8] =
    b"otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme";

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for (label, payload) in [("short_uri", SHORT_URI), ("otpauth_uri", OTPAUTH_URI)] {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        for ec in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
            group.bench_with_input(
                BenchmarkId::new(label, format!("{ec:?}")),
                &(payload, ec),
                |b, &(p, ec)| {
                    b.iter(|| Encoder::new(black_box(p)).ec_level(ec).build().unwrap());
                },
            );
        }
    }
    group.finish();
}

fn bench_render_png(c: &mut Criterion) {
    let mut group = c.benchmark_group("render_png");
    let code_l = Encoder::new(OTPAUTH_URI)
        .ec_level(EcLevel::L)
        .build()
        .unwrap();
    let code_h = Encoder::new(OTPAUTH_URI)
        .ec_level(EcLevel::H)
        .build()
        .unwrap();
    for (label, code) in [("M-sized_L", &code_l), ("M-sized_H", &code_h)] {
        group.bench_function(BenchmarkId::new("render", label), |b| {
            b.iter(|| black_box(code).render().scale(8).quiet_zone(4).build());
        });
        let bitmap = code.render().scale(8).quiet_zone(4).build();
        group.bench_function(BenchmarkId::new("to_png", label), |b| {
            b.iter(|| black_box(&bitmap).to_png());
        });
    }
    group.finish();
}

fn bench_decode_pbm(c: &mut Criterion) {
    let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    let bitmap = code.render().scale(4).quiet_zone(4).build();
    let pbm_text = bitmap.to_pbm();
    let pbm_bytes = pbm_text.as_bytes();
    c.bench_function("decode/pbm/otpauth_M", |b| {
        b.iter(|| Reader::from_pbm(black_box(pbm_bytes)).unwrap());
    });
}

fn bench_decode_png(c: &mut Criterion) {
    let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    let bitmap = code.render().scale(4).quiet_zone(4).build();
    let png_bytes = bitmap.to_png();
    c.bench_function("decode/png/otpauth_M", |b| {
        b.iter(|| Reader::from_png(black_box(&png_bytes)).unwrap());
    });
}

fn bench_round_trip(c: &mut Criterion) {
    c.bench_function("round_trip/otpauth_M_png", |b| {
        b.iter(|| {
            let code = Encoder::new(black_box(OTPAUTH_URI))
                .ec_level(EcLevel::M)
                .build()
                .unwrap();
            let bitmap = code.render().scale(4).quiet_zone(4).build();
            let png = bitmap.to_png();
            Reader::from_png(&png).unwrap()
        });
    });
}

criterion_group!(
    benches,
    bench_encode,
    bench_render_png,
    bench_decode_pbm,
    bench_decode_png,
    bench_round_trip
);
criterion_main!(benches);
