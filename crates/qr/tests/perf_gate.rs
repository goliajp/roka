//! Performance regression gates. See [BUDGETS.md](../BUDGETS.md).
//!
//! Each test runs the target operation many times, takes the median wall-clock
//! time per iteration, and asserts the median is under the budget.
//!
//! Run with `cargo test -p roka-qr --test perf_gate --release`.

use std::time::{Duration, Instant};

use roka_qr::{EcLevel, Encoder, Reader};

const ITERS: usize = 50;
const OTPAUTH_URI: &[u8] =
    b"otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme";

/// Skip the budget check in debug builds — the budgets are calibrated for
/// release-mode codegen.
fn skip_in_debug() -> bool {
    if cfg!(debug_assertions) {
        eprintln!("perf_gate: debug build — skipping (run with --release to enforce)");
        return true;
    }
    false
}

fn time_median<F: FnMut()>(mut op: F) -> Duration {
    // Warm-up
    for _ in 0..10 {
        op();
    }
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let start = Instant::now();
        op();
        samples.push(start.elapsed());
    }
    samples.sort();
    samples[ITERS / 2]
}

#[test]
fn encode_otpauth_m_under_budget() {
    if skip_in_debug() { return; }
    let median = time_median(|| {
        let _ = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    });
    let budget = Duration::from_millis(1);
    assert!(
        median < budget,
        "encode otpauth M median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn encode_otpauth_h_under_budget() {
    if skip_in_debug() { return; }
    let median = time_median(|| {
        let _ = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::H).build().unwrap();
    });
    let budget = Duration::from_micros(2500);
    assert!(
        median < budget,
        "encode otpauth H median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn render_png_under_budget() {
    if skip_in_debug() { return; }
    let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    let median = time_median(|| {
        let _ = code.render().scale(8).quiet_zone(4).build().to_png();
    });
    let budget = Duration::from_micros(1500);
    assert!(
        median < budget,
        "render+to_png median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn decode_pbm_under_budget() {
    if skip_in_debug() { return; }
    let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    let pbm = code.render().scale(4).quiet_zone(4).build().to_pbm();
    let pbm_bytes = pbm.as_bytes();
    let median = time_median(|| {
        let _ = Reader::from_pbm(pbm_bytes).unwrap();
    });
    let budget = Duration::from_micros(800);
    assert!(
        median < budget,
        "decode pbm median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn decode_png_under_budget() {
    if skip_in_debug() { return; }
    let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
    let png = code.render().scale(4).quiet_zone(4).build().to_png();
    let median = time_median(|| {
        let _ = Reader::from_png(&png).unwrap();
    });
    let budget = Duration::from_micros(1500);
    assert!(
        median < budget,
        "decode png median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn round_trip_under_budget() {
    if skip_in_debug() { return; }
    let median = time_median(|| {
        let code = Encoder::new(OTPAUTH_URI).ec_level(EcLevel::M).build().unwrap();
        let png = code.render().scale(4).quiet_zone(4).build().to_png();
        let _ = Reader::from_png(&png).unwrap();
    });
    let budget = Duration::from_millis(3);
    assert!(
        median < budget,
        "round-trip median {median:?} exceeded {budget:?}"
    );
}
