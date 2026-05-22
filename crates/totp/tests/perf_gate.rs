//! Performance regression gates. See [BUDGETS.md](../BUDGETS.md).

use std::time::{Duration, Instant};

use roka_totp::{Secret, Totp};

const ITERS: usize = 100;
const BASE32: &str = "JBSWY3DPEHPK3PXP";

/// Skip the budget check in debug builds — budgets are calibrated for release.
fn skip_in_debug() -> bool {
    if cfg!(debug_assertions) {
        eprintln!("perf_gate: debug build — skipping (run with --release to enforce)");
        return true;
    }
    false
}

fn time_median<F: FnMut()>(mut op: F) -> Duration {
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
fn secret_decode_under_budget() {
    if skip_in_debug() { return; }
    let median = time_median(|| {
        let _ = Secret::from_base32(BASE32).unwrap();
    });
    let budget = Duration::from_micros(5);
    assert!(
        median < budget,
        "Secret::from_base32 median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn code_at_under_budget() {
    if skip_in_debug() { return; }
    let totp = Totp::builder(Secret::from_base32(BASE32).unwrap()).build();
    let median = time_median(|| {
        let _ = totp.code_at(1_700_000_000);
    });
    let budget = Duration::from_micros(10);
    assert!(
        median < budget,
        "Totp::code_at median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn verify_match_under_budget() {
    if skip_in_debug() { return; }
    let totp = Totp::builder(Secret::from_base32(BASE32).unwrap()).build();
    let code = totp.code_at(0);
    let median = time_median(|| {
        let _ = totp.verify(&code, 0, 1);
    });
    let budget = Duration::from_micros(20);
    assert!(
        median < budget,
        "Totp::verify (match) median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn verify_miss_under_budget() {
    if skip_in_debug() { return; }
    let totp = Totp::builder(Secret::from_base32(BASE32).unwrap()).build();
    let median = time_median(|| {
        let _ = totp.verify("000000", 0, 1);
    });
    let budget = Duration::from_micros(20);
    assert!(
        median < budget,
        "Totp::verify (miss) median {median:?} exceeded {budget:?}"
    );
}

#[test]
fn uri_under_budget() {
    if skip_in_debug() { return; }
    let totp = Totp::builder(Secret::from_base32(BASE32).unwrap())
        .issuer("Acme")
        .account("alice@example.com")
        .build();
    let median = time_median(|| {
        let _ = totp.uri();
    });
    let budget = Duration::from_micros(10);
    assert!(
        median < budget,
        "Totp::uri median {median:?} exceeded {budget:?}"
    );
}
