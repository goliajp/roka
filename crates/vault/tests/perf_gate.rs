//! Performance regression gates. See [BUDGETS.md](../BUDGETS.md).
//!
//! Run with `cargo test --release -p roka-vault --test perf_gate`.

use std::time::{Duration, Instant};

use roka_vault::aead;
use roka_vault::chacha20::ChaCha20;
use roka_vault::hmac::hmac_sha256;
use roka_vault::pbkdf2::pbkdf2_hmac_sha256;
use roka_vault::poly1305::poly1305;
use roka_vault::sha256::sha256;
use roka_vault::{Account, Vault};

const ITERS: usize = 50;
const KEY: [u8; 32] = [0xa5; 32];
const NONCE: [u8; 12] = [0x42; 12];

fn skip_in_debug() -> bool {
    if cfg!(debug_assertions) {
        eprintln!("perf_gate: debug build — skipping (run with --release)");
        return true;
    }
    false
}

fn time_median<F: FnMut()>(mut op: F) -> Duration {
    for _ in 0..5 {
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
fn sha256_1kb_under_budget() {
    if skip_in_debug() { return; }
    let data = vec![0u8; 1024];
    let median = time_median(|| {
        let _ = sha256(&data);
    });
    let budget = Duration::from_micros(6);
    assert!(median < budget, "sha256 1KB median {median:?} > {budget:?}");
}

#[test]
fn hmac_sha256_1kb_under_budget() {
    if skip_in_debug() { return; }
    let data = vec![0u8; 1024];
    let median = time_median(|| {
        let _ = hmac_sha256(&KEY, &data);
    });
    let budget = Duration::from_micros(8);
    assert!(median < budget, "hmac_sha256 1KB median {median:?} > {budget:?}");
}

#[test]
fn chacha20_1kb_under_budget() {
    if skip_in_debug() { return; }
    let median = time_median(|| {
        let mut buf = vec![0u8; 1024];
        let mut cc = ChaCha20::new(&KEY, &NONCE, 0);
        cc.apply_keystream(&mut buf);
    });
    let budget = Duration::from_micros(3);
    assert!(median < budget, "chacha20 1KB median {median:?} > {budget:?}");
}

#[test]
fn poly1305_1kb_under_budget() {
    if skip_in_debug() { return; }
    let data = vec![0u8; 1024];
    let median = time_median(|| {
        let _ = poly1305(&KEY, &data);
    });
    let budget = Duration::from_micros(1) + Duration::from_nanos(500); // 1.5 µs
    assert!(median < budget, "poly1305 1KB median {median:?} > {budget:?}");
}

#[test]
fn aead_4kb_under_budget() {
    if skip_in_debug() { return; }
    let aad = b"vault-header";
    let pt = vec![0u8; 4096];
    let median_enc = time_median(|| {
        let _ = aead::encrypt(&KEY, &NONCE, aad, &pt);
    });
    let budget = Duration::from_micros(20);
    assert!(median_enc < budget, "aead encrypt 4KB median {median_enc:?} > {budget:?}");

    let combined = aead::encrypt(&KEY, &NONCE, aad, &pt);
    let median_dec = time_median(|| {
        let _ = aead::decrypt(&KEY, &NONCE, aad, &combined);
    });
    assert!(median_dec < budget, "aead decrypt 4KB median {median_dec:?} > {budget:?}");
}

/// The load-bearing one: user unlock latency.
#[test]
fn pbkdf2_600k_under_500ms() {
    if skip_in_debug() { return; }
    // Run fewer samples since each is ~200 ms.
    const PBKDF_SAMPLES: usize = 5;
    let mut samples = Vec::with_capacity(PBKDF_SAMPLES);
    for _ in 0..PBKDF_SAMPLES {
        let start = Instant::now();
        let _ = pbkdf2_hmac_sha256(b"password", b"NaCl_salt_yum", 600_000, 32);
        samples.push(start.elapsed());
    }
    samples.sort();
    let median = samples[PBKDF_SAMPLES / 2];
    let budget = Duration::from_millis(500);
    assert!(median < budget, "pbkdf2 600k median {median:?} > {budget:?}");
}

#[test]
fn vault_seal_open_under_budget() {
    if skip_in_debug() { return; }
    let mut v = Vault::new();
    for i in 0..5 {
        v.add(Account {
            issuer: format!("Service{i}"),
            account: format!("user{i}@example.com"),
            secret: vec![0xa5; 20],
        });
    }
    let rand = [0x42u8; 28];
    let median_seal = time_median(|| {
        let _ = v.seal_with(b"password", &rand, 10_000);
    });
    let budget = Duration::from_millis(8);
    assert!(median_seal < budget, "vault seal median {median_seal:?} > {budget:?}");

    let sealed = v.seal_with(b"password", &rand, 10_000);
    let median_open = time_median(|| {
        let _ = Vault::open(&sealed, b"password").unwrap();
    });
    assert!(median_open < budget, "vault open median {median_open:?} > {budget:?}");
}
