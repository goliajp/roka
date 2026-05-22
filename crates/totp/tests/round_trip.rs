//! Integration tests for the full TOTP / HOTP pipeline.

use roka_totp::{Hotp, Secret, Totp};

#[test]
fn rfc6238_appendix_b_sha1_vectors() {
    // RFC 6238 Appendix B — TOTP test values (T0=0, step=30, SHA-1).
    // Secret is "12345678901234567890" → base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
    let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let totp = Totp::builder(secret).digits(8).build();
    // Each (T, expected 8-digit code)
    let cases = [
        (59u64, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];
    for (t, expected) in cases {
        assert_eq!(totp.code_at(t), expected, "T={t}");
    }
}

#[test]
fn rfc4226_appendix_d_hotp_vectors() {
    // RFC 4226 Appendix D — counter 0..9, secret "12345678901234567890".
    let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let hotp = Hotp::new(secret);
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, exp) in expected.iter().enumerate() {
        assert_eq!(hotp.code_at(counter as u64), *exp, "counter {counter}");
    }
}

#[test]
fn code_is_correct_digit_count() {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    for digits in [6u32, 7, 8] {
        let totp = Totp::builder(secret.clone()).digits(digits).build();
        let code = totp.code_at(0);
        assert_eq!(code.len(), digits as usize, "digits={digits}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn verify_accepts_match_and_neighbors_within_window() {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let totp = Totp::builder(secret).build();
    let t = 1_700_000_000u64;
    let code_now = totp.code_at(t);
    let code_prev = totp.code_at(t - 30);
    let code_next = totp.code_at(t + 30);
    let code_far = totp.code_at(t + 90);

    assert_eq!(totp.verify(&code_now, t, 1), Some(0));
    assert_eq!(totp.verify(&code_prev, t, 1), Some(-1));
    assert_eq!(totp.verify(&code_next, t, 1), Some(1));
    // Outside ±1 window
    assert_eq!(totp.verify(&code_far, t, 1), None);
    // Wider window catches it
    assert_eq!(totp.verify(&code_far, t, 3), Some(3));
}

#[test]
fn verify_rejects_wrong_code() {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let totp = Totp::builder(secret).build();
    assert_eq!(totp.verify("000000", 0, 5), None);
    assert_eq!(totp.verify("not-a-code", 0, 5), None);
}

#[test]
fn uri_contains_required_fields() {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let totp = Totp::builder(secret)
        .issuer("Acme")
        .account("alice@example.com")
        .build();
    let uri = totp.uri();
    assert!(uri.starts_with("otpauth://totp/Acme:"));
    assert!(uri.contains("secret="));
    assert!(uri.contains("issuer=Acme"));
}

#[test]
fn secret_rejects_invalid_base32() {
    assert!(Secret::from_base32("definitely not base32!").is_err());
    assert!(Secret::from_base32("").is_ok()); // empty is valid (zero bytes)
}

#[test]
fn secret_debug_does_not_leak_bytes() {
    let secret = Secret::from_bytes(b"super-secret-key".to_vec());
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains("super-secret"), "Debug leaked secret bytes");
    assert!(dbg.contains("16 bytes"));
}

#[test]
fn seconds_remaining_is_in_window() {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let totp = Totp::builder(secret).step(30).build();
    for t in [0u64, 29, 30, 31, 100, 1_700_000_000] {
        let r = totp.seconds_remaining_at(t);
        assert!(r >= 1 && r <= 30, "t={t} remaining={r}");
    }
}
