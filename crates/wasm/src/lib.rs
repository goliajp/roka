//! WASM bindings for the Roka PWA / browser extension.
//!
//! Exposes a thin JS-shaped surface over `roka-totp` + `roka-qr`. The Rust core
//! stays zero-dep; this crate carries the only WASM-specific dependency
//! (`wasm-bindgen`) and lives at `publish = false` — it ships as the compiled
//! `.wasm` bundle, not as a crates.io artifact.

use wasm_bindgen::prelude::*;

use roka_totp::{Secret, Totp};

/// One TOTP account: secret + display metadata.
///
/// `TotpAccount` is the unit of work in the PWA — a Rust-side handle to a
/// Secret + a `Totp` config bundle. JS keeps the metadata (issuer / account
/// labels) in `localStorage`; this struct lives only for the duration of an
/// `otp_at` / `verify_at` call.
#[wasm_bindgen]
pub struct TotpAccount {
    totp: Totp,
}

#[wasm_bindgen]
impl TotpAccount {
    /// Build a `TotpAccount` from a base32 secret.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_base32: &str) -> Result<TotpAccount, JsError> {
        let secret = Secret::from_base32(secret_base32)
            .map_err(|e| JsError::new(&format!("invalid base32 secret: {e}")))?;
        let totp = Totp::builder(secret).build();
        Ok(TotpAccount { totp })
    }

    /// Compute the OTP at a given UNIX-epoch seconds timestamp.
    ///
    /// JS callers pass `Math.floor(Date.now() / 1000)` — WASM has no clock.
    pub fn otp_at(&self, unix_seconds: u64) -> String {
        self.totp.code_at(unix_seconds)
    }

    /// Seconds remaining in the current 30-second window.
    pub fn seconds_remaining_at(&self, unix_seconds: u64) -> u32 {
        self.totp.seconds_remaining_at(unix_seconds) as u32
    }
}

/// Parsed otpauth URI fields the PWA needs to populate a new account.
#[wasm_bindgen]
pub struct OtpauthFields {
    issuer: String,
    account: String,
    secret_base32: String,
}

#[wasm_bindgen]
impl OtpauthFields {
    /// Issuer label (service name).
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> String {
        self.issuer.clone()
    }

    /// Account label (typically a user identifier).
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> String {
        self.account.clone()
    }

    /// Secret, base32-encoded.
    #[wasm_bindgen(getter)]
    pub fn secret_base32(&self) -> String {
        self.secret_base32.clone()
    }
}

/// Parse an `otpauth://totp/...` URI into the fields the PWA needs.
///
/// Accepts the standard layout `otpauth://totp/{label}?secret=...&issuer=...`.
/// The label is split on `:` into issuer/account; if there's no `:`, the whole
/// label becomes the account and the `issuer` query parameter (if any) becomes
/// the issuer.
#[wasm_bindgen]
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpauthFields, JsError> {
    let stripped = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| JsError::new("not an otpauth://totp/ URI"))?;
    let (label_raw, query) = stripped.split_once('?').unwrap_or((stripped, ""));
    let label = url_decode(label_raw).ok_or_else(|| JsError::new("bad URL encoding in label"))?;

    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret = None;
    let mut query_issuer = None;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = url_decode(v).ok_or_else(|| JsError::new("bad URL encoding in query"))?;
        match k {
            "secret" => secret = Some(v),
            "issuer" => query_issuer = Some(v),
            _ => {} // ignore unknown parameters (algorithm/digits/period for now)
        }
    }
    let secret_base32 = secret.ok_or_else(|| JsError::new("missing secret= parameter"))?;
    let issuer = query_issuer.or(label_issuer).unwrap_or_default();
    Ok(OtpauthFields {
        issuer,
        account,
        secret_base32,
    })
}

fn url_decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let a = chars.next()?;
                let b = chars.next()?;
                let byte = u8::from_str_radix(&format!("{a}{b}"), 16).ok()?;
                out.push(byte as char);
            }
            '+' => out.push(' '),
            other => out.push(other),
        }
    }
    Some(out)
}
