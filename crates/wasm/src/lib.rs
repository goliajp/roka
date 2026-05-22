//! WASM bindings for the Roka PWA / browser extension.
//!
//! Exposes a thin JS-shaped surface over `roka-totp` + `roka-qr`. The Rust core
//! stays zero-dep; this crate carries the only WASM-specific dependency
//! (`wasm-bindgen`) and lives at `publish = false` — it ships as the compiled
//! `.wasm` bundle, not as a crates.io artifact.

use wasm_bindgen::prelude::*;

use roka_totp::{Secret, Totp};
use roka_vault::{Account, Vault};

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

// ───────────────────────────── Vault wrapper ─────────────────────────────

/// PWA-side handle for an encrypted vault.
///
/// JS lifecycle:
/// 1. **First-run**: `new WasmVault()` → user picks master password →
///    `seal_initial(password, random_28b, 0)` → store bytes in localStorage.
/// 2. **Unlock**: `WasmVault.unlock(sealed_bytes, password)` derives & **caches** the
///    master key, decrypts accounts. PBKDF2 runs once here (≈ 200 ms).
/// 3. **Modify**: `add`/`add_from_uri`/`remove` → `reseal(nonce_12b)` (no PBKDF2,
///    a few ms). Caller provides 12 fresh random bytes per reseal.
/// 4. **Lock**: drop the WasmVault → cached key gone from memory.
#[wasm_bindgen]
pub struct WasmVault {
    inner: Vault,
    key: Option<[u8; 32]>,
    salt: Option<[u8; 16]>,
    iter: u32,
}

#[wasm_bindgen]
impl WasmVault {
    /// Create an empty unlocked vault in memory (no salt/key yet — `seal_initial` sets them).
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmVault {
        Self {
            inner: Vault::new(),
            key: None,
            salt: None,
            iter: 0,
        }
    }

    /// Unlock an existing sealed vault. PBKDF2 runs here (~200 ms on M2).
    /// Caches the derived key for cheap subsequent `reseal()`.
    pub fn unlock(sealed: &[u8], password: &str) -> Result<WasmVault, JsError> {
        let (salt, iter) = Vault::read_header(sealed).map_err(|e| JsError::new(&e.to_string()))?;
        let key = Vault::derive_key(password.as_bytes(), &salt, iter);
        let inner = Vault::open_with_key(sealed, &key).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(WasmVault {
            inner,
            key: Some(key),
            salt: Some(salt),
            iter,
        })
    }

    /// First-time seal: derives a fresh key from `password` + the salt in `random_28b[..16]`,
    /// then seals using `random_28b[16..28]` as nonce. Caches the key for `reseal`.
    /// `iterations = 0` means use the library default (600 000).
    pub fn seal_initial(
        &mut self,
        password: &str,
        random_28b: &[u8],
        iterations: u32,
    ) -> Result<Vec<u8>, JsError> {
        if random_28b.len() != 28 {
            return Err(JsError::new("random_28b must be exactly 28 bytes"));
        }
        let mut rand = [0u8; 28];
        rand.copy_from_slice(random_28b);
        let iter = if iterations == 0 { roka_vault::DEFAULT_ITERATIONS } else { iterations };
        let bytes = self.inner.seal_with(password.as_bytes(), &rand, iter);
        let salt: [u8; 16] = rand[..16].try_into().unwrap();
        let key = Vault::derive_key(password.as_bytes(), &salt, iter);
        self.key = Some(key);
        self.salt = Some(salt);
        self.iter = iter;
        Ok(bytes)
    }

    /// Re-seal an already-unlocked vault using the cached key. `nonce_12b` must be
    /// 12 fresh random bytes. **Will fail** if vault is locked.
    pub fn reseal(&self, nonce_12b: &[u8]) -> Result<Vec<u8>, JsError> {
        let key = self.key.as_ref().ok_or_else(|| JsError::new("vault is locked"))?;
        let salt = self.salt.as_ref().ok_or_else(|| JsError::new("vault is locked"))?;
        if nonce_12b.len() != 12 {
            return Err(JsError::new("nonce_12b must be exactly 12 bytes"));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_12b);
        Ok(self.inner.seal_with_key(key, salt, self.iter, &nonce))
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.inner.accounts().len()
    }

    /// Issuer for account at `index`. Empty string if out of bounds.
    pub fn issuer(&self, index: usize) -> String {
        self.inner.accounts().get(index).map(|a| a.issuer.clone()).unwrap_or_default()
    }

    /// Account label for account at `index`. Empty string if out of bounds.
    pub fn account_label(&self, index: usize) -> String {
        self.inner.accounts().get(index).map(|a| a.account.clone()).unwrap_or_default()
    }

    /// OTP at `unix_seconds` for account `index`.
    pub fn otp_at(&self, index: usize, unix_seconds: u64) -> Result<String, JsError> {
        let a = self.inner.accounts().get(index).ok_or_else(|| JsError::new("index out of bounds"))?;
        let totp = Totp::builder(Secret::from_bytes(a.secret.clone())).build();
        Ok(totp.code_at(unix_seconds))
    }

    /// Add an account from explicit fields (`secret_base32` is decoded).
    pub fn add(&mut self, issuer: &str, account: &str, secret_base32: &str) -> Result<(), JsError> {
        let secret = Secret::from_base32(secret_base32)
            .map_err(|e| JsError::new(&format!("invalid base32 secret: {e}")))?;
        self.inner.add(Account {
            issuer: issuer.to_string(),
            account: account.to_string(),
            secret: secret.as_bytes().to_vec(),
        });
        Ok(())
    }

    /// Add an account from an `otpauth://` URI.
    pub fn add_from_uri(&mut self, uri: &str) -> Result<(), JsError> {
        let a = Account::from_otpauth_uri(uri).map_err(|e| JsError::new(&e.to_string()))?;
        self.inner.add(a);
        Ok(())
    }

    /// Remove account by index. Returns `false` if out of bounds.
    pub fn remove(&mut self, index: usize) -> bool {
        self.inner.remove(index)
    }
}
