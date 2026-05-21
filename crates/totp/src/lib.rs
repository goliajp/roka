#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! Zero-dependency TOTP / HOTP implementation with optional QR code support.
//!
//! `roka-totp` is a from-scratch implementation of [RFC 6238] (TOTP) and
//! [RFC 4226] (HOTP). It carries its own SHA-1, HMAC, and Base32 — no crypto
//! crate is pulled in, no `unsafe` is used.
//!
//! # Quick start
//!
//! ```
//! use roka_totp::{Totp, Secret};
//!
//! let secret = Secret::from_base32("JBSWY3DPEHPK3PXP")?;
//! let totp = Totp::builder(secret)
//!     .issuer("Acme")
//!     .account("alice@example.com")
//!     .build();
//!
//! let code: String = totp.code_at(0); // current 6-digit OTP at UNIX time 0
//! assert_eq!(code, "282760");
//!
//! let uri = totp.uri();
//! assert!(uri.starts_with("otpauth://totp/Acme:alice"));
//! # Ok::<(), roka_totp::Error>(())
//! ```
//!
//! # Highlights
//!
//! - **Zero external crate dependencies** — `std` only.
//! - **No `unsafe`**.
//! - **RFC test vectors verified** — SHA-1 (RFC 3174), HMAC (RFC 2202), HOTP
//!   (RFC 4226 Appendix D), TOTP (RFC 6238 Appendix B).
//! - **otpauth URI build** ready for QR pairing.
//!
//! [RFC 4226]: https://datatracker.ietf.org/doc/html/rfc4226
//! [RFC 6238]: https://datatracker.ietf.org/doc/html/rfc6238

mod base32;
mod hmac;
mod hotp;
mod otpauth;
mod sha1;
mod totp;

use std::time::{SystemTime, UNIX_EPOCH};

/// Default time step in seconds (30 — the RFC 6238 standard).
pub const DEFAULT_STEP: u64 = totp::DEFAULT_STEP;
/// Default OTP digit count (6).
pub const DEFAULT_DIGITS: u32 = totp::DEFAULT_DIGITS;

/// Errors produced by `roka-totp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Base32 input was malformed.
    InvalidBase32(String),
    /// otpauth URI was malformed.
    InvalidUri(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidBase32(s) => write!(f, "invalid base32: {s}"),
            Error::InvalidUri(s) => write!(f, "invalid otpauth URI: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Hash algorithm used to derive OTPs.
///
/// Currently only SHA-1 is supported; SHA-256 / SHA-512 are reserved for a
/// future release. (The otpauth URI standard supports all three.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// SHA-1 — the RFC 6238 baseline and what every authenticator app supports.
    #[default]
    Sha1,
}

/// A TOTP / HOTP shared secret (raw bytes).
///
/// Wrap secret bytes in this newtype rather than passing `Vec<u8>` directly —
/// this prevents accidentally treating a base32 string as raw bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Decode a base32 string into a [`Secret`].
    pub fn from_base32(s: &str) -> Result<Self, Error> {
        base32::decode(s).map(Secret).map_err(Error::InvalidBase32)
    }

    /// Wrap raw secret bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Secret(bytes.into())
    }

    /// Borrow the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode the secret as base32 (no `=` padding, no grouping).
    pub fn to_base32(&self) -> String {
        let s = base32::encode(&self.0);
        s.trim_end_matches('=').to_string()
    }

    /// Encode the secret as 4-character grouped base32, easy for humans to type.
    pub fn to_base32_grouped(&self) -> String {
        base32::encode_grouped(&self.0)
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak the secret in Debug output.
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

/// HOTP — RFC 4226 counter-based one-time password.
///
/// Use this when the verifier and the prover share a monotonically increasing
/// counter (e.g. hardware token with a button). For time-synchronized OTPs use
/// [`Totp`] instead.
#[derive(Debug, Clone)]
pub struct Hotp {
    secret: Secret,
    digits: u32,
    algorithm: Algorithm,
}

impl Hotp {
    /// Create a new HOTP with default digits (6) and algorithm (SHA-1).
    pub fn new(secret: Secret) -> Self {
        Self {
            secret,
            digits: DEFAULT_DIGITS,
            algorithm: Algorithm::default(),
        }
    }

    /// Override the digit count (typically 6 or 8).
    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// OTP at the given counter.
    pub fn code_at(&self, counter: u64) -> String {
        let _ = self.algorithm; // SHA-1 only for now
        hotp::hotp(self.secret.as_bytes(), counter, self.digits)
    }
}

/// TOTP — RFC 6238 time-based one-time password.
///
/// Construct via [`Totp::builder`]. See the [module-level docs](crate) for an
/// end-to-end example.
#[derive(Debug, Clone)]
pub struct Totp {
    secret: Secret,
    issuer: String,
    account: String,
    digits: u32,
    step: u64,
    algorithm: Algorithm,
}

impl Totp {
    /// Start configuring a TOTP. Defaults: digits=6, step=30s, algorithm=SHA-1.
    pub fn builder(secret: Secret) -> TotpBuilder {
        TotpBuilder {
            secret,
            issuer: String::new(),
            account: String::new(),
            digits: DEFAULT_DIGITS,
            step: DEFAULT_STEP,
            algorithm: Algorithm::default(),
        }
    }

    /// The OTP at the given UNIX time (seconds since epoch).
    pub fn code_at(&self, unix_time: u64) -> String {
        let _ = self.algorithm;
        totp::totp(self.secret.as_bytes(), unix_time, self.step, self.digits)
    }

    /// The OTP at the current system time.
    pub fn code_now(&self) -> String {
        self.code_at(unix_now())
    }

    /// Seconds remaining in the current TOTP window at the given UNIX time.
    pub fn seconds_remaining_at(&self, unix_time: u64) -> u64 {
        totp::seconds_remaining(unix_time, self.step)
    }

    /// Seconds remaining in the current TOTP window at the current system time.
    pub fn seconds_remaining_now(&self) -> u64 {
        self.seconds_remaining_at(unix_now())
    }

    /// Verify a user-supplied code against the current window ± `window` steps.
    ///
    /// Returns `Some(offset)` where `offset` is the window difference (0 means
    /// the current window matched), or `None` if the code is invalid.
    pub fn verify(&self, code: &str, unix_time: u64, window: u32) -> Option<i64> {
        totp::verify(
            self.secret.as_bytes(),
            code,
            unix_time,
            self.step,
            self.digits,
            window as i64,
        )
    }

    /// Issuer (the service name shown in authenticator apps).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Account (the user identity shown in authenticator apps).
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The shared secret.
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Build the `otpauth://totp/` URI suitable for QR code pairing.
    pub fn uri(&self) -> String {
        otpauth::build_uri(&self.issuer, &self.account, self.secret.as_bytes())
    }
}

/// Builder for [`Totp`].
pub struct TotpBuilder {
    secret: Secret,
    issuer: String,
    account: String,
    digits: u32,
    step: u64,
    algorithm: Algorithm,
}

impl TotpBuilder {
    /// Set the issuer (service name).
    pub fn issuer(mut self, s: impl Into<String>) -> Self {
        self.issuer = s.into();
        self
    }

    /// Set the account name.
    pub fn account(mut self, s: impl Into<String>) -> Self {
        self.account = s.into();
        self
    }

    /// Override the digit count (default 6).
    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// Override the time step in seconds (default 30).
    pub fn step(mut self, step: u64) -> Self {
        self.step = step;
        self
    }

    /// Override the hash algorithm (currently SHA-1 only).
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> Totp {
        Totp {
            secret: self.secret,
            issuer: self.issuer,
            account: self.account,
            digits: self.digits,
            step: self.step,
            algorithm: self.algorithm,
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
