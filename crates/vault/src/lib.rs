#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! `roka-vault` — zero-dependency encrypted vault for TOTP secrets.
//!
//! Self-implemented cryptography (every primitive has standard test vectors):
//!
//! - **SHA-256** (FIPS 180-4) — hash
//! - **HMAC-SHA-256** (RFC 4231) — MAC
//! - **PBKDF2-HMAC-SHA-256** (RFC 6070-style) — password-based key derivation
//! - **ChaCha20** (RFC 8439) — stream cipher
//! - **Poly1305** (RFC 8439) — MAC
//! - **ChaCha20-Poly1305 AEAD** (RFC 8439) — combined encryption + authentication
//!
//! Designed for the Roka authenticator product but the lower-level primitive
//! modules are usable on their own.
//!
//! # Risk note
//!
//! Self-implemented cryptography is **not a substitute for audited libraries**
//! for high-stakes deployments. This crate's primitives are validated against
//! the published RFC / NIST test vectors and pass cross-tool checks against
//! `openssl` / `pyca/cryptography`, but they have not received a formal audit.
//! Use for personal / non-critical applications; for production secret
//! handling consider RustCrypto.

pub mod account;
pub mod aead;
pub mod chacha20;
pub mod hmac;
pub mod pbkdf2;
pub mod poly1305;
pub mod sha256;
pub mod vault;

pub use account::OtpauthError;
pub use vault::{Account, Vault, VaultError, DEFAULT_ITERATIONS};
// upcoming modules will land here as the β checkpoint progresses:
// pub mod pbkdf2;
// pub mod chacha20;
// pub mod poly1305;
// pub mod aead;
// pub mod vault;
// pub mod account;
