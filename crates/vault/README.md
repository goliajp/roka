# roka-vault

Zero-dependency encrypted vault for TOTP secrets. Self-implemented SHA-256,
HMAC-SHA-256, PBKDF2, ChaCha20-Poly1305 — all validated against RFC / NIST test
vectors.

> ⚠️ **Self-implemented cryptography**. The primitives pass the published
> standard test vectors and cross-tool checks against `openssl` /
> `pyca/cryptography`, but have not received a formal third-party audit. Use
> for personal / non-critical applications.

## License

Dual-licensed under MIT or Apache 2.0.
