# roka

> コインロッカー — deposit a secret, retrieve a one-time code.

**Roka** is a 2FA authenticator product. The product binary lives in this
repository alongside the open-source library crates it's built on.

## Layout

```
roka/
├── crates/
│   ├── qr/            ← published as `roka-qr` on crates.io
│   ├── totp/          ← published as `roka-totp` on crates.io
│   └── app/           ← the `roka` product binary (publish = false; coming next)
└── Cargo.toml         ← workspace root
```

## Crates

| Crate | Published | What it does |
|-------|-----------|--------------|
| [`roka-qr`](crates/qr/) | ✅ crates.io | Zero-dependency QR encoder + decoder with built-in PNG/PBM I/O. |
| [`roka-totp`](crates/totp/) | ✅ crates.io | Zero-dependency TOTP / HOTP with optional QR code generation and scanning (via `roka-qr`). |
| [`roka-vault`](crates/vault/) | crates.io (planned) | Encrypted vault for TOTP secrets — self-implemented SHA-256, ChaCha20-Poly1305, PBKDF2 (≥ 600 000 iter). All primitives validated against RFC / NIST vectors + cross-checked with `pyca/cryptography`. |
| [`roka-wasm`](crates/wasm/) | internal (`publish = false`) | wasm-bindgen surface around the three crates above; the deployable artifact is the `.wasm` bundle in [`web/pkg/`](web/pkg/). |
| `roka` | ❌ binary | The product itself — CLI now, possibly GUI later. Uses both crates above. |

## PWA (v1.0-β)

A WASM-powered static PWA lives in [`web/`](web/). Encrypted vault: master
password derives a key (PBKDF2-SHA-256, 600 000 iter), accounts encrypted at
rest with ChaCha20-Poly1305. Live at <https://goliajp.github.io/roka/>.

```bash
# Build the WASM bundle (one-time / on changes)
./web/build.sh

# Serve locally
cd web && python3 -m http.server 6003
# → open http://127.0.0.1:6003
```

**Security**: `localStorage` holds only AEAD-encrypted bytes. Any tampering
with the header (salt / iter / nonce) or ciphertext causes decryption to
fail. Master password cannot be recovered if lost.

> Self-implemented cryptography — see [`crates/vault/README.md`](crates/vault/README.md)
> for the risk note. Algorithms pass standard test vectors but have not received
> a formal third-party audit.

## Status

🚧 **0.0.1 placeholder releases only.** The real 0.1.0 ships after API polish.
Working prototype lives in the
[`lab10-2fa`](https://github.com/goliajp/labs) experimental lab.

## Goals for the library crates

- **Zero external crate dependencies.** Only `std`.
- **No unsafe.**
- **Encode + decode in one crate** — fills a gap on crates.io.
- **Audit-friendly code** with detailed comments.
- **Round-trip tested** against `qrencode` and `zbarimg`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option.

Brought to you by [GOLIA Inc.](https://github.com/goliajp)
