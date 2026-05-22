//! Vault 文件格式 + 顶层 Vault API。
//!
//! # 容器格式（v1）
//!
//! ```text
//!   0  ROKA-V01  (8 字节 magic)
//!   8  algo_id   (1 字节: 1 = PBKDF2-SHA256 + ChaCha20-Poly1305)
//!   9  reserved  (7 字节, must be 0; 将来留给算法变体)
//!  16  salt      (16 字节, PBKDF2 salt)
//!  32  iter_be   (4 字节 BE, PBKDF2 iterations)
//!  36  nonce     (12 字节, ChaCha20-Poly1305 nonce)
//!  48  ciphertext + tag (变长，tag 是末尾 16 字节)
//! ```
//!
//! AEAD 的 AAD = **整个前 48 字节 header**，保证 magic / salt / iter / nonce 任意篡改都会
//! 触发解密失败。
//!
//! # 明文 payload 格式（一个简单 len-prefixed 二进制 schema，不依赖 serde）
//!
//! ```text
//!   u32_le    版本号 = 1（本字段 distinct from container version）
//!   u32_le    accounts.len
//!   for each account:
//!     u16_le  issuer.len
//!     bytes   issuer (UTF-8)
//!     u16_le  account.len
//!     bytes   account (UTF-8)
//!     u16_le  secret.len
//!     bytes   secret (raw bytes — 通常 20)
//! ```

use core::convert::TryInto;

use super::aead;
use super::pbkdf2::pbkdf2_hmac_sha256;

const MAGIC: &[u8; 8] = b"ROKA-V01";
const ALGO_PBKDF2_CC20P1305: u8 = 1;
const HEADER_LEN: usize = 48;
const PAYLOAD_VERSION: u32 = 1;

/// 默认 PBKDF2 迭代数（OWASP 2024 PBKDF2-SHA256 推荐）。可以被 `seal_with` 覆盖。
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// 一个 TOTP 账户。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// 服务名，例如 "GitHub" / "Acme"。
    pub issuer: String,
    /// 账户名，例如 "alice@example.com"。
    pub account: String,
    /// **原始字节** secret（不是 base32）。HOTP/TOTP 算法直接消费。
    pub secret: Vec<u8>,
}

/// Vault 错误。粒度刻意粗——攻击者不该获得区分 "MAC 不对" 和 "格式不对" 的辨别信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// File 头部 magic 不对、长度太短、reserved 字段非零、版本不识别。
    Malformed,
    /// 密文 AEAD 校验失败（密码错 / 文件被改）。
    Auth,
    /// Payload 反序列化失败（密文是对的但内部格式 broken）——通常意味着版本不兼容。
    Payload,
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VaultError::Malformed => f.write_str("vault file malformed"),
            VaultError::Auth => f.write_str("vault authentication failed (bad password or tampered file)"),
            VaultError::Payload => f.write_str("vault payload is unrecognized"),
        }
    }
}

impl std::error::Error for VaultError {}

/// 解密后的账户集合。
#[derive(Debug, Clone, Default)]
pub struct Vault {
    accounts: Vec<Account>,
}

impl Vault {
    /// 新建空 vault。
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前账户列表。
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// 添加一个账户（追加到末尾）。
    pub fn add(&mut self, a: Account) {
        self.accounts.push(a);
    }

    /// 删除第 `index` 个账户。越界返回 false。
    pub fn remove(&mut self, index: usize) -> bool {
        if index >= self.accounts.len() {
            return false;
        }
        self.accounts.remove(index);
        true
    }

    /// 解密 vault 文件字节。
    pub fn open(bytes: &[u8], password: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN + 16 {
            return Err(VaultError::Malformed);
        }
        if &bytes[0..8] != MAGIC {
            return Err(VaultError::Malformed);
        }
        if bytes[8] != ALGO_PBKDF2_CC20P1305 {
            return Err(VaultError::Malformed);
        }
        if bytes[9..16] != [0u8; 7] {
            return Err(VaultError::Malformed);
        }
        let salt: [u8; 16] = bytes[16..32].try_into().unwrap();
        let iter = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        if iter == 0 {
            return Err(VaultError::Malformed);
        }
        let nonce: [u8; 12] = bytes[36..48].try_into().unwrap();
        let aad = &bytes[..HEADER_LEN];
        let body = &bytes[HEADER_LEN..];

        let key_bytes = pbkdf2_hmac_sha256(password, &salt, iter, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let pt = aead::decrypt(&key, &nonce, aad, body).map_err(|_| VaultError::Auth)?;
        let accounts = parse_payload(&pt).ok_or(VaultError::Payload)?;
        Ok(Self { accounts })
    }

    /// 加密 vault 到字节。`random` 提供 16 字节 salt + 12 字节 nonce（由调用方填，
    /// 因为本 crate 不假定 RNG——WASM 调用方传 `crypto.getRandomValues`，CLI 传
    /// `/dev/urandom`）。`iterations` 决定 PBKDF2 强度。
    pub fn seal_with(
        &self,
        password: &[u8],
        random: &[u8; 28],
        iterations: u32,
    ) -> Vec<u8> {
        assert!(iterations > 0, "iterations must be > 0");
        let salt: [u8; 16] = random[..16].try_into().unwrap();
        let nonce: [u8; 12] = random[16..28].try_into().unwrap();

        let mut header = [0u8; HEADER_LEN];
        header[0..8].copy_from_slice(MAGIC);
        header[8] = ALGO_PBKDF2_CC20P1305;
        // header[9..16] left as zeros (reserved)
        header[16..32].copy_from_slice(&salt);
        header[32..36].copy_from_slice(&iterations.to_be_bytes());
        header[36..48].copy_from_slice(&nonce);

        let payload = encode_payload(&self.accounts);
        let key_bytes = pbkdf2_hmac_sha256(password, &salt, iterations, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let ct_and_tag = aead::encrypt(&key, &nonce, &header, &payload);

        let mut out = Vec::with_capacity(HEADER_LEN + ct_and_tag.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct_and_tag);
        out
    }

    /// 用默认迭代次数加密。
    pub fn seal(&self, password: &[u8], random: &[u8; 28]) -> Vec<u8> {
        self.seal_with(password, random, DEFAULT_ITERATIONS)
    }

    /// 派生主密钥（昂贵：PBKDF2 600k iter ≈ 200ms on M2）。返回 (key, salt, iter)。
    ///
    /// 设计意图：UI 调用方持有这个三元组直到 lock，期间任何 seal 都可直接用 `seal_with_key`
    /// 跳过 PBKDF2（毫秒级而非 200ms）。
    pub fn derive_key(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
        let k = pbkdf2_hmac_sha256(password, salt, iterations, 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&k);
        out
    }

    /// 用已派生的 key 打开 vault。读 header 拿 salt/iter/nonce，但不 re-do PBKDF2。
    /// **风险**：调用方必须保证 `key` 是 `(password, salt, iter)` 派生出的——错 key
    /// 会 AEAD 失败但不会泄露。
    pub fn open_with_key(bytes: &[u8], key: &[u8; 32]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN + 16 {
            return Err(VaultError::Malformed);
        }
        if &bytes[0..8] != MAGIC
            || bytes[8] != ALGO_PBKDF2_CC20P1305
            || bytes[9..16] != [0u8; 7]
        {
            return Err(VaultError::Malformed);
        }
        let nonce: [u8; 12] = bytes[36..48].try_into().unwrap();
        let aad = &bytes[..HEADER_LEN];
        let body = &bytes[HEADER_LEN..];
        let pt = aead::decrypt(key, &nonce, aad, body).map_err(|_| VaultError::Auth)?;
        let accounts = parse_payload(&pt).ok_or(VaultError::Payload)?;
        Ok(Self { accounts })
    }

    /// 用已派生的 key + 现成 salt/iter 加密。只需 16 字节随机 (nonce)，跳过 PBKDF2。
    pub fn seal_with_key(
        &self,
        key: &[u8; 32],
        salt: &[u8; 16],
        iterations: u32,
        nonce: &[u8; 12],
    ) -> Vec<u8> {
        let mut header = [0u8; HEADER_LEN];
        header[0..8].copy_from_slice(MAGIC);
        header[8] = ALGO_PBKDF2_CC20P1305;
        header[16..32].copy_from_slice(salt);
        header[32..36].copy_from_slice(&iterations.to_be_bytes());
        header[36..48].copy_from_slice(nonce);

        let payload = encode_payload(&self.accounts);
        let ct_and_tag = aead::encrypt(key, nonce, &header, &payload);

        let mut out = Vec::with_capacity(HEADER_LEN + ct_and_tag.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct_and_tag);
        out
    }

    /// 拿出 header 里的 (salt, iterations) — 让调用方在 open 后用 derive_key + 缓存。
    pub fn read_header(bytes: &[u8]) -> Result<([u8; 16], u32), VaultError> {
        if bytes.len() < HEADER_LEN
            || &bytes[0..8] != MAGIC
            || bytes[8] != ALGO_PBKDF2_CC20P1305
            || bytes[9..16] != [0u8; 7]
        {
            return Err(VaultError::Malformed);
        }
        let salt: [u8; 16] = bytes[16..32].try_into().unwrap();
        let iter = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        if iter == 0 {
            return Err(VaultError::Malformed);
        }
        Ok((salt, iter))
    }
}

/// 序列化账户列表为 payload 字节流。
fn encode_payload(accounts: &[Account]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
    out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for a in accounts {
        push_short_bytes(&mut out, a.issuer.as_bytes());
        push_short_bytes(&mut out, a.account.as_bytes());
        push_short_bytes(&mut out, &a.secret);
    }
    out
}

fn push_short_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() <= u16::MAX as usize, "field too long for vault encoding");
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// 反序列化 payload → 账户列表。任何越界返回 None。
fn parse_payload(bytes: &[u8]) -> Option<Vec<Account>> {
    let mut cur = bytes;
    let ver = take_u32_le(&mut cur)?;
    if ver != PAYLOAD_VERSION {
        return None;
    }
    let n = take_u32_le(&mut cur)? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let issuer = String::from_utf8(take_short_bytes(&mut cur)?.to_vec()).ok()?;
        let account = String::from_utf8(take_short_bytes(&mut cur)?.to_vec()).ok()?;
        let secret = take_short_bytes(&mut cur)?.to_vec();
        out.push(Account { issuer, account, secret });
    }
    if !cur.is_empty() {
        return None; // trailing garbage = format error
    }
    Some(out)
}

fn take_u32_le(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let (h, rest) = cur.split_at(4);
    *cur = rest;
    Some(u32::from_le_bytes(h.try_into().unwrap()))
}

fn take_short_bytes<'a>(cur: &mut &'a [u8]) -> Option<&'a [u8]> {
    if cur.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes(cur[..2].try_into().unwrap()) as usize;
    *cur = &cur[2..];
    if cur.len() < len {
        return None;
    }
    let (h, rest) = cur.split_at(len);
    *cur = rest;
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand28(seed: u64) -> [u8; 28] {
        // Deterministic "rand" for tests — never use in real seal().
        let mut s = seed;
        let mut out = [0u8; 28];
        for b in out.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (s >> 56) as u8;
        }
        out
    }

    /// Round-trip: seal + open with right password = identical accounts.
    #[test]
    fn round_trip_simple() {
        let mut v = Vault::new();
        v.add(Account {
            issuer: "GitHub".into(),
            account: "alice@example.com".into(),
            secret: vec![0xa5; 20],
        });
        v.add(Account {
            issuer: "Acme".into(),
            account: "bob".into(),
            secret: b"some-other-secret-bytes".to_vec(),
        });
        let sealed = v.seal_with(b"correct horse battery staple", &rand28(1), 10_000);
        let opened = Vault::open(&sealed, b"correct horse battery staple").unwrap();
        assert_eq!(opened.accounts(), v.accounts());
    }

    /// 错密码 → Auth 错误，不区分错在哪。
    #[test]
    fn wrong_password_rejected() {
        let mut v = Vault::new();
        v.add(Account {
            issuer: "x".into(),
            account: "y".into(),
            secret: vec![1, 2, 3],
        });
        let sealed = v.seal_with(b"secret123", &rand28(2), 1_000);
        assert_eq!(Vault::open(&sealed, b"secret124").err(), Some(VaultError::Auth));
        assert_eq!(Vault::open(&sealed, b"").err(), Some(VaultError::Auth));
    }

    /// 篡改 1 个 header byte → Auth 失败（因为 header 是 AEAD 的 AAD）。
    #[test]
    fn header_tampering_rejected() {
        let mut v = Vault::new();
        v.add(Account {
            issuer: "x".into(),
            account: "y".into(),
            secret: vec![9, 9, 9],
        });
        let pwd = b"pw";
        let sealed = v.seal_with(pwd, &rand28(3), 1_000);
        // Flip a bit in the salt
        let mut tampered = sealed.clone();
        tampered[20] ^= 1;
        assert_eq!(Vault::open(&tampered, pwd).err(), Some(VaultError::Auth));
        // Flip a bit in the iter field
        let mut tampered2 = sealed.clone();
        tampered2[33] ^= 1;
        assert_eq!(Vault::open(&tampered2, pwd).err(), Some(VaultError::Auth));
        // Flip a bit in the nonce
        let mut tampered3 = sealed.clone();
        tampered3[40] ^= 1;
        assert_eq!(Vault::open(&tampered3, pwd).err(), Some(VaultError::Auth));
        // Flip a bit in the ciphertext
        let mut tampered4 = sealed.clone();
        tampered4[HEADER_LEN] ^= 1;
        assert_eq!(Vault::open(&tampered4, pwd).err(), Some(VaultError::Auth));
    }

    /// Bad magic / wrong algo / non-zero reserved field → Malformed.
    #[test]
    fn malformed_inputs() {
        assert_eq!(Vault::open(&[0u8; 10], b"pw").err(), Some(VaultError::Malformed));
        let mut bad = vec![0u8; HEADER_LEN + 16];
        // Set length-valid but bad magic
        assert_eq!(Vault::open(&bad, b"pw").err(), Some(VaultError::Malformed));
        bad[0..8].copy_from_slice(b"ROKA-V01");
        // Algo byte 0 (we expect 1)
        assert_eq!(Vault::open(&bad, b"pw").err(), Some(VaultError::Malformed));
        bad[8] = ALGO_PBKDF2_CC20P1305;
        bad[9] = 1; // reserved must be 0
        assert_eq!(Vault::open(&bad, b"pw").err(), Some(VaultError::Malformed));
    }

    /// Empty vault round-trips.
    #[test]
    fn empty_vault_round_trips() {
        let v = Vault::new();
        let sealed = v.seal_with(b"pw", &rand28(4), 1_000);
        let opened = Vault::open(&sealed, b"pw").unwrap();
        assert!(opened.accounts().is_empty());
    }

    /// remove() bounds check.
    #[test]
    fn remove_out_of_bounds() {
        let mut v = Vault::new();
        v.add(Account {
            issuer: "a".into(),
            account: "b".into(),
            secret: vec![1],
        });
        assert!(!v.remove(5));
        assert_eq!(v.accounts().len(), 1);
        assert!(v.remove(0));
        assert!(v.accounts().is_empty());
    }
}
