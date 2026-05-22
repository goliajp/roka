//! ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）。
//!
//! AEAD = Authenticated Encryption with Associated Data：把 ChaCha20 流密码（提供
//! 保密）和 Poly1305 MAC（提供完整性 + 真实性）组合成一个不可分割的原语。任何对密文
//! 或 AAD 的修改都会让解密失败。
//!
//! # 算法（RFC 8439 §2.8.1）
//!
//! 加密：
//! 1. `otk = ChaCha20(key, nonce, counter=0)[0..32]`  — 一次性 Poly1305 key
//! 2. `ciphertext = ChaCha20(key, nonce, counter=1) XOR plaintext`
//! 3. MAC 输入 = `aad ‖ pad16(aad) ‖ ciphertext ‖ pad16(ciphertext) ‖ len(aad)₈ ‖ len(ct)₈`
//! 4. `tag = Poly1305(otk, MAC 输入)`
//!
//! 解密：先重算 `tag`，constant-time 对比，再 ChaCha20 反 XOR 出明文。**任何不匹配都拒绝**。

use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;

/// AEAD 解密失败。不区分 "MAC 不对" / "长度不对" 等不同原因——攻击者不该获得辨别信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AEAD authentication failed")
    }
}

impl std::error::Error for AeadError {}

/// 加密：返回 ciphertext + 16-byte tag 串联后的新 Vec。
///
/// `aad` 任何长度（含 0）。`nonce` 必须 12 字节且 (key, nonce) 必须**全局**唯一。
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + 16);

    // 1. derive one-time Poly1305 key
    let otk = poly1305_key_gen(key, nonce);

    // 2. encrypt plaintext (counter starts at 1)
    let mut ct = plaintext.to_vec();
    let mut cc = ChaCha20::new(key, nonce, 1);
    cc.apply_keystream(&mut ct);
    out.extend_from_slice(&ct);

    // 3. compute tag
    let tag = compute_tag(&otk, aad, &ct);
    out.extend_from_slice(&tag);
    out
}

/// 解密：验证 tag 通过后返回 plaintext。任何不一致返回 `AeadError`。
///
/// `combined` = ciphertext ‖ tag（即 `encrypt` 的输出）。
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    combined: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if combined.len() < 16 {
        return Err(AeadError);
    }
    let split = combined.len() - 16;
    let ct = &combined[..split];
    let tag_in = &combined[split..];

    let otk = poly1305_key_gen(key, nonce);
    let tag_calc = compute_tag(&otk, aad, ct);

    if !constant_time_eq(tag_in, &tag_calc) {
        return Err(AeadError);
    }
    // 真正解密（与加密同算，对称）
    let mut pt = ct.to_vec();
    let mut cc = ChaCha20::new(key, nonce, 1);
    cc.apply_keystream(&mut pt);
    Ok(pt)
}

/// 用 ChaCha20 keystream 的 counter=0 块前 32 字节做 Poly1305 一次性 key。
fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let cc = ChaCha20::new(key, nonce, 0);
    let block = cc.block(0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    otk
}

/// 构造 Poly1305 MAC 输入并算 tag。
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(otk);
    mac.update(aad);
    // pad1 to 16-byte boundary
    let pad1 = (16 - aad.len() % 16) % 16;
    if pad1 > 0 {
        mac.update(&[0u8; 16][..pad1]);
    }
    mac.update(ciphertext);
    let pad2 = (16 - ciphertext.len() % 16) % 16;
    if pad2 > 0 {
        mac.update(&[0u8; 16][..pad2]);
    }
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

/// Constant-time byte slice equality. Returns false on different lengths immediately
/// (length isn't secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_vec(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len() / 2)
            .map(|i| u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let v = hex_to_vec(s);
        assert_eq!(v.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    #[allow(dead_code)]
    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// RFC 8439 §2.8.2 — 完整加密 test vector。
    ///
    /// key   = 80 81 .. 9f
    /// nonce = 07 00 00 00 40 41 42 43 44 45 46 47
    /// aad   = 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7
    /// plaintext = "Ladies and Gentlemen ..." (114 bytes)
    #[test]
    fn rfc8439_2_8_2() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647");
        let aad = hex_to_vec("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let combined = encrypt(&key, &nonce, &aad, plaintext);

        let expected_ct = hex_to_vec(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let expected_tag = hex_to_vec("1ae10b594f09e26a7e902ecbd0600691");

        assert_eq!(&combined[..plaintext.len()], &expected_ct[..]);
        assert_eq!(&combined[plaintext.len()..], &expected_tag[..]);

        // round-trip
        let pt2 = decrypt(&key, &nonce, &aad, &combined).expect("auth");
        assert_eq!(pt2, plaintext);
    }

    /// RFC 8439 §A.5 — Decrypt round-trip with the spec example.
    #[test]
    fn rfc8439_a_5_decrypt() {
        let key: [u8; 32] = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        let nonce: [u8; 12] = hex("000000000102030405060708");
        let aad = hex_to_vec("f33388860000000000004e91");
        let ct_and_tag = hex_to_vec(
            "64a0861575861af460f062c79be643bd\
             5e805cfd345cf389f108670ac76c8cb2\
             4c6cfc18755d43eea09ee94e382d26b0\
             bdb7b73c321b0100d4f03b7f355894cf\
             332f830e710b97ce98c8a84abd0b9481\
             14ad176e008d33bd60f982b1ff37c855\
             9797a06ef4f0ef61c186324e2b350638\
             3606907b6a7c02b0f9f6157b53c867e4\
             b9166c767b804d46a59b5216cde7a4e9\
             9040c5a40433225ee282a1b0a06c523e\
             af4534d7f83fa1155b0047718cbc546a\
             0d072b04b3564eea1b422273f548271a\
             0bb2316053fa76991955ebd63159434e\
             cebb4e466dae5a1073a6727627097a10\
             49e617d91d361094fa68f0ff77987130\
             305beaba2eda04df997b714d6c6f2c29\
             a6ad5cb4022b02709beead9d67890cbb\
             22392336fea1851f38",
        );

        let pt = decrypt(&key, &nonce, &aad, &ct_and_tag).expect("auth");
        // RFC 8439 §A.5 plaintext is a known prefix; auth success is the strong correctness signal.
        assert!(pt.starts_with(b"Internet-Drafts"));
        // 端值校验留给 round-trip 那条等价：encrypt(decrypted) must equal the input ct.
        let recombined = encrypt(&key, &nonce, &aad, &pt);
        assert_eq!(recombined, ct_and_tag, "re-encrypt must reproduce identical bytes");
    }

    /// 篡改 1 个密文 byte 必须解密失败。
    #[test]
    fn tampered_ciphertext_rejected() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647");
        let aad = b"associated data";
        let pt = b"sensitive payload";
        let mut combined = encrypt(&key, &nonce, aad, pt);
        // flip a bit in the ciphertext
        combined[0] ^= 1;
        assert_eq!(decrypt(&key, &nonce, aad, &combined), Err(AeadError));
    }

    /// 篡改 tag byte 必须拒绝。
    #[test]
    fn tampered_tag_rejected() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647");
        let aad = b"";
        let pt = b"payload";
        let mut combined = encrypt(&key, &nonce, aad, pt);
        let last = combined.len() - 1;
        combined[last] ^= 1;
        assert_eq!(decrypt(&key, &nonce, aad, &combined), Err(AeadError));
    }

    /// 篡改 AAD 必须拒绝。
    #[test]
    fn tampered_aad_rejected() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647");
        let combined = encrypt(&key, &nonce, b"context", b"secret");
        assert_eq!(decrypt(&key, &nonce, b"different_context", &combined), Err(AeadError));
    }

    /// 空 plaintext + 空 AAD：tag 应该仍然能验证。
    #[test]
    fn empty_round_trip() {
        let key: [u8; 32] = [0xa5; 32];
        let nonce: [u8; 12] = [0x42; 12];
        let combined = encrypt(&key, &nonce, b"", b"");
        assert_eq!(combined.len(), 16); // just the tag
        let pt = decrypt(&key, &nonce, b"", &combined).expect("auth");
        assert!(pt.is_empty());
    }
}
