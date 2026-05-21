//! SHA-1 哈希（RFC 3174 / FIPS 180-1）。
//!
//! 教学注释
//! ========
//! SHA-1 把任意长度的字节流压成固定 20 字节摘要。整体可以分两步看：
//!
//!   1. **填充**：在消息末尾补一个 `0x80`，再补 0，使总长度（字节）
//!      满足 `len ≡ 56 (mod 64)`，最后 8 字节附上"原消息位长度"
//!      （big-endian）。这样消息长度变成 64 字节的整数倍，方便分块。
//!
//!   2. **逐块压缩**：每 64 字节当作一个块，跑 80 轮位运算压缩到
//!      5 个 32-bit 状态字 `(a, b, c, d, e)` 上。所有块跑完后，把
//!      这 5 个字拼起来就是 20 字节的输出。
//!
//! 安全提醒
//! --------
//! SHA-1 已经因为碰撞攻击不再适合做"防伪签名"，但 HMAC-SHA1 至今
//! 仍被 TOTP / IPsec 等协议使用 —— HMAC 的双重哈希结构对底层
//! 哈希的弱点更鲁棒。所以"SHA-1 已破"和"HMAC-SHA1 还能用"并不冲突。

/// SHA-1 的初始状态常量（FIPS 180-1 §5.3.1，前 5 个素数平方根的小数部分）
const H_INIT: [u32; 5] = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
];

/// 计算消息的 SHA-1 摘要，返回 20 字节。
pub fn sha1(message: &[u8]) -> [u8; 20] {
    // ---------- 1. 填充消息 ----------
    // 原消息位长度（在追加任何 padding 之前记录！）
    let bit_len = (message.len() as u64).wrapping_mul(8);

    let mut padded: Vec<u8> = Vec::with_capacity(message.len() + 72);
    padded.extend_from_slice(message);
    padded.push(0x80); // 必须的"1 比特"分隔符（在字节边界上就是 0x80）
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    debug_assert!(padded.len() % 64 == 0);

    // ---------- 2. 逐块压缩 ----------
    let mut h = H_INIT;
    for chunk in padded.chunks(64) {
        // 把 64 字节切成 16 个 big-endian u32（W[0..16]）
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        // 消息扩展：W[16..80] 由前面的字异或循环左移 1 位得来
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // 80 轮主循环。每 20 轮换一组 (f, k)。
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k): (u32, u32) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),    // Ch
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),               // Parity
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC), // Maj
                _ => (b ^ c ^ d, 0xCA62C1D6),                     // Parity
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // 把本块算出的状态加回到 h（注意是 wrapping，按 mod 2^32）
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    // ---------- 3. 拼装 20 字节输出 ----------
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 把字节数组转成小写 hex 字符串，方便和 RFC 给出的字面值比对。
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // 下面的测试向量来自 FIPS 180-1 / RFC 3174 附录。
    #[test]
    fn empty_string() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn abc() {
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn two_block_message() {
        // 56 字节 → 加上 0x80 后已经超过 56，会触发"跨块填充"分支
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(&sha1(msg)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn one_million_a() {
        let msg = vec![b'a'; 1_000_000];
        assert_eq!(hex(&sha1(&msg)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }
}
