//! HOTP — HMAC-based One-Time Password（RFC 4226）。
//!
//! 教学注释
//! ========
//! HOTP 是 TOTP 的"内核"。你只需要 HMAC + 一个叫**动态截断**的小动作，
//! 就能把"一个 8 字节计数器"变成"6 位一次性数字"。
//!
//! 算法本体只有四步：
//!
//! ```text
//!   mac    = HMAC-SHA1(secret, counter_be8)        // 20 字节
//!   offset = mac[19] & 0x0F                         // 取低 4 bit (0..15)
//!   bin    = (mac[offset]   & 0x7F) << 24
//!          | (mac[offset+1] & 0xFF) << 16
//!          | (mac[offset+2] & 0xFF) <<  8
//!          | (mac[offset+3] & 0xFF)
//!   code   = bin mod 10^digits
//! ```
//!
//! 几个小细节"为什么这样设计"
//! --------------------------
//! - **为什么偏移 `offset` 由 MAC 自己决定**？让攻击者无法预测会用哪
//!   4 个字节，等于在 MAC 上又叠了一层不确定性。
//! - **为什么把最高位与上 `0x7F`**？把它强制变成正数。这样不管你用
//!   的语言对"有符号 / 无符号 32 位整数"理解如何，结果都一致。
//! - **为什么取 mod 10^digits**？把 31 bit (≈ 2.1e9) 折成 6 或 8 位
//!   十进制 —— 6 位就是 6 位字符串，前面不足时左侧补 0。
//!
//! 这就是为什么 RFC 4226 里反复强调："HOTP 的安全性 ≈ HMAC 的安全性"
//! —— 截断步骤本身不引入新弱点，它只是为了"压成短码方便人输入"。

use crate::hmac::hmac_sha1;

/// 给定 secret 和计数器，算 HOTP 一次性密码。
///
/// * `secret` —— 共享密钥（任意字节）
/// * `counter` —— 计数器（HOTP 用单调递增的；TOTP 用 time/step）
/// * `digits` —— 输出位数，常用 6 或 8（最大 9，再多就溢出 u32）
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    debug_assert!(digits >= 1 && digits <= 9, "digits must be in 1..=9");

    // 1. 把计数器写成 8 字节 big-endian
    let counter_bytes = counter.to_be_bytes();

    // 2. HMAC-SHA1，得到 20 字节 MAC
    let mac = hmac_sha1(secret, &counter_bytes);

    // 3. 动态截断
    let offset = (mac[19] & 0x0F) as usize;
    let bin: u32 = ((mac[offset] & 0x7F) as u32) << 24
        | (mac[offset + 1] as u32) << 16
        | (mac[offset + 2] as u32) << 8
        | (mac[offset + 3] as u32);

    // 4. 取后 N 位十进制，左侧补 0
    let modulus = 10u32.pow(digits);
    let code = bin % modulus;
    format!("{:0>width$}", code, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 附录 D 的标准测试向量。
    /// secret = ASCII "12345678901234567890"。
    #[test]
    fn rfc4226_appendix_d() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                hotp(secret, counter as u64, 6),
                *want,
                "counter = {}",
                counter
            );
        }
    }
}
