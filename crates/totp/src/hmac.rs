//! HMAC-SHA1（RFC 2104）。
//!
//! 教学注释
//! ========
//! HMAC 是一种"用密钥保护消息完整性"的标准结构。它的定义看起来奇怪，
//! 但每一步都有目的：
//!
//! ```text
//!   HMAC(K, M) = H( (K' XOR opad) || H( (K' XOR ipad) || M ) )
//! ```
//!
//! 其中：
//!   - `K'` = 把密钥规范化到底层哈希的"块大小"（SHA-1 是 64 字节）：
//!       * 太长 → 先 H(K)（变成 20 字节）
//!       * 短了 → 右侧补 0
//!   - `ipad` = `0x36` 重复块大小次（"inner pad"）
//!   - `opad` = `0x5C` 重复块大小次（"outer pad"）
//!
//! 为什么要"双层哈希"？
//!   只用 H(K || M) 会被"长度扩展攻击"绕过（攻击者不知道 K 也能在
//!   M 后面续写消息并算出对应的 MAC）。HMAC 把 key 放在两层哈希里，
//!   并且两层用不同 pad 让两次内部状态不同，干净地堵掉这条路。
//!
//! 顺便：`ipad` 和 `opad` 之所以选 0x36 / 0x5C，是因为它们的二进制
//! 位模式正好互补一半 —— 这让两层的内部状态尽量"不相关"。

use crate::sha1::sha1;

/// SHA-1 的块大小（512 bits = 64 bytes）。
const BLOCK_SIZE: usize = 64;

/// 用 `key` 给 `message` 算 HMAC-SHA1，返回 20 字节。
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    // ---- 1. 把 key 规范化到 BLOCK_SIZE ----
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // 太长就先 hash 一次，结果 20 字节，自然 < 64
        k[..20].copy_from_slice(&sha1(key));
    } else {
        // 短了就右侧补 0（数组初始化就是 0，直接 copy 即可）
        k[..key.len()].copy_from_slice(key);
    }

    // ---- 2. 构造内外 pad ----
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // ---- 3. 内层： H(ipad || message) ----
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = sha1(&inner_input);

    // ---- 4. 外层： H(opad || inner_hash) ----
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    sha1(&outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // RFC 2202 §3 测试向量（HMAC-SHA1）
    #[test]
    fn rfc2202_case1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        assert_eq!(
            hex(&hmac_sha1(&key, msg)),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn rfc2202_case2() {
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        assert_eq!(
            hex(&hmac_sha1(key, msg)),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn rfc2202_case3_long_data() {
        // key = 20 字节 0xaa, data = 50 字节 0xdd
        let key = [0xaau8; 20];
        let msg = [0xddu8; 50];
        assert_eq!(
            hex(&hmac_sha1(&key, &msg)),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    #[test]
    fn rfc2202_case5_long_key() {
        // key 80 字节 → 进入"先 hash key"分支
        let key = [0xaau8; 80];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hex(&hmac_sha1(&key, msg)),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }
}
