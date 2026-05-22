//! HMAC-SHA-256（RFC 2104 + RFC 4231）。
//!
//! HMAC 把任意长度的 key 转成 fixed-size 后做两层 hash：
//!
//! ```text
//!   key_block = key length > 64 ? sha256(key) padded to 64 bytes : key padded to 64 bytes
//!   hmac = sha256( (key_block ⊕ opad) || sha256( (key_block ⊕ ipad) || msg ) )
//! ```
//!
//! 其中 `ipad = 0x36 × 64`、`opad = 0x5C × 64`。
//!
//! # 性能要点（PBKDF2 用得到）
//!
//! 同一个 key 多次 HMAC 时，`(key ⊕ ipad)` 这 64 字节 block 是固定的——可以一次
//! 算完 SHA-256 inner-state 缓存起来，之后每次 PBKDF2 迭代只需从 mid-state 继续
//! 喂入 message 部分。`Hmac256::with_cached_state` 把这层优化暴露出来；
//! 单次 hmac_sha256() 内部自动使用。

use super::sha256::Sha256;

const BLOCK_SIZE: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// 把任意长度的 key 标准化成 64 字节 block（按 RFC 2104）。
fn normalize_key(key: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // 超长 key：用 SHA-256 摘要替代
        let digest = super::sha256::sha256(key);
        block[..32].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    block
}

/// HMAC-SHA-256 单次接口。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Hmac256::new(key);
    h.update(msg);
    h.finalize()
}

/// HMAC-SHA-256 增量接口 + 可保留 inner/outer 预算状态用于 PBKDF2 加速。
pub struct Hmac256 {
    /// `key ⊕ ipad`，备用（PBKDF2 用）。
    key_ipad_block: [u8; BLOCK_SIZE],
    /// `key ⊕ opad`，备用（finalize 时用）。
    key_opad_block: [u8; BLOCK_SIZE],
    /// 进行中的 inner hash。
    inner: Sha256,
}

impl Hmac256 {
    /// 新建并喂入第一个 inner block (key ⊕ ipad)。
    pub fn new(key: &[u8]) -> Self {
        let key_block = normalize_key(key);
        let mut k_ipad = [0u8; BLOCK_SIZE];
        let mut k_opad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            k_ipad[i] = key_block[i] ^ IPAD;
            k_opad[i] = key_block[i] ^ OPAD;
        }
        let mut inner = Sha256::new();
        inner.compress_block(&k_ipad);
        inner.restore_midstate(inner.midstate().0, BLOCK_SIZE as u64 * 8);

        Self {
            key_ipad_block: k_ipad,
            key_opad_block: k_opad,
            inner,
        }
    }

    /// 喂入消息。
    pub fn update(&mut self, msg: &[u8]) {
        self.inner.update(msg);
    }

    /// 取 inner SHA mid-state（key ⊕ ipad 已喂入但 msg 未喂入时的状态）。
    /// 用于 PBKDF2：每轮起点都从这个 mid-state 出发。
    pub fn inner_midstate(&self) -> [u32; 8] {
        let mut h = Sha256::new();
        h.compress_block(&self.key_ipad_block);
        h.midstate().0
    }

    /// 取 outer SHA mid-state（key ⊕ opad 已喂入但 inner-digest 未喂入时的状态）。
    pub fn outer_midstate(&self) -> [u32; 8] {
        let mut h = Sha256::new();
        h.compress_block(&self.key_opad_block);
        h.midstate().0
    }

    /// 完成一次 HMAC：跑 outer SHA、产 32 字节 tag。
    pub fn finalize(self) -> [u8; 32] {
        let inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.compress_block(&self.key_opad_block);
        outer.restore_midstate(outer.midstate().0, BLOCK_SIZE as u64 * 8);
        outer.update(&inner_digest);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// RFC 4231 §4.2 — Test Case 1
    #[test]
    fn rfc4231_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 §4.3 — Test Case 2: short key + ASCII data
    #[test]
    fn rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 §4.4 — Test Case 3: 20-byte key, 50-byte 0xdd data
    #[test]
    fn rfc4231_case3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let mac = hmac_sha256(&key, &data);
        assert_eq!(
            hex(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// RFC 4231 §4.5 — Test Case 4: structured key + data
    #[test]
    fn rfc4231_case4() {
        let key: Vec<u8> = (1u8..=25).collect();
        let data = [0xcdu8; 50];
        let mac = hmac_sha256(&key, &data);
        assert_eq!(
            hex(&mac),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    /// RFC 4231 §4.6 — Test Case 5: truncated to 128 bits — we keep full 256, just check prefix
    #[test]
    fn rfc4231_case5_prefix() {
        let key = [0x0cu8; 20];
        let data = b"Test With Truncation";
        let mac = hmac_sha256(&key, data);
        // The truncated reference tag (first 128 bits) is a3b6167473100ee06e0c796c2955552b.
        assert_eq!(&hex(&mac)[..32], "a3b6167473100ee06e0c796c2955552b");
    }

    /// RFC 4231 §4.7 — Test Case 6: key longer than block size (131 bytes)
    #[test]
    fn rfc4231_case6_long_key() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// RFC 4231 §4.8 — Test Case 7: long key + long data
    #[test]
    fn rfc4231_case7_long_both() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex(&mac),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    /// 增量喂入与一次性等价。
    #[test]
    fn incremental_matches_oneshot() {
        let key = b"some-key-for-incremental-test";
        let msg = b"The quick brown fox jumps over the lazy dog. The five boxing wizards jump quickly.";
        let one = hmac_sha256(key, msg);
        for split in [0, 1, 7, 32, 50, msg.len()] {
            let mut h = Hmac256::new(key);
            h.update(&msg[..split]);
            h.update(&msg[split..]);
            assert_eq!(h.finalize(), one, "split {split}");
        }
    }
}
