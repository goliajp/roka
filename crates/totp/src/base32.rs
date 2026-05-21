//! Base32（RFC 4648）。
//!
//! 教学注释
//! ========
//! Base32 跟 Base64 是同一类东西 —— 把任意字节流编码成"打印安全"的字符串。
//! 区别只在每组取多少 bit：
//!
//!   * Base64：每 6 bit 一组，64 字符（A-Z, a-z, 0-9, +, /）
//!   * Base32：每 5 bit 一组，32 字符（A-Z, 2-7）
//!
//! TOTP 协议偏爱 base32 而不是 base16/64，原因很"人性"：
//!   1. **不区分大小写** —— 用户在手机 App 上打字方便。
//!   2. **避开易混字符** —— 没有 0/1/8/9，没有 O/I/L/B 等容易看错的组合。
//!   3. **5 bit/字符** 比 hex 的 4 bit/字符 更紧凑。
//!
//! 编码块对齐
//! ----------
//! 每 **5 字节**（40 bit）正好编出 **8 个字符**。不足 5 字节的最后一组
//! 用 `=` 补齐到 8 字符：
//!
//! ```text
//!   1 byte ( 8 bit) →  2 chars +  6 '='
//!   2 bytes (16 bit) →  4 chars +  4 '='
//!   3 bytes (24 bit) →  5 chars +  3 '='
//!   4 bytes (32 bit) →  7 chars +  1 '='
//!   5 bytes (40 bit) →  8 chars +  0 '='
//! ```

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 把字节切片编码成 base32 字符串（含 `=` padding，大写）。
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 4) / 5 * 8);

    for chunk in input.chunks(5) {
        // 把当前 1..=5 字节装进一个 u64 的高位。
        // 例如 chunk = [B0, B1, B2]，先得到 buf = 0x0000000000B0B1B2，
        // 然后左移 (5 - 3) * 8 = 16 bit → 0x00B0B1B2_00000000 高位 40 bit 对齐。
        let mut buf: u64 = 0;
        for &b in chunk {
            buf = (buf << 8) | b as u64;
        }
        let pad_bytes = 5 - chunk.len();
        buf <<= pad_bytes * 8;

        // 实际要输出的字符数（剩下的位置用 '=' 填）
        let output_chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            5 => 8,
            _ => unreachable!(),
        };
        // 从最高 5 bit 开始，依次取 8 段
        for i in 0..8 {
            if i < output_chars {
                let shift = 35 - i * 5; // 35, 30, 25, 20, 15, 10, 5, 0
                let idx = ((buf >> shift) & 0x1F) as usize;
                out.push(ALPHABET[idx] as char);
            } else {
                out.push('=');
            }
        }
    }

    out
}

/// 把 base32 字符串解回字节。容忍大小写、空白、缺失的 `=` padding。
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    // 清洗：去空白、去 padding、统一大写
    let cleaned: Vec<u8> = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();

    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);

    for chunk in cleaned.chunks(8) {
        // 先把 1..=8 个字符的 5-bit 值塞进 u64 高位
        let mut buf: u64 = 0;
        for &c in chunk {
            let val = ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or_else(|| format!("invalid base32 char: {}", c as char))?;
            buf = (buf << 5) | val as u64;
        }
        let pad_chars = 8 - chunk.len();
        buf <<= pad_chars * 5;

        // 实际能恢复的字节数由"原始字符数"反推
        let output_bytes = match chunk.len() {
            2 => 1,
            4 => 2,
            5 => 3,
            7 => 4,
            8 => 5,
            n => return Err(format!("invalid base32 group length: {}", n)),
        };
        for i in 0..output_bytes {
            let shift = 32 - i * 8; // 32, 24, 16, 8, 0
            out.push(((buf >> shift) & 0xFF) as u8);
        }
    }

    Ok(out)
}

/// 给人看的格式：每 4 个字符一组，空格分隔（像 Authenticator 上的 secret 显示）。
pub fn encode_grouped(input: &[u8]) -> String {
    let raw = encode(input);
    let raw = raw.trim_end_matches('=');
    let mut out = String::with_capacity(raw.len() + raw.len() / 4);
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 给的测试向量
    #[test]
    fn rfc4648_examples() {
        let cases = [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];
        for (raw, b32) in cases {
            assert_eq!(encode(raw.as_bytes()), b32, "encode {:?}", raw);
            assert_eq!(decode(b32).unwrap(), raw.as_bytes(), "decode {:?}", b32);
        }
    }

    #[test]
    fn decode_is_lenient() {
        // 没有 padding、有空白、混合大小写都应该能解
        assert_eq!(decode("mzxw 6ytb").unwrap(), b"fooba");
        assert_eq!(decode("MZXW6YQ").unwrap(), b"foob"); // 缺末尾 '='
    }

    #[test]
    fn round_trip_random_lengths() {
        for len in 0..20 {
            let bytes: Vec<u8> = (0..len as u8).collect();
            let s = encode(&bytes);
            let back = decode(&s).unwrap();
            assert_eq!(back, bytes, "round-trip failed at len={}", len);
        }
    }
}
