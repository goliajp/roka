//! BCH(15,5) 与 BCH(18,6) —— QR 码格式信息和版本信息的编/解码。
//!
//! # 用途
//!
//! - **Format info**（5 位数据 → 15 位）：编码 EC 级别（2 位）+ 掩码模式（3 位），写在二维码定位图案旁两处。
//!   解码端必须先读出格式信息才能反掩码并解读数据区——所以格式信息本身需要超强的纠错。
//!   生成多项式 G(x) = x^10 + x^8 + x^5 + x^4 + x^2 + x + 1 = 0x537。t = 3，可纠 3 位错。
//!   编完之后还要 XOR 掩码 `0x5412`，避免全 0 字串（全 0 看起来像背景）。
//!
//! - **Version info**（6 位数据 → 18 位）：编码版本号（7-40），写在 v7+ 的二维码两处。
//!   生成多项式 G(x) = x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1 = 0x1F25。t = 3。
//!   无 XOR 掩码。
//!
//! # 编码
//!
//! 标准"系统编码"长除：data << ec_bits，求其模 G(x) 的余式，把余式接在 data 后面成为完整码字。
//!
//! # 解码
//!
//! 32 / 40 个合法码字数量很小，直接穷举找 Hamming 距离最小的合法码字。BCH(15,5) 最小距离 7（t=3），
//! 收到的字串与正确码字相差 ≤ 3 位时唯一可纠。

/// Format info 生成多项式 x^10 + x^8 + x^5 + x^4 + x^2 + x + 1。
const FORMAT_INFO_GEN: u32 = 0x537;
/// Format info 异或掩码（ISO 18004 §7.9）。
pub const FORMAT_INFO_MASK: u32 = 0x5412;
/// Version info 生成多项式 x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1。
const VERSION_INFO_GEN: u32 = 0x1F25;

/// Error-correction level for a QR code.
///
/// Per ISO/IEC 18004 the four levels recover the following share of damaged
/// codewords: **L** ≈ 7%, **M** ≈ 15%, **Q** ≈ 25%, **H** ≈ 30%.
///
/// The 2-bit on-the-wire encoding is **not** the alphabetical ordering — see
/// the standard's format-info table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    /// Low: ~7% recoverable. Maximum payload capacity.
    L,
    /// Medium: ~15% recoverable. The common default.
    M,
    /// Quartile: ~25% recoverable.
    Q,
    /// High: ~30% recoverable. Minimum payload capacity.
    H,
}

impl EcLevel {
    /// 2-bit on-the-wire encoding used in QR format information.
    pub fn bits(self) -> u8 {
        match self {
            EcLevel::L => 0b01,
            EcLevel::M => 0b00,
            EcLevel::Q => 0b11,
            EcLevel::H => 0b10,
        }
    }
    /// Decode the 2-bit on-the-wire encoding back into an [`EcLevel`].
    pub fn from_bits(b: u8) -> Option<EcLevel> {
        Some(match b & 0b11 {
            0b01 => EcLevel::L,
            0b00 => EcLevel::M,
            0b11 => EcLevel::Q,
            0b10 => EcLevel::H,
            _ => return None,
        })
    }
}

/// 多项式长除：以 generator 为模，求 `dividend` 的余式。`gen_deg` 是 generator 的次数。
fn polynomial_remainder(mut dividend: u32, generator: u32, gen_deg: u32) -> u32 {
    // 找出 dividend 的最高位，逐位用 generator 抵消。
    let mut top = 31u32;
    while top >= gen_deg {
        if (dividend >> top) & 1 == 1 {
            dividend ^= generator << (top - gen_deg);
        }
        if top == 0 {
            break;
        }
        top -= 1;
    }
    dividend
}

/// 编码 format info：返回 15 位整数（最低 15 位有效）。
pub fn encode_format(ec_level: EcLevel, mask: u8) -> u32 {
    debug_assert!(mask < 8);
    let data = ((ec_level.bits() as u32) << 3) | (mask as u32 & 0b111); // 5 位
    let remainder = polynomial_remainder(data << 10, FORMAT_INFO_GEN, 10);
    ((data << 10) | remainder) ^ FORMAT_INFO_MASK
}

/// 解码 format info：穷举 32 个合法码字，取 Hamming 距离最小者；要求 ≤ 3 位错。
/// 返回 (EC 级别, 掩码, 纠错位数)。
pub fn decode_format(received: u32) -> Option<(EcLevel, u8, u8)> {
    let received = received & 0x7FFF;
    let mut best: Option<(EcLevel, u8, u8)> = None;
    for level_bits in [0b00u8, 0b01, 0b10, 0b11] {
        let level = EcLevel::from_bits(level_bits).unwrap();
        for mask in 0u8..8 {
            let codeword = encode_format(level, mask);
            let dist = (codeword ^ received).count_ones() as u8;
            if dist > 3 {
                continue;
            }
            best = match best {
                None => Some((level, mask, dist)),
                Some((_, _, bd)) if dist < bd => Some((level, mask, dist)),
                _ => best,
            };
        }
    }
    best
}

/// 编码 version info：返回 18 位整数（最低 18 位有效）。仅 7..=40 有效。
pub fn encode_version(version: u8) -> u32 {
    debug_assert!((7..=40).contains(&version));
    let data = version as u32;
    let remainder = polynomial_remainder(data << 12, VERSION_INFO_GEN, 12);
    (data << 12) | remainder
}

/// 解码 version info：穷举 34 个合法码字（版本 7..=40），取 Hamming 距离最小者；要求 ≤ 3 位错。
/// 返回 (version, 纠错位数)。
#[allow(dead_code)]
pub fn decode_version(received: u32) -> Option<(u8, u8)> {
    let received = received & 0x3FFFF;
    let mut best: Option<(u8, u8)> = None;
    for v in 7u8..=40 {
        let codeword = encode_version(v);
        let dist = (codeword ^ received).count_ones() as u8;
        if dist > 3 {
            continue;
        }
        best = match best {
            None => Some((v, dist)),
            Some((_, bd)) if dist < bd => Some((v, dist)),
            _ => best,
        };
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ISO/IEC 18004 §C.1：L 级 + mask 0 → 0x77C4。
    #[test]
    fn format_iso_examples() {
        assert_eq!(encode_format(EcLevel::L, 0), 0x77C4);
        // L + mask 1 → 0b111001011110011 = 0x72F3
        assert_eq!(encode_format(EcLevel::L, 1), 0x72F3);
        // M + mask 0 → 0b101010000010010 = 0x5412 (即与 mask 异或本身)
        assert_eq!(encode_format(EcLevel::M, 0), 0x5412);
        // M + mask 5 → 0b100000011001110 = 0x40CE（ISO 表）
        assert_eq!(encode_format(EcLevel::M, 5), 0x40CE);
        // Q + mask 0 → 0b011010101011111 = 0x355F
        assert_eq!(encode_format(EcLevel::Q, 0), 0x355F);
        // H + mask 0 → 0b001011010001001 = 0x1689
        assert_eq!(encode_format(EcLevel::H, 0), 0x1689);
    }

    #[test]
    fn format_round_trip() {
        for &level in &[EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
            for mask in 0u8..8 {
                let cw = encode_format(level, mask);
                let (l, m, d) = decode_format(cw).unwrap();
                assert_eq!(l, level);
                assert_eq!(m, mask);
                assert_eq!(d, 0);
            }
        }
    }

    #[test]
    fn format_corrects_three_errors() {
        let cw = encode_format(EcLevel::Q, 5);
        // 翻 3 位
        let corrupted = cw ^ 0b101_0000_0010_0000;
        let (l, m, d) = decode_format(corrupted).unwrap();
        assert_eq!(l, EcLevel::Q);
        assert_eq!(m, 5);
        assert_eq!(d, 3);
    }

    /// ISO/IEC 18004 §D.1：v7 → 000111110010010100 = 0x07C94。
    #[test]
    fn version_iso_examples() {
        assert_eq!(encode_version(7), 0x07C94);
        // ISO Annex D 还列了 v8、v9...v40。取若干校验。
        assert_eq!(encode_version(8), 0x085BC);
        assert_eq!(encode_version(40), 0x28C69);
    }

    #[test]
    fn version_round_trip() {
        for v in 7u8..=40 {
            let cw = encode_version(v);
            let (vr, d) = decode_version(cw).unwrap();
            assert_eq!(vr, v);
            assert_eq!(d, 0);
        }
    }

    #[test]
    fn version_corrects_three_errors() {
        let cw = encode_version(25);
        let corrupted = cw ^ 0b1_0000_0001_0000_0001;
        let (v, d) = decode_version(corrupted).unwrap();
        assert_eq!(v, 25);
        assert_eq!(d, 3);
    }

    #[test]
    fn ec_level_bits_round_trip() {
        for &l in &[EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
            assert_eq!(EcLevel::from_bits(l.bits()), Some(l));
        }
    }
}
