//! QR 解码：模块矩阵 → 数据字节。
//!
//! 流程（反向于 encode.rs）：
//!   1. 矩阵尺寸 → 版本号；读两处 format info、BCH 解码、得 EC 级别和掩码
//!   2. 数据区做掩码 XOR（反掩码）
//!   3. 按 zigzag 路径读 codeword bit 流
//!   4. 反交错：按 EC 块结构把交错流拆回成 N 个 (data + EC) 块
//!   5. 每块 RS 解码（含纠错），得 data codewords
//!   6. 拼回 data codewords → 解 mode + count + payload

use super::bch::{decode_format, EcLevel};
use super::mask::apply_mask;
use super::matrix::Matrix;
use super::reed_solomon;
use super::tables::{byte_mode_count_bits, ec_blocks, Version};

/// 从矩阵推算版本号（基于尺寸）。
pub fn version_from_size(size: usize) -> Result<Version, &'static str> {
    if size < 21 || size > 177 || (size - 17) % 4 != 0 {
        return Err("invalid QR size");
    }
    let v = ((size - 17) / 4) as u8;
    Ok(Version::new(v))
}

/// 读 15 位 format info（与 encode 端的位排布严格对称）。返回 (EC 级别, 掩码) 或错误。
/// 两处都试，谁的 BCH Hamming 距离小就用谁。
pub(crate) fn read_format_info(matrix: &Matrix) -> Result<(EcLevel, u8), &'static str> {
    let n = matrix.size;
    let bit_at = |row: usize, col: usize| -> u32 {
        if matrix.get(row, col) {
            1
        } else {
            0
        }
    };
    // 副本 A：左上 L 形（标准 Nayuki/qrencode/ISO 约定）
    // bit 0..5 = col 8 rows 0..5；bit 6 = (7,8)；bit 7 = (8,8)；bit 8 = (8,7)；bit 9..14 = row 8 cols 5..0
    let mut a = 0u32;
    for i in 0u32..6 {
        a |= bit_at(i as usize, 8) << i;
    }
    a |= bit_at(7, 8) << 6;
    a |= bit_at(8, 8) << 7;
    a |= bit_at(8, 7) << 8;
    for i in 9u32..15 {
        a |= bit_at(8, (14 - i) as usize) << i;
    }
    // 副本 B：右上 + 左下
    // bit 0..7 = row 8 cols n-1..n-8；bit 8..14 = col 8 rows n-7..n-1
    let mut b = 0u32;
    for i in 0u32..8 {
        b |= bit_at(8, n - 1 - i as usize) << i;
    }
    for i in 8u32..15 {
        b |= bit_at(n - 15 + i as usize, 8) << i;
    }

    let da = decode_format(a);
    let db = decode_format(b);
    match (da, db) {
        (Some((la, ma, dista)), Some((_lb, _mb, distb))) => {
            if dista <= distb {
                Ok((la, ma))
            } else {
                Ok((_lb, _mb))
            }
        }
        (Some((l, m, _)), None) => Ok((l, m)),
        (None, Some((l, m, _))) => Ok((l, m)),
        (None, None) => Err("could not decode format info"),
    }
}

/// 用与 encode 完全相同的 zigzag 路径，把矩阵的数据区读成 bit 序列。
fn read_data_zigzag(matrix: &Matrix) -> Vec<bool> {
    let n = matrix.size;
    let mut bits = Vec::with_capacity(n * n);
    let mut upward = true;
    let mut right = (n as i32) - 1;
    while right > 0 {
        if right == 6 {
            right -= 1;
        }
        for step in 0..n {
            let y = if upward { n - 1 - step } else { step };
            for j in 0..2 {
                let x = (right - j as i32) as usize;
                if !matrix.is_reserved(y, x) {
                    bits.push(matrix.get(y, x));
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
    bits
}

/// 把 bit 流（按 8 bit/byte，MSB first）拼成 byte 流。多余的尾部位（remainder bits）丢弃。
fn bits_to_bytes(bits: &[bool], n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    for i in 0..n_bytes {
        let mut b = 0u8;
        for j in 0..8 {
            let idx = i * 8 + j;
            if idx < bits.len() && bits[idx] {
                b |= 1 << (7 - j);
            }
        }
        out[i] = b;
    }
    out
}

/// 反交错 + RS 解码：把交错的 codeword 流拆回 N 个数据块，逐块纠错。
fn deinterleave_and_decode(
    codewords: &[u8],
    version: Version,
    level: EcLevel,
) -> Result<Vec<u8>, &'static str> {
    let info = ec_blocks(version, level);
    let total_blocks = info.total_blocks() as usize;
    // 每块的 data 长度
    let mut block_data_sizes: Vec<usize> = Vec::with_capacity(total_blocks);
    let (g1n, g1d) = info.group1;
    for _ in 0..g1n {
        block_data_sizes.push(g1d as usize);
    }
    if let Some((g2n, g2d)) = info.group2 {
        for _ in 0..g2n {
            block_data_sizes.push(g2d as usize);
        }
    }
    let ec_per_block = info.ec_per_block as usize;
    let max_data_len = *block_data_sizes.iter().max().unwrap();

    let mut data_blocks: Vec<Vec<u8>> = block_data_sizes.iter().map(|&d| Vec::with_capacity(d)).collect();
    let mut ec_blocks_vec: Vec<Vec<u8>> = (0..total_blocks).map(|_| Vec::with_capacity(ec_per_block)).collect();

    let mut cursor = 0usize;
    // data 交错部分
    for i in 0..max_data_len {
        for b in 0..total_blocks {
            if i < block_data_sizes[b] {
                data_blocks[b].push(codewords[cursor]);
                cursor += 1;
            }
        }
    }
    // EC 交错部分
    for _ in 0..ec_per_block {
        for b in 0..total_blocks {
            ec_blocks_vec[b].push(codewords[cursor]);
            cursor += 1;
        }
    }

    // 每块 RS 解码（输入 = data + EC concat）。
    let mut out = Vec::new();
    for (db, eb) in data_blocks.iter().zip(ec_blocks_vec.iter()) {
        let mut received = db.clone();
        received.extend(eb);
        let recovered = reed_solomon::decode(&received, ec_per_block)?;
        out.extend(recovered);
    }
    Ok(out)
}

/// 解析数据 codeword 流，支持多个分段。
///
/// 一个 QR 码里可以串接多个不同模式的段（QR 标准里叫 "structured concatenation"，
/// 但其实就是 mode + count + payload 重复，最后用 mode = 0000 终止）。
///
/// 支持模式：
/// - 0b0100 byte：直接 8 bit/byte 读
/// - 0b0010 alphanumeric：45 进制，11 bit/对、6 bit/单字符
/// - 0b0001 numeric：10 进制，10 bit/3 个、7 bit/2 个、4 bit/单个
/// - 0b0000 terminator：结束
fn parse_segments(data: &[u8], version: Version) -> Result<Vec<u8>, &'static str> {
    let mut br = BitReader::new(data);
    let mut out = Vec::new();
    loop {
        // 若剩余位 < 4，自然终止（QR 末尾常有不足的填充零）
        let mode_opt = br.read_bits(4);
        let mode = match mode_opt {
            Some(m) => m,
            None => break,
        };
        match mode {
            0b0000 => break, // terminator
            0b0100 => parse_byte_segment(&mut br, version, &mut out)?,
            0b0010 => parse_alpha_segment(&mut br, version, &mut out)?,
            0b0001 => parse_numeric_segment(&mut br, version, &mut out)?,
            _ => return Err("unsupported mode segment"),
        }
    }
    Ok(out)
}

fn parse_byte_segment(br: &mut BitReader, version: Version, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let count_bits = byte_mode_count_bits(version);
    let count = br.read_bits(count_bits).ok_or("truncated: byte count")? as usize;
    for _ in 0..count {
        let b = br.read_bits(8).ok_or("truncated: byte payload")?;
        out.push(b as u8);
    }
    Ok(())
}

/// Alphanumeric 字符集（ISO 18004 §8.4.4）。索引 0..44 即对应字符。
const ALPHA_CHARS: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn alpha_count_bits(version: Version) -> usize {
    match version.0 {
        1..=9 => 9,
        10..=26 => 11,
        _ => 13,
    }
}

fn parse_alpha_segment(br: &mut BitReader, version: Version, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let count_bits = alpha_count_bits(version);
    let mut count = br.read_bits(count_bits).ok_or("truncated: alpha count")? as usize;
    while count >= 2 {
        let v = br.read_bits(11).ok_or("truncated: alpha pair")?;
        let c1 = (v / 45) as usize;
        let c2 = (v % 45) as usize;
        if c1 >= 45 || c2 >= 45 {
            return Err("alpha char out of range");
        }
        out.push(ALPHA_CHARS[c1]);
        out.push(ALPHA_CHARS[c2]);
        count -= 2;
    }
    if count == 1 {
        let v = br.read_bits(6).ok_or("truncated: alpha single")? as usize;
        if v >= 45 {
            return Err("alpha char out of range");
        }
        out.push(ALPHA_CHARS[v]);
    }
    Ok(())
}

fn numeric_count_bits(version: Version) -> usize {
    match version.0 {
        1..=9 => 10,
        10..=26 => 12,
        _ => 14,
    }
}

fn parse_numeric_segment(br: &mut BitReader, version: Version, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let count_bits = numeric_count_bits(version);
    let mut count = br.read_bits(count_bits).ok_or("truncated: numeric count")? as usize;
    while count >= 3 {
        let v = br.read_bits(10).ok_or("truncated: numeric triple")? as usize;
        if v >= 1000 {
            return Err("numeric triple out of range");
        }
        out.push(b'0' + (v / 100) as u8);
        out.push(b'0' + ((v / 10) % 10) as u8);
        out.push(b'0' + (v % 10) as u8);
        count -= 3;
    }
    if count == 2 {
        let v = br.read_bits(7).ok_or("truncated: numeric pair")? as usize;
        if v >= 100 {
            return Err("numeric pair out of range");
        }
        out.push(b'0' + (v / 10) as u8);
        out.push(b'0' + (v % 10) as u8);
    } else if count == 1 {
        let v = br.read_bits(4).ok_or("truncated: numeric single")? as usize;
        if v >= 10 {
            return Err("numeric single out of range");
        }
        out.push(b'0' + v as u8);
    }
    Ok(())
}

/// 顶层：模块矩阵 → 字节净荷。
pub fn decode(matrix: &Matrix) -> Result<Vec<u8>, &'static str> {
    let version = version_from_size(matrix.size)?;
    let (level, mask) = read_format_info(matrix)?;

    // 反掩码：复制矩阵，反 XOR。
    let mut m2 = matrix.clone();
    apply_mask(&mut m2, mask);

    let bits = read_data_zigzag(&m2);
    let total_codewords = (ec_blocks(version, level).total_data_codewords()
        + ec_blocks(version, level).total_ec_codewords()) as usize;
    let codewords = bits_to_bytes(&bits, total_codewords);
    let data = deinterleave_and_decode(&codewords, version, level)?;
    parse_segments(&data, version)
}

// ───────────────────────────── BitReader ─────────────────────────────

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // 位偏移
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn read_bits(&mut self, n: usize) -> Option<u32> {
        if self.pos + n > self.data.len() * 8 {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.data[self.pos / 8];
            let bit = (byte >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | bit as u32;
            self.pos += 1;
        }
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;

    #[test]
    fn round_trip_v1q_hello() {
        let original = b"HELLO WORLD";
        let (matrix, _, _) = encode::encode(original, EcLevel::Q).unwrap();
        let recovered = decode(&matrix).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn round_trip_otpauth_uri() {
        let uri = b"otpauth://totp/Lab10:lihao@golia.jp?secret=GEZDGNBVGY3TQOJQ&issuer=Lab10";
        let (matrix, version, _) = encode::encode(uri, EcLevel::M).unwrap();
        let recovered = decode(&matrix).unwrap();
        assert_eq!(recovered, uri);
        // 这种长度 (~70 字节) M 级应该挑 v5/v6 量级
        assert!(version.0 >= 4);
    }

    #[test]
    fn round_trip_various_versions_and_levels() {
        // 几个不同长度和 EC 级别。
        let cases: &[(&[u8], EcLevel)] = &[
            (b"x", EcLevel::L),
            (b"hello", EcLevel::M),
            (b"abcdefghijklmnopqrstuvwxyz", EcLevel::Q),
            (b"otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme", EcLevel::H),
        ];
        for (data, level) in cases {
            let (matrix, _, _) = encode::encode(data, *level).unwrap();
            let recovered = decode(&matrix).unwrap();
            assert_eq!(&recovered, data);
        }
    }

    #[test]
    fn round_trip_corrupted_modules() {
        // 随便挑一个 H 级别，故意翻几个数据模块；应靠 RS 纠回。
        let original = b"Hello, world!";
        let (mut matrix, _, _) = encode::encode(original, EcLevel::H).unwrap();
        // 翻 3 个数据区模块
        let n = matrix.size;
        let mut count = 0;
        'outer: for r in 5..n {
            for c in 5..n {
                if !matrix.is_reserved(r, c) {
                    let v = matrix.get(r, c);
                    matrix.set_data(r, c, !v);
                    count += 1;
                    if count >= 3 {
                        break 'outer;
                    }
                }
            }
        }
        let recovered = decode(&matrix).unwrap();
        assert_eq!(recovered, original);
    }
}
