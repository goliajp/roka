//! QR 编码：字节 → 完整的 QR 模块矩阵。
//!
//! 流程（ISO 18004 §8）：
//!   1. 挑能装下输入的最小版本
//!   2. 构造 bitstream：mode(4) + count(8/16) + payload + terminator + 填充
//!   3. 按 EC 块结构切块、给每块算 RS EC
//!   4. 交错块（data 部分 + EC 部分各自交错）
//!   5. 末尾追加 remainder bits（0..7 个 0）
//!   6. 按 zigzag 路径把 bit 流写入矩阵的数据区
//!   7. 试遍 8 个掩码、写 format info、选评分最低者
//!   8. v7+ 写 version info

use super::bch::{encode_format, encode_version, EcLevel};
use super::mask::{apply_mask, score};
use super::matrix::Matrix;
use super::reed_solomon;
use super::tables::{byte_mode_count_bits, byte_mode_max_capacity, ec_blocks, Version};

/// 寻找能装下 `data_len` 字节（byte mode）的最小版本。
pub fn find_min_version(data_len: usize, level: EcLevel) -> Result<Version, &'static str> {
    for v in 1u8..=40 {
        let version = Version::new(v);
        if data_len <= byte_mode_max_capacity(version, level) {
            return Ok(version);
        }
    }
    Err("data too large for QR (max version 40)")
}

/// 把数据组装为完整的 bit 流（已 pad 到 data 容量）。
///
/// 返回的是一个 byte 序列，每个 byte 是 8 个 bit；下游可以位精确处理。
/// 长度 = data_codewords_capacity (字节)。
fn build_data_codewords(data: &[u8], version: Version, level: EcLevel) -> Vec<u8> {
    let total_data_bytes = ec_blocks(version, level).total_data_codewords() as usize;
    let count_bits = byte_mode_count_bits(version);

    // 用 BitWriter 累计写入。
    let mut bw = BitWriter::new();
    bw.write_bits(0b0100, 4); // 字节模式指示
    bw.write_bits(data.len() as u32, count_bits);
    for &b in data {
        bw.write_bits(b as u32, 8);
    }
    // 终止符：最多 4 个 0，若快到容量界限则截断。
    let total_bits = total_data_bytes * 8;
    let remaining = total_bits.saturating_sub(bw.len());
    let term_bits = remaining.min(4);
    bw.write_bits(0, term_bits);
    // 补齐 byte 边界。
    while bw.len() % 8 != 0 {
        bw.write_bits(0, 1);
    }
    // 用 0xEC / 0x11 交替填到容量。
    let mut toggle = false;
    while bw.byte_len() < total_data_bytes {
        bw.write_bits(if toggle { 0x11 } else { 0xEC }, 8);
        toggle = !toggle;
    }
    bw.into_bytes()
}

/// 切块 + 给每块算 EC。返回 (data_blocks, ec_blocks)，两者按 ISO 顺序（先所有 group1 块，后所有 group2 块）。
fn build_blocks(
    codewords: &[u8],
    version: Version,
    level: EcLevel,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let info = ec_blocks(version, level);
    let mut data_blocks: Vec<Vec<u8>> = Vec::new();
    let mut ec_block_vecs: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;
    for &(n, d) in [Some(info.group1), info.group2].iter().flatten() {
        for _ in 0..n {
            let block = codewords[cursor..cursor + d as usize].to_vec();
            cursor += d as usize;
            let ec = reed_solomon::encode(&block, info.ec_per_block as usize);
            data_blocks.push(block);
            ec_block_vecs.push(ec);
        }
    }
    debug_assert_eq!(cursor, codewords.len(), "数据 codeword 没用完");
    (data_blocks, ec_block_vecs)
}

/// 交错：对每个"列下标 i"，依次取每个块第 i 个 codeword（短块用完即跳）。
fn interleave_blocks(data_blocks: &[Vec<u8>], ec_blocks_vec: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let max_data_len = data_blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    for i in 0..max_data_len {
        for blk in data_blocks {
            if i < blk.len() {
                out.push(blk[i]);
            }
        }
    }
    let max_ec_len = ec_blocks_vec.iter().map(|b| b.len()).max().unwrap_or(0);
    for i in 0..max_ec_len {
        for blk in ec_blocks_vec {
            if i < blk.len() {
                out.push(blk[i]);
            }
        }
    }
    out
}

/// Remainder bits（ISO 18004 Table 1）：codeword 之后追加的 0 比特数。
pub fn remainder_bits(version: Version) -> usize {
    match version.0 {
        1 => 0,
        2..=6 => 7,
        7..=13 => 0,
        14..=20 => 3,
        21..=27 => 4,
        28..=34 => 3,
        35..=40 => 0,
        _ => unreachable!(),
    }
}

/// Zigzag 路径写入：从矩阵右下角开始，每次走两列（先右列、再左列），上下交替。
///
/// - 列 6 是 vertical timing pattern，跳过整列（zigzag 把列号减 1 表示"略过 col 6"）。
/// - 遇到 reserved 模块跳过。
pub fn write_data_zigzag(matrix: &mut Matrix, bits: &[bool]) {
    let n = matrix.size;
    let mut bit_iter = bits.iter();
    let mut upward = true; // 第一对列从下往上
    let mut right = (n as i32) - 1; // "对"的右列下标

    while right > 0 {
        if right == 6 {
            // 列 6 是 timing，跳过
            right -= 1;
        }
        for step in 0..n {
            let y = if upward { n - 1 - step } else { step };
            for j in 0..2 {
                let x = (right - j as i32) as usize;
                if !matrix.is_reserved(y, x) {
                    if let Some(&b) = bit_iter.next() {
                        matrix.set_data(y, x, b);
                    }
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

/// 写入 15 位 format info（已 BCH 编码并 mask 异或）。
/// **位置约定与 Nayuki / libqrencode 一致**（ISO/IEC 18004 §7.9.1）：
///
/// 左上 L 形（第一份拷贝）：
///   bit 0..5 沿 col 8 向下 — (0,8),(1,8),(2,8),(3,8),(4,8),(5,8)
///   bit 6 → (7,8)（跳过 row 6 的水平 timing）
///   bit 7 → (8,8)
///   bit 8 → (8,7)（跳过 col 6 的竖直 timing）
///   bit 9..14 沿 row 8 向左 — (8,5),(8,4),(8,3),(8,2),(8,1),(8,0)
///
/// 右上 + 左下两条（第二份拷贝）：
///   bit 0..7 沿 row 8 自右往左 — (8,n-1),(8,n-2),...,(8,n-8)
///   bit 8..14 沿 col 8 向下 — (n-7,8),(n-6,8),...,(n-1,8)
pub fn write_format_info_bits(matrix: &mut Matrix, fmt: u32) {
    let n = matrix.size;
    let get_bit = |k: u32| ((fmt >> k) & 1) == 1;
    // 左上：col 8 down 0..5
    for i in 0u32..6 {
        matrix.set_reserved_bit(i as usize, 8, get_bit(i));
    }
    matrix.set_reserved_bit(7, 8, get_bit(6));
    matrix.set_reserved_bit(8, 8, get_bit(7));
    matrix.set_reserved_bit(8, 7, get_bit(8));
    for i in 9u32..15 {
        // (8, 14-i) for i in 9..14: (8,5),(8,4),(8,3),(8,2),(8,1),(8,0)
        let col = (14 - i) as usize;
        matrix.set_reserved_bit(8, col, get_bit(i));
    }
    // 右上 + 左下：bit 0..7 row 8 右→左；bit 8..14 col 8 下行
    for i in 0u32..8 {
        matrix.set_reserved_bit(8, n - 1 - i as usize, get_bit(i));
    }
    for i in 8u32..15 {
        let row = n - 15 + i as usize;
        matrix.set_reserved_bit(row, 8, get_bit(i));
    }
}

/// 写入 18 位 version info（v7+）。两处 3×6 块。
pub fn write_version_info_bits(matrix: &mut Matrix, version: Version) {
    if version.0 < 7 {
        return;
    }
    let bits = encode_version(version.0);
    let n = matrix.size;
    let get_bit = |k: u32| ((bits >> k) & 1) == 1;
    for i in 0u32..18 {
        let b = get_bit(i);
        let a = n - 11 + (i % 3) as usize;
        let b_idx = (i / 3) as usize;
        matrix.set_reserved_bit(a, b_idx, b); // 左下块
        matrix.set_reserved_bit(b_idx, a, b); // 右上块
    }
}

/// 选最佳掩码：试遍 8 个、写入 format info、评分；最后留下最佳的状态。
fn select_mask_and_write(matrix: &mut Matrix, level: EcLevel) -> u8 {
    let mut best = (0u8, u32::MAX);
    for m in 0u8..8 {
        apply_mask(matrix, m);
        write_format_info_bits(matrix, encode_format(level, m));
        let s = score(matrix);
        if s < best.1 {
            best = (m, s);
        }
        apply_mask(matrix, m);
    }
    apply_mask(matrix, best.0);
    write_format_info_bits(matrix, encode_format(level, best.0));
    best.0
}

/// 顶层：把 `data` 字节编码成完整 QR 模块矩阵（已写入数据 + 掩码 + format/version info）。
pub fn encode(data: &[u8], level: EcLevel) -> Result<(Matrix, Version, u8), &'static str> {
    let version = find_min_version(data.len(), level)?;
    let codewords = build_data_codewords(data, version, level);
    let (data_blocks, ec_block_vecs) = build_blocks(&codewords, version, level);
    let interleaved = interleave_blocks(&data_blocks, &ec_block_vecs);
    let mut bits: Vec<bool> = Vec::with_capacity(interleaved.len() * 8 + 7);
    for byte in interleaved {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits.extend(std::iter::repeat(false).take(remainder_bits(version)));

    let mut matrix = Matrix::new(version);
    write_data_zigzag(&mut matrix, &bits);

    if version.0 >= 7 {
        write_version_info_bits(&mut matrix, version);
    }
    let mask = select_mask_and_write(&mut matrix, level);

    Ok((matrix, version, mask))
}

/// 公开：用指定版本编码（不让算法挑），用于测试。如果 `data` 装不下指定版本，返回 Err。
#[allow(dead_code)]
pub fn encode_at_version(
    data: &[u8],
    level: EcLevel,
    version: Version,
) -> Result<(Matrix, u8), &'static str> {
    if data.len() > byte_mode_max_capacity(version, level) {
        return Err("data too large for given version");
    }
    let codewords = build_data_codewords(data, version, level);
    let (data_blocks, ec_block_vecs) = build_blocks(&codewords, version, level);
    let interleaved = interleave_blocks(&data_blocks, &ec_block_vecs);
    let mut bits: Vec<bool> = Vec::with_capacity(interleaved.len() * 8 + 7);
    for byte in interleaved {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits.extend(std::iter::repeat(false).take(remainder_bits(version)));
    let mut matrix = Matrix::new(version);
    write_data_zigzag(&mut matrix, &bits);
    if version.0 >= 7 {
        write_version_info_bits(&mut matrix, version);
    }
    let mask = select_mask_and_write(&mut matrix, level);
    Ok((matrix, mask))
}

// ───────────────────────────── BitWriter（位累加器） ─────────────────────────────

struct BitWriter {
    buf: Vec<u8>,
    bit_pos: usize, // 当前在 buf 中的总位偏移
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }
    fn write_bits(&mut self, value: u32, n_bits: usize) {
        for i in (0..n_bits).rev() {
            let bit = (value >> i) & 1 == 1;
            self.push_bit(bit);
        }
    }
    fn push_bit(&mut self, bit: bool) {
        let byte_idx = self.bit_pos / 8;
        let bit_offset = 7 - (self.bit_pos % 8);
        if byte_idx == self.buf.len() {
            self.buf.push(0);
        }
        if bit {
            self.buf[byte_idx] |= 1 << bit_offset;
        }
        self.bit_pos += 1;
    }
    fn len(&self) -> usize {
        self.bit_pos
    }
    fn byte_len(&self) -> usize {
        (self.bit_pos + 7) / 8
    }
    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_version_byte_mode() {
        // L 级 v1 容量 17 字节，v2 容量 32（v1: 19 data - 1 mode/2 nibbles = 17）
        assert_eq!(find_min_version(17, EcLevel::L).unwrap().0, 1);
        assert_eq!(find_min_version(18, EcLevel::L).unwrap().0, 2);
        assert_eq!(find_min_version(32, EcLevel::L).unwrap().0, 2);
        assert_eq!(find_min_version(33, EcLevel::L).unwrap().0, 3);
        // 极限：超过 v40-L 容量应当出错
        assert!(find_min_version(3000, EcLevel::H).is_err());
    }

    /// V1-Q 编码 "HELLO WORLD"（11 字节）+ 字节模式。
    /// 用作 zigzag + 全 pipeline 的 smoke test：能产出合法矩阵 + format info BCH 解出 (Q, mask)。
    #[test]
    fn encode_hello_world_v1q() {
        let data = b"HELLO WORLD"; // 11 字节
        let (matrix, version, mask) = encode(data, EcLevel::Q).unwrap();
        // V1-Q 容量 17，可容 11
        assert_eq!(version.0, 1);
        assert!(mask < 8);
        // Format info 应能被反向 BCH 解码
        let bits = read_format_info_top_left(&matrix);
        let (lvl, m, dist) = crate::bch::decode_format(bits as u32).unwrap();
        assert_eq!(lvl, EcLevel::Q);
        assert_eq!(m, mask);
        assert_eq!(dist, 0);
    }

    /// 从矩阵读出左上 finder 周围的 15 位 format info，按写入约定逆序拼回 u32。
    fn read_format_info_top_left(matrix: &Matrix) -> u32 {
        let mut bits = 0u32;
        let set_if = |bit_idx: u32, on: bool| if on { 1u32 << bit_idx } else { 0u32 };
        // col 8 rows 0..5
        for i in 0u32..6 {
            bits |= set_if(i, matrix.get(i as usize, 8));
        }
        bits |= set_if(6, matrix.get(7, 8));
        bits |= set_if(7, matrix.get(8, 8));
        bits |= set_if(8, matrix.get(8, 7));
        // row 8 cols 5..0
        for i in 9u32..15 {
            bits |= set_if(i, matrix.get(8, (14 - i) as usize));
        }
        bits
    }

    /// 数据 codeword 容量检查 + Thonky 参考向量交叉验证。
    /// V1-M, 16 字节: 0x10 0x20 0x0C ... 0x11 → EC 0xA5 0x24 0xD4 ...
    /// 不过 Thonky 的"数据"已经是 mode+count+payload+pad 的产物，不是 raw bytes。
    /// 这里我们手工构造同样的 codewords。
    #[test]
    fn build_blocks_v1m_thonky() {
        let codewords = vec![
            0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11,
            0xEC, 0x11,
        ];
        let (data_blocks, ec_blocks_vec) =
            build_blocks(&codewords, Version::new(1), EcLevel::M);
        assert_eq!(data_blocks.len(), 1);
        assert_eq!(data_blocks[0], codewords);
        assert_eq!(ec_blocks_vec.len(), 1);
        assert_eq!(
            ec_blocks_vec[0],
            vec![0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55]
        );
    }

    /// 全部 40 版本 × 4 级别 × 1 字节最简 payload 都能编出来不 panic。
    #[test]
    fn smoke_all_versions() {
        for v in 1..=40u8 {
            for level in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
                let version = Version::new(v);
                let _ = encode_at_version(b"x", level, version).unwrap();
            }
        }
    }
}
