//! QR 码规范表（ISO/IEC 18004）：版本容量、EC 块结构、对齐图案位置。
//!
//! 这些表是 QR 标准的"原始数据"，没有公式能简洁推出，每个版本都得查表。所有数字来自 ISO 18004
//! 附录，用 Thonky QR 教程交叉验证。typo 会导致很难调试的错误，所以测试里加了"总字节数 == 版本字节数"
//! 的自洽检查。

use super::bch::EcLevel;

/// EC 块结构：一个版本+EC 级别对应一组数据块。每块都用相同的 EC codeword 数（`ec_per_block`），
/// 但数据 codeword 数可能分成两组（group1 / group2，group2 比 group1 多 1）。
///
/// 例：V5-Q 是 `{ec_per_block: 18, group1: (2, 15), group2: Some((2, 16))}`
/// 即"2 个 15 数据 + 18 EC 的块"加"2 个 16 数据 + 18 EC 的块"。
#[derive(Debug, Clone, Copy)]
pub struct EcBlockInfo {
    pub ec_per_block: u16,
    pub group1: (u16, u16),
    pub group2: Option<(u16, u16)>,
}

impl EcBlockInfo {
    /// 数据 codeword 总数（不含 EC）。
    pub fn total_data_codewords(&self) -> u16 {
        let g1 = self.group1.0 * self.group1.1;
        let g2 = self.group2.map(|(n, d)| n * d).unwrap_or(0);
        g1 + g2
    }

    /// 块总数。
    pub fn total_blocks(&self) -> u16 {
        self.group1.0 + self.group2.map(|(n, _)| n).unwrap_or(0)
    }

    /// EC codeword 总数。
    pub fn total_ec_codewords(&self) -> u16 {
        self.total_blocks() * self.ec_per_block
    }
}

/// QR version number, in the range 1..=40.
///
/// The matrix side length is `17 + 4 * version` modules — v1 = 21×21, v40 = 177×177.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(
    /// Raw version number (1..=40).
    pub u8,
);

impl Version {
    /// Create a [`Version`]. Panics if `v` is not in `1..=40`.
    pub fn new(v: u8) -> Self {
        assert!((1..=40).contains(&v));
        Self(v)
    }
    /// Side length of the module matrix: `17 + 4 * version`.
    pub fn size(self) -> usize {
        17 + 4 * self.0 as usize
    }
}

/// 各版本的"总 codeword 数"（= 数据 + EC）。索引 = version - 1。
#[allow(dead_code)]
pub const TOTAL_CODEWORDS: [u16; 40] = [
    26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901, 991,
    1085, 1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611, 2761, 2876,
    3034, 3196, 3362, 3532, 3706,
];

/// EC 块结构表。维度：[40 版本][4 级别]（级别顺序 L, M, Q, H）。
#[rustfmt::skip]
const EC_BLOCKS: [[EcBlockInfo; 4]; 40] = [
    // V1
    [ b1(7,1,19),  b1(10,1,16), b1(13,1,13), b1(17,1,9) ],
    // V2
    [ b1(10,1,34), b1(16,1,28), b1(22,1,22), b1(28,1,16) ],
    // V3
    [ b1(15,1,55), b1(26,1,44), b1(18,2,17), b1(22,2,13) ],
    // V4
    [ b1(20,1,80), b1(18,2,32), b1(26,2,24), b1(16,4,9) ],
    // V5
    [ b1(26,1,108), b1(24,2,43), b2(18,2,15,2,16), b2(22,2,11,2,12) ],
    // V6
    [ b1(18,2,68), b1(16,4,27), b1(24,4,19), b1(28,4,15) ],
    // V7
    [ b1(20,2,78), b1(18,4,31), b2(18,2,14,4,15), b2(26,4,13,1,14) ],
    // V8
    [ b1(24,2,97), b2(22,2,38,2,39), b2(22,4,18,2,19), b2(26,4,14,2,15) ],
    // V9
    [ b1(30,2,116), b2(22,3,36,2,37), b2(20,4,16,4,17), b2(24,4,12,4,13) ],
    // V10
    [ b2(18,2,68,2,69), b2(26,4,43,1,44), b2(24,6,19,2,20), b2(28,6,15,2,16) ],
    // V11
    [ b1(20,4,81), b2(30,1,50,4,51), b2(28,4,22,4,23), b2(24,3,12,8,13) ],
    // V12
    [ b2(24,2,92,2,93), b2(22,6,36,2,37), b2(26,4,20,6,21), b2(28,7,14,4,15) ],
    // V13
    [ b1(26,4,107), b2(22,8,37,1,38), b2(24,8,20,4,21), b2(22,12,11,4,12) ],
    // V14
    [ b2(30,3,115,1,116), b2(24,4,40,5,41), b2(20,11,16,5,17), b2(24,11,12,5,13) ],
    // V15
    [ b2(22,5,87,1,88), b2(24,5,41,5,42), b2(30,5,24,7,25), b2(24,11,12,7,13) ],
    // V16
    [ b2(24,5,98,1,99), b2(28,7,45,3,46), b2(24,15,19,2,20), b2(30,3,15,13,16) ],
    // V17
    [ b2(28,1,107,5,108), b2(28,10,46,1,47), b2(28,1,22,15,23), b2(28,2,14,17,15) ],
    // V18
    [ b2(30,5,120,1,121), b2(26,9,43,4,44), b2(28,17,22,1,23), b2(28,2,14,19,15) ],
    // V19
    [ b2(28,3,113,4,114), b2(26,3,44,11,45), b2(26,17,21,4,22), b2(26,9,13,16,14) ],
    // V20
    [ b2(28,3,107,5,108), b2(26,3,41,13,42), b2(30,15,24,5,25), b2(28,15,15,10,16) ],
    // V21
    [ b2(28,4,116,4,117), b1(26,17,42), b2(28,17,22,6,23), b2(30,19,16,6,17) ],
    // V22
    [ b2(28,2,111,7,112), b1(28,17,46), b2(30,7,24,16,25), b1(24,34,13) ],
    // V23
    [ b2(30,4,121,5,122), b2(28,4,47,14,48), b2(30,11,24,14,25), b2(30,16,15,14,16) ],
    // V24
    [ b2(30,6,117,4,118), b2(28,6,45,14,46), b2(30,11,24,16,25), b2(30,30,16,2,17) ],
    // V25
    [ b2(26,8,106,4,107), b2(28,8,47,13,48), b2(30,7,24,22,25), b2(30,22,15,13,16) ],
    // V26
    [ b2(28,10,114,2,115), b2(28,19,46,4,47), b2(28,28,22,6,23), b2(30,33,16,4,17) ],
    // V27
    [ b2(30,8,122,4,123), b2(28,22,45,3,46), b2(30,8,23,26,24), b2(30,12,15,28,16) ],
    // V28
    [ b2(30,3,117,10,118), b2(28,3,45,23,46), b2(30,4,24,31,25), b2(30,11,15,31,16) ],
    // V29
    [ b2(30,7,116,7,117), b2(28,21,45,7,46), b2(30,1,23,37,24), b2(30,19,15,26,16) ],
    // V30
    [ b2(30,5,115,10,116), b2(28,19,47,10,48), b2(30,15,24,25,25), b2(30,23,15,25,16) ],
    // V31
    [ b2(30,13,115,3,116), b2(28,2,46,29,47), b2(30,42,24,1,25), b2(30,23,15,28,16) ],
    // V32
    [ b1(30,17,115), b2(28,10,46,23,47), b2(30,10,24,35,25), b2(30,19,15,35,16) ],
    // V33
    [ b2(30,17,115,1,116), b2(28,14,46,21,47), b2(30,29,24,19,25), b2(30,11,15,46,16) ],
    // V34
    [ b2(30,13,115,6,116), b2(28,14,46,23,47), b2(30,44,24,7,25), b2(30,59,16,1,17) ],
    // V35
    [ b2(30,12,121,7,122), b2(28,12,47,26,48), b2(30,39,24,14,25), b2(30,22,15,41,16) ],
    // V36
    [ b2(30,6,121,14,122), b2(28,6,47,34,48), b2(30,46,24,10,25), b2(30,2,15,64,16) ],
    // V37
    [ b2(30,17,122,4,123), b2(28,29,46,14,47), b2(30,49,24,10,25), b2(30,24,15,46,16) ],
    // V38
    [ b2(30,4,122,18,123), b2(28,13,46,32,47), b2(30,48,24,14,25), b2(30,42,15,32,16) ],
    // V39
    [ b2(30,20,117,4,118), b2(28,40,47,7,48), b2(30,43,24,22,25), b2(30,10,15,67,16) ],
    // V40
    [ b2(30,19,118,6,119), b2(28,18,47,31,48), b2(30,34,24,34,25), b2(30,20,15,61,16) ],
];

const fn b1(ec: u16, n: u16, d: u16) -> EcBlockInfo {
    EcBlockInfo {
        ec_per_block: ec,
        group1: (n, d),
        group2: None,
    }
}
const fn b2(ec: u16, n1: u16, d1: u16, n2: u16, d2: u16) -> EcBlockInfo {
    EcBlockInfo {
        ec_per_block: ec,
        group1: (n1, d1),
        group2: Some((n2, d2)),
    }
}

/// 取 EC 块结构。
pub fn ec_blocks(version: Version, level: EcLevel) -> EcBlockInfo {
    let idx = level_index(level);
    EC_BLOCKS[version.0 as usize - 1][idx]
}

fn level_index(level: EcLevel) -> usize {
    match level {
        EcLevel::L => 0,
        EcLevel::M => 1,
        EcLevel::Q => 2,
        EcLevel::H => 3,
    }
}

/// 对齐图案的中心坐标列表。所有"对齐图案"放在这些坐标的笛卡尔积上（除了与 finder 重叠的角）。
///
/// V1 无对齐图案，返回空切片。
pub fn alignment_centers(version: Version) -> &'static [u8] {
    ALIGNMENT_CENTERS[version.0 as usize - 1]
}

const ALIGNMENT_CENTERS: [&[u8]; 40] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
    &[6, 34, 62],
    &[6, 26, 46, 66],
    &[6, 26, 48, 70],
    &[6, 26, 50, 74],
    &[6, 30, 54, 78],
    &[6, 30, 56, 82],
    &[6, 30, 58, 86],
    &[6, 34, 62, 90],
    &[6, 28, 50, 72, 94],
    &[6, 26, 50, 74, 98],
    &[6, 30, 54, 78, 102],
    &[6, 28, 54, 80, 106],
    &[6, 32, 58, 84, 110],
    &[6, 30, 58, 86, 114],
    &[6, 34, 62, 90, 118],
    &[6, 26, 50, 74, 98, 122],
    &[6, 30, 54, 78, 102, 126],
    &[6, 26, 52, 78, 104, 130],
    &[6, 30, 56, 82, 108, 134],
    &[6, 34, 60, 86, 112, 138],
    &[6, 30, 58, 86, 114, 142],
    &[6, 34, 62, 90, 118, 146],
    &[6, 30, 54, 78, 102, 126, 150],
    &[6, 24, 50, 76, 102, 128, 154],
    &[6, 28, 54, 80, 106, 132, 158],
    &[6, 32, 58, 84, 110, 136, 162],
    &[6, 26, 54, 82, 110, 138, 166],
    &[6, 30, 58, 86, 114, 142, 170],
];

/// 字节模式的"字符计数指示符"位长。
/// QR 标准 §8.4.1：v1-9 = 8 位，v10-40 = 16 位。
pub fn byte_mode_count_bits(version: Version) -> usize {
    if version.0 <= 9 {
        8
    } else {
        16
    }
}

/// 字节模式可编码的最大字节数（数据净荷）。
///
/// 总数据 bit = total_data_codewords * 8
/// 减去：模式指示 4 位 + 字符计数指示 N 位 + 末尾 0 bits（≤4，可舍）
/// 剩下的字节数 = (total_data_bits - 4 - count_bits) / 8
pub fn byte_mode_max_capacity(version: Version, level: EcLevel) -> usize {
    let total_data_bits = ec_blocks(version, level).total_data_codewords() as usize * 8;
    let overhead = 4 + byte_mode_count_bits(version);
    (total_data_bits - overhead) / 8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部 40 版本 × 4 级别：data + ec 总数 == TOTAL_CODEWORDS[version-1]。
    #[test]
    fn ec_blocks_match_total_codewords() {
        for v in 1..=40u8 {
            let version = Version::new(v);
            let expected = TOTAL_CODEWORDS[v as usize - 1];
            for level in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
                let info = ec_blocks(version, level);
                let actual = info.total_data_codewords() + info.total_ec_codewords();
                assert_eq!(
                    actual, expected,
                    "v{} {:?}: data={} + ec={} != total={}",
                    v,
                    level,
                    info.total_data_codewords(),
                    info.total_ec_codewords(),
                    expected
                );
            }
        }
    }

    /// 矩阵大小公式：21 + 4 * (v-1) = 17 + 4v。V1=21, V40=177。
    #[test]
    fn version_sizes() {
        assert_eq!(Version::new(1).size(), 21);
        assert_eq!(Version::new(2).size(), 25);
        assert_eq!(Version::new(7).size(), 45);
        assert_eq!(Version::new(40).size(), 177);
    }

    /// 对齐图案中心数：V1=0, V2-6=2, V7-13=3, V14-20=4, V21-27=5, V28-34=6, V35-40=7。
    #[test]
    fn alignment_centers_count() {
        for v in 1..=40u8 {
            let n = alignment_centers(Version::new(v)).len();
            let expected = match v {
                1 => 0,
                2..=6 => 2,
                7..=13 => 3,
                14..=20 => 4,
                21..=27 => 5,
                28..=34 => 6,
                35..=40 => 7,
                _ => unreachable!(),
            };
            assert_eq!(n, expected, "v{}: alignment count", v);
        }
    }

    #[test]
    fn byte_capacity_v1_l() {
        // V1-L: 19 data codewords = 152 bits。减去 4 (mode) + 8 (count) = 140 bits = 17 bytes 余 4 bits。
        assert_eq!(byte_mode_max_capacity(Version::new(1), EcLevel::L), 17);
    }

    #[test]
    fn byte_capacity_v10_h() {
        // V10-H: data codewords = 6*15 + 2*16 = 122 → 976 bits。减 4 + 16 (v>=10 用 16 位 count) = 956 / 8 = 119
        assert_eq!(byte_mode_max_capacity(Version::new(10), EcLevel::H), 119);
    }
}
