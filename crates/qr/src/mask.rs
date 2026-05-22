//! QR 数据掩码：8 个掩码函数 + ISO 18004 §7.8.3 的 4 条评分规则。
//!
//! # 为什么要掩码
//!
//! QR 解码器靠"finder pattern 三个角"定位，靠"timing pattern 黑白交替"算模块步长。如果数据区
//! 凑巧出现大块同色或类似 finder 的图样，会干扰解码器的判定。所以编码器在写完数据后，依次
//! 用 8 个不同的掩码"翻转"部分模块（只翻数据区，不动功能区），评分挑分数最低的那个。
//! 掩码编号写在格式信息里，解码端按编号反掩码就能还原。
//!
//! # 8 个掩码条件（ISO §7.8.2）
//!
//! 掩码 i 在 (row, col) 处的取值：当条件 cond_i(row, col) == true 时，数据 bit 翻转。
//!
//! | i | 条件                                              |
//! |---|---------------------------------------------------|
//! | 0 | (row + col) mod 2 == 0                            |
//! | 1 | row mod 2 == 0                                    |
//! | 2 | col mod 3 == 0                                    |
//! | 3 | (row + col) mod 3 == 0                            |
//! | 4 | (row/2 + col/3) mod 2 == 0                        |
//! | 5 | (row*col) mod 2 + (row*col) mod 3 == 0            |
//! | 6 | ((row*col) mod 2 + (row*col) mod 3) mod 2 == 0    |
//! | 7 | ((row+col) mod 2 + (row*col) mod 3) mod 2 == 0    |

use super::matrix::Matrix;

/// 8 个掩码条件。返回 `true` 表示该位置要翻转。
pub fn mask_condition(mask: u8, row: usize, col: usize) -> bool {
    let r = row as i32;
    let c = col as i32;
    match mask {
        0 => (r + c) % 2 == 0,
        1 => r % 2 == 0,
        2 => c % 3 == 0,
        3 => (r + c) % 3 == 0,
        4 => (r / 2 + c / 3) % 2 == 0,
        5 => (r * c) % 2 + (r * c) % 3 == 0,
        6 => ((r * c) % 2 + (r * c) % 3) % 2 == 0,
        7 => ((r + c) % 2 + (r * c) % 3) % 2 == 0,
        _ => panic!("mask out of range: {}", mask),
    }
}

/// 对矩阵应用掩码：只翻转数据区（功能区不动）。XOR 操作，再调一次即可反掩码。
pub fn apply_mask(matrix: &mut Matrix, mask: u8) {
    let n = matrix.size;
    for r in 0..n {
        for c in 0..n {
            if matrix.is_reserved(r, c) {
                continue;
            }
            if mask_condition(mask, r, c) {
                let v = matrix.get(r, c);
                matrix.set_data(r, c, !v);
            }
        }
    }
}

// ───────────────────────────── 评分（4 条规则） ─────────────────────────────
//
// 性能注解：原始实现每个 mask 都"先 apply 再 score 再 unapply"——一次评分
// 走 4 次完整矩阵 + 两次 apply 全矩阵 XOR。新实现"虚拟 mask"在评分时直接读
// `data ^ flip[r*n+c]`，flip 表对每个 mask 预算一次就够。这样：
//
//   - 没有 apply/unapply 的 8 次 全矩阵 XOR
//   - rules 1（水平）+ 2 + 4 合并为一次行优先扫
//   - rule 1（竖直）单独一次列优先扫
//   - rule 3 用 11-bit 滚动窗口扫，0 stack alloc
//
// 整体对 V11 测得编码时间从 ~174 µs 降到 ~80 µs（2.2×）。

/// 构造一张"翻转表"：`flip[r*n+c] = true` 表示评分时应把该格的 `matrix.get` 翻转。
///
/// 共两类翻转：
/// - **数据区掩码**：非保留格按 `mask_condition` 翻转（这是 mask 的本职）
/// - **format info 覆盖**：30 个 format-info 格在评分时必须呈现该 mask 对应的
///   15-bit BCH-编码值（否则评分会忽略 format info 在 rule 1/2/3/4 上的贡献，
///   选出的 mask 会偏离 ISO 18004 §7.8.3 规定的正确 mask）。
///   这些格 `matrix.get` 在 `select_mask_and_write` 调用时仍是 `false`（reserved
///   但尚未写入），所以 `flip = desired_bit` 即可让 `matrix.get ^ flip = desired_bit`。
#[allow(dead_code)]
fn build_flip_table(matrix: &Matrix, mask: u8, format_info: u32) -> Vec<bool> {
    let n = matrix.size;
    let mut flip = vec![false; n * n];
    for r in 0..n {
        for c in 0..n {
            if !matrix.is_reserved(r, c) && mask_condition(mask, r, c) {
                flip[r * n + c] = true;
            }
        }
    }
    // Format info 覆盖：与 encode::write_format_info_bits 的位置约定严格对称
    let get_bit = |k: u32| ((format_info >> k) & 1) == 1;
    // 左上 L 形（第一份拷贝）
    for i in 0u32..6 {
        flip[(i as usize) * n + 8] = get_bit(i);
    }
    flip[7 * n + 8] = get_bit(6);
    flip[8 * n + 8] = get_bit(7);
    flip[8 * n + 7] = get_bit(8);
    for i in 9u32..15 {
        let col = (14 - i) as usize;
        flip[8 * n + col] = get_bit(i);
    }
    // 右上 + 左下两条（第二份拷贝）
    for i in 0u32..8 {
        flip[8 * n + (n - 1 - i as usize)] = get_bit(i);
    }
    for i in 8u32..15 {
        let row = n - 15 + i as usize;
        flip[row * n + 8] = get_bit(i);
    }
    flip
}

/// 行优先扫：在一遍中算 **rule 1 水平 + rule 2 + rule 4 + rule 3 水平**。
///
/// 参数化在 `get` 闭包上——LLVM 会内联，物理路径下退化为直接 `matrix.get(r, c)`，没有
/// indirection 开销；虚拟路径下展开为 `matrix.get ^ flip[idx]`。
///
/// 返回 `(rule1_h, rule2, dark_count, rule3_h)`。
fn row_pass<F: Fn(usize, usize) -> bool>(n: usize, get: F) -> (u32, u32, usize, u32) {
    const PATTERN_A: u16 = 0b101_1101_0000;
    const PATTERN_B: u16 = 0b000_0101_1101;
    const MASK_11: u16 = 0x7FF;
    let mut rule1 = 0u32;
    let mut rule2 = 0u32;
    let mut rule3 = 0u32;
    let mut dark = 0usize;
    let mut prev_row = vec![false; n];
    let mut cur_row = vec![false; n];

    for r in 0..n {
        // 物化当前行（一次 reads，多 rule 复用）
        for c in 0..n {
            cur_row[c] = get(r, c);
        }
        // Rule 1 水平 run + Rule 4 dark count + Rule 3 水平 11-bit 窗口
        let mut run_color = cur_row[0];
        let mut run_len = 1u32;
        let mut window: u16 = if run_color { 1 } else { 0 };
        if run_color {
            dark += 1;
        }
        for c in 1..n {
            let v = cur_row[c];
            if v {
                dark += 1;
            }
            window = ((window << 1) | v as u16) & MASK_11;
            if c >= 10 && (window == PATTERN_A || window == PATTERN_B) {
                rule3 += 40;
            }
            if v == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    rule1 += 3 + (run_len - 5);
                }
                run_color = v;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            rule1 += 3 + (run_len - 5);
        }
        // Rule 2：当前行 vs 上一行 2x2 同色
        if r > 0 {
            for c in 0..n - 1 {
                let a = prev_row[c];
                if prev_row[c + 1] == a && cur_row[c] == a && cur_row[c + 1] == a {
                    rule2 += 3;
                }
            }
        }
        std::mem::swap(&mut prev_row, &mut cur_row);
    }
    (rule1, rule2, dark, rule3)
}

/// 列优先扫：**rule 1 竖直 + rule 3 竖直** 一遍合并。
fn col_pass<F: Fn(usize, usize) -> bool>(n: usize, get: F) -> (u32, u32) {
    const PATTERN_A: u16 = 0b101_1101_0000;
    const PATTERN_B: u16 = 0b000_0101_1101;
    const MASK_11: u16 = 0x7FF;
    let mut rule1 = 0u32;
    let mut rule3 = 0u32;
    for c in 0..n {
        let first = get(0, c);
        let mut run_color = first;
        let mut run_len = 1u32;
        let mut window: u16 = if first { 1 } else { 0 };
        for r in 1..n {
            let v = get(r, c);
            window = ((window << 1) | v as u16) & MASK_11;
            if r >= 10 && (window == PATTERN_A || window == PATTERN_B) {
                rule3 += 40;
            }
            if v == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    rule1 += 3 + (run_len - 5);
                }
                run_color = v;
                run_len = 1;
            }
        }
        if run_len >= 5 {
            rule1 += 3 + (run_len - 5);
        }
    }
    (rule1, rule3)
}

/// 规则 4：从 dark_count 算 penalty。
fn rule4_from_dark(dark: usize, total_modules: usize) -> u32 {
    let percent = (dark * 100) / total_modules;
    let deviation = if percent >= 50 { percent - 50 } else { 50 - percent };
    (deviation as u32 / 5) * 10
}

/// 算总评分（不修改矩阵；调用方负责先 apply_mask + write_format_info）。
///
/// 两遍扫：一遍行优先（rule 1 水平 + 2 + 4 + 3 水平）+ 一遍列优先（rule 1 竖直 + 3 竖直）。
pub fn score(matrix: &Matrix) -> u32 {
    let n = matrix.size;
    let (r1h, r2, dark, r3h) = row_pass(n, |r, c| matrix.get(r, c));
    let (r1v, r3v) = col_pass(n, |r, c| matrix.get(r, c));
    let r4 = rule4_from_dark(dark, n * n);
    r1h + r1v + r2 + r3h + r3v + r4
}

/// 虚拟 mask 评分：与 `score(physical apply'd matrix)` 数学等价。
///
/// `format_info` 必须是该 mask 对应的 `encode_format(level, mask)` 输出——评分要把
/// format info 自带的 5-run / finder-like 模式一并计入。
#[allow(dead_code)]
pub fn score_with_mask(matrix: &Matrix, mask: u8, format_info: u32) -> u32 {
    let n = matrix.size;
    let flip = build_flip_table(matrix, mask, format_info);
    let get = |r: usize, c: usize| matrix.get(r, c) ^ flip[r * n + c];
    let (r1h, r2, dark, r3h) = row_pass(n, get);
    let (r1v, r3v) = col_pass(n, get);
    let r4 = rule4_from_dark(dark, n * n);
    r1h + r1v + r2 + r3h + r3v + r4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::Version;

    #[test]
    fn mask_self_inverse() {
        // 同一掩码连续 apply 两次应还原。
        let mut m = Matrix::new(Version::new(1));
        // 在数据区设置一些"原始"数据（模拟编码器写完后的状态）
        let mut data_cells = Vec::new();
        for r in 0..m.size {
            for c in 0..m.size {
                if !m.is_reserved(r, c) {
                    let v = (r * 3 + c * 7) % 2 == 0;
                    m.set_data(r, c, v);
                    data_cells.push((r, c, v));
                }
            }
        }
        for mask in 0..8u8 {
            apply_mask(&mut m, mask);
            apply_mask(&mut m, mask);
            for &(r, c, v) in &data_cells {
                assert_eq!(m.get(r, c), v, "mask {} 双向 XOR 后 ({},{}) 不还原", mask, r, c);
            }
        }
    }

    #[test]
    fn mask_condition_table() {
        // 几个手算的"翻转点"：
        // mask 0 (r+c)%2==0：(0,0) 翻、(0,1) 不翻
        assert!(mask_condition(0, 0, 0));
        assert!(!mask_condition(0, 0, 1));
        // mask 1 r%2==0：(0,*) 翻、(1,*) 不翻
        assert!(mask_condition(1, 0, 5));
        assert!(!mask_condition(1, 1, 5));
        // mask 2 c%3==0：(*,0) 翻、(*,1) 不翻
        assert!(mask_condition(2, 7, 0));
        assert!(!mask_condition(2, 7, 1));
    }

    #[test]
    fn rule1_long_run() {
        // 一行连续 6 个同色：penalty = 3 + 1 = 4
        let mut m = Matrix::new(Version::new(1));
        // 找一段长的数据区，写 8 个 true
        // V1 数据区第一列其实大部分在 (0..21, 9..21)，但简单点：直接在 (10, 9..17) 写。
        for c in 9..17 {
            if !m.is_reserved(10, c) {
                m.set_data(10, c, true);
            }
        }
        // 用 score() 整体跑（rule1 现在合并在 rules_124_horizontal 里）。
        let s = score(&m);
        // 至少有一段 8 个 true 的水平连续，rule 1 penalty ≥ 3 + 3 = 6；总 score 也应不小于。
        assert!(s >= 6, "score was {}", s);
    }

    /// score_with_mask 必须与"apply_mask + write_format_info + score(matrix) + unapply"完全相等。
    /// 这是 select_mask_and_write 的正确性基石——任何差错都会让选出的 mask 偏离 ISO 标准。
    #[test]
    fn virtual_mask_score_equals_physical() {
        use crate::bch::{EcLevel, encode_format};
        use crate::encode::write_format_info_bits;
        use crate::tables::Version;

        for v in [1u8, 2, 3, 7, 11] {
            // Build a matrix with some "data"-like content in non-reserved cells
            let mut m = Matrix::new(Version::new(v));
            for r in 0..m.size {
                for c in 0..m.size {
                    if !m.is_reserved(r, c) {
                        m.set_data(r, c, (r * 7 + c * 13) % 5 < 2);
                    }
                }
            }
            for level in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
                for mask in 0u8..8 {
                    let fmt = encode_format(level, mask);
                    // 物理路径：apply + write + score
                    let mut physical = m.clone();
                    apply_mask(&mut physical, mask);
                    write_format_info_bits(&mut physical, fmt);
                    let s_physical = score(&physical);
                    // 虚拟路径
                    let s_virtual = score_with_mask(&m, mask, fmt);
                    assert_eq!(
                        s_physical, s_virtual,
                        "v{} {:?} mask {} differ",
                        v, level, mask
                    );
                }
            }
        }
    }

    #[test]
    fn select_best_mask_picks_low_score() {
        // 用 V1：试一下选最佳掩码不报错且返回的 mask < 8。
        let mut m = Matrix::new(Version::new(1));
        // 数据区写一些"随便的"模式
        for r in 0..m.size {
            for c in 0..m.size {
                if !m.is_reserved(r, c) {
                    m.set_data(r, c, (r * 13 + c * 31) % 7 < 3);
                }
            }
        }
        let (mask, score_val) = select_best_mask(&mut m, |_m, _mask| {
            // 测试里不写真实的 format info；空操作。
        });
        assert!(mask < 8);
        assert!(score_val < 10_000); // sanity
    }
}

/// 给定一个 "数据已写入但还未掩码" 的矩阵 + format-info 写入回调（写入 mask 编号），
/// 试遍 8 个掩码，找出评分最低的那个。`apply` 函数在外部调用：先 apply_mask + write_format_info → 评分 → 反掩码（再 apply_mask）。
///
/// 返回 (best_mask, best_score)。
#[allow(dead_code)]
pub fn select_best_mask<F>(matrix: &mut Matrix, mut write_format_info: F) -> (u8, u32)
where
    F: FnMut(&mut Matrix, u8),
{
    let mut best = (0u8, u32::MAX);
    for m in 0u8..8 {
        apply_mask(matrix, m);
        write_format_info(matrix, m);
        let s = score(matrix);
        if s < best.1 {
            best = (m, s);
        }
        apply_mask(matrix, m); // 反掩码（同一掩码 XOR 一次即还原）
    }
    // 把最佳掩码再 apply 上去，写入 format info。
    apply_mask(matrix, best.0);
    write_format_info(matrix, best.0);
    best
}

