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

/// 规则 1：行/列方向连续 ≥ 5 个同色，penalty = 3 + (run_len - 5)。每行每列各算。
fn rule1(matrix: &Matrix) -> u32 {
    let n = matrix.size;
    let mut total = 0u32;
    for r in 0..n {
        total += run_score_along(|c| matrix.get(r, c), n);
    }
    for c in 0..n {
        total += run_score_along(|r| matrix.get(r, c), n);
    }
    total
}

fn run_score_along<F: Fn(usize) -> bool>(get: F, n: usize) -> u32 {
    let mut score = 0u32;
    let mut run_color = get(0);
    let mut run_len = 1u32;
    for i in 1..n {
        let v = get(i);
        if v == run_color {
            run_len += 1;
        } else {
            if run_len >= 5 {
                score += 3 + (run_len - 5);
            }
            run_color = v;
            run_len = 1;
        }
    }
    if run_len >= 5 {
        score += 3 + (run_len - 5);
    }
    score
}

/// 规则 2：每个 2×2 同色方块 +3。
fn rule2(matrix: &Matrix) -> u32 {
    let n = matrix.size;
    let mut total = 0u32;
    for r in 0..n - 1 {
        for c in 0..n - 1 {
            let a = matrix.get(r, c);
            if matrix.get(r, c + 1) == a && matrix.get(r + 1, c) == a && matrix.get(r + 1, c + 1) == a
            {
                total += 3;
            }
        }
    }
    total
}

/// 规则 3：1:1:3:1:1（finder 比例）模式两端再加 4 个浅模块。每出现一次 +40。
/// 模式即 BBWBBBWBB（黑白黑黑黑白黑）右边或左边接 4 个白，共 11 模块。
/// 水平方向 + 垂直方向都查。
fn rule3(matrix: &Matrix) -> u32 {
    let n = matrix.size;
    let mut total = 0u32;
    // 两个"坏"图样：左侧 4 白 + finder，或 finder + 右侧 4 白。
    let pattern_a: [bool; 11] = [false, false, false, false, true, false, true, true, true, false, true];
    let pattern_b: [bool; 11] = [true, false, true, true, true, false, true, false, false, false, false];
    for r in 0..n {
        for c in 0..=n - 11 {
            let mut buf = [false; 11];
            for k in 0..11 {
                buf[k] = matrix.get(r, c + k);
            }
            if buf == pattern_a || buf == pattern_b {
                total += 40;
            }
        }
    }
    for c in 0..n {
        for r in 0..=n - 11 {
            let mut buf = [false; 11];
            for k in 0..11 {
                buf[k] = matrix.get(r + k, c);
            }
            if buf == pattern_a || buf == pattern_b {
                total += 40;
            }
        }
    }
    total
}

/// 规则 4：黑色比例偏离 50% 越远，penalty 越大。
/// penalty = 10 * floor(|dark% - 50| / 5)
fn rule4(matrix: &Matrix) -> u32 {
    let n = matrix.size;
    let total_modules = n * n;
    let dark = matrix.modules_iter().filter(|&&v| v).count();
    let percent = (dark * 100) / total_modules;
    let deviation = if percent >= 50 { percent - 50 } else { 50 - percent };
    (deviation as u32 / 5) * 10
}

/// 总评分。
pub fn score(matrix: &Matrix) -> u32 {
    rule1(matrix) + rule2(matrix) + rule3(matrix) + rule4(matrix)
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
        let s = rule1(&m);
        // 至少有一段 8 个 true 的水平连续，penalty ≥ 3 + 3 = 6（实际可能因周边更多）。
        assert!(s >= 6, "rule1 score was {}", s);
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

