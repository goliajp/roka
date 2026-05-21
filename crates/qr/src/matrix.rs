//! QR 模块矩阵：放置所有"功能图案"（finder / alignment / timing / format/version info 占位），
//! 区分出哪些格子是固定的、哪些可写数据。
//!
//! # 坐标约定
//!
//! `(row, col)`，左上为原点，row 向下增长，col 向右增长。这与 ISO 18004 图示一致。
//!
//! # 功能图案布局速记
//!
//! ```text
//!   ┌─────┬───────────────────────┬─────┐
//!   │  F  │       timing          │  F  │  F = 7×7 finder + 1 宽 separator
//!   │     │                       │     │  timing = 1×N 交替黑白（row 6 / col 6）
//!   ├─────┘                       └─────┤
//!   │                                   │
//!   │            数据区                  │  数据区里散布若干 5×5 对齐图案
//!   │                                   │
//!   │  ┌─────┐                          │
//!   │  │  F  │     dark module 在 (4v+9, 8)
//!   │  │     │
//!   └──┴─────┴──────────────────────────┘
//! ```
//!
//! 格式信息（15 bit）占两块"L 形"区域，分布在 (top-left finder 邻边) 和 (top-right + bottom-left finder 邻边)。
//! 版本信息（v7+，18 bit）占两块 3×6 矩形，分布在 top-right finder 左方和 bottom-left finder 上方。

use super::tables::{alignment_centers, Version};

/// 模块颜色：true = "黑"（即数据 bit 为 1，扫描时识别为深色），false = "白"。
pub type Module = bool;

#[derive(Debug, Clone)]
pub struct Matrix {
    pub version: Version,
    pub size: usize,
    /// 模块值。`modules[row * size + col]` 表示 (row, col) 的颜色。
    modules: Vec<Module>,
    /// 功能区掩码。`true` = 该格被固定（包括 finder/alignment/timing/dark/format/version 占位）。
    reserved: Vec<bool>,
}

impl Matrix {
    /// 新建一个矩阵，并把全部功能图案放好；数据区留空（全 false），未保留。
    /// 注意：format / version info 的内容这里**还没填**（编码时根据 EC 级别和掩码决定），
    /// 但这些区域已被标记为 `reserved`。
    pub fn new(version: Version) -> Self {
        let size = version.size();
        let mut m = Matrix {
            version,
            size,
            modules: vec![false; size * size],
            reserved: vec![false; size * size],
        };
        m.place_finders_and_separators();
        m.place_timing_patterns();
        m.place_alignment_patterns();
        m.place_dark_module();
        m.reserve_format_info();
        if version.0 >= 7 {
            m.reserve_version_info();
        }
        m
    }

    #[inline]
    fn idx(&self, row: usize, col: usize) -> usize {
        row * self.size + col
    }

    #[inline]
    pub fn get(&self, row: usize, col: usize) -> Module {
        self.modules[self.idx(row, col)]
    }

    /// 设置一个数据模块（用于编码器写数据流时调用）。debug 模式下若试图写功能区会 panic。
    #[inline]
    pub fn set_data(&mut self, row: usize, col: usize, value: Module) {
        debug_assert!(
            !self.reserved[self.idx(row, col)],
            "set_data on reserved cell ({}, {})",
            row,
            col
        );
        let i = self.idx(row, col);
        self.modules[i] = value;
    }

    /// 设置一个功能模块（同时标 reserved）。
    fn set_function(&mut self, row: usize, col: usize, value: Module) {
        let i = self.idx(row, col);
        self.modules[i] = value;
        self.reserved[i] = true;
    }

    /// 写入 format/version info 等"将占用 reserved 区"的位（区别于 set_function：不重置 reserved）。
    pub fn set_reserved_bit(&mut self, row: usize, col: usize, value: Module) {
        let i = self.idx(row, col);
        debug_assert!(self.reserved[i], "set_reserved_bit on unreserved ({}, {})", row, col);
        self.modules[i] = value;
    }

    /// 只标 reserved，不改值（用于"将被后续填写"的 format/version info 占位）。
    fn reserve(&mut self, row: usize, col: usize) {
        let i = self.idx(row, col);
        self.reserved[i] = true;
    }

    #[inline]
    pub fn is_reserved(&self, row: usize, col: usize) -> bool {
        self.reserved[self.idx(row, col)]
    }

    /// 全部模块的只读迭代器（row-major）。供评分函数等使用。
    pub fn modules_iter(&self) -> std::slice::Iter<'_, bool> {
        self.modules.iter()
    }

    /// 从采样得到的原始模块值重建矩阵（功能区也按图像里看到的填充）。
    /// `reserved` 仍然按 `Version` 计算——decoder 用它来判定哪些格子是数据。
    pub fn from_modules(version: Version, modules: Vec<bool>) -> Self {
        let template = Matrix::new(version); // 借它的 reserved
        debug_assert_eq!(modules.len(), template.size * template.size);
        Self {
            version,
            size: template.size,
            modules,
            reserved: template.reserved,
        }
    }

    /// 把一个 7×7 的 finder 图案画到左上角（top, left）位置。
    /// 图案：外圈实心 + 中间留白 + 中心 3×3 实心。
    fn place_finder_at(&mut self, top: usize, left: usize) {
        for dr in 0..7 {
            for dc in 0..7 {
                let on_outer = dr == 0 || dr == 6 || dc == 0 || dc == 6;
                let in_inner = (2..=4).contains(&dr) && (2..=4).contains(&dc);
                self.set_function(top + dr, left + dc, on_outer || in_inner);
            }
        }
    }

    /// Finder 旁的 separator：1 宽白边，紧贴 finder 的"内侧"。
    fn place_separators(&mut self) {
        let n = self.size;
        // Top-left finder 的右边 + 下边（行 7，列 0..8；列 7，行 0..8）
        for k in 0..8 {
            self.set_function(7, k, false);
            self.set_function(k, 7, false);
        }
        // Top-right finder 的左边 + 下边（行 7，列 n-8..n；列 n-8，行 0..8）
        for k in 0..8 {
            self.set_function(7, n - 1 - k, false);
            self.set_function(k, n - 8, false);
        }
        // Bottom-left finder 的右边 + 上边（行 n-8，列 0..8；列 7，行 n-8..n）
        for k in 0..8 {
            self.set_function(n - 8, k, false);
            self.set_function(n - 1 - k, 7, false);
        }
    }

    fn place_finders_and_separators(&mut self) {
        let n = self.size;
        self.place_finder_at(0, 0);
        self.place_finder_at(0, n - 7);
        self.place_finder_at(n - 7, 0);
        self.place_separators();
    }

    /// Timing patterns：行 6 和列 6 上，从 finder 右边到下一个 finder 左边之间，交替黑白。
    /// 偶数下标黑（true），奇数下标白（false）；起点 (6, 8) 是黑。
    fn place_timing_patterns(&mut self) {
        let n = self.size;
        for i in 8..(n - 8) {
            let on = i % 2 == 0;
            self.set_function(6, i, on); // 水平 timing
            self.set_function(i, 6, on); // 垂直 timing
        }
    }

    /// 5×5 对齐图案：外圈实心 + 中间一圈白 + 中心 1 黑。
    fn place_alignment_at(&mut self, center_row: usize, center_col: usize) {
        for dr in -2i32..=2 {
            for dc in -2i32..=2 {
                let r = (center_row as i32 + dr) as usize;
                let c = (center_col as i32 + dc) as usize;
                let on_outer = dr.abs() == 2 || dc.abs() == 2;
                let is_center = dr == 0 && dc == 0;
                self.set_function(r, c, on_outer || is_center);
            }
        }
    }

    /// 在所有对齐图案中心的笛卡尔积位置放对齐图案，但跳过与 finder 重叠的角。
    fn place_alignment_patterns(&mut self) {
        let centers = alignment_centers(self.version);
        if centers.is_empty() {
            return;
        }
        let n = self.size;
        for &r in centers {
            for &c in centers {
                let r = r as usize;
                let c = c as usize;
                // 跳过与 finder 重叠的三个角：左上 (6,6)、右上 (6, n-7)、左下 (n-7, 6) 邻域。
                // 标准 QR：若 (r, c) 5×5 区域与任一 finder 7×7 重叠，则跳过。
                let overlaps_finder = (r < 8 && c < 8)
                    || (r < 8 && c > n - 9)
                    || (r > n - 9 && c < 8);
                if overlaps_finder {
                    continue;
                }
                self.place_alignment_at(r, c);
            }
        }
    }

    /// "Dark module"：在 (4v+9, 8) 永远是黑色，这是 QR 标准强制规定。
    fn place_dark_module(&mut self) {
        let v = self.version.0 as usize;
        self.set_function(4 * v + 9, 8, true);
    }

    /// 预留 15 位格式信息所在格子。
    fn reserve_format_info(&mut self) {
        let n = self.size;
        // 围绕左上 finder 的 L 形：行 8 列 0..9（跳过列 6 timing），列 8 行 0..9（跳过行 6 timing）
        for c in 0..9 {
            if c == 6 {
                continue;
            }
            self.reserve(8, c);
        }
        for r in 0..9 {
            if r == 6 {
                continue;
            }
            self.reserve(r, 8);
        }
        // 围绕右上 + 左下 finder 的 L 形：行 8 列 n-8..n；列 8 行 n-7..n
        for c in (n - 8)..n {
            self.reserve(8, c);
        }
        for r in (n - 7)..n {
            self.reserve(r, 8);
        }
    }

    /// 预留 18 位版本信息（v7+）所在格子：两个 3×6 矩形。
    fn reserve_version_info(&mut self) {
        let n = self.size;
        // 右上 finder 左方：行 0..6, 列 n-11..n-8
        for r in 0..6 {
            for c in (n - 11)..(n - 8) {
                self.reserve(r, c);
            }
        }
        // 左下 finder 上方：行 n-11..n-8, 列 0..6
        for r in (n - 11)..(n - 8) {
            for c in 0..6 {
                self.reserve(r, c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_size_and_finders() {
        let m = Matrix::new(Version::new(1));
        assert_eq!(m.size, 21);
        // 三个角 finder 的中心 (3,3), (3,17), (17,3) 应该是黑（中心 3×3 区）。
        assert!(m.get(3, 3));
        assert!(m.get(3, 17));
        assert!(m.get(17, 3));
        // Finder 内圈白色 (1,3)。
        assert!(!m.get(1, 3));
    }

    #[test]
    fn v1_timing_alternates() {
        let m = Matrix::new(Version::new(1));
        for c in 8..13 {
            assert_eq!(m.get(6, c), c % 2 == 0, "row 6 col {}", c);
            assert_eq!(m.get(c, 6), c % 2 == 0, "col 6 row {}", c);
        }
    }

    #[test]
    fn dark_module_present() {
        let m = Matrix::new(Version::new(1));
        // V1: (4*1+9, 8) = (13, 8) 必须为黑。
        assert!(m.get(13, 8));
        assert!(m.is_reserved(13, 8));
    }

    #[test]
    fn v2_has_one_alignment_pattern() {
        let m = Matrix::new(Version::new(2));
        // V2 对齐图案中心 (18, 18)。其外圈应全黑。
        assert!(m.get(16, 16)); // 左上角外圈
        assert!(m.get(18, 18)); // 中心
        assert!(!m.get(17, 17)); // 内圈白
    }

    #[test]
    fn v7_has_version_info_reserved() {
        let m = Matrix::new(Version::new(7));
        let n = m.size;
        // 版本信息区一定被 reserve。
        assert!(m.is_reserved(0, n - 11));
        assert!(m.is_reserved(5, n - 9));
        assert!(m.is_reserved(n - 11, 0));
        assert!(m.is_reserved(n - 9, 5));
    }

    #[test]
    fn format_info_area_reserved() {
        let m = Matrix::new(Version::new(1));
        let n = m.size;
        // 左上 finder 邻接的 L 形
        assert!(m.is_reserved(8, 0));
        assert!(m.is_reserved(8, 8));
        assert!(m.is_reserved(0, 8));
        // 右上、左下区
        assert!(m.is_reserved(8, n - 1));
        assert!(m.is_reserved(n - 1, 8));
        // timing 在 (6, _) 不应被 format info 覆盖（这一格属于 timing 区，但既然是 functional 也算 reserved）
        assert!(m.is_reserved(6, 0));
    }

    #[test]
    fn data_area_not_reserved() {
        let m = Matrix::new(Version::new(1));
        // 中间一个明显是数据区的格子。
        assert!(!m.is_reserved(10, 10));
        assert!(!m.is_reserved(14, 12));
    }

    /// 计算数据区模块总数（= reserved=false 的格子），手算公式：
    /// `size^2 - finder_pattern_total - timing - alignment - format/version - dark`
    /// 但更简单的是 ISO 18004 Annex A 直接给出"data modules" 表。
    /// V1: 208；V2: 359。
    #[test]
    fn data_module_count_v1() {
        let m = Matrix::new(Version::new(1));
        let n_data: usize = m.reserved.iter().filter(|&&r| !r).count();
        assert_eq!(n_data, 208, "V1 应有 208 个数据模块");
    }

    #[test]
    fn data_module_count_v2() {
        let m = Matrix::new(Version::new(2));
        let n_data: usize = m.reserved.iter().filter(|&&r| !r).count();
        assert_eq!(n_data, 359, "V2 应有 359 个数据模块");
    }
}
