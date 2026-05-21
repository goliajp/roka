//! Matrix → Bitmap：渲染时控制放大倍数和 quiet zone 宽度。
//!
//! - `scale`：每个模块放大成 scale × scale 像素
//! - `quiet`：四周白色边框宽度（以模块数计）。QR 标准建议 ≥ 4。

use super::matrix::Matrix;
use crate::pbm::Bitmap;

pub fn render_to_bitmap(matrix: &Matrix, scale: usize, quiet: usize) -> Bitmap {
    let n = matrix.size;
    let dim_modules = n + 2 * quiet;
    let dim_pixels = dim_modules * scale;
    let mut bm = Bitmap::new(dim_pixels, dim_pixels);
    for r in 0..n {
        for c in 0..n {
            let v = matrix.get(r, c);
            if !v {
                continue; // 白色像素已经是初始值
            }
            let y0 = (quiet + r) * scale;
            let x0 = (quiet + c) * scale;
            for dy in 0..scale {
                for dx in 0..scale {
                    bm.set(x0 + dx, y0 + dy, true);
                }
            }
        }
    }
    bm
}
