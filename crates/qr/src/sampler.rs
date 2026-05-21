//! 从二值位图采样回 QR 模块矩阵。
//!
//! # 假设
//!
//! - 图像已对齐：无旋转、无透视变形
//! - 模块是整像素方块（可能被放大，但每个模块的宽 = 高 = 整数像素 M ≥ 1）
//! - 可选的 quiet zone（白色边框）会被自动 trim
//!
//! 真实手机相机拍的图需要先用外部工具（ImageMagick 等）做透视校正 + 二值化，才能喂给本采样器。
//! 本采样器的范围是"已经处理好的"PBM。
//!
//! # 算法
//!
//! 1. trim_quiet_zone：找全图四周的纯白边框，剪掉
//! 2. detect_module_size：剪完后第 0 行的第一段黑色游程 = top-left finder 的顶边 = 7 个模块。
//!    M = run_length / 7
//! 3. 矩阵边长 N = trimmed_width / M；由 N 反推版本号
//! 4. 用每个模块中心像素的颜色填充 Matrix（连功能区一起覆盖）

use super::matrix::Matrix;
use super::tables::Version;
use crate::pbm::Bitmap;

/// 找四周纯白的边界，返回裁剪后实际 QR 区域的 (x0, y0, x1, y1)（含两端）。
fn trim_quiet_zone(bm: &Bitmap) -> Result<(usize, usize, usize, usize), &'static str> {
    // 找第一/最后一行非全白
    let mut y0 = None;
    for y in 0..bm.height {
        if (0..bm.width).any(|x| bm.get(x, y)) {
            y0 = Some(y);
            break;
        }
    }
    let y0 = y0.ok_or("image is all white")?;
    let mut y1 = bm.height - 1;
    while y1 > y0 && !(0..bm.width).any(|x| bm.get(x, y1)) {
        y1 -= 1;
    }
    // 找第一/最后一列非全白
    let mut x0 = None;
    for x in 0..bm.width {
        if (y0..=y1).any(|y| bm.get(x, y)) {
            x0 = Some(x);
            break;
        }
    }
    let x0 = x0.ok_or("image is all white")?;
    let mut x1 = bm.width - 1;
    while x1 > x0 && !(y0..=y1).any(|y| bm.get(x1, y)) {
        x1 -= 1;
    }
    Ok((x0, y0, x1, y1))
}

/// 在第 0 行（已剪 quiet zone）找第一段黑色游程的长度。
fn first_black_run_length(bm: &Bitmap, x0: usize, y0: usize, x1: usize) -> usize {
    let mut len = 0;
    for x in x0..=x1 {
        if bm.get(x, y0) {
            len += 1;
        } else {
            break;
        }
    }
    len
}

/// 从 Bitmap 重建模块矩阵。
pub fn matrix_from_bitmap(bm: &Bitmap) -> Result<Matrix, &'static str> {
    let (x0, y0, x1, y1) = trim_quiet_zone(bm)?;
    let region_w = x1 + 1 - x0;
    let region_h = y1 + 1 - y0;
    if region_w != region_h {
        return Err("QR region is not square");
    }
    let run = first_black_run_length(bm, x0, y0, x1);
    if run < 7 || run % 7 != 0 {
        return Err("could not detect module size from finder top edge");
    }
    let module_size = run / 7;
    if region_w % module_size != 0 {
        return Err("region size is not an integer multiple of module size");
    }
    let n = region_w / module_size;
    if !(21..=177).contains(&n) || (n - 17) % 4 != 0 {
        return Err("decoded module count is not a valid QR size");
    }
    let version = Version::new(((n - 17) / 4) as u8);
    let mut modules = vec![false; n * n];
    let center_offset = module_size / 2;
    for row in 0..n {
        for col in 0..n {
            let cy = y0 + row * module_size + center_offset;
            let cx = x0 + col * module_size + center_offset;
            modules[row * n + col] = bm.get(cx, cy);
        }
    }
    Ok(Matrix::from_modules(version, modules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bch::EcLevel;
    use crate::encode;
    use crate::render::render_to_bitmap;

    /// 端到端 round-trip：URI → matrix → 渲染为 Bitmap（无 quiet zone、scale=1）
    /// → 采样回 matrix → 解码回 URI。
    #[test]
    fn round_trip_minimal() {
        let uri = b"otpauth://totp/T:a@b?secret=JBSWY3DPEHPK3PXP&issuer=T";
        let (matrix, _, _) = encode::encode(uri, EcLevel::M).unwrap();
        // 渲染时 quiet zone 0，scale 1：原模块就是像素
        let bm = render_to_bitmap(&matrix, 1, 0);
        let recovered_matrix = matrix_from_bitmap(&bm).unwrap();
        let recovered = crate::decode::decode(&recovered_matrix).unwrap();
        assert_eq!(recovered.as_slice(), uri.as_ref());
    }

    /// 带 quiet zone + scale 2：sampler 应自动 trim + 算模块大小。
    #[test]
    fn round_trip_with_quiet_zone_and_scale() {
        let uri = b"otpauth://totp/Lab:lihao@golia.jp?secret=ABCDEFGHIJKLMNOP&issuer=Lab";
        let (matrix, _, _) = encode::encode(uri, EcLevel::L).unwrap();
        let bm = render_to_bitmap(&matrix, 3, 4); // scale 3、quiet 4 模块
        let recovered_matrix = matrix_from_bitmap(&bm).unwrap();
        let recovered = crate::decode::decode(&recovered_matrix).unwrap();
        assert_eq!(recovered.as_slice(), uri.as_ref());
    }
}
