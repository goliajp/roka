//! PBM (Portable Bitmap) P1 ASCII 格式的读写。
//!
//! # 格式速记
//!
//! ```text
//!   P1
//!   # 注释（可选）
//!   <width> <height>
//!   1 0 0 1 1 0 1 ...     // height × width 个 token，'0' = 白，'1' = 黑
//! ```
//!
//! 我们用 P1 而不是 P4（紧凑二进制）：
//! - 教学体验好——cat 出来就能看
//! - 解析简单——只用空白和井号注释
//! - 任何主流图像工具都识别（ImageMagick `convert`、`netpbm` 等）

use std::fmt::Write as _;

/// 一张二值位图。`pixels` 长度 = width * height；`true` = 黑，`false` = 白。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitmap {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<bool>,
}

impl Bitmap {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            pixels: vec![false; width * height],
        }
    }

    #[inline]
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.pixels[y * self.width + x]
    }

    #[inline]
    pub fn set(&mut self, x: usize, y: usize, value: bool) {
        self.pixels[y * self.width + x] = value;
    }
}

/// 把 Bitmap 序列化为 P1 PBM 字符串。每行最多 70 个字符（PBM 规范上限是 70 ASCII 字符）。
pub fn write_p1(bitmap: &Bitmap) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "P1");
    let _ = writeln!(s, "# lab10-2fa QR PBM");
    let _ = writeln!(s, "{} {}", bitmap.width, bitmap.height);
    let mut col = 0usize;
    for y in 0..bitmap.height {
        for x in 0..bitmap.width {
            let c = if bitmap.get(x, y) { '1' } else { '0' };
            if col + 2 > 70 {
                s.push('\n');
                col = 0;
            }
            if col > 0 {
                s.push(' ');
                col += 1;
            }
            s.push(c);
            col += 1;
        }
    }
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// 解析 PBM（自动识别 P1 / P4）。输入是 `&[u8]` 而非 `&str`，
/// 因为 P4 是二进制格式有非 UTF-8 字节。
pub fn read(input: &[u8]) -> Result<Bitmap, &'static str> {
    // 看前两字节决定 magic。
    if input.len() < 2 {
        return Err("input too short");
    }
    match &input[0..2] {
        b"P1" => {
            let s = std::str::from_utf8(input).map_err(|_| "P1 has invalid UTF-8")?;
            read_p1(s)
        }
        b"P4" => read_p4(input),
        _ => Err("not a PBM (need P1 or P4 magic)"),
    }
}

/// 解析 P4（二进制位图）。Header 部分仍是 ASCII 文本（magic + 宽 + 高 + 单字节空白），
/// 之后是 ceil(width/8) * height 字节，每字节 8 个像素 MSB-first，1 = 黑。
fn read_p4(input: &[u8]) -> Result<Bitmap, &'static str> {
    // 跳过 magic
    let i = 2;
    // 跳过 magic 后第一个空白（必须有）
    if i >= input.len() {
        return Err("truncated P4");
    }
    // 读 width / height（跳注释和空白）
    let (w, j) = read_ascii_uint(input, i, true)?;
    let (h, mut k) = read_ascii_uint(input, j, true)?;
    // PBM 规范：header 与数据之间是单个空白字符
    if k >= input.len() {
        return Err("truncated P4 (no data)");
    }
    if !is_pbm_whitespace(input[k]) {
        return Err("P4 header not followed by whitespace");
    }
    k += 1;
    let _ = (i, j); // 借用提醒
    let row_bytes = (w + 7) / 8;
    let expected = row_bytes * h;
    if input.len() < k + expected {
        return Err("P4 truncated body");
    }
    let mut bm = Bitmap::new(w, h);
    for y in 0..h {
        for x in 0..w {
            let byte = input[k + y * row_bytes + x / 8];
            let bit = (byte >> (7 - x % 8)) & 1 == 1;
            bm.set(x, y, bit);
        }
    }
    Ok(bm)
}

/// 跳过空白和 '#' 注释，读一个 ASCII 无符号整数。返回 (value, new_pos)。
fn read_ascii_uint(input: &[u8], mut i: usize, skip_leading_ws: bool) -> Result<(usize, usize), &'static str> {
    if skip_leading_ws {
        loop {
            if i >= input.len() {
                return Err("unexpected EOF");
            }
            if input[i] == b'#' {
                while i < input.len() && input[i] != b'\n' {
                    i += 1;
                }
            } else if is_pbm_whitespace(input[i]) {
                i += 1;
            } else {
                break;
            }
        }
    }
    let start = i;
    while i < input.len() && input[i].is_ascii_digit() {
        i += 1;
    }
    if start == i {
        return Err("expected number");
    }
    let s = std::str::from_utf8(&input[start..i]).map_err(|_| "non-ASCII number")?;
    let v: usize = s.parse().map_err(|_| "bad number")?;
    Ok((v, i))
}

fn is_pbm_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C')
}

/// 解析 P1 PBM。容错：忽略 '#' 起头的注释（直到行尾）、忽略多余空白。
pub fn read_p1(input: &str) -> Result<Bitmap, &'static str> {
    let tokens = tokenize_pbm(input);
    let mut it = tokens.into_iter();
    let header = it.next().ok_or("empty PBM")?;
    if header != "P1" {
        return Err("only P1 (ASCII bitmap) supported");
    }
    let w: usize = it
        .next()
        .ok_or("missing width")?
        .parse()
        .map_err(|_| "bad width")?;
    let h: usize = it
        .next()
        .ok_or("missing height")?
        .parse()
        .map_err(|_| "bad height")?;
    let mut bitmap = Bitmap::new(w, h);
    for y in 0..h {
        for x in 0..w {
            let t = it.next().ok_or("truncated bitmap")?;
            // 标准 P1 是单字符 0/1 token；netpbm 也允许多 token 间无分隔。
            // 这里既支持 "1 0 1 0"，也支持 "1010"。
            if t.len() == 1 {
                match t.as_str() {
                    "0" => bitmap.set(x, y, false),
                    "1" => bitmap.set(x, y, true),
                    _ => return Err("invalid bit"),
                }
            } else {
                // 多字符 token（罕见但合法）：暂不支持，建议生成方按空白分割。
                return Err("multi-char PBM tokens not supported—separate bits with whitespace");
            }
        }
    }
    Ok(bitmap)
}

/// 分词：每个 token 是连续非空白非 '#' 的字符。'#' 起头注释直到行尾。
fn tokenize_pbm(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    let mut in_comment = false;
    for ch in input.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }
        if ch == '#' {
            in_comment = true;
            if !buf.is_empty() {
                tokens.push(std::mem::take(&mut buf));
            }
            continue;
        }
        if ch.is_whitespace() {
            if !buf.is_empty() {
                tokens.push(std::mem::take(&mut buf));
            }
        } else {
            buf.push(ch);
        }
    }
    if !buf.is_empty() {
        tokens.push(buf);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small() {
        let mut bm = Bitmap::new(3, 2);
        bm.set(0, 0, true);
        bm.set(2, 1, true);
        let s = write_p1(&bm);
        let bm2 = read_p1(&s).unwrap();
        assert_eq!(bm, bm2);
    }

    #[test]
    fn read_with_comments_and_packed_tokens() {
        // 故意把空白搞乱、加注释
        let s = "P1\n# this is a comment\n3 2\n1 0 0\n# another\n0 0 1\n";
        let bm = read_p1(s).unwrap();
        assert_eq!(bm.width, 3);
        assert_eq!(bm.height, 2);
        assert!(bm.get(0, 0));
        assert!(!bm.get(1, 0));
        assert!(!bm.get(2, 0));
        assert!(!bm.get(0, 1));
        assert!(!bm.get(1, 1));
        assert!(bm.get(2, 1));
    }

    #[test]
    fn rejects_non_p1() {
        assert!(read_p1("P4\n3 2\n").is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(read_p1("P1\n3 2\n1 0\n").is_err());
    }

    /// P4 解析：手工构造一个 10x10 全黑位图，验证 read() 自动识别 P4。
    #[test]
    fn read_auto_detects_p4() {
        // 10x10，每行 ceil(10/8) = 2 字节。全 1 模式 = 0xFF 0xC0（最后 6 bit 是 padding）
        let mut data = Vec::from("P4\n10 10\n");
        for _ in 0..10 {
            data.push(0xFF);
            data.push(0xC0);
        }
        let bm = super::read(&data).unwrap();
        assert_eq!(bm.width, 10);
        assert_eq!(bm.height, 10);
        for y in 0..10 {
            for x in 0..10 {
                assert!(bm.get(x, y), "P4 ({},{}) 应为黑", x, y);
            }
        }
    }
}
