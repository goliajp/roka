//! 自研 PNG 编/解码：零依赖。编码限 8-bit 灰度（够让 Authenticator 扫）；
//! 解码支持 grayscale / palette / RGB(A) 几种常见 color type，二值化为 Bitmap。
//!
//! # 文件结构
//!
//! ```text
//!   ┌──────────────────────────────────────────────────┐
//!   │ PNG 签名 (8 字节)                                 │
//!   │ IHDR chunk: 宽/高/bit_depth/color_type/...       │
//!   │ [PLTE chunk]: 调色板（color_type=3 时必需）        │
//!   │ IDAT chunk(s): zlib 流（DEFLATE 三类 block 任意）  │
//!   │ IEND chunk                                       │
//!   └──────────────────────────────────────────────────┘
//! ```
//!
//! 每个 chunk 格式：length(4) + type(4) + data(N) + crc32(4)。CRC32 算在 `type ++ data` 上。
//!
//! # 编码：DEFLATE stored 块（足够让 zbar / Authenticator 识别）
//!
//! 我们只走最简化版："不压缩，原样放进去"。块结构：BFINAL(1) + BTYPE=00(2) + padding +
//! LEN(2) + NLEN(2) + 数据。块体最长 65535 字节；超出则拆多块。
//!
//! # 解码：用 deflate 模块（支持全 3 类 block + 动态 Huffman + LZ77）
//!
//! 比编码端复杂。流程：拆 chunk → 拼 IDAT → 解 zlib → 反向 5 种 filter → 二值化。

use crate::deflate;
use crate::pbm::Bitmap;

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// 把 Bitmap 编码为 PNG（8-bit 灰度，0=黑 255=白；行首 filter byte 用 0=None）。
pub fn encode_grayscale(bitmap: &Bitmap) -> Vec<u8> {
    let w = bitmap.width as u32;
    let h = bitmap.height as u32;

    // 构造未压缩"图像数据"：每行 = filter byte (0) + width 个 灰度像素。
    let mut raw = Vec::with_capacity((bitmap.width + 1) * bitmap.height);
    for y in 0..bitmap.height {
        raw.push(0u8); // filter type None
        for x in 0..bitmap.width {
            // PBM 约定 true = 黑，PNG 灰度约定 0 = 黑、255 = 白。
            raw.push(if bitmap.get(x, y) { 0 } else { 255 });
        }
    }

    // zlib 包装 DEFLATE stored blocks。
    let compressed = zlib_wrap(&raw);

    let mut out = Vec::new();
    out.extend_from_slice(&PNG_SIGNATURE);

    // IHDR
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // color type = grayscale
    ihdr.push(0); // compression = deflate
    ihdr.push(0); // filter method = adaptive
    ihdr.push(0); // interlace = none
    write_chunk(&mut out, b"IHDR", &ihdr);

    // IDAT
    write_chunk(&mut out, b"IDAT", &compressed);

    // IEND
    write_chunk(&mut out, b"IEND", &[]);
    out
}

/// 写一个 PNG chunk：length(4 BE) + type(4) + data + crc32(4 BE)。
fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let crc_start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[crc_start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

// ───────────────────────────── CRC32 ─────────────────────────────

const CRC32_POLY: u32 = 0xEDB88320; // IEEE 802.3 反向多项式（PNG/zlib 用的就是这个）

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let mut x = (crc ^ b as u32) & 0xFF;
        for _ in 0..8 {
            x = if x & 1 == 1 { (x >> 1) ^ CRC32_POLY } else { x >> 1 };
        }
        crc = (crc >> 8) ^ x;
    }
    !crc
}

// ───────────────────────────── Adler-32 ─────────────────────────────

const ADLER_MOD: u32 = 65521;

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &x in data {
        a = (a + x as u32) % ADLER_MOD;
        b = (b + a) % ADLER_MOD;
    }
    (b << 16) | a
}

// ───────────────────────────── zlib + DEFLATE stored ─────────────────────────────

fn zlib_wrap(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // CMF = 0x78：method=8(deflate)，window=7(2^(7+8)=32K)
    // FLG = 0x01：fdict=0, flevel=0, fcheck 让 CMF*256+FLG ≡ 0 (mod 31)。
    //  0x78*256 + 0x01 = 30721, 30721 % 31 = 0 ✓
    out.push(0x78);
    out.push(0x01);
    // DEFLATE 流：拆成 ≤ 65535 字节的 stored 块
    let mut i = 0usize;
    while i < raw.len() {
        let block_size = (raw.len() - i).min(65535);
        let bfinal = i + block_size == raw.len();
        // 一字节 = BFINAL (bit 0) + BTYPE (bit 1-2 = 00) + 5 padding bits
        out.push(if bfinal { 0x01 } else { 0x00 });
        // LEN + NLEN (little-endian)
        let len = block_size as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&raw[i..i + block_size]);
        i += block_size;
    }
    // Adler-32（对原始数据，BE）
    out.extend_from_slice(&adler32(raw).to_be_bytes());
    out
}

// ───────────────────────────── PNG 解码 ─────────────────────────────

/// 顶层：把 PNG 字节流解码为二值 Bitmap（用阈值二分像素亮度：< 128 = 黑）。
pub fn decode(data: &[u8]) -> Result<Bitmap, &'static str> {
    if data.len() < 8 || data[..8] != PNG_SIGNATURE {
        return Err("PNG: bad signature");
    }
    let chunks = parse_chunks(&data[8..])?;
    let ihdr = chunks
        .iter()
        .find(|c| c.kind == *b"IHDR")
        .ok_or("PNG: missing IHDR")?;
    let header = parse_ihdr(ihdr.data)?;

    // 收集所有 IDAT 拼成 zlib 流
    let mut zlib_stream = Vec::new();
    for c in &chunks {
        if c.kind == *b"IDAT" {
            zlib_stream.extend_from_slice(c.data);
        }
    }
    if zlib_stream.is_empty() {
        return Err("PNG: no IDAT");
    }

    // 可选的 palette
    let palette: Option<Vec<[u8; 3]>> = chunks
        .iter()
        .find(|c| c.kind == *b"PLTE")
        .map(|c| {
            if c.data.len() % 3 != 0 {
                return Err("PNG: PLTE not multiple of 3");
            }
            Ok(c.data.chunks(3).map(|t| [t[0], t[1], t[2]]).collect())
        })
        .transpose()?;

    // 解 zlib：CMF + FLG + DEFLATE + Adler-32
    let raw = zlib_unwrap(&zlib_stream)?;

    // 反 filter 得到每行像素 byte 序列
    let unfiltered = unfilter(&raw, &header)?;

    // 解释为 bool 位图
    pixels_to_bitmap(&unfiltered, &header, palette.as_deref())
}

#[derive(Debug)]
struct Chunk<'a> {
    kind: [u8; 4],
    data: &'a [u8],
}

fn parse_chunks(mut data: &[u8]) -> Result<Vec<Chunk<'_>>, &'static str> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 12 {
            return Err("PNG: chunk truncated");
        }
        let length = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
        if data.len() < 12 + length {
            return Err("PNG: chunk length exceeds file");
        }
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&data[4..8]);
        let chunk_data = &data[8..8 + length];
        let crc_expected = u32::from_be_bytes(data[8 + length..12 + length].try_into().unwrap());
        let crc_actual = crc32(&data[4..8 + length]);
        if crc_actual != crc_expected {
            return Err("PNG: chunk CRC mismatch");
        }
        out.push(Chunk { kind, data: chunk_data });
        if &kind == b"IEND" {
            return Ok(out);
        }
        data = &data[12 + length..];
    }
    Err("PNG: missing IEND")
}

#[derive(Debug, Clone, Copy)]
struct IhdrInfo {
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: u8,
    // compression / filter / interlace 必须分别是 0, 0, 0
}

impl IhdrInfo {
    fn channels(&self) -> usize {
        match self.color_type {
            0 => 1, // grayscale
            2 => 3, // RGB
            3 => 1, // palette index
            4 => 2, // grayscale + alpha
            6 => 4, // RGBA
            _ => 0,
        }
    }
    /// 每行原始字节数（不含 filter 字节）
    fn row_bytes(&self) -> usize {
        let bits_per_pixel = self.bit_depth as usize * self.channels();
        (self.width as usize * bits_per_pixel + 7) / 8
    }
}

fn parse_ihdr(data: &[u8]) -> Result<IhdrInfo, &'static str> {
    if data.len() != 13 {
        return Err("PNG: IHDR not 13 bytes");
    }
    let info = IhdrInfo {
        width: u32::from_be_bytes(data[0..4].try_into().unwrap()),
        height: u32::from_be_bytes(data[4..8].try_into().unwrap()),
        bit_depth: data[8],
        color_type: data[9],
    };
    if data[10] != 0 {
        return Err("PNG: unsupported compression method");
    }
    if data[11] != 0 {
        return Err("PNG: unsupported filter method");
    }
    if data[12] != 0 {
        return Err("PNG: interlaced PNG not supported");
    }
    if info.channels() == 0 {
        return Err("PNG: bad color_type");
    }
    Ok(info)
}

/// zlib：剥掉 CMF/FLG，调用 deflate::inflate，最后验证 Adler-32。
fn zlib_unwrap(stream: &[u8]) -> Result<Vec<u8>, &'static str> {
    if stream.len() < 6 {
        return Err("zlib: stream too short");
    }
    let cmf = stream[0];
    let flg = stream[1];
    if (cmf & 0x0F) != 8 {
        return Err("zlib: not DEFLATE");
    }
    if ((cmf as u32) * 256 + flg as u32) % 31 != 0 {
        return Err("zlib: bad header checksum");
    }
    if flg & 0x20 != 0 {
        // FDICT — we don't support pre-set dictionaries (rare in PNGs)
        return Err("zlib: FDICT not supported");
    }
    let deflated = &stream[2..stream.len() - 4];
    let inflated = deflate::inflate(deflated)?;
    let adler_expected = u32::from_be_bytes(stream[stream.len() - 4..].try_into().unwrap());
    let adler_actual = adler32(&inflated);
    if adler_actual != adler_expected {
        return Err("zlib: Adler-32 mismatch");
    }
    Ok(inflated)
}

/// 反 5 种 filter（None/Sub/Up/Average/Paeth），返回每行原始像素 bytes 拼接的扁平数组。
fn unfilter(raw: &[u8], h: &IhdrInfo) -> Result<Vec<u8>, &'static str> {
    let row_bytes = h.row_bytes();
    let height = h.height as usize;
    if raw.len() != (row_bytes + 1) * height {
        return Err("PNG: unfilter expected size mismatch");
    }
    let bpp = (h.bit_depth as usize * h.channels() + 7) / 8; // bytes per pixel, 取整字节
    let bpp = bpp.max(1); // sub-byte pixels：用 1 字节步长（不完全正确但对 grayscale 1-bit/调色板 1-bit 够用）
    let mut out = vec![0u8; row_bytes * height];
    for y in 0..height {
        let in_row = &raw[y * (row_bytes + 1)..(y + 1) * (row_bytes + 1)];
        let filter_type = in_row[0];
        let in_row_data = &in_row[1..];
        let prev_row_start = if y == 0 { None } else { Some((y - 1) * row_bytes) };
        for x in 0..row_bytes {
            let cur = in_row_data[x];
            let left = if x >= bpp { out[y * row_bytes + x - bpp] } else { 0 };
            let up = match prev_row_start {
                Some(s) => out[s + x],
                None => 0,
            };
            let up_left = match prev_row_start {
                Some(s) if x >= bpp => out[s + x - bpp],
                _ => 0,
            };
            let value = match filter_type {
                0 => cur,
                1 => cur.wrapping_add(left),
                2 => cur.wrapping_add(up),
                3 => cur.wrapping_add(((left as u16 + up as u16) / 2) as u8),
                4 => cur.wrapping_add(paeth_predictor(left, up, up_left)),
                _ => return Err("PNG: bad filter type"),
            };
            out[y * row_bytes + x] = value;
        }
    }
    Ok(out)
}

fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let pa = (p - a as i32).abs();
    let pb = (p - b as i32).abs();
    let pc = (p - c as i32).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// 像素 bytes → Bitmap。按 color_type 解释，最后用亮度阈值二值化。
fn pixels_to_bitmap(
    pixels: &[u8],
    h: &IhdrInfo,
    palette: Option<&[[u8; 3]]>,
) -> Result<Bitmap, &'static str> {
    let w = h.width as usize;
    let height = h.height as usize;
    let mut bm = Bitmap::new(w, height);
    let row_bytes = h.row_bytes();
    for y in 0..height {
        let row = &pixels[y * row_bytes..(y + 1) * row_bytes];
        for x in 0..w {
            let brightness = sample_pixel(row, x, h, palette)?;
            // < 128 视为"黑"（QR 模块）
            bm.set(x, y, brightness < 128);
        }
    }
    Ok(bm)
}

fn sample_pixel(
    row: &[u8],
    x: usize,
    h: &IhdrInfo,
    palette: Option<&[[u8; 3]]>,
) -> Result<u8, &'static str> {
    let bd = h.bit_depth as usize;
    match h.color_type {
        0 => {
            // Grayscale。bit_depth 1/2/4/8/16。
            let v = read_sub_byte_sample(row, x, bd);
            Ok(scale_to_u8(v, bd))
        }
        2 => {
            // RGB。8 或 16 bit per channel；这里只支持 8。
            if bd != 8 {
                return Err("PNG: RGB only supported at 8-bit depth");
            }
            let r = row[x * 3];
            let g = row[x * 3 + 1];
            let b = row[x * 3 + 2];
            Ok(((r as u16 + g as u16 + b as u16) / 3) as u8)
        }
        3 => {
            // Palette。bit_depth 1/2/4/8。索引到 PLTE。
            let idx = read_sub_byte_sample(row, x, bd) as usize;
            let pal = palette.ok_or("PNG: palette image missing PLTE")?;
            if idx >= pal.len() {
                return Err("PNG: palette index out of range");
            }
            let [r, g, b] = pal[idx];
            Ok(((r as u16 + g as u16 + b as u16) / 3) as u8)
        }
        4 => {
            // Grayscale + alpha
            if bd != 8 {
                return Err("PNG: gray+alpha only at 8-bit");
            }
            Ok(row[x * 2]) // ignore alpha for binarization
        }
        6 => {
            // RGBA
            if bd != 8 {
                return Err("PNG: RGBA only at 8-bit");
            }
            let r = row[x * 4];
            let g = row[x * 4 + 1];
            let b = row[x * 4 + 2];
            Ok(((r as u16 + g as u16 + b as u16) / 3) as u8)
        }
        _ => Err("PNG: unknown color_type"),
    }
}

/// 从一行 byte 里取下标 x 处的 sub-byte sample（bit_depth = 1/2/4/8）。
fn read_sub_byte_sample(row: &[u8], x: usize, bit_depth: usize) -> u8 {
    match bit_depth {
        1 => (row[x / 8] >> (7 - x % 8)) & 0x01,
        2 => (row[x / 4] >> (6 - 2 * (x % 4))) & 0x03,
        4 => (row[x / 2] >> (4 - 4 * (x % 2))) & 0x0F,
        8 => row[x],
        _ => 0,
    }
}

/// 把 bit_depth 位的样本扩展到 8 位（保持亮度比例）。
fn scale_to_u8(v: u8, bit_depth: usize) -> u8 {
    match bit_depth {
        1 => v * 255,
        2 => v * 85,
        4 => v * 17,
        8 => v,
        _ => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已知 CRC32 测试向量：CRC32("123456789") = 0xCBF43926。
    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0x00000000);
    }

    /// Adler-32 标准向量：Adler-32("Wikipedia") = 0x11E60398。
    #[test]
    fn adler32_known_value() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
        assert_eq!(adler32(b""), 0x00000001); // 初始 a=1, b=0
    }

    #[test]
    fn png_signature_and_chunks() {
        let bm = Bitmap::new(2, 2);
        let png = encode_grayscale(&bm);
        // PNG 签名
        assert_eq!(&png[..8], &PNG_SIGNATURE);
        // 紧跟 13 + 4 字节 IHDR (chunk type + 数据) + 4 字节 length + 4 字节 CRC
        // length 字段
        assert_eq!(&png[8..12], &[0, 0, 0, 13]);
        assert_eq!(&png[12..16], b"IHDR");
        // 宽 = 2, 高 = 2
        assert_eq!(&png[16..20], &2u32.to_be_bytes());
        assert_eq!(&png[20..24], &2u32.to_be_bytes());
    }

    #[test]
    fn round_trip_encode_decode_grayscale() {
        let mut bm = Bitmap::new(7, 5);
        for y in 0..5 {
            for x in 0..7 {
                bm.set(x, y, (x * 3 + y) % 2 == 0);
            }
        }
        let png = encode_grayscale(&bm);
        let decoded = decode(&png).unwrap();
        assert_eq!(decoded.width, 7);
        assert_eq!(decoded.height, 5);
        assert_eq!(decoded, bm);
    }

    #[test]
    fn png_round_trip_via_file_signature() {
        // 简单功能：构造一个 5x5 棋盘 PNG，校验文件以 PNG 签名开头、以 IEND chunk 结束。
        let mut bm = Bitmap::new(5, 5);
        for y in 0..5 {
            for x in 0..5 {
                bm.set(x, y, (x + y) % 2 == 0);
            }
        }
        let png = encode_grayscale(&bm);
        assert_eq!(&png[..8], &PNG_SIGNATURE);
        // IEND chunk 是 "00 00 00 00 49 45 4E 44 AE 42 60 82" (length=0, type=IEND, crc=AE426082)
        let iend_marker = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        assert!(
            png.windows(8).any(|w| w == iend_marker),
            "PNG 末尾应包含 IEND chunk"
        );
    }
}
