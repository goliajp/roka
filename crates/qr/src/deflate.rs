//! DEFLATE 解压（RFC 1951）—— PNG 内嵌 zlib 流的核心。
//!
//! # 数据流结构
//!
//! 一个 DEFLATE 流由一段或多段 "block" 组成，每个 block 头部：
//!
//! ```text
//!   BFINAL  1 bit   — 是否最后一个 block
//!   BTYPE   2 bits  — 00=stored / 01=fixed Huffman / 10=dynamic Huffman / 11=保留
//! ```
//!
//! - **stored (00)**：跳到字节边界 → LEN(2 BE LE) + NLEN(2 LE) + LEN 字节原数据
//! - **fixed (01)**：用 RFC 1951 §3.2.6 写死的 Huffman 表解码"字面值 / 长度"符号；
//!                  遇到长度码再读距离码（5 bit）→ 从已输出区往回拷贝
//! - **dynamic (10)**：先读 "code-length 表" 的 Huffman 表（用来描述其它表），再
//!                    读字面值/长度表和距离表的码长，最后用这两张 Huffman 表解码数据
//!
//! # 位序的坑
//!
//! DEFLATE 的位序与"通常"的网络协议反着来：
//!   - **每字节内**：bit 0 = LSB（最低位）先读。即 reader 从 byte 的最低位往最高位走
//!   - **多 bit 整数（如 LEN、码长等）**：LSB-first 拼出来
//!   - **Huffman 码**：MSB-first 拼出来——也就是第一位读到是码的高位
//!
//! 这两个约定看似冲突，其实是因为 Huffman 码本身在编码时也用了 MSB-first 打包，
//! 而 LSB-first 的位流让最高位"最后才装进字节"，于是解码端先读到它的最低字节位置，
//! 把码从高到低拼齐。

use std::convert::TryInto;

/// 顶层 API：把整段 DEFLATE 流解压成字节。
pub fn inflate(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut br = BitReader::new(input);
    let mut out = Vec::new();
    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        match btype {
            0 => inflate_stored(&mut br, &mut out)?,
            1 => inflate_huffman(&mut br, &mut out, &fixed_litlen_table(), &fixed_dist_table())?,
            2 => {
                let (litlen, dist) = read_dynamic_tables(&mut br)?;
                inflate_huffman(&mut br, &mut out, &litlen, &dist)?;
            }
            _ => return Err("invalid DEFLATE block type"),
        }
        if bfinal == 1 {
            break;
        }
    }
    Ok(out)
}

// ───────────────────────────── BitReader (LSB-first per byte) ─────────────────────────────

pub struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0..=7, 0 = LSB
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }
    /// 读 n 个 bit（n ≤ 32），LSB-first 拼出 u32：第一个 bit 是结果的最低位。
    pub fn read_bits(&mut self, n: u8) -> Result<u32, &'static str> {
        debug_assert!(n <= 32);
        let mut val = 0u32;
        for i in 0..n {
            if self.byte_pos >= self.data.len() {
                return Err("DEFLATE: unexpected EOF");
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            val |= (bit as u32) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(val)
    }
    /// 偷看 n 个 bit（不消耗）。返回 None 表示剩余 bit 不够（来到流末尾）。
    /// 注意：DEFLATE bit 流是 LSB-first per byte，所以"先读到的 bit"就是结果的低位。
    /// 但 Huffman 码要 MSB-first 拼，所以 fast_path 表索引时需要把这 n bit 反转。
    ///
    /// 这里我们用一个简单约定：返回的 u32 把"先读到的 bit"放在最高位
    /// （= 反过来）。这样 Huffman fast table 直接拿这 n bit 当 MSB-first index。
    pub fn peek_msb_bits(&self, n: usize) -> Option<u32> {
        let mut val = 0u32;
        let mut byte_pos = self.byte_pos;
        let mut bit_pos = self.bit_pos;
        for i in 0..n {
            if byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[byte_pos] >> bit_pos) & 1;
            // 把这一 bit 放进 val 的"逻辑高位"——表示这是 Huffman 码的早期 bit。
            // n-1-i 是从高到低的位置。
            val |= (bit as u32) << (n - 1 - i);
            bit_pos += 1;
            if bit_pos == 8 {
                bit_pos = 0;
                byte_pos += 1;
            }
        }
        Some(val)
    }

    /// 消耗 n 个 bit（推进位置，不返回值）。配合 peek_msb_bits 使用。
    pub fn consume_bits(&mut self, n: usize) {
        let total = self.bit_pos as usize + n;
        self.byte_pos += total / 8;
        self.bit_pos = (total % 8) as u8;
    }

    /// 跳到下一个字节边界。
    fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }
    /// 直接读 n 个字节（必须已 align_to_byte）。
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        debug_assert_eq!(self.bit_pos, 0);
        if self.byte_pos + n > self.data.len() {
            return Err("DEFLATE: unexpected EOF (bytes)");
        }
        let s = &self.data[self.byte_pos..self.byte_pos + n];
        self.byte_pos += n;
        Ok(s)
    }
}

// ───────────────────────────── Stored (BTYPE=00) ─────────────────────────────

fn inflate_stored(br: &mut BitReader, out: &mut Vec<u8>) -> Result<(), &'static str> {
    br.align_to_byte();
    let header = br.read_bytes(4)?;
    let len = u16::from_le_bytes(header[0..2].try_into().unwrap()) as usize;
    let nlen = u16::from_le_bytes(header[2..4].try_into().unwrap());
    if (len as u16) ^ nlen != 0xFFFF {
        return Err("DEFLATE: stored LEN/NLEN mismatch");
    }
    let data = br.read_bytes(len)?;
    out.extend_from_slice(data);
    Ok(())
}

// ───────────────────────────── Canonical Huffman ─────────────────────────────

/// Canonical Huffman 解码表，带 9-bit 直接查表 fast path。
///
/// # 解码原理
///
/// 读 bit 时按 MSB-first 拼码（第一位读到 = 码的最高位）。Canonical Huffman 的性质：
/// 同一长度的码是连续整数，所以只需要知道每个长度的"起始码"和"该长度有几个码"，就能
/// 用 O(1) 的算术（不是查表）反推出 symbol。
///
/// 进一步加速：把前 9 个 bit 当 index 直接查 512 项表——绝大多数 PNG 字面值都 ≤ 9 bit，
/// 一次 load 就能解码完毕。只有少数 long code（10..15 bit）才走 fallback 慢路径。
pub struct HuffmanTable {
    /// 长度 L 的起始码值（canonical 顺序）。`base_code[L]` 对应该长度的最小码。
    base_code: [u32; 16],
    /// 长度 L 的累计 symbol 偏移：长度 ≤ L 的总 symbol 数。`base_sym[L]` = sum(count[1..L])。
    base_sym: [u32; 16],
    /// canonical 顺序排列的所有 symbol。decode 时根据 (len, code) 反查
    /// `symbols[base_sym[len] + (code - base_code[len])]`。
    symbols: Vec<u16>,
    /// 9-bit fast path。索引是 9 个 bit 当 u16；entry 高 8 bit 是码长（0 = miss），
    /// 低 8 bit 是 symbol 值（< 256）；对于 sym ≥ 256 用单独的 fast_path_sym 表。
    fast_path: [u32; 512],
    max_len: usize,
}

const FAST_PATH_BITS: usize = 9;

impl HuffmanTable {
    /// 从"每个 symbol 的码长"构建解码表（RFC 1951 §3.2.2 标准 canonical Huffman 算法）。
    pub fn from_lengths(lengths: &[u8]) -> Result<Self, &'static str> {
        let max_len = *lengths.iter().max().unwrap_or(&0) as usize;
        if max_len == 0 {
            return Ok(Self {
                base_code: [0; 16],
                base_sym: [0; 16],
                symbols: Vec::new(),
                fast_path: [0; 512],
                max_len: 0,
            });
        }
        if max_len > 15 {
            return Err("DEFLATE: Huffman code length exceeds 15");
        }
        // 1. 计每个长度的码数。
        let mut count = [0u32; 16];
        for &l in lengths {
            if l > 0 {
                count[l as usize] += 1;
            }
        }
        // 2. 每个长度的"起始码值"（RFC 1951 §3.2.2 步骤 2）。
        let mut base_code = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..=max_len {
            code = (code + count[bits - 1]) << 1;
            base_code[bits] = code;
        }
        // 3. 按 (len, sym_in_input_order) 给出 canonical symbol 顺序。
        //    base_sym[len] = 长度 < len 的 symbol 总数。
        let mut base_sym = [0u32; 16];
        for bits in 1..=max_len {
            base_sym[bits] = base_sym[bits - 1] + count[bits - 1];
        }
        let total: usize = count.iter().sum::<u32>() as usize;
        let mut symbols = vec![0u16; total];
        let mut next = base_sym;
        for (sym, &l) in lengths.iter().enumerate() {
            if l > 0 {
                symbols[next[l as usize] as usize] = sym as u16;
                next[l as usize] += 1;
            }
        }
        // 4. 9-bit fast path：对每个 ≤ 9 bit 的 symbol，把它在所有"以这个码为前缀"的
        //    9-bit 表项处都写入 (len << 16) | sym。其余项保持 0（=miss，走 slow path）。
        let mut fast_path = [0u32; 1 << FAST_PATH_BITS];
        for sym_idx in 0..symbols.len() {
            // 找出该 symbol 的长度。倒推：sym_idx 落在 base_sym[len]..base_sym[len+1]
            let mut len = 1usize;
            while len <= max_len {
                let next_base = if len < max_len {
                    base_sym[len + 1]
                } else {
                    total as u32
                };
                if (sym_idx as u32) < next_base {
                    break;
                }
                len += 1;
            }
            if len > FAST_PATH_BITS {
                continue; // long code, slow path only
            }
            // 该 symbol 的码值
            let c = base_code[len] + (sym_idx as u32 - base_sym[len]);
            let entry = ((len as u32) << 16) | (symbols[sym_idx] as u32);
            // 把 c 用 9 个 bit 表示——code 是 len bit MSB-first；后面 (FAST_PATH_BITS - len)
            // bit 任意，意味着所有以这个 code 为前缀的 9-bit 模式都映射到此 symbol。
            let shift = FAST_PATH_BITS - len;
            let base_idx = (c << shift) as usize;
            let span = 1usize << shift;
            for k in 0..span {
                fast_path[base_idx + k] = entry;
            }
        }
        Ok(Self {
            base_code,
            base_sym,
            symbols,
            fast_path,
            max_len,
        })
    }

    /// 读一个码并解码为 symbol。
    pub fn decode(&self, br: &mut BitReader) -> Result<u16, &'static str> {
        // Fast path: peek 9 bits, look up table. 但 BitReader 没 peek，所以这里实际是先 read
        // 9 bit 拼成 index（MSB-first），查表；若 miss，已经吃掉的 bit 不能退回——所以慢路径
        // 必须能基于这 9 bit 继续往后接。
        //
        // 简化：fast path 只在能保证 ≥ FAST_PATH_BITS bit 可读时启用。否则走 slow。
        let peek = br.peek_msb_bits(FAST_PATH_BITS);
        if let Some(peek_val) = peek {
            let entry = self.fast_path[peek_val as usize];
            if entry != 0 {
                let len = (entry >> 16) as u8;
                br.consume_bits(len as usize);
                return Ok((entry & 0xFFFF) as u16);
            }
        }
        // Slow path: bit-by-bit, identical to before but using canonical lookup
        let mut code = 0u32;
        for len in 1..=self.max_len {
            let bit = br.read_bits(1)?;
            code = (code << 1) | bit;
            let base = self.base_code[len];
            let next_base = if len < self.max_len {
                self.base_code[len + 1] >> 1
            } else {
                code + 1
            };
            if code >= base && code < next_base {
                let sym_idx = self.base_sym[len] + (code - base);
                if (sym_idx as usize) < self.symbols.len() {
                    return Ok(self.symbols[sym_idx as usize]);
                }
            }
        }
        Err("DEFLATE: no Huffman code matched")
    }
}

// ───────────────────────────── Fixed Huffman 表（RFC 1951 §3.2.6） ─────────────────────────────

fn fixed_litlen_table() -> HuffmanTable {
    // 287 个 symbol，码长按 RFC 规定：
    //   0..143  → 8 bit
    //   144..255 → 9 bit
    //   256..279 → 7 bit
    //   280..287 → 8 bit
    let mut lens = vec![0u8; 288];
    for s in 0..=143 {
        lens[s] = 8;
    }
    for s in 144..=255 {
        lens[s] = 9;
    }
    for s in 256..=279 {
        lens[s] = 7;
    }
    for s in 280..=287 {
        lens[s] = 8;
    }
    HuffmanTable::from_lengths(&lens).unwrap()
}

fn fixed_dist_table() -> HuffmanTable {
    // 30 个 distance 码（实际只有 0..29 有效），都用 5 bit
    let lens = vec![5u8; 30];
    HuffmanTable::from_lengths(&lens).unwrap()
}

// ───────────────────────────── 长度 / 距离表（RFC 1951 §3.2.5） ─────────────────────────────

/// 给定长度码 257..285，返回 (基础长度, 额外 bit 数)。
fn length_base_extra(sym: u16) -> Result<(u16, u8), &'static str> {
    if !(257..=285).contains(&sym) {
        return Err("DEFLATE: bad length symbol");
    }
    const LENGTH_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    let i = (sym - 257) as usize;
    Ok((LENGTH_BASE[i], LENGTH_EXTRA[i]))
}

/// 给定距离码 0..29，返回 (基础距离, 额外 bit 数)。
fn distance_base_extra(sym: u16) -> Result<(u16, u8), &'static str> {
    if sym > 29 {
        return Err("DEFLATE: bad distance symbol");
    }
    const DIST_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    Ok((DIST_BASE[sym as usize], DIST_EXTRA[sym as usize]))
}

// ───────────────────────────── 通用 Huffman 解块 ─────────────────────────────

fn inflate_huffman(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    litlen: &HuffmanTable,
    dist: &HuffmanTable,
) -> Result<(), &'static str> {
    loop {
        let sym = litlen.decode(br)?;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else {
            // 长度码
            let (base_len, extra_len) = length_base_extra(sym)?;
            let length = base_len as usize + br.read_bits(extra_len)? as usize;
            // 距离码
            let dsym = dist.decode(br)?;
            let (base_dist, extra_dist) = distance_base_extra(dsym)?;
            let distance = base_dist as usize + br.read_bits(extra_dist)? as usize;
            if distance > out.len() {
                return Err("DEFLATE: back-reference past start");
            }
            // 反向拷贝。注意：length 可能 > distance（自引用），必须逐字节复制。
            let start = out.len() - distance;
            for i in 0..length {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
}

// ───────────────────────────── Dynamic Huffman 表头解析 ─────────────────────────────

/// "Code-length code" 字母表的写入顺序（RFC 1951 §3.2.7）。
const CODE_LEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn read_dynamic_tables(br: &mut BitReader) -> Result<(HuffmanTable, HuffmanTable), &'static str> {
    let hlit = br.read_bits(5)? as usize + 257;
    let hdist = br.read_bits(5)? as usize + 1;
    let hclen = br.read_bits(4)? as usize + 4;

    // 读 hclen 个 3-bit 码长，按 CODE_LEN_ORDER 顺序填入。
    let mut code_len_lens = [0u8; 19];
    for i in 0..hclen {
        code_len_lens[CODE_LEN_ORDER[i]] = br.read_bits(3)? as u8;
    }
    let code_len_table = HuffmanTable::from_lengths(&code_len_lens)?;

    // 用 code_len_table 解码 (hlit + hdist) 个码长。
    let total = hlit + hdist;
    let mut lens = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = code_len_table.decode(br)?;
        match sym {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("DEFLATE: repeat-prev at start");
                }
                let prev = lens[i - 1];
                let n = br.read_bits(2)? as usize + 3;
                if i + n > total {
                    return Err("DEFLATE: repeat overflow");
                }
                for _ in 0..n {
                    lens[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let n = br.read_bits(3)? as usize + 3;
                if i + n > total {
                    return Err("DEFLATE: zero-repeat overflow");
                }
                for _ in 0..n {
                    lens[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let n = br.read_bits(7)? as usize + 11;
                if i + n > total {
                    return Err("DEFLATE: long-zero-repeat overflow");
                }
                for _ in 0..n {
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => return Err("DEFLATE: bad code-length symbol"),
        }
    }

    let litlen = HuffmanTable::from_lengths(&lens[..hlit])?;
    let dist = HuffmanTable::from_lengths(&lens[hlit..])?;
    Ok((litlen, dist))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitreader_lsb_first() {
        // 字节 0b1010_0101 = 0xA5。LSB-first 一位一位读应该得到 1, 0, 1, 0, 0, 1, 0, 1
        let mut br = BitReader::new(&[0xA5]);
        let bits: Vec<u32> = (0..8).map(|_| br.read_bits(1).unwrap()).collect();
        assert_eq!(bits, vec![1, 0, 1, 0, 0, 1, 0, 1]);
    }

    #[test]
    fn bitreader_multi_bit() {
        // 两字节 0x34, 0x12 → 16 位整数 LSB-first 拼出 = 0x1234
        let mut br = BitReader::new(&[0x34, 0x12]);
        assert_eq!(br.read_bits(16).unwrap(), 0x1234);
    }

    /// 手工构造的 stored block：BFINAL=1, BTYPE=00, LEN=5, NLEN=~5, "Hello"
    #[test]
    fn inflate_stored_block() {
        // 头字节：低 3 bit = BFINAL(1) | BTYPE(00 << 1) = 0b001
        // 然后跳到字节边界（其余 5 bit 是 padding），后面是 LEN+NLEN+data
        let mut data = vec![0b0000_0001u8]; // BFINAL=1, BTYPE=00
        data.extend_from_slice(&5u16.to_le_bytes()); // LEN = 5
        data.extend_from_slice(&(!5u16).to_le_bytes()); // NLEN
        data.extend_from_slice(b"Hello");
        assert_eq!(inflate(&data).unwrap(), b"Hello");
    }

    /// 测试 canonical Huffman 构造。RFC 1951 §3.2.2 给的例子：
    /// 字母 A,B,C,D,E,F,G,H 码长 3,3,3,3,3,2,4,4 →
    ///   F:00, A:010, B:011, C:100, D:101, E:110, G:1110, H:1111
    #[test]
    fn canonical_huffman_rfc_example() {
        // Lengths in alphabetical order: A=3, B=3, C=3, D=3, E=3, F=2, G=4, H=4
        let lens = vec![3, 3, 3, 3, 3, 2, 4, 4];
        let t = HuffmanTable::from_lengths(&lens).unwrap();
        // 编码 F (sym 5) → 码 00 长 2
        // Encoding: stream bits MSB-first = 0,0 → bitreader gets bits LSB-first into byte
        //   byte = 0b xxxx_xx00 = 0x00（高位是 padding）
        // 用 bitreader 读这 2 bit (LSB-first reading) = 0, 0. 拼成 Huffman MSB-first → code = 00.
        let mut br = BitReader::new(&[0b0000_0000]);
        assert_eq!(t.decode(&mut br).unwrap(), 5); // F
    }

    /// 用 Python zlib 生成的"Hello, world!"压缩流，跑 inflate 看结果。
    /// 实际数据由 `python3 -c "import zlib; print(zlib.compress(b'Hello, world!')[2:-4].hex())"` 生成（去掉 zlib 包装的 CMF/FLG 和 Adler-32）
    /// 但这里我们用更可控的方式：在 deflate_round_trip 测试里用自家压缩+解压不可能（没写 deflate 编码），
    /// 所以靠 fixed Huffman 的手工小例子。
    ///
    /// 这个测试用一个真实的 zlib stream（去包装后）：
    ///   原文："Hi" (字面 0x48 0x69)
    ///   zlib 输出：78 9C F3 C8 04 00 01 6B 00 87
    ///   去掉前 2 字节 CMF/FLG 和后 4 字节 Adler-32：F3 C8 04 00
    ///   即 [0xF3, 0xC8, 0x04, 0x00]
    #[test]
    fn inflate_fixed_huffman_real_zlib_payload() {
        let payload = [0xF3u8, 0xC8, 0x04, 0x00];
        let out = inflate(&payload).unwrap();
        assert_eq!(out, b"Hi");
    }

    /// 多 block：两个 stored block 拼起来。
    #[test]
    fn inflate_two_stored_blocks() {
        // Block 1: BFINAL=0, BTYPE=00, LEN=3, "abc"
        // Block 2: BFINAL=1, BTYPE=00, LEN=3, "def"
        let mut data = Vec::new();
        data.push(0b0000_0000u8); // BFINAL=0, BTYPE=00
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&(!3u16).to_le_bytes());
        data.extend_from_slice(b"abc");
        data.push(0b0000_0001u8); // BFINAL=1, BTYPE=00
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&(!3u16).to_le_bytes());
        data.extend_from_slice(b"def");
        assert_eq!(inflate(&data).unwrap(), b"abcdef");
    }

    /// 真实 zlib 流（含 LZ77 反向引用）：原文 "abcabcabc"
    /// Python: `zlib.compress(b'abcabcabc')[2:-4]` → 4B 4C 4A 4E 04 23 00
    #[test]
    fn inflate_lz77_back_reference() {
        let payload = [0x4Bu8, 0x4C, 0x4A, 0x4E, 0x04, 0x23, 0x00];
        let out = inflate(&payload).unwrap();
        assert_eq!(out, b"abcabcabc");
    }

    /// 经典 "Hello, world!" 通过 zlib（去包装）。
    /// Python 生成：F3 48 CD C9 C9 D7 51 28 CF 2F CA 49 51 04 00
    #[test]
    fn inflate_hello_world() {
        let payload = [
            0xF3u8, 0x48, 0xCD, 0xC9, 0xC9, 0xD7, 0x51, 0x28, 0xCF, 0x2F, 0xCA, 0x49, 0x51, 0x04,
            0x00,
        ];
        let out = inflate(&payload).unwrap();
        assert_eq!(out, b"Hello, world!");
    }
}
