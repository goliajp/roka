//! DEFLATE encoder — fixed Huffman (BTYPE=01) + LZ77 back-references.
//!
//! Replaces the earlier "stored block only" approach in PNG output. For QR images
//! the typical compression ratio against raw pixel data is ~30-100×, so the
//! per-byte cost of CRC32 / Adler-32 / `Vec::extend_from_slice` shrinks
//! proportionally — that's where the wall-clock win comes from.
//!
//! # Strategy
//!
//! 1. **Fixed Huffman codes** (RFC 1951 §3.2.6). Pre-encoded, no per-block table
//!    construction. For QR's 0x00 / 0xFF dominated histogram this is already
//!    close to optimal (the dynamic-Huffman win is ~5-10% extra, not worth the
//!    complexity here).
//! 2. **LZ77 with a hash table**: 3-byte rolling hash → most-recent position.
//!    Walk the chain (single-slot for now; multi-slot is task #32 if needed) to
//!    find the longest back-reference within 32 KiB. Minimum match length 3.
//! 3. **Lazy matching**: at position `i`, also try a match at `i+1`. Pick the
//!    longer one. This is the standard zlib-level-3-ish trick that consistently
//!    finds the +5-10% extra runs.
//! 4. **Bit packing**: DEFLATE writes bits LSB-first within each byte; Huffman
//!    codes are MSB-first within the code. We store all Huffman codes already
//!    bit-reversed so the writer can blindly LSB-pack them.
//!
//! Output: a single BFINAL=1 BTYPE=01 block (no header overhead beyond 3 bits).

#![allow(dead_code)] // some helpers / consts are pub for testability

const WINDOW: usize = 32 * 1024; // RFC 1951 max distance
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const HASH_BITS: usize = 15;
const HASH_SIZE: usize = 1 << HASH_BITS; // 32 KiB entries

/// Bit-packed output (LSB-first within each byte, the DEFLATE convention).
struct BitWriter {
    buf: Vec<u8>,
    bit_buf: u64,
    bit_count: u8,
}

impl BitWriter {
    fn new(estimated_size: usize) -> Self {
        Self {
            buf: Vec::with_capacity(estimated_size),
            bit_buf: 0,
            bit_count: 0,
        }
    }

    /// Write `n` bits, with bit 0 of `value` going out first.
    #[inline(always)]
    fn write_bits(&mut self, value: u32, n: u8) {
        debug_assert!(n <= 32);
        self.bit_buf |= (value as u64) << self.bit_count;
        self.bit_count += n;
        while self.bit_count >= 8 {
            self.buf.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bit_count -= 8;
        }
    }

    /// Flush any remaining bits (pad with zero to byte boundary) and return the buffer.
    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.buf.push((self.bit_buf & 0xFF) as u8);
        }
        self.buf
    }
}

// ────────────── Fixed Huffman tables (pre-reversed for LSB-first writing) ──────────────

/// Fixed-Huffman code table for literal/length symbols 0..=287.
///
/// Each entry is `(reversed_code, code_length)`.
/// Per RFC 1951 §3.2.6:
/// - syms 0..=143  → 8-bit, code = 0b00110000 + sym
/// - syms 144..=255 → 9-bit, code = 0b110010000 + (sym - 144)
/// - syms 256..=279 → 7-bit, code = 0b0000000 + (sym - 256)
/// - syms 280..=287 → 8-bit, code = 0b11000000 + (sym - 280)
static LITLEN_CODES: [(u16, u8); 288] = build_litlen_codes();

const fn build_litlen_codes() -> [(u16, u8); 288] {
    let mut t = [(0u16, 0u8); 288];
    let mut sym = 0;
    while sym < 144 {
        t[sym] = (reverse_bits((0b00110000 + sym) as u16, 8), 8);
        sym += 1;
    }
    while sym < 256 {
        t[sym] = (reverse_bits((0b110010000 + (sym - 144)) as u16, 9), 9);
        sym += 1;
    }
    while sym < 280 {
        t[sym] = (reverse_bits((sym - 256) as u16, 7), 7);
        sym += 1;
    }
    while sym < 288 {
        t[sym] = (reverse_bits((0b11000000 + (sym - 280)) as u16, 8), 8);
        sym += 1;
    }
    t
}

/// Reverse the low `n` bits of `v`.
const fn reverse_bits(v: u16, n: u8) -> u16 {
    let mut r = 0u16;
    let mut i = 0;
    while i < n {
        r = (r << 1) | ((v >> i) & 1);
        i += 1;
    }
    r
}

/// Distance code table: distance 0..=29, all 5-bit fixed codes (RFC 1951 §3.2.6).
/// Stored pre-reversed.
static DIST_CODES: [(u16, u8); 30] = build_dist_codes();

const fn build_dist_codes() -> [(u16, u8); 30] {
    let mut t = [(0u16, 0u8); 30];
    let mut sym = 0;
    while sym < 30 {
        t[sym] = (reverse_bits(sym as u16, 5), 5);
        sym += 1;
    }
    t
}

// ───────────────────── Length / distance code tables (RFC 1951 §3.2.5) ─────────────────────

/// For a given match length 3..=258, returns `(litlen_sym, extra_bits_count, extra_bits_value)`.
fn length_to_code(len: usize) -> (u16, u8, u32) {
    // Tabulated since the partitioning is irregular at length boundaries.
    const TABLE: [(u16, u8); 29] = [
        (257, 0), (258, 0), (259, 0), (260, 0), (261, 0), (262, 0), (263, 0), (264, 0),
        (265, 1), (266, 1), (267, 1), (268, 1),
        (269, 2), (270, 2), (271, 2), (272, 2),
        (273, 3), (274, 3), (275, 3), (276, 3),
        (277, 4), (278, 4), (279, 4), (280, 4),
        (281, 5), (282, 5), (283, 5), (284, 5),
        (285, 0),
    ];
    const BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
        67, 83, 99, 115, 131, 163, 195, 227, 258,
    ];
    // Binary search for the bucket.
    let mut idx = 0;
    while idx + 1 < BASE.len() && BASE[idx + 1] <= len {
        idx += 1;
    }
    let (sym, extra) = TABLE[idx];
    let extra_val = (len - BASE[idx]) as u32;
    (sym, extra, extra_val)
}

/// For a given match distance 1..=32768, returns `(dist_sym, extra_bits_count, extra_bits_value)`.
fn distance_to_code(dist: usize) -> (u16, u8, u32) {
    const BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
        9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    ];
    let mut idx = 0;
    while idx + 1 < BASE.len() && BASE[idx + 1] <= dist {
        idx += 1;
    }
    let extra_val = (dist - BASE[idx]) as u32;
    (idx as u16, EXTRA[idx], extra_val)
}

// ───────────────────────────────── LZ77 hash table ─────────────────────────────────

/// Simple 3-byte rolling hash → most-recent position (`usize::MAX` = empty).
struct HashTable {
    head: Box<[u32; HASH_SIZE]>,
}

impl HashTable {
    fn new() -> Self {
        Self {
            head: Box::new([u32::MAX; HASH_SIZE]),
        }
    }

    #[inline(always)]
    fn hash(a: u8, b: u8, c: u8) -> usize {
        // Knuth-style multiplier mod 2^32, then take top HASH_BITS.
        let v = ((a as u32) << 16) | ((b as u32) << 8) | (c as u32);
        ((v.wrapping_mul(2654435761) as usize) >> (32 - HASH_BITS)) & (HASH_SIZE - 1)
    }
}

// ───────────────────────────── DEFLATE encoder ─────────────────────────────

/// Encode `input` as a single fixed-Huffman DEFLATE block (BFINAL=1, BTYPE=01)
/// while simultaneously computing the Adler-32 checksum of `input`.
///
/// PNG callers need both — folding them into one scan saves an extra full O(N)
/// pass over the raw image data.
pub fn deflate_fixed_with_adler32(input: &[u8]) -> (Vec<u8>, u32) {
    let mut bw = BitWriter::new(input.len() / 2 + 16);

    // Block header: BFINAL=1 (1 bit), BTYPE=01 (2 bits LSB-first).
    bw.write_bits(1, 1);
    bw.write_bits(0b01, 2);

    const ADLER_MOD: u32 = 65521;
    const NMAX: usize = 5552;
    let mut adler_a: u32 = 1;
    let mut adler_b: u32 = 0;
    let mut adler_since_mod = 0usize;

    let mut hash = HashTable::new();
    let mut i = 0usize;
    while i < input.len() {
        let match_here = find_match(input, i, &mut hash);
        let chosen = if let Some((len_here, dist_here)) = match_here {
            // Lazy match: probe i+1 for a strictly longer match. Skip the probe
            // when the current match is already very long — diminishing returns
            // and the probe re-inserts into the hash table needlessly.
            if len_here < 32 && i + 1 < input.len() {
                let next = find_match(input, i + 1, &mut hash);
                if let Some((len_next, _)) = next {
                    if len_next > len_here {
                        // Emit literal at i and update Adler over that byte.
                        let b = input[i];
                        emit_literal(&mut bw, b);
                        adler_a = adler_a.wrapping_add(b as u32);
                        adler_b = adler_b.wrapping_add(adler_a);
                        adler_since_mod += 1;
                        if adler_since_mod >= NMAX {
                            adler_a %= ADLER_MOD;
                            adler_b %= ADLER_MOD;
                            adler_since_mod = 0;
                        }
                        i += 1;
                        continue;
                    }
                }
            }
            Some((len_here, dist_here))
        } else {
            None
        };

        match chosen {
            Some((len, dist)) => {
                emit_match(&mut bw, len, dist);
                // Update Adler over the consumed bytes.
                for &b in &input[i..i + len] {
                    adler_a = adler_a.wrapping_add(b as u32);
                    adler_b = adler_b.wrapping_add(adler_a);
                }
                adler_since_mod += len;
                if adler_since_mod >= NMAX {
                    adler_a %= ADLER_MOD;
                    adler_b %= ADLER_MOD;
                    adler_since_mod = 0;
                }
                i += len;
            }
            None => {
                let b = input[i];
                emit_literal(&mut bw, b);
                adler_a = adler_a.wrapping_add(b as u32);
                adler_b = adler_b.wrapping_add(adler_a);
                adler_since_mod += 1;
                if adler_since_mod >= NMAX {
                    adler_a %= ADLER_MOD;
                    adler_b %= ADLER_MOD;
                    adler_since_mod = 0;
                }
                i += 1;
            }
        }
    }

    // End-of-block marker (litlen symbol 256).
    let (rev, n) = LITLEN_CODES[256];
    bw.write_bits(rev as u32, n);

    adler_a %= ADLER_MOD;
    adler_b %= ADLER_MOD;
    let adler = (adler_b << 16) | adler_a;
    (bw.finish(), adler)
}

/// Encode `input` as a single fixed-Huffman DEFLATE block (BFINAL=1, BTYPE=01).
pub fn deflate_fixed(input: &[u8]) -> Vec<u8> {
    // Heuristic output size: assume 2× compression — way over-budget for QR images.
    let mut bw = BitWriter::new(input.len() / 2 + 16);

    // Block header: BFINAL=1 (1 bit), BTYPE=01 (2 bits LSB-first → bits "1, 0").
    bw.write_bits(1, 1); // BFINAL
    bw.write_bits(0b01, 2); // BTYPE (LSB-first means bit 0 first; 01 → bit0=1, bit1=0)

    let mut hash = HashTable::new();
    let mut i = 0usize;
    while i < input.len() {
        let match_here = find_match(input, i, &mut hash);
        // Lazy match: see if i+1 gives a strictly better one.
        let chosen = if let Some((len_here, dist_here)) = match_here {
            if i + 1 < input.len() {
                let next = find_match(input, i + 1, &mut hash);
                if let Some((len_next, _)) = next {
                    if len_next > len_here {
                        // Emit literal at i, defer the match decision to i+1.
                        emit_literal(&mut bw, input[i]);
                        i += 1;
                        continue;
                    }
                }
            }
            Some((len_here, dist_here))
        } else {
            None
        };

        match chosen {
            Some((len, dist)) => {
                emit_match(&mut bw, len, dist);
                i += len;
            }
            None => {
                emit_literal(&mut bw, input[i]);
                i += 1;
            }
        }
    }

    // End-of-block marker (litlen symbol 256).
    let (rev, n) = LITLEN_CODES[256];
    bw.write_bits(rev as u32, n);

    bw.finish()
}

#[inline]
fn emit_literal(bw: &mut BitWriter, byte: u8) {
    let (rev, n) = LITLEN_CODES[byte as usize];
    bw.write_bits(rev as u32, n);
}

#[inline]
fn emit_match(bw: &mut BitWriter, len: usize, dist: usize) {
    let (litlen_sym, len_extra_bits, len_extra_val) = length_to_code(len);
    let (rev, n) = LITLEN_CODES[litlen_sym as usize];
    bw.write_bits(rev as u32, n);
    if len_extra_bits > 0 {
        bw.write_bits(len_extra_val, len_extra_bits);
    }
    let (dist_sym, dist_extra_bits, dist_extra_val) = distance_to_code(dist);
    let (dist_rev, dist_n) = DIST_CODES[dist_sym as usize];
    bw.write_bits(dist_rev as u32, dist_n);
    if dist_extra_bits > 0 {
        bw.write_bits(dist_extra_val, dist_extra_bits);
    }
}

/// At position `i`, search for the longest LZ77 match within the sliding window.
/// Also inserts `i` into the hash table.
#[inline]
fn find_match(input: &[u8], i: usize, hash: &mut HashTable) -> Option<(usize, usize)> {
    if i + MIN_MATCH > input.len() {
        return None;
    }
    let h = HashTable::hash(input[i], input[i + 1], input[i + 2]);
    let prev = hash.head[h];
    // Insert current position (single-slot table — overwrite).
    hash.head[h] = i as u32;
    if prev == u32::MAX {
        return None;
    }
    let prev = prev as usize;
    if i <= prev {
        return None;
    }
    let dist = i - prev;
    if dist > WINDOW {
        return None;
    }
    // Verify match and extend.
    if input[prev] != input[i]
        || input[prev + 1] != input[i + 1]
        || input[prev + 2] != input[i + 2]
    {
        return None;
    }
    let max_extend = MAX_MATCH.min(input.len() - i);
    let mut len = 3;
    while len < max_extend && input[prev + len] == input[i + len] {
        len += 1;
    }
    Some((len, dist))
}

// ────────────────────────────────── Tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::inflate;

    fn round_trip(input: &[u8]) {
        let compressed = deflate_fixed(input);
        let decompressed = inflate(&compressed)
            .expect("our own DEFLATE output should round-trip");
        assert_eq!(decompressed, input, "round-trip mismatch");
    }

    #[test]
    fn empty_input_round_trips() {
        round_trip(b"");
    }

    #[test]
    fn single_byte_round_trips() {
        round_trip(b"a");
    }

    #[test]
    fn short_text_round_trips() {
        round_trip(b"Hello, world!");
    }

    #[test]
    fn lots_of_zeros_compresses() {
        let input = vec![0u8; 10_000];
        let compressed = deflate_fixed(&input);
        // 10 KiB of zeros should compress to a tiny output.
        assert!(
            compressed.len() < 150,
            "10 KiB zeros compressed to {} bytes (expected < 150)",
            compressed.len()
        );
        round_trip(&input);
    }

    #[test]
    fn lots_of_alternating_bytes_compresses() {
        let mut input = Vec::new();
        for _ in 0..2000 {
            input.extend_from_slice(&[0x00, 0xFF]);
        }
        let compressed = deflate_fixed(&input);
        assert!(
            compressed.len() < 200,
            "4 KiB alternating compressed to {} bytes",
            compressed.len()
        );
        round_trip(&input);
    }

    #[test]
    fn repeated_pattern_compresses() {
        let pattern = b"abcdefghij";
        let input: Vec<u8> = pattern.iter().cycle().take(5000).copied().collect();
        let compressed = deflate_fixed(&input);
        assert!(
            compressed.len() < 500,
            "5 KiB repeated 10-byte pattern compressed to {} bytes",
            compressed.len()
        );
        round_trip(&input);
    }

    #[test]
    fn random_bytes_round_trip() {
        // No compression expected, but must round-trip.
        let mut seed = 0x1234_5678u64;
        let mut input = vec![0u8; 1000];
        for b in input.iter_mut() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (seed >> 56) as u8;
        }
        round_trip(&input);
    }
}
