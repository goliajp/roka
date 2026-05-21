//! GF(256) 有限域算术 —— Reed-Solomon 和 BCH 的算术基础。
//!
//! # 直觉
//!
//! 计算机里 8 位字节天然就是 0..=255。如果我们想做"字节级别的加减乘除"——
//! 即把 byte 看作可计算的"数"——必须定义清楚这四种运算结果还是 byte。
//! 普通整数算术不行：`200 * 3 = 600` 超出 byte 范围。
//!
//! GF(256)（256 元有限域）就是给这 256 个值定义的一套"加减乘除"，让结果永远落在 0..=255 内，
//! 而且满足通常的代数定律（结合律、分配律、逆元存在）。Reed-Solomon 纠错码本质就是在 GF(256)
//! 上做多项式运算，所以它的每个系数永远是一个 byte。
//!
//! # GF(256) 的具体定义
//!
//! - **加法 / 减法**：异或（XOR）。`a + b = a ^ b`，自己加自己等于零，所以加法和减法是同一种操作。
//!
//! - **乘法**：把每个 byte 看作"系数都是 0 或 1 的多项式"——比如 `0b1011 = x^3 + x + 1`。
//!   两个多项式相乘是常规多项式乘法，但系数运算用 XOR（即 mod 2）。乘完结果可能超过 8 位，
//!   再用一个 8 次的"本原多项式"取余，结果就回到 8 位以内。
//!   QR 码标准使用本原多项式 `x^8 + x^4 + x^3 + x^2 + 1`，二进制是 `0b1_0001_1101 = 0x11D`。
//!
//! - **除法**：通过"对数表"实现。任何非零元素都能写成 `α^k` 的形式（α 是生成元，取 α=2 即 `0x02`），
//!   于是 `a * b = α^(log_a + log_b)`，`a / b = α^(log_a - log_b)`。预计算两张表就把乘除变成查表 + 加减。
//!
//! # 表的形状
//!
//! - `EXP[i] = α^i`，i 取 0..=511（多分配一倍长度让 `log_a + log_b` 不用取模）
//! - `LOG[a] = i` 满足 `α^i = a`；`LOG[0]` 未定义（约定填 0，但调用方必须先排除 a==0 的情况）
//!
//! # 测试基准
//!
//! 直接验证 RFC 6238 / ISO 18004 给出的若干乘除等式，确保表的方向和本原多项式都正确。

/// QR 标准本原多项式：x^8 + x^4 + x^3 + x^2 + 1 = 0x11D。
pub const PRIM: u16 = 0x11D;

/// 生成元 α = 2。GF(256) 上 2 是本原多项式 0x11D 下的本原元（阶为 255）。
#[allow(dead_code)]
pub const GENERATOR: u8 = 2;

/// 反对数表 α^i，i ∈ 0..=511。前 255 项即所有非零元素，后面是循环重复，
/// 这样 `a*b = EXP[LOG[a] + LOG[b]]` 不必取模 255。
pub const EXP: [u8; 512] = build_exp();

/// 对数表 LOG[a] = i 满足 EXP[i] = a；LOG[0] 不定义（实现里填 0，调用方需排除）。
pub const LOG: [u8; 256] = build_log(&EXP);

const fn build_exp() -> [u8; 512] {
    let mut exp = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= PRIM;
        }
        i += 1;
    }
    // 后半段重复一次，i ∈ 255..512 时 EXP[i] = EXP[i-255]，方便乘法不取模。
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    exp
}

const fn build_log(exp: &[u8; 512]) -> [u8; 256] {
    let mut log = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        log[exp[i] as usize] = i as u8;
        i += 1;
    }
    log
}

/// 加法 / 减法 —— 在 GF(2^n) 里两者都是 XOR（特征 2，自加为零）。
#[inline]
#[allow(dead_code)]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// 乘法：0 与任何数相乘为 0；否则查 EXP/LOG 表。
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
}

/// 除法：a / b，b != 0。0 / b = 0。
#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "GF(256) division by zero");
    if a == 0 {
        return 0;
    }
    // log_a - log_b 在 [-(255-1), 255-1] 内，加 255 让结果非负，再用 EXP 的 512 长查表自动处理回绕。
    let diff = LOG[a as usize] as i16 - LOG[b as usize] as i16 + 255;
    EXP[diff as usize]
}

/// 求逆：1 / a，a != 0。
#[inline]
#[allow(dead_code)]
pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0, "GF(256) inverse of zero");
    EXP[255 - LOG[a as usize] as usize]
}

/// 幂：a^n。约定 a==0 && n==0 时返回 1（多项式 0^0 通常取 1，便于 RS 求值）。
#[allow(dead_code)]
pub fn pow(a: u8, n: u32) -> u8 {
    if a == 0 {
        return if n == 0 { 1 } else { 0 };
    }
    let exp_idx = ((LOG[a as usize] as u32) * n) % 255;
    EXP[exp_idx as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_powers_basic() {
        // α = 2，α^i 在 i<8 时就是普通 2^i（还没溢出，不需要约简）。
        assert_eq!(EXP[0], 1);
        assert_eq!(EXP[1], 2);
        assert_eq!(EXP[2], 4);
        assert_eq!(EXP[7], 128);
        // α^8 = α^4 + α^3 + α^2 + 1 = 16+8+4+1 = 29（由本原多项式约简）。
        assert_eq!(EXP[8], 29);
    }

    #[test]
    fn log_is_inverse_of_exp() {
        for i in 0..255 {
            assert_eq!(LOG[EXP[i] as usize] as usize, i);
        }
    }

    #[test]
    fn exp_wraps_at_255() {
        // EXP 的后半段是前半段重复一次，方便乘法不取模。
        for i in 0..255 {
            assert_eq!(EXP[i + 255], EXP[i]);
        }
    }

    #[test]
    fn mul_zero_short_circuits() {
        for a in 0u8..=255 {
            assert_eq!(mul(0, a), 0);
            assert_eq!(mul(a, 0), 0);
        }
    }

    #[test]
    fn mul_one_is_identity() {
        for a in 0u8..=255 {
            assert_eq!(mul(1, a), a);
            assert_eq!(mul(a, 1), a);
        }
    }

    #[test]
    fn mul_commutative_and_associative() {
        for &(a, b, c) in &[(2u8, 3, 5), (17, 200, 33), (0xAB, 0xCD, 0xEF)] {
            assert_eq!(mul(a, b), mul(b, a));
            assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
        }
    }

    #[test]
    fn mul_distributive_over_add() {
        for &(a, b, c) in &[(2u8, 3, 5), (17, 200, 33), (0xAB, 0xCD, 0xEF)] {
            assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
        }
    }

    #[test]
    fn div_is_inverse_of_mul() {
        for a in 1u8..=255 {
            for b in 1u8..=255 {
                let p = mul(a, b);
                assert_eq!(div(p, b), a);
                assert_eq!(div(p, a), b);
            }
        }
    }

    #[test]
    fn inv_times_self_is_one() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }

    #[test]
    fn pow_basic_cases() {
        assert_eq!(pow(0, 0), 1);
        assert_eq!(pow(0, 5), 0);
        assert_eq!(pow(7, 0), 1);
        assert_eq!(pow(7, 1), 7);
        // pow(2, k) == EXP[k] for k < 255
        for k in 0u32..255 {
            assert_eq!(pow(2, k), EXP[k as usize]);
        }
        // pow 应满足周期 255：a^255 = 1（任何非零 a）
        for a in 1u8..=255 {
            assert_eq!(pow(a, 255), 1);
        }
    }
}
