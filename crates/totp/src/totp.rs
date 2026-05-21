//! TOTP — Time-based One-Time Password（RFC 6238）。
//!
//! 教学注释
//! ========
//! TOTP 是 HOTP 的一个特例：把"计数器"换成"当前时间窗口的编号"。
//!
//! ```text
//!   T = floor( (current_unix_time - T0) / step )
//!   code = HOTP(secret, T)
//! ```
//!
//! 工程上几乎全部使用 `T0 = 0`、`step = 30` 秒、`digits = 6`。所以同一
//! 个 30 秒窗口内，服务端和手机 App 各自独立算出来的码是一样的。
//!
//! 时钟偏移 & 验证窗口
//! -------------------
//! 真实世界里两边的时钟会有偏差，加上用户输入 + 网络延迟，所以服务端
//! 验证时通常允许 **±1 个 step** 的偏移：依次尝试 `T-1, T, T+1` 三个
//! 值，任意一个匹配就算验证通过。
//!
//! 注意事项（实战相关，不在本 demo 内做）：
//! - **重放保护**：每个 secret 在每个 (T, digits) 上只能验证成功一次，
//!   服务端要把"上次成功的最大 T"记下来，拒绝 ≤ 它的请求。
//! - **限速**：6 位码只有 100 万种可能，必须配合速率限制和锁定策略。

use crate::hotp::hotp;

/// 默认 TOTP 时间窗口：30 秒。
pub const DEFAULT_STEP: u64 = 30;
/// 默认 TOTP 输出位数：6。
pub const DEFAULT_DIGITS: u32 = 6;

/// 计算给定时间戳下的 TOTP 码。
pub fn totp(secret: &[u8], unix_time: u64, step: u64, digits: u32) -> String {
    let counter = unix_time / step;
    hotp(secret, counter, digits)
}

/// 验证用户输入的 `code`，允许在 ±`window` 个 step 范围内匹配。
///
/// 返回值：
/// * `Some(offset)` —— 命中时的窗口偏移，`-window..=window`，
///   `0` 表示"当前窗口"，`-1` 表示"上一个窗口"，依此类推。
/// * `None` —— 不匹配。
///
/// 用 `Some(offset)` 而不是 `bool` 让上层可以记录"用户落后/超前了多少"，
/// 这是真实系统里诊断"用户时钟漂了"或"重放攻击"的有用信息。
pub fn verify(
    secret: &[u8],
    code: &str,
    unix_time: u64,
    step: u64,
    digits: u32,
    window: i64,
) -> Option<i64> {
    let center = (unix_time / step) as i64;
    for offset in -window..=window {
        let counter = (center + offset) as u64;
        if hotp(secret, counter, digits) == code {
            return Some(offset);
        }
    }
    None
}

/// 当前 step 还剩多少秒进入下一个窗口（给 watch 进度条用）。
pub fn seconds_remaining(unix_time: u64, step: u64) -> u64 {
    step - (unix_time % step)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的标准测试向量（SHA-1 部分，8 位输出）。
    /// secret = ASCII "12345678901234567890"。
    #[test]
    fn rfc6238_appendix_b() {
        let secret = b"12345678901234567890";
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ];
        for &(t, want) in cases {
            assert_eq!(totp(secret, t, 30, 8), want, "t = {}", t);
        }
    }

    #[test]
    fn verify_within_window() {
        let secret = b"12345678901234567890";
        // RFC 4226: counter = 1 → "287082"。t=59 → counter=1，t=89 → counter=2。
        let code_at_59 = totp(secret, 59, 30, 6);
        // 当前窗口验证
        assert_eq!(verify(secret, &code_at_59, 59, 30, 6, 1), Some(0));
        // 30 秒后再来验证：是上一个窗口
        assert_eq!(verify(secret, &code_at_59, 89, 30, 6, 1), Some(-1));
        // 90 秒之后已经超出 ±1 窗口，应该失败
        assert_eq!(verify(secret, &code_at_59, 130, 30, 6, 1), None);
    }

    #[test]
    fn seconds_remaining_basics() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
        assert_eq!(seconds_remaining(31, 30), 29);
    }
}
