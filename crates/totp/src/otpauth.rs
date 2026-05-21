//! `otpauth://` URI 构造（Google Authenticator Key URI Format）。
//!
//! 教学注释
//! ========
//! 这不是 IETF 标准，而是 Google 早期定下的"事实标准"，几乎所有 2FA App
//! （Google Authenticator / Authy / 1Password / Bitwarden …）都识别它。
//!
//! 长这样：
//!
//! ```text
//!   otpauth://totp/Issuer:account?
//!       secret=BASE32&
//!       issuer=Issuer&
//!       algorithm=SHA1&
//!       digits=6&
//!       period=30
//! ```
//!
//! 把这串文本编码成二维码，让手机 App 扫一下，就完成绑定了。
//!
//! 字段说明
//! --------
//! * `label`：路径里的那段，约定写成 `Issuer:account`，会作为 App 列表
//!   里那条记录的标题显示。
//! * `secret`：base32 编码的密钥，**不能含 padding `=`**（多数 App 接受
//!   带 padding 的，但去掉看起来更标准）。
//! * `issuer`：单独再列一遍 issuer，App 用它做图标匹配。
//! * 其余 `algorithm/digits/period`：默认值，写出来更明确。

use crate::base32;

/// 构造 otpauth:// URI。
pub fn build_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    // label 形如 "Issuer:account"。注意 ':' 是 label 的结构分隔符，不能被
    // 百分号转义；而 issuer / account 内部出现的特殊字符各自要 url-encode。
    let label = format!("{}:{}", url_encode(issuer), url_encode(account));

    // base32 编码并去掉 padding —— 多数 App 都支持无 padding 形式
    let secret_b32 = base32::encode(secret);
    let secret_b32 = secret_b32.trim_end_matches('=');

    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        label = label,
        secret = secret_b32,
        issuer = url_encode(issuer),
    )
}

/// 简易 URL 编码（百分号转义所有非 unreserved 字符）。
///
/// "unreserved" 在 RFC 3986 里定义为 `ALPHA / DIGIT / - / _ / . / ~`。
/// 我们刻意写得啰嗦一点，方便阅读。
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let unreserved =
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            // 大写两位 hex
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_inputs() {
        // RFC 4226 测试 secret = "12345678901234567890"
        let uri = build_uri("Lab10", "alice", b"12345678901234567890");
        // 关键片段都在
        assert!(uri.starts_with("otpauth://totp/Lab10:alice?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Lab10"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn encodes_special_chars_in_label() {
        let uri = build_uri("My Co", "alice@example.com", b"secret___");
        // 空格 → %20，@ → %40
        assert!(uri.contains("totp/My%20Co:alice%40example.com"));
        assert!(uri.contains("issuer=My%20Co"));
    }
}
