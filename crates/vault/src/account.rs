//! Account 工具：otpauth URI build / parse + base32 secret 转码。
//!
//! 与 `Account` 配对使用，让 PWA / CLI 都不必各自实现 URI 解析。
//!
//! 接受的 URI：
//! ```text
//!   otpauth://totp/<label>?secret=<base32>[&issuer=...][&algorithm=SHA1][&digits=6][&period=30]
//! ```
//!
//! `<label>` 经过 url 解码后按 `:` 拆为 `(issuer, account)`；如果没有 `:`，整段当 account
//! 用，`issuer` 取 query `issuer=` 字段。

use super::vault::Account;

/// 解析错误。粗粒度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpauthError {
    /// 不是 `otpauth://totp/` 起头。
    BadScheme,
    /// URI 中包含无效百分号转义。
    BadEncoding,
    /// 缺少 `secret=` 参数。
    MissingSecret,
    /// `secret=` 不是合法的 base32。
    BadSecret,
}

impl core::fmt::Display for OtpauthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OtpauthError::BadScheme => f.write_str("not an otpauth://totp/ URI"),
            OtpauthError::BadEncoding => f.write_str("invalid percent-encoding"),
            OtpauthError::MissingSecret => f.write_str("missing secret= parameter"),
            OtpauthError::BadSecret => f.write_str("secret is not valid base32"),
        }
    }
}

impl std::error::Error for OtpauthError {}

impl Account {
    /// 从一个 `otpauth://totp/...` URI 构造 `Account`。
    ///
    /// Algorithm / digits / period 参数被读但 v1 不入存储——我们的 TOTP layer 全用默认值
    /// (SHA-1, 6 digits, 30s)。未来当我们的 TOTP 支持其它算法时再加。
    pub fn from_otpauth_uri(uri: &str) -> Result<Self, OtpauthError> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or(OtpauthError::BadScheme)?;
        let (label_raw, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = url_decode(label_raw).ok_or(OtpauthError::BadEncoding)?;

        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
            None => (None, label.trim().to_string()),
        };

        let mut secret_b32: Option<String> = None;
        let mut query_issuer: Option<String> = None;
        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = url_decode(v).ok_or(OtpauthError::BadEncoding)?;
            match k {
                "secret" => secret_b32 = Some(v),
                "issuer" => query_issuer = Some(v),
                _ => {} // ignore algorithm / digits / period in v1
            }
        }
        let secret_b32 = secret_b32.ok_or(OtpauthError::MissingSecret)?;
        let secret = base32_decode(&secret_b32).ok_or(OtpauthError::BadSecret)?;
        let issuer = query_issuer.or(label_issuer).unwrap_or_default();
        Ok(Account {
            issuer,
            account,
            secret,
        })
    }

    /// 构造 `otpauth://totp/<issuer>:<account>?secret=...&issuer=...`。
    pub fn to_otpauth_uri(&self) -> String {
        let mut s = String::from("otpauth://totp/");
        if !self.issuer.is_empty() {
            push_url_encoded(&mut s, &self.issuer);
            s.push(':');
        }
        push_url_encoded(&mut s, &self.account);
        s.push_str("?secret=");
        s.push_str(&base32_encode(&self.secret));
        if !self.issuer.is_empty() {
            s.push_str("&issuer=");
            push_url_encoded(&mut s, &self.issuer);
        }
        s
    }
}

// ───────────────────────────── helpers ─────────────────────────────

/// RFC 4648 base32 encode，**不**追加 `=` padding（authenticator app 通常都不要 padding）。
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// RFC 4648 base32 decode。容错：忽略 ASCII 空白，接受小写，忽略尾部 `=`。
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        let c = c.to_ascii_uppercase();
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let v = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            '2'..='7' => (c as u8 - b'2' + 26) as u32,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// URL decode (percent + plus → space). None on bad escape.
fn url_decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let h1 = chars.next()?.to_digit(16)?;
                let h2 = chars.next()?.to_digit(16)?;
                out.push((h1 * 16 + h2) as u8 as char);
            }
            '+' => out.push(' '),
            other => out.push(other),
        }
    }
    Some(out)
}

/// URL encode — conservative: percent-encode every non-unreserved char except ':' '/' '?' '&' '=' which
/// have structural meaning at higher levels. For label fields we treat `:` as separator, so this is
/// called on individual fields where structural chars must be encoded.
fn push_url_encoded(out: &mut String, s: &str) {
    for b in s.bytes() {
        let unreserved = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_nybble(b >> 4));
            out.push(hex_nybble(b & 0x0f));
        }
    }
}

fn hex_nybble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + n - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00\xff\x01\xfe",
        ];
        for input in cases {
            let encoded = base32_encode(input);
            let decoded = base32_decode(&encoded).unwrap();
            assert_eq!(&decoded[..], *input, "round trip on {input:?}");
        }
    }

    /// RFC 4648 §10 vectors.
    #[test]
    fn rfc4648_vectors() {
        let pairs: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (raw, expected) in pairs {
            assert_eq!(base32_encode(raw), *expected);
            assert_eq!(base32_decode(expected).unwrap(), *raw);
        }
    }

    #[test]
    fn parse_simple_otpauth() {
        let a = Account::from_otpauth_uri(
            "otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme",
        )
        .unwrap();
        assert_eq!(a.issuer, "Acme");
        assert_eq!(a.account, "alice@example.com");
        assert_eq!(a.secret, base32_decode("JBSWY3DPEHPK3PXP").unwrap());
    }

    #[test]
    fn parse_url_encoded_label() {
        let a = Account::from_otpauth_uri(
            "otpauth://totp/Acme:alice%40example.com?secret=JBSWY3DPEHPK3PXP",
        )
        .unwrap();
        assert_eq!(a.account, "alice@example.com");
    }

    #[test]
    fn parse_no_issuer() {
        let a = Account::from_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.issuer, "");
        assert_eq!(a.account, "alice");
    }

    #[test]
    fn parse_query_issuer_overrides_label() {
        let a = Account::from_otpauth_uri(
            "otpauth://totp/Old:alice?secret=JBSWY3DPEHPK3PXP&issuer=New",
        )
        .unwrap();
        assert_eq!(a.issuer, "New"); // query takes precedence
    }

    #[test]
    fn parse_rejects_bad_scheme() {
        assert_eq!(
            Account::from_otpauth_uri("https://example.com").err(),
            Some(OtpauthError::BadScheme)
        );
    }

    #[test]
    fn parse_rejects_missing_secret() {
        assert_eq!(
            Account::from_otpauth_uri("otpauth://totp/foo?issuer=x").err(),
            Some(OtpauthError::MissingSecret)
        );
    }

    #[test]
    fn parse_rejects_bad_base32() {
        assert_eq!(
            Account::from_otpauth_uri("otpauth://totp/foo?secret=!!").err(),
            Some(OtpauthError::BadSecret)
        );
    }

    #[test]
    fn build_then_parse_round_trip() {
        let original = Account {
            issuer: "Acme Corp".into(),
            account: "alice+work@example.com".into(),
            secret: vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21],
        };
        let uri = original.to_otpauth_uri();
        let parsed = Account::from_otpauth_uri(&uri).unwrap();
        assert_eq!(parsed.issuer, original.issuer);
        assert_eq!(parsed.account, original.account);
        assert_eq!(parsed.secret, original.secret);
    }
}
