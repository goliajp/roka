//! Reed-Solomon 编码 / 解码（QR 码使用的 BCH 视角）。
//!
//! # RS 的本质
//!
//! Reed-Solomon 把 m 个数据字节看成多项式 M(x) = d_0 x^{m-1} + d_1 x^{m-2} + ... + d_{m-1}
//! 的系数（系数取自 GF(256)），编码就是计算 `M(x) * x^k mod g(x)`，把这个余式（k 个字节）
//! 作为 EC 字节附在数据后面。生成多项式 g(x) 是
//!
//! ```text
//!   g(x) = (x - α^0)(x - α^1) ... (x - α^{k-1})
//! ```
//!
//! 这种特殊构造让"代码字 = M(x)·x^k - 余式"在所有 α^i (i = 0..k-1) 处取值为 0——这就是 BCH 视角。
//! 校验解码时算 R(α^i)（叫做"症状" syndrome）；若全部为 0 则无错；否则解一组方程求出错位和错值。
//!
//! # 错误能纠到几个？
//!
//! k 个 EC 字节可纠 ⌊k/2⌋ 个错（任意位置）。QR 码的 EC 级别 L/M/Q/H 大致对应每块 7/15/25/30 % 的纠错能力，
//! 体现在 k 的取值上。
//!
//! # 解码算法
//!
//! 三步：syndrome → Berlekamp-Massey（求错位多项式 Λ(x)）→ Chien 搜索（解 Λ(x) 的根 = 出错位置）
//! → Forney 公式（算每个出错位置的错值）。教材标准，参考 Lin & Costello《Error Control Coding》。

use super::galois::{self, EXP};

/// 生成 k 个 EC 字节的生成多项式 g(x) = ∏_{i=0}^{k-1}(x - α^i)。
///
/// 返回的 `Vec<u8>` 是 g 的系数，长度 k+1，最高次项（首项）总是 1。
/// 例如 k=2 时 g(x) = (x-1)(x-α) = x^2 + (1+α)x + α，返回 `[1, 3, 2]`（α = 2）。
pub fn generator_poly(k: usize) -> Vec<u8> {
    // 从 g(x) = 1 开始（用"最高次在前"约定，g[0] 是首项系数）。
    let mut g = vec![1u8];
    for i in 0..k {
        // 乘 (x - α^i) = (x + α^i)（GF(2^n) 中加减相同）
        // 在"最高次在前"约定下：
        //   g(x) * x       → 系数下标整体保持（最高次升 1，所以新 new_g[j] = g[j] for j in 0..len）
        //   g(x) * α^i     → 系数下标整体保持但乘 α^i（new_g[j+1] += g[j] * α^i）
        let alpha_i = EXP[i];
        let mut new_g = vec![0u8; g.len() + 1];
        for (j, &gj) in g.iter().enumerate() {
            new_g[j] ^= gj; // 来自 g(x) * x
            new_g[j + 1] ^= galois::mul(gj, alpha_i); // 来自 g(x) * α^i
        }
        g = new_g;
    }
    g
}

/// 编码：给定数据字节 + EC 字节数 k，返回 k 个 EC 字节。
///
/// 标准长除：把 data 后面接 k 个 0，逐项把 g(x) 减掉首位非零项。最后剩下的就是余式（EC）。
pub fn encode(data: &[u8], k: usize) -> Vec<u8> {
    let g = generator_poly(k);
    // 缓冲区 = data 后接 k 个 0；最后 k 字节就是余式。
    let mut buf = vec![0u8; data.len() + k];
    buf[..data.len()].copy_from_slice(data);

    for i in 0..data.len() {
        let coef = buf[i];
        if coef != 0 {
            // 把 g(x) * coef 从 buf[i..i+k+1] 里减掉（XOR）。
            for j in 0..=k {
                buf[i + j] ^= galois::mul(g[j], coef);
            }
        }
    }
    buf[data.len()..].to_vec()
}

// ───────────────────────────────────────── 解码部分 ─────────────────────────────────────────

/// 多项式 a + b（每个系数 XOR）。a 和 b 的次数可以不同。
fn poly_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut r = vec![0u8; n];
    // 注意：约定下标 0 是最高次项；为了对齐次数，从末尾对齐。
    for (i, &v) in a.iter().enumerate() {
        r[i + n - a.len()] ^= v;
    }
    for (i, &v) in b.iter().enumerate() {
        r[i + n - b.len()] ^= v;
    }
    r
}

/// 多项式乘法。
fn poly_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; a.len() + b.len() - 1];
    for (i, &av) in a.iter().enumerate() {
        if av == 0 {
            continue;
        }
        for (j, &bv) in b.iter().enumerate() {
            r[i + j] ^= galois::mul(av, bv);
        }
    }
    r
}

/// 在 x 处求 P(x) 的值（Horner）。`p[0]` 是最高次项。
fn poly_eval(p: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in p {
        y = galois::mul(y, x) ^ c;
    }
    y
}

/// 标量乘多项式。
fn poly_scale(p: &[u8], s: u8) -> Vec<u8> {
    p.iter().map(|&c| galois::mul(c, s)).collect()
}

/// 计算 syndromes：S_i = R(α^i) for i = 0..k-1。
///
/// R(x) 把"接收码"看作多项式，下标 0 = 最高次项。
fn syndromes(received: &[u8], k: usize) -> Vec<u8> {
    (0..k).map(|i| poly_eval(received, EXP[i])).collect()
}

/// Berlekamp-Massey：求错位多项式 Λ(x)（QR 用习惯：Λ(0) = 1，最低次项=1 在末尾）。
///
/// 这里采用"BCH 视角 + Massey 形式"的标准算法。返回 `Λ` 用最高次系数在前的约定。
fn berlekamp_massey(syndromes: &[u8]) -> Vec<u8> {
    // C(x) 和 B(x) 都用"最高次在前"约定。初始 C(x) = 1，B(x) = 1。
    let mut c: Vec<u8> = vec![1];
    let mut b: Vec<u8> = vec![1];
    let mut l: usize = 0; // 当前错位多项式次数
    let mut m: usize = 1; // 自上次跳变后的步数
    let mut bb: u8 = 1; // 上次"discrepancy"用过的值

    for n in 0..syndromes.len() {
        // d = S_n + Σ_{i=1..l} C_i * S_{n-i}
        // C 用"最高次在前"，所以 C 的常数项在 c[c.len()-1]，C_i = c[c.len()-1-i]。
        let mut d = syndromes[n];
        for i in 1..=l {
            // c.len() = l+1（C 度数 l），c[c.len()-1-i] = C_i
            let ci = c[c.len() - 1 - i];
            d ^= galois::mul(ci, syndromes[n - i]);
        }
        if d == 0 {
            m += 1;
        } else if 2 * l <= n {
            // T = C; C = C - (d/bb) * x^m * B; L = n+1-L; B = T; bb = d; m = 1
            let t = c.clone();
            let scale = galois::div(d, bb);
            let shifted = {
                // x^m * B = B 在低端追加 m 个 0；用"最高次在前"约定即在末尾加 m 个 0。
                let mut tmp = b.clone();
                tmp.extend(std::iter::repeat(0u8).take(m));
                tmp
            };
            let term = poly_scale(&shifted, scale);
            c = poly_add(&c, &term);
            l = n + 1 - l;
            b = t;
            bb = d;
            m = 1;
        } else {
            // C = C - (d/bb) * x^m * B; m += 1
            let scale = galois::div(d, bb);
            let shifted = {
                let mut tmp = b.clone();
                tmp.extend(std::iter::repeat(0u8).take(m));
                tmp
            };
            let term = poly_scale(&shifted, scale);
            c = poly_add(&c, &term);
            m += 1;
        }
    }

    // 去掉前导零，使首项非零（即首项 = Λ 的最高次系数）。
    while c.len() > 1 && c[0] == 0 {
        c.remove(0);
    }
    c
}

/// Chien 搜索：找 Λ(x) 在 GF(256) 上的根。
///
/// 返回所有 α^p（每个根的"位置指数 p"），其中 p 是错位的"指数"。
/// 注意：根 = α^{-p}（即 Λ 在 α^{-p} 处为 0 表示位置 p 出错），所以位置 p = (255 - log(root)) % 255。
fn chien_search(lambda: &[u8], n: usize) -> Vec<usize> {
    let mut positions = Vec::new();
    for p in 0..n {
        // 求 Λ(α^{-p}) = Λ(α^{255-p})；EXP 是 512 长，下标 (255-p) % 255 即可。
        // 但用 EXP[(255 - p) % 255] 直接查更稳当。
        let x = EXP[(255 - p as i32).rem_euclid(255) as usize];
        if poly_eval(lambda, x) == 0 {
            positions.push(p);
        }
    }
    positions
}

/// Forney 公式求错值。
///
/// 给定 syndromes、error_positions（自高位往低位的下标）、码长 n，返回与每个 error_position 对应的错值。
/// 标准做法：
///   1. 错位多项式 Λ(x) 已知；构造 Ω(x) = (S(x) * Λ(x)) mod x^k（k = syndromes 长度）
///   2. 对每个错位 p，错值 = Ω(X^{-1}) / Λ'(X^{-1})，其中 X = α^p
///      （在 char-2 域里负号不存在）
fn forney(syndromes: &[u8], lambda: &[u8], positions: &[usize], n: usize) -> Vec<u8> {
    let k = syndromes.len();
    // S(x) 用"最高次在前"约定。S(x) = s_0 + s_1 x + s_2 x^2 + ... ；翻一下方向。
    let s_high_first: Vec<u8> = syndromes.iter().rev().copied().collect();
    let prod = poly_mul(&s_high_first, lambda);
    // Ω(x) = prod mod x^k，即只保留次数 < k 的项。"最高次在前"下，
    // 取末尾 k 个系数（次数 0..k-1）。
    let omega_start = prod.len().saturating_sub(k);
    let omega: Vec<u8> = prod[omega_start..].to_vec();

    // Λ' 在 char-2 下：丢掉偶数次项，对奇数次项保留并降阶 1。
    // "最高次在前"约定下，最低次项在 lambda[lambda.len()-1]。
    // 设 Λ(x) = Σ_i λ_i x^i（i 从 0 到 deg），则 Λ'(x) = Σ_{i odd} λ_i x^{i-1}。
    let mut lambda_prime = vec![0u8; lambda.len() - 1];
    let deg = lambda.len() - 1;
    for i in 1..=deg {
        // λ_i = lambda[deg - i]; 仅当 i 为奇数才保留。
        if i % 2 == 1 {
            // x^{i-1} 在结果里的下标（"最高次在前"约定）：lambda_prime.len() - 1 - (i-1)
            //                                                = (lambda.len() - 1) - i
            lambda_prime[(lambda.len() - 1) - i] = lambda[deg - i];
        }
    }

    let mut magnitudes = Vec::with_capacity(positions.len());
    for &p in positions {
        // X_p = α^p；X_p^{-1} = α^{-p} = α^{255 - p}（错位的"反 root"，用于求值）
        let xi = EXP[(255 - p as i32).rem_euclid(255) as usize];
        let num = poly_eval(&omega, xi);
        let den = poly_eval(&lambda_prime, xi);
        debug_assert!(den != 0, "Λ' 在错位处不应为零");
        // Forney 公式（QR / BCH，c = 首根指数 = 0）：
        //   e_p = X_p^{1-c} * Ω(X_p^{-1}) / Λ'(X_p^{-1})  = X_p * Ω/Λ'（c=0 时）
        // 用单错算例校验：σ(x)=1+X_p·x, ω(x)=e, σ'(x)=X_p
        //   X_p · e / X_p = e ✓
        let x_p = EXP[p % 255];
        let mag = galois::mul(x_p, galois::div(num, den));
        magnitudes.push(mag);
        let _ = n;
    }
    magnitudes
}

/// 解码：尝试纠错。成功则返回原始数据（去除 EC 部分）；失败返回 Err。
///
/// `received` 长度 = data + ec。`k` = ec 字节数。
pub fn decode(received: &[u8], k: usize) -> Result<Vec<u8>, &'static str> {
    let n = received.len();
    if n <= k {
        return Err("received too short");
    }
    let s = syndromes(received, k);
    if s.iter().all(|&x| x == 0) {
        // 无错。
        return Ok(received[..n - k].to_vec());
    }
    let lambda = berlekamp_massey(&s);
    let positions = chien_search(&lambda, n);
    let expected_errors = lambda.len() - 1; // Λ 的次数 = 错的个数
    if positions.len() != expected_errors {
        return Err("decoder failed: could not locate all errors");
    }
    let mags = forney(&s, &lambda, &positions, n);

    let mut corrected = received.to_vec();
    for (&p, &m) in positions.iter().zip(mags.iter()) {
        // 位置 p 表示"从右数第 p 项"，即下标 n-1-p。
        corrected[n - 1 - p] ^= m;
    }

    // 校验：纠后 syndrome 全 0 才算成功。
    let s2 = syndromes(&corrected, k);
    if !s2.iter().all(|&x| x == 0) {
        return Err("decoder failed: residual syndrome");
    }

    Ok(corrected[..n - k].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Project Nayuki / Thonky 公认测试向量：v1-M，16 data + 10 EC。
    #[test]
    fn encode_qr_v1m_reference_vector() {
        let data = [
            0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11,
            0xEC, 0x11,
        ];
        let expected_ec = [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55];
        let ec = encode(&data, 10);
        assert_eq!(ec, expected_ec);
    }

    /// 生成多项式 deg 2：(x-1)(x-α) = x^2 + (1+α)x + α
    /// α = 2，1+α = 3，所以系数为 [1, 3, 2]（最高次在前）。
    #[test]
    fn generator_poly_small() {
        assert_eq!(generator_poly(0), vec![1]);
        assert_eq!(generator_poly(1), vec![1, 1]); // (x - 1) = x + 1
        assert_eq!(generator_poly(2), vec![1, 3, 2]);
    }

    #[test]
    fn encode_then_decode_no_error() {
        let data: Vec<u8> = (0..20).map(|i| (i * 7 + 13) as u8).collect();
        let k = 8;
        let ec = encode(&data, k);
        let mut received = data.clone();
        received.extend(&ec);
        let recovered = decode(&received, k).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn decode_corrects_single_error() {
        let data: Vec<u8> = (0..16).map(|i| (i * 11 + 3) as u8).collect();
        let k = 8; // 可纠 4 个错
        let ec = encode(&data, k);
        let mut received = data.clone();
        received.extend(&ec);
        received[5] ^= 0xAB; // 制造一个错
        let recovered = decode(&received, k).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn decode_corrects_multiple_errors() {
        let data: Vec<u8> = (0..16).map(|i| (i * 11 + 3) as u8).collect();
        let k = 10; // 可纠 5 个错
        let ec = encode(&data, k);
        let mut received = data.clone();
        received.extend(&ec);
        // 制造 4 个错（含 EC 区）。
        received[0] ^= 0x01;
        received[3] ^= 0xFF;
        received[10] ^= 0x80;
        received[20] ^= 0x55; // EC 区
        let recovered = decode(&received, k).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn decode_fails_on_too_many_errors() {
        let data: Vec<u8> = (0..16).map(|i| (i * 11 + 3) as u8).collect();
        let k = 4; // 仅能纠 2 个错
        let ec = encode(&data, k);
        let mut received = data.clone();
        received.extend(&ec);
        // 制造 3 个错——超出能力。期望返回 Err（不是 panic）。
        received[0] ^= 0x01;
        received[1] ^= 0x02;
        received[2] ^= 0x04;
        let result = decode(&received, k);
        // 不一定保证返回 Err（RS 解码对超错可能"误纠"成另一个有效码字）；
        // 至少不应该 panic 也不应该等于原数据。
        if let Ok(r) = result {
            assert_ne!(r, data);
        }
    }
}
