//! Encode a string into a QR code PNG.
//!
//! ```text
//! cargo run --release --example encode -- "https://example.com" qr.png
//! ```

use std::env;
use std::process::ExitCode;

use roka_qr::{EcLevel, Encoder};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: encode <text> <out.png> [L|M|Q|H]");
        return ExitCode::from(2);
    }
    let text = &args[1];
    let out_path = &args[2];
    let ec = match args.get(3).map(String::as_str) {
        Some("L") => EcLevel::L,
        Some("M") | None => EcLevel::M,
        Some("Q") => EcLevel::Q,
        Some("H") => EcLevel::H,
        Some(other) => {
            eprintln!("bad EC level {other:?} (use L, M, Q, or H)");
            return ExitCode::from(2);
        }
    };

    let code = match Encoder::new(text.as_bytes()).ec_level(ec).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("encode error: {e}");
            return ExitCode::from(1);
        }
    };

    let png = code.render().scale(8).quiet_zone(4).build().to_png();
    if let Err(e) = std::fs::write(out_path, png) {
        eprintln!("write {out_path}: {e}");
        return ExitCode::from(1);
    }

    eprintln!(
        "wrote {out_path}: V{}, EC {:?}, mask {} ({}×{} modules)",
        code.version().0,
        code.ec_level(),
        code.mask(),
        code.size(),
        code.size()
    );
    ExitCode::SUCCESS
}
