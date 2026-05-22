//! Scan a QR code image (PNG or PBM) and print the payload.
//!
//! ```text
//! cargo run --release --example scan -- qr.png
//! ```

use std::env;
use std::process::ExitCode;

use roka_qr::Reader;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: scan <image.png|image.pbm>");
        return ExitCode::from(2);
    }
    let path = &args[1];
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let code = match Reader::from_image_bytes(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("decode {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let payload = code.payload();
    if let Ok(s) = std::str::from_utf8(payload) {
        println!("{s}");
    } else {
        // Binary payload
        println!("<{} bytes of binary data>", payload.len());
    }
    ExitCode::SUCCESS
}
