//! Print the current TOTP code for a base32 secret.
//!
//! ```text
//! cargo run --release --example now -- JBSWY3DPEHPK3PXP
//! ```

use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use roka_totp::{Secret, Totp};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: now <secret-base32>");
        return ExitCode::from(2);
    }
    let secret = match Secret::from_base32(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bad secret: {e}");
            return ExitCode::from(1);
        }
    };

    let totp = Totp::builder(secret).build();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    let code = totp.code_at(now);
    let remaining = totp.seconds_remaining_at(now);
    println!("{code}  ({remaining}s left in window)");
    ExitCode::SUCCESS
}
