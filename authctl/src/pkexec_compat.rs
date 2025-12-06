//! pkexec compatibility wrapper
//! Translates pkexec-style arguments to authctl

use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    // pkexec [options] <program> [args...]
    if args.is_empty() {
        eprintln!("pkexec: missing program");
        std::process::exit(1);
    }

    // Launch authctl with the target
    let status = Command::new("authctl")
        .args(&args)
        .status();

    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("pkexec: failed to run authctl: {}", e);
            std::process::exit(1);
        }
    }
}
