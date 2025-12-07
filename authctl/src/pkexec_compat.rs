//! pkexec compatibility wrapper
//! Translates pkexec-style arguments to authctl

use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    // pkexec [options] <program> [args...]
    // Strip pkexec-specific options, keep only the command and its args
    let mut cmd_args: Vec<String> = Vec::new();
    let mut skip_next = false;

    for arg in &args {
        if skip_next {
            skip_next = false;
            continue;
        }

        match arg.as_str() {
            "--disable-internal-agent" | "--keep-cwd" => continue,
            "--user" => {
                skip_next = true; // skip the username argument
                continue;
            }
            "--help" | "--version" => {
                eprintln!("pkexec (authd compatibility wrapper)");
                std::process::exit(0);
            }
            _ if arg.starts_with("--user=") => continue,
            _ => cmd_args.push(arg.clone()),
        }
    }

    if cmd_args.is_empty() {
        eprintln!("pkexec: missing program");
        std::process::exit(1);
    }

    // Launch authctl with the target
    let status = Command::new("authctl")
        .args(&cmd_args)
        .status();

    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("pkexec: failed to run authctl: {}", e);
            std::process::exit(1);
        }
    }
}
