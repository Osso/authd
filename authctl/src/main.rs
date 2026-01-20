//! authctl - simple client for authd
//!
//! Sends authorization requests to authd daemon.
//! authd handles all UI (session-lock dialog).

use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use peercred_ipc::Client;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        print_help();
        process::exit(1);
    }

    if args[0] == "--help" || args[0] == "-h" {
        print_help();
        process::exit(0);
    }

    if args[0] == "--version" || args[0] == "-V" {
        println!("authctl {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let target = PathBuf::from(&args[0]);
    let target_args: Vec<String> = args.iter().skip(1).cloned().collect();

    let request = AuthRequest {
        target,
        args: target_args,
        env: collect_wayland_env(),
        password: String::new(),
        confirm_only: false,
    };

    match send_request(&request) {
        Ok(AuthResponse::Success { pid }) => {
            eprintln!("authctl: process spawned (pid {})", pid);
            process::exit(0);
        }
        Ok(AuthResponse::Denied { reason }) => {
            eprintln!("authctl: denied - {}", reason);
            process::exit(1);
        }
        Ok(AuthResponse::UnknownTarget) => {
            eprintln!("authctl: no policy for this command");
            process::exit(1);
        }
        Ok(AuthResponse::AuthFailed) => {
            eprintln!("authctl: authentication failed");
            process::exit(1);
        }
        Ok(AuthResponse::Error { message }) => {
            eprintln!("authctl: error - {}", message);
            process::exit(1);
        }
        Err(e) => {
            if e.contains("connect") {
                eprintln!("authctl: daemon not running");
            } else {
                eprintln!("authctl: {}", e);
            }
            process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!("authctl - privilege escalation client for authd");
    eprintln!();
    eprintln!("Usage: authctl <command> [args...]");
    eprintln!();
    eprintln!("Sends authorization requests to authd daemon.");
    eprintln!("If authorized, the command runs as root.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -h, --help     Show this help");
    eprintln!("  -V, --version  Show version");
}

fn collect_wayland_env() -> HashMap<String, String> {
    wayland_env()
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|val| (key.to_string(), val)))
        .collect()
}

fn send_request(request: &AuthRequest) -> Result<AuthResponse, String> {
    Client::call(SOCKET_PATH, request).map_err(|e| e.to_string())
}
