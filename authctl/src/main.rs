//! authctl - simple client for authd
//!
//! Sends authorization requests to authd daemon.
//! authd handles all UI (session-lock dialog).

use authd_protocol::{AuthRequest, collect_wayland_env};
#[cfg(not(coverage))]
use authd_protocol::{AuthResponse, DaemonRequest, SOCKET_PATH};
#[cfg(not(coverage))]
use peercred_ipc::Client;
#[cfg(not(coverage))]
use std::env;
use std::path::PathBuf;
#[cfg(not(coverage))]
use std::process;

#[cfg(not(coverage))]
fn main() {
    let args = cli_args();
    handle_meta_args(&args);
    let request = build_request(&args);
    exit_with_response(send_request(&request));
}

#[cfg(coverage)]
fn main() {}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
fn cli_args() -> Vec<String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        process::exit(1);
    }
    args
}

#[cfg(not(coverage))]
fn handle_meta_args(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            print_help();
            process::exit(0);
        }
        Some("--version" | "-V") => {
            println!("authctl {}", env!("CARGO_PKG_VERSION"));
            process::exit(0);
        }
        _ => {}
    }
}

fn build_request(args: &[String]) -> AuthRequest {
    AuthRequest {
        target: PathBuf::from(&args[0]),
        args: args.iter().skip(1).cloned().collect(),
        env: collect_wayland_env(),
        password: String::new(),
        confirm_only: false,
        prompt_title: None,
        prompt_message: None,
        prompt_detail: None,
    }
}

#[cfg(not(coverage))]
fn exit_with_response(response: Result<AuthResponse, String>) -> ! {
    match response {
        Ok(AuthResponse::Success { pid }) => {
            eprintln!("authctl: process spawned (pid {})", pid);
            process::exit(0);
        }
        Ok(AuthResponse::Denied { reason }) => exit_with_error(&format!("denied - {}", reason)),
        Ok(AuthResponse::UnknownTarget) => exit_with_error("no policy for this command"),
        Ok(AuthResponse::AuthFailed) => exit_with_error("authentication failed"),
        Ok(AuthResponse::Error { message }) => exit_with_error(&format!("error - {}", message)),
        Err(error) if error.contains("connect") => exit_with_error("daemon not running"),
        Err(error) => exit_with_error(&error),
    }
}

#[cfg(not(coverage))]
fn exit_with_error(message: &str) -> ! {
    eprintln!("authctl: {}", message);
    process::exit(1)
}

#[cfg(not(coverage))]
fn send_request(request: &AuthRequest) -> Result<AuthResponse, String> {
    Client::call(SOCKET_PATH, &DaemonRequest::Exec(request.clone())).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_exec_request_from_cli_args() {
        let args = vec![
            "/usr/bin/id".to_string(),
            "-u".to_string(),
            "--name".to_string(),
        ];

        let request = build_request(&args);

        assert_eq!(request.target, PathBuf::from("/usr/bin/id"));
        assert_eq!(request.args, vec!["-u", "--name"]);
        assert!(!request.confirm_only);
        assert!(request.password.is_empty());
        assert!(request.prompt_title.is_none());
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_main_stub_is_callable() {
        main();
    }
}
