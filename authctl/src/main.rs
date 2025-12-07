//! authctl - simple client for authd
//!
//! Sends authorization requests to authd daemon.
//! authd handles all UI (session-lock dialog).

use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("usage: authctl <command> [args...]");
        process::exit(1);
    }

    let target = PathBuf::from(&args[0]);
    let target_args: Vec<String> = args.iter().skip(1).cloned().collect();

    let request = AuthRequest {
        target,
        args: target_args,
        env: collect_wayland_env(),
        password: String::new(),
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

fn collect_wayland_env() -> HashMap<String, String> {
    wayland_env()
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|val| (key.to_string(), val)))
        .collect()
}

fn send_request(request: &AuthRequest) -> Result<AuthResponse, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("connect: {}", e))?;

    let data = rmp_serde::to_vec(request).map_err(|e| format!("serialize: {}", e))?;
    stream.write_all(&data).map_err(|e| format!("write: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {}", e))?;

    rmp_serde::from_slice(&buf[..n]).map_err(|e| format!("deserialize: {}", e))
}
